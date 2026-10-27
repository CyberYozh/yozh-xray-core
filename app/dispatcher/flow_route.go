package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// reportFlowRoute tells an inbound that asked (session.ContextWithFlowRouteReport) where the flow
// has just been routed, before routedDispatch hands it to that outbound — the tun inbound's UDP
// flows, whose later datagrams may go to other destinations and must each take their own route.
// `forced` is a flow the platform sent to its outbound by tag: every destination of it goes there.
func (d *DefaultDispatcher) reportFlowRoute(ctx context.Context, handler outbound.Handler, forced bool) {
	report := session.FlowRouteReportFromContext(ctx)
	if report == nil {
		return
	}
	tag := handler.Tag()
	report(session.FlowRoute{
		Tag: tag,
		RouteOf: func(destination net.Destination, datagrams [][]byte) (string, error) {
			if forced {
				return tag, nil
			}
			return d.routeOf(ctx, destination, datagrams)
		},
	})
}

// errRouteOfDropped: routedDispatch would drop the datagrams — a rule names an outbound that does
// not exist, or there is no outbound at all.
var errRouteOfDropped = errors.New("no outbound would take it")

// routeOfSniffLimit is how much of a new flow's first packets sniffer() reads: its buffer's size.
const routeOfSniffLimit = 32767

// routeOf is routedDispatch's choice of outbound for datagrams of the flow in ctx to another
// destination, as if they were the first packets of a flow of their own: the flow's inbound and
// source, that destination as the target, and what the flow's sniffing finds in these datagrams —
// not what it found in the flow's first packet, which was not theirs. protocol.ErrProtoNeedMoreData:
// they cannot tell yet (sniffDatagrams). errRouteOfDropped: routedDispatch would drop them.
func (d *DefaultDispatcher) routeOf(ctx context.Context, destination net.Destination, datagrams [][]byte) (string, error) {
	var request session.SniffingRequest
	if flow := session.ContentFromContext(ctx); flow != nil {
		request = flow.SniffingRequest
	}
	ob := &session.Outbound{OriginalTarget: destination, Target: destination}
	content := &session.Content{SniffingRequest: request}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.ContextWithRouteProbe(ctx)
	if request.Enabled {
		result, err := sniffDatagrams(ctx, datagrams, request.MetadataOnly, destination.Network)
		if err == protocol.ErrProtoNeedMoreData {
			return "", err
		}
		if err == nil {
			content.Protocol = result.Protocol()
			if d.shouldOverride(ctx, result, request, destination) {
				d.overrideTarget(ob, result, request)
			}
		}
	}
	if d.router != nil {
		if route, err := d.router.PickRoute(routing_session.AsRoutingContext(ctx)); err == nil {
			if handler := d.ohm.GetHandler(route.GetOutboundTag()); handler != nil {
				return handler.Tag(), nil
			}
			return "", errRouteOfDropped
		}
	}
	if handler := d.ohm.GetDefaultHandler(); handler != nil {
		return handler.Tag(), nil
	}
	return "", errRouteOfDropped
}

// sniffDatagrams is sniffer() for the datagrams at hand: the metadata sniffers, then the content
// sniffers on the datagrams read one after another, up to sniffer()'s buffer, the two results put
// together the same way. With no datagrams there is no content result, as when sniffer()'s wait ends
// empty. A sniffer that needs more than these answers protocol.ErrProtoNeedMoreData: the dispatcher
// would read on into the flow's next datagrams, which the caller has not got yet. Where no sniffer
// knows them (common.ErrNoClue), the dispatcher would also wait up to 200 ms for another one and try
// again on both; here there is no content result, as when that wait ends empty, which is how it
// usually ends.
//
// The datagrams are sniffed in a copy (joinDatagrams): the QUIC sniffer decrypts in place, and the
// caller sends them on as the program wrote them.
func sniffDatagrams(ctx context.Context, datagrams [][]byte, metadataOnly bool, network net.Network) (SniffResult, error) {
	sniffer := NewSniffer(ctx)
	metaresult, metadataErr := sniffer.SniffMetadata(ctx)
	if metadataOnly {
		return metaresult, metadataErr
	}
	var contentResult SniffResult
	var contentErr error = errUnknownContent // nothing to sniff: no content result
	if payload := joinDatagrams(datagrams); len(payload) > 0 {
		contentResult, contentErr = sniffer.Sniff(ctx, payload, network)
		if contentErr == protocol.ErrProtoNeedMoreData {
			return nil, contentErr
		}
	}
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

// joinDatagrams puts the datagrams one after another in a buffer of their own, as sniffer() reads a
// flow's first packets into its buffer: what does not fit in routeOfSniffLimit is left out.
func joinDatagrams(datagrams [][]byte) []byte {
	size := 0
	for _, datagram := range datagrams {
		size += len(datagram)
	}
	payload := make([]byte, 0, min(size, routeOfSniffLimit))
	for _, datagram := range datagrams {
		payload = append(payload, datagram[:min(len(datagram), cap(payload)-len(payload))]...)
	}
	return payload
}

// overrideTarget puts the sniffed name where Dispatch puts it for a flow's first packet: in the
// target the rules see (RouteTarget) with routeOnly, and in the target itself otherwise — always
// for a name from fake DNS or an address of its pool.
func (d *DefaultDispatcher) overrideTarget(ob *session.Outbound, result SniffResult, request session.SniffingRequest) {
	destination := ob.Target
	destination.Address = net.ParseAddress(result.Domain())
	sniffedProtocol := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		sniffedProtocol = resComp.ProtocolForDomainResult()
	}
	isFakeIP := false
	if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && fkr0.IsIPInIPPool(ob.Target.Address) {
		isFakeIP = true
	}
	if request.RouteOnly && sniffedProtocol != "fakedns" && sniffedProtocol != "fakedns+others" && !isFakeIP {
		ob.RouteTarget = destination
	} else {
		ob.Target = destination
	}
}
