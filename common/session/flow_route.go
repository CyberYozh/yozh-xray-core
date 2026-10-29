package session

import (
	"context"

	"github.com/xtls/xray-core/common/net"
)

// FlowRoute is what the dispatcher tells an inbound that asked (ContextWithFlowRouteReport) about a
// flow it has just routed, before the flow reaches its outbound.
//
// It exists for the tun inbound's UDP flows (proxy/tun, udp_fullcone.go). Such a flow is one
// program socket, whatever it sends to (full cone), and it is routed once, by its first datagram.
// Its later datagrams may go anywhere, and each must travel its own route: the inbound needs to
// know where the flow went and where a datagram of it to another destination would go.
type FlowRoute struct {
	// Tag of the outbound the flow was handed to.
	Tag string
	// RouteOf answers the tag of the outbound that datagrams of the same flow to another
	// destination would be handed to: what routedDispatch would choose for them as the first
	// packets of a flow of their own — the same inbound and source, that destination, and what
	// sniffing finds in them (not in the flow's first packet). `datagrams` are the ones waiting for
	// that destination, in the order sent, and the sniffers read them one after another, as they
	// read a new flow's first packets; with none, nothing is sniffed, as when a flow's sniffing
	// found nothing in its time. RouteOf does not modify them.
	//
	// protocol.ErrProtoNeedMoreData: they cannot tell yet — a sniffer needs more of them, as for a
	// ClientHello split over two QUIC Initials when only the first is here; the dispatcher would
	// read on into the flow's next packets for as long as its sniffing waits. Any other error: the
	// dispatcher would drop them. It may take as long as routing does.
	RouteOf func(destination net.Destination, datagrams [][]byte) (string, error)
}

type flowRouteReportKey struct{}

// ContextWithFlowRouteReport asks the dispatcher to report the flow's route to `report`.
func ContextWithFlowRouteReport(ctx context.Context, report func(FlowRoute)) context.Context {
	return context.WithValue(ctx, flowRouteReportKey{}, report)
}

// FlowRouteReportFromContext is the report an inbound asked for, or nil.
func FlowRouteReportFromContext(ctx context.Context) func(FlowRoute) {
	if report, ok := ctx.Value(flowRouteReportKey{}).(func(FlowRoute)); ok {
		return report
	}
	return nil
}
