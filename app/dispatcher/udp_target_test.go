package dispatcher

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// A UDP flow whose first datagram sniffing named is routed by that name, as a TCP flow is — the rules
// see the name and not the address — and is handed to its outbound with the address the program sent
// to: target and original target equal, so the outbound handler leaves every datagram's address as
// the program wrote it (app/proxyman/outbound udp_target_test.go shows what it does otherwise). The
// name stays as the RouteTarget. TCP keeps upstream's behavior: a CONNECT by name lets the exit
// resolve it. Addresses are documentation ranges; the QUIC Initial is the sniffer's own test packet,
// which names www.google.com.

// sniffingCtx is a tun flow's context as the dispatcher gets it: the inbound, its sniffing (http,
// tls and quic, routeOnly off), and an engine the sniffers can ask for features (this one has none).
func sniffingCtx(source net.Destination) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "tun", Name: "tun", Source: source})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: flowRouteClientSniffing()})
	return context.WithValue(ctx, flowRouteXrayKey, &core.Instance{})
}

// handedOver is the outbound session as the handler found it when it took the flow, by value: the
// session itself is shared, and a read after the dispatch would see what was done later.
type handedOver struct {
	original, target, route net.Destination
}

// entryHandler notes the outbound session at the moment it takes a flow, then pumps the link.
type entryHandler struct {
	outbound.Handler
	tag     string
	entries chan handedOver
}

func (h *entryHandler) Tag() string { return h.tag }

func (h *entryHandler) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	h.entries <- handedOver{original: ob.OriginalTarget, target: ob.Target, route: ob.RouteTarget}
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err != nil {
			break
		}
	}
	common.Close(link.Writer)
}

func newEntryHandler() *entryHandler {
	return &entryHandler{tag: "proxy", entries: make(chan handedOver, 1)}
}

func (h *entryHandler) next(t *testing.T) handedOver {
	t.Helper()
	select {
	case entry := <-h.entries:
		return entry
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was handed to the handler")
		return handedOver{}
	}
}

// viewRouter routes every dispatch to `tag` ("" — no rule matches) and keeps what the rules were shown
// at the moment of the choice: a routing context reads the live session.
type viewRouter struct {
	routing.Router
	tag     string
	domains []string
	ips     [][]net.IP
}

func (r *viewRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.domains = append(r.domains, ctx.GetTargetDomain())
	r.ips = append(r.ips, ctx.GetTargetIPs())
	if r.tag == "" {
		return nil, common.ErrNoClue
	}
	return viewRoute{tag: r.tag}, nil
}

type viewRoute struct {
	routing.Route
	tag string
}

func (r viewRoute) GetOutboundTag() string { return r.tag }
func (r viewRoute) GetRuleTag() string     { return "main" }

func viewDispatcher(handler *entryHandler, tag string) (*DefaultDispatcher, *viewRouter) {
	router := &viewRouter{tag: tag}
	return &DefaultDispatcher{
		ohm:    flowRouteOutbounds{handlers: map[string]outbound.Handler{handler.tag: handler}},
		router: router,
	}, router
}

var programsTarget = net.UDPDestination(net.ParseAddress("203.0.113.10"), 443)

func isTheSniffedName(d net.Destination) bool {
	return d.IsValid() && d.Address.Family().IsDomain() && d.Address.Domain() == "www.google.com" &&
		d.Port == 443 && d.Network == net.Network_UDP
}

// handedTheAddress: the outbound got the program's address as both its target and its original target
// (so the handler does not readdress the datagrams), with the sniffed name as the route target.
func handedTheAddress(t *testing.T, entry handedOver) {
	t.Helper()
	if entry.target != programsTarget || entry.original != programsTarget {
		t.Fatalf("the outbound was handed target %v (original %v), want the program's address %v for both",
			entry.target, entry.original, programsTarget)
	}
	if !isTheSniffedName(entry.route) {
		t.Fatalf("the route target is %v, want the sniffed name www.google.com:443 over UDP", entry.route)
	}
}

func TestAUDPFlowSniffedByNameIsRoutedByTheNameAndHandedItsAddress(t *testing.T) {
	handler := newEntryHandler()
	d, router := viewDispatcher(handler, "proxy")

	viaDispatchLink(t, d, sniffingCtx(net.UDPDestination(net.ParseAddress("192.0.2.2"), 50000)), programsTarget,
		flowRouteBytes(t, flowRouteQUICInitial))

	handedTheAddress(t, handler.next(t))
	if len(router.domains) != 1 {
		t.Fatalf("the router was asked %d times, want once", len(router.domains))
	}
	// The rules were shown what they were shown before: the name, and no address — an address row
	// does not take a named flow, for UDP as for TCP.
	if router.domains[0] != "www.google.com" {
		t.Fatalf("domain rules saw %q, want www.google.com", router.domains[0])
	}
	if len(router.ips[0]) != 0 {
		t.Fatalf("address rules saw %v, want none — a named flow is routed by its name", router.ips[0])
	}
}

func TestAUDPFlowThroughDispatchIsHandedItsAddressToo(t *testing.T) {
	handler := newEntryHandler()
	d, _ := viewDispatcher(handler, "proxy")

	link, err := d.Dispatch(sniffingCtx(net.UDPDestination(net.ParseAddress("192.0.2.2"), 50001)), programsTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, flowRouteBytes(t, flowRouteQUICInitial))); err != nil {
		t.Fatal(err)
	}
	common.Close(link.Writer)
	readAll(link.Reader)

	handedTheAddress(t, handler.next(t))
}

func TestAUDPFlowOnAPlatformDetourIsHandedItsAddressToo(t *testing.T) {
	handler := newEntryHandler()
	d, _ := viewDispatcher(handler, "")
	ctx := session.SetForcedOutboundTagToContext(sniffingCtx(net.UDPDestination(net.ParseAddress("192.0.2.2"), 50002)), "proxy")

	viaDispatchLink(t, d, ctx, programsTarget, flowRouteBytes(t, flowRouteQUICInitial))

	handedTheAddress(t, handler.next(t))
}

func TestAUDPFlowNoRuleMatchesIsHandedItsAddressByTheDefaultOutboundToo(t *testing.T) {
	handler := newEntryHandler()
	d := &DefaultDispatcher{
		ohm:    flowRouteOutbounds{handlers: map[string]outbound.Handler{}, fallback: handler},
		router: &viewRouter{},
	}

	viaDispatchLink(t, d, sniffingCtx(net.UDPDestination(net.ParseAddress("192.0.2.2"), 50003)), programsTarget,
		flowRouteBytes(t, flowRouteQUICInitial))

	handedTheAddress(t, handler.next(t))
}

func TestATCPFlowSniffedByNameStillGoesByTheName(t *testing.T) {
	handler := newEntryHandler()
	d, _ := viewDispatcher(handler, "proxy")
	target := net.TCPDestination(net.ParseAddress("203.0.113.10"), 80)

	viaDispatchLink(t, d, sniffingCtx(net.TCPDestination(net.ParseAddress("192.0.2.2"), 50004)), target,
		[]byte("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"))

	entry := handler.next(t)
	if !entry.target.Address.Family().IsDomain() || entry.target.Address.Domain() != "www.google.com" || entry.target.Port != 80 {
		t.Fatalf("a TCP flow was handed %v, want the sniffed name www.google.com:80, as upstream sends it", entry.target)
	}
}

// poolOnlyFakeDNS answers only whether an address is in its pool — all the dispatcher asks of fake
// DNS on these paths.
type poolOnlyFakeDNS struct {
	dns.FakeDNSEngineRev0
	pool *stdnet.IPNet
}

func (f poolOnlyFakeDNS) IsIPInIPPool(ip net.Address) bool {
	return ip.Family().IsIP() && f.pool.Contains(ip.IP())
}

// An address of fake DNS is no address at all: the name is all there is to send to. The pool here is
// a documentation range standing in for fake DNS's own.
func TestAUDPFlowToAFakeDNSAddressStillGoesByTheName(t *testing.T) {
	handler := newEntryHandler()
	d, _ := viewDispatcher(handler, "proxy")
	_, pool, err := stdnet.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d.fdns = poolOnlyFakeDNS{pool: pool}
	fake := net.UDPDestination(net.ParseAddress("198.51.100.5"), 443)

	viaDispatchLink(t, d, sniffingCtx(net.UDPDestination(net.ParseAddress("192.0.2.2"), 50005)), fake,
		flowRouteBytes(t, flowRouteQUICInitial))

	if entry := handler.next(t); !isTheSniffedName(entry.target) {
		t.Fatalf("a flow to a fake DNS address was handed %v, want the sniffed name www.google.com:443", entry.target)
	}
}
