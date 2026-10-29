package tun

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// SetTagForTest names the handler's inbound as the engine does when it runs the inbound
// (AlwaysOnInboundHandler), so that rows with an inboundTag match the flows it dispatches
// (udp_flow_rules_test.go).
func (t *Handler) SetTagForTest(tag string) {
	t.tag = tag
}

// SetSniffingForTest gives the handler the inbound's sniffing settings, which the engine hands it
// the same way (AlwaysOnInboundHandler), so that the flows it dispatches are sniffed as a client's
// are (udp_flow_rules_test.go).
func (t *Handler) SetSniffingForTest(request session.SniffingRequest) {
	t.sniffingRequest = request
}

// SettledRouteForTest is where the dispatcher sent the first flow of source, and the RouteOf it
// reported with it (settle); ok is false until that flow is routed.
func (u *udpConnectionHandler) SettledRouteForTest(source net.Destination) (tag string, routeOf func(net.Destination, [][]byte) (string, error), ok bool) {
	u.Lock()
	defer u.Unlock()
	s := u.sources[source]
	if s == nil || len(s.flows) == 0 || !s.flows[0].routed {
		return "", nil, false
	}
	return s.flows[0].route, s.routeOf, true
}
