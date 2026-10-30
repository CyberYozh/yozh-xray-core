package tun

import "github.com/xtls/xray-core/common/session"

// SetTagForTest names the handler's inbound as the engine does when it runs the inbound
// (AlwaysOnInboundHandler), so that the flows it dispatches carry the tag a client's do
// (udp_flow_pool_test.go).
func (t *Handler) SetTagForTest(tag string) {
	t.tag = tag
}

// SetSniffingForTest gives the handler the inbound's sniffing settings, which the engine hands it
// the same way (AlwaysOnInboundHandler), so that the flows it dispatches are sniffed as a client's
// are (udp_flow_pool_test.go).
func (t *Handler) SetSniffingForTest(request session.SniffingRequest) {
	t.sniffingRequest = request
}
