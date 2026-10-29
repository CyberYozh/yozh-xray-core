package tun

import "github.com/xtls/xray-core/common/net"

// The real UDP flow table, with this platform's policy, for the engine tests in package
// tun_test (udp_flow_engine_test.go), which import main/distro/all and so cannot live in package tun.

type UDPFlowsForTest = udpConnectionHandler

// NewUDPFlowsForTest builds the table by the function the bridge builds its own by (installHandlers),
// so the handler's rule for the addresses of fake DNS is in it.
func NewUDPFlowsForTest(h *Handler, write func(data []byte, src net.Destination, dst net.Destination) error) *UDPFlowsForTest {
	return newUdpConnectionHandler(h, write)
}

// FlowCount is how many live flows the table holds, all sources together.
func (u *udpConnectionHandler) FlowCount() int {
	u.Lock()
	defer u.Unlock()
	n := 0
	for _, s := range u.sources {
		n += len(s.flows)
	}
	return n
}

// Identified: the table knows which socket is behind source.
func (u *udpConnectionHandler) Identified(source net.Destination) bool {
	return u.identifiedFlow(source)
}
