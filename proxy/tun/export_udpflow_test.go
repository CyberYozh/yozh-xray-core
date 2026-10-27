package tun

import "github.com/xtls/xray-core/common/net"

// The real UDP flow table, with this platform's policy, for the engine tests in package tun_test
// (udp_flow_engine_test.go), which import main/distro/all and so cannot live in package tun.
// The constructors are darwin's (export_udpflow_darwin_test.go), the only platform with engine tests.

type UDPFlowsForTest = udpConnectionHandler

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
