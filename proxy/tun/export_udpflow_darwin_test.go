//go:build darwin

package tun

import "github.com/xtls/xray-core/common/net"

// NewUDPFlowsForTest is the real UDP flow table with darwin's policy, save one thing: no socket is
// set aside as the engine's own. In the engine tests the programs, the echo servers and the engine
// are one process, and the product's policy would take every program's socket for one of the
// engine's.
func NewUDPFlowsForTest(h *Handler, write func(data []byte, src net.Destination, dst net.Destination) error) *UDPFlowsForTest {
	policy := defaultUDPFlowPolicy()
	policy.lookup.(*pcblistLookup).engine = 0
	return newUdpConnectionHandlerWithPolicy(h.HandleConnection, write, policy)
}

// NewUDPFlowsOfTheProductForTest is the table as the tun stack builds it (stack_gvisor.go), policy and
// all: the sockets of this process are set aside as the engine's own.
func NewUDPFlowsOfTheProductForTest(h *Handler, write func(data []byte, src net.Destination, dst net.Destination) error) *UDPFlowsForTest {
	return newUdpConnectionHandler(h.HandleConnection, write)
}
