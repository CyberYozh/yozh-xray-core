//go:build !darwin

package tun

import "github.com/xtls/xray-core/common/net"

// NewUDPFlowsForTest is the UDP flow table as the bridge builds it on a platform that has no socket
// table: the platform's policy, which is empty, and the handler's rule for the addresses of fake DNS.
// On darwin the table is the real one, and the constructor is export_udpflow_darwin_test.go's.
func NewUDPFlowsForTest(h *Handler, write func(data []byte, src net.Destination, dst net.Destination) error) *UDPFlowsForTest {
	return newUdpConnectionHandler(h, write)
}
