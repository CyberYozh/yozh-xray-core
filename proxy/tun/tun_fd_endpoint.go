//go:build linux || android

package tun

import (
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// newFDEndpoint serves a TUN file descriptor, opened without packet
// information, through gVisor's fd-based link endpoint. Packets read from
// the descriptor were built by the local kernel, so the stack is told not to
// verify their checksums again, as LinkEndpoint does on other platforms.
// The descriptor stays owned by the caller.
func newFDEndpoint(fd int, mtu uint32) (stack.LinkEndpoint, error) {
	var opts fdbased.Options
	opts.FDs = []int{fd}
	opts.MTU = mtu
	opts.RXChecksumOffload = true
	return fdbased.New(&opts)
}
