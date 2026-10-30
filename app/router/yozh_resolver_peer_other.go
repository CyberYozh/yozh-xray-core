//go:build !darwin && !freebsd && !linux

package router

import (
	"net"
)

// yozhPeerUID elsewhere: there is no peer credential to read here, and a resolver whose user cannot
// be read is not trusted — a config with yozh labels refuses to start on this platform.
func yozhPeerUID(net.Conn) (uint32, error) {
	return 0, errYozhPeerUnreadable
}
