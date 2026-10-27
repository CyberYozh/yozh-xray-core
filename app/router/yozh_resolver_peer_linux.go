//go:build linux

package router

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

// yozhPeerUID reads the user of the socket at the other end of conn: SO_PEERCRED, the peer's
// credentials as the kernel keeps them, not anything the peer says about itself.
func yozhPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("the routing resolver connection is not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}
