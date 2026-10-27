//go:build darwin || freebsd

package router

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

// yozhPeerUID reads the user of the socket at the other end of conn: LOCAL_PEERCRED, which on the
// connecting side gives the server's effective credentials as they were when it called listen(2),
// and which the other party cannot influence (unix(4)).
func yozhPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("the routing resolver connection is not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return yozhXucredUID(cred)
}

// yozhXucredVersion is XUCRED_VERSION of sys/ucred.h, the same on macOS and FreeBSD.
const yozhXucredVersion = 0

// yozhXucredUID reads the user out of a struct xucred only when its layout is the one this code
// knows (cr_version == XUCRED_VERSION), and refuses any other, as libc's getpeereid does.
func yozhXucredUID(cred *unix.Xucred) (uint32, error) {
	if cred.Version != yozhXucredVersion {
		return 0, errors.New("the routing resolver's credentials are of an unknown layout")
	}
	return cred.Uid, nil
}
