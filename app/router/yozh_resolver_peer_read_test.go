//go:build darwin || freebsd || linux

package router

import (
	"net"
	"os"
	"testing"
)

// Here the listener's user can be read: LOCAL_PEERCRED on macOS and FreeBSD, SO_PEERCRED on Linux
// and Android. The stub is this process's own socket, and it reads as this process's user.
func TestYozhTheResolversPeerIsReadAsThisUser(t *testing.T) {
	stub := StartYozhStub(t)
	conn, err := net.Dial("unix", stub.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := yozhPeerUID(conn)
	if err != nil {
		t.Fatalf("the peer's credentials: %v", err)
	}
	if uid != uint32(os.Geteuid()) {
		t.Fatalf("the peer read as uid %d, want this process's %d", uid, os.Geteuid())
	}
	pipe, other := net.Pipe()
	defer pipe.Close()
	defer other.Close()
	if _, err := yozhPeerUID(pipe); err == nil {
		t.Fatal("a connection that is not a unix socket has no peer to read, and must not pass")
	}
}
