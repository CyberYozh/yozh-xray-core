//go:build darwin || freebsd

package router

import (
	"testing"

	"golang.org/x/sys/unix"
)

// LOCAL_PEERCRED hands back a struct xucred whose first field names its layout. The engine reads
// the user out of the one layout it knows, XUCRED_VERSION, and refuses any other, as libc's
// getpeereid does: a struct of another layout could hold anything where the user is read.
func TestYozhAPeerCredentialOfAnotherLayoutIsRefused(t *testing.T) {
	if uid, err := yozhXucredUID(&unix.Xucred{Version: yozhXucredVersion, Uid: 4242}); err != nil || uid != 4242 {
		t.Fatalf("a credential of the known layout: uid %d, %v; want 4242", uid, err)
	}
	for _, version := range []uint32{yozhXucredVersion + 1, 0xffffffff} {
		if uid, err := yozhXucredUID(&unix.Xucred{Version: version, Uid: 4242}); err == nil {
			t.Errorf("a credential of layout version %d was read as uid %d, want it refused", version, uid)
		}
	}
}
