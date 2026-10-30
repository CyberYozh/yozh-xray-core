//go:build !darwin && !freebsd && !linux

package router

import (
	"errors"
	"testing"
)

// Here the listener's user cannot be read, and the engine trusts no resolver: a config with yozh
// labels refuses to start. The resolver's other tests let the stub they started through
// (yozhLetTheStubThrough); this socket is not one of them.
func TestYozhNoResolverIsTrustedWhereItsUserCannotBeRead(t *testing.T) {
	listener, path := yozhListen(t)
	t.Cleanup(func() { listener.Close() })
	UseYozhSocketForTest(t, path)
	if _, err := newProcessCondition([]string{"yozh:rule-1"}); !errors.Is(err, errYozhPeerUnreadable) {
		t.Fatalf("a config with yozh labels: %v, want it refused as unreadable", err)
	}
}
