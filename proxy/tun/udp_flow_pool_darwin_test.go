//go:build darwin

package tun

import (
	"os"
	"testing"
)

// The two constructors the engine tests build their tables by (export_udpflow_darwin_test.go) are the
// bridge's function with darwin's policy: each gives the table the handler's rule for the addresses of
// fake DNS and keeps the policy whole. They differ in one thing, whose sockets are the engine's own:
// none in NewUDPFlowsForTest, those of this process in the product's. The tests of udp_flow_test.go
// run on every platform, and off darwin they compare empty policies; this is where the rule meets a
// real one.
func TestUDPFlowTheEngineTestsTablesCarryTheFakeDNSRuleAndDarwinsPolicy(t *testing.T) {
	handler := &Handler{fakeDNS: &stubFakeDNS{pool: testPool}}
	platform := defaultUDPFlowPolicy()
	for _, c := range []struct {
		name   string
		table  *UDPFlowsForTest
		engine int32 // the pid whose sockets the table sets aside as the engine's own; 0: none
	}{
		{"NewUDPFlowsForTest", NewUDPFlowsForTest(handler, discardReplies), 0},
		{"NewUDPFlowsOfTheProductForTest", NewUDPFlowsOfTheProductForTest(handler, discardReplies), int32(os.Getpid())},
	} {
		policy := c.table.policy
		if policy.ownFlow == nil || !policy.ownFlow(poolA) || policy.ownFlow(realA) {
			t.Errorf("%s: the table has no own-flow rule of fake DNS", c.name)
		}
		if lookup, ok := policy.lookup.(*pcblistLookup); !ok || lookup.read == nil || lookup.engine != c.engine {
			t.Errorf("%s: the socket table is %+v, want the kernel's, with the sockets of pid %d set aside", c.name, policy.lookup, c.engine)
		}
		if policy.window != platform.window || policy.silence != platform.silence || policy.recheck != platform.recheck || policy.idle == nil {
			t.Errorf("%s: the policy has window %v, silence %v, re-check %v, idle %v; darwin's has %v, %v, %v, %v",
				c.name, policy.window, policy.silence, policy.recheck, policy.idle != nil,
				platform.window, platform.silence, platform.recheck, platform.idle != nil)
		}
	}
}
