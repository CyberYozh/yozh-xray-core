package router_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"testing"

	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

// yozhVolleyRouting is the shape of the app's direct-by-default config (the corpus's rows, trimmed
// to the labels): a program's rule before the failure's row, the failure's row before later rules,
// and the tail direct. %s is where a failure goes: the base proxy, or block in strict mode.
const yozhVolleyRouting = `{"domainStrategy":"AsIs","rules":[
  {"type":"field","inboundTag":["api"],"outboundTag":"api"},
  {"type":"field","port":"53","network":"tcp,udp","outboundTag":"dns-out"},
  {"type":"field","process":["yozh:rule-0"],"outboundTag":"direct"},
  {"type":"field","process":["yozh:rule-1","yozh:rule-6"],"outboundTag":"block"},
  {"type":"field","process":["yozh:rule-2"],"network":"udp","outboundTag":"app-p-alpha-udp"},
  {"type":"field","process":["yozh:rule-2"],"network":"tcp","outboundTag":"app-p-alpha"},
  {"type":"field","process":["yozh:unresolved"],"outboundTag":"%s"},
  {"type":"field","process":["yozh:nolocal"],"outboundTag":"proxy"},
  {"type":"field","process":["yozh:rule-4"],"outboundTag":"app-p-alpha"},
  {"type":"field","network":"tcp,udp","outboundTag":"direct"}]}`

// A volley of connections through the real router, built from config as the engine builds it: every
// first question times out (a resolver swamped by the volley), and asked again the resolver would
// name the program's block rule. Each connection's verdict is its first answer, "failed", at every
// label of its pass: it goes where a failure goes — never to the direct tail, strict mode or not —
// and it is asked about once.
func TestYozhAVolleyOfPassesKeepsEachFirstAnswer(t *testing.T) {
	for _, c := range []struct {
		name, failure string
	}{
		{"direct-by-default", "proxy"},
		{"direct-by-default-strict", "block"},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := router.StartYozhStub(t)
			router.UseYozhSocketForTest(t, stub.Path)
			stub.Fallback = "silent"
			stub.Repeat = "rule 1"

			var routing conf.RouterConfig
			if err := json.Unmarshal(fmt.Appendf(nil, yozhVolleyRouting, c.failure), &routing); err != nil {
				t.Fatal(err)
			}
			config, err := routing.Build()
			if err != nil {
				t.Fatal(err)
			}
			engine := new(router.Router)
			if err := engine.Init(context.Background(), config, nil, nil, nil); err != nil {
				t.Fatal(err)
			}

			const passes = 5000
			went := make([]string, passes)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range passes {
				wg.Add(1)
				go func() {
					defer wg.Done()
					network := xnet.Network_TCP
					if i%2 == 1 {
						network = xnet.Network_UDP
					}
					source := netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), uint16(20000+i))
					target := xnet.Destination{Network: network, Address: xnet.ParseAddress("192.0.2.1"), Port: 443}
					ctx := &routing_session.Context{
						Inbound: &session.Inbound{
							Tag:    "tun",
							Source: xnet.Destination{Network: network, Address: xnet.IPAddress(source.Addr().AsSlice()), Port: xnet.Port(source.Port())},
						},
						Outbound: &session.Outbound{OriginalTarget: target, Target: target},
					}
					<-start
					route, err := engine.PickRoute(ctx)
					if err != nil {
						went[i] = "(no route)"
						return
					}
					went[i] = route.GetOutboundTag()
				}()
			}
			close(start)
			wg.Wait()

			tally := map[string]int{}
			for _, tag := range went {
				tally[tag]++
			}
			asked := map[string]int{}
			for _, question := range stub.Questions() {
				asked[question]++
			}
			askedAgain := 0
			for _, n := range asked {
				if n > 1 {
					askedAgain++
				}
			}
			t.Logf("%d passes went %v; %d connections asked about, %d of them more than once", passes, tally, len(asked), askedAgain)
			tags := make([]string, 0, len(tally))
			for tag := range tally {
				tags = append(tags, tag)
			}
			sort.Strings(tags)
			for _, tag := range tags {
				if tag != c.failure {
					t.Errorf("%d of %d passes went %s, want every one to go where a failure goes (%s)", tally[tag], passes, tag, c.failure)
				}
			}
			if askedAgain > 0 {
				t.Errorf("%d connections were asked about more than once in their one pass", askedAgain)
			}
		})
	}
}
