package router_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

// The shared corpus of per-app routing (app-routing-corpus.json) comes from the macOS client's
// config builder: each case gives the `routing` the builder writes for its `input`, and the
// builder's own tests hold it to that. Here the same `routing` goes through the REAL router —
// infra/conf's parser, Router.Init, PickRoute — with a stub resolver answering each case's
// `answer`, and every case must land on its `expect`. Together the two halves say: the rule order
// the client specifies is the order the engine walks.
//
// The contexts are the dispatcher's: OriginalTarget is the address the application dialled, and a
// case with `sniffedDomain` has Target replaced by that name, as sniffing with routeOnly=false
// leaves it (app/dispatcher/default.go) — so no `ip` rule can match it, exactly as in the tunnel.
type yozhCorpus struct {
	Format   int `json:"format"`
	Variants []struct {
		Name    string           `json:"name"`
		Routing json.RawMessage  `json:"routing"`
		Cases   []yozhCorpusCase `json:"cases"`
	} `json:"variants"`
}

type yozhCorpusCase struct {
	Name           string `json:"name"`
	Network        string `json:"network"`
	Source         string `json:"source"`
	OriginalTarget string `json:"originalTarget"`
	SniffedDomain  string `json:"sniffedDomain"`
	Answer         string `json:"answer"`
	Expect         string `json:"expect"`
	Questions      int    `json:"questions"`
	Why            string `json:"why"`
}

// stubAnswer is what the stub answers the case's question with. A case whose resolver is "silent"
// is answered "failed": a question nobody answers becomes exactly that verdict when its timeout
// passes (TestYozhASilentResolverIsAFailureWithinFiftyMilliseconds), and here the stub says so at
// once, so that no case waits on the clock.
func (c yozhCorpusCase) stubAnswer() string {
	if c.Answer == "silent" {
		return "failed"
	}
	return c.Answer
}

// question is the case as the resolver sees it, without the number.
func (c yozhCorpusCase) question() string {
	source := netip.MustParseAddrPort(c.Source)
	target := netip.MustParseAddrPort(c.OriginalTarget)
	return fmt.Sprintf("%s %s %d %s %d", c.Network, source.Addr(), source.Port(), target.Addr(), target.Port())
}

func (c yozhCorpusCase) context(t *testing.T) *routing_session.Context {
	var network xnet.Network
	switch c.Network {
	case "tcp":
		network = xnet.Network_TCP
	case "udp":
		network = xnet.Network_UDP
	default:
		t.Fatalf("%s: network %q", c.Name, c.Network)
	}
	source := netip.MustParseAddrPort(c.Source)
	target := netip.MustParseAddrPort(c.OriginalTarget)
	original := xnet.Destination{Network: network, Address: xnet.IPAddress(target.Addr().AsSlice()), Port: xnet.Port(target.Port())}
	outbound := &session.Outbound{OriginalTarget: original, Target: original}
	if c.SniffedDomain != "" {
		outbound.Target = xnet.Destination{Network: network, Address: xnet.DomainAddress(c.SniffedDomain), Port: original.Port}
	}
	return &routing_session.Context{
		Inbound: &session.Inbound{
			Tag:    "tun",
			Source: xnet.Destination{Network: network, Address: xnet.IPAddress(source.Addr().AsSlice()), Port: xnet.Port(source.Port())},
		},
		Outbound: outbound,
	}
}

func TestYozhCorpusThroughTheRealRouter(t *testing.T) {
	path := os.Getenv("YOZH_ROUTING_CORPUS")
	if path == "" {
		t.Skip("YOZH_ROUTING_CORPUS is not set: point it at an " +
			"app-routing-corpus.json to run this test")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus yozhCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != 1 || len(corpus.Variants) == 0 {
		t.Fatalf("corpus format %d with %d variants: this test reads format 1", corpus.Format, len(corpus.Variants))
	}
	for _, variant := range corpus.Variants {
		t.Run(variant.Name, func(t *testing.T) {
			stub := router.StartYozhStub(t)
			router.UseYozhSocketForTest(t, stub.Path)
			router.UseYozhAskTimeoutForTest(t, router.YozhLongAskTimeout)
			for _, c := range variant.Cases {
				stub.Answer(c.question(), c.stubAnswer())
			}
			var routing conf.RouterConfig
			if err := json.Unmarshal(variant.Routing, &routing); err != nil {
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
			for _, c := range variant.Cases {
				route, err := engine.PickRoute(c.context(t))
				got := "(no route: " + fmt.Sprint(err) + ")"
				if err == nil {
					got = route.GetOutboundTag()
				}
				if got != c.Expect {
					t.Errorf("%s: went to %s, want %s (%s)", c.Name, got, c.Expect, c.Why)
				}
				// Counted by the question's text: every case of a variant asks about addresses of its
				// own, so no other case's question is counted as this one's.
				asked := 0
				for _, question := range stub.Questions() {
					if question == c.question() {
						asked++
					}
				}
				if asked != c.Questions {
					t.Errorf("%s: the resolver was asked %d times, want %d", c.Name, asked, c.Questions)
				}
			}
		})
	}
}
