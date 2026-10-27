package router_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/infra/conf"
)

// A config's root "env" object is applied with os.Setenv while the config is built (infra/conf,
// Config.Build), before the router exists. Read at that point, YOZH_ROUTING_SOCKET was whatever the
// config said, and a config could name a resolver of its own choosing: one that answers "none" for
// every program turns every per-app rule off. The resolver's socket is the one in the engine's
// environment when it started, whatever a config sets later.
func TestYozhTheResolverSocketIsTheOneTheEngineStartedWith(t *testing.T) {
	ours, theirs := router.StartYozhStub(t), router.StartYozhStub(t)
	ours.Fallback, theirs.Fallback = "rule 1", "none"
	t.Setenv("YOZH_ROUTING_SOCKET", "") // Build below sets it; this puts it back after the test
	router.UseYozhSocketForTest(t, ours.Path)
	router.UseYozhAskTimeoutForTest(t, router.YozhLongAskTimeout)

	var config conf.Config
	if err := json.Unmarshal(fmt.Appendf(nil, `{"log":{"loglevel":"none"},
	  "env":{"YOZH_ROUTING_SOCKET":%q},
	  "routing":{"rules":[
	    {"type":"field","process":["yozh:rule-1"],"outboundTag":"block"},
	    {"type":"field","network":"tcp,udp","outboundTag":"direct"}]}}`, theirs.Path), &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	var routing *router.Config
	for _, app := range built.App {
		instance, err := app.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := instance.(*router.Config); ok {
			routing = r
		}
	}
	if routing == nil {
		t.Fatal("no router in the built config")
	}
	engine := new(router.Router)
	if err := engine.Init(context.Background(), routing, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	target := xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 443)
	route, err := engine.PickRoute(&routing_session.Context{
		Inbound:  &session.Inbound{Tag: "tun", Source: xnet.TCPDestination(xnet.ParseAddress("198.18.0.1"), 42200)},
		Outbound: &session.Outbound{OriginalTarget: target, Target: target},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := route.GetOutboundTag(); got != "block" || len(ours.Questions()) != 1 || len(theirs.Questions()) != 0 {
		t.Fatalf("went %s; the engine's resolver was asked %d times, the config's %d times", got, len(ours.Questions()), len(theirs.Questions()))
	}
}
