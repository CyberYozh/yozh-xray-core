package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// tunTLSContext is the routing context of a TLS connection from the tun inbound, as in the
// example start event: a TEST-NET source, the sniffed name over a TEST-NET address.
func tunTLSContext() *routing_session.Context {
	return &routing_session.Context{
		Inbound: &session.Inbound{
			Tag: "tun", Name: "tun",
			Source: xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 53811),
			User:   &protocol.MemoryUser{Level: 0},
		},
		Outbound: &session.Outbound{
			OriginalTarget: xnet.TCPDestination(xnet.ParseAddress("203.0.113.10"), 443),
			Target:         xnet.TCPDestination(xnet.ParseAddress("example.com"), 443),
		},
		Content: &session.Content{Protocol: "tls"},
	}
}

// The body a rule without reportEnd sends, pinned on the code before the change: it must not move
// by a byte. If this test fails on the unchanged tree, the string below is replaced by the body it
// prints there — that output is the definition of the golden body.
const goldenStartBody = `{"email":null,"level":0,"protocol":"tls","network":"tcp","source":"192.0.2.1:53811",` +
	`"destination":"example.com:443","originalTarget":"tcp:203.0.113.10:443","routeTarget":null,` +
	`"inboundTag":"tun","inboundName":"tun","inboundLocal":null,"outboundTag":"proxy","ts":1790000000}`

func TestWithoutReportEndTheBodyIsWhatItWas(t *testing.T) {
	ev := buildEvent(tunTLSContext(), "proxy")
	ev.Timestamp = 1790000000
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != goldenStartBody {
		t.Fatalf("body\n  %s\nwant\n  %s", body, goldenStartBody)
	}
}

// postSpy is a webhook receiver: it keeps the bodies in arrival order and answers 204.
type postSpy struct {
	mu      sync.Mutex
	bodies  []string
	rules   map[string]map[string]bool // X-Rule header -> remote addresses seen
	hold    chan struct{}              // when set, the first request waits on it
	entered chan struct{}
	fail    int // the first `fail` requests are cut without an answer
	server  *httptest.Server
}

func newPostSpy(t *testing.T) *postSpy {
	s := &postSpy{rules: map[string]map[string]bool{}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		cut := s.fail > 0
		if cut {
			s.fail--
		}
		hold := s.hold
		s.hold = nil
		if rule := r.Header.Get("X-Rule"); rule != "" {
			if s.rules[rule] == nil {
				s.rules[rule] = map[string]bool{}
			}
			s.rules[rule][r.RemoteAddr] = true
		}
		s.mu.Unlock()
		if hold != nil {
			s.entered <- struct{}{}
			<-hold
		}
		if cut {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		s.mu.Lock()
		s.bodies = append(s.bodies, string(body))
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *postSpy) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := append([]string(nil), s.bodies...)
		s.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("fewer than %d bodies arrived", n)
	return nil
}

func reportingNotifier(t *testing.T, url string, headers map[string]string) *WebhookNotifier {
	t.Helper()
	h, err := NewWebhookNotifier(&WebhookConfig{Url: url, ReportEnd: true, Headers: headers})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("%v in %s", err, body)
	}
	return m
}

func endOf(conn uint64) routing.ConnEnd {
	return routing.ConnEnd{Conn: conn, FirstDownMs: -1, LastUpMs: -1, LastDownMs: -1}
}

func TestWithoutReportEndFireGoesTheOldWay(t *testing.T) {
	spy := newPostSpy(t)
	h, err := NewWebhookNotifier(&WebhookConfig{Url: spy.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.Fire(tunTLSContext(), "proxy")
	body := spy.waitFor(t, 1)[0]
	if h.yozh.items != nil {
		t.Fatal("a rule without reportEnd started the queue")
	}
	for _, key := range []string{`"kind"`, `"conn"`, `"tsMs"`, `"lost"`} {
		if strings.Contains(body, key) {
			t.Fatalf("%s in %s", key, body)
		}
	}
}

func TestWithReportEndTheStartAndTheRouteCarryTheirConn(t *testing.T) {
	spy := newPostSpy(t)
	h := reportingNotifier(t, spy.server.URL, nil)
	ctx := tunTLSContext()
	_, ctx.Report = session.WithConnReport(t.Context())
	h.Fire(ctx, "proxy")
	probe := *ctx
	probe.Probe = true
	h.Fire(&probe, "proxy")

	bodies := spy.waitFor(t, 2)
	start, route := decode(t, bodies[0]), decode(t, bodies[1])
	if start["kind"] != "start" || route["kind"] != "route" {
		t.Fatalf("kinds %v and %v", start["kind"], route["kind"])
	}
	for _, m := range []map[string]any{start, route} {
		if uint64(m["conn"].(float64)) != ctx.Report.Conn || m["tsMs"].(float64) <= 0 {
			t.Fatalf("conn or tsMs wrong in %v", m)
		}
		if _, lost := m["lost"]; lost {
			t.Fatalf("lost without a loss in %v", m)
		}
		if m["destination"] != "example.com:443" {
			t.Fatalf("the start lost its old fields: %v", m)
		}
	}
}

func TestTheEndCarriesNumbersOnly(t *testing.T) {
	spy := newPostSpy(t)
	h := reportingNotifier(t, spy.server.URL, nil)
	h.FireEnd(routing.ConnEnd{
		Conn: 1841, TsMs: 1790000042917, DurMs: 42799, FirstDownMs: 187,
		LastUpMs: 40902, LastDownMs: 42672, Up: 18233, Down: 1402117,
	})
	h.FireEnd(routing.ConnEnd{
		Conn: 1907, TsMs: 1790000060311, DurMs: 1204, FirstDownMs: -1,
		LastUpMs: 3, LastDownMs: -1, Up: 517, Error: "udp-not-supported",
	})

	bodies := spy.waitFor(t, 2)
	want := []string{
		`{"kind":"end","conn":1841,"tsMs":1790000042917,"durMs":42799,"firstDownMs":187,"lastUpMs":40902,"lastDownMs":42672,"up":18233,"down":1402117}`,
		`{"kind":"end","conn":1907,"tsMs":1790000060311,"durMs":1204,"lastUpMs":3,"up":517,"down":0,"error":"udp-not-supported"}`,
	}
	for i := range want {
		if bodies[i] != want[i] {
			t.Fatalf("end %d\n  %s\nwant\n  %s", i, bodies[i], want[i])
		}
	}
}

// 10 000 pairs through one rule: every end after its start, and no goroutine per event. The
// producer waits now and then so that the queue (1024) never overflows: a loss is another test.
func TestStartsAndEndsStayInOrderThroughOneRule(t *testing.T) {
	spy := newPostSpy(t)
	h := reportingNotifier(t, spy.server.URL, nil)
	before := runtime.NumGoroutine()
	const pairs = 10000
	for i := 1; i <= pairs; i++ {
		ctx := tunTLSContext()
		_, ctx.Report = session.WithConnReport(t.Context())
		h.Fire(ctx, "proxy")
		h.FireEnd(endOf(ctx.Report.Conn))
		if i%100 == 0 {
			spy.waitFor(t, 2*i-512)
		}
		if i%1000 == 0 {
			if grown := runtime.NumGoroutine() - before; grown > 8 {
				t.Fatalf("%d goroutines more after %d pairs: a goroutine per event", grown, i)
			}
		}
	}
	bodies := spy.waitFor(t, 2*pairs)
	started := map[uint64]bool{}
	for _, body := range bodies {
		m := decode(t, body)
		conn := uint64(m["conn"].(float64))
		if m["kind"] == "end" && !started[conn] {
			t.Fatalf("the end of %d came before its start", conn)
		}
		started[conn] = true
	}
}

func TestTheWorkerIsLazyAndLeavesOnClose(t *testing.T) {
	spy := newPostSpy(t)
	before := runtime.NumGoroutine()
	h, err := NewWebhookNotifier(&WebhookConfig{Url: spy.server.URL, ReportEnd: true})
	if err != nil {
		t.Fatal(err)
	}
	// > and not !=: goroutines of earlier tests may leave between the two counts.
	if runtime.NumGoroutine() > before {
		t.Fatal("a notifier with nothing to send holds a goroutine")
	}
	h.FireEnd(endOf(1))
	spy.waitFor(t, 1)
	h.Close()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before {
		t.Fatalf("%d goroutines left after Close", runtime.NumGoroutine()-before)
	}
}

func TestEachRuleKeepsOneConnection(t *testing.T) {
	spy := newPostSpy(t)
	const rules, events = 3, 200
	var wg sync.WaitGroup
	for r := 0; r < rules; r++ {
		h := reportingNotifier(t, spy.server.URL, map[string]string{"X-Rule": string(rune('a' + r))})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < events; i++ {
				h.FireEnd(endOf(uint64(i + 1)))
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()
	spy.waitFor(t, rules*events)
	spy.mu.Lock()
	defer spy.mu.Unlock()
	if len(spy.rules) != rules {
		t.Fatalf("%d rules seen, want %d", len(spy.rules), rules)
	}
	for rule, conns := range spy.rules {
		if len(conns) != 1 {
			t.Fatalf("rule %s used %d connections for %d events", rule, len(conns), events)
		}
	}
}

func TestAFullQueueDropsAndCountsWhatDidNotFit(t *testing.T) {
	spy := newPostSpy(t)
	release := make(chan struct{})
	spy.hold, spy.entered = release, make(chan struct{}, 1)
	h := reportingNotifier(t, spy.server.URL, nil)

	h.FireEnd(endOf(1))
	<-spy.entered // the worker holds the first event; the queue is empty again
	const dropped = 5
	for i := 0; i < yozhQueueSize+dropped; i++ {
		h.FireEnd(endOf(uint64(i + 2)))
	}
	if got := h.yozh.lost.Load(); got != dropped {
		t.Fatalf("lost %d, want %d", got, dropped)
	}
	close(release)

	bodies := spy.waitFor(t, 2)
	if decode(t, bodies[0])["lost"] != nil {
		t.Fatalf("the held event carries a loss: %s", bodies[0])
	}
	if got := decode(t, bodies[1])["lost"]; got != float64(dropped) {
		t.Fatalf("the next body carries lost %v, want %d", got, dropped)
	}
}

func TestAFailedPostIsCountedInTheNextBody(t *testing.T) {
	spy := newPostSpy(t)
	spy.fail = 1
	h := reportingNotifier(t, spy.server.URL, nil)
	h.FireEnd(endOf(1))
	h.FireEnd(endOf(2))

	body := decode(t, spy.waitFor(t, 1)[0])
	if body["conn"] != float64(2) || body["lost"] != float64(1) {
		t.Fatalf("the body after a cut POST: %v", body)
	}
}

// webhookRule is a rule with a webhook on url that reports ends or not. Nothing is sent until a
// dispatch matches it.
func webhookRule(tag, url string, reportEnd bool) *RoutingRule {
	return &RoutingRule{
		TargetTag: &RoutingRule_Tag{Tag: "proxy"},
		Networks:  []xnet.Network{xnet.Network_TCP},
		RuleTag:   tag,
		Webhook:   &WebhookConfig{Url: url, ReportEnd: reportEnd},
	}
}

const silentURL = "http://127.0.0.1:9/e"

func loudRule(tag string) *RoutingRule  { return webhookRule(tag, silentURL, true) }
func quietRule(tag string) *RoutingRule { return webhookRule(tag, silentURL, false) }

func plainRule(tag string) *RoutingRule {
	rule := quietRule(tag)
	rule.Webhook = nil
	return rule
}

func initRouter(t *testing.T, rules ...*RoutingRule) *Router {
	t.Helper()
	r := new(Router)
	if err := r.Init(t.Context(), &Config{Rule: rules}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// askReportsEnd asks from another goroutine, as a dispatch does.
func askReportsEnd(r *Router) <-chan bool {
	answer := make(chan bool, 1)
	go func() { answer <- r.ReportsEnd() }()
	return answer
}

// A dispatch asks ReportsEnd on every Dispatch and DispatchLink. ReloadRules and RemoveRule hold
// r.mu while they build conditions and close notifiers (a Close waits up to 5 s for a POST): an
// answer that waited for r.mu would stall the packet path, with reportEnd or without it.
func TestReportsEndDoesNotWaitForTheRouterLock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []*RoutingRule
		want  bool
	}{
		{"a rule reports ends", []*RoutingRule{plainRule("a"), loudRule("b")}, true},
		{"no rule reports ends", []*RoutingRule{plainRule("a"), quietRule("b")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := initRouter(t, tc.rules...)
			r.mu.Lock()
			answer := askReportsEnd(r)
			select {
			case got := <-answer:
				r.mu.Unlock()
				if got != tc.want {
					t.Fatalf("ReportsEnd %v, want %v", got, tc.want)
				}
			case <-time.After(100 * time.Millisecond):
				r.mu.Unlock()
				<-answer
				t.Fatal("ReportsEnd waits for the router lock")
			}
		})
	}
}

// The case the lock test stands for: a reload whose old rule closes while its receiver holds a POST.
func TestReportsEndDoesNotWaitForAReload(t *testing.T) {
	spy := newPostSpy(t)
	release := make(chan struct{})
	spy.hold, spy.entered = release, make(chan struct{}, 1)
	r := initRouter(t, webhookRule("a", spy.server.URL, true))
	r.rules[0].Webhook.FireEnd(endOf(1))
	<-spy.entered // the worker's POST waits in the receiver; closing rule a waits for it

	reloaded := make(chan error, 1)
	go func() { reloaded <- r.ReloadRules(&Config{Rule: []*RoutingRule{quietRule("b")}}, false) }()
	for r.mu.TryLock() { // until the reload holds the lock
		r.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	answer := askReportsEnd(r)
	select {
	case <-answer:
		close(release)
	case <-time.After(100 * time.Millisecond):
		close(release)
		<-answer
		t.Error("ReportsEnd waits for a reload")
	}
	if err := <-reloaded; err != nil {
		t.Fatal(err)
	}
	if r.ReportsEnd() {
		t.Fatal("after the reload no rule reports ends")
	}
}

// ReportsEnd answers for the rule set as each change leaves it, failed changes included.
func TestReportsEndFollowsEveryChangeOfTheRules(t *testing.T) {
	expect := func(t *testing.T, r *Router, want bool, after string) {
		t.Helper()
		if got := r.ReportsEnd(); got != want {
			t.Fatalf("after %s: ReportsEnd %v, want %v", after, got, want)
		}
	}
	t.Run("Init", func(t *testing.T) {
		expect(t, initRouter(t, plainRule("a"), quietRule("b")), false, "Init without reportEnd")
		expect(t, initRouter(t, plainRule("a"), loudRule("b")), true, "Init with reportEnd")
		expect(t, initRouter(t), false, "Init without rules")
	})
	t.Run("AddRule and RemoveRule", func(t *testing.T) {
		r := initRouter(t, quietRule("a"))
		if err := r.AddRule(serial.ToTypedMessage(&Config{Rule: []*RoutingRule{loudRule("b")}}), true); err != nil {
			t.Fatal(err)
		}
		expect(t, r, true, "AddRule of a rule with reportEnd")
		if err := r.RemoveRule("b"); err != nil {
			t.Fatal(err)
		}
		expect(t, r, false, "RemoveRule of the rule with reportEnd")
	})
	t.Run("ReloadRules", func(t *testing.T) {
		r := initRouter(t, quietRule("a"))
		if err := r.ReloadRules(&Config{Rule: []*RoutingRule{loudRule("b")}}, false); err != nil {
			t.Fatal(err)
		}
		expect(t, r, true, "a reload to a rule with reportEnd")
		if err := r.ReloadRules(&Config{Rule: []*RoutingRule{quietRule("c")}}, false); err != nil {
			t.Fatal(err)
		}
		expect(t, r, false, "a reload to a rule without reportEnd")
	})
	t.Run("a failed append keeps the rules it found", func(t *testing.T) {
		r := initRouter(t, quietRule("a"))
		if err := r.ReloadRules(&Config{Rule: []*RoutingRule{loudRule("b"), quietRule("a")}}, true); err == nil {
			t.Fatal("a duplicate ruleTag was accepted")
		}
		expect(t, r, false, "a failed append of a rule with reportEnd")
	})
	t.Run("a failed reload drops the old rules", func(t *testing.T) {
		r := initRouter(t, loudRule("a"))
		if err := r.ReloadRules(&Config{Rule: []*RoutingRule{quietRule("x"), quietRule("x")}}, false); err == nil {
			t.Fatal("a duplicate ruleTag was accepted")
		}
		expect(t, r, false, "a failed reload that closed the rule with reportEnd")
	})
	var _ routing.EndReporting = new(Router)
}

func TestARouteSendsItsEndThroughItsRule(t *testing.T) {
	spy := newPostSpy(t)
	h := reportingNotifier(t, spy.server.URL, nil)
	var reporter routing.ConnEndReporter = &Route{webhook: h}
	reporter.ReportEnd(endOf(9))
	(&Route{}).ReportEnd(endOf(10))
	if got := decode(t, spy.waitFor(t, 1)[0])["conn"]; got != float64(9) {
		t.Fatalf("conn %v", got)
	}
}

// Cookie and Authorization of a plain HTTP request sit in Content.Attributes: no body reads them.
func TestContentAttributesReachNoBody(t *testing.T) {
	spy := newPostSpy(t)
	h := reportingNotifier(t, spy.server.URL, nil)
	ctx := tunTLSContext()
	ctx.Content.Attributes = map[string]string{"Cookie": "fixture-cookie-7", "Authorization": "Bearer fixture-token-7", ":path": "/fixture-path-7"}
	_, ctx.Report = session.WithConnReport(t.Context())
	h.Fire(ctx, "proxy")
	h.FireEnd(endOf(ctx.Report.Conn))
	for _, body := range spy.waitFor(t, 2) {
		if strings.Contains(body, "fixture-") {
			t.Fatalf("an attribute in %s", body)
		}
	}
}
