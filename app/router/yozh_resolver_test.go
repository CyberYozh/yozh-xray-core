package router

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"weak"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// ---- The stub resolver (exported: yozh_corpus_test.go, package router_test, uses it too) -----

// YozhStub plays the app's root component: a routing resolver on a temporary unix socket. It
// answers each question by its text without the number ("tcp 198.18.0.1 40001 192.0.2.1 443"):
//
//	"rule N" | "none" | "failed" | "nolocal"  answered at once
//	"silent"                                   never answered
//	"late <answer>"                            answered when the test calls SendLate
//	"raw:<text>"                               <text> sent verbatim, "{id}" replaced by the number
//
// A question with no answer set gets Fallback ("none" unless changed). Repeat, when set, answers
// every question the stub has been asked before, whatever else is set: a resolver whose verdict
// for a connection changed between two questions about it. ReverseBatch > 0 holds that many
// questions and answers them last-first — the proof that answers are matched by number.
type YozhStub struct {
	Path string

	listener     net.Listener
	mu           sync.Mutex
	answers      map[string]string
	asked        map[string]int
	Fallback     string
	Repeat       string
	ReverseBatch int
	held         []func()
	late         []func()
	questions    []string
	connections  int
	open         []net.Conn
}

// StartYozhStub listens on a fresh socket and closes it when the test ends.
func StartYozhStub(t testing.TB) *YozhStub {
	t.Helper()
	listener, path := yozhListen(t)
	yozhLetTheStubThrough(t, path)
	stub := &YozhStub{Path: path, listener: listener, answers: map[string]string{}, asked: map[string]int{}, Fallback: "none"}
	t.Cleanup(stub.Close)
	go stub.serve()
	return stub
}

// yozhListen listens on a fresh unix socket, removed when the test ends. The directory is made with
// os.MkdirTemp("", …), not t.TempDir(): a unix socket path must fit sun_path (104 bytes on macOS),
// and t.TempDir() adds the test's name.
func yozhListen(t testing.TB) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "yozh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "r.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener, path
}

// yozhLetTheStubThrough: where the listener's user cannot be read, the engine refuses every
// resolver (errYozhPeerUnreadable), and a test whose subject is anything else about the resolver
// could not raise one. For as long as the test runs, the stub it started at path gets past that one
// refusal and nothing else: the engine's own check runs first, and its verdict stands for any other
// socket, for a stub read as another user, and wherever the user can be read.
func yozhLetTheStubThrough(t testing.TB, path string) {
	t.Helper()
	previous := yozhPeerCheck
	yozhPeerCheck = func(r *yozhResolver, conn net.Conn) error {
		err := previous(r, conn)
		if err != nil && r.path == path && errors.Is(err, errYozhPeerUnreadable) {
			return nil
		}
		return err
	}
	t.Cleanup(func() { yozhPeerCheck = previous })
}

func (s *YozhStub) Answer(question, answer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[question] = answer
}

func (s *YozhStub) Questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.questions...)
}

func (s *YozhStub) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections
}

// SendLate sends the answers of the "late <answer>" questions read so far, in the order they came.
func (s *YozhStub) SendLate() {
	s.mu.Lock()
	late := s.late
	s.late = nil
	s.mu.Unlock()
	for _, send := range late {
		send()
	}
}

// DropConnections closes every accepted connection, as a restarting resolver would.
func (s *YozhStub) DropConnections() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conn := range s.open {
		conn.Close()
	}
	s.open = nil
}

func (s *YozhStub) Close() {
	s.listener.Close()
	s.DropConnections()
}

func (s *YozhStub) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connections++
		s.open = append(s.open, conn)
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *YozhStub) handle(conn net.Conn) {
	var writing sync.Mutex
	write := func(text string) {
		writing.Lock()
		defer writing.Unlock()
		io.WriteString(conn, text)
	}
	lines := bufio.NewScanner(conn)
	for lines.Scan() {
		id, question, ok := strings.Cut(lines.Text(), " q ")
		if !ok {
			continue
		}
		s.mu.Lock()
		s.questions = append(s.questions, question)
		s.asked[question]++
		answer, set := s.answers[question]
		if !set {
			answer = s.Fallback
		}
		if s.Repeat != "" && s.asked[question] > 1 {
			answer = s.Repeat
		}
		var send func()
		switch {
		case answer == "silent":
		case strings.HasPrefix(answer, "late "):
			late := strings.TrimPrefix(answer, "late ")
			s.late = append(s.late, func() { write(id + " a " + late + "\n") })
		case strings.HasPrefix(answer, "raw:"):
			raw := strings.ReplaceAll(strings.TrimPrefix(answer, "raw:"), "{id}", id)
			send = func() { write(raw + "\n") }
		default:
			send = func() { write(id + " a " + answer + "\n") }
		}
		if s.ReverseBatch > 0 && send != nil {
			s.held = append(s.held, send)
			if len(s.held) < s.ReverseBatch {
				s.mu.Unlock()
				continue
			}
			batch := s.held
			s.held = nil
			s.mu.Unlock()
			for i := len(batch) - 1; i >= 0; i-- {
				batch[i]()
			}
			continue
		}
		s.mu.Unlock()
		if send != nil {
			send()
		}
	}
}

// UseYozhSocketForTest points the engine's routing resolver at path for the rest of the test, as
// YOZH_ROUTING_SOCKET in the engine's environment at start does. Setting the variable in a test does
// nothing: the engine read it once, when the test binary started.
func UseYozhSocketForTest(t testing.TB, path string) {
	t.Helper()
	previous := yozhSocketPath
	yozhSocketPath = path
	t.Cleanup(func() { yozhSocketPath = previous })
}

// YozhLongAskTimeout is the ask timeout of the tests whose subject is not the timeout. A question
// the stub answers returns as soon as the answer comes, so it costs such a test nothing; it only
// keeps a busy machine, one that takes more than the engine's 50 ms to hand an answer over, from
// failing a question that was answered. A failure such a test needs comes from the stub ("failed"),
// never from the timeout.
const YozhLongAskTimeout = 10 * time.Second

// UseYozhAskTimeoutForTest sets the ask timeout of the resolver the engine builds for its config
// (newProcessCondition) for the rest of the test. It takes effect for a resolver built after it:
// call it before the config's rules are built.
func UseYozhAskTimeoutForTest(t testing.TB, timeout time.Duration) {
	t.Helper()
	previous := yozhAskTimeout
	yozhAskTimeout = timeout
	t.Cleanup(func() { yozhAskTimeout = previous })
}

// ---- Helpers ---------------------------------------------------------------------------------

// yozhCtx is the context the dispatcher builds for a tun flow: the source, the ORIGINAL target,
// and — when `sniffed` is set — the target replaced by the sniffed name (routeOnly=false).
func yozhCtx(network xnet.Network, source string, target string, sniffed string) *routing_session.Context {
	src := netip.MustParseAddrPort(source)
	dst := netip.MustParseAddrPort(target)
	original := xnet.Destination{Network: network, Address: xnet.IPAddress(dst.Addr().AsSlice()), Port: xnet.Port(dst.Port())}
	outbound := &session.Outbound{OriginalTarget: original, Target: original}
	if sniffed != "" {
		outbound.Target = xnet.Destination{Network: network, Address: xnet.DomainAddress(sniffed), Port: original.Port}
	}
	return &routing_session.Context{
		Inbound: &session.Inbound{
			Tag:    "tun",
			Source: xnet.Destination{Network: network, Address: xnet.IPAddress(src.Addr().AsSlice()), Port: xnet.Port(src.Port())},
		},
		Outbound: outbound,
	}
}

func yozhCondition(t *testing.T, labels ...string) *ProcessNameMatcher {
	t.Helper()
	matcher, err := newProcessCondition(labels)
	if err != nil {
		t.Fatalf("%v: %v", labels, err)
	}
	return matcher
}

// yozhTestResolver is a resolver of the test's own, for the tests that need another timeout than
// the engine's (the shared one is built by newProcessCondition from the environment).
func yozhTestResolver(t *testing.T, stub *YozhStub, timeout time.Duration) *yozhResolver {
	t.Helper()
	resolver := newYozhResolver(stub.Path, timeout)
	if err := resolver.open(time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.close)
	return resolver
}

func yozhKeyFor(t *testing.T, network string, source, target string) yozhKey {
	t.Helper()
	return yozhKey{network: network, source: netip.MustParseAddrPort(source), target: netip.MustParseAddrPort(target)}
}

// ---- Labels and start ------------------------------------------------------------------------

func TestYozhLabelsAreParsedStrictly(t *testing.T) {
	labels, err := parseYozhLabels([]string{"yozh:rule-0", "yozh:rule-999", "yozh:unresolved", "yozh:nolocal", "yozh:rule-007"})
	if err != nil {
		t.Fatal(err)
	}
	if !labels.rules[0] || !labels.rules[999] || !labels.rules[7] || !labels.unresolved || !labels.nolocal || len(labels.rules) != 3 {
		t.Fatalf("parsed %+v", labels)
	}
	if labels, err := parseYozhLabels([]string{"curl", "/usr/bin/", "self/"}); labels != nil || err != nil {
		t.Fatalf("a list without labels must stay upstream's: %+v %v", labels, err)
	}
	for _, bad := range [][]string{
		{"yozh:rule-1000"},
		{"yozh:rule-"},
		{"yozh:rule-x"},
		{"yozh:rule--1"},
		{"yozh:foo"},
		{"yozh:"},
		{"Yozh:rule-1"},
		{"YOZH:unresolved"},
		{"yozh:rule-1 "},
		{" yozh:rule-1"},
		{"\tyozh:nolocal"},
		{"yozh:rule-1", "curl"},
		{"/usr/bin/", "yozh:unresolved"},
	} {
		if labels, err := parseYozhLabels(bad); err == nil {
			t.Errorf("%q: accepted as %+v", bad, labels)
		}
	}
}

func TestYozhRuleRefusesToBuildWithoutTheSocketVariable(t *testing.T) {
	UseYozhSocketForTest(t, "")
	rule := &RoutingRule{TargetTag: &RoutingRule_Tag{Tag: "direct"}, Process: []string{"yozh:rule-0"}}
	if _, err := rule.BuildCondition(); err == nil || !strings.Contains(err.Error(), yozhSocketEnv) {
		t.Fatalf("a labelled rule built without %s: %v", yozhSocketEnv, err)
	}
	plain := &RoutingRule{TargetTag: &RoutingRule_Tag{Tag: "direct"}, Process: []string{"curl"}}
	if _, err := plain.BuildCondition(); err != nil {
		t.Fatalf("a rule without labels needs no resolver: %v", err)
	}
}

func TestYozhRuleRefusesToBuildWhenTheSocketDoesNotOpen(t *testing.T) {
	dir, err := os.MkdirTemp("", "yozh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	UseYozhSocketForTest(t, filepath.Join(dir, "nobody-listens.sock"))
	rule := &RoutingRule{TargetTag: &RoutingRule_Tag{Tag: "direct"}, Process: []string{"yozh:unresolved"}}
	if _, err := rule.BuildCondition(); err == nil || !strings.Contains(err.Error(), "did not open") {
		t.Fatalf("a labelled rule built with no resolver listening: %v", err)
	}
}

// ---- Answers ---------------------------------------------------------------------------------

func TestYozhEachAnswerMatchesOnlyItsOwnLabels(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	rule3 := yozhCondition(t, "yozh:rule-3")
	rule2or3 := yozhCondition(t, "yozh:rule-2", "yozh:rule-3")
	unresolved := yozhCondition(t, "yozh:unresolved")
	nolocal := yozhCondition(t, "yozh:nolocal")

	for i, c := range []struct {
		answer                            string
		rule3, rule2or3, unresolved, nolo bool
	}{
		{"rule 3", true, true, false, false},
		{"rule 2", false, true, false, false},
		{"rule 30", false, false, false, false},
		{"failed", false, false, true, false},
		{"nolocal", false, false, false, true},
		{"none", false, false, false, false},
		{"rule 1000", false, false, true, false}, // a number no label can carry is a failure
		{"maybe", false, false, true, false},     // so is a word that is not a verdict
	} {
		source := "198.18.0.1:" + strconv.Itoa(41000+i)
		stub.Answer("tcp 198.18.0.1 "+strconv.Itoa(41000+i)+" 192.0.2.1 443", c.answer)
		ctx := newYozhPass(yozhCtx(xnet.Network_TCP, source, "192.0.2.1:443", ""))
		got := []bool{rule3.Apply(ctx), rule2or3.Apply(ctx), unresolved.Apply(ctx), nolocal.Apply(ctx)}
		want := []bool{c.rule3, c.rule2or3, c.unresolved, c.nolo}
		for j := range got {
			if got[j] != want[j] {
				t.Errorf("answer %q: labels matched %v, want %v", c.answer, got, want)
				break
			}
		}
	}
}

func TestYozhAsksAboutTheOriginalTargetNotTheSniffedName(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	stub.Answer("udp 198.18.0.1 41100 192.0.2.10 443", "rule 5")
	rule5 := yozhCondition(t, "yozh:rule-5")

	ctx := yozhCtx(xnet.Network_UDP, "198.18.0.1:41100", "192.0.2.10:443", "quic.example")
	if len(ctx.GetTargetIPs()) != 0 {
		t.Fatal("precondition: a sniffed flow has no target IP left to route on")
	}
	// Wrapped as the router wraps it for IpOnDemand: a nil DNS client would panic if the matcher
	// asked the wrapper for target IPs, which would resolve the sniffed name.
	if !rule5.Apply(routing_dns.ContextWithDNSClient(newYozhPass(ctx), nil)) {
		t.Fatalf("questions: %q", stub.Questions())
	}
	if got := stub.Questions(); len(got) != 1 || got[0] != "udp 198.18.0.1 41100 192.0.2.10 443" {
		t.Fatalf("questions: %q", got)
	}
}

// yozhSixteenBytes hands out its connection's addresses in their 16-byte form, IPv4 included, as
// net.ParseIP and a resolved name's net.IP carry them. The dispatcher's own context has already made
// an IPv4 address four bytes (xnet.IPAddress), so through it alone the resolver never sees a mapped
// address. Not being the dispatcher's context, it also has no OriginalTarget, and its target IP is
// the one asked about (yozhOriginalTarget).
type yozhSixteenBytes struct{ routing.Context }

func (c yozhSixteenBytes) GetSourceIPs() []net.IP { return yozhTo16(c.Context.GetSourceIPs()) }
func (c yozhSixteenBytes) GetTargetIPs() []net.IP { return yozhTo16(c.Context.GetTargetIPs()) }

func yozhTo16(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.To16())
	}
	return out
}

func TestYozhIPv4MappedAddressesAreAskedAsIPv4(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	rule1 := yozhCondition(t, "yozh:rule-1")
	stub.Answer("tcp 198.18.0.1 41150 192.0.2.15 80", "rule 1")
	stub.Answer("tcp 198.18.0.1 41151 192.0.2.15 80", "rule 1")
	ctx := newYozhPass(yozhCtx(xnet.Network_TCP, "[::ffff:198.18.0.1]:41150", "[::ffff:192.0.2.15]:80", ""))
	if !rule1.Apply(ctx) {
		t.Fatalf("the dispatcher's context: questions %q", stub.Questions())
	}
	sixteen := yozhSixteenBytes{yozhCtx(xnet.Network_TCP, "198.18.0.1:41151", "192.0.2.15:80", "")}
	if ip := sixteen.GetSourceIPs()[0]; len(ip) != net.IPv6len {
		t.Fatalf("precondition: the source is handed out as %d bytes, want %d", len(ip), net.IPv6len)
	}
	if !rule1.Apply(newYozhPass(sixteen)) {
		t.Fatalf("addresses in their 16-byte form: questions %q", stub.Questions())
	}
}

func TestYozhAllLabelsOfOneConnectionCostOneQuestion(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	stub.Answer("tcp 198.18.0.1 41200 192.0.2.20 443", "rule 4")
	engine := &Router{rules: []*Rule{
		yozhRow(t, "row 0", &RoutingRule{Process: []string{"yozh:rule-0"}}),
		yozhRow(t, "row 1", &RoutingRule{Process: []string{"yozh:rule-1", "yozh:rule-6"}}),
		yozhRow(t, "row 2", &RoutingRule{Process: []string{"yozh:rule-2"}}),
		yozhRow(t, "row 3", &RoutingRule{Process: []string{"yozh:nolocal", "yozh:unresolved"}}),
		yozhRow(t, "row 4", &RoutingRule{Process: []string{"yozh:rule-4"}}),
	}}
	route, err := engine.PickRoute(yozhCtx(xnet.Network_TCP, "198.18.0.1:41200", "192.0.2.20:443", ""))
	if err != nil || route.GetOutboundTag() != "row 4" {
		t.Fatalf("went to %v (%v), want row 4", route, err)
	}
	if got := len(stub.Questions()); got != 1 {
		t.Fatalf("%d questions for one connection, want 1", got)
	}
}

// Under the tunnel every program has the utun's source address, and the kernel hands a closed
// socket's port out again: another program's connection can arrive on the very addresses of an
// earlier one. The earlier verdict is not its verdict.
func TestYozhAnotherConnectionOnTheSameAddressesIsAskedAgain(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	const question = "udp 198.18.0.1 41250 192.0.2.25 443"
	rule1 := yozhCondition(t, "yozh:rule-1")
	rule2 := yozhCondition(t, "yozh:rule-2")
	stub.Answer(question, "rule 1")
	first := newYozhPass(yozhCtx(xnet.Network_UDP, "198.18.0.1:41250", "192.0.2.25:443", ""))
	if !rule1.Apply(first) {
		t.Fatalf("the first connection: questions %q", stub.Questions())
	}
	stub.Answer(question, "rule 2")
	second := newYozhPass(yozhCtx(xnet.Network_UDP, "198.18.0.1:41250", "192.0.2.25:443", ""))
	if rule1.Apply(second) || !rule2.Apply(second) {
		t.Fatalf("the second connection was routed on the first one's verdict; questions %q", stub.Questions())
	}
	if !rule1.Apply(first) {
		t.Fatal("the first connection's pass lost its own answer")
	}
	if got := len(stub.Questions()); got != 2 {
		t.Fatalf("%d questions for two connections, want 2", got)
	}
}

func TestYozhAConnectionWithoutAnAddressIsAFailureWithoutAQuestion(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	unresolved := yozhCondition(t, "yozh:unresolved")
	noSource := yozhCtx(xnet.Network_TCP, "198.18.0.1:41300", "192.0.2.30:443", "")
	noSource.Inbound = nil
	domainOnly := &routing_session.Context{
		Inbound: &session.Inbound{Source: xnet.TCPDestination(xnet.ParseAddress("198.18.0.1"), 41301)},
		Outbound: &session.Outbound{
			OriginalTarget: xnet.TCPDestination(xnet.DomainAddress("example.com"), 443),
			Target:         xnet.TCPDestination(xnet.DomainAddress("example.com"), 443),
		},
	}
	if !unresolved.Apply(newYozhPass(noSource)) || !unresolved.Apply(newYozhPass(domainOnly)) {
		t.Fatal("a connection with no key must be a failure (through the base), not a non-match")
	}
	if got := stub.Questions(); len(got) != 0 {
		t.Fatalf("asked %q", got)
	}
}

// ---- One routing pass, one answer ----------------------------------------------------------------

// yozhElsewhere is a row that never matches. It stands for the rest of the engine while one
// connection's rows are walked: it does what it is given and returns false.
type yozhElsewhere func()

func (e yozhElsewhere) Apply(routing.Context) bool {
	e()
	return false
}

// yozhRow builds a row the way Router.Init does, from a RoutingRule.
func yozhRow(t *testing.T, tag string, rule *RoutingRule) *Rule {
	t.Helper()
	condition, err := rule.BuildCondition()
	if err != nil {
		t.Fatalf("%s: %v", tag, err)
	}
	return &Rule{Tag: tag, Condition: condition}
}

func yozhCIDRs(prefixes ...string) []*geodata.IPRule {
	rules := make([]*geodata.IPRule, 0, len(prefixes))
	for _, text := range prefixes {
		prefix := netip.MustParsePrefix(text)
		rules = append(rules, &geodata.IPRule{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{
			Cidr: &geodata.CIDR{Ip: prefix.Addr().AsSlice(), Prefix: uint32(prefix.Bits())},
		}}})
	}
	return rules
}

func yozhPorts(ports ...uint32) *xnet.PortList {
	list := &xnet.PortList{}
	for _, port := range ports {
		list.Range = append(list.Range, &xnet.PortRange{From: port, To: port})
	}
	return list
}

// Between two labels of one connection the engine goes on routing other connections — under a
// burst, thousands of them — and the resolver may say something else if asked again (its own cache
// of the owner was filled meanwhile). The pass's first answer is its verdict to the end: a pass that
// saw "failed" at one label and "rule 1" at the next skips both the failure's row and the rule's,
// and falls to the tail — direct, for a program whose rule blocks it.
//
// The labels stand in rows 8, 11 and 13 of a config shaped like the app's; rows 9 and 12 route 5000
// other connections through the same resolver, and row 10 turns the resolver's answer for this
// connection into "rule 1". The others are routed yozhOthersAtOnce at a time, as the engine routes
// connections side by side. One after another, the test took 10000 times whatever the machine
// needed to hand one answer over, and in a starved process that outlasted the test binary's
// timeout.
func TestYozhAPassKeepsItsFirstAnswerWhileThousandsOfOthersAreRouted(t *testing.T) {
	for _, c := range []struct {
		first, want string
	}{
		{"failed", "base"},        // row 11
		{"rule 2", "app-p-alpha"}, // row 13
	} {
		t.Run(c.first, func(t *testing.T) {
			stub := StartYozhStub(t)
			UseYozhSocketForTest(t, stub.Path)
			UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
			const question = "tcp 198.18.0.1 42000 192.0.2.100 443"
			stub.Answer(question, c.first)

			others := &Router{rules: []*Rule{yozhRow(t, "others", &RoutingRule{Process: []string{"yozh:rule-1"}})}}
			routed := 0
			routeOthers := yozhElsewhere(func() {
				ports := make(chan int)
				var routing sync.WaitGroup
				for range yozhOthersAtOnce {
					routing.Go(func() {
						for port := range ports {
							others.PickRoute(yozhCtx(xnet.Network_TCP, "198.18.0.1:"+strconv.Itoa(port), "192.0.2.200:443", ""))
						}
					})
				}
				for range 5000 {
					routed++
					ports <- 10000 + routed
				}
				close(ports)
				routing.Wait()
			})
			tcpUDP := []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}
			engine := &Router{rules: []*Rule{
				yozhRow(t, "api", &RoutingRule{InboundTag: []string{"api"}}),                                                    // 1
				yozhRow(t, "proxy", &RoutingRule{InboundTag: []string{"dns-app"}}),                                              // 2
				yozhRow(t, "dns-out", &RoutingRule{PortList: yozhPorts(53), Networks: tcpUDP}),                                  // 3
				yozhRow(t, "direct", &RoutingRule{Ip: yozhCIDRs("10.0.0.0/8", "192.168.0.0/16", "198.18.0.0/15", "fc00::/7")}),  // 4
				yozhRow(t, "block", &RoutingRule{PortList: yozhPorts(67, 68, 123), Networks: []xnet.Network{xnet.Network_UDP}}), // 5
				yozhRow(t, "block", &RoutingRule{Ip: yozhCIDRs("224.0.0.0/3", "ff00::/8")}),                                     // 6
				yozhRow(t, "direct", &RoutingRule{Ip: yozhCIDRs("203.0.113.10/32")}),                                            // 7
				yozhRow(t, "block", &RoutingRule{Process: []string{"yozh:rule-1"}}),                                             // 8
				{Tag: "never", Condition: routeOthers},                                                                          // 9
				{Tag: "never", Condition: yozhElsewhere(func() { stub.Answer(question, "rule 1") })},                            // 10
				yozhRow(t, "base", &RoutingRule{Process: []string{"yozh:unresolved"}}),                                          // 11
				{Tag: "never", Condition: routeOthers},                                                                          // 12
				yozhRow(t, "app-p-alpha", &RoutingRule{Process: []string{"yozh:rule-2"}}),                                       // 13
				yozhRow(t, "direct", &RoutingRule{Networks: tcpUDP}),                                                            // 14
			}}

			route, err := engine.PickRoute(yozhCtx(xnet.Network_TCP, "198.18.0.1:42000", "192.0.2.100:443", ""))
			if err != nil {
				t.Fatal(err)
			}
			asked := 0
			for _, q := range stub.Questions() {
				if q == question {
					asked++
				}
			}
			if got := route.GetOutboundTag(); got != c.want {
				t.Errorf("first answer %q: went to %s, want %s (the connection was asked about %d times)", c.first, got, c.want, asked)
			}
			if asked != 1 {
				t.Errorf("first answer %q: the connection was asked about %d times in one pass, want 1", c.first, asked)
			}
			if others := len(stub.Questions()) - asked; others != routed {
				t.Errorf("first answer %q: %d questions about other connections, want one for each of the %d routed", c.first, others, routed)
			}
		})
	}
}

// yozhOthersAtOnce is how many other connections TestYozhAPassKeepsItsFirstAnswerWhileThousandsOfOthersAreRouted
// routes side by side.
const yozhOthersAtOnce = 32

// With IpIfNonMatch the router walks the rows twice, the second time with the context wrapped for
// DNS. Both walks are one pass: one question, and the second walk reads the first one's answer.
func TestYozhBothWalksOfIpIfNonMatchAreOnePass(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	stub.Answer("udp 198.18.0.1 42060 192.0.2.106 443", "rule 4")
	walks := 0
	engine := &Router{domainStrategy: Config_IpIfNonMatch, rules: []*Rule{
		yozhRow(t, "block", &RoutingRule{Process: []string{"yozh:rule-1"}}),
		{Tag: "never", Condition: yozhElsewhere(func() { walks++ })},
		yozhRow(t, "base", &RoutingRule{Process: []string{"yozh:unresolved"}}),
	}}
	// A sniffed name, so the second walk happens; the rows name no IP, so the nil DNS client is
	// never asked.
	route, err := engine.PickRoute(yozhCtx(xnet.Network_UDP, "198.18.0.1:42060", "192.0.2.106:443", "quic.example"))
	if err != common.ErrNoClue {
		t.Fatalf("a program with rule 4 matched a row: %v %v (questions %q)", route, err, stub.Questions())
	}
	if walks != 2 {
		t.Fatalf("%d walks, want 2", walks)
	}
	if got := stub.Questions(); len(got) != 1 {
		t.Fatalf("questions: %q, want one for both walks", got)
	}
}

// A label is answered inside a routing pass (Router.PickRoute), which keeps the answer for every
// label of the pass. Outside one there is nowhere to keep it, and two labels could see two answers;
// so no question is asked, and the answer is a failure — through the base, never a rule's route.
func TestYozhALabelOutsideARoutingPassIsAFailureWithoutAQuestion(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	stub.Fallback = "rule 1"
	rule1 := yozhCondition(t, "yozh:rule-1")
	unresolved := yozhCondition(t, "yozh:unresolved")
	ctx := yozhCtx(xnet.Network_TCP, "198.18.0.1:42050", "192.0.2.105:443", "")
	if rule1.Apply(ctx) || !unresolved.Apply(ctx) {
		t.Fatalf("a label outside a routing pass must be a failure; questions %q", stub.Questions())
	}
	if got := stub.Questions(); len(got) != 0 {
		t.Fatalf("asked %q", got)
	}
}

// ---- Time --------------------------------------------------------------------------------------

func TestYozhASilentResolverIsAFailureWithinFiftyMilliseconds(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	stub.Fallback = "silent"
	unresolved := yozhCondition(t, "yozh:unresolved")

	start := time.Now()
	matched := unresolved.Apply(newYozhPass(yozhCtx(xnet.Network_TCP, "198.18.0.1:41400", "192.0.2.40:443", "")))
	elapsed := time.Since(start)
	if !matched {
		t.Fatal("a question nobody answered must be `failed`, which yozh:unresolved matches")
	}
	if elapsed < 45*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("gave up after %v, want 50 ms", elapsed)
	}
}

// The engine's resolver runs on a test clock here: the question gives up when the clock reaches
// the engine's 50 ms timeout, not a nanosecond sooner, and the answer is sent only after that, so it
// is late however busy the machine is.
func TestYozhALateAnswerNeverOverturnsTheFailure(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	const question = "tcp 198.18.0.1 41500 192.0.2.50 443"
	stub.Answer(question, "late rule 1")
	unresolved := yozhCondition(t, "yozh:unresolved")
	rule1 := yozhCondition(t, "yozh:rule-1")
	resolver := unresolved.yozh.resolver
	clock := yozhOnTestClock(resolver)
	ctx := newYozhPass(yozhCtx(xnet.Network_TCP, "198.18.0.1:41500", "192.0.2.50:443", ""))

	first := make(chan bool, 1)
	go func() { first <- unresolved.Apply(ctx) }()
	yozhAwait(t, "the question to wait for its answer", func() bool { return clock.timersWaiting() == 1 })
	const engineTimeout = 50 * time.Millisecond
	clock.advance(engineTimeout - time.Nanosecond)
	if clock.timersWaiting() != 1 {
		t.Fatalf("the question gave up %v into the engine's %v timeout", engineTimeout-time.Nanosecond, engineTimeout)
	}
	clock.advance(time.Nanosecond)
	if clock.timersWaiting() != 0 {
		t.Fatalf("the question still waits at the engine's %v timeout", engineTimeout)
	}
	select {
	case matched := <-first:
		if !matched {
			t.Fatal("the first label must see the timeout as `failed`")
		}
	case <-time.After(yozhWaitLimit):
		t.Fatalf("the question was still waiting %v after the engine's %v timeout", yozhWaitLimit, engineTimeout)
	}
	resolver.mu.Lock()
	waiting := len(resolver.pending)
	resolver.mu.Unlock()
	if waiting != 0 {
		t.Fatalf("%d questions still wait for an answer after the timeout", waiting)
	}

	// The answer comes after the failure, and the resolver reads it. Asked again, the resolver would
	// name rule 1 at once.
	yozhAwait(t, "the stub to read the question", func() bool { return len(stub.Questions()) == 1 })
	stub.SendLate()
	yozhAwait(t, "the resolver to read the late answer", func() bool {
		resolver.mu.Lock()
		defer resolver.mu.Unlock()
		return resolver.answered
	})
	stub.Answer(question, "rule 1")
	if rule1.Apply(ctx) {
		t.Fatal("a later label of the same connection saw the late answer: one pass, two verdicts")
	}
	if got := len(stub.Questions()); got != 1 {
		t.Fatalf("%d questions, want 1", got)
	}
}

// ---- The connection ------------------------------------------------------------------------------

func TestYozhALostResolverFailsWhatIsWaitingAndIsDialledAgain(t *testing.T) {
	stub := StartYozhStub(t)
	resolver, _ := yozhClockedResolver(t, stub.Path)
	stub.Answer("tcp 198.18.0.1 41600 192.0.2.60 443", "silent")
	stub.Answer("tcp 198.18.0.1 41601 192.0.2.60 443", "rule 9")

	waiting := yozhAskInBackground(resolver, yozhKeyFor(t, "tcp", "198.18.0.1:41600", "192.0.2.60:443"))
	yozhAwait(t, "the stub to read the question", func() bool { return len(stub.Questions()) == 1 })
	stub.DropConnections()
	// The clock stands still, so the question's timeout never comes: only the lost connection can
	// fail it.
	if answer := yozhReturned(t, waiting); answer != yozhFailedAnswer {
		t.Fatalf("a question on a dropped connection got %+v", answer)
	}
	if answer := yozhAskStill(t, resolver, yozhKeyFor(t, "tcp", "198.18.0.1:41601", "192.0.2.60:443")); answer != (yozhAnswer{kind: yozhRule, rule: 9}) {
		t.Fatalf("after the drop: %+v", answer)
	}
	if got := stub.Connections(); got != 2 {
		t.Fatalf("%d connections, want a second dial", got)
	}
}

// A question that waited for the connection past its own deadline fails by itself: it writes
// nothing, and the connection stays, with every other question on it. Written with a deadline
// already past, it failed at once and dropped the connection, failing every question waiting on it
// (dropLocked) — one slow moment turned into a volley of failures, through the base.
func TestYozhAQuestionPastItsDeadlineFailsAloneWithoutTouchingTheConnection(t *testing.T) {
	stub := StartYozhStub(t)
	resolver, clock := yozhClockedResolver(t, stub.Path)
	stub.Answer("tcp 198.18.0.1 41900 192.0.2.90 443", "rule 1")
	stub.Answer("tcp 198.18.0.1 41901 192.0.2.90 443", "rule 2")

	resolver.mu.Lock() // another question holds the connection (a slow write, a dial)
	read := clock.timesRead()
	late := yozhAskInBackground(resolver, yozhKeyFor(t, "tcp", "198.18.0.1:41900", "192.0.2.90:443"))
	yozhAwait(t, "the question to take its deadline", func() bool { return clock.timesRead() > read })
	clock.advance(resolver.timeout) // its deadline passes while it waits for the connection
	resolver.mu.Unlock()

	if answer := yozhReturned(t, late); answer != yozhFailedAnswer {
		t.Fatalf("a question past its deadline got %+v", answer)
	}
	if answer := yozhAskStill(t, resolver, yozhKeyFor(t, "tcp", "198.18.0.1:41901", "192.0.2.90:443")); answer != (yozhAnswer{kind: yozhRule, rule: 2}) {
		t.Fatalf("the next question: %+v", answer)
	}
	if got := stub.Connections(); got != 1 {
		t.Fatalf("%d connections: the late question dropped the connection", got)
	}
	if got := stub.Questions(); len(got) != 1 || got[0] != "tcp 198.18.0.1 41901 192.0.2.90 443" {
		t.Fatalf("questions on the wire: %q, want only the second one", got)
	}
}

// The same with no connection: the resolver's connection was lost while questions waited for the
// lock past their deadlines. They fail by themselves and dial nothing. Dialled with a deadline
// already past, each would be a failed dial, two of them would start the pause before the next dial
// (failedLocked), and the question after them, in time and with the resolver there, would fail
// through the base instead of dialling.
func TestYozhQuestionsPastTheirDeadlineDialNothing(t *testing.T) {
	stub := StartYozhStub(t)
	resolver, clock := yozhClockedResolver(t, stub.Path)
	stub.Answer("tcp 198.18.0.1 41910 192.0.2.91 443", "rule 1")
	stub.Answer("tcp 198.18.0.1 41920 192.0.2.91 443", "rule 2")
	if answer := yozhAskStill(t, resolver, yozhKeyFor(t, "tcp", "198.18.0.1:41910", "192.0.2.91:443")); answer != (yozhAnswer{kind: yozhRule, rule: 1}) {
		t.Fatalf("the first question: %+v", answer)
	}

	resolver.mu.Lock()
	resolver.dropLocked(resolver.conn) // lost after it answered: the next dial is made at once
	read := clock.timesRead()
	const late = 3
	var asked []<-chan yozhAnswer
	for i := range late {
		asked = append(asked, yozhAskInBackground(resolver, yozhKeyFor(t, "tcp", "198.18.0.1:"+strconv.Itoa(41911+i), "192.0.2.91:443")))
	}
	yozhAwait(t, "the questions to take their deadlines", func() bool { return clock.timesRead() >= read+late })
	clock.advance(resolver.timeout) // their deadlines pass while they wait for the connection
	resolver.mu.Unlock()
	for _, answer := range asked {
		if answer := yozhReturned(t, answer); answer != yozhFailedAnswer {
			t.Fatalf("a question past its deadline got %+v", answer)
		}
	}
	if yozhConnOf(resolver) != nil {
		t.Fatal("a question past its deadline dialled the resolver")
	}

	if answer := yozhAskStill(t, resolver, yozhKeyFor(t, "tcp", "198.18.0.1:41920", "192.0.2.91:443")); answer != (yozhAnswer{kind: yozhRule, rule: 2}) {
		t.Fatalf("the question after the late ones, in time, with the resolver there: %+v", answer)
	}
	if got := stub.Connections(); got != 2 {
		t.Fatalf("%d connections, want the first and the one the question in time dialled", got)
	}
	if got := stub.Questions(); len(got) != 2 || got[1] != "tcp 198.18.0.1 41920 192.0.2.91 443" {
		t.Fatalf("questions on the wire: %q, want the first one and the one in time", got)
	}
}

// yozhFailingWrites is the resolver's connection with its next write replaced: `sent` bytes of the
// line go out, then the write fails with `err`.
type yozhFailingWrites struct {
	net.Conn
	mu   sync.Mutex
	next *struct {
		sent int
		err  error
	}
}

func (c *yozhFailingWrites) failNext(sent int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next = &struct {
		sent int
		err  error
	}{sent, err}
}

func (c *yozhFailingWrites) Write(b []byte) (int, error) {
	c.mu.Lock()
	next := c.next
	c.next = nil
	c.mu.Unlock()
	if next == nil {
		return c.Conn.Write(b)
	}
	if next.sent > 0 {
		c.Conn.Write(b[:next.sent])
	}
	return next.sent, next.err
}

// A write that fails is that question's failure. The connection goes only when the line is broken:
// part of it went out (the stream is out of step with the resolver), or the socket itself failed.
// A timeout with nothing written leaves the stream whole, and the connection stays.
func TestYozhAFailedWriteDropsTheConnectionOnlyWhenTheStreamIsBroken(t *testing.T) {
	for _, c := range []struct {
		name    string
		sent    int
		err     error
		dropped bool
	}{
		{"a timeout with nothing written", 0, os.ErrDeadlineExceeded, false},
		{"a timeout after half a line", 5, os.ErrDeadlineExceeded, true},
		{"a broken socket", 0, syscall.EPIPE, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := StartYozhStub(t)
			resolver := yozhTestResolver(t, stub, YozhLongAskTimeout)
			stub.Answer("tcp 198.18.0.1 41950 192.0.2.95 443", "rule 3")
			resolver.mu.Lock()
			conn := &yozhFailingWrites{Conn: resolver.conn}
			resolver.conn = conn
			resolver.mu.Unlock()

			conn.failNext(c.sent, c.err)
			if answer := resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:41949", "192.0.2.95:443")); answer != yozhFailedAnswer {
				t.Fatalf("a failed write got %+v", answer)
			}
			if answer := resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:41950", "192.0.2.95:443")); answer != (yozhAnswer{kind: yozhRule, rule: 3}) {
				t.Fatalf("the next question: %+v", answer)
			}
			if dropped := stub.Connections() == 2; dropped != c.dropped {
				t.Fatalf("%d connections: dropped %v, want %v", stub.Connections(), dropped, c.dropped)
			}
			resolver.mu.Lock()
			pending := len(resolver.pending)
			resolver.mu.Unlock()
			if pending != 0 {
				t.Fatalf("%d questions left pending", pending)
			}
		})
	}
}

func TestYozhAnswersAreMatchedToQuestionsByNumber(t *testing.T) {
	stub := StartYozhStub(t)
	const n = 16
	stub.ReverseBatch = n
	resolver := yozhTestResolver(t, stub, YozhLongAskTimeout)
	for i := 0; i < n; i++ {
		stub.Answer("tcp 198.18.0.1 "+strconv.Itoa(41700+i)+" 192.0.2.70 443", "rule "+strconv.Itoa(i))
	}
	var wg sync.WaitGroup
	got := make([]yozhAnswer, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:"+strconv.Itoa(41700+i), "192.0.2.70:443"))
		}()
	}
	wg.Wait()
	for i, answer := range got {
		if answer != (yozhAnswer{kind: yozhRule, rule: i}) {
			t.Errorf("question %d got %+v", i, answer)
		}
	}
}

func TestYozhMalformedAnswersFailTheirQuestion(t *testing.T) {
	stub := StartYozhStub(t)
	resolver, clock := yozhClockedResolver(t, stub.Path)
	key := func(port int, answer string) yozhKey {
		stub.Answer("tcp 198.18.0.1 "+strconv.Itoa(port)+" 192.0.2.80 443", answer)
		return yozhKeyFor(t, "tcp", "198.18.0.1:"+strconv.Itoa(port), "192.0.2.80:443")
	}
	first := yozhConnOf(resolver)

	// A line with no number: nothing to hand it to. It is read, and its question goes on waiting.
	unnumbered := yozhAskInBackground(resolver, key(41800, "raw:garbage without a number"))
	yozhAwait(t, "the resolver to read the line", func() bool {
		resolver.mu.Lock()
		defer resolver.mu.Unlock()
		return resolver.answered
	})
	// Numbered, but not a verdict: failed at once, on the same connection.
	if answer := yozhAskStill(t, resolver, key(41801, "raw:{id} a rule x")); answer != yozhFailedAnswer {
		t.Errorf("a numbered line that is not a verdict: %+v", answer)
	}
	resolver.mu.Lock()
	waiting := len(resolver.pending)
	resolver.mu.Unlock()
	if conn := yozhConnOf(resolver); conn != first || waiting != 1 {
		t.Fatalf("after a line with no number: connection kept %v, %d questions waiting; want it kept and its question waiting", conn == first, waiting)
	}
	clock.advance(resolver.timeout) // the question of the line with no number waits out its timeout
	if answer := yozhReturned(t, unnumbered); answer != yozhFailedAnswer {
		t.Errorf("a line with no number: %+v", answer)
	}

	// Over-long: the line is not read, the connection is dropped, and its question fails with it.
	if answer := yozhAskStill(t, resolver, key(41802, "raw:{id} a "+strings.Repeat("x", yozhMaxLine))); answer != yozhFailedAnswer {
		t.Errorf("an over-long line: %+v", answer)
	}
	if answer := yozhAskStill(t, resolver, key(41803, "rule 2")); answer != (yozhAnswer{kind: yozhRule, rule: 2}) {
		t.Fatalf("after the over-long line the resolver must be dialled again and answer: %+v", answer)
	}
	if got := stub.Connections(); got != 2 {
		t.Fatalf("%d connections: after the over-long line the resolver must be dialled again", got)
	}
}

// ---- Whose socket it is ------------------------------------------------------------------------------

// The resolver is the app's root component, and the engine it serves runs as the same user. A socket
// at the resolver's path that another user listens on is not the resolver, whoever put it there: its
// answers would route every program. The engine reads the listener's credentials off the connection
// (LOCAL_PEERCRED on macOS) and talks only to its own user; a socket whose user cannot be read is
// refused too.
func TestYozhAResolverSocketOfAnotherUserIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		peer func(net.Conn) (uint32, error)
	}{
		{"another user", func(net.Conn) (uint32, error) { return uint32(os.Geteuid()) + 1, nil }},
		{"no credentials", func(net.Conn) (uint32, error) { return 0, syscall.EINVAL }},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := StartYozhStub(t)
			stub.Fallback = "rule 1"
			resolver := newYozhResolver(stub.Path, 50*time.Millisecond)
			resolver.peer = c.peer
			t.Cleanup(resolver.close)
			if err := resolver.open(time.Second); err == nil {
				t.Fatal("opened a resolver socket that is not the engine's own user's")
			}
			if answer := resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:42100", "192.0.2.110:443")); answer != yozhFailedAnswer {
				t.Fatalf("asked a stranger and took its answer: %+v", answer)
			}
			if got := stub.Questions(); len(got) != 0 {
				t.Fatalf("questions sent to a stranger: %q", got)
			}
		})
	}
}

// yozhLogLines collects the engine's log lines about the routing resolver while a test runs.
type yozhLogLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *yozhLogLines) Handle(msg xlog.Message) {
	if text := msg.String(); strings.Contains(text, "yozh routing resolver") {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.lines = append(l.lines, text)
	}
}

func (l *yozhLogLines) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// yozhCaptureLog takes the engine's log for the rest of the test, and then gives it back to the
// handler the log package starts with (standard output).
func yozhCaptureLog(t *testing.T) *yozhLogLines {
	t.Helper()
	lines := &yozhLogLines{}
	xlog.RegisterHandler(lines)
	t.Cleanup(func() { xlog.RegisterHandler(xlog.NewLogger(xlog.CreateStdoutLogWriter())) })
	return lines
}

// A resolver socket refused after start fails its questions through the base, and said nothing: the
// engine went on as if the resolver answered "failed", and only the routes showed it. The refusal is
// logged, once for a run of refusals — a refused socket is dialled again after every pause, and a
// stranger at the path would fill the log — and with no address and no path. A connection that
// passes ends the run.
func TestYozhAResolverRefusedAfterStartIsLoggedOncePerRun(t *testing.T) {
	stub := StartYozhStub(t)
	stub.Fallback = "rule 1"
	resolver := yozhTestResolver(t, stub, YozhLongAskTimeout)
	logged := yozhCaptureLog(t)
	own := resolver.peer
	stranger := func(net.Conn) (uint32, error) { return uint32(os.Geteuid()) + 1, nil }
	// redial: the next question dials, with this reader of the peer, whatever pause earlier failures
	// set (the pause is not this test's subject).
	redial := func(peer func(net.Conn) (uint32, error)) {
		resolver.mu.Lock()
		defer resolver.mu.Unlock()
		resolver.peer = peer
		if resolver.conn != nil {
			resolver.dropLocked(resolver.conn)
		}
		resolver.redialAt = time.Time{}
	}

	for i := range 3 {
		redial(stranger)
		if answer := resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:"+strconv.Itoa(42200+i), "192.0.2.120:443")); answer != yozhFailedAnswer {
			t.Fatalf("a stranger's answer was taken: %+v", answer)
		}
	}
	lines := logged.Lines()
	t.Logf("logged: %q", lines)
	if len(lines) != 1 {
		t.Fatalf("three refusals after start logged %d lines, want 1: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "another user's") {
		t.Errorf("the line does not say why the socket was refused: %q", lines[0])
	}
	for _, private := range []string{stub.Path, filepath.Dir(stub.Path), "198.18.0.1", "192.0.2.120"} {
		if strings.Contains(lines[0], private) {
			t.Errorf("the line carries %q: %q", private, lines[0])
		}
	}

	redial(own)
	if answer := resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:42210", "192.0.2.120:443")); answer != (yozhAnswer{kind: yozhRule, rule: 1}) {
		t.Fatalf("the resolver's own socket again: %+v", answer)
	}
	redial(stranger)
	resolver.ask(yozhKeyFor(t, "tcp", "198.18.0.1:42211", "192.0.2.120:443"))
	if lines := logged.Lines(); len(lines) != 2 {
		t.Fatalf("a refusal after a connection that passed logged %d lines in all, want 2: %q", len(lines), lines)
	}
}

// Where the listener's user cannot be read, the engine refuses every resolver, and the stubs of the
// resolver's other tests with it. Those tests let the stub they started through, and nothing else:
// a socket the test did not start as its stub stays refused. The reader of such a platform stands in
// for this one's here.
func TestYozhWhereTheUserCannotBeReadOnlyTheTestsOwnStubIsLetThrough(t *testing.T) {
	unreadable := func(net.Conn) (uint32, error) { return 0, errYozhPeerUnreadable }
	stub := StartYozhStub(t)
	stub.Fallback = "rule 1"
	own := newYozhResolver(stub.Path, YozhLongAskTimeout)
	own.peer = unreadable
	t.Cleanup(own.close)
	if err := own.open(time.Second); err != nil {
		t.Fatalf("the test's own stub was refused: %v", err)
	}
	if answer := own.ask(yozhKeyFor(t, "tcp", "198.18.0.1:42110", "192.0.2.111:443")); answer != (yozhAnswer{kind: yozhRule, rule: 1}) {
		t.Fatalf("the test's own stub let through, and its answer lost: %+v", answer)
	}

	stranger, path := yozhListen(t)
	t.Cleanup(func() { stranger.Close() })
	other := newYozhResolver(path, YozhLongAskTimeout)
	other.peer = unreadable
	t.Cleanup(other.close)
	if err := other.open(time.Second); !errors.Is(err, errYozhPeerUnreadable) {
		t.Fatalf("a socket the test did not start as its stub: %v, want it refused as unreadable", err)
	}
}

// ---- Nothing outlives the pass --------------------------------------------------------------------

func TestYozhARoutedConnectionIsNotKeptAlive(t *testing.T) {
	stub := StartYozhStub(t)
	UseYozhSocketForTest(t, stub.Path)
	UseYozhAskTimeoutForTest(t, YozhLongAskTimeout)
	engine := &Router{rules: []*Rule{yozhRow(t, "block", &RoutingRule{Process: []string{"yozh:rule-1"}})}}
	var gone weak.Pointer[routing_session.Context]
	func() {
		ctx := yozhCtx(xnet.Network_TCP, "198.18.0.1:41260", "192.0.2.26:443", "")
		engine.PickRoute(ctx)
		gone = weak.Make(ctx)
	}()
	runtime.GC()
	if got := stub.Questions(); len(got) != 1 {
		t.Fatalf("questions %q: the pass did not ask", got)
	}
	if gone.Value() != nil {
		t.Fatal("a routed connection's routing context (and its Inbound.Conn) is kept alive")
	}
}
