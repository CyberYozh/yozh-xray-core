//go:build darwin

package tun_test

// The socket check together with the per-app labels (app/router/yozh_resolver.go): the port-reuse
// scenario, which must now end with two questions to the resolver and the second program on its
// own route. Drop this file when offering the socket check upstream without the labels;
// udp_flow_engine_test.go carries the same proof with a port rule.

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/tun"
)

type resolverStub struct {
	answer atomic.Value // what every question is answered with
	asked  atomic.Int64
}

// yozhChild marks the process a test started again for itself (inProcessStartedWithResolverSocket).
const yozhChild = "YOZH_UDPFLOW_TEST_CHILD"

// inProcessStartedWithResolverSocket answers the resolver socket's path when this is a process
// started with YOZH_ROUTING_SOCKET in its environment. The engine reads the variable once, when it
// starts — as the app's root component hands it over — and a test cannot set it later. So otherwise
// the test runs again in a process of its own started with it, and the answer is "" (the test's
// result is that process's). os.MkdirTemp, not t.TempDir: a unix socket path must fit sun_path (104
// bytes), and t.TempDir adds the test's long name.
func inProcessStartedWithResolverSocket(t *testing.T) string {
	t.Helper()
	if os.Getenv(yozhChild) == "1" {
		path := os.Getenv("YOZH_ROUTING_SOCKET")
		if path == "" {
			t.Fatal("started again for the test without YOZH_ROUTING_SOCKET")
		}
		return path
	}
	dir, err := os.MkdirTemp("", "yz")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	child := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")
	child.Env = append(os.Environ(), "YOZH_ROUTING_SOCKET="+filepath.Join(dir, "r.sock"), yozhChild+"=1")
	out, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: "+t.Name())) {
		t.Fatalf("the test, in a process started with YOZH_ROUTING_SOCKET: %v\n%s", err, out)
	}
	return ""
}

// startResolverStub listens at path, where YOZH_ROUTING_SOCKET points.
func startResolverStub(t *testing.T, path, first string) *resolverStub {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	stub := &resolverStub{}
	stub.answer.Store(first)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				lines := bufio.NewScanner(conn)
				for lines.Scan() {
					fields := strings.Fields(lines.Text())
					if len(fields) < 2 || fields[1] != "q" {
						continue
					}
					stub.asked.Add(1)
					fmt.Fprintf(conn, "%s a %s\n", fields[0], stub.answer.Load().(string))
				}
			}(conn)
		}
	}()
	return stub
}

func TestYozhUDPFlowAnotherProgramOnTheSamePortIsAskedAndRoutedByItsOwnRule(t *testing.T) {
	path := inProcessStartedWithResolverSocket(t)
	if path == "" {
		return
	}
	resolver := startResolverStub(t, path, "rule 1")
	a, b := newUDPEcho(t), newUDPEcho(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},"stats":{},
	  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
	  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"via-x","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing":{"rules":[
	    {"type":"field","process":["yozh:rule-1"],"outboundTag":"direct"},
	    {"type":"field","process":["yozh:rule-2"],"outboundTag":"via-x"},
	    {"type":"field","network":"udp","outboundTag":"block"}]}}`)
	flows := flowTable(t, instance)

	// Program A (rule 1, direct) sends to server A.
	programA, source := program(t, 0)
	flows.HandlePacket(source, a.dest(), []byte("from-program-A"))
	waitUntil(t, "A's datagram reaches server A", 2*time.Second, func() bool { return len(a.senders()) == 1 })
	waitUntil(t, "the flow knows A's socket", 2*time.Second, func() bool { return flows.Identified(source) })
	directAfterA := uplinkOf(instance, "direct")

	// A closes; program B (rule 2, via X) is handed the same port and sends to server B.
	programA.Close()
	program(t, source.Port)
	resolver.answer.Store("rule 2")
	flows.HandlePacket(source, b.dest(), []byte("from-program-B"))
	waitUntil(t, "B's datagram reaches server B", 2*time.Second, func() bool { return len(b.senders()) == 1 })
	time.Sleep(100 * time.Millisecond) // the counters settle

	if asked := resolver.asked.Load(); asked != 2 {
		t.Errorf("the resolver was asked %d times, want 2: B's flow must ask about B", asked)
	}
	if up := uplinkOf(instance, "via-x"); up <= 0 {
		t.Errorf("via-x carried %d bytes: B did not go by its own rule", up)
	}
	if up := uplinkOf(instance, "direct"); up != directAfterA {
		t.Errorf("direct carried %d more bytes after A: B rode A's route", up-directAfterA)
	}
	if senderPort(a.senders()[0]) == senderPort(b.senders()[0]) {
		t.Errorf("B left through A's outbound socket (%s)", a.senders()[0])
	}
	if n := flows.FlowCount(); n != 1 {
		t.Errorf("%d flows under the source, want 1 (B's)", n)
	}
}

// The same with the app's rows: a local-network row sends the first datagram direct, and the
// program's second datagram, to the internet, is asked about and routed by its own label — blocked,
// through its own proxy, or through the base — never out of the direct socket.
func yozhSecondAddressIsRoutedByTheLabel(t *testing.T, answer, outbound string) {
	path := inProcessStartedWithResolverSocket(t)
	if path == "" {
		return
	}
	resolver := startResolverStub(t, path, answer)
	lan := newUDPEcho(t)
	internet, internetDest := newUDPEcho6(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},"stats":{},
	  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
	  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"app-p-alpha-udp","protocol":"freedom"},
	    {"tag":"proxy-udp","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing":{"rules":[
	    {"type":"field","ip":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","198.18.0.0/15","fc00::/7","fe80::/10"],"outboundTag":"direct"},
	    {"type":"field","process":["yozh:rule-1","yozh:rule-6"],"outboundTag":"block"},
	    {"type":"field","process":["yozh:rule-2"],"network":"udp","outboundTag":"app-p-alpha-udp"},
	    {"type":"field","process":["yozh:unresolved","yozh:nolocal"],"network":"udp","outboundTag":"proxy-udp"},
	    {"type":"field","network":"udp","outboundTag":"proxy-udp"}]}}`)
	flows := flowTable(t, instance)

	_, source := program(t, 0)
	flows.HandlePacket(source, lan.dest(), []byte("to-lan"))
	waitUntil(t, "the LAN datagram arrives", 2*time.Second, func() bool { return len(lan.senders()) == 1 })
	flows.HandlePacket(source, internetDest, []byte("to-internet"))
	if outbound == "block" {
		time.Sleep(500 * time.Millisecond)
	} else {
		waitUntil(t, "the internet datagram arrives", 2*time.Second, func() bool { return len(internet.senders()) == 1 })
	}
	time.Sleep(100 * time.Millisecond) // the counters settle

	t.Logf("answer=%q questions=%d internet-senders=%v lan-senders=%v direct-up=%d alpha-up=%d proxy-up=%d flows=%d",
		answer, resolver.asked.Load(), internet.senders(), lan.senders(), uplinkOf(instance, "direct"),
		uplinkOf(instance, "app-p-alpha-udp"), uplinkOf(instance, "proxy-udp"), flows.FlowCount())
	if up := uplinkOf(instance, "direct"); up != int64(len("to-lan")) {
		t.Errorf("direct carried %d bytes, want only the LAN datagram's %d", up, len("to-lan"))
	}
	if got := internet.senders(); outbound == "block" && len(got) != 0 {
		t.Errorf("a blocked program's datagram reached the internet, from %v", got)
	}
	if outbound != "block" {
		if up := uplinkOf(instance, outbound); up != int64(len("to-internet")) {
			t.Errorf("%s carried %d bytes, want the internet datagram's %d", outbound, up, len("to-internet"))
		}
	}
	if asked := resolver.asked.Load(); asked < 1 {
		t.Errorf("the resolver was never asked about the internet datagram")
	}
}

func TestYozhUDPFlowASecondAddressOfABlockedProgramIsBlocked(t *testing.T) {
	yozhSecondAddressIsRoutedByTheLabel(t, "rule 1", "block")
}

func TestYozhUDPFlowASecondAddressOfAProxiedProgramTakesItsProxy(t *testing.T) {
	yozhSecondAddressIsRoutedByTheLabel(t, "rule 2", "app-p-alpha-udp")
}

func TestYozhUDPFlowASecondAddressOfAProgramWithoutARuleTakesTheBase(t *testing.T) {
	yozhSecondAddressIsRoutedByTheLabel(t, "none", "proxy-udp")
}

// heldResolver answers each question with the answer set when the question arrived. The question
// after holdNextQuestion is answered once release is closed, and at most 40 ms after it came: inside
// the engine's 50 ms deadline.
type heldResolver struct {
	mu       sync.Mutex
	answer   string
	holdNext bool
	held     chan struct{}
	release  chan struct{}
	log      []string
}

func startHeldResolver(t *testing.T, path, first string) *heldResolver {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	r := &heldResolver{answer: first}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				var writeMu sync.Mutex
				lines := bufio.NewScanner(conn)
				for lines.Scan() {
					fields := strings.Fields(lines.Text())
					if len(fields) < 2 || fields[1] != "q" {
						continue
					}
					r.mu.Lock()
					answer, hold := r.answer, r.holdNext
					r.holdNext = false
					held, release := r.held, r.release
					r.log = append(r.log, strings.Join(fields[2:], " ")+" => "+answer)
					r.mu.Unlock()
					go func(id string) {
						if hold {
							close(held)
							select {
							case <-release:
							case <-time.After(40 * time.Millisecond):
							}
						}
						writeMu.Lock()
						defer writeMu.Unlock()
						fmt.Fprintf(conn, "%s a %s\n", id, answer)
					}(fields[0])
				}
			}(conn)
		}
	}()
	return r
}

func (r *heldResolver) setAnswer(answer string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answer = answer
}

func (r *heldResolver) holdNextQuestion() (held, release chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.holdNext = true
	r.held, r.release = make(chan struct{}), make(chan struct{})
	return r.held, r.release
}

func (r *heldResolver) questions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

// handOver is the scene of the tests below. Program A, whose rule (1) blocks it, sent a datagram to
// the LAN, which the direct row takes; its next datagram, to the internet, now waits for its route,
// and the resolver holds that question. What happens to the port next is the test's.
type handOver struct {
	resolver *heldResolver
	release  chan struct{}
	instance *core.Instance
	flows    *tun.UDPFlowsForTest
	programA *net.UDPConn
	source   xnet.Destination
	lan      *udpEcho
	internet *udpEcho
}

// startHandOver answers nil in the process that only starts the test again with the resolver
// socket (inProcessStartedWithResolverSocket).
func startHandOver(t *testing.T) *handOver {
	t.Helper()
	path := inProcessStartedWithResolverSocket(t)
	if path == "" {
		return nil
	}
	h := &handOver{resolver: startHeldResolver(t, path, "rule 1"), lan: newUDPEcho(t)}
	var internetDest xnet.Destination
	h.internet, internetDest = newUDPEcho6(t)
	h.instance = startTestEngine(t, `{"log":{"loglevel":"none"},"stats":{},
	  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
	  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"proxy-udp","protocol":"freedom"},
	    {"tag":"block","protocol":"blackhole"}],
	  "routing":{"rules":[
	    {"type":"field","ip":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","198.18.0.0/15","fc00::/7","fe80::/10"],"outboundTag":"direct"},
	    {"type":"field","process":["yozh:rule-0"],"outboundTag":"direct"},
	    {"type":"field","process":["yozh:rule-1"],"outboundTag":"block"},
	    {"type":"field","process":["yozh:unresolved","yozh:nolocal"],"network":"udp","outboundTag":"proxy-udp"},
	    {"type":"field","network":"udp","outboundTag":"proxy-udp"}]}}`)
	h.flows = flowTable(t, h.instance)

	h.programA, h.source = program(t, 0)
	h.flows.HandlePacket(h.source, h.lan.dest(), []byte("A-to-lan"))
	waitUntil(t, "A's LAN datagram arrives", 2*time.Second, func() bool { return len(h.lan.senders()) == 1 })
	waitUntil(t, "the flow knows A's socket", 2*time.Second, func() bool { return h.flows.Identified(h.source) })

	var held chan struct{}
	held, h.release = h.resolver.holdNextQuestion()
	h.flows.HandlePacket(h.source, internetDest, []byte("A-secret"))
	select {
	case <-held:
	case <-time.After(2 * time.Second):
		t.Fatal("A's internet datagram was never asked about")
	}
	return h
}

func (h *handOver) report(t *testing.T) {
	t.Helper()
	t.Logf("questions=%q", h.resolver.questions())
	t.Logf("internet-senders=%v direct-up=%d proxy-up=%d flows=%d", h.internet.senders(),
		uplinkOf(h.instance, "direct"), uplinkOf(h.instance, "proxy-udp"), h.flows.FlowCount())
}

// A closes its socket while its internet datagram waits for its route; program B (rule 0: direct)
// is handed the port and sends to another address. A's datagram is dropped, and B's goes by B's
// rule. A's datagram used to be routed again with B's, as B's, and left direct.
func TestYozhUDPFlowAWaitingDatagramNeverTakesTheNextProgramsRoute(t *testing.T) {
	h := startHandOver(t)
	if h == nil {
		return
	}
	other, otherDest := newUDPEcho6(t)
	h.programA.Close()
	program(t, h.source.Port)
	h.resolver.setAnswer("rule 0")
	h.flows.HandlePacket(h.source, otherDest, []byte("B-data"))
	time.Sleep(15 * time.Millisecond)
	close(h.release)
	waitUntil(t, "B's datagram arrives", 2*time.Second, func() bool { return len(other.senders()) == 1 })
	time.Sleep(300 * time.Millisecond)

	h.report(t)
	if got := h.internet.senders(); len(got) != 0 {
		t.Errorf("A's datagram (A's rule: block) reached the internet from %v", got)
	}
}

// The same with B on the port and silent: no datagram of B's re-checks the source. The resolver
// answered A's question with A's rule, and the flow A's datagram would have opened was routed with a
// question of its own, answered with B's. The table is read again once the route is known: B's
// socket is there, and A's datagram is dropped.
func TestYozhUDPFlowAWaitingDatagramIsDroppedWhileTheNextProgramIsSilent(t *testing.T) {
	h := startHandOver(t)
	if h == nil {
		return
	}
	h.programA.Close()
	program(t, h.source.Port)
	h.resolver.setAnswer("rule 0")
	time.Sleep(15 * time.Millisecond)
	close(h.release)
	time.Sleep(400 * time.Millisecond)

	h.report(t)
	if got := h.internet.senders(); len(got) != 0 {
		t.Errorf("A's datagram (A's rule: block) reached the internet from %v", got)
	}
}

// A sends one more datagram, to a third address, and closes; nobody takes the port. The datagram
// that waited for its route is dropped. The last one, held by the check that found no socket, is
// the one the check decides: with no socket to ask about it goes through the base (nolocal), never
// direct.
func TestYozhUDPFlowAWaitingDatagramOfAProgramThatClosedIsDropped(t *testing.T) {
	h := startHandOver(t)
	if h == nil {
		return
	}
	other, otherDest := newUDPEcho6(t)
	h.flows.HandlePacket(h.source, otherDest, []byte("A-last"))
	h.programA.Close()
	h.resolver.setAnswer("nolocal")
	time.Sleep(15 * time.Millisecond)
	close(h.release)
	time.Sleep(400 * time.Millisecond)

	h.report(t)
	if got := h.internet.senders(); len(got) != 0 {
		t.Errorf("A's datagram (A's rule: block) reached the internet from %v", got)
	}
	if up := uplinkOf(h.instance, "direct"); up != int64(len("A-to-lan")) {
		t.Errorf("direct carried %d bytes, want only the LAN datagram's %d", up, len("A-to-lan"))
	}
	if got := other.senders(); len(got) > 1 {
		t.Errorf("A's last datagram arrived %d times", len(got))
	}
}
