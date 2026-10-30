package tun

// A UDP flow belongs to its source socket. These tests drive the real flow table with
// a socket table and a dispatcher of their own, so every rule of udp_flow_policy.go is pinned on
// every platform; udp_socket_darwin_test.go reads the real kernel table, and
// udp_flow_engine_test.go runs the whole engine.

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
)

// ---- A socket table the test sets --------------------------------------------------------------

type fakeSockets struct {
	mu     sync.Mutex
	marks  map[net.Destination][]uint64 // a source with no entry has no socket
	calls  int                          // reads of the table
	gate   chan struct{}                // when set, a read waits for it to close
	gated  int                          // reads that came to the gate
	broken bool                         // the table cannot be read
}

func newFakeSockets() *fakeSockets {
	return &fakeSockets{marks: map[net.Destination][]uint64{}}
}

func (f *fakeSockets) set(source net.Destination, marks ...uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(marks) == 0 {
		delete(f.marks, source)
		return
	}
	f.marks[source] = marks
}

func (f *fakeSockets) setBroken(broken bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.broken = broken
}

func (f *fakeSockets) reads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSockets) hold() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = make(chan struct{})
	return f.gate
}

// atGate: how many reads have come to the gate since the test set one.
func (f *fakeSockets) atGate() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gated
}

func (f *fakeSockets) identify(sources []net.Destination) []socketIdentity {
	f.mu.Lock()
	gate := f.gate
	if gate != nil {
		f.gated++
	}
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	identities := make([]socketIdentity, len(sources))
	if f.broken {
		return identities
	}
	for i, source := range sources {
		identities[i] = socketIdentity{known: true, marks: []socketMark{}}
		for _, generation := range f.marks[source] {
			identities[i].marks = append(identities[i].marks, socketMark{generation: generation})
		}
	}
	return identities
}

// ---- A dispatcher that records every flow ------------------------------------------------------

type recordedFlow struct {
	first  net.Destination
	conn   *udpConn
	mu     sync.Mutex
	got    []string // payloads, in order
	closed bool     // Close has been called
}

func (f *recordedFlow) payloads() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.got, ",")
}

func (f *recordedFlow) wasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

type flowRecorder struct {
	mu      sync.Mutex
	flows   []*recordedFlow
	linger  time.Duration // how long a flow's dispatch outlives its EOF (an outbound winding down)
	replies []string
	// repliesFrom: whom each of the replies came from, as the program is shown it.
	repliesFrom []net.Destination
	// holdWrite, when set, makes the next reply's write signal `writing` and wait for `release`.
	holdWrite *heldWrite

	// The recorder is the dispatcher too, and reports each flow's route as the real one does
	// (session.FlowRoute). routes: where a destination is routed, "out" when it is not listed.
	routes map[net.Destination]string
	// sniffed: where a flow is sent by its first destination when that differs from routes — the
	// real dispatcher routes a flow's first packet by the name it sniffed in it.
	sniffed map[net.Destination]string
	// silent: flows are handed on without a report, as by a dispatcher that never reports.
	silent bool
	// reportGate, when set, holds every report until it is closed (sniffing takes its time).
	reportGate chan struct{}
	// told: destinations whose datagrams name their route only two or more together (a ClientHello
	// split over two QUIC Initials), and the route of that name. Given one, RouteOf answers
	// protocol.ErrProtoNeedMoreData; given none, nothing is sniffed and routes decides.
	told map[net.Destination]string
	// routeQuestions counts RouteOf calls: routing a destination that is not a flow's first.
	routeQuestions int
	// asked: every RouteOf question, with the datagrams it was given.
	asked []routeQuestion
	// routeGate, when set, holds every RouteOf answer until it is closed (routing takes its time).
	routeGate chan struct{}
	// routeDelay: how long each RouteOf answer takes (a resolver's round trip).
	routeDelay time.Duration
}

func (r *flowRecorder) setRoutes(routes map[net.Destination]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes = routes
}

type routeQuestion struct {
	dest      net.Destination
	datagrams string // the datagrams given, comma-separated
}

func (r *flowRecorder) routeOf(dest net.Destination, datagrams [][]byte) (string, error) {
	given := make([]string, len(datagrams))
	for i, datagram := range datagrams {
		given[i] = string(datagram)
	}
	r.mu.Lock()
	r.routeQuestions++
	r.asked = append(r.asked, routeQuestion{dest: dest, datagrams: strings.Join(given, ",")})
	gate, delay := r.routeGate, r.routeDelay
	r.mu.Unlock()
	if gate != nil {
		<-gate
	}
	time.Sleep(delay)
	r.mu.Lock()
	defer r.mu.Unlock()
	if tag, ok := r.told[dest]; ok && len(datagrams) > 0 {
		if len(datagrams) < 2 {
			return "", protocol.ErrProtoNeedMoreData
		}
		return tag, nil
	}
	if tag, ok := r.routes[dest]; ok {
		return tag, nil
	}
	return "out", nil
}

func (r *flowRecorder) questions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routeQuestions
}

// questionsAbout is what RouteOf was given each time it was asked about dest, in order.
func (r *flowRecorder) questionsAbout(dest net.Destination) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var given []string
	for _, question := range r.asked {
		if question.dest == dest {
			given = append(given, question.datagrams)
		}
	}
	return given
}

// report is what the dispatcher does between routing a flow and handing it to its outbound.
func (r *flowRecorder) report(conn *udpConn, first net.Destination) {
	r.mu.Lock()
	silent, gate := r.silent, r.reportGate
	tag, ok := r.sniffed[first]
	if !ok {
		if tag, ok = r.routes[first]; !ok {
			tag = "out"
		}
	}
	r.mu.Unlock()
	if silent {
		return
	}
	if gate != nil {
		<-gate
	}
	conn.settle(session.FlowRoute{Tag: tag, RouteOf: r.routeOf})
}

type heldWrite struct {
	writing, release chan struct{}
}

// holdNextWrite makes the next reply's write wait, mid-write, until release is closed.
func (r *flowRecorder) holdNextWrite() (writing, release chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.holdWrite = &heldWrite{writing: make(chan struct{}), release: make(chan struct{})}
	return r.holdWrite.writing, r.holdWrite.release
}

func (r *flowRecorder) handle(conn net.Conn, dest net.Destination) {
	flow := &recordedFlow{first: dest, conn: conn.(*udpConn)}
	r.mu.Lock()
	r.flows = append(r.flows, flow)
	linger := r.linger
	r.mu.Unlock()
	r.report(flow.conn, dest)
	for {
		mb, err := conn.(buf.Reader).ReadMultiBuffer()
		if err != nil {
			break
		}
		flow.mu.Lock()
		for _, b := range mb {
			flow.got = append(flow.got, string(b.Bytes()))
		}
		flow.mu.Unlock()
		buf.ReleaseMulti(mb)
	}
	time.Sleep(linger)
	conn.Close()
	flow.mu.Lock()
	flow.closed = true
	flow.mu.Unlock()
}

func (r *flowRecorder) write(data []byte, src net.Destination, dst net.Destination) error {
	r.mu.Lock()
	held := r.holdWrite
	r.holdWrite = nil
	r.mu.Unlock()
	if held != nil {
		close(held.writing)
		<-held.release
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replies = append(r.replies, string(data))
	r.repliesFrom = append(r.repliesFrom, src)
	return nil
}

func (r *flowRecorder) all() []*recordedFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*recordedFlow(nil), r.flows...)
}

// payloadsOf: what flow i received so far, "" while there is no flow i yet.
func (r *flowRecorder) payloadsOf(i int) string {
	flows := r.all()
	if i >= len(flows) {
		return ""
	}
	return flows[i].payloads()
}

func (r *flowRecorder) delivered() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.replies...)
}

// deliveredFrom: whom the replies delivered so far appear to come from, in the order of delivered.
func (r *flowRecorder) deliveredFrom() []net.Destination {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]net.Destination(nil), r.repliesFrom...)
}

// ---- Helpers -----------------------------------------------------------------------------------

var (
	flowSource = net.UDPDestination(net.ParseAddress("198.18.0.2"), 50000)
	flowA      = net.UDPDestination(net.ParseAddress("192.0.2.1"), 3478)
	flowB      = net.UDPDestination(net.ParseAddress("192.0.2.2"), 3478)
	flowC      = net.UDPDestination(net.ParseAddress("192.0.2.3"), 3478)
	flowD      = net.UDPDestination(net.ParseAddress("192.0.2.4"), 3478)
)

// testPolicy is darwin's policy with the test's socket table, a 5 ms window, a silence of `silence`
// and no idle expiry unless the test sets one.
func testPolicy(sockets socketLookup, silence time.Duration) udpFlowPolicy {
	return udpFlowPolicy{lookup: sockets, window: 5 * time.Millisecond, silence: silence}
}

func newTestFlows(policy udpFlowPolicy) (*udpConnectionHandler, *flowRecorder) {
	recorder := &flowRecorder{}
	return newUdpConnectionHandlerWithPolicy(recorder.handle, recorder.write, policy), recorder
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// flowFor is the oldest live flow of source, nil when the table holds none.
func (u *udpConnectionHandler) flowFor(source net.Destination) *udpConn {
	u.Lock()
	defer u.Unlock()
	if s := u.sources[source]; s != nil && len(s.flows) > 0 {
		return s.flows[0]
	}
	return nil
}

// routedFlow: the oldest flow of source has reported its route (settle).
func (u *udpConnectionHandler) routedFlow(source net.Destination) bool {
	u.Lock()
	defer u.Unlock()
	s := u.sources[source]
	return s != nil && len(s.flows) > 0 && s.flows[0].routed
}

// identifiedFlow: the table knows which socket is behind source.
func (u *udpConnectionHandler) identifiedFlow(source net.Destination) bool {
	u.Lock()
	defer u.Unlock()
	s := u.sources[source]
	return s != nil && s.identified
}

func flowCount(r *flowRecorder) int { return len(r.all()) }

// carried: the flows that carried payload p, by their order.
func (r *flowRecorder) carried(p string) []int {
	var in []int
	for i, flow := range r.all() {
		for _, got := range strings.Split(flow.payloads(), ",") {
			if got == p {
				in = append(in, i)
			}
		}
	}
	return in
}

// waitingFor: how many packets of source wait for a route, and whether a check of it is under way.
func (u *udpConnectionHandler) waitingFor(source net.Destination) (int, bool) {
	u.Lock()
	defer u.Unlock()
	if s := u.sources[source]; s != nil {
		return len(s.waiting), s.checking
	}
	return 0, false
}

// routingOver: nothing of source is waiting for a route, or the table no longer holds it.
func (u *udpConnectionHandler) routingOver(source net.Destination) bool {
	u.Lock()
	defer u.Unlock()
	s := u.sources[source]
	return s == nil || !s.routing && len(s.waiting) == 0
}

// ---- Full cone for a live socket -----------------------------------------------------------------

// One socket, three destinations: one flow, one outbound — the full cone this inbound exists for.
func TestUDPFlowOneSocketKeepsOneFlowAcrossDestinations(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "all three packets in the flow", func() bool { return r.payloadsOf(0) == "a,b,c" })
	time.Sleep(20 * time.Millisecond)
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows for one socket, want 1", n)
	}
}

// ---- A new flow is routed once its socket is known -----------------------------------------------

// A new flow goes to routing only after the table has said which socket it belongs to. Routed first
// and identified after, the flow could be routed for the program that sent its first packet (the
// resolver reads the table when it is asked) and then remember the socket of the next program on the
// port (the table read a moment later): that program's packets would pass every re-check and ride a
// route that was never its own. Until the answer, the flow's packets wait in its queue, in order.
func TestUDPFlowANewFlowIsRoutedOnlyOnceItsSocketIsKnown(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	gate := sockets.hold()
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	u.HandlePacket(flowSource, flowA, []byte("a2"))
	time.Sleep(30 * time.Millisecond)
	if n := flowCount(r); n != 0 {
		t.Fatalf("%d flow(s) handed to routing before the table answered", n)
	}
	close(gate)
	eventually(t, "the flow is routed with both packets, in order", func() bool { return r.payloadsOf(0) == "a,a2" })
	if !u.identifiedFlow(flowSource) {
		t.Fatal("routed without its socket")
	}
}

// ---- Another socket on the source ----------------------------------------------------------------

// The port changes hands, and the next program's packet to a new destination must not ride the
// first program's flow.
func TestUDPFlowAnotherSocketOnTheSourceStartsANewFlow(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("from-A"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	sockets.set(flowSource, 9) // program A closed its socket, program B got the port
	u.HandlePacket(flowSource, flowB, []byte("from-B"))

	eventually(t, "a second flow", func() bool { return flowCount(r) == 2 })
	flows := r.all()
	eventually(t, "B's packet in the second flow", func() bool { return flows[1].payloads() == "from-B" })
	if flows[1].first != flowB {
		t.Fatalf("the new flow starts at %v, want %v", flows[1].first, flowB)
	}
	if got := flows[0].payloads(); got != "from-A" {
		t.Fatalf("the old flow got %q", got)
	}
	eventually(t, "the old flow is finished", func() bool { return flows[0].wasClosed() })
}

// A socket that vanished is not the flow's socket either: whoever sent this packet is gone or new.
func TestUDPFlowASocketThatVanishedStartsANewFlow(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	sockets.set(flowSource)
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "a second flow", func() bool { return flowCount(r) == 2 })
}

// A program that sent once and closed its socket before the table was read leaves a flow with no
// socket; a socket there now belongs to another program.
func TestUDPFlowNoSocketThenASocketIsAnotherProgram(t *testing.T) {
	sockets := newFakeSockets()
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("one-shot"))
	eventually(t, "the flow knows it has no socket", func() bool { return u.identifiedFlow(flowSource) })
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowB, []byte("new-program"))
	eventually(t, "a second flow", func() bool { return flowCount(r) == 2 })
	eventually(t, "its packet", func() bool { return r.payloadsOf(1) == "new-program" })
}

// No socket before and none now: a virtual machine or internet sharing behind the Mac. It keeps the
// full cone it has today.
func TestUDPFlowNoSocketBeforeAndNoneNowStaysOneFlow(t *testing.T) {
	sockets := newFakeSockets()
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows it has no socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "all in one flow", func() bool { return r.payloadsOf(0) == "a,b,c" })
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1", n)
	}
}

// ---- When the table is asked -------------------------------------------------------------------

// The same destination after a silence on the program's side is asked about too: a port that
// changed hands usually did so in a pause.
func TestUDPFlowTheSameDestinationAfterASilenceIsRechecked(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, 100*time.Millisecond))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	sockets.set(flowSource, 9)
	time.Sleep(150 * time.Millisecond)
	u.HandlePacket(flowSource, flowA, []byte("a-again"))
	eventually(t, "a second flow", func() bool { return flowCount(r) == 2 })
}

// The residual risk udp_flow_policy.go names under "What is left": the same destination within the
// silence is NOT asked about. This pins the window so that changing it is a decision, not an
// accident. The re-check interval bounds it
// (TestUDPFlowASteadyStreamToOneDestinationIsRecheckedEveryInterval); testPolicy sets none.
func TestUDPFlowTheSameDestinationWithinTheSilenceIsNotRechecked(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	reads := sockets.reads()
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowA, []byte("a-again"))
	eventually(t, "the packet in the first flow", func() bool { return r.payloadsOf(0) == "a,a-again" })
	if n, more := flowCount(r), sockets.reads()-reads; n != 1 || more != 0 {
		t.Fatalf("%d flows and %d more reads, want 1 flow and no read", n, more)
	}
}

// A stream that never pauses and never changes destination is asked about too, every `recheck`: a
// port that changes hands between two of its packets would otherwise carry the next program on the
// old one's flow for as long as the stream lasts.
func TestUDPFlowASteadyStreamToOneDestinationIsRecheckedEveryInterval(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	policy := testPolicy(sockets, time.Second)
	policy.recheck = 150 * time.Millisecond
	u, r := newTestFlows(policy)

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	start := time.Now()
	sockets.set(flowSource, 9) // the port changes hands; the stream goes on without a pause
	for flowCount(r) < 2 && time.Since(start) < time.Second {
		u.HandlePacket(flowSource, flowA, []byte("x"))
		time.Sleep(10 * time.Millisecond)
	}
	if n := flowCount(r); n != 2 {
		t.Fatalf("%d flow(s) after a second of a steady stream from another socket, want 2", n)
	}
	if took := time.Since(start); took < 100*time.Millisecond {
		t.Fatalf("re-checked after %v: sooner than the interval, so not by it", took)
	}
}

// The same stream from the same socket stays one flow — the full cone — while it is asked about.
func TestUDPFlowASteadyStreamFromItsOwnSocketStaysOneFlowAcrossRechecks(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	policy := testPolicy(sockets, time.Second)
	policy.recheck = 50 * time.Millisecond
	u, r := newTestFlows(policy)

	u.HandlePacket(flowSource, flowA, []byte("0"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	reads := sockets.reads()
	want := []string{"0"}
	for i := 1; i <= 30; i++ {
		payload := strconv.Itoa(i)
		u.HandlePacket(flowSource, flowA, []byte(payload))
		want = append(want, payload)
		time.Sleep(10 * time.Millisecond)
	}
	eventually(t, "every packet in the one flow, in order", func() bool { return r.payloadsOf(0) == strings.Join(want, ",") })
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows for one socket, want 1", n)
	}
	if more := sockets.reads() - reads; more < 3 {
		t.Fatalf("%d re-checks in 300 ms at a 50 ms interval, want several", more)
	}
}

// ---- The check never blocks, keeps order, and is shared ----------------------------------------

// While the table is being read, the source's packets wait — in order — and the stack is not held
// up: HandlePacket returns at once. When the answer is "another socket", all of them go to the new
// flow.
func TestUDPFlowPacketsWaitForTheCheckInOrderWithoutBlocking(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	gate := sockets.hold()
	sockets.set(flowSource, 9)
	for _, p := range []struct {
		to   net.Destination
		data string
	}{{flowB, "b"}, {flowC, "c"}, {flowD, "d"}} {
		start := time.Now()
		u.HandlePacket(flowSource, p.to, []byte(p.data))
		if took := time.Since(start); took > 50*time.Millisecond {
			t.Fatalf("HandlePacket blocked for %v while the table was being read", took)
		}
	}
	time.Sleep(30 * time.Millisecond)
	if n := flowCount(r); n != 1 || r.payloadsOf(0) != "a" {
		t.Fatalf("packets went somewhere before the answer: %d flows, first got %q", n, r.payloadsOf(0))
	}
	close(gate)
	eventually(t, "b, c, d in the new flow, in order", func() bool {
		return r.payloadsOf(1) == "b,c,d"
	})
}

// One read answers every check of a window: forty sources asking at once cost at most two reads.
// Each second packet goes to a new destination, so each source reads the table once more when that
// destination's route is known (routeWaiting); those reads come together too, and share one.
func TestUDPFlowChecksShareOneReadOfTheTable(t *testing.T) {
	sockets := newFakeSockets()
	policy := testPolicy(sockets, time.Second)
	policy.window = 50 * time.Millisecond
	u, r := newTestFlows(policy)
	var sources []net.Destination
	for i := 0; i < 40; i++ {
		source := net.UDPDestination(net.ParseAddress("198.18.0.2"), net.Port(51000+i))
		sockets.set(source, uint64(100+i))
		sources = append(sources, source)
		u.HandlePacket(source, flowA, []byte("a"))
	}
	for _, source := range sources {
		eventually(t, "every flow knows its socket", func() bool { return u.identifiedFlow(source) })
	}
	time.Sleep(60 * time.Millisecond) // the window after the last read
	before := sockets.reads()
	for _, source := range sources {
		u.HandlePacket(source, flowB, []byte("b"))
	}
	eventually(t, "every flow got its second packet", func() bool {
		for _, flow := range r.all() {
			if flow.payloads() != "a,b" {
				return false
			}
		}
		return true
	})
	if reads := sockets.reads() - before; reads > 3 {
		t.Fatalf("%d reads for 40 checks and 40 routes in one burst, want at most 3", reads)
	}
	if n := flowCount(r); n != 40 {
		t.Fatalf("%d flows, want 40 (every socket is still its own)", n)
	}
}

// A table that cannot be read is no reason to break every flow: today's full cone.
func TestUDPFlowAnUnreadableTableKeepsTheFullCone(t *testing.T) {
	sockets := newFakeSockets()
	sockets.broken = true
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow is routed on the (unknown) answer", func() bool { return r.payloadsOf(0) == "a" })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "both in one flow", func() bool { return r.payloadsOf(0) == "a,b" })
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1", n)
	}
}

// A table that could not be read when the flow began says nothing about the flow's socket, and the
// flow does not keep that "unknown" for life — unknown is the same as anything, so it would pass
// every re-check to the end. The next answer that names a socket is taken as the first one, and the
// re-checks after it hold the flow to that socket.
func TestUDPFlowAnUnknownSocketIsReplacedByTheNextKnownAnswer(t *testing.T) {
	sockets := newFakeSockets()
	sockets.setBroken(true)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow is routed on the unknown answer", func() bool { return r.payloadsOf(0) == "a" })
	sockets.setBroken(false)
	sockets.set(flowSource, 7)
	u.HandlePacket(flowSource, flowB, []byte("b")) // re-checked: the first known answer is the flow's socket
	eventually(t, "b in the same flow", func() bool { return r.payloadsOf(0) == "a,b" })
	sockets.set(flowSource, 9) // the port changes hands
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "c in a flow of its own", func() bool { return r.payloadsOf(1) == "c" })
	if got := r.payloadsOf(0); got != "a,b" {
		t.Fatalf("the first flow got %q", got)
	}
}

// The same for a flow a re-check opens: its predecessor ended during the check and the answer was
// unknown. The successor asks the table for its own socket instead of keeping "unknown" for life.
func TestUDPFlowASuccessorOpenedOnAnUnknownAnswerAsksForItsOwnSocket(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	eventually(t, "the first flow is dispatched", func() bool { return flowCount(r) == 1 })
	gate := sockets.hold()
	sockets.setBroken(true)
	u.HandlePacket(flowSource, flowB, []byte("b")) // another destination: checked, waits
	first := r.all()[0]
	first.conn.Close() // the outbound's dispatch returns while the check waits
	eventually(t, "the first flow's dispatch is over", func() bool { return first.wasClosed() })
	close(gate) // the answer is "unknown": b opens the successor
	eventually(t, "b in the successor", func() bool { return r.payloadsOf(1) == "b" })

	sockets.setBroken(false)
	sockets.set(flowSource, 7)
	u.HandlePacket(flowSource, flowC, []byte("c")) // the first known answer: the successor's socket
	eventually(t, "c in the successor", func() bool { return r.payloadsOf(1) == "b,c" })
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowD, []byte("d"))
	eventually(t, "d in a flow of its own", func() bool { return r.payloadsOf(2) == "d" })
}

// ---- The old flow's end never ends its successor -------------------------------------------------

// Measured on upstream's code: an early-retired flow's Close, arriving after its outbound wound
// down, deleted whatever sat under the key — the NEW flow.
func TestUDPFlowAnOldFlowsCloseNeverEndsItsSuccessor(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.linger = 200 * time.Millisecond

	u.HandlePacket(flowSource, flowA, []byte("old"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowB, []byte("new-1"))
	eventually(t, "the successor", func() bool { return flowCount(r) == 2 })
	successor := r.all()[1]
	eventually(t, "the old flow's Close", func() bool { return r.all()[0].wasClosed() })

	if got := u.flowFor(flowSource); got != successor.conn {
		t.Fatal("the old flow's Close removed or replaced its successor")
	}
	u.HandlePacket(flowSource, flowB, []byte("new-2"))
	eventually(t, "the successor keeps receiving", func() bool { return successor.payloads() == "new-1,new-2" })
	if n := flowCount(r); n != 2 {
		t.Fatalf("%d flows, want 2: a third means the successor was lost", n)
	}
}

// A flow whose outbound's dispatch ends while a check is under way stays in the table until the
// answer: a packet sent meanwhile waits behind the ones already held instead of overtaking them in
// a flow of its own.
func TestUDPFlowAFlowEndingDuringACheckKeepsItsPacketsInOrder(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow", func() bool { return flowCount(r) == 1 })
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	gate := sockets.hold()
	u.HandlePacket(flowSource, flowB, []byte("b")) // another destination: checked, waits
	first := r.all()[0]
	first.conn.Close() // the outbound's dispatch returns while the check waits
	eventually(t, "the first flow's dispatch is over", func() bool { return first.wasClosed() })
	u.HandlePacket(flowSource, flowC, []byte("c"))
	time.Sleep(20 * time.Millisecond)
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows before the answer: a packet overtook the ones waiting", n)
	}
	close(gate)
	eventually(t, "b, c in the next flow, in order", func() bool { return r.payloadsOf(1) == "b,c" })
	if n := flowCount(r); n != 2 {
		t.Fatalf("%d flows, want 2", n)
	}
}

// ---- Idle ---------------------------------------------------------------------------------------

// The idle time is chosen by the first packet: its protocol's own header where it has one, else its
// port.
func TestUDPFlowIdleTimeIsChosenByTheFirstPacket(t *testing.T) {
	stun := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	quic := append([]byte{0xC3, 0x00, 0x00, 0x00, 0x01}, make([]byte, 20)...)
	dtls := append([]byte{22, 0xFE, 0xFD}, make([]byte, 20)...)
	other := []byte("hello")
	to := func(port net.Port) net.Destination {
		return net.UDPDestination(net.ParseAddress("192.0.2.9"), port)
	}
	for _, c := range []struct {
		name  string
		dst   net.Destination
		first []byte
		want  time.Duration
	}{
		{"dns by port", to(53), other, 10 * time.Second},
		{"ntp by port", to(123), other, 10 * time.Second},
		{"stun by port", to(3478), other, 10 * time.Second},
		{"stun by its cookie on Google's port", to(19302), stun, 10 * time.Second},
		{"quic by port", to(443), other, 30 * time.Second},
		{"quic v1 long header elsewhere", to(8443), quic, 30 * time.Second},
		{"quic on the dns port: the header decides first", to(53), quic, 30 * time.Second},
		{"dtls record elsewhere", to(50123), dtls, 30 * time.Second},
		{"anything else", to(27015), other, 60 * time.Second},
		{"an empty first packet", to(27015), nil, 60 * time.Second},
	} {
		if got := udpIdleByFirstPacket(c.dst, c.first); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Replies do not keep a flow alive: a remote that keeps sending cannot hold a port for a program
// that has gone. Once retired, the flow refuses what its outbound still hands it.
func TestUDPFlowRepliesDoNotKeepAFlowAlive(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	policy := testPolicy(sockets, time.Second)
	policy.idle = func(net.Destination, []byte) time.Duration { return 200 * time.Millisecond }
	u, r := newTestFlows(policy)

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow", func() bool { return flowCount(r) == 1 })
	flow := r.all()[0]
	start := time.Now()
	for time.Since(start) < 500*time.Millisecond && !flow.conn.retired.Load() {
		reply := buf.New()
		reply.Write([]byte("reply"))
		reply.UDP = &flowA
		flow.conn.WriteMultiBuffer(buf.MultiBuffer{reply})
		time.Sleep(40 * time.Millisecond)
	}
	if !flow.conn.retired.Load() {
		t.Fatal("replies kept the flow alive past its idle time")
	}
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("retired after %v, want about 200 ms", took)
	}
	delivered := len(r.delivered())
	late := buf.New()
	late.Write([]byte("late"))
	late.UDP = &flowA
	if err := flow.conn.WriteMultiBuffer(buf.MultiBuffer{late}); err != errUDPFlowRetired {
		t.Fatalf("a retired flow took a reply: %v", err)
	}
	if len(r.delivered()) != delivered {
		t.Fatal("a reply of a retired flow reached the tun side")
	}
	eventually(t, "the flow is finished", func() bool { return flow.wasClosed() && u.flowFor(flowSource) == nil })
}

// A reply is written before the flow is retired or not at all. Checked once at the start of a batch,
// the rest of a batch that was being written when the flow ended went on to the tun side — to a port
// that the retirement had just found in another program's hands. Only the reply already under way
// when the flow ends may still land; none after it.
func TestUDPFlowNoReplyIsWrittenOnceTheFlowIsRetired(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow", func() bool { return flowCount(r) == 1 })
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	flow := r.all()[0]
	reply := func(payload string) *buf.Buffer {
		b := buf.New()
		b.Write([]byte(payload))
		b.UDP = &flowA
		return b
	}
	writing, release := r.holdNextWrite()
	result := make(chan error, 1)
	go func() {
		result <- flow.conn.WriteMultiBuffer(buf.MultiBuffer{reply("r1"), reply("r2"), reply("r3")})
	}()
	<-writing // r1 is being written
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowB, []byte("b")) // the re-check finds another socket: the flow ends
	time.Sleep(100 * time.Millisecond)             // the answer is in and the flow is being retired
	close(release)

	if err := <-result; err != errUDPFlowRetired {
		t.Fatalf("the batch ended with %v, want the retired flow's refusal", err)
	}
	if got := strings.Join(r.delivered(), ","); got != "r1" {
		t.Fatalf("replies written: %q; after the flow ended only the one under way may land", got)
	}
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
}

// Retiring a flow does not wait for the reply its outbound is writing. It is retired under the
// table's lock, and that lock is every source's: waiting there for one flow's write to the tun side
// held up every other program's packets, every check's answer and every idle check behind it.
func TestUDPFlowRetiringAFlowNeverWaitsForItsReplyWrite(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	other := net.UDPDestination(net.ParseAddress("198.18.0.2"), 50001)
	sockets.set(other, 8)
	u, r := newTestFlows(testPolicy(sockets, time.Second))

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return flowCount(r) == 1 && u.identifiedFlow(flowSource) })
	flow := r.all()[0]
	writing, release := r.holdNextWrite()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	reply := buf.New()
	reply.Write([]byte("r1"))
	reply.UDP = &flowA
	go flow.conn.WriteMultiBuffer(buf.MultiBuffer{reply})
	<-writing // the reply is being written
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowB, []byte("b")) // the re-check finds another socket: the flow ends
	time.Sleep(50 * time.Millisecond)              // the answer is in and the flow is being retired

	handled := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		u.HandlePacket(other, flowA, []byte("o"))
		handled <- time.Since(start)
	}()
	select {
	case took := <-handled:
		t.Logf("another source's packet was handled after %v", took)
	case <-time.After(300 * time.Millisecond):
		close(release)
		t.Fatalf("another source's packet waited %v and more for one flow's reply write", <-handled)
	}
}

// The program's own packets do keep it alive.
func TestUDPFlowTheProgramsPacketsKeepItAlive(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	policy := testPolicy(sockets, time.Second)
	policy.idle = func(net.Destination, []byte) time.Duration { return 300 * time.Millisecond }
	u, r := newTestFlows(policy)

	u.HandlePacket(flowSource, flowA, []byte("a"))
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		u.HandlePacket(flowSource, flowA, []byte("a"))
	}
	if n := flowCount(r); n != 1 || r.all()[0].conn.retired.Load() {
		t.Fatalf("%d flows (retired: %v) while the program kept sending", n, r.all()[0].conn.retired.Load())
	}
	eventually(t, "retired once the program stops", func() bool { return r.all()[0].conn.retired.Load() })
}

// ---- Without a policy: upstream's full cone ------------------------------------------------------

// What every platform but darwin gets (udp_socket_other.go): no reads, no idle of the inbound's own.
func TestUDPFlowWithoutAPolicyIsUpstreamsFullCone(t *testing.T) {
	u, r := newTestFlows(udpFlowPolicy{})
	if u.checker != nil {
		t.Fatal("a checker without a socket table")
	}
	u.HandlePacket(flowSource, flowA, []byte("a"))
	time.Sleep(20 * time.Millisecond)
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "both in one flow", func() bool { return r.payloadsOf(0) == "a,b" })
	time.Sleep(100 * time.Millisecond)
	if n, retired := flowCount(r), r.all()[0].conn.retired.Load(); n != 1 || retired {
		t.Fatalf("%d flows, retired %v: want one live flow", n, retired)
	}
}

// ---- Every destination on its own route ----------------------------------------------------------

// A datagram to a destination that another route takes travels in a flow of its own. The flow was
// routed once, by its first datagram, and carried the socket's datagrams to anywhere: a first
// datagram that an address row sends direct took the rest of the program's traffic direct with it.
func TestUDPFlowADestinationAnotherRouteTakesGetsAFlowOfItsOwn(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy"})

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
	if first := r.all()[1].first; first != flowB {
		t.Fatalf("the second flow starts at %v, want %v", first, flowB)
	}
	time.Sleep(20 * time.Millisecond)
	if got := r.payloadsOf(0); got != "a" {
		t.Fatalf("the first flow carried %q, want only a", got)
	}
}

// Destinations of one route share its flow — the full cone, within the route — and a destination
// is routed once while its flow lives.
func TestUDPFlowDestinationsOfOneRouteShareItsFlow(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy", flowC: "direct"})

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	for _, step := range []struct {
		to   net.Destination
		data string
		flow int
		want string
	}{{flowB, "b", 0, "a,b"}, {flowC, "c", 1, "c"}, {flowB, "b2", 0, "a,b,b2"}, {flowA, "a2", 0, "a,b,b2,a2"}, {flowC, "c2", 1, "c,c2"}} {
		u.HandlePacket(flowSource, step.to, []byte(step.data))
		eventually(t, step.data+" in flow "+strconv.Itoa(step.flow), func() bool { return r.payloadsOf(step.flow) == step.want })
	}
	if n := flowCount(r); n != 2 {
		t.Fatalf("%d flows, want 2: one per route", n)
	}
	if q := r.questions(); q != 2 {
		t.Fatalf("%d destinations routed, want 2 (b and c, once each)", q)
	}
}

// A flow is matched by where it was sent, not by where its first address would be routed: the
// dispatcher routes a flow's first packet by the name it sniffed in it, and a flow sent direct for
// its name must not carry a destination the rows send through the proxy.
func TestUDPFlowAFlowIsMatchedByWhereItWentNotByItsFirstAddress(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy"})
	r.mu.Lock()
	r.sniffed = map[net.Destination]string{flowA: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
	if got := r.payloadsOf(0); got != "a" {
		t.Fatalf("the flow sent direct carried %q", got)
	}
}

// A datagram to a new destination waits until the source's flows are routed — the dispatcher's
// report — and goes nowhere meanwhile: not even into the flow it will turn out to share.
func TestUDPFlowANewDestinationWaitsForItsFlowsToBeRouted(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy"})
	gate := make(chan struct{})
	r.mu.Lock()
	r.reportGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	time.Sleep(30 * time.Millisecond)
	first := u.flowFor(flowSource)
	if n, queued := flowCount(r), len(first.egress); n != 1 || queued != 1 {
		t.Fatalf("before the report: %d flows, %d packets in the first flow's queue; want 1 and 1 (a alone)", n, queued)
	}
	close(gate)
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
	if got := r.payloadsOf(0); got != "a" {
		t.Fatalf("the first flow carried %q", got)
	}
}

// Each flow of a source lives on its own: the end of one does not end the others, and its
// destinations are routed again when the program sends to them next.
func TestUDPFlowTheFlowsOfASourceEndOneByOne(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy"})

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
	first := r.all()[0]
	first.conn.Close() // the first flow's outbound winds down
	eventually(t, "the first flow's dispatch is over", func() bool { return first.wasClosed() })

	u.HandlePacket(flowSource, flowB, []byte("b2"))
	eventually(t, "b2 in b's flow", func() bool { return r.payloadsOf(1) == "b,b2" })
	u.HandlePacket(flowSource, flowA, []byte("a2"))
	eventually(t, "a2 in a new flow", func() bool { return r.payloadsOf(2) == "a2" })
	if n := flowCount(r); n != 3 {
		t.Fatalf("%d flows, want 3", n)
	}
}

// Another socket on the source ends every flow of it: they were all the previous program's.
func TestUDPFlowAnotherSocketEndsEveryFlowOfTheSource(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy"})

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
	sockets.set(flowSource, 9)
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "c in a flow of its own", func() bool { return r.payloadsOf(2) == "c" })
	eventually(t, "both flows of the previous socket are finished", func() bool {
		return r.all()[0].wasClosed() && r.all()[1].wasClosed()
	})
}

// A flow whose route is never reported (its dispatch ended before routing, or a dispatcher that does
// not report) is not waited for past routeWait: the datagram to a new destination goes into a flow
// of its own, which is routed for it.
func TestUDPFlowAFlowThatIsNeverReportedIsNotWaitedForForever(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	u.routeWait = 100 * time.Millisecond
	r.mu.Lock()
	r.silent = true
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b"))
	eventually(t, "b in a flow of its own", func() bool { return r.payloadsOf(1) == "b" })
	if got := r.payloadsOf(0); got != "a" {
		t.Fatalf("the unreported flow carried %q", got)
	}
}

// Packets to one destination keep their order when every flow of the source ends while they wait
// for their route: a later one does not open a flow ahead of the earlier ones.
func TestUDPFlowPacketsWaitingForARouteKeepTheirOrderWhenTheFlowsEnd(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy"})
	gate := make(chan struct{})
	r.mu.Lock()
	r.routeGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b1"))
	eventually(t, "b is being routed", func() bool { return r.questions() == 1 })
	first := r.all()[0]
	first.conn.Close() // the only flow of the source ends while b1 waits for its route
	eventually(t, "the first flow's dispatch is over", func() bool { return first.wasClosed() })
	u.HandlePacket(flowSource, flowB, []byte("b2"))
	close(gate)
	eventually(t, "b1 and b2 in a flow", func() bool { return r.payloadsOf(1) != "" })
	time.Sleep(20 * time.Millisecond)
	if got := r.payloadsOf(1); got != "b1,b2" {
		t.Fatalf("the flow for b got %q, want b1,b2", got)
	}
}

// ---- A datagram waiting for its route when the port changes hands -------------------------------

// A datagram that waits for its route was checked as its program's. When the port changes hands
// meanwhile and the next program sends, that datagram is dropped: routed from scratch with the next
// program's datagrams, it took the next program's route, and a program whose rule blocks it left
// direct through the flow of a program allowed to. The next program's own datagram, held by the
// check that found the change, starts the source afresh.
func TestUDPFlowADatagramWaitingForItsRouteIsDroppedWhenThePortChangesHands(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "block", flowC: "direct"})
	gate := make(chan struct{})
	r.mu.Lock()
	r.routeGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b7"))
	eventually(t, "b7 is being routed", func() bool { return r.questions() == 1 })
	sockets.set(flowSource, 8) // program 7 closed its socket, program 8 got the port
	u.HandlePacket(flowSource, flowC, []byte("c8"))
	eventually(t, "a flow after the hand-over", func() bool { return flowCount(r) == 2 })
	close(gate)
	eventually(t, "c8 is sent", func() bool { return len(r.carried("c8")) == 1 })
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if in := r.carried("b7"); len(in) != 0 {
		t.Fatalf("program 7's datagram, waiting for its route when the port changed hands, left in flow %v (the flows begin at %v)", in, firstDestinations(r))
	}
	eventually(t, "program 7's flow is finished", func() bool { return r.all()[0].wasClosed() })
}

// The same when nobody sends after the hand-over. The route of a waiting datagram was asked while
// the port changed hands, so the answer may be the next program's. The table is read again once the
// route is known and before the datagram goes anywhere: another socket there, and the datagram is
// dropped and the source's flows are finished — whether its route led into a new flow or into a flow
// of the previous program.
func TestUDPFlowADatagramWhoseRouteWasAskedAcrossAHandOverIsDropped(t *testing.T) {
	for _, c := range []struct{ name, route string }{{"into a new flow", "proxy"}, {"into the previous program's flow", "direct"}} {
		t.Run(c.name, func(t *testing.T) {
			sockets := newFakeSockets()
			sockets.set(flowSource, 7)
			u, r := newTestFlows(testPolicy(sockets, time.Second))
			r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: c.route})
			gate := make(chan struct{})
			r.mu.Lock()
			r.routeGate = gate
			r.mu.Unlock()

			u.HandlePacket(flowSource, flowA, []byte("a7"))
			eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
			u.HandlePacket(flowSource, flowB, []byte("b7"))
			eventually(t, "b7 is being routed", func() bool { return r.questions() == 1 })
			sockets.set(flowSource, 8) // program 7 closed its socket; program 8 got the port and sends nothing yet
			close(gate)
			eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
			if in := r.carried("b7"); len(in) != 0 {
				t.Fatalf("program 7's datagram, routed while the port changed hands, left in flow %v (the flows begin at %v)", in, firstDestinations(r))
			}
			eventually(t, "program 7's flow is finished", func() bool { return r.all()[0].wasClosed() })
		})
	}
}

// When the table is read again for a waiting datagram while a check of the next program's datagram
// is under way, the waiting datagram is dropped and that check decides the rest: the next
// program's datagram starts the source afresh, and is not lost with the previous program's flows.
// The window is long here so that the check's read comes well after the one for the route.
func TestUDPFlowTheNextProgramsDatagramUnderACheckIsNotLostWithAWaitingOne(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	policy := testPolicy(sockets, time.Second)
	policy.window = 200 * time.Millisecond
	u, r := newTestFlows(policy)
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy", flowC: "direct"})
	routeGate := make(chan struct{})
	r.mu.Lock()
	r.routeGate = routeGate
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b7"))
	eventually(t, "b7 is being routed", func() bool { return r.questions() == 1 })
	sockets.set(flowSource, 8) // program 7 closed its socket, program 8 got the port
	tableGate := sockets.hold()
	close(routeGate)
	eventually(t, "the table is read again for b7's route", func() bool { return sockets.atGate() == 1 })
	u.HandlePacket(flowSource, flowC, []byte("c8")) // checked after that read
	close(tableGate)
	eventually(t, "c8 is sent", func() bool { return len(r.carried("c8")) == 1 })
	if in := r.carried("b7"); len(in) != 0 {
		t.Fatalf("program 7's datagram left in flow %v (the flows begin at %v)", in, firstDestinations(r))
	}
	eventually(t, "program 7's flow is finished", func() bool { return r.all()[0].wasClosed() })
}

// settledFlow: the dispatcher has reported flow i's route (or the flow ended).
func settledFlow(r *flowRecorder, i int) bool {
	flows := r.all()
	if i >= len(flows) {
		return false
	}
	select {
	case <-flows[i].conn.settled:
		return true
	default:
		return false
	}
}

// A new flow opened after a wait is preceded by a read of its own. The routes of two destinations are
// vouched for by one read; the first opens a flow, and the second waits for that flow's route. The
// port changes hands during the wait, and the second destination's route, vouched for before it, says
// nothing about who holds the port now: another read finds the next program's socket, and the
// datagram is dropped instead of opening a flow that would be routed for that program.
func TestUDPFlowANewFlowAfterAWaitIsOpenedOnlyAfterAnotherRead(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy", flowC: "third"})

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the first flow is routed", func() bool { return u.identifiedFlow(flowSource) && settledFlow(r, 0) })
	tableGate := sockets.hold()
	u.HandlePacket(flowSource, flowB, []byte("b7"))
	u.HandlePacket(flowSource, flowC, []byte("c7")) // held by the same check: both wait together
	reportGate := make(chan struct{})
	r.mu.Lock()
	r.reportGate = reportGate
	r.mu.Unlock()
	close(tableGate)
	eventually(t, "b7 opened a flow of its own, not routed yet", func() bool { return flowCount(r) == 2 })
	if first := r.all()[1].first; first != flowB {
		t.Fatalf("the second flow begins at %v, want %v", first, flowB)
	}
	sockets.set(flowSource, 8) // program 7 closed its socket, program 8 got the port
	close(reportGate)
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if in := r.carried("c7"); len(in) != 0 {
		t.Fatalf("a datagram opened a flow after the port changed hands, with no read after the wait: flow %v (the flows begin at %v)", in, firstDestinations(r))
	}
}

// A round of route questions asked after a read is vouched for by a read after it, not by that
// earlier one: the port may have changed hands while the round was asked.
func TestUDPFlowARouteAskedAfterAReadWaitsForTheNextRead(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "direct", flowC: "proxy"})

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the first flow is routed", func() bool { return u.identifiedFlow(flowSource) && settledFlow(r, 0) })
	first := make(chan struct{})
	r.mu.Lock()
	r.routeGate = first
	r.mu.Unlock()
	u.HandlePacket(flowSource, flowB, []byte("b7"))
	eventually(t, "b7 is being routed", func() bool { return r.questions() == 1 })
	u.HandlePacket(flowSource, flowC, []byte("c7"))
	eventually(t, "c7 waits behind it", func() bool {
		waiting, checking := u.waitingFor(flowSource)
		return waiting == 2 && !checking
	})
	second := make(chan struct{})
	r.mu.Lock()
	r.routeGate = second
	r.mu.Unlock()
	close(first) // b7: answered, vouched for by a read, into the first flow; then c7 is asked about
	eventually(t, "c7 is being routed", func() bool { return r.questions() == 2 })
	sockets.set(flowSource, 8) // program 7 closed its socket, program 8 got the port
	close(second)
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if got := r.payloadsOf(0); got != "a7,b7" {
		t.Fatalf("the first flow carried %q, want a7,b7", got)
	}
	if in := r.carried("c7"); len(in) != 0 {
		t.Fatalf("a datagram whose route was asked across a hand-over left in flow %v, on a read made before the question (the flows begin at %v)", in, firstDestinations(r))
	}
}

// A table that cannot be read when a waiting datagram's route is known says nothing about the
// socket: the datagram goes on as it would with no table (unknown is the same as anything).
func TestUDPFlowAnUnreadableTableLetsAWaitingDatagramGoOn(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.setRoutes(map[net.Destination]string{flowA: "direct", flowB: "proxy"})
	gate := make(chan struct{})
	r.mu.Lock()
	r.routeGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b7"))
	eventually(t, "b7 is being routed", func() bool { return r.questions() == 1 })
	sockets.setBroken(true)
	close(gate)
	eventually(t, "b7 in a flow of its own", func() bool { return r.payloadsOf(1) == "b7" })
	if r.all()[0].wasClosed() {
		t.Fatal("an unreadable table finished the source's flow")
	}
}

// The table is read again once for the destinations that wait together, not once for each: every
// route asked before the read is vouched for by it. A source that sends to many new addresses at
// once (a DHT node) would otherwise wait a read of the table for each of them, one after another.
func TestUDPFlowDestinationsThatWaitTogetherShareOneReadForTheirRoutes(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	gate := make(chan struct{})
	r.mu.Lock()
	r.reportGate = gate // the first flow is not routed yet: every new destination waits for it
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	want := []string{"a"}
	for i := range 20 {
		to := net.UDPDestination(net.ParseAddress("192.0.2.100"), net.Port(40000+i))
		payload := "n" + strconv.Itoa(i)
		u.HandlePacket(flowSource, to, []byte(payload))
		want = append(want, payload)
		time.Sleep(time.Millisecond)
	}
	eventually(t, "all twenty wait for a route, and no check is under way", func() bool {
		waiting, checking := u.waitingFor(flowSource)
		return waiting == 20 && !checking
	})
	before := sockets.reads()
	close(gate)
	eventually(t, "all twenty in the flow", func() bool { return r.payloadsOf(0) == strings.Join(want, ",") })
	if reads := sockets.reads() - before; reads != 1 {
		t.Fatalf("%d reads of the table to route twenty destinations that waited together, want 1", reads)
	}
	if q := r.questions(); q != 20 {
		t.Fatalf("%d route questions, want 20: one for each destination", q)
	}
}

// A round of route questions is bounded in time: the oldest waiting packet does not wait for the
// answers of every destination behind it before the read that lets it go.
func TestUDPFlowTheOldestWaitingDestinationIsNotHeldBackByALongRound(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	gate := make(chan struct{})
	r.mu.Lock()
	r.reportGate = gate // the first flow is not routed yet: every new destination waits for it
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	for i := range 100 {
		u.HandlePacket(flowSource, net.UDPDestination(net.ParseAddress("192.0.2.100"), net.Port(40000+i)), []byte("n"+strconv.Itoa(i)))
		time.Sleep(200 * time.Microsecond)
	}
	eventually(t, "all hundred wait for a route", func() bool {
		waiting, checking := u.waitingFor(flowSource)
		return waiting == 100 && !checking
	})
	r.mu.Lock()
	r.routeDelay = 2 * time.Millisecond // a hundred answers take 200 ms
	r.mu.Unlock()
	start := time.Now()
	close(gate)
	eventually(t, "the oldest in the flow", func() bool { return len(r.carried("n0")) == 1 })
	took := time.Since(start)
	t.Logf("the oldest of a hundred waiting destinations went after %v", took.Round(time.Millisecond))
	if took > 100*time.Millisecond {
		t.Fatalf("the oldest waiting destination went after %v: it waited for the answers of those behind it", took.Round(time.Millisecond))
	}
	eventually(t, "all hundred in the flow", func() bool { return len(r.carried("n99")) == 1 })
}

// New destinations that keep coming while a round is asked do not join it without end: the answers
// of a round are used before the next round asks about the newcomers.
func TestUDPFlowNewDestinationsThatKeepComingDoNotHoldBackTheOldest(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	r.mu.Lock()
	r.routeDelay = 2 * time.Millisecond
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	start := time.Now()
	var first time.Duration
	for i := 0; time.Since(start) < 400*time.Millisecond; i++ {
		u.HandlePacket(flowSource, net.UDPDestination(net.ParseAddress("192.0.2.100"), net.Port(40000+i)), []byte("n"+strconv.Itoa(i)))
		if first == 0 && len(r.carried("n0")) == 1 {
			first = time.Since(start)
		}
		time.Sleep(time.Millisecond)
	}
	if first == 0 {
		t.Fatal("the first new destination had not gone after 400 ms of a steady stream of new ones")
	}
	t.Logf("the first new destination went after %v of a steady stream of new ones", first.Round(time.Millisecond))
	if first > 200*time.Millisecond {
		t.Fatalf("the first new destination went after %v, more than 200 ms, while new ones kept coming", first.Round(time.Millisecond))
	}
}

// firstDestinations: where each recorded flow began, for a failure's message.
func firstDestinations(r *flowRecorder) []string {
	var firsts []string
	for _, flow := range r.all() {
		firsts = append(firsts, flow.first.NetAddr())
	}
	return firsts
}

// ---- Each destination routed by what its own datagrams carry --------------------------------------

// A round of route questions asks about each waiting destination with the datagrams that wait for
// it, in the order sent, and each is routed by what they carry: not with nothing, not with the
// packet at the head of the queue, and not with its own last one alone. c's two datagrams name a
// route together (a ClientHello split over two Initials) that differs from its address's.
func TestUDPFlowEachWaitingDestinationIsAskedWithItsOwnDatagrams(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	u.sniffWait = time.Minute
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy", flowC: "proxy", flowD: "proxy"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowC: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow's route is reported", func() bool { return u.routedFlow(flowSource) })
	gate := make(chan struct{}) // b's question takes its time, and the others queue up behind it
	r.mu.Lock()
	r.routeGate = gate
	r.mu.Unlock()
	u.HandlePacket(flowSource, flowB, []byte("b1"))
	eventually(t, "b is being asked about", func() bool { return r.questions() == 1 })
	u.HandlePacket(flowSource, flowC, []byte("c1"))
	u.HandlePacket(flowSource, flowD, []byte("d1"))
	u.HandlePacket(flowSource, flowC, []byte("c2"))
	eventually(t, "b1, c1, d1 and c2 wait for their routes", func() bool { n, checking := u.waitingFor(flowSource); return n == 4 && !checking })
	r.mu.Lock()
	r.routeGate = nil
	r.mu.Unlock()
	close(gate)

	eventually(t, "b1 and d1 in the flow of their address's route", func() bool { return r.payloadsOf(0) == "a,b1,d1" })
	eventually(t, "c1 and c2 in the flow of the route they name", func() bool { return r.payloadsOf(1) == "c1,c2" })
	for _, c := range []struct {
		dest net.Destination
		want string
	}{{flowB, "b1"}, {flowC, "c1,c2"}, {flowD, "d1"}} {
		if got := r.questionsAbout(c.dest); len(got) != 1 || got[0] != c.want {
			t.Errorf("RouteOf was given %q for %v, want %q", got, c.dest, c.want)
		}
	}
}

// A datagram that cannot tell its route alone — the first half of a ClientHello split over two
// Initials — waits for the next datagram to its destination, and RouteOf is asked again with both:
// they go, by the name they carry together, into the source's flow that went there. No flow of
// their own: through a proxy, each would be an association of its own.
func TestUDPFlowADatagramThatCannotTellItsRouteWaitsForTheNext(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	u.sniffWait = time.Minute
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy", flowC: "direct"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowB: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "c in a flow of its own", func() bool { return r.payloadsOf(1) == "c" })
	u.HandlePacket(flowSource, flowB, []byte("b1"))
	eventually(t, "b1 is asked about", func() bool { return len(r.questionsAbout(flowB)) == 1 })
	time.Sleep(30 * time.Millisecond)
	if n, a, c := flowCount(r), r.payloadsOf(0), r.payloadsOf(1); n != 2 || a != "a" || c != "c" {
		t.Fatalf("b1 alone: %d flows carrying %q and %q; want 2 carrying a and c: b1 waits, in no flow", n, a, c)
	}
	u.HandlePacket(flowSource, flowB, []byte("b2"))
	eventually(t, "b1 and b2 in the flow their name went to", func() bool { return r.payloadsOf(1) == "c,b1,b2" })
	if got := r.questionsAbout(flowB); len(got) != 2 || got[0] != "b1" || got[1] != "b1,b2" {
		t.Fatalf("RouteOf was given %q for b, want b1 and then b1,b2", got)
	}
	time.Sleep(20 * time.Millisecond)
	if n := flowCount(r); n != 2 {
		t.Fatalf("%d flows, want 2: one per route", n)
	}
}

// While a destination's datagrams wait for the rest of what names them, the source's other new
// destinations are routed: they do not wait behind them, nor behind a flow opened for them.
func TestUDPFlowADatagramThatCannotTellItsRouteHoldsUpNoOtherDestination(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	u.sniffWait, u.routeWait = time.Minute, time.Minute
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy", flowC: "proxy"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowB: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow's route is reported", func() bool { return u.routedFlow(flowSource) })
	gate := make(chan struct{}) // from now on a new flow's routing takes its time
	defer close(gate)
	r.mu.Lock()
	r.reportGate = gate
	r.mu.Unlock()
	u.HandlePacket(flowSource, flowB, []byte("b1"))
	eventually(t, "b1 is asked about", func() bool { return len(r.questionsAbout(flowB)) == 1 })
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "c in the flow of its route while b1 waits", func() bool { return r.payloadsOf(0) == "a,c" })
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1: b1 opened none", n)
	}
}

// A datagram that cannot tell its route, with nothing after it, waits no longer than the dispatcher's
// sniffing would (sniffWait), and is then routed as a flow whose sniffing found nothing is: RouteOf
// is asked with no datagrams, and the answer, the address's route, takes it into the source's flow
// that went there.
func TestUDPFlowADatagramThatNeverTellsItsRouteIsRoutedWithNothingSniffed(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	u.sniffWait = 50 * time.Millisecond
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowB: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow knows its socket", func() bool { return u.identifiedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b1"))
	eventually(t, "b1 in the flow of its address's route", func() bool { return r.payloadsOf(0) == "a,b1" })
	if got := r.questionsAbout(flowB); len(got) != 2 || got[0] != "b1" || got[1] != "" {
		t.Fatalf("RouteOf was given %q for b, want b1 and then nothing", got)
	}
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1", n)
	}
}

// The rest of what names a destination's route, sent within sniffWait, is read with the rest even
// when the question comes later — the source's new flow had to be routed first: the dispatcher's
// sniffing would have read it in its time too.
func TestUDPFlowTheRestSentInTimeIsReadThoughTheQuestionComesLater(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Second))
	u.sniffWait = 50 * time.Millisecond
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowB: "proxy", flowC: "direct"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowB: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a"))
	eventually(t, "the flow's route is reported", func() bool { return u.routedFlow(flowSource) })
	u.HandlePacket(flowSource, flowB, []byte("b1"))
	eventually(t, "b1 is asked about", func() bool { return len(r.questionsAbout(flowB)) == 1 })
	gate := make(chan struct{}) // the next flow's routing takes its time
	r.mu.Lock()
	r.reportGate = gate
	r.mu.Unlock()
	u.HandlePacket(flowSource, flowC, []byte("c"))
	eventually(t, "c in a flow of its own, not routed yet", func() bool { return flowCount(r) == 2 })
	u.HandlePacket(flowSource, flowB, []byte("b2"))
	time.Sleep(100 * time.Millisecond) // past b's sniffWait, while c's flow is being routed
	close(gate)
	eventually(t, "b1 and b2 in the flow their name went to", func() bool { return r.payloadsOf(1) == "c,b1,b2" })
	if got := r.questionsAbout(flowB); len(got) != 2 || got[1] != "b1,b2" {
		t.Fatalf("RouteOf was given %q for b, want b1 and then b1,b2", got)
	}
}

// The answer RouteOf gives once the rest of a destination's name has come is vouched for by a read
// made after that answer, not by the read that vouched for the round in which the destination could
// not tell its route yet. The port may have changed hands in between: a datagram to the same
// destination within the silence is not checked on its own, and the answer, asked with it, is then
// the next program's. Here b7 could not tell its route in a round that a read vouched for (c7 went
// on the strength of it), the port changes hands, and b's next datagram tells a route that a live
// flow of the source takes: another read finds the next program's socket, and b7 is dropped instead
// of joining that flow.
func TestUDPFlowAnAnswerToTheRestOfANameIsVouchedForByALaterRead(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Minute))
	u.sniffWait = time.Minute
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowC: "proxy"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowB: "proxy"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the first flow is routed", func() bool { return u.identifiedFlow(flowSource) && settledFlow(r, 0) })
	tableGate := sockets.hold()
	u.HandlePacket(flowSource, flowC, []byte("c7"))
	u.HandlePacket(flowSource, flowB, []byte("b7")) // held by the same check: both are asked about in one round
	close(tableGate)
	eventually(t, "c7 in the first flow, after a read", func() bool { return r.payloadsOf(0) == "a7,c7" })
	eventually(t, "b7 waits for the rest of its name", func() bool {
		waiting, checking := u.waitingFor(flowSource)
		return waiting == 1 && !checking
	})
	sockets.set(flowSource, 8)                      // program 7 closed its socket, program 8 got the port
	u.HandlePacket(flowSource, flowB, []byte("b8")) // the same destination within the silence: not checked
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if got := r.questionsAbout(flowB); len(got) != 2 || got[1] != "b7,b8" {
		t.Fatalf("RouteOf was given %q for b, want b7 and then b7,b8", got)
	}
	if in := r.carried("b7"); len(in) != 0 {
		t.Fatalf("program 7's datagram left in flow %v on an answer asked across a hand-over, vouched for by a read made before the question (the flows begin at %v)", in, firstDestinations(r))
	}
	eventually(t, "program 7's flow is finished", func() bool { return r.all()[0].wasClosed() })
}

// A datagram that waited for the rest of its name opens a flow only after a read of the table made
// after the wait. Its round was vouched for before the wait; meanwhile the source's only flow ended
// and the port changed hands. With no flow left, no route can be asked, and the datagram would open
// a flow of its own, routed for whoever holds the port now: another read finds the next program's
// socket, and the datagram is dropped instead.
func TestUDPFlowADatagramThatWaitedForItsNameOpensAFlowOnlyAfterAnotherRead(t *testing.T) {
	sockets := newFakeSockets()
	sockets.set(flowSource, 7)
	u, r := newTestFlows(testPolicy(sockets, time.Minute))
	u.sniffWait = time.Minute
	r.setRoutes(map[net.Destination]string{flowA: "proxy", flowC: "proxy"})
	r.mu.Lock()
	r.told = map[net.Destination]string{flowB: "direct"}
	r.mu.Unlock()

	u.HandlePacket(flowSource, flowA, []byte("a7"))
	eventually(t, "the first flow is routed", func() bool { return u.identifiedFlow(flowSource) && settledFlow(r, 0) })
	tableGate := sockets.hold()
	u.HandlePacket(flowSource, flowC, []byte("c7"))
	u.HandlePacket(flowSource, flowB, []byte("b7")) // held by the same check: both are asked about in one round
	close(tableGate)
	eventually(t, "c7 in the first flow, after a read", func() bool { return r.payloadsOf(0) == "a7,c7" })
	eventually(t, "b7 waits for the rest of its name", func() bool {
		waiting, checking := u.waitingFor(flowSource)
		return waiting == 1 && !checking
	})
	first := r.all()[0]
	first.conn.Close() // the source's only flow ends while b7 waits
	eventually(t, "the first flow's dispatch is over", func() bool { return first.wasClosed() })
	sockets.set(flowSource, 8)                      // program 7 closed its socket, program 8 got the port
	u.HandlePacket(flowSource, flowB, []byte("b8")) // the same destination within the silence: not checked
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if in := r.carried("b7"); len(in) != 0 {
		t.Fatalf("program 7's datagram opened a flow after the port changed hands, with no read after the wait: flow %v (the flows begin at %v)", in, firstDestinations(r))
	}
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1: none opened after the hand-over", n)
	}
}

// A source holds at most udpFlowLimit flows. Destinations of one route share a flow, so a source
// needs one per route it sends to; it gets more from flows that do not report their route in time
// (routeWait), since a destination is matched only against flows that did, and here each flow never
// does: each destination opens a flow of its own. Past the limit the flow the program used least
// recently ends: a destination it keeps sending to keeps its flow, and an ended flow's destination
// is routed again when the program next sends to it. Every datagram travels in a flow.
func TestUDPFlowASourceHoldsAtMostUDPFlowLimitFlows(t *testing.T) {
	u, r := newTestFlows(udpFlowPolicy{})
	u.routeWait = time.Millisecond
	dests := make([]net.Destination, 100)
	for i := range dests {
		dests[i] = net.UDPDestination(net.ParseAddress("198.51.100."+strconv.Itoa(i+1)), 443)
	}
	r.mu.Lock()
	r.silent = true
	r.mu.Unlock()

	kept := []string{"p0"}
	for i, dst := range dests {
		payload := "p" + strconv.Itoa(i)
		u.HandlePacket(flowSource, dst, []byte(payload))
		eventually(t, payload+" in a flow of its own", func() bool { return r.payloadsOf(i) == payload })
		if i > 0 {
			keep := "k" + strconv.Itoa(i)
			u.HandlePacket(flowSource, dests[0], []byte(keep)) // the first destination stays in use
			kept = append(kept, keep)
		}
		if n := u.FlowCount(); n > udpFlowLimit {
			t.Fatalf("after %d destinations the source holds %d flows, want at most %d", i+1, n, udpFlowLimit)
		}
	}
	eventually(t, "the first destination kept its flow", func() bool { return r.payloadsOf(0) == strings.Join(kept, ",") })

	// Flows 1..68 ended, oldest first; 69..99 and the first one live.
	ended := len(dests) - udpFlowLimit
	for i, flow := range r.all() {
		if want := i >= 1 && i <= ended; flow.conn.retired.Load() != want {
			t.Fatalf("flow %d (%s): retired %v, want %v", i, flow.payloads(), !want, want)
		}
	}
	eventually(t, "the ended flows' dispatch is over", func() bool {
		for _, flow := range r.all()[1 : ended+1] {
			if !flow.wasClosed() {
				return false
			}
		}
		return true
	})

	u.HandlePacket(flowSource, dests[1], []byte("again"))
	eventually(t, "an ended flow's destination is routed again", func() bool { return r.payloadsOf(len(dests)) == "again" })
	if n := u.FlowCount(); n != udpFlowLimit {
		t.Fatalf("%d flows, want %d", n, udpFlowLimit)
	}
}

// At the limit a datagram still travels only in a flow of its own route. Here every flow reports,
// each on a route of its own, so the source holds udpFlowLimit flows that a destination can be
// matched against, and then sends to a destination of yet another route: the flow it used least
// recently ends and the datagram opens a flow of its own. Put into a live flow of another route
// instead, a datagram that the rules block would leave by that route.
func TestUDPFlowAtTheLimitADatagramStillTravelsOnlyInAFlowOfItsRoute(t *testing.T) {
	u, r := newTestFlows(udpFlowPolicy{})
	dests := make([]net.Destination, udpFlowLimit+1)
	routes := make(map[net.Destination]string, len(dests))
	for i := range dests {
		dests[i] = net.UDPDestination(net.ParseAddress("198.51.100."+strconv.Itoa(i+1)), 443)
		routes[dests[i]] = "r" + strconv.Itoa(i)
	}
	last := dests[udpFlowLimit]
	routes[last] = "block"
	r.setRoutes(routes)
	payload := func(i int) string { return "d" + strconv.Itoa(i) + ".1" }

	// The recorder reports a flow's route before it reads the flow: a flow that got its datagram is
	// routed, and the next destination is matched against it.
	for i, dst := range dests[:udpFlowLimit] {
		u.HandlePacket(flowSource, dst, []byte(payload(i)))
		eventually(t, payload(i)+" in a flow of its own", func() bool { return r.payloadsOf(i) == payload(i) })
	}
	u.HandlePacket(flowSource, last, []byte(payload(udpFlowLimit)))
	eventually(t, "the datagram of the last route is sent", func() bool {
		sent := 0
		for _, flow := range r.all() {
			if got := flow.payloads(); got != "" {
				sent += strings.Count(got, ",") + 1
			}
		}
		return sent == len(dests)
	})

	flows := r.all()
	for i, flow := range flows {
		for _, got := range strings.Split(flow.payloads(), ",") {
			if want := payload(i); got != want {
				t.Fatalf("%q left in flow %d, of route %s: every flow here carries its first datagram alone", got, i, routes[flow.first])
			}
		}
	}
	if n := len(flows); n != udpFlowLimit+1 || flows[udpFlowLimit].first != last {
		t.Fatalf("%d flows, the last beginning at %v; want %d, the last at %v", n, flows[n-1].first, udpFlowLimit+1, last)
	}
	if !flows[0].conn.retired.Load() {
		t.Fatal("the flow used least recently lives on past the limit")
	}
	if n := u.FlowCount(); n != udpFlowLimit {
		t.Fatalf("%d flows, want %d", n, udpFlowLimit)
	}
}

// ---- An address of fake DNS has a flow of its own ------------------------------------------------

// A datagram to an address of fake DNS never joins the flow of another destination. The outbound puts
// the name that sniffing found in place of the pool address of a flow's FIRST destination alone, so a
// second pool address in the same flow would reach the proxy as the pool address itself, and the proxy
// routes a whole flow by its first destination. These tests stand a pool of 198.51.100.0/24 in for the
// engine's, through the policy's ownFlow; the real addresses are in 203.0.113.0/24, and every
// destination is on one route ("out"). udp_flow_pool_test.go runs the real engine with the pool the
// product uses.

var (
	poolA = net.UDPDestination(net.ParseAddress("198.51.100.1"), 3478)
	poolB = net.UDPDestination(net.ParseAddress("198.51.100.2"), 3478)
	realA = net.UDPDestination(net.ParseAddress("203.0.113.1"), 3478)
	realB = net.UDPDestination(net.ParseAddress("203.0.113.2"), 3478)
)

var testPool = netip.MustParsePrefix("198.51.100.0/24")

// inTestPool is the ownFlow of poolPolicy: the destination's address lies in testPool.
func inTestPool(dst net.Destination) bool {
	if !dst.Address.Family().IsIP() {
		return false
	}
	addr, ok := netip.AddrFromSlice(dst.Address.IP())
	return ok && testPool.Contains(addr.Unmap())
}

// poolPolicy is no socket table and no idle expiry, with the addresses of testPool on flows of their own.
func poolPolicy() udpFlowPolicy {
	return udpFlowPolicy{ownFlow: inTestPool}
}

// Two addresses of fake DNS on one route are two flows, each with the datagrams of its own address
// alone, and the replies in each come from that address.
func TestUDPFlowTwoFakeDNSAddressesOfOneRouteGetAFlowEach(t *testing.T) {
	u, r := newTestFlows(poolPolicy())

	u.HandlePacket(flowSource, poolA, []byte("a1"))
	eventually(t, "the first flow reports its route", func() bool { return u.routedFlow(flowSource) })
	u.HandlePacket(flowSource, poolB, []byte("b1"))
	u.HandlePacket(flowSource, poolA, []byte("a2"))
	u.HandlePacket(flowSource, poolB, []byte("b2"))

	eventually(t, "a1, a2 in the flow of the first address and b1, b2 in a flow of the second", func() bool {
		return r.payloadsOf(0) == "a1,a2" && r.payloadsOf(1) == "b1,b2"
	})
	time.Sleep(20 * time.Millisecond)
	flows := r.all()
	if len(flows) != 2 || flows[0].first != poolA || flows[1].first != poolB {
		t.Fatalf("%d flows; want two, opened for %v and %v", len(flows), poolA, poolB)
	}
	for _, flow := range flows {
		reply := buf.New()
		reply.Write([]byte("reply"))
		if err := flow.conn.WriteMultiBuffer(buf.MultiBuffer{reply}); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.deliveredFrom(); len(got) != 2 || got[0] != poolA || got[1] != poolB {
		t.Fatalf("the replies came from %v, want %v and %v", got, poolA, poolB)
	}
}

// A pool address does not join the flow of a real destination of its route.
func TestUDPFlowAFakeDNSAddressDoesNotJoinTheFlowOfARealAddress(t *testing.T) {
	u, r := newTestFlows(poolPolicy())

	u.HandlePacket(flowSource, realA, []byte("r1"))
	eventually(t, "the flow of the real address reports its route", func() bool { return u.routedFlow(flowSource) })
	u.HandlePacket(flowSource, poolA, []byte("p1"))
	u.HandlePacket(flowSource, realA, []byte("r2"))
	u.HandlePacket(flowSource, poolA, []byte("p2"))

	eventually(t, "r1, r2 in the flow of the real address and p1, p2 in a flow of the pool address", func() bool {
		return r.payloadsOf(0) == "r1,r2" && r.payloadsOf(1) == "p1,p2"
	})
	time.Sleep(20 * time.Millisecond)
	if flows := r.all(); len(flows) != 2 || flows[1].first != poolA {
		t.Fatalf("%d flows; want two, the second opened for %v", len(flows), poolA)
	}
}

// A real address is matched by its route whatever opened the flow: it joins the flow of its route
// even when a pool address opened that one. A second pool address does not.
func TestUDPFlowARealAddressStillJoinsAFakeDNSFlowButASecondFakeDNSAddressDoesNot(t *testing.T) {
	u, r := newTestFlows(poolPolicy())

	u.HandlePacket(flowSource, poolA, []byte("a1"))
	eventually(t, "the first flow reports its route", func() bool { return u.routedFlow(flowSource) })
	u.HandlePacket(flowSource, realA, []byte("r1"))
	eventually(t, "the real address in the flow of the pool address", func() bool { return r.payloadsOf(0) == "a1,r1" })
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1: the real address of the route joins its flow", n)
	}

	u.HandlePacket(flowSource, poolB, []byte("b1"))
	eventually(t, "the second pool address in a flow of its own", func() bool { return r.payloadsOf(1) == "b1" })
	if got := r.payloadsOf(0); got != "a1,r1" {
		t.Fatalf("the flow of the first pool address carried %q: the second pool address's datagram is not its", got)
	}
}

// Without the rule a pool address is a destination like any other: matched by its route, it joins
// the flow of that route.
func TestUDPFlowWithoutAnOwnFlowRuleTwoPoolAddressesShareAFlow(t *testing.T) {
	u, r := newTestFlows(udpFlowPolicy{})

	u.HandlePacket(flowSource, poolA, []byte("a1"))
	eventually(t, "the first flow reports its route", func() bool { return u.routedFlow(flowSource) })
	u.HandlePacket(flowSource, poolB, []byte("b1"))
	eventually(t, "both in one flow", func() bool { return r.payloadsOf(0) == "a1,b1" })
	time.Sleep(20 * time.Millisecond)
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows, want 1", n)
	}
}

// A pool address has no route to wait for: no flow of the source can be matched to it. It opens its
// flow at once, though the source's first flow has not reported its route, and the datagrams after
// it travel in that flow, in order. A real address that comes after waits for the report, as every
// destination without a flow of its own does.
func TestUDPFlowAFakeDNSAddressOpensItsFlowBeforeTheSourcesFlowsAreRouted(t *testing.T) {
	u, r := newTestFlows(poolPolicy())
	u.routeWait = time.Minute // the real address below waits for the report, not for the clock
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	r.mu.Lock()
	r.reportGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, realA, []byte("r1"))
	eventually(t, "the flow of the real address is open", func() bool { return flowCount(r) == 1 })
	u.HandlePacket(flowSource, poolA, []byte("p1"))
	eventually(t, "the pool address in a flow of its own though no flow has reported", func() bool { return flowCount(r) == 2 })
	if u.routedFlow(flowSource) {
		t.Fatal("a flow reported its route: the reports are held")
	}
	u.HandlePacket(flowSource, poolA, []byte("p2"))
	u.HandlePacket(flowSource, realB, []byte("r2"))
	time.Sleep(50 * time.Millisecond)
	if n := flowCount(r); n != 2 {
		t.Fatalf("%d flows before the report, want 2: the real address opened a flow without waiting", n)
	}
	if queued := len(r.all()[0].conn.egress); queued != 1 {
		t.Fatalf("%d datagrams in the flow of the real address before the report, want 1 (r1 alone): r2 did not wait", queued)
	}

	release()
	eventually(t, "r2 in the flow of the real address and p1, p2 in the flow of the pool address, in order", func() bool {
		return r.payloadsOf(0) == "r1,r2" && r.payloadsOf(1) == "p1,p2"
	})
	if first := r.all()[1].first; first != poolA {
		t.Fatalf("the second flow was opened for %v, want %v", first, poolA)
	}
}

// The queue of datagrams that wait for a route is the source's, not a destination's: a pool address
// behind a real one that waits for the report waits behind it, as every destination does.
func TestUDPFlowAFakeDNSAddressWaitsBehindARealAddressThatIsWaitingForARoute(t *testing.T) {
	u, r := newTestFlows(poolPolicy())
	u.routeWait = time.Minute
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	r.mu.Lock()
	r.reportGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, realA, []byte("r1"))
	eventually(t, "the flow of the real address is open", func() bool { return flowCount(r) == 1 })
	u.HandlePacket(flowSource, realB, []byte("r2")) // waits for the report
	u.HandlePacket(flowSource, poolA, []byte("p1")) // behind it
	time.Sleep(50 * time.Millisecond)
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows before the report, want 1: the pool address passed the real address ahead of it", n)
	}

	release()
	eventually(t, "r2 in the flow of the real address and p1 in a flow of the pool address", func() bool {
		return r.payloadsOf(0) == "r1,r2" && r.payloadsOf(1) == "p1"
	})
}

// A flow of a pool address counts toward the source's udpFlowLimit like any other: past it the flow
// the program used least recently ends, its replies are refused, and the next datagram to its
// address opens a new flow of its own. Every flow carries the datagrams of its first destination
// alone. All the addresses are on one route, so that only the pool addresses can fill the limit: on
// different routes the destinations would fill it by themselves.
func TestUDPFlowFakeDNSFlowsCountTowardTheFlowLimit(t *testing.T) {
	u, r := newTestFlows(poolPolicy())
	pool := make([]net.Destination, udpFlowLimit+1)
	for i := range pool {
		pool[i] = net.UDPDestination(net.ParseAddress("198.51.100."+strconv.Itoa(i+1)), 3478)
	}
	payload := func(i, n int) string { return "d" + strconv.Itoa(i) + "." + strconv.Itoa(n) }

	for i, dst := range pool {
		u.HandlePacket(flowSource, dst, []byte(payload(i, 1)))
		eventually(t, payload(i, 1)+" in a flow of its own", func() bool { return r.payloadsOf(i) == payload(i, 1) })
		if n := u.FlowCount(); n > udpFlowLimit {
			t.Fatalf("after %d pool addresses the source holds %d flows, want at most %d", i+1, n, udpFlowLimit)
		}
	}
	flows := r.all()
	if len(flows) != len(pool) || !flows[0].conn.retired.Load() {
		t.Fatalf("%d flows, the first retired: %v; want %d, the one used least recently ended", len(flows), flows[0].conn.retired.Load(), len(pool))
	}
	if n := u.FlowCount(); n != udpFlowLimit {
		t.Fatalf("%d flows, want %d", n, udpFlowLimit)
	}

	for i := 1; i < len(pool); i++ {
		u.HandlePacket(flowSource, pool[i], []byte(payload(i, 2)))
	}
	eventually(t, "the second datagram of each live flow in it", func() bool {
		for i := 1; i < len(pool); i++ {
			if r.payloadsOf(i) != payload(i, 1)+","+payload(i, 2) {
				return false
			}
		}
		return true
	})
	if got := r.payloadsOf(0); got != payload(0, 1) {
		t.Fatalf("the ended flow carried %q, want its first datagram alone", got)
	}

	late := buf.New()
	late.Write([]byte("late"))
	late.UDP = &pool[0]
	if err := flows[0].conn.WriteMultiBuffer(buf.MultiBuffer{late}); err != errUDPFlowRetired {
		t.Fatalf("a reply into the ended flow: %v, want the refusal of a retired flow", err)
	}

	u.HandlePacket(flowSource, pool[0], []byte("again"))
	eventually(t, "the next datagram to the ended flow's address in a new flow of its own", func() bool {
		all := r.all()
		return len(all) == len(pool)+1 && all[len(pool)].first == pool[0] && all[len(pool)].payloads() == "again"
	})
	if n := u.FlowCount(); n != udpFlowLimit {
		t.Fatalf("%d flows, want %d", n, udpFlowLimit)
	}
}

// ---- A pool address opens its flow only after a read of the socket table -------------------------

// A datagram to a pool address opens a flow of its own without a route question, but not without the
// read that every new flow is preceded by: the flow is routed for whoever holds the port when it is
// routed, so the table is read first, and a port that changed hands meanwhile drops the datagram.
//
// poolDatagramAtItsRead stages that read, held. Program 7 sends to a real address, whose flow is
// routed, and then to a pool address (p7). p7's own check, made when it was sent, is the first read,
// held at one gate; once it passes, p7 waits for its flow and routeWaiting reads the table for it, held
// at a second gate: that read is the one the tests act on. Hold the first read alone and it is p7's own
// check that is held, which a new owner of the port turns into a new source that carries p7 on its
// own (rechecked), whatever routeWaiting does with the datagram.
//
// Without the read this stage ends at once, with p7 in a flow of its own: the second gate is never
// reached, and the flow count tells.
func poolDatagramAtItsRead(t *testing.T, window time.Duration) (u *udpConnectionHandler, r *flowRecorder, sockets *fakeSockets, release chan struct{}) {
	t.Helper()
	sockets = newFakeSockets()
	sockets.set(flowSource, 7)
	policy := testPolicy(sockets, time.Second)
	policy.ownFlow = inTestPool
	if window > 0 {
		policy.window = window
	}
	u, r = newTestFlows(policy)

	u.HandlePacket(flowSource, realA, []byte("r7"))
	eventually(t, "the first flow is routed", func() bool { return u.identifiedFlow(flowSource) && settledFlow(r, 0) })
	first := sockets.hold()
	u.HandlePacket(flowSource, poolA, []byte("p7"))
	eventually(t, "the pool datagram's own check is at the gate", func() bool { return sockets.atGate() == 1 })
	release = sockets.hold()
	close(first)
	eventually(t, "a second read at the gate, or a flow for the pool address", func() bool { return sockets.atGate() == 2 || flowCount(r) >= 2 })
	return u, r, sockets, release
}

// The port changes hands during the read that a pool datagram's flow waits for: the datagram was the
// previous program's, and it is dropped. Opened ahead of the read, its flow would be routed for the
// next program.
func TestUDPFlowAFakeDNSDatagramIsDroppedWhenThePortChangesHandsDuringItsRead(t *testing.T) {
	u, r, sockets, release := poolDatagramAtItsRead(t, 0)

	sockets.set(flowSource, 8) // program 7 closed its socket, program 8 got the port
	close(release)
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if in := r.carried("p7"); len(in) != 0 {
		t.Fatalf("the pool datagram left in a flow opened without a fresh read of the socket table: flow %v (the flows begin at %v)", in, firstDestinations(r))
	}
	if n := flowCount(r); n != 1 {
		t.Fatalf("%d flows (they begin at %v), want 1: a flow was opened for the pool datagram of the previous program", n, firstDestinations(r))
	}
	eventually(t, "program 7's flow is finished", func() bool { return r.all()[0].wasClosed() })
}

// The same stage with the port unchanged: the read passes, and only then does the pool address open
// its flow, with the datagram alone in it and no question to the router.
func TestUDPFlowAFakeDNSAddressOpensItsFlowOnlyOnceTheTableIsRead(t *testing.T) {
	_, r, _, release := poolDatagramAtItsRead(t, 0)

	time.Sleep(30 * time.Millisecond)
	if n := flowCount(r); n != 1 {
		t.Fatalf("a flow for the pool address while the read is held: %d flows (they begin at %v), want 1", n, firstDestinations(r))
	}
	close(release)
	eventually(t, "p7 alone in a flow of its own", func() bool { return r.payloadsOf(1) == "p7" })
	if first := r.all()[1].first; first != poolA {
		t.Fatalf("the second flow was opened for %v, want %v", first, poolA)
	}
	if r.all()[0].wasClosed() {
		t.Fatal("program 7's flow was finished: its port did not change hands")
	}
	if q := r.questionsAbout(poolA); len(q) != 0 {
		t.Fatalf("RouteOf was asked about the pool address: %q", q)
	}
}

// The next program's datagram, checked while the pool datagram's read is held, is not lost with it.
// The read finds the change and drops the pool datagram; the check of the next program's datagram
// finishes the source and starts it afresh, with that datagram alone (rechecked). The window is long
// here so that the check's read comes well after the one for the pool datagram.
func TestUDPFlowTheNextProgramsDatagramUnderACheckIsNotLostWithAWaitingFakeDNSOne(t *testing.T) {
	u, r, sockets, release := poolDatagramAtItsRead(t, 200*time.Millisecond)

	sockets.set(flowSource, 8)                      // program 7 closed its socket, program 8 got the port
	u.HandlePacket(flowSource, flowC, []byte("c8")) // checked after the read that is held
	close(release)
	eventually(t, "c8 is sent", func() bool { return len(r.carried("c8")) == 1 })
	time.Sleep(30 * time.Millisecond)
	if in := r.carried("c8"); len(in) != 1 {
		t.Fatalf("the next program's datagram was sent %d times (flows %v), want once", len(in), in)
	}
	if in := r.carried("p7"); len(in) != 0 {
		t.Fatalf("the pool datagram left in a flow opened without a fresh read of the socket table: flow %v (the flows begin at %v)", in, firstDestinations(r))
	}
	eventually(t, "program 7's flow is finished", func() bool { return r.all()[0].wasClosed() })
}

// A pool address opens its flow whether or not the source has flows left. The source's only flow ends
// during the read that the pool datagram's flow waits for, and the datagram still opens a flow of its
// own: with no flow left no route can be asked for anything, and a pool address needs none.
func TestUDPFlowAFakeDNSAddressOpensItsFlowWhenTheSourcesLastFlowEndsDuringTheRead(t *testing.T) {
	u, r, _, release := poolDatagramAtItsRead(t, 0)

	first := r.all()[0]
	first.conn.Close() // program 7's only flow ends while the read is held
	eventually(t, "the first flow's dispatch is over", func() bool { return first.wasClosed() })
	if n := u.FlowCount(); n != 0 {
		t.Fatalf("%d flows left, want none: the source's only flow ended", n)
	}
	close(release)
	eventually(t, "p7 alone in a flow of its own", func() bool { return r.payloadsOf(1) == "p7" })
	if got := r.all()[1].first; got != poolA {
		t.Fatalf("the second flow was opened for %v, want %v", got, poolA)
	}
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })
	if n := u.FlowCount(); n != 1 {
		t.Fatalf("%d flows, want 1: the pool address's", n)
	}
}

// No route is asked for a pool address: no answer would place it, and each question costs the round a
// routing pass (with per-app rows, a resolver round trip) that the real destinations behind it wait
// out. Both destinations here wait for the first flow's report, the real one first and the pool
// address behind it, so that when the report comes they fall into one round of questions: the round
// asks about the real address, with its datagram, and leaves the pool address out. (A pool datagram
// that came after the round would never be in one, and the test would show nothing.)
func TestUDPFlowNoRouteIsAskedForAFakeDNSAddress(t *testing.T) {
	u, r := newTestFlows(poolPolicy())
	u.routeWait = time.Minute
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	r.mu.Lock()
	r.reportGate = gate
	r.mu.Unlock()

	u.HandlePacket(flowSource, realA, []byte("r1"))
	eventually(t, "the flow of the real address is open", func() bool { return flowCount(r) == 1 })
	u.HandlePacket(flowSource, realB, []byte("r2"))
	u.HandlePacket(flowSource, poolA, []byte("p1"))
	eventually(t, "both wait", func() bool { waiting, _ := u.waitingFor(flowSource); return waiting == 2 })
	release()
	eventually(t, "nothing waits for a route", func() bool { return u.routingOver(flowSource) })

	if q := r.questionsAbout(poolA); len(q) != 0 {
		t.Fatalf("RouteOf was asked about the pool address: %q", q)
	}
	if q := r.questionsAbout(realB); len(q) != 1 || q[0] != "r2" {
		t.Fatalf("RouteOf was given %q for the real address, want r2", q)
	}
	eventually(t, "r2 in the flow of its route and p1 in a flow of the pool address", func() bool {
		return r.payloadsOf(0) == "r1,r2" && r.payloadsOf(1) == "p1"
	})
}

// ---- The table takes its rule from the handler ---------------------------------------------------

// stubFakeDNS is an engine of fake DNS whose pool the test sets: the engine's own appears only when
// it starts. It answers the interface the dispatcher asks the engine for (dns.FakeDNSEngine) and the
// one it casts that to (dns.FakeDNSEngineRev0).
type stubFakeDNS struct {
	mu   sync.Mutex
	pool netip.Prefix // the zero prefix holds no address
}

func (*stubFakeDNS) Type() interface{}                                    { return (*dns.FakeDNSEngine)(nil) }
func (*stubFakeDNS) Start() error                                         { return nil }
func (*stubFakeDNS) Close() error                                         { return nil }
func (*stubFakeDNS) GetFakeIPForDomain(string) []net.Address              { return nil }
func (*stubFakeDNS) GetDomainFromFakeDNS(net.Address) string              { return "" }
func (*stubFakeDNS) GetFakeIPForDomain3(string, bool, bool) []net.Address { return nil }

func (s *stubFakeDNS) setPool(pool netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pool = pool
}

func (s *stubFakeDNS) IsIPInIPPool(ip net.Address) bool {
	if !ip.Family().IsIP() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip.IP())
	s.mu.Lock()
	defer s.mu.Unlock()
	return ok && s.pool.Contains(addr.Unmap())
}

func discardReplies([]byte, net.Destination, net.Destination) error { return nil }

// A table whose handler has no fake DNS has no rule: every destination is matched by its route alone.
// So has one whose handler is not the tun's own (the bridge's tests hand it a recorder), and one whose
// engine cannot tell its pool.
func TestUDPFlowATableWithoutFakeDNSHasNoOwnFlowRule(t *testing.T) {
	var noHandler *Handler
	for name, conns := range map[string]ConnectionHandler{
		"a handler that is not the tun's":     newRecordingHandler(),
		"a handler with no fake DNS":          &Handler{},
		"no handler":                          noHandler,
		"an engine that cannot tell its pool": &Handler{fakeDNS: struct{ dns.FakeDNSEngine }{&stubFakeDNS{pool: testPool}}},
	} {
		if u := newUdpConnectionHandler(conns, discardReplies); u.policy.ownFlow != nil {
			t.Errorf("%s: the table has an own-flow rule", name)
		}
	}
}

// The rule asks the engine on every call and keeps nothing of its answer, so it does not depend on the
// order in which features start: a pool that appears after the table is built (setPool) is the rule's
// from then on, for every destination.
func TestUDPFlowATablesOwnFlowRuleIsTheFakeDNSPoolAsItIsWhenAsked(t *testing.T) {
	engine := &stubFakeDNS{}
	u := newUdpConnectionHandler(&Handler{fakeDNS: engine}, discardReplies)
	own := u.policy.ownFlow
	if own == nil {
		t.Fatal("no own-flow rule for a handler with fake DNS")
	}
	if own(poolA) {
		t.Fatal("a pool address is one before the engine has a pool")
	}

	engine.setPool(testPool)
	for _, c := range []struct {
		name string
		dst  net.Destination
		want bool
	}{
		{"an address of the pool", poolA, true},
		{"the same address on another port", net.UDPDestination(poolA.Address, 53), true},
		{"a real address", realA, false},
		{"a name", net.UDPDestination(net.DomainAddress("one.example"), 3478), false},
		{"an IPv6 address", net.UDPDestination(net.ParseAddress("2001:db8::1"), 3478), false},
	} {
		if got := own(c.dst); got != c.want {
			t.Errorf("%s: the rule says %v, want %v", c.name, got, c.want)
		}
	}
}

// The platform's policy is the table's, whole: the rule is added to it, not put in its place. Only
// darwin's policy has anything in it (a socket table, a window, a silence, a re-check, idle times);
// elsewhere this compares empty policies, and export_udpflow_darwin_test.go's constructors are
// checked in udp_flow_pool_darwin_test.go.
func TestUDPFlowATablesOwnFlowRuleComesWithThePlatformPolicy(t *testing.T) {
	platform := defaultUDPFlowPolicy()
	for name, conns := range map[string]ConnectionHandler{
		"no fake DNS": &Handler{},
		"fake DNS":    &Handler{fakeDNS: &stubFakeDNS{pool: testPool}},
	} {
		got := newUdpConnectionHandler(conns, discardReplies).policy
		if (got.lookup != nil) != (platform.lookup != nil) || got.window != platform.window ||
			got.silence != platform.silence || got.recheck != platform.recheck || (got.idle != nil) != (platform.idle != nil) {
			t.Errorf("%s: the policy has a socket table %v, window %v, silence %v, re-check %v, idle %v; the platform's has %v, %v, %v, %v, %v",
				name, got.lookup != nil, got.window, got.silence, got.recheck, got.idle != nil,
				platform.lookup != nil, platform.window, platform.silence, platform.recheck, platform.idle != nil)
		}
	}
}
