package tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apppolicy "github.com/xtls/xray-core/app/policy"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type testCounter struct {
	value int64
}

func (c *testCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value) - value
}

type testConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func newTestConn(input []byte) *testConn {
	return &testConn{reader: bytes.NewReader(input)}
}

func (c *testConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

func (c *testConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}

func (c *testConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testDispatcher struct {
	writePayload []byte
	readBytes    int32
}

func (d *testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *testDispatcher) Start() error {
	return nil
}

func (d *testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

// testPacketConn mimics the fullcone udpConn: ReadMultiBuffer stamps the per-packet
// destination (b.UDP), WriteMultiBuffer reads it back from the reply buffer.
// Losing either one is a fullcone regression.
type testPacketConn struct {
	testConn
	readDest   *xnet.Destination
	gotReplyTo []*xnet.Destination
	readOnce   bool
}

func (c *testPacketConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if c.readOnce {
		return nil, io.EOF
	}
	c.readOnce = true
	b := buf.New()
	if _, err := b.Write([]byte("uplink")); err != nil {
		b.Release()
		return nil, err
	}
	b.UDP = c.readDest
	return buf.MultiBuffer{b}, nil
}

func (c *testPacketConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		c.gotReplyTo = append(c.gotReplyTo, b.UDP)
		c.writer.Write(b.Bytes())
		b.Release()
	}
	return nil
}

// fullconeProbeDispatcher records b.UDP of the incoming packet and replies with a
// packet carrying its own b.UDP, like a real socks outbound in fullcone mode.
type fullconeProbeDispatcher struct {
	gotDest *xnet.Destination
	replyTo xnet.Destination
}

func (d *fullconeProbeDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *fullconeProbeDispatcher) Start() error {
	return nil
}

func (d *fullconeProbeDispatcher) Close() error {
	return nil
}

func (d *fullconeProbeDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *fullconeProbeDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	if len(mb) > 0 {
		d.gotDest = mb[0].UDP
	}
	buf.ReleaseMulti(mb)

	reply := buf.New()
	if _, err := reply.Write([]byte("downlink")); err != nil {
		reply.Release()
		return err
	}
	reply.UDP = &d.replyTo
	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{reply})
}

func TestHandlerCountersPreserveFullconePacketDestinations(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	uplinkUdpCounter := new(testCounter)
	downlinkUdpCounter := new(testCounter)
	destA := xnet.UDPDestination(xnet.ParseAddress("203.0.113.10"), 3478)
	destB := xnet.UDPDestination(xnet.ParseAddress("203.0.113.20"), 3478)
	conn := &testPacketConn{testConn: *newTestConn([]byte("uplink")), readDest: &destA}
	dispatcher := &fullconeProbeDispatcher{replyTo: destB}

	handler := &Handler{
		ctx:                context.Background(),
		config:             &Config{},
		dispatcher:         dispatcher,
		uplinkCounter:      uplinkCounter,
		downlinkCounter:    downlinkCounter,
		uplinkUdpCounter:   uplinkUdpCounter,
		downlinkUdpCounter: downlinkUdpCounter,
	}
	handler.HandleConnection(conn, xnet.UDPDestination(xnet.LocalHostIP, 53))

	if dispatcher.gotDest == nil || *dispatcher.gotDest != destA {
		t.Fatalf("per-packet destination lost on the way in: got %v, want %v", dispatcher.gotDest, destA)
	}
	if len(conn.gotReplyTo) != 1 || conn.gotReplyTo[0] == nil || *conn.gotReplyTo[0] != destB {
		t.Fatalf("per-packet reply destination lost on the way out: got %v, want %v", conn.gotReplyTo, destB)
	}
	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	// This regression test used to check only the old pair of aggregates; without checking the
	// udp counters, the per-network split could silently miss the fullcone path.
	if got := uplinkUdpCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected udp uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkUdpCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected udp downlink counter: got %d, want %d", got, len("downlink"))
	}
}

// activeProbeDispatcher records the active counter's value AT dispatch time;
// from outside it can only be seen as zero (the defer has already run).
type activeProbeDispatcher struct {
	testDispatcher
	active       *testCounter
	activeDuring int64
}

func (d *activeProbeDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	d.activeDuring = d.active.Value()
	return d.testDispatcher.DispatchLink(ctx, dest, link)
}

func TestHandlerCountsTunConnections(t *testing.T) {
	activeCounter := new(testCounter)
	handledCounter := new(testCounter)
	dispatcher := &activeProbeDispatcher{
		testDispatcher: testDispatcher{writePayload: []byte("downlink")},
		active:         activeCounter,
	}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:            context.Background(),
		config:         &Config{},
		dispatcher:     dispatcher,
		activeCounter:  activeCounter,
		handledCounter: handledCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := handledCounter.Value(); got != 1 {
		t.Fatalf("unexpected handled counter: got %d, want 1", got)
	}
	if got := dispatcher.activeDuring; got != 1 {
		t.Fatalf("active counter during dispatch: got %d, want 1", got)
	}
	if got := activeCounter.Value(); got != 0 {
		t.Fatalf("active counter must return to zero after the connection: got %d", got)
	}
}

func TestHandlerCountsTunConnectionTraffic(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	dispatcher := &testDispatcher{writePayload: []byte("downlink")}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("dispatcher read unexpected bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("connection write mismatch: got %q, want %q", got, "downlink")
	}
}

func TestHandlerSplitsTrafficByNetwork(t *testing.T) {
	up, down := new(testCounter), new(testCounter)
	upTCP, downTCP := new(testCounter), new(testCounter)
	upUDP, downUDP := new(testCounter), new(testCounter)

	handler := &Handler{
		ctx: context.Background(), config: &Config{}, dispatcher: &testDispatcher{writePayload: []byte("downlink")},
		uplinkCounter: up, downlinkCounter: down,
		uplinkTcpCounter: upTCP, downlinkTcpCounter: downTCP,
		uplinkUdpCounter: upUDP, downlinkUdpCounter: downUDP,
	}

	handler.HandleConnection(newTestConn([]byte("hello!")), xnet.TCPDestination(xnet.LocalHostIP, 443))

	if upTCP.Value() == 0 {
		t.Fatalf("a TCP flow left the tcp uplink counter at zero")
	}
	// downTCP (inbound TCP) is usually the busiest of the four per-network counters, and
	// until this line nothing checked it: fanOut(down, t.downlinkTcpCounter) could be
	// removed from handler.go and go test ./proxy/tun/ would stay green.
	if downTCP.Value() == 0 {
		t.Fatalf("a TCP flow left the tcp downlink counter at zero")
	}
	if upUDP.Value() != 0 || downUDP.Value() != 0 {
		t.Errorf("a TCP flow moved the udp counters: up=%d down=%d", upUDP.Value(), downUDP.Value())
	}
	// The same "aggregate equals the sum" invariant as in TestHandlerUdpFlowMovesOnlyTheUdpCounters,
	// but on a TCP flow: there down equals downUDP, so that test passes whatever downTCP does.
	if up.Value() != upTCP.Value()+upUDP.Value() {
		t.Errorf("uplink %d != tcp %d + udp %d", up.Value(), upTCP.Value(), upUDP.Value())
	}
	if down.Value() != downTCP.Value()+downUDP.Value() {
		t.Errorf("downlink %d != tcp %d + udp %d", down.Value(), downTCP.Value(), downUDP.Value())
	}
}

func TestHandlerUdpFlowMovesOnlyTheUdpCounters(t *testing.T) {
	up, down := new(testCounter), new(testCounter)
	upTCP, downTCP := new(testCounter), new(testCounter)
	upUDP, downUDP := new(testCounter), new(testCounter)

	// Built the same way as testPacketConn in TestHandlerCountersPreserveFullconePacketDestinations:
	// no separate newTestPacketConn is needed, the packet-aware conn is assembled in place.
	readDest := xnet.UDPDestination(xnet.ParseAddress("203.0.113.10"), 3478)
	conn := &testPacketConn{testConn: *newTestConn([]byte("uplink")), readDest: &readDest}

	handler := &Handler{
		ctx: context.Background(), config: &Config{}, dispatcher: &fullconeProbeDispatcher{},
		uplinkCounter: up, downlinkCounter: down,
		uplinkTcpCounter: upTCP, downlinkTcpCounter: downTCP,
		uplinkUdpCounter: upUDP, downlinkUdpCounter: downUDP,
	}

	handler.HandleConnection(conn, xnet.UDPDestination(xnet.LocalHostIP, 53))

	if upUDP.Value() == 0 || downUDP.Value() == 0 {
		t.Fatalf("a UDP flow left the udp counters at zero: up=%d down=%d", upUDP.Value(), downUDP.Value())
	}
	if upTCP.Value() != 0 || downTCP.Value() != 0 {
		t.Errorf("a UDP flow moved the tcp counters: up=%d down=%d", upTCP.Value(), downTCP.Value())
	}
	// An invariant, not an approximation: exactly two paths go through HandleConnection
	// (the TCP and UDP forwarders), ICMP is answered locally in the stack and never gets
	// here, and the TUN inbound has no workers, so the aggregate must be the EXACT sum.
	if up.Value() != upTCP.Value()+upUDP.Value() {
		t.Errorf("uplink %d != tcp %d + udp %d", up.Value(), upTCP.Value(), upUDP.Value())
	}
	if down.Value() != downTCP.Value()+downUDP.Value() {
		t.Errorf("downlink %d != tcp %d + udp %d", down.Value(), downTCP.Value(), downUDP.Value())
	}
}

const xrayKey core.XrayKey = 1

// The first test in this file that actually calls Init(): the counter names are part of the
// contract with app/metrics/metrics.go, and until now nothing checked them.
func TestHandlerRegistersCountersUnderTheNamesMetricsGroupsBy(t *testing.T) {
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appstats.Config{}),
			serial.ToTypedMessage(&apppolicy.Config{
				System: &apppolicy.SystemPolicy{
					Stats: &apppolicy.SystemPolicy_Stats{InboundUplink: true, InboundDownlink: true},
				},
			}),
		},
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	ctx := context.WithValue(context.Background(), xrayKey, v)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "tun"})

	handler := &Handler{config: &Config{}}
	pm := v.GetFeature(policy.ManagerType()).(policy.Manager)
	if err := handler.Init(ctx, pm, nil); err != nil {
		t.Fatalf("Init: %v", err)
	}

	sm := v.GetFeature(stats.ManagerType()).(stats.Manager)

	// The check must run over the ACTUALLY registered names (as app/metrics/metrics.go
	// itself does via VisitCounters), not over a literal slice: comparing a literal with
	// itself cannot catch anything. A mutation run confirmed it: the FAIL came only from
	// GetCounter, not from the segment checks.
	var registered []string
	sm.VisitCounters(func(name string, _ stats.Counter) bool {
		parts := strings.Split(name, ">>>")
		if len(parts) >= 2 && parts[0] == "inbound" && parts[1] == "tun" {
			registered = append(registered, name)
		}
		return true
	})

	want := []string{
		"inbound>>>tun>>>traffic>>>uplink",
		"inbound>>>tun>>>traffic>>>downlink",
		"inbound>>>tun>>>traffic>>>uplink-tcp",
		"inbound>>>tun>>>traffic>>>downlink-tcp",
		"inbound>>>tun>>>traffic>>>uplink-udp",
		"inbound>>>tun>>>traffic>>>downlink-udp",
	}
	haveName := map[string]bool{}
	for _, name := range registered {
		haveName[name] = true
	}
	for _, name := range want {
		if !haveName[name] {
			t.Errorf("counter %q is not registered", name)
		}
	}

	// A /debug/vars cell is the triple (segment [0], segment [1], segment [3]): that is what
	// metrics.go builds, dropping segment [2]. A collision in this triple is a lost number,
	// and it has to be caught on the set of names that actually sits in stats.Manager, not
	// on a table of expectations known in advance (and so unable to disagree with itself).
	type cell struct{ typeName, tag, direction string }
	seenCells := map[cell]string{}
	for _, name := range registered {
		parts := strings.Split(name, ">>>")
		if len(parts) < 4 {
			t.Fatalf("registered counter %q has %d segments; metrics.go drops anything shorter than four", name, len(parts))
		}
		key := cell{parts[0], parts[1], parts[3]}
		if other, clash := seenCells[key]; clash {
			t.Errorf("%q and %q share the /debug/vars cell (%q, %q, %q)", name, other, key.typeName, key.tag, key.direction)
		}
		seenCells[key] = name
	}
}
