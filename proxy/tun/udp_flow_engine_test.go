//go:build darwin

package tun_test

// The whole engine: the tun inbound's real UDP flow table (darwin policy, the real
// kernel socket table) feeding the real handler, dispatcher, router and outbounds. Loopback only, no
// root: the "internet" is UDP echo servers on 127.0.0.1, and a "program" is a real UDP socket on
// 127.0.0.1 whose address and port the test hands to HandlePacket as the packet's source — what
// every program behind a utun looks like to this table, with the utun's address instead.

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/tun"
)

type udpEcho struct {
	conn *net.UDPConn
	mu   sync.Mutex
	from []string // the sender of every datagram: the outbound socket that carried it
}

func newUDPEcho(t *testing.T) *udpEcho {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echo := &udpEcho{conn: conn}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.mu.Lock()
			echo.from = append(echo.from, from.String())
			echo.mu.Unlock()
			conn.WriteToUDP(b[:n], from)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return echo
}

func (e *udpEcho) port() int { return e.conn.LocalAddr().(*net.UDPAddr).Port }

func (e *udpEcho) dest() xnet.Destination {
	return xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(e.port()))
}

func (e *udpEcho) senders() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.from...)
}

func startTestEngine(t *testing.T, config string) *core.Instance {
	t.Helper()
	parsed, err := serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return instance
}

func uplinkOf(instance *core.Instance, tag string) int64 {
	manager := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if counter := manager.GetCounter("outbound>>>" + tag + ">>>traffic>>>uplink"); counter != nil {
		return counter.Value()
	}
	return -1
}

// flowTable is the tun inbound's UDP table on a handler of this engine, as stack_gvisor.go builds it.
func flowTable(t *testing.T, instance *core.Instance) *tun.UDPFlowsForTest {
	t.Helper()
	object, err := core.CreateObject(instance, &tun.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return tun.NewUDPFlowsForTest(object.(*tun.Handler), func([]byte, xnet.Destination, xnet.Destination) error { return nil })
}

// program opens a real socket on 127.0.0.1 (port 0: any) — a program as the socket table sees it.
func program(t *testing.T, port xnet.Port) (*net.UDPConn, xnet.Destination) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port))
}

func waitUntil(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never happened within %v: %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func senderPort(sender string) string { return sender[strings.LastIndex(sender, ":")+1:] }

// A port reused without process rules: a port rule sends program A direct; program B, on A's port
// once A closed it, sends to an address the rules block. With a flow held by its source alone, B's
// datagram left through A's direct socket.
func TestUDPFlowAnotherProgramOnTheSamePortIsRoutedAgain(t *testing.T) {
	a, b := newUDPEcho(t), newUDPEcho(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},
	  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing":{"rules":[
	    {"type":"field","network":"udp","port":"`+strconv.Itoa(a.port())+`","outboundTag":"direct"},
	    {"type":"field","network":"udp","outboundTag":"block"}]}}`)
	flows := flowTable(t, instance)

	programA, source := program(t, 0)
	flows.HandlePacket(source, a.dest(), []byte("from-A"))
	waitUntil(t, "A's datagram reaches its server", 2*time.Second, func() bool { return len(a.senders()) == 1 })
	waitUntil(t, "the flow knows A's socket", 2*time.Second, func() bool { return flows.Identified(source) })

	programA.Close()
	program(t, source.Port) // program B is handed the same port
	flows.HandlePacket(source, b.dest(), []byte("from-B"))
	time.Sleep(time.Second)
	if got := b.senders(); len(got) != 0 {
		t.Fatalf("B's datagram to a blocked address left through A's flow, from %v", got)
	}
	if n := flows.FlowCount(); n != 1 {
		t.Fatalf("%d flows under the source, want 1 (B's own, blocked)", n)
	}
}

// A live socket keeps its full cone: two destinations and a pause (which re-checks the same socket)
// are one flow and one outbound socket.
func TestUDPFlowALiveSocketKeepsItsFullCone(t *testing.T) {
	a, b := newUDPEcho(t), newUDPEcho(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},
	  "outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	flows := flowTable(t, instance)

	_, source := program(t, 0)
	flows.HandlePacket(source, a.dest(), []byte("1"))
	waitUntil(t, "A answered", 2*time.Second, func() bool { return len(a.senders()) == 1 })
	flows.HandlePacket(source, b.dest(), []byte("2"))
	waitUntil(t, "B answered", 2*time.Second, func() bool { return len(b.senders()) == 1 })
	time.Sleep(1100 * time.Millisecond) // past the silence: the next packet is re-checked
	flows.HandlePacket(source, a.dest(), []byte("3"))
	waitUntil(t, "A answered again", 2*time.Second, func() bool { return len(a.senders()) == 2 })

	senders := append(a.senders(), b.senders()...)
	for _, sender := range senders[1:] {
		if senderPort(sender) != senderPort(senders[0]) {
			t.Fatalf("one socket went out through several outbound sockets: %v", senders)
		}
	}
	if n := flows.FlowCount(); n != 1 {
		t.Fatalf("%d flows, want 1", n)
	}
}

// Traffic with no socket on this Mac (a virtual machine, internet sharing) keeps its full cone too.
func TestUDPFlowTrafficWithoutASocketKeepsItsFullCone(t *testing.T) {
	a, b := newUDPEcho(t), newUDPEcho(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},
	  "outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	flows := flowTable(t, instance)

	nobody, source := program(t, 0)
	nobody.Close() // a port no socket holds
	flows.HandlePacket(source, a.dest(), []byte("1"))
	waitUntil(t, "A answered", 2*time.Second, func() bool { return len(a.senders()) == 1 })
	waitUntil(t, "the flow knows it has no socket", 2*time.Second, func() bool { return flows.Identified(source) })
	flows.HandlePacket(source, b.dest(), []byte("2"))
	waitUntil(t, "B answered", 2*time.Second, func() bool { return len(b.senders()) == 1 })
	if senderPort(a.senders()[0]) != senderPort(b.senders()[0]) {
		t.Fatalf("socketless traffic lost its full cone: %v then %v", a.senders(), b.senders())
	}
}

// newUDPEcho6 is an echo server on [::1]: an address the rows below leave out of 127.0.0.0/8, so a
// datagram to it is routed by the rows that follow — the "internet" next to a "LAN" on 127.0.0.1.
func newUDPEcho6(t *testing.T) (*udpEcho, xnet.Destination) {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	echo := &udpEcho{conn: conn}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.mu.Lock()
			echo.from = append(echo.from, from.String())
			echo.mu.Unlock()
			conn.WriteToUDP(b[:n], from)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return echo, xnet.UDPDestination(xnet.ParseAddress("::1"), xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port))
}

// A socket's datagram to another address is routed for that address. The flow used to be routed
// once, for its first datagram, and to carry every later one of the socket, to any address, through
// the same outbound: a first datagram that an address rule sends direct (rules for local networks
// and proxy servers come before the rest) took the program's datagrams to anywhere out of the
// direct socket, past the rules that block them.
func TestUDPFlowADatagramToAnotherAddressIsRoutedForThatAddress(t *testing.T) {
	lan := newUDPEcho(t)
	internet, internetDest := newUDPEcho6(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},
	  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing":{"rules":[
	    {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"direct"},
	    {"type":"field","network":"udp","outboundTag":"block"}]}}`)
	flows := flowTable(t, instance)

	_, source := program(t, 0)
	flows.HandlePacket(source, lan.dest(), []byte("to-lan"))
	waitUntil(t, "the LAN datagram arrives", 2*time.Second, func() bool { return len(lan.senders()) == 1 })
	flows.HandlePacket(source, internetDest, []byte("to-internet"))
	flows.HandlePacket(source, lan.dest(), []byte("to-lan-again"))
	waitUntil(t, "the second LAN datagram arrives", 2*time.Second, func() bool { return len(lan.senders()) == 2 })
	time.Sleep(300 * time.Millisecond)

	if got := internet.senders(); len(got) != 0 {
		t.Fatalf("a datagram to an address the rows block left through the LAN datagram's route, from %v", got)
	}
	if got := lan.senders(); senderPort(got[0]) != senderPort(got[1]) {
		t.Fatalf("the LAN destination lost its flow: %v", got)
	}
}

// Each route a socket's destinations take keeps a full cone of its own: one flow and one outbound
// socket per route, all alive at once — a WebRTC socket that talks to a peer on the LAN and to a
// STUN server and a peer on the internet keeps one mapping for each. (An address of fake DNS shares
// the flow of no route: it has one of its own. This engine has no fake DNS; the one in
// udp_flow_rules_test.go has.)
func TestUDPFlowEveryRouteOfASocketKeepsItsOwnFullCone(t *testing.T) {
	lan := newUDPEcho(t)
	internetA, destA := newUDPEcho6(t)
	internetB, destB := newUDPEcho6(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},"stats":{},
	  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
	  "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"proxy-udp","protocol":"freedom"}],
	  "routing":{"rules":[
	    {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"direct"},
	    {"type":"field","network":"udp","outboundTag":"proxy-udp"}]}}`)
	flows := flowTable(t, instance)

	_, source := program(t, 0)
	for _, step := range []struct {
		to   xnet.Destination
		echo *udpEcho
		want int
	}{{lan.dest(), lan, 1}, {destA, internetA, 1}, {lan.dest(), lan, 2}, {destB, internetB, 1}, {destA, internetA, 2}} {
		flows.HandlePacket(source, step.to, []byte("12345"))
		waitUntil(t, "the datagram arrives", 2*time.Second, func() bool { return len(step.echo.senders()) == step.want })
	}
	time.Sleep(100 * time.Millisecond) // the counters settle

	onProxy := append(internetA.senders(), internetB.senders()...)
	for _, sender := range onProxy[1:] {
		if senderPort(sender) != senderPort(onProxy[0]) {
			t.Fatalf("the internet destinations went out through several sockets: %v", onProxy)
		}
	}
	if got := lan.senders(); senderPort(got[0]) != senderPort(got[1]) {
		t.Fatalf("the LAN destination went out through several sockets: %v", got)
	}
	if direct, proxy := uplinkOf(instance, "direct"), uplinkOf(instance, "proxy-udp"); direct != 10 || proxy != 15 {
		t.Fatalf("direct carried %d bytes (want the two LAN datagrams, 10), proxy-udp %d (want the three internet ones, 15)", direct, proxy)
	}
	if n := flows.FlowCount(); n != 2 {
		t.Fatalf("%d flows, want 2: one per route", n)
	}
}
