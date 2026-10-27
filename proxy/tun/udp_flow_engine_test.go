//go:build darwin

package tun_test

// The whole engine: the tun inbound's real UDP flow table (darwin policy, the real
// kernel socket table) feeding the real handler, dispatcher, router and outbounds. Loopback only, no
// root: the "internet" is UDP echo servers on 127.0.0.1, and a "program" is a real UDP socket on
// 127.0.0.1 whose address and port the test hands to HandlePacket as the packet's source — what
// every program behind a utun looks like to this table, with the utun's address instead. A program
// is a socket of this process, the engine's too, so the table here sets no socket aside as the
// engine's own (flowTable); the tests of that rule hold their programs in processes of their own
// (flowTableOfThisProcess).

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// loopback4 opens a UDP socket on 127.0.0.1 whose port no outbound socket of the engine can take
// for the rest of the test, the socket open or closed. An outbound socket is dual-stack on [::] (Go
// "udp" on 0.0.0.0:0, transport/internet/system_dialer.go), and the kernel picks its port among the
// ports IPv6 sockets leave free, without looking at IPv4 sockets. So the port is also held on [::1]
// until the test ends. The socket table never reads that socket as one on 127.0.0.1 (it is bound to
// ::1, neither to 127.0.0.1 nor to a wildcard), so what a test's socket is to the flow table stays
// the same. A port some IPv6 socket already holds is given back, and another one taken.
func loopback4(t *testing.T) *net.UDPConn {
	t.Helper()
	for range 16 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		if guard, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port}); err == nil {
			t.Cleanup(func() { guard.Close() })
			return conn
		}
		conn.Close()
	}
	t.Fatal("no port on 127.0.0.1 that is free on [::1] too")
	return nil
}

func newUDPEcho(t *testing.T) *udpEcho {
	t.Helper()
	conn := loopback4(t)
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

// flowTable is the tun inbound's UDP table on a handler of this engine, as stack_gvisor.go builds it,
// with no socket set aside as the engine's own: the tests' programs share the engine's process.
func flowTable(t *testing.T, instance *core.Instance) *tun.UDPFlowsForTest {
	t.Helper()
	return tun.NewUDPFlowsForTest(handlerOf(t, instance), func([]byte, xnet.Destination, xnet.Destination) error { return nil })
}

// flowTableOfThisProcess is that table as the product builds and runs it, policy and all: the
// sockets of this process are the engine's own. Its programs are sockets of other processes
// (socketOfAnotherProcess).
func flowTableOfThisProcess(t *testing.T, instance *core.Instance) *tun.UDPFlowsForTest {
	t.Helper()
	return tun.NewUDPFlowsOfTheProductForTest(handlerOf(t, instance), func([]byte, xnet.Destination, xnet.Destination) error { return nil })
}

func handlerOf(t *testing.T, instance *core.Instance) *tun.Handler {
	t.Helper()
	object, err := core.CreateObject(instance, &tun.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return object.(*tun.Handler)
}

// socketHolder, in the environment of a process this test binary starts again, names the UDP socket
// that process opens and holds for a test: "<network> <address>", then " reuse" for SO_REUSEADDR.
const socketHolder = "UDPFLOW_TEST_SOCKET_HOLDER"

// TestMain: a process started with socketHolder set runs no test. It opens the socket named, writes
// its port on a line of its own, and holds it until its standard input closes.
func TestMain(m *testing.M) {
	if spec := os.Getenv(socketHolder); spec != "" {
		os.Exit(holdSocket(spec))
	}
	os.Exit(m.Run())
}

func holdSocket(spec string) int {
	fields := strings.Fields(spec)
	if len(fields) < 2 {
		fmt.Println("no socket named:", spec)
		return 1
	}
	var config net.ListenConfig
	if len(fields) == 3 && fields[2] == "reuse" {
		config.Control = reuseAddress
	}
	conn, err := config.ListenPacket(context.Background(), fields[0], fields[1])
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer conn.Close()
	fmt.Println(conn.LocalAddr().(*net.UDPAddr).Port)
	io.Copy(io.Discard, os.Stdin)
	return 0
}

func reuseAddress(_, _ string, c syscall.RawConn) error {
	var err error
	if controlErr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); controlErr != nil {
		return controlErr
	}
	return err
}

// socketOfAnotherProcess opens a UDP socket in a process of its own, which holds it until the test
// ends or until the function returned is called, and returns its port: a program, to the engine of
// the product, is a socket of another process. reuse: SO_REUSEADDR, to bind next to a socket already
// on the port.
func socketOfAnotherProcess(t *testing.T, network, address string, reuse bool) (xnet.Port, func()) {
	t.Helper()
	spec := network + " " + address
	if reuse {
		spec += " reuse"
	}
	holder := exec.Command(os.Args[0], "-test.run=^$")
	holder.Env = append(os.Environ(), socketHolder+"="+spec)
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	var closing sync.Once
	closeSocket := func() {
		closing.Do(func() {
			stdin.Close()
			holder.Wait() // the process has exited: its socket is closed
		})
	}
	t.Cleanup(closeSocket)
	line, _ := bufio.NewReader(stdout).ReadString('\n')
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("a socket %s in another process: %q", spec, line)
	}
	return xnet.Port(port), closeSocket
}

// programOfAnotherProcess is program() in a process of its own: a socket on 127.0.0.1, and the
// function that closes it.
func programOfAnotherProcess(t *testing.T) (xnet.Destination, func()) {
	t.Helper()
	port, closeSocket := socketOfAnotherProcess(t, "udp4", "127.0.0.1:0", false)
	return xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), port), closeSocket
}

// enginesSocketOn opens, in this process, what the engine's outbound opens for a UDP flow (Go "udp"
// on the wildcard: dual-stack [::]), on the port of the test's choosing. SO_REUSEADDR lets it bind
// next to the program's socket: the pair the kernel makes now and then by itself.
func enginesSocketOn(t *testing.T, port xnet.Port) {
	t.Helper()
	conn, err := (&net.ListenConfig{Control: reuseAddress}).ListenPacket(context.Background(), "udp", "0.0.0.0:"+strconv.Itoa(int(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
}

// program opens a real socket on 127.0.0.1 (port 0: any) — a program as the socket table sees it.
// A port other than 0 is one an earlier program of the test was given, so loopback4 keeps it
// from the outbound sockets already.
func program(t *testing.T, port xnet.Port) (*net.UDPConn, xnet.Destination) {
	t.Helper()
	var conn *net.UDPConn
	if port == 0 {
		conn = loopback4(t)
	} else {
		var err error
		if conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { conn.Close() })
	return conn, xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port))
}

// The ports of the tests' sockets on 127.0.0.1 are kept from the engine's outbound sockets
// (loopback4). On an echo server's port an outbound socket loses the answers meant for it to the
// echo's socket, the more exact match, and the echo servers keep answering each other (or one
// itself), so a count of datagrams never settles. One on a program's port, open or closed, is one more socket
// there in the socket table, which to the flow table is a port that changed hands: the engine's
// sockets are set aside by their process, and here the programs share it (flowTable). Either way an
// engine test fails for a pair of sockets the kernel made, not for anything the flow table did.
func TestUDPFlowTheTestsPortsAreKeptFromTheOutboundSockets(t *testing.T) {
	held := map[int]string{}
	for range 200 {
		held[newUDPEcho(t).port()] = "an echo server"
		_, open := program(t, 0)
		held[int(open.Port)] = "a program"
		closed, gone := program(t, 0)
		closed.Close()
		held[int(gone.Port)] = "a program that closed its socket"
	}
	var taken []string
	for range 600 {
		// What the system dialer opens for a freedom outbound's UDP flow (transport/internet/system_dialer.go).
		conn, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		if what, ok := held[conn.LocalAddr().(*net.UDPAddr).Port]; ok {
			taken = append(taken, conn.LocalAddr().String()+" took the port of "+what)
		}
	}
	if len(taken) != 0 {
		t.Fatalf("%d of 600 outbound sockets took the port of one of the %d test sockets: %v", len(taken), len(held), taken)
	}
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

// The port-reuse scenario without per-app rules: a port rule sends program A direct; program B, on
// A's port once A closed it, sends to an address the rules block. In upstream's full cone, B's
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

// The engine's own socket on a program's port is not the program's. The kernel picks the port of an
// outbound socket (dual-stack [::]) without looking at IPv4 sockets, so it can give it the port a
// program holds; counted, it was a second socket there, the port "changed hands", and the program's
// flows ended while it kept its socket. The engine runs as a process of its own, so the sockets of its
// process are set aside.
func TestUDPFlowTheEnginesOwnSocketOnAProgramsPortLeavesTheProgramItsFlow(t *testing.T) {
	a, b := newUDPEcho(t), newUDPEcho(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},
	  "outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	flows := flowTableOfThisProcess(t, instance)

	source, _ := programOfAnotherProcess(t)
	flows.HandlePacket(source, a.dest(), []byte("1"))
	waitUntil(t, "A answered", 2*time.Second, func() bool { return len(a.senders()) == 1 })
	waitUntil(t, "the flow knows the program's socket", 2*time.Second, func() bool { return flows.Identified(source) })
	enginesSocketOn(t, source.Port)
	flows.HandlePacket(source, b.dest(), []byte("2")) // another destination: the source is checked again
	waitUntil(t, "B answered", 2*time.Second, func() bool { return len(b.senders()) == 1 })

	if senderPort(a.senders()[0]) != senderPort(b.senders()[0]) {
		t.Fatalf("the program lost its flow to a socket of the engine on its port: %v then %v", a.senders(), b.senders())
	}
	if n := flows.FlowCount(); n != 1 {
		t.Fatalf("%d flows, want 1", n)
	}
}

// A socket of another process on the program's port is still another socket there: the port changed
// hands, the program's flow ends, and its next datagram is routed afresh in a flow of its own.
func TestUDPFlowASocketOfAnotherProcessOnAProgramsPortEndsTheProgramsFlow(t *testing.T) {
	a, b := newUDPEcho(t), newUDPEcho(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},
	  "outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	flows := flowTableOfThisProcess(t, instance)

	source, _ := programOfAnotherProcess(t)
	flows.HandlePacket(source, a.dest(), []byte("1"))
	waitUntil(t, "A answered", 2*time.Second, func() bool { return len(a.senders()) == 1 })
	waitUntil(t, "the flow knows the program's socket", 2*time.Second, func() bool { return flows.Identified(source) })
	socketOfAnotherProcess(t, "udp", "0.0.0.0:"+strconv.Itoa(int(source.Port)), true)
	flows.HandlePacket(source, b.dest(), []byte("2"))
	waitUntil(t, "B answered", 2*time.Second, func() bool { return len(b.senders()) == 1 })

	if senderPort(a.senders()[0]) == senderPort(b.senders()[0]) {
		t.Fatalf("a socket of another process on the program's port left the program's flow as it was: both from %v", a.senders())
	}
	if n := flows.FlowCount(); n != 1 {
		t.Fatalf("%d flows, want 1: the new one", n)
	}
}

// Setting the engine's sockets aside hides no change of hands. The program closes its socket and a
// program of another process binds the same address and port, with a socket of the engine on that
// port or without one. The next program's datagram, to another destination or to the same one after
// a silence, does not ride the first program's flow: that flow ends, and the datagram goes out in a
// flow of its own, from another outbound socket.
func TestUDPFlowAPortThatChangesHandsUnderASocketOfTheEngineEndsTheFlow(t *testing.T) {
	for _, engineOnThePort := range []bool{true, false} {
		for _, sameDestination := range []bool{false, true} {
			name := "no socket of the engine on the port"
			if engineOnThePort {
				name = "a socket of the engine on the port"
			}
			if sameDestination {
				name += ", the same destination after a silence"
			} else {
				name += ", another destination"
			}
			t.Run(name, func(t *testing.T) {
				a, b := newUDPEcho(t), newUDPEcho(t)
				instance := startTestEngine(t, `{"log":{"loglevel":"none"},
				  "outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
				flows := flowTableOfThisProcess(t, instance)

				source, closeFirst := programOfAnotherProcess(t)
				flows.HandlePacket(source, a.dest(), []byte("1"))
				waitUntil(t, "A answered", 2*time.Second, func() bool { return len(a.senders()) == 1 })
				waitUntil(t, "the flow knows the program's socket", 2*time.Second, func() bool { return flows.Identified(source) })
				if engineOnThePort {
					enginesSocketOn(t, source.Port)
				}
				closeFirst()
				socketOfAnotherProcess(t, "udp4", source.NetAddr(), true)

				next := b
				if sameDestination {
					next = a
					time.Sleep(1500 * time.Millisecond) // past darwin's 1 s silence: the source is checked again
				}
				answers := len(next.senders()) + 1
				flows.HandlePacket(source, next.dest(), []byte("2"))
				waitUntil(t, "the next program's datagram answered", 2*time.Second, func() bool { return len(next.senders()) == answers })

				if first, then := senderPort(a.senders()[0]), senderPort(next.senders()[answers-1]); first == then {
					t.Fatalf("the next program on the port rode the first program's flow: both from port %s", first)
				}
				if n := flows.FlowCount(); n != 1 {
					t.Fatalf("%d flows, want 1: the next program's", n)
				}
			})
		}
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
// the same outbound: a first datagram that an address row sends direct (the app's rows for local
// networks and proxy hops come before every per-app row) took the program's datagrams to anywhere
// out of the direct socket — a program whose own rule blocks it too.
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

// The other way round: a socket whose first datagram goes to an address the rows block still reaches
// an address they send through the proxy, through the proxy. Routed once, by its first datagram, the
// flow carried the socket's later datagrams to the blackhole too, which keeps a UDP flow open for
// half a minute or more.
func TestUDPFlowAfterABlockedFirstDatagramAnAllowedAddressArrivesThroughItsOwnRoute(t *testing.T) {
	blocked := newUDPEcho(t)
	allowed, allowedDest := newUDPEcho6(t)
	instance := startTestEngine(t, `{"log":{"loglevel":"none"},"stats":{},
	  "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
	  "outbounds":[{"tag":"proxy-udp","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing":{"rules":[
	    {"type":"field","ip":["127.0.0.0/8"],"outboundTag":"block"},
	    {"type":"field","network":"udp","outboundTag":"proxy-udp"}]}}`)
	flows := flowTable(t, instance)

	_, source := program(t, 0)
	flows.HandlePacket(source, blocked.dest(), []byte("to-blocked"))
	waitUntil(t, "the flow knows the socket", 2*time.Second, func() bool { return flows.Identified(source) })
	flows.HandlePacket(source, allowedDest, []byte("to-allowed"))
	waitUntil(t, "the datagram to the allowed address arrives", 3*time.Second, func() bool { return len(allowed.senders()) == 1 })
	flows.HandlePacket(source, blocked.dest(), []byte("to-blocked-again"))
	time.Sleep(300 * time.Millisecond)

	if got := blocked.senders(); len(got) != 0 {
		t.Fatalf("a datagram to the blocked address arrived, from %v", got)
	}
	if proxy := uplinkOf(instance, "proxy-udp"); proxy != int64(len("to-allowed")) {
		t.Fatalf("proxy-udp carried %d bytes, want the allowed datagram's %d", proxy, len("to-allowed"))
	}
	if n := flows.FlowCount(); n != 2 {
		t.Fatalf("%d flows, want 2: the blocked route's and the proxy's", n)
	}
}

// Each route a socket's destinations take keeps a full cone of its own: one flow and one outbound
// socket per route, all alive at once — a WebRTC socket that talks to a peer on the LAN and to a
// STUN server and a peer on the internet keeps one mapping for each.
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
