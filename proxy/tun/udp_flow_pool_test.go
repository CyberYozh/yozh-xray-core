package tun_test

// The whole engine with fake DNS, on every platform: the tun inbound's UDP flow table, built as the
// bridge builds it (NewUDPFlowsForTest), feeding the real handler, dispatcher, router and outbounds
// of a client, which reach a proxy server that is a second engine. Loopback only, nothing leaves the
// machine. The tables of udp_flow_test.go stand a pool in for fake DNS's; this is the pool the
// product uses, and the proxy protocols that carry a flow by its first destination.
//
// The file has no TestMain: darwin's tests have one (udp_flow_engine_test.go), and the other
// platforms need none. On darwin the table is the real kernel one, so the sockets of the tests keep
// their ports from the engine's outbound sockets (poolLoopback).

import (
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/tun"
)

const (
	// Not a documentation range: the product's own pool, the shape its rules and its sniffing exclusions
	// are written around, which the test must meet as it is.
	poolLabPool = "198.19.0.0/17"
	poolLabPort = 3478
	poolLabUUID = "b831381d-6324-4d53-ad4f-8cda48b30811" // the example UUID of Xray's own docs
)

// poolLabPrivateNetworks is the bypass:lan row of a whole-system client: loopback, private,
// link-local, CGNAT and documentation ranges, and the benchmarking block cut down to the tun's own
// 198.18.0.0/16. The pool lies in the rest of that block (198.18.0.0/15): left in the row, the pool
// would be sent direct and the sniffing would leave it alone.
var poolLabPrivateNetworks = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.18.0.0/16", "198.51.100.0/24", "203.0.113.0/24",
	"::1/128", "fc00::/7", "fe80::/10",
}

// poolLoopback opens a UDP socket on 127.0.0.1 whose port no outbound socket of the engine can take
// for the rest of the test, the socket open or closed. An outbound socket is dual-stack on [::] (Go
// "udp" on 0.0.0.0:0, transport/internet/system_dialer.go), and darwin's kernel picks its port among
// the ports IPv6 sockets leave free, without looking at IPv4 sockets. On a program's port the
// source then looks to the socket table like a port that changed hands, and ends; on an echo's port
// the echo answers itself and a count of datagrams never settles. So the port is also held on [::1]
// until the test ends. The socket table never reads that one as a socket on 127.0.0.1 (it is bound
// to ::1, neither to 127.0.0.1 nor to a wildcard), so what a test's socket is to the flow table stays
// the same. A port some IPv6 socket already holds is given back, and another one taken. This is
// udp_flow_engine_test.go's loopback4, which only darwin builds. Only darwin's kernel needs the
// guard, and darwin always has ::1; where there is no ::1 the guard cannot be taken, and the socket
// is taken as it is.
func poolLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	guarded := hasIPv6Loopback()
	for range 16 {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		if !guarded {
			return conn
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

func hasIPv6Loopback() bool {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return false
	}
	probe.Close()
	return true
}

// poolEcho sends every datagram it gets back to where it came from, and keeps their payloads.
type poolEcho struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  []string
}

func newPoolEcho(t *testing.T) *poolEcho {
	t.Helper()
	conn := poolLoopback(t)
	echo := &poolEcho{conn: conn}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.mu.Lock()
			echo.got = append(echo.got, string(b[:n]))
			echo.mu.Unlock()
			conn.WriteToUDP(b[:n], from)
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return echo
}

func (e *poolEcho) port() int { return e.conn.LocalAddr().(*net.UDPAddr).Port }

func (e *poolEcho) payloads() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.got)
}

func startPoolEngine(t *testing.T, config string) *core.Instance {
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

// poolFreePort is a port free on 127.0.0.1 for TCP and UDP both, for the proxy server. It is looked
// for below the ephemeral range: Windows reserves blocks of that range per protocol
// (excludedportrange), so a port the system hands out for one protocol is often refused to the other.
func poolFreePort(t *testing.T) int {
	t.Helper()
	const low, span = 20000, 25000
	start := rand.IntN(span)
	for i := range 200 {
		port := low + (start+i)%span
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		listener.Close()
		if err == nil {
			udp.Close()
			return port
		}
	}
	t.Fatal("no port free for TCP and UDP on 127.0.0.1")
	return 0
}

// poolProgram opens a real socket on 127.0.0.1 and names it as a packet's source: a program behind
// the tun, as the flow table sees it.
func poolProgram(t *testing.T) xnet.Destination {
	t.Helper()
	conn := poolLoopback(t)
	t.Cleanup(func() { conn.Close() })
	return xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port))
}

func poolWait(t *testing.T, what string, within time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Errorf("never happened within %v: %s", within, what)
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// ---- Fake DNS: every name travels in a flow of its own ------------------------------------------

// Two names of fake DNS, one program socket, one route. The client sniffs the flows of its tun by the
// pool address (fakedns) and routes each by its name; the outbound resolves the name (targetStrategy)
// and puts the result in place of the pool address of the flow's FIRST destination alone
// (buf.EndpointOverrideReader). A second name in the same flow would leave with its pool address as it
// is, an address no exit knows; and a proxy server routes a whole association by its first
// destination and answers every datagram of it as the first request (proxy/socks/server.go), so the
// second name's datagram would come out of the first name's exit and its answer would seem to come
// from the first name's address. With a flow for each name, the datagrams, their exits and their
// answers stay apart.
//
// The proxy server routes by address: 203.0.113.1, what one.example resolves to, out of exit 1,
// 203.0.113.2 out of exit 2, anything else out of `stray`, where a flow that left with the pool address
// itself would end up. Every exit is a freedom redirected to an echo on 127.0.0.1, so nothing leaves
// the machine; dns.hosts keeps the names from the system resolver.
//
// The pool is the product's, 198.19.0.0/17 (poolLabPrivateNetworks). The port is neither 53 nor 443,
// which a VLESS client carries another way (proxy/vless/outbound).

// poolLabSniffing is the sniffing of the client's tun inbound for fake DNS: the name fakedns finds
// replaces the pool address (routeOnly off), except for the private networks, whose rows are written
// by address.
func poolLabSniffing(t *testing.T) session.SniffingRequest {
	t.Helper()
	config, err := (&conf.SniffingConfig{
		Enabled:      true,
		DestOverride: conf.StringList{"fakedns"},
		MetadataOnly: true,
		RouteOnly:    false,
		IPsExcluded:  poolLabPrivateNetworks,
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	request, err := proxyman.BuildSniffingRequest(config)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type poolReply struct {
	data string
	from xnet.Destination // whom the program is shown it come from
}

type poolLab struct {
	engine       *core.Instance // the client's
	exit1, exit2 *poolEcho      // the echoes behind the proxy server's exits for the two names
	stray, lan   *poolEcho      // behind its exit for any other address; behind the client's direct
	flows        *tun.UDPFlowsForTest

	mu      sync.Mutex
	replies []poolReply // what the program got, in order
}

// newPoolLab starts the proxy server (SOCKS5 or VLESS, as `transport` says), the client engine with
// fake DNS, and the tun inbound's UDP flow table on a handler of that engine, built as the bridge
// builds it (NewUDPFlowsForTest).
func newPoolLab(t *testing.T, transport string) *poolLab {
	t.Helper()
	lab := &poolLab{exit1: newPoolEcho(t), exit2: newPoolEcho(t), stray: newPoolEcho(t), lan: newPoolEcho(t)}
	serverPort := poolFreePort(t)
	var serverIn, clientOut string
	switch transport {
	case "socks":
		serverIn = fmt.Sprintf(`{"tag":"proxy-in","listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}`, serverPort)
		clientOut = fmt.Sprintf(`{"tag":"proxy-udp","protocol":"socks","targetStrategy":"ForceIPv4","settings":{"servers":[{"address":"127.0.0.1","port":%d}]}}`, serverPort)
	case "vless":
		// No TLS: a VLESS client allows that to a private address.
		serverIn = fmt.Sprintf(`{"tag":"proxy-in","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"}}`, serverPort, poolLabUUID)
		clientOut = fmt.Sprintf(`{"tag":"proxy-udp","protocol":"vless","targetStrategy":"ForceIPv4","settings":{"address":"127.0.0.1","port":%d,"id":"%s","encryption":"none"}}`, serverPort, poolLabUUID)
	default:
		t.Fatalf("unknown transport %q", transport)
	}
	// Every freedom here, the client's direct one too, lets loopback through and blocks the rest
	// (finalRules). For a vless inbound freedom cuts private addresses off by default, and these exits
	// are redirected to 127.0.0.1; the rules are checked after the redirect, and should a change to
	// freedom ever drop it, they keep the lab on the machine.
	startPoolEngine(t, fmt.Sprintf(`{"log":{"loglevel":"none"},
	  "inbounds":[%s],
	  "outbounds":[
	    {"tag":"exit1","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]},{"action":"block"}]}},
	    {"tag":"exit2","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]},{"action":"block"}]}},
	    {"tag":"stray","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]},{"action":"block"}]}}],
	  "routing":{"rules":[
	    {"type":"field","ip":["203.0.113.1/32"],"outboundTag":"exit1"},
	    {"type":"field","ip":["203.0.113.2/32"],"outboundTag":"exit2"},
	    {"type":"field","network":"tcp,udp","outboundTag":"stray"}]}}`,
		serverIn, lab.exit1.port(), lab.exit2.port(), lab.stray.port()))
	lab.engine = startPoolEngine(t, fmt.Sprintf(`{"log":{"loglevel":"none"},
	  "fakeDns":{"ipPool":"%s","poolSize":16384},
	  "dns":{"hosts":{"one.example":"203.0.113.1","two.example":"203.0.113.2"}},
	  "outbounds":[%s,
	    {"tag":"direct","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]},{"action":"block"}]}}],
	  "routing":{"domainStrategy":"AsIs","rules":[
	    {"type":"field","ip":["%s"],"outboundTag":"direct","ruleTag":"bypass:lan"},
	    {"type":"field","network":"udp","outboundTag":"proxy-udp","ruleTag":"main:udp"}]}}`,
		poolLabPool, clientOut, lab.lan.port(), strings.Join(poolLabPrivateNetworks, `","`)))

	object, err := core.CreateObject(lab.engine, &tun.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := object.(*tun.Handler)
	handler.SetTagForTest("tun")
	handler.SetSniffingForTest(poolLabSniffing(t))
	lab.flows = tun.NewUDPFlowsForTest(handler, func(data []byte, from, _ xnet.Destination) error {
		lab.mu.Lock()
		defer lab.mu.Unlock()
		lab.replies = append(lab.replies, poolReply{data: string(data), from: from})
		return nil
	})
	return lab
}

// poolAddress is the pool address the engine's fake DNS gives a name, as a resolver would hand it to
// a program, with the lab's port.
func (l *poolLab) poolAddress(t *testing.T, name string) xnet.Destination {
	t.Helper()
	engine, ok := l.engine.GetFeature((*dns.FakeDNSEngine)(nil)).(dns.FakeDNSEngine)
	if !ok {
		t.Fatal("the client engine has no fake DNS")
	}
	addresses := engine.GetFakeIPForDomain(name)
	if len(addresses) != 1 {
		t.Fatalf("%d fake addresses for %s, want 1", len(addresses), name)
	}
	return xnet.UDPDestination(addresses[0], poolLabPort)
}

func (l *poolLab) answers() []poolReply {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.replies)
}

// Two rounds of a datagram to each of two names from one socket. Each name's datagrams reach the exit
// of its own address and no other, nothing reaches `stray` or the client's direct, the answers come
// from the pool address the datagram went to, and the table holds one flow for each name.
func TestUDPFlowRulesEveryFakeDNSNameTravelsInAFlowOfItsOwn(t *testing.T) {
	poolLabRun(t, "socks")
}

// The same over VLESS, and the guard of XUDP's global ID. A VLESS client sends UDP through XUDP: one
// mux session in the connection of the flow, which the server dispatches by the session's first
// destination (common/mux/server.go), the flow's first name again. xudp.GetGlobalID names the tun
// inbound, so every flow of a source would get one global ID, and a server that meets an ID again
// hands the new flow the session of the old one, with the old one's destination: the second name
// would use the first name's session, exit and answers, whatever the table does. The flows of this
// inbound get no ID, because their context holds no "cone" flag of the engine (which
// xudp.GetGlobalID asks for); if that ever changes, this test turns red.
//
// The server's freedom lets loopback through (finalRules): for a vless inbound it cuts private
// addresses off by default, and the exits here are on 127.0.0.1.
func TestUDPFlowRulesEveryFakeDNSNameTravelsInAFlowOfItsOwnOverVLESS(t *testing.T) {
	poolLabRun(t, "vless")
}

func poolLabRun(t *testing.T, transport string) {
	lab := newPoolLab(t, transport)
	source := poolProgram(t)
	one, two := lab.poolAddress(t, "one.example"), lab.poolAddress(t, "two.example")

	for round := 1; round <= 2; round++ {
		lab.flows.HandlePacket(source, one, []byte(fmt.Sprintf("one-%d", round)))
		lab.flows.HandlePacket(source, two, []byte(fmt.Sprintf("two-%d", round)))
		if !poolWait(t, fmt.Sprintf("round %d: both names are answered", round), 5*time.Second, func() bool { return len(lab.answers()) == 2*round }) {
			break
		}
	}
	time.Sleep(300 * time.Millisecond) // anything still on its way arrives

	if got := lab.exit1.payloads(); !slices.Equal(got, []string{"one-1", "one-2"}) {
		t.Errorf("exit 1 carried %q; want name one's datagrams alone, one-1 and one-2", got)
	}
	if got := lab.exit2.payloads(); !slices.Equal(got, []string{"two-1", "two-2"}) {
		t.Errorf("exit 2 carried %q; want name two's datagrams alone, two-1 and two-2", got)
	}
	if got := lab.stray.payloads(); len(got) != 0 {
		t.Errorf("the proxy's exit for other addresses carried %q: a datagram left with an address no name stands for", got)
	}
	if got := lab.lan.payloads(); len(got) != 0 {
		t.Errorf("direct carried %q: a datagram to the pool was taken for a local address", got)
	}
	for _, answer := range lab.answers() {
		want := one
		if strings.HasPrefix(answer.data, "two-") {
			want = two
		}
		if answer.from != want {
			t.Errorf("the answer %q appears to come from %v, want %v", answer.data, answer.from, want)
		}
	}
	if n := lab.flows.FlowCount(); n != 2 {
		t.Errorf("the table holds %d flows, want 2: one for each name", n)
	}
}
