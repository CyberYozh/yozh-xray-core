package tun_test

// A tun UDP socket's datagrams against a rule set of the shape a whole-system client uses: DNS,
// local noise and multicast first; then the addresses that must bypass the tunnel (private
// networks, the proxy server itself, a direct list); then one row for all other UDP — through the
// proxy, or blocked when the proxy carries no UDP — and one for TCP. The first matching row wins,
// and the bypass rows come before the UDP row on purpose.
//
// The inbound keys a UDP flow by its source socket, and the flow is routed once, by its first
// datagram. When that flow also carried the socket's later datagrams, to any address, a socket
// whose first datagram went to a bypassed address sent everything after it out of the direct
// outbound, with the machine's own address, past the UDP row. These tests pin every destination of
// a socket to its own route; another socket is the control, routed by the rows from its first
// datagram.
//
// The client sniffs its tun flows (http, tls, quic) and routes them by the name it finds, except
// for the addresses its bypass rows are written for (ipsExcluded): the tests run with that sniffing
// too, and with a name on the direct list, which a sniffed flow can take while its address would be
// routed elsewhere.
//
// Nothing leaves the machine. "direct" is a freedom redirected to a sink on 127.0.0.1 — the local
// network, and the machine's own interface for anything that would leak — and "proxy" is a SOCKS5
// outbound to a second engine whose freedom is redirected to another sink. The public addresses
// below are only what the rules see; nothing dials them.

import (
	"encoding/hex"
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
	rulesProxyServer = "1.2.3.4"  // the proxy server as the rules see it: bypass:proxy
	rulesDirectList  = "1.2.3.20" // an address on a direct list: list:direct
	rulesPublicA     = "1.2.3.30" // addresses no bypass row covers: the UDP row decides
	rulesPublicB     = "1.2.3.31"
	rulesQUICName    = "www.google.com" // the name rulesQUICInitial carries
	rulesOtherName   = "direct.example" // a name on the direct list that no datagram here carries
)

// rulesQUICInitial is a client's QUIC Initial whose ClientHello names rulesQUICName: the QUIC
// sniffer's own test packet (common/protocol/quic/sniff_test.go, TestSniffQUIC).
const rulesQUICInitial = "cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b"

// rulesSplitInitials are a client's first two QUIC Initials, 1250 bytes each, whose ClientHello for
// rulesSplitName spans both: the QUIC sniffer's own test packets
// (common/protocol/quic/sniff_test.go, TestSniffQUICIncompleteServerName). The first alone cannot
// name the host.
const (
	rulesSplitName     = "play.google.com"
	rulesSplitInitials = "ca0000000108d799f48baf472fc3004047005411dcdaa24bd4c3cdbef653940a1ea0a671bb8c23222a8502bfcbd0a335af016df330b1190e4b1efd420aa82c4414a7dfd7b1aa63aa7bd0269ec8ed0d24895a467b737fcc514488a8142241b81c4952fb32e9f123f3f8d1be9eecc1340d7fa747c6f4838810209d51ad453fcec084ffaa382f9fed010a0585f8ce73c36dc6c628df940f72fb5b8e3e06f4612128d3b8f87725770d81305489a3a23cd443fcc668fece0ec9a909c82cfdb66819ce031422c3edd49ea72b6216efb940b8c186e2510b0f93d4cf3b6434ed9f5817c5a5a19fa861d24883bd48ba296df81e887fcb9ef18013ab1070df268049f3d35e8ddfffd2b100e4eb687176a02e7975085caa138e9df7cb6f9862356faafba3300f586df09af3b4e3eec15b6d1f14b34fe4eeb8e762ff482f3b7b0595c16d3eb20cf9c892b3f7c6449e51ffa33f3dc877d32e572e10ba4d5a320117110b150bec4a9434103de963aa2de1b22eaa992b59a8583c7a2d4e5743ef98a1b1f5f4aaeb2b49dbe441c331e7cb028e70432ce0890f78d40671f13d5feccc4ab264ae903affaa951897128d598ed8e8542294aa03abb0a2a7ec970ab874387b8777827c4847bb29ff93d0427c1fcc581407465611e4400bfeab39de4c4f65572365156421503706d66138317e514214db27303ad8b5b17eb443e959faad1ccb3d3def5f3843b241dd9a60378cd907a02cc5c6e8527715c7734079cf9143586ed471587690816133fa8f09b8421f2de6ff1f5cecc134ac404e53a367b57fd4f3c85fe7e121e7094fbf93c06d427cec30cd519ee43a6018a8bb8717c05d7660b379101a182bfd3018d485d5b46e81d39445ccd4d8baefdd7590e664f2289f11bbad3d35ea6d70e157aaa7f9e91a692794b85c5b86db33863151468d32792ecfdb2aec52784ded5aa431fa9a7337ddd9e95313a897fe5ca6ef3c7e0cf3d41f7f104506f8695f2ba307715022e5e98472d6ff24125004d14db2c7a4cc71ca39a9874bfb93b64dd54ef451097059bbdfa96aca6c6c01e1f000b8d35bdead1502874e5d80ac00a79593b6d7e2fbee406c2212b4abd7b7e9f0037518de232cd6559443f4e3f0f03c17cef616a74992f65754bb6699b08c0eb2ec59508086e496e070c6239a73f11a9d14a727b10188ca97ebf04851fa475ed1774836a94cfb6543c33888dfc250100e9992b0cca8bd27ae8552541f1b3d81546f15b740e4f07b41af864769fe17290eb7076c0c1f938ce56a45ead6deb6c89164f829543414a1b8cd2361c3d9b22cf85d4ad0d4221dcc87533506e32c1cfdc8240636b669f97f7c6e150ea3753fcb63a7b9eedb5615b257651e090b567a20fdc5c167ad58fa940985572db004db2b14709a6663c1fb79dc045e45cb7228f11eab4c60a48fffc702cd74dcf5aabded8355a5ae1a5e6325a3afff608e53af3aa944437139c438e6200c75bb27c8a8ce7ce9f9ec9723c4423e9e49c807b12484783ed79fc501b544f03e4b29bdf0c74eb055dbac9b78fe87a66efc819f9d2ea637dd478b920b7196232b970ed092050ba0621329aa2b3e26184176137a9c6283e4cc2c03c07e28d2da7b0485da51f131686f4dd6b23735c66316142f48781885c35c9940054a4b9187a20914bedd1c48e94af358994da5c6060dd224b0ba84ddd5e95f395fe941d464e2cccd857a180de756d32407540c3611b649c7a71cbf5a492bf5c8d4e112a743498ce83ea3e94bcaa6c00000000108d799f48baf472fc3004047005411dcdaa24bd4c3cdbef653940a1ea0a671bb8c23222a8502bfcbd0a335af016df330b1190e4b1efd420aa82c4414a7dfd7b1aa63aa7bd0269ec8ed0d24895a467b737fcc514488e7151df796764293639665547941eaaa7d83dfc9d42952583a821611921cba9e0276f9244f197e011b6c2d898255802c81c8792dd68d03cd8982ee6146c8734814e9640e0999312f97e898db60642ceca21700be9e698b5e577062148d1ac840e737f7bc4f18f9ffd13e656fca1517c96d0e0c607b67d7e75795f62131255b44c2178d896192348d5f053060fa21c855236401e853e435fbc71a428c8e126cd8393cb860193fd6304d9576e8a8ce7f6959739afa7d7ffaf86516afb061ade1eef603e8e5c66f002cacbef25546e84b59be707c547837f7b49471a59325ad58a4f189a525a3a354a4be5ffd3db34ce0585ec470f78f0ff6eb807989d5998e2fccc80bd651de654da3581b6c8a858b56c4df47c3041c50d74f0b3a3a5a325882cd356d0c46d6db74559cef934a1655c65a06daff218244f5f4e95b96794e45d371a03afee2c89768fe3d7bc134844f45440620a88d6ddb5d07b7f6c9b2adfbf5743c5c586520504febf14ee4b216f8186ee1bf9802ccebd4dac519bd337a554940a3873cd21ef32f3d4d4fdfd3eaabb172b5314490b3587a9ca2dc12637fa80dcd526859bb83d54f67dedeb173470e052beec9edba4b41444d31253accb3381237179a5381d437fc4d47c0a82f1c9da8c76ad3eee9417bf69acb8d530ac824e65d796b84bee40b14daa9e80c11e466f93233e1768ecc6c0237e71b901f1faa093bbd9e5324b2a160d02f09d4590392279a15c73edc4d1d7501ebad992fc8f1c9dce96c190879225dbbb09d20532f9dcbb845e3484c87cb8c3b06fe892b07bdc60926e3d4b5c9024acde5abed0a72686d546da535a2122cfd6d6488a491dc9612b90f3f6709835e83f59fd612c2259c3ac944fdae87ffd744176a92fbea1efd037565a39d5bc38991cfe6617135b43cd6c6484a3b228e10d3f8184227a7ee63121be20f099c4264461d52aecf4b8ee1a4d0ec41717f9a68e1394544cf3be0a3a171ece35c879b67afdaac49c12731e6dc5ccaa49fa72610901036a7f0752951077cd9f1d77eb6e4f12c16dab08e1a9655fda3ba0e80c34c767f40e61491f706ab9d1b50f48273ca4e37708d075909a3e2c4b173510114d8377b5300994f9a4f794db2781b98c2e9d0056fdbe87b249beb3e7301c86efe6b32242b4c7fabef280a1ca7bdd6abb38624cbebb01b6b75b07d0cd9090b2c296d0e330b9008788dd6f7e1af1dd63b02408f1a67b57be3316152270bf90c36e9f74322c9caba5adab3309e5bd7c44d3c2ac77329e167dafda7395e37313723fb550a6ab96729a9fa8f9e4a3e5957bffa3302617d48fd38196635309928c491ca974a112768de16043fc618001780b49a0bac2ea9fc2607ebd1f25b8ef65a6cab42d16c9184e23af496ac5cfab274d9557006d9c52bb56cd8c019ddf085f260a0582ef465c73f97fedc02271dda53eec20e6aa50503357ed1847f7d976899cb24e5dd42dd87ae48db3c9335b38957fc0f86a6ceee590b1cbee41fc6ace3189886bd86f9b082e66fb263f1a98dd8e564bff9ec412ae79e29fd519ac96e9c5b446b436b78a6ca555c496ca5c5e73c2c1c5837b13f7a953d57738440d4ed60efd4701bbbbcad79e1697b5724695f52dab8bce02e7f"
)

// rulesPrivateNetworks: the bypass:lan row — loopback, private, link-local, CGNAT, benchmarking and
// documentation ranges.
var rulesPrivateNetworks = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"::1/128", "fc00::/7", "fe80::/10",
}

// rulesClientConfig: the rows in their order, with main:udp sending the rest of UDP to mainUDP and
// directName on the direct list.
func rulesClientConfig(mainUDP, directName string, socksPort, lanPort int) string {
	return fmt.Sprintf(`{"log":{"loglevel":"none"},
	  "outbounds":[
	    {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":%d}]}},
	    {"tag":"dns-out","protocol":"dns"},
	    {"tag":"direct","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d"}},
	    {"tag":"block","protocol":"blackhole"}],
	  "routing":{"domainStrategy":"AsIs","rules":[
	    {"type":"field","inboundTag":["dns-app"],"outboundTag":"proxy","ruleTag":"sys:dns-cascade"},
	    {"type":"field","network":"tcp,udp","port":"53","outboundTag":"dns-out","ruleTag":"sys:dns"},
	    {"type":"field","network":"udp","port":"67,68,123,135,137-139,1900,3702,5353,5355","outboundTag":"block","ruleTag":"sys:lan-noise"},
	    {"type":"field","ip":["224.0.0.0/3","ff00::/8"],"outboundTag":"block","ruleTag":"sys:multicast"},
	    {"type":"field","ip":["%s"],"outboundTag":"direct","ruleTag":"bypass:lan"},
	    {"type":"field","ip":["::/0"],"outboundTag":"block","ruleTag":"sys:ipv6"},
	    {"type":"field","ip":["%s/32"],"outboundTag":"direct","ruleTag":"bypass:proxy"},
	    {"type":"field","inboundTag":["tun"],"ip":["%s/32"],"outboundTag":"direct","ruleTag":"list:direct"},
	    {"type":"field","inboundTag":["tun"],"domain":["full:%s"],"outboundTag":"direct","ruleTag":"list:direct"},
	    {"type":"field","network":"udp","outboundTag":"%s","ruleTag":"main:udp"},
	    {"type":"field","network":"tcp","outboundTag":"proxy","ruleTag":"main:tcp"}]}}`,
		socksPort, lanPort, strings.Join(rulesPrivateNetworks, `","`), rulesProxyServer, rulesDirectList, directName, mainUDP)
}

// rulesClientSniffing: the client's sniffing block for its tun inbound: http, tls and quic, the
// sniffed name replacing the address (routeOnly false), except for the addresses of the bypass
// rows written by address, private networks and the proxy server.
func rulesClientSniffing(t *testing.T) session.SniffingRequest {
	t.Helper()
	config, err := (&conf.SniffingConfig{
		Enabled:      true,
		DestOverride: conf.StringList{"http", "tls", "quic"},
		RouteOnly:    false,
		IPsExcluded:  append(slices.Clone(rulesPrivateNetworks), rulesProxyServer+"/32"),
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

// rulesProxyConfig: the proxy server, a SOCKS5 inbound with UDP whose exit lands on a sink.
func rulesProxyConfig(socksPort, sinkPort int) string {
	return fmt.Sprintf(`{"log":{"loglevel":"none"},
	  "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],
	  "outbounds":[{"tag":"exit","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d"}}]}`, socksPort, sinkPort)
}

// rulesSink records the payload of every datagram that reaches it.
type rulesSink struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  []string
}

func newRulesSink(t *testing.T) *rulesSink {
	t.Helper()
	return newRulesSinkEchoing(t, false)
}

// newRulesEcho is a sink that sends every datagram back to where it came from.
func newRulesEcho(t *testing.T) *rulesSink {
	t.Helper()
	return newRulesSinkEchoing(t, true)
}

func newRulesSinkEchoing(t *testing.T, echo bool) *rulesSink {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sink := &rulesSink{conn: conn}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(b)
			if err != nil {
				return
			}
			sink.mu.Lock()
			sink.got = append(sink.got, string(b[:n]))
			sink.mu.Unlock()
			if echo {
				conn.WriteToUDP(b[:n], from)
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return sink
}

func (s *rulesSink) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *rulesSink) payloads() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.got)
}

func (s *rulesSink) has(payload string) bool { return slices.Contains(s.payloads(), payload) }

// count is how many datagrams with this payload reached the sink: copies of one Initial sent by two
// sockets look the same.
func (s *rulesSink) count(payload string) int {
	n := 0
	for _, got := range s.payloads() {
		if got == payload {
			n++
		}
	}
	return n
}

func rulesEngine(t *testing.T, config string) *core.Instance {
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

// rulesFreePort is a port free on 127.0.0.1 for TCP and UDP both, for the SOCKS5 server. It is
// looked for below the ephemeral range: Windows reserves blocks of that range per protocol
// (excludedportrange), so a port the system hands out for one protocol is often refused to the other.
func rulesFreePort(t *testing.T) int {
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

// rulesSource opens a real socket on 127.0.0.1 and names it as a packet's source: a program behind
// the tun, as the flow table sees it.
func rulesSource(t *testing.T) xnet.Destination {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return xnet.UDPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port))
}

func rulesWait(t *testing.T, what string, within time.Duration, cond func() bool) bool {
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

type rulesLab struct {
	lan     *rulesSink // everything "direct" carries
	proxied *rulesSink // everything the proxy server's exit carries
	flows   *tun.UDPFlowsForTest
}

// newRulesLab starts the proxy server and the client engine, and the client's tun UDP flow table
// on a handler tagged "tun", as the inbound is in the client's config; with the client's sniffing
// when `sniffing` is set, and directName on the direct list.
func newRulesLab(t *testing.T, mainUDP string, sniffing bool, directName string) *rulesLab {
	t.Helper()
	lab := &rulesLab{lan: newRulesSink(t), proxied: newRulesSink(t)}
	socksPort := rulesFreePort(t)
	rulesEngine(t, rulesProxyConfig(socksPort, lab.proxied.port()))
	client := rulesEngine(t, rulesClientConfig(mainUDP, directName, socksPort, lab.lan.port()))
	object, err := core.CreateObject(client, &tun.Config{})
	if err != nil {
		t.Fatal(err)
	}
	handler := object.(*tun.Handler)
	handler.SetTagForTest("tun")
	if sniffing {
		handler.SetSniffingForTest(rulesClientSniffing(t))
	}
	lab.flows = tun.NewUDPFlowsForTest(handler, func([]byte, xnet.Destination, xnet.Destination) error { return nil })
	return lab
}

func rulesDest(address string, port int) xnet.Destination {
	return xnet.UDPDestination(xnet.ParseAddress(address), xnet.Port(port))
}

// A socket's first datagram goes to an address a bypass row sends direct; its next datagrams go to
// public addresses, which main:udp blocks or sends through the proxy. Each must take main:udp, and
// the bypassed destination keeps going direct. Another socket, sending straight to a public
// address, is the control: the rows themselves route it right.
func TestUDPFlowRulesADirectFirstDatagramDoesNotTakeTheSocketPastMainUDP(t *testing.T) {
	rulesDirectFirstDatagram(t, false)
}

// The same with the client's sniffing: every flow is sniffed before it is routed and reports its
// route only then, and a datagram to a new destination waits for that report.
func TestUDPFlowRulesADirectFirstDatagramDoesNotTakeTheSocketPastMainUDPWithSniffing(t *testing.T) {
	rulesDirectFirstDatagram(t, true)
}

func rulesDirectFirstDatagram(t *testing.T, sniffing bool) {
	for _, mainUDP := range []string{"block", "proxy"} {
		for _, first := range []struct{ row, address string }{
			{"bypass:lan", "127.0.0.1"},
			{"bypass:proxy", rulesProxyServer},
			{"list:direct", rulesDirectList},
		} {
			t.Run("main:udp="+mainUDP+"/first="+first.row, func(t *testing.T) {
				lab := newRulesLab(t, mainUDP, sniffing, rulesOtherName)
				// "direct" lands on the LAN sink whatever the address; the port is the sink's own
				// only for the LAN address.
				firstDest := rulesDest(first.address, 40000)
				if first.row == "bypass:lan" {
					firstDest = rulesDest(first.address, lab.lan.port())
				}
				publicA, publicB := rulesDest(rulesPublicA, 40001), rulesDest(rulesPublicB, 40002)

				source := rulesSource(t)
				lab.flows.HandlePacket(source, firstDest, []byte("first"))
				if !rulesWait(t, "the first datagram goes direct ("+first.row+")", 3*time.Second, func() bool { return lab.lan.has("first") }) {
					return
				}
				lab.flows.HandlePacket(source, publicA, []byte("public-a"))
				lab.flows.HandlePacket(source, publicB, []byte("public-b"))
				lab.flows.HandlePacket(source, firstDest, []byte("first-again"))

				other := rulesSource(t)
				lab.flows.HandlePacket(other, publicA, []byte("other-public-a"))

				rulesWait(t, "the bypassed destination keeps going direct", 3*time.Second, func() bool { return lab.lan.has("first-again") })
				if mainUDP == "proxy" {
					for _, payload := range []string{"public-a", "public-b", "other-public-a"} {
						rulesWait(t, payload+" reaches the proxy", 3*time.Second, func() bool { return lab.proxied.has(payload) })
					}
				}
				// Anything still on its way arrives. Blocked datagrams leave no trace, so for them the
				// wait outlasts the 2 s a datagram may wait for its route (udpRouteWait): one parked
				// and then let into the direct flow would show here.
				settle := 300 * time.Millisecond
				if mainUDP == "block" {
					settle = 2500 * time.Millisecond
				}
				time.Sleep(settle)

				for _, payload := range []string{"public-a", "public-b"} {
					if lab.lan.has(payload) {
						t.Errorf("the socket's datagram %q to a public address left through direct, past main:udp=%s", payload, mainUDP)
					}
				}
				if lab.lan.has("other-public-a") {
					t.Errorf("control: another socket's datagram to a public address left through direct")
				}
				if mainUDP == "block" {
					if got := lab.proxied.payloads(); len(got) != 0 {
						t.Errorf("main:udp=block, yet the proxy carried %q", got)
					}
				}
				t.Logf("direct carried %q; the proxy carried %q", lab.lan.payloads(), lab.proxied.payloads())
			})
		}
	}
}

// A sniffed first datagram: the client's sniffing names the flow by its QUIC Initial, and the flow
// is routed by that name while its address alone would be routed elsewhere. The socket's datagrams
// to other destinations must take their own routes, not the route the name gave the flow.
//
// A name on the direct list: the Initial goes to a public address and leaves direct by its name.
// The socket's datagram to another public address must take main:udp; its next datagram to the
// Initial's own destination travels on with the Initial, direct.
//
// An address on the direct list: the Initial goes to an address on the direct list whose name the
// list does not hold, and the name replaces the address before the rows see it (ipsExcluded holds
// only the bypass rows' addresses), so the Initial takes main:udp. The socket's datagram to that
// address on another port is not sniffed and is routed by its address, direct; one to a public
// address takes main:udp.
func TestUDPFlowRulesASniffedFirstDatagramGivesItsRouteToNoOtherDestination(t *testing.T) {
	initial, err := hex.DecodeString(rulesQUICInitial)
	if err != nil {
		t.Fatal(err)
	}
	for _, mainUDP := range []string{"block", "proxy"} {
		for _, first := range []struct {
			name       string
			directName string           // the name on the direct list
			initialTo  xnet.Destination // where the Initial goes
			direct     xnet.Destination // the socket's destination that must leave direct
			byName     bool             // the Initial leaves direct by its name; else it takes main:udp
		}{
			{"name on the direct list", rulesQUICName, rulesDest(rulesPublicA, 443), rulesDest(rulesPublicA, 443), true},
			{"address on the direct list", rulesOtherName, rulesDest(rulesDirectList, 443), rulesDest(rulesDirectList, 40000), false},
		} {
			t.Run("main:udp="+mainUDP+"/"+first.name, func(t *testing.T) {
				lab := newRulesLab(t, mainUDP, true, first.directName)
				publicB := rulesDest(rulesPublicB, 40002)

				source := rulesSource(t)
				lab.flows.HandlePacket(source, first.initialTo, initial)
				// The case holds only if the flow's route is the one its name gave it.
				switch {
				case first.byName:
					if !rulesWait(t, "the Initial leaves direct by its name", 3*time.Second, func() bool { return lab.lan.has(string(initial)) }) {
						return
					}
				case mainUDP == "proxy":
					if !rulesWait(t, "the Initial takes main:udp by its name", 3*time.Second, func() bool { return lab.proxied.has(string(initial)) }) {
						return
					}
				}
				lab.flows.HandlePacket(source, publicB, []byte("public-b"))
				lab.flows.HandlePacket(source, first.direct, []byte("direct-again"))

				other := rulesSource(t)
				lab.flows.HandlePacket(other, publicB, []byte("other-public-b"))

				rulesWait(t, "the destination that must leave direct does", 3*time.Second, func() bool { return lab.lan.has("direct-again") })
				if mainUDP == "proxy" {
					for _, payload := range []string{"public-b", "other-public-b"} {
						rulesWait(t, payload+" reaches the proxy", 3*time.Second, func() bool { return lab.proxied.has(payload) })
					}
				}
				settle := 300 * time.Millisecond
				if mainUDP == "block" {
					settle = 2500 * time.Millisecond
				}
				time.Sleep(settle)

				if lab.lan.has("public-b") {
					t.Errorf("the socket's datagram to a public address left through direct, past main:udp=%s", mainUDP)
				}
				if lab.lan.has("other-public-b") {
					t.Errorf("control: another socket's datagram to a public address left through direct")
				}
				if !first.byName && lab.lan.has(string(initial)) {
					t.Errorf("the Initial left through direct: its name did not take it off the address row")
				}
				if mainUDP == "block" {
					if got := lab.proxied.payloads(); len(got) != 0 {
						t.Errorf("main:udp=block, yet the proxy carried %q", rulesReadable(got, initial))
					}
				}
				t.Logf("direct carried %q; the proxy carried %q", rulesReadable(lab.lan.payloads(), initial), rulesReadable(lab.proxied.payloads(), initial))
			})
		}
	}
}

// A later datagram of a socket is routed by what it carries, as it would be as the first packet of
// a flow of its own: the client's sniffing names a QUIC Initial by its server name, and the name
// decides. The socket's first datagram is plain and takes the route of its address; the Initial
// that follows, to another destination, must not ride that flow when its name sends it elsewhere.
//
// A name on the direct list: the first datagram goes to a public address and takes main:udp; the
// Initial to another public address leaves direct by its name, and none of it reaches the proxy.
//
// An address on the direct list, its name not on it: the first datagram goes to that address on
// another port and leaves direct; the Initial to the address takes main:udp by its name (ipsExcluded
// holds only the bypass rows' addresses), and does not leave through the machine's own interface.
//
// The control, sent first, is a fresh socket whose first datagram is a copy of the same Initial to
// the same destination. Each datagram gets its own copy of the bytes: a sniffer decrypts in place.
func TestUDPFlowRulesALaterDatagramIsRoutedByTheNameItCarries(t *testing.T) {
	initial, err := hex.DecodeString(rulesQUICInitial)
	if err != nil {
		t.Fatal(err)
	}
	want := string(initial)
	for _, mainUDP := range []string{"block", "proxy"} {
		for _, c := range []struct {
			name        string
			directName  string           // the name on the direct list
			first       xnet.Destination // where the socket's first, plain datagram goes
			firstDirect bool             // it leaves direct; else it takes main:udp
			initialTo   xnet.Destination // where the Initial goes
			byName      bool             // the Initial leaves direct by its name; else it takes main:udp
		}{
			{"name on the direct list", rulesQUICName, rulesDest(rulesPublicA, 40001), false, rulesDest(rulesPublicB, 443), true},
			{"address on the direct list", rulesOtherName, rulesDest(rulesDirectList, 40000), true, rulesDest(rulesDirectList, 443), false},
		} {
			t.Run("main:udp="+mainUDP+"/"+c.name, func(t *testing.T) {
				lab := newRulesLab(t, mainUDP, true, c.directName)

				source := rulesSource(t)
				lab.flows.HandlePacket(source, c.first, []byte("first"))
				switch {
				case c.firstDirect:
					if !rulesWait(t, "the first datagram leaves direct by its address", 3*time.Second, func() bool { return lab.lan.has("first") }) {
						return
					}
				case mainUDP == "proxy":
					if !rulesWait(t, "the first datagram takes main:udp", 3*time.Second, func() bool { return lab.proxied.has("first") }) {
						return
					}
				default:
					time.Sleep(300 * time.Millisecond) // blocked, so no trace: its flow is routed meanwhile
				}

				other := rulesSource(t)
				lab.flows.HandlePacket(other, c.initialTo, slices.Clone(initial))
				switch {
				case c.byName:
					if !rulesWait(t, "control: a fresh socket's Initial leaves direct by its name", 3*time.Second, func() bool { return lab.lan.count(want) == 1 }) {
						return
					}
				case mainUDP == "proxy":
					if !rulesWait(t, "control: a fresh socket's Initial takes main:udp by its name", 3*time.Second, func() bool { return lab.proxied.count(want) == 1 }) {
						return
					}
				}

				lab.flows.HandlePacket(source, c.initialTo, slices.Clone(initial))
				switch {
				case c.byName:
					rulesWait(t, "the socket's Initial leaves direct by its name, as the control's did", 3*time.Second, func() bool { return lab.lan.count(want) == 2 })
				case mainUDP == "proxy":
					rulesWait(t, "the socket's Initial takes main:udp by its name, as the control's did", 3*time.Second, func() bool { return lab.proxied.count(want) == 2 })
				}
				settle := 300 * time.Millisecond
				if mainUDP == "block" {
					settle = 2500 * time.Millisecond
				}
				time.Sleep(settle)

				if n := lab.proxied.count(want); c.byName && n != 0 {
					t.Errorf("the Initial named on the direct list reached the proxy %d time(s): it rode the socket's main:udp flow", n)
				}
				if n := lab.lan.count(want); !c.byName && n != 0 {
					t.Errorf("the Initial left through direct %d time(s): it rode the socket's direct flow, past its name's row", n)
				}
				// Each side carried exactly what the rows send it, in the order sent: the first
				// datagram, then the control's Initial and the socket's. Checked whole, so that an
				// Initial that left in any other form (a sniffer decrypting the program's bytes in
				// place, say) shows as well as an exact copy does.
				var wantLAN, wantProxied []string
				if c.firstDirect {
					wantLAN = append(wantLAN, "first")
				} else if mainUDP == "proxy" {
					wantProxied = append(wantProxied, "first")
				}
				for range 2 {
					if c.byName {
						wantLAN = append(wantLAN, want)
					} else if mainUDP == "proxy" {
						wantProxied = append(wantProxied, want)
					}
				}
				if got := lab.lan.payloads(); !slices.Equal(got, wantLAN) {
					t.Errorf("direct carried %q, want %q", rulesReadable(got, initial), rulesReadable(wantLAN, initial))
				}
				if got := lab.proxied.payloads(); !slices.Equal(got, wantProxied) {
					t.Errorf("the proxy carried %q, want %q", rulesReadable(got, initial), rulesReadable(wantProxied, initial))
				}
				t.Logf("direct carried %q; the proxy carried %q", rulesReadable(lab.lan.payloads(), initial), rulesReadable(lab.proxied.payloads(), initial))
			})
		}
	}
}

// RouteOf's answer for a datagram is the route the dispatcher gives the same datagram as the first
// packet of a flow of its own: the same rows, the same sniffing. Each row sends the datagram from a
// fresh socket, whose flow reports where it went, and asks another socket's RouteOf about the same
// bytes and destination. The rows' own answer is checked too, so that the two cannot agree on a
// wrong one.
func TestUDPFlowRulesRouteOfIsTheRouteOfTheDatagramAsAFlowsFirstPacket(t *testing.T) {
	initial, err := hex.DecodeString(rulesQUICInitial)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("plain")
	for _, directName := range []string{rulesQUICName, rulesOtherName} {
		t.Run("direct list names "+directName, func(t *testing.T) {
			lab := newRulesLab(t, "proxy", true, directName)
			byName := "proxy" // where the Initial's name sends it
			if directName == rulesQUICName {
				byName = "direct"
			}

			asker := rulesSource(t)
			lab.flows.HandlePacket(asker, rulesDest("127.0.0.1", lab.lan.port()), []byte("asker"))
			var routeOf func(xnet.Destination, [][]byte) (string, error)
			if !rulesWait(t, "the asking socket's flow is routed", 3*time.Second, func() bool {
				_, routeOf, _ = lab.flows.SettledRouteForTest(asker)
				return routeOf != nil
			}) {
				return
			}

			for _, c := range []struct {
				name    string
				to      xnet.Destination
				payload []byte
				want    string // the rows' answer
			}{
				{"plain to a public address", rulesDest(rulesPublicA, 40001), plain, "proxy"},
				{"plain to the direct list's address", rulesDest(rulesDirectList, 40000), plain, "direct"},
				{"plain to a LAN noise port", rulesDest(rulesPublicA, 123), plain, "block"},
				{"Initial to a public address", rulesDest(rulesPublicA, 443), initial, byName},
				{"Initial to the direct list's address", rulesDest(rulesDirectList, 443), initial, byName},
				{"Initial to an excluded address", rulesDest(rulesProxyServer, 443), initial, "direct"},
			} {
				first := rulesSource(t)
				lab.flows.HandlePacket(first, c.to, slices.Clone(c.payload))
				var went string
				if !rulesWait(t, c.name+": the fresh socket's flow is routed", 3*time.Second, func() bool {
					var ok bool
					went, _, ok = lab.flows.SettledRouteForTest(first)
					return ok
				}) {
					continue
				}
				if tag, err := routeOf(c.to, [][]byte{slices.Clone(c.payload)}); tag != went || err != nil {
					t.Errorf("%s: RouteOf answers (%q, %v); as a flow's first packet it went to %q", c.name, tag, err, went)
				}
				if went != c.want {
					t.Errorf("%s: went to %q, the rows say %q", c.name, went, c.want)
				}
			}
		})
	}
}

// rulesSplitHalves are the two datagrams of rulesSplitInitials.
func rulesSplitHalves(t *testing.T) (first, rest []byte) {
	t.Helper()
	both, err := hex.DecodeString(rulesSplitInitials)
	if err != nil {
		t.Fatal(err)
	}
	return both[:1250], both[1250:]
}

// rulesPeer is a public address no bypass row covers, like rulesPublicA, on the QUIC port: one of a
// socket's many peers.
func rulesPeer(i int) xnet.Destination { return rulesDest("1.2.3."+strconv.Itoa(40+i), 443) }

// One socket sends QUIC Initials to many peers, each ClientHello split over two datagrams (post-
// quantum key shares make it the usual case; one socket for many peers is what QUIC stacks built for
// peer-to-peer do). The first half alone cannot tell its route and waits for the second; together
// they are routed by the name they carry, into the socket's flow that went there. The socket holds
// one flow per route however many peers it has, as it does for plain datagrams: through the proxy,
// every flow is a UDP association of its own.
func TestUDPFlowRulesAClientHelloSplitOverTwoDatagramsTakesTheFlowOfItsRoute(t *testing.T) {
	first, rest := rulesSplitHalves(t)
	const peers = 4
	for _, c := range []struct {
		name       string
		directName string // the name on the direct list
		byName     bool   // the Initials leave direct by their name; else they take main:udp
	}{
		{"name on the direct list", rulesSplitName, true},
		{"name not on the direct list", rulesOtherName, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			lab := newRulesLab(t, "proxy", true, c.directName)
			source := rulesSource(t)
			lab.flows.HandlePacket(source, rulesDest(rulesPublicA, 40001), []byte("first"))
			if !rulesWait(t, "the first datagram takes main:udp", 3*time.Second, func() bool { return lab.proxied.has("first") }) {
				return
			}
			for i := range peers {
				lab.flows.HandlePacket(source, rulesPeer(i), slices.Clone(first))
				lab.flows.HandlePacket(source, rulesPeer(i), slices.Clone(rest))
			}

			wantLAN, wantProxied, wantFlows := []string{}, []string{"first"}, 1
			for range peers {
				if c.byName {
					wantLAN = append(wantLAN, string(first), string(rest))
				} else {
					wantProxied = append(wantProxied, string(first), string(rest))
				}
			}
			if c.byName {
				wantFlows = 2 // main:udp's and direct's
			}
			rulesWait(t, "every half reaches the side its name is routed to", 3*time.Second, func() bool {
				return len(lab.lan.payloads()) == len(wantLAN) && len(lab.proxied.payloads()) == len(wantProxied)
			})
			time.Sleep(300 * time.Millisecond)
			readable := func(got []string) []string {
				out := make([]string, len(got))
				for i, payload := range got {
					switch payload {
					case string(first):
						payload = "<first half>"
					case string(rest):
						payload = "<second half>"
					}
					out[i] = payload
				}
				return out
			}
			// Every peer's halves are the same bytes, so each side is compared as a whole, in any order.
			sameHalves := func(got, want []string) bool {
				return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
			}
			if got := lab.lan.payloads(); !sameHalves(got, wantLAN) {
				t.Errorf("direct carried %q, want %q", readable(got), readable(wantLAN))
			}
			if got := lab.proxied.payloads(); !sameHalves(got, wantProxied) {
				t.Errorf("the proxy carried %q, want %q", readable(got), readable(wantProxied))
			}
			if n := lab.flows.FlowCount(); n != wantFlows {
				t.Errorf("the socket holds %d flows for %d peers, want %d: one per route", n, peers, wantFlows)
			}
		})
	}
}

// The first halves of ClientHellos whose rest never comes wait as long as the dispatcher's sniffing
// would for a flow's next packet, and are then routed as such a flow is: with nothing sniffed, by
// their address. Meanwhile the socket's next new destination is routed at once — not behind them,
// one sniffing wait each — and none of them opens a flow of its own.
func TestUDPFlowRulesDatagramsThatCannotTellTheirRouteHoldUpNothing(t *testing.T) {
	first, _ := rulesSplitHalves(t)
	const peers = 4
	lab := newRulesLab(t, "proxy", true, rulesSplitName)
	source := rulesSource(t)
	lab.flows.HandlePacket(source, rulesDest(rulesPublicA, 40001), []byte("first"))
	if !rulesWait(t, "the first datagram takes main:udp", 3*time.Second, func() bool { return lab.proxied.has("first") }) {
		return
	}
	start := time.Now()
	for i := range peers {
		lab.flows.HandlePacket(source, rulesPeer(i), slices.Clone(first))
	}
	lab.flows.HandlePacket(source, rulesDest(rulesPublicB, 40002), []byte("next"))
	var tookNext time.Duration
	rulesWait(t, "the next destination reaches the proxy", 3*time.Second, func() bool {
		tookNext = time.Since(start)
		return lab.proxied.has("next")
	})
	rulesWait(t, "every first half reaches the proxy by its address", 3*time.Second, func() bool { return lab.proxied.count(string(first)) == peers })
	time.Sleep(300 * time.Millisecond)

	got := lab.proxied.payloads()
	if next := slices.Index(got, "next"); next < 0 || slices.Contains(got[:next], string(first)) {
		t.Errorf("the next destination reached the proxy after a first half: it waited behind them (%v)", tookNext)
	}
	if n := lab.flows.FlowCount(); n != 1 {
		t.Errorf("the socket holds %d flows, want 1: the first halves opened flows of their own", n)
	}
	if got := lab.lan.payloads(); len(got) != 0 {
		t.Errorf("direct carried %d datagram(s); a first half alone names nothing", len(got))
	}
	t.Logf("the next destination reached the proxy after %v", tookNext)
}

// rulesReadable names the Initial in a list of payloads instead of printing its bytes.
func rulesReadable(payloads []string, initial []byte) []string {
	out := make([]string, len(payloads))
	for i, payload := range payloads {
		if payload == string(initial) {
			payload = "<initial>"
		}
		out[i] = payload
	}
	return out
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
// The pool is the product's, 198.19.0.0/17. It lies inside the benchmarking block 198.18.0.0/15 that
// rulesPrivateNetworks lists whole, and with it rulesClientConfig and rulesClientSniffing: there, the
// bypass:lan row would send the pool direct and the sniffing would leave it alone. This lab keeps out
// the tun's own 198.18.0.0/16 and no more. The port is neither 53 nor 443, which a VLESS client
// carries another way (proxy/vless/outbound).

const (
	// Not a documentation range: the product's own pool, the shape its rules and its sniffing exclusions
	// are written around, which the test must meet as it is.
	poolLabPool = "198.19.0.0/17"
	poolLabPort = 3478
	poolLabUUID = "b831381d-6324-4d53-ad4f-8cda48b30811" // the example UUID of Xray's own docs
)

// poolLabPrivateNetworks is rulesPrivateNetworks with the benchmarking block cut down to the tun's
// 198.18.0.0/16, which leaves the pool out.
func poolLabPrivateNetworks() []string {
	networks := slices.DeleteFunc(slices.Clone(rulesPrivateNetworks), func(network string) bool { return network == "198.18.0.0/15" })
	return append(networks, "198.18.0.0/16")
}

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
		IPsExcluded:  poolLabPrivateNetworks(),
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
	exit1, exit2 *rulesSink     // the echoes behind the proxy server's exits for the two names
	stray, lan   *rulesSink     // behind its exit for any other address; behind the client's direct
	flows        *tun.UDPFlowsForTest

	mu      sync.Mutex
	replies []poolReply // what the program got, in order
}

// newPoolLab starts the proxy server (SOCKS5 or VLESS, as `transport` says), the client engine with
// fake DNS, and the tun inbound's UDP flow table on a handler of that engine, built as the bridge
// builds it (NewUDPFlowsForTest).
func newPoolLab(t *testing.T, transport string) *poolLab {
	t.Helper()
	lab := &poolLab{exit1: newRulesEcho(t), exit2: newRulesEcho(t), stray: newRulesEcho(t), lan: newRulesEcho(t)}
	serverPort := rulesFreePort(t)
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
	// Every freedom of this lab, the client's direct one too, lets loopback through and blocks the
	// rest (finalRules). For a vless inbound freedom cuts private addresses off by default, and these
	// exits are redirected to 127.0.0.1; the rules are checked after the redirect, and should a change
	// to freedom ever drop it, they keep the lab on the machine.
	rulesEngine(t, fmt.Sprintf(`{"log":{"loglevel":"none"},
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
	lab.engine = rulesEngine(t, fmt.Sprintf(`{"log":{"loglevel":"none"},
	  "fakeDns":{"ipPool":"%s","poolSize":16384},
	  "dns":{"hosts":{"one.example":"203.0.113.1","two.example":"203.0.113.2"}},
	  "outbounds":[%s,
	    {"tag":"direct","protocol":"freedom","settings":{"redirect":"127.0.0.1:%d","finalRules":[{"action":"allow","ip":["127.0.0.0/8"]},{"action":"block"}]}}],
	  "routing":{"domainStrategy":"AsIs","rules":[
	    {"type":"field","ip":["%s"],"outboundTag":"direct","ruleTag":"bypass:lan"},
	    {"type":"field","network":"udp","outboundTag":"proxy-udp","ruleTag":"main:udp"}]}}`,
		poolLabPool, clientOut, lab.lan.port(), strings.Join(poolLabPrivateNetworks(), `","`)))

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
	source := rulesSource(t)
	one, two := lab.poolAddress(t, "one.example"), lab.poolAddress(t, "two.example")

	for round := 1; round <= 2; round++ {
		lab.flows.HandlePacket(source, one, []byte(fmt.Sprintf("one-%d", round)))
		lab.flows.HandlePacket(source, two, []byte(fmt.Sprintf("two-%d", round)))
		if !rulesWait(t, fmt.Sprintf("round %d: both names are answered", round), 5*time.Second, func() bool { return len(lab.answers()) == 2*round }) {
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
