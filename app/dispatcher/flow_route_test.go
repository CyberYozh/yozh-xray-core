package dispatcher

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

type flowRouteHandler struct {
	outbound.Handler
	tag string
}

func (h flowRouteHandler) Tag() string { return h.tag }

type flowRouteOutbounds struct {
	outbound.Manager
	handlers map[string]outbound.Handler
	fallback outbound.Handler
}

func (m flowRouteOutbounds) GetHandler(tag string) outbound.Handler {
	if handler, ok := m.handlers[tag]; ok {
		return handler
	}
	return nil
}

func (m flowRouteOutbounds) GetDefaultHandler() outbound.Handler { return m.fallback }

type flowRouteRoute struct {
	routing.Route
	tag string
}

func (r flowRouteRoute) GetOutboundTag() string { return r.tag }

// flowRouteRouter routes by the target's name and port when the rules are shown a name, as a domain
// rule does, and by its address and port otherwise; it remembers what it was asked.
type flowRouteRouter struct {
	routing.Router
	byTarget map[string]string
	asked    []routing.Context
}

func (r *flowRouteRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.asked = append(r.asked, ctx)
	var address net.Address
	if domain := ctx.GetTargetDomain(); domain != "" {
		address = net.DomainAddress(domain)
	} else {
		address = net.IPAddress(ctx.GetTargetIPs()[0])
	}
	if tag, ok := r.byTarget[net.UDPDestination(address, ctx.GetTargetPort()).NetAddr()]; ok {
		return flowRouteRoute{tag: tag}, nil
	}
	return nil, common.ErrNoClue
}

func flowRouteDispatcher() (*DefaultDispatcher, *flowRouteRouter) {
	router := &flowRouteRouter{byTarget: map[string]string{
		"192.0.2.1:443":       "proxy",
		"192.0.2.2:443":       "gone", // a rule naming an outbound that does not exist
		"www.google.com:443":  "direct",
		"play.google.com:443": "direct",
	}}
	first := flowRouteHandler{tag: "first"}
	return &DefaultDispatcher{
		ohm: flowRouteOutbounds{
			handlers: map[string]outbound.Handler{"first": first, "proxy": flowRouteHandler{tag: "proxy"}, "direct": flowRouteHandler{tag: "direct"}},
			fallback: first,
		},
		router: router,
	}, router
}

// flowRouteCtx is a tun UDP flow's context as the dispatcher sees it after sniffing its first packet.
func flowRouteCtx(report func(session.FlowRoute)) context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "tun",
		Source: net.UDPDestination(net.ParseAddress("198.18.0.2"), 50000),
	})
	first := net.UDPDestination(net.ParseAddress("192.168.1.5"), 3478)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{OriginalTarget: first, Target: first}})
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "quic"})
	return session.ContextWithFlowRouteReport(ctx, report)
}

const flowRouteXrayKey core.XrayKey = 1

// flowRouteSniffedCtx is flowRouteCtx for an inbound that sniffs its flows with `request`, in an
// engine the sniffers ask for features (this one has none, fake DNS included).
func flowRouteSniffedCtx(report func(session.FlowRoute), request session.SniffingRequest) context.Context {
	ctx := flowRouteCtx(report)
	ctx = session.ContextWithContent(ctx, &session.Content{Protocol: "quic", SniffingRequest: request})
	return context.WithValue(ctx, flowRouteXrayKey, &core.Instance{})
}

// flowRouteClientSniffing: http, tls and quic, the sniffed name replacing the address.
func flowRouteClientSniffing() session.SniffingRequest {
	return session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: []string{"http", "tls", "quic"}}
}

// flowRouteOf is the RouteOf reported for a flow of an inbound that sniffs with `request`.
func flowRouteOf(t *testing.T, d *DefaultDispatcher, request session.SniffingRequest) func(net.Destination, [][]byte) (string, error) {
	t.Helper()
	var reported *session.FlowRoute
	d.reportFlowRoute(flowRouteSniffedCtx(func(route session.FlowRoute) { reported = &route }, request), flowRouteHandler{tag: "first"}, false)
	if reported == nil {
		t.Fatal("the flow's route was not reported")
	}
	return reported.RouteOf
}

// flowRouteQUICInitial is a client's QUIC Initial whose ClientHello names www.google.com: the QUIC
// sniffer's own test packet (common/protocol/quic/sniff_test.go, TestSniffQUIC).
const flowRouteQUICInitial = "cd0000000108f1fb7bcc78aa5e7203a8f86400421531fe825b19541876db6c55c38890cd73149d267a084afee6087304095417a3033df6a81bbb71d8512e7a3e16df1e277cae5df3182cb214b8fe982ba3fdffbaa9ffec474547d55945f0fddbeadfb0b5243890b2fa3da45169e2bd34ec04b2e29382f48d612b28432a559757504d158e9e505407a77dd34f4b60b8d3b555ee85aacd6648686802f4de25e7216b19e54c5f78e8a5963380c742d861306db4c16e4f7fc94957aa50b9578a0b61f1e406b2ad5f0cd3cd271c4d99476409797b0c3cb3efec256118912d4b7e4fd79d9cb9016b6e5eaa4f5e57b637b217755daf8968a4092bed0ed5413f5d04904b3a61e4064f9211b2629e5b52a89c7b19f37a713e41e27743ea6dfa736dfa1bb0a4b2bc8c8dc632c6ce963493a20c550e6fdb2475213665e9a85cfc394da9cec0cf41f0c8abed3fc83be5245b2b5aa5e825d29349f721d30774ef5bf965b540f3d8d98febe20956b1fc8fa047e10e7d2f921c9c6622389e02322e80621a1cf5264e245b7276966eb02932584e3f7038bd36aa908766ad3fb98344025dec18670d6db43a1c5daac00937fce7b7c7d61ff4e6efd01a2bdee0ee183108b926393df4f3d74bbcbb015f240e7e346b7d01c41111a401225ce3b095ab4623a5836169bf9599eeca79d1d2e9b2202b5960a09211e978058d6fc0484eff3e91ce4649a5e3ba15b906d334cf66e28d9ff575406e1ae1ac2febafd72870b6f5d58fc5fb949cb1f40feb7c1d9ce5e71b"

// flowRouteSplitInitial is the first datagram of a client whose ClientHello, for play.google.com,
// spans two Initials: the first 1250 bytes of TestSniffQUICIncompleteServerName's two packets
// (common/protocol/quic/sniff_test.go), on which the QUIC sniffer asks for more data.
// flowRouteSplitInitialRest is the second: the other 1250 bytes, which complete the ClientHello.
const flowRouteSplitInitial = "ca0000000108d799f48baf472fc3004047005411dcdaa24bd4c3cdbef653940a1ea0a671bb8c23222a8502bfcbd0a335af016df330b1190e4b1efd420aa82c4414a7dfd7b1aa63aa7bd0269ec8ed0d24895a467b737fcc514488a8142241b81c4952fb32e9f123f3f8d1be9eecc1340d7fa747c6f4838810209d51ad453fcec084ffaa382f9fed010a0585f8ce73c36dc6c628df940f72fb5b8e3e06f4612128d3b8f87725770d81305489a3a23cd443fcc668fece0ec9a909c82cfdb66819ce031422c3edd49ea72b6216efb940b8c186e2510b0f93d4cf3b6434ed9f5817c5a5a19fa861d24883bd48ba296df81e887fcb9ef18013ab1070df268049f3d35e8ddfffd2b100e4eb687176a02e7975085caa138e9df7cb6f9862356faafba3300f586df09af3b4e3eec15b6d1f14b34fe4eeb8e762ff482f3b7b0595c16d3eb20cf9c892b3f7c6449e51ffa33f3dc877d32e572e10ba4d5a320117110b150bec4a9434103de963aa2de1b22eaa992b59a8583c7a2d4e5743ef98a1b1f5f4aaeb2b49dbe441c331e7cb028e70432ce0890f78d40671f13d5feccc4ab264ae903affaa951897128d598ed8e8542294aa03abb0a2a7ec970ab874387b8777827c4847bb29ff93d0427c1fcc581407465611e4400bfeab39de4c4f65572365156421503706d66138317e514214db27303ad8b5b17eb443e959faad1ccb3d3def5f3843b241dd9a60378cd907a02cc5c6e8527715c7734079cf9143586ed471587690816133fa8f09b8421f2de6ff1f5cecc134ac404e53a367b57fd4f3c85fe7e121e7094fbf93c06d427cec30cd519ee43a6018a8bb8717c05d7660b379101a182bfd3018d485d5b46e81d39445ccd4d8baefdd7590e664f2289f11bbad3d35ea6d70e157aaa7f9e91a692794b85c5b86db33863151468d32792ecfdb2aec52784ded5aa431fa9a7337ddd9e95313a897fe5ca6ef3c7e0cf3d41f7f104506f8695f2ba307715022e5e98472d6ff24125004d14db2c7a4cc71ca39a9874bfb93b64dd54ef451097059bbdfa96aca6c6c01e1f000b8d35bdead1502874e5d80ac00a79593b6d7e2fbee406c2212b4abd7b7e9f0037518de232cd6559443f4e3f0f03c17cef616a74992f65754bb6699b08c0eb2ec59508086e496e070c6239a73f11a9d14a727b10188ca97ebf04851fa475ed1774836a94cfb6543c33888dfc250100e9992b0cca8bd27ae8552541f1b3d81546f15b740e4f07b41af864769fe17290eb7076c0c1f938ce56a45ead6deb6c89164f829543414a1b8cd2361c3d9b22cf85d4ad0d4221dcc87533506e32c1cfdc8240636b669f97f7c6e150ea3753fcb63a7b9eedb5615b257651e090b567a20fdc5c167ad58fa940985572db004db2b14709a6663c1fb79dc045e45cb7228f11eab4c60a48fffc702cd74dcf5aabded8355a5ae1a5e6325a3afff608e53af3aa944437139c438e6200c75bb27c8a8ce7ce9f9ec9723c4423e9e49c807b12484783ed79fc501b544f03e4b29bdf0c74eb055dbac9b78fe87a66efc819f9d2ea637dd478b920b7196232b970ed092050ba0621329aa2b3e26184176137a9c6283e4cc2c03c07e28d2da7b0485da51f131686f4dd6b23735c66316142f48781885c35c9940054a4b9187a20914bedd1c48e94af358994da5c6060dd224b0ba84ddd5e95f395fe941d464e2cccd857a180de756d32407540c3611b649c7a71cbf5a492bf5c8d4e112a743498ce83ea3e94bcaa6"

const flowRouteSplitInitialRest = "c00000000108d799f48baf472fc3004047005411dcdaa24bd4c3cdbef653940a1ea0a671bb8c23222a8502bfcbd0a335af016df330b1190e4b1efd420aa82c4414a7dfd7b1aa63aa7bd0269ec8ed0d24895a467b737fcc514488e7151df796764293639665547941eaaa7d83dfc9d42952583a821611921cba9e0276f9244f197e011b6c2d898255802c81c8792dd68d03cd8982ee6146c8734814e9640e0999312f97e898db60642ceca21700be9e698b5e577062148d1ac840e737f7bc4f18f9ffd13e656fca1517c96d0e0c607b67d7e75795f62131255b44c2178d896192348d5f053060fa21c855236401e853e435fbc71a428c8e126cd8393cb860193fd6304d9576e8a8ce7f6959739afa7d7ffaf86516afb061ade1eef603e8e5c66f002cacbef25546e84b59be707c547837f7b49471a59325ad58a4f189a525a3a354a4be5ffd3db34ce0585ec470f78f0ff6eb807989d5998e2fccc80bd651de654da3581b6c8a858b56c4df47c3041c50d74f0b3a3a5a325882cd356d0c46d6db74559cef934a1655c65a06daff218244f5f4e95b96794e45d371a03afee2c89768fe3d7bc134844f45440620a88d6ddb5d07b7f6c9b2adfbf5743c5c586520504febf14ee4b216f8186ee1bf9802ccebd4dac519bd337a554940a3873cd21ef32f3d4d4fdfd3eaabb172b5314490b3587a9ca2dc12637fa80dcd526859bb83d54f67dedeb173470e052beec9edba4b41444d31253accb3381237179a5381d437fc4d47c0a82f1c9da8c76ad3eee9417bf69acb8d530ac824e65d796b84bee40b14daa9e80c11e466f93233e1768ecc6c0237e71b901f1faa093bbd9e5324b2a160d02f09d4590392279a15c73edc4d1d7501ebad992fc8f1c9dce96c190879225dbbb09d20532f9dcbb845e3484c87cb8c3b06fe892b07bdc60926e3d4b5c9024acde5abed0a72686d546da535a2122cfd6d6488a491dc9612b90f3f6709835e83f59fd612c2259c3ac944fdae87ffd744176a92fbea1efd037565a39d5bc38991cfe6617135b43cd6c6484a3b228e10d3f8184227a7ee63121be20f099c4264461d52aecf4b8ee1a4d0ec41717f9a68e1394544cf3be0a3a171ece35c879b67afdaac49c12731e6dc5ccaa49fa72610901036a7f0752951077cd9f1d77eb6e4f12c16dab08e1a9655fda3ba0e80c34c767f40e61491f706ab9d1b50f48273ca4e37708d075909a3e2c4b173510114d8377b5300994f9a4f794db2781b98c2e9d0056fdbe87b249beb3e7301c86efe6b32242b4c7fabef280a1ca7bdd6abb38624cbebb01b6b75b07d0cd9090b2c296d0e330b9008788dd6f7e1af1dd63b02408f1a67b57be3316152270bf90c36e9f74322c9caba5adab3309e5bd7c44d3c2ac77329e167dafda7395e37313723fb550a6ab96729a9fa8f9e4a3e5957bffa3302617d48fd38196635309928c491ca974a112768de16043fc618001780b49a0bac2ea9fc2607ebd1f25b8ef65a6cab42d16c9184e23af496ac5cfab274d9557006d9c52bb56cd8c019ddf085f260a0582ef465c73f97fedc02271dda53eec20e6aa50503357ed1847f7d976899cb24e5dd42dd87ae48db3c9335b38957fc0f86a6ceee590b1cbee41fc6ace3189886bd86f9b082e66fb263f1a98dd8e564bff9ec412ae79e29fd519ac96e9c5b446b436b78a6ca555c496ca5c5e73c2c1c5837b13f7a953d57738440d4ed60efd4701bbbbcad79e1697b5724695f52dab8bce02e7f"

func flowRouteBytes(t *testing.T, hexData string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A flow that asked is told where it went, and how its other destinations are routed: by the same
// rules, for the same inbound and source, that destination — and nothing sniffed from the first
// packet, which was not theirs.
func TestFlowRouteReportsTheOutboundAndRoutesOtherDestinationsLikeRoutedDispatch(t *testing.T) {
	d, router := flowRouteDispatcher()
	var reported *session.FlowRoute
	d.reportFlowRoute(flowRouteCtx(func(route session.FlowRoute) { reported = &route }), flowRouteHandler{tag: "direct"}, false)
	if reported == nil || reported.Tag != "direct" {
		t.Fatalf("reported %+v, want the flow's own outbound, direct", reported)
	}

	for _, c := range []struct {
		name, to string
		tag      string
		dropped  bool
	}{
		{"a rule's outbound", "192.0.2.1", "proxy", false},
		{"no rule: the default outbound", "192.0.2.9", "first", false},
		{"a rule naming no outbound: dropped", "192.0.2.2", "", true},
	} {
		tag, err := reported.RouteOf(net.UDPDestination(net.ParseAddress(c.to), 443), [][]byte{[]byte("plain")})
		if tag != c.tag || (err != nil) != c.dropped || err == protocol.ErrProtoNeedMoreData {
			t.Errorf("%s: (%q, %v), want (%q, dropped %v)", c.name, tag, err, c.tag, c.dropped)
		}
	}
	asked := router.asked[0]
	if asked.GetInboundTag() != "tun" || asked.GetSourcePort() != 50000 || asked.GetNetwork() != net.Network_UDP {
		t.Errorf("routed as inbound %q, source port %d, network %v: not the flow's", asked.GetInboundTag(), asked.GetSourcePort(), asked.GetNetwork())
	}
	if protocol := asked.GetProtocol(); protocol != "" {
		t.Errorf("another destination was routed as %q, sniffed from the flow's first packet", protocol)
	}
}

// A datagram is routed as the first packet of a flow of its own would be: the flow's sniffing finds
// the name in its QUIC Initial, and the name, not the address, meets the rules — with the protocol.
func TestFlowRouteOfRoutesADatagramByTheNameSniffedInIt(t *testing.T) {
	d, router := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{flowRouteBytes(t, flowRouteQUICInitial)})
	if tag != "direct" || err != nil {
		t.Fatalf("(%q, %v), want (direct, nil): the name's route, not the address's (proxy)", tag, err)
	}
	asked := router.asked[0]
	if domain, protocol := asked.GetTargetDomain(), asked.GetProtocol(); domain != "www.google.com" || protocol != "quic" {
		t.Errorf("routed as name %q, protocol %q; want www.google.com and quic", domain, protocol)
	}
}

// Sniffing the datagrams leaves them as they were: the QUIC sniffer decrypts in place, and the
// datagrams RouteOf is asked about are the ones that are sent next.
func TestFlowRouteOfLeavesTheDatagramsAsTheyWere(t *testing.T) {
	d, _ := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	for _, datagrams := range [][][]byte{
		{flowRouteBytes(t, flowRouteQUICInitial)},
		{flowRouteBytes(t, flowRouteSplitInitial), flowRouteBytes(t, flowRouteSplitInitialRest)},
	} {
		var before [][]byte
		for _, datagram := range datagrams {
			before = append(before, bytes.Clone(datagram))
		}
		routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), datagrams)
		for i := range datagrams {
			if !bytes.Equal(datagrams[i], before[i]) {
				t.Fatalf("RouteOf changed datagram %d of the %d it was asked about", i, len(datagrams))
			}
		}
	}
}

// A plain datagram carries nothing the sniffers know, and is routed by its address, with no protocol
// — not with the one the flow's first packet was sniffed as.
func TestFlowRouteOfAPlainDatagramIsRoutedByItsAddress(t *testing.T) {
	d, router := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{[]byte("plain")}); tag != "proxy" || err != nil {
		t.Fatalf("(%q, %v), want (proxy, nil)", tag, err)
	}
	if protocol := router.asked[0].GetProtocol(); protocol != "" {
		t.Errorf("routed as %q, sniffed from the flow's first packet", protocol)
	}
}

// An inbound that does not sniff has its datagrams routed by address, whatever they carry.
func TestFlowRouteOfWithoutSniffingRoutesByTheAddress(t *testing.T) {
	d, router := flowRouteDispatcher()
	request := flowRouteClientSniffing()
	request.Enabled = false
	routeOf := flowRouteOf(t, d, request)
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{flowRouteBytes(t, flowRouteQUICInitial)}); tag != "proxy" || err != nil {
		t.Fatalf("(%q, %v), want (proxy, nil): the address's route", tag, err)
	}
	if domain, protocol := router.asked[0].GetTargetDomain(), router.asked[0].GetProtocol(); domain != "" || protocol != "" {
		t.Errorf("routed as name %q, protocol %q; want neither", domain, protocol)
	}
}

// An address the sniffing excludes (ipsExcluded) keeps its address for the rules though the Initial
// names a host; the protocol found is still theirs, as it is for a flow's first packet.
func TestFlowRouteOfAnExcludedAddressIsRoutedByTheAddress(t *testing.T) {
	d, router := flowRouteDispatcher()
	request := flowRouteClientSniffing()
	excluded, err := geodata.IPReg.BuildIPMatcher(common.Must2(geodata.ParseIPRules([]string{"192.0.2.1/32"})))
	if err != nil {
		t.Fatal(err)
	}
	request.ExcludeForIP = excluded
	routeOf := flowRouteOf(t, d, request)
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{flowRouteBytes(t, flowRouteQUICInitial)}); tag != "proxy" || err != nil {
		t.Fatalf("(%q, %v), want (proxy, nil): the address's route", tag, err)
	}
	if domain, protocol := router.asked[0].GetTargetDomain(), router.asked[0].GetProtocol(); domain != "" || protocol != "quic" {
		t.Errorf("routed as name %q, protocol %q; want no name, quic", domain, protocol)
	}
}

// With routeOnly the name decides the route and the address stays the target, as for a flow's first
// packet.
func TestFlowRouteOfRouteOnlyRoutesByTheNameAndKeepsTheAddress(t *testing.T) {
	d, router := flowRouteDispatcher()
	request := flowRouteClientSniffing()
	request.RouteOnly = true
	routeOf := flowRouteOf(t, d, request)
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{flowRouteBytes(t, flowRouteQUICInitial)}); tag != "direct" || err != nil {
		t.Fatalf("(%q, %v), want (direct, nil): the name's route", tag, err)
	}
	asked := router.asked[0]
	if domain := asked.GetTargetDomain(); domain != "www.google.com" {
		t.Errorf("routed as name %q, want www.google.com", domain)
	}
	if ips := asked.GetTargetIPs(); len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("the target became %v, want the address kept, 192.0.2.1", ips)
	}
}

// A datagram that is only the start of what a sniffer needs — a ClientHello split over two Initials
// — cannot tell its route alone, and RouteOf says so with the sniffer's own answer: the caller holds
// on to it for the rest, as the dispatcher's sniffing reads on into a flow's next packets. It is not
// the answer for a datagram the dispatcher would drop.
func TestFlowRouteOfADatagramThatCannotTellAloneSaysSo(t *testing.T) {
	d, router := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{flowRouteBytes(t, flowRouteSplitInitial)}); err != protocol.ErrProtoNeedMoreData {
		t.Fatalf("(%q, %v), want (\"\", %v): the first Initial alone does not name the host", tag, err, protocol.ErrProtoNeedMoreData)
	}
	if len(router.asked) != 0 {
		t.Error("the rules were asked with half a ClientHello")
	}
}

// The datagrams waiting for one destination are sniffed one after another, as the dispatcher's
// sniffing reads a flow's first packets: the two halves of a split ClientHello name the host
// together, and the name meets the rules.
func TestFlowRouteOfReadsADestinationsDatagramsTogether(t *testing.T) {
	d, router := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	datagrams := [][]byte{flowRouteBytes(t, flowRouteSplitInitial), flowRouteBytes(t, flowRouteSplitInitialRest)}
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), datagrams); tag != "direct" || err != nil {
		t.Fatalf("(%q, %v), want (direct, nil): the name both halves carry", tag, err)
	}
	if domain, protocol := router.asked[0].GetTargetDomain(), router.asked[0].GetProtocol(); domain != "play.google.com" || protocol != "quic" {
		t.Errorf("routed as name %q, protocol %q; want play.google.com and quic", domain, protocol)
	}
}

// Asked with no datagrams, RouteOf sniffs nothing: the route a flow takes when its sniffing found
// nothing in its time — the address's.
func TestFlowRouteOfWithNoDatagramsSniffsNothing(t *testing.T) {
	d, router := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), nil); tag != "proxy" || err != nil {
		t.Fatalf("(%q, %v), want (proxy, nil): the address's route", tag, err)
	}
	if domain, protocol := router.asked[0].GetTargetDomain(), router.asked[0].GetProtocol(); domain != "" || protocol != "" {
		t.Errorf("routed as name %q, protocol %q; want neither", domain, protocol)
	}
}

// RouteOf reads no more of the datagrams than the dispatcher's sniffing does of a flow's first
// packets (its buffer): Initials past it are not sniffed, and the last one read is cut short, which
// the QUIC sniffer answers as not knowing — the flow would be routed by its address.
func TestFlowRouteOfReadsNoMoreThanTheDispatchersSniffing(t *testing.T) {
	d, _ := flowRouteDispatcher()
	routeOf := flowRouteOf(t, d, flowRouteClientSniffing())
	first := flowRouteBytes(t, flowRouteSplitInitial)
	var datagrams [][]byte
	for range 32767/len(first) + 1 {
		datagrams = append(datagrams, first)
	}
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), datagrams); tag != "proxy" || err != nil {
		t.Fatalf("(%q, %v), want (proxy, nil): the address's route, as the dispatcher's sniffing ends", tag, err)
	}
	if tag, err := routeOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), datagrams[:len(datagrams)-1]); err != protocol.ErrProtoNeedMoreData {
		t.Fatalf("(%q, %v), want (\"\", %v): within the buffer every Initial is read whole", tag, err, protocol.ErrProtoNeedMoreData)
	}
}

// A flow the platform sent to its outbound by tag sends every destination there.
func TestFlowRouteOfAForcedFlowIsItsOutboundForEveryDestination(t *testing.T) {
	d, router := flowRouteDispatcher()
	var reported *session.FlowRoute
	d.reportFlowRoute(flowRouteCtx(func(route session.FlowRoute) { reported = &route }), flowRouteHandler{tag: "direct"}, true)
	if tag, err := reported.RouteOf(net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), [][]byte{[]byte("plain")}); tag != "direct" || err != nil {
		t.Fatalf("(%q, %v), want the forced outbound", tag, err)
	}
	if len(router.asked) != 0 {
		t.Fatal("the rules were asked about a forced flow")
	}
}

// A flow that did not ask is not told anything.
func TestFlowRouteIsReportedOnlyWhenAsked(t *testing.T) {
	d, router := flowRouteDispatcher()
	d.reportFlowRoute(context.Background(), flowRouteHandler{tag: "direct"}, false)
	if len(router.asked) != 0 {
		t.Fatal("routed for a flow that did not ask")
	}
}
