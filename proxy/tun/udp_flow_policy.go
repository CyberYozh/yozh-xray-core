package tun

// A UDP flow belongs to the socket that opened it, and every datagram travels the route of its own
// destination.
//
// The tun inbound keys UDP by its source address and port alone, so that one socket keeps one
// outbound mapping whatever it sends to (full cone: STUN, WebRTC, games). Behind a utun every
// program has the same source address, so the key is in effect the port — and the kernel hands a
// port that was just closed to the next socket that asks, at once and at random. A new program on
// that port joined the old program's flow: no sniffing, no routing, no rule, the old program's
// outbound, until the flow went idle 300–600 s later.
//
// The key stays. What changes: the source remembers which socket it belongs to — the socket's
// generation (xinpcb_n inp_gencnt) in the kernel's UDP table — and asks the table again when its
// traffic could have changed hands: a packet to another destination than the previous one, a packet
// after a silence on the program's side, and — for a stream that neither turns nor pauses, which a
// port could change hands in the middle of — a packet 5 s or more after the last check, whatever
// the traffic. A different socket, a socket gone, or a socket where there was none, and every flow
// of the source is finished and the packet starts afresh, routed from scratch. No socket before and
// none now (a virtual machine, internet sharing) is left as it is.
//
// The table is read off the packet path: the packets of a source being checked wait in a short
// queue, the others pass, and one read of the table answers every check of a short window. A new
// source's flow is routed only once the table has named its socket; its packets wait in its queue
// until then.
//
// Every destination on its own route. A flow is routed once, by its first packet, and upstream's
// flow carried the socket's later packets, to anywhere, through that one outbound: a first packet
// that an address row sends direct (the app's rows for local networks and proxy hops come before
// every per-app row) took the program's traffic to any address direct, a program whose own rule
// blocks it included, without a question to the routing resolver. Now a packet to a destination the
// source has not sent to is routed as the first packet of a flow would be (the dispatcher's
// session.FlowRoute: same inbound and source, that address and port, what sniffing finds in the
// packet — and in the next ones to that destination when it alone cannot tell, as the dispatcher's
// sniffing reads on into a flow's next packets) and goes into the source's flow that went to the
// same outbound — the full cone, within a route — or, when none did, into a new flow of its own,
// which the dispatcher sniffs and routes as it does every flow. A source thus has a flow per route
// (and one for each address of fake DNS, below), each with its own mapping, all alive at once, each
// ending on its own (udp_fullcone.go, routeWaiting). Until the route is known the packet waits, and
// goes nowhere. The port may change hands while it waits, and the per-app rows ask who holds the
// port when they are asked, so an answer given after the change is the next program's. So the table
// is read again after the answer and before the packet goes anywhere: another socket there, and the
// packets that wait are dropped — they were the previous program's — and the source's flows are
// finished. One read vouches for every answer a round of questions got before it.
//
// An address of fake DNS has a flow of its own, whatever the route (ownFlow). It stands for a name:
// sniffing finds the name by the pool address, the flow is routed by the name, and the outbound puts
// the name's real address in place of the pool address of the flow's FIRST destination, and of no
// other (buf.EndpointOverrideReader). A second pool address in the same flow would reach the proxy as
// the pool address itself, and a proxy takes a flow, one association, to the exit of its first
// destination. So a datagram to a pool address never joins the flow of another destination, and
// there is no route to wait for: none of the other flows can place it. Its flow, like every new
// flow, opens only after such a read. It counts toward udpFlowLimit and ends as the others do. The
// other destinations are matched by their route alone: one whose route a pool address's flow went
// to joins it, if that is the first flow of the route.
//
// What it costs:
//   - A datagram from the same socket straight to the address a name resolved to goes into the flow
//     of its route, and is answered from the pool address when that flow is the name's: telling it
//     apart would tell a WebRTC peer apart from the STUN mapping the socket learned its address by.
//   - Every pool address is an association of its own at the proxy, up to udpFlowLimit for a
//     socket. Behind a proxy that changes its exit for every connection, two STUN servers asked for
//     by name can leave from different exits.
//   - One pool address on two ports is two flows: a destination is an address and a port, and the
//     route of a UDP datagram depends on the port too (53 is DNS; 123, 137-139, 1900, 5353 and
//     others are local noise).
//
// A flow also ends after a quiet spell on the program's side, sized by what its first packet looks
// like: 10 s for DNS, NTP and STUN, which ask once and are answered at once; 30 s for QUIC, DTLS
// and port 443, whose live sessions send more often than that; 60 s for the rest. Replies do not
// extend it: a remote that keeps sending cannot keep a flow alive for a program that has gone.
//
// What is left. A program that is handed the port of another program's live flow and sends to the
// SAME destination, with gaps shorter than the silence, is not asked about until the periodic
// check: for up to `recheck` (5 s on darwin) its packets ride the previous program's flow and
// route. It takes a port collision, the same destination and no pause. And between a read of the
// table and the routing question of the flow opened after it — for a new source, and for a packet
// that waited for its route — the port can still change hands: that flow is routed for the next
// program. The window is the time from the read to the question, as for every new flow. The packets
// a check holds when it finds another socket, or none, are routed for what it found: the last
// datagrams of a program that closed its socket are routed as traffic with no socket is (the per-app
// rows send it through the base, never direct).
//
// Only darwin has the table (udp_socket_darwin.go). Elsewhere the platform's policy is empty, since
// there is no table to ask: a source is never re-checked and its flows never end by themselves, as in
// upstream's full cone — but every destination still takes its own route. The rule for the addresses
// of fake DNS (ownFlow) is the tun handler's, added to the platform's policy on every platform
// (handler.go, ownUDPFlow); with no table the read that precedes a pool address's flow answers at
// once.

import (
	"cmp"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// socketIdentity is what the socket table said about the socket(s) behind a flow's source at one
// moment: the sorted marks of the sockets bound to its port on its address or on a wildcard, save
// the engine's own (udp_socket_darwin.go, identityOf).
type socketIdentity struct {
	// known is false when the table could not be read. An unknown identity is the same as any
	// other, since without an answer there is nothing to tell two sockets apart by: a flow then
	// behaves as in upstream's full cone. A flow never keeps one as its own socket, or it would pass
	// every re-check for life: it takes the next known answer instead (udp_fullcone.go, identified).
	known bool
	// marks: one per socket, sorted (compareSocketMarks). Empty: no socket.
	marks []socketMark
}

// socketMark tells one socket in the table from another. A kernel socket is its generation
// (xinpcb_n inp_gencnt), its own for its life, peer or none. A user-space (Skywalk) flow, which the
// kernel reports with generation 0, has no generation to be told by: it is its owner's pid and its
// peer, the foreign port and address. By the pid alone, every flow of one process on a port was one
// socket, and a new flow to another peer rode its predecessor's flow and route. An unconnected one
// has no peer (zero) and stays one flow, as before.
type socketMark struct {
	generation uint64
	pid        int32
	fport      uint16
	faddr      netip.Addr
}

func compareSocketMarks(a, b socketMark) int {
	return cmp.Or(cmp.Compare(a.generation, b.generation), cmp.Compare(a.pid, b.pid), cmp.Compare(a.fport, b.fport), a.faddr.Compare(b.faddr))
}

func (a socketIdentity) same(b socketIdentity) bool {
	if !a.known || !b.known {
		return true
	}
	return slices.Equal(a.marks, b.marks)
}

// socketLookup reads the socket table once and answers for every source asked about.
type socketLookup interface {
	identify(sources []net.Destination) []socketIdentity
}

// udpFlowPolicy is how the tun inbound treats its UDP flows. The zero value is upstream's full cone:
// never re-checked, never ended by the inbound itself.
type udpFlowPolicy struct {
	lookup  socketLookup  // nil: no re-checks
	window  time.Duration // at most one read of the table per window
	silence time.Duration // a packet after this much silence from the program is re-checked
	recheck time.Duration // a packet this long after the flow's last check is re-checked; 0: never
	// idle sizes a flow's life from its first packet; nil: the inbound never ends a flow itself.
	idle func(dst net.Destination, first []byte) time.Duration
	// ownFlow picks the destinations that have a flow of their own: the addresses of fake DNS. A
	// datagram to one never joins the flow of another destination; nil: no destination has one. The
	// rule is asked in routeWaiting, about the datagram nextLocked hands out (whether or not the
	// source has flows), and in askRoutesLocked, which never asks a route for such a destination.
	// That datagram opens its flow without waiting for the source's other flows to report a route and
	// without a route question, but, like every new flow, only after a read of the socket table made
	// since the last wait or question. A datagram queued behind one that waits for a flow or an answer
	// waits behind it; it passes one that waits only for the rest of its packets, as every destination
	// does. The rule is called with the table's lock held: it must be cheap and must not block.
	ownFlow func(dst net.Destination) bool
}

// udpIdleByFirstPacket: 10 s for DNS, NTP and STUN, 30 s for QUIC and DTLS (and port 443), 60 s for
// the rest. The protocol is read from the first packet's own header where it has one, and only else
// from the port: QUIC to port 53 is QUIC.
func udpIdleByFirstPacket(dst net.Destination, first []byte) time.Duration {
	switch {
	case isSTUN(first):
		return 10 * time.Second
	case isQUICLongHeader(first), isDTLS(first):
		return 30 * time.Second
	case dst.Port == 53, dst.Port == 123, dst.Port == 3478:
		return 10 * time.Second
	case dst.Port == 443:
		return 30 * time.Second
	default:
		return 60 * time.Second
	}
}

// isSTUN: RFC 8489 §5 — the two top bits zero and the magic cookie at bytes 4–7.
func isSTUN(b []byte) bool {
	return len(b) >= 20 && b[0]&0xC0 == 0 && binary.BigEndian.Uint32(b[4:8]) == 0x2112A442
}

// isQUICLongHeader: RFC 9000 §17.2 (form and fixed bits set) with version 1 or 2 (RFC 9369).
func isQUICLongHeader(b []byte) bool {
	if len(b) < 5 || b[0]&0xC0 != 0xC0 {
		return false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	return version == 0x00000001 || version == 0x6b3343cf
}

// isDTLS: a DTLS record header (RFC 9147 §4) — content type 20–25, version 1.0 or 1.2.
func isDTLS(b []byte) bool {
	return len(b) >= 13 && b[0] >= 20 && b[0] <= 25 && b[1] == 0xFE && (b[2] == 0xFF || b[2] == 0xFD)
}

// socketChecker batches questions to the socket table: the first question after a quiet window is
// read at once; the ones that arrive while a read is under way or the window lasts share the next
// read. Answers are delivered in the order asked, on the checker's goroutine — never on the
// packet path.
type socketChecker struct {
	lookup socketLookup
	window time.Duration

	mu      sync.Mutex
	queue   []socketQuery
	running bool
}

type socketQuery struct {
	source net.Destination
	answer func(socketIdentity)
}

func (c *socketChecker) ask(source net.Destination, answer func(socketIdentity)) {
	c.mu.Lock()
	c.queue = append(c.queue, socketQuery{source: source, answer: answer})
	start := !c.running
	c.running = true
	c.mu.Unlock()
	if start {
		go c.run()
	}
}

func (c *socketChecker) run() {
	for {
		c.mu.Lock()
		batch := c.queue
		c.queue = nil
		if len(batch) == 0 {
			c.running = false
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		sources := make([]net.Destination, len(batch))
		for i, query := range batch {
			sources[i] = query.source
		}
		identities := c.lookup.identify(sources)
		if len(identities) != len(batch) {
			identities = make([]socketIdentity, len(batch)) // a broken answer is no answer
		}
		for i, query := range batch {
			query.answer(identities[i])
		}
		time.Sleep(c.window)
	}
}
