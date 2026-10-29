package tun

import (
	"cmp"
	"context"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
)

type packet struct {
	data []byte
	dest *net.Destination
}

// udpHeldLimit bounds what one source may have waiting while it is re-checked against its socket
// (udp_flow_policy.go), and again what may wait for a route (routeWaiting).
const udpHeldLimit = 256

// udpRouteWait bounds how long a source's datagrams to a new destination wait for the source's flows
// to be routed: the dispatcher reports a flow's route once it has sniffed and routed its first
// packet (settle). A flow that has not reported by then matches no destination but its own.
const udpRouteWait = 2 * time.Second

// udpSniffWait bounds how long a destination's datagrams wait for the rest of what names their route,
// when those at hand cannot tell RouteOf (protocol.ErrProtoNeedMoreData: a ClientHello split over two
// QUIC Initials, and only the first is here): as long as the dispatcher's sniffing waits for a new
// flow's next packets. Past it they are routed with nothing sniffed, as such a flow is.
const udpSniffWait = 200 * time.Millisecond

// udpDestLimit bounds how many destinations a source remembers the flow of. Past it one is
// forgotten, and routed again when the program next sends to it.
const udpDestLimit = 1024

// udpFlowLimit bounds how many flows a source holds at once. Destinations of one route share a
// flow, so a source needs one per route it sends to, and one for each address of fake DNS, which
// joins no flow but its own (ownFlow); a real address of its route can still join that flow, if it
// is the route's first. A source gets more from flows that do not report their route in time
// (routeWait): a destination is matched only against flows that did, so each destination then opens
// a flow, and each flow holds a socket or a proxy association until its outbound times out.
// (Datagrams whose route RouteOf cannot tell yet open none: they wait for the rest, routeWaiting.)
// Past the limit the flow the program used least recently ends (openLocked), and its destinations
// are routed again when the program next sends to them.
const udpFlowLimit = 32

// errUDPFlowRetired is what a retired flow answers its outbound's replies with: the port may belong
// to another program by now, and nothing of the old flow is delivered to it.
var errUDPFlowRetired = errors.New("udp flow retired")

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.RWMutex

	// sources: one entry per source address and port, with the flows its datagrams travel in.
	sources map[net.Destination]*udpSource

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error

	// udp_flow_policy.go: who a flow belongs to, and how long it lives
	policy  udpFlowPolicy
	checker *socketChecker // nil when the policy has no socket table

	routeWait time.Duration // udpRouteWait; a test sets its own
	sniffWait time.Duration // udpSniffWait; a test sets its own

	// sends counts the packets handed to flows: which flow the program used last (udpConn.used).
	sends uint64
}

// newUdpConnectionHandler is the flow table of the tun inbound: this platform's policy, whole, with
// the handler's rule for the destinations that have a flow of their own added when conns is the tun's
// own handler. The bridge and the tests that run the real engine build the table by this one function.
func newUdpConnectionHandler(conns ConnectionHandler, writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	policy := defaultUDPFlowPolicy()
	if handler, ok := conns.(*Handler); ok && handler != nil {
		policy.ownFlow = handler.ownUDPFlow()
	}
	return newUdpConnectionHandlerWithPolicy(conns.HandleConnection, writePacket, policy)
}

func newUdpConnectionHandlerWithPolicy(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error, policy udpFlowPolicy) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		sources:          make(map[net.Destination]*udpSource),
		handleConnection: handleConnection,
		writePacket:      writePacket,
		policy:           policy,
		routeWait:        udpRouteWait,
		sniffWait:        udpSniffWait,
	}
	if policy.lookup != nil {
		handler.checker = &socketChecker{lookup: policy.lookup, window: policy.window}
	}

	return handler
}

// udpSource is one source address and port of the tun side — one program socket at a time — and
// the flows its datagrams travel in: one flow per route its destinations take, each with a full
// cone of its own (udp_flow_policy.go).
type udpSource struct {
	src net.Destination

	// Who the source is (udp_flow_policy.go): the socket behind it, and when to ask the table again.
	lastDst     net.Destination // where the program's previous datagram went
	lastSent    time.Time       // when the program last sent; replies do not move it
	lastChecked time.Time       // when the table was last asked about this source
	ident       socketIdentity  // the socket the source's flows belong to
	identified  bool            // ident holds a known answer of the table
	checking    bool            // a re-check is under way; datagrams wait in held
	held        []*packet

	// Where its datagrams go.
	flows   []*udpConn                                      // live flows, oldest first
	dests   map[net.Destination]*udpConn                    // the flow each destination travels in
	routeOf func(net.Destination, [][]byte) (string, error) // the dispatcher's, from the first flow it routed
	waiting []*packet                                       // datagrams to destinations with no flow yet, in order
	routing bool                                            // routeWaiting is at work on them
	wake    chan struct{}                                   // news for routeWaiting while it waits (wakeLocked)
	gone    bool                                            // out of the table
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source addr:port
//
// With a socket table (udp_flow_policy.go), the source is re-checked when a packet goes to another
// destination than the previous one, comes after a silence, or comes `recheck` or more after the
// source's last check (a stream that neither pauses nor turns); until the answer, that source's
// packets wait. A packet then travels in the flow of its destination's route (deliverLocked), not
// in whatever flow the source's first packet opened. Nothing here blocks: the table is read by the
// checker, and routes are asked off the packet path (routeWaiting).
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data []byte) {
	now := time.Now()
	p := &packet{data: data, dest: &dst}

	u.Lock()
	defer u.Unlock()

	s, found := u.sources[src]
	if !found {
		s = u.newSourceLocked(src, socketIdentity{}, now)
		s.lastDst = dst
		u.openLocked(s, p)
		return
	}
	if s.checking {
		s.lastDst = dst
		s.lastSent = now
		s.holdLocked(p)
		return
	}
	recheck := u.checker != nil && (dst != s.lastDst || now.Sub(s.lastSent) >= u.policy.silence ||
		u.policy.recheck > 0 && now.Sub(s.lastChecked) >= u.policy.recheck)
	s.lastDst = dst
	s.lastSent = now
	if !recheck {
		u.deliverLocked(s, p)
		return
	}
	s.checking = true
	s.lastChecked = now
	s.holdLocked(p)
	u.checker.ask(src, func(fresh socketIdentity) { u.rechecked(s, fresh) })
}

// newSourceLocked puts a source in the table. `identity` is the table's answer when the caller
// already has it (a re-check that just ended the previous source); unknown, it is asked with the
// source's first flow (openLocked).
func (u *udpConnectionHandler) newSourceLocked(src net.Destination, identity socketIdentity, now time.Time) *udpSource {
	s := &udpSource{src: src, lastSent: now, lastChecked: now, dests: make(map[net.Destination]*udpConn), wake: make(chan struct{}, 1)}
	if identity.known {
		s.ident, s.identified = identity, true
	}
	u.sources[src] = s
	return s
}

// openLocked starts a flow of s with `first` as its first packet. While the source's socket is not
// known yet, the table is asked first, and the flow goes to routing only once the answer is in
// (identified): routed first, it could be routed for the program that sent `first` and then take
// the socket of the next program on the port for its own. Its packets wait in its queue meanwhile.
func (u *udpConnectionHandler) openLocked(s *udpSource, first *packet) *udpConn {
	if len(s.flows) >= udpFlowLimit {
		// No address in the log: which programs talk to whom is not the log's business.
		errors.LogDebug(context.Background(), "[tun] udp: a source holds ", len(s.flows), " flows; the one used least recently is finished")
		u.retireLocked(slices.MinFunc(s.flows, func(a, b *udpConn) int { return cmp.Compare(a.used, b.used) }))
	}
	conn := &udpConn{
		handler: u,
		source:  s,
		egress:  make(chan *packet, 1024),
		src:     s.src,
		dst:     *first.dest,
		opened:  time.Now(),
		settled: make(chan struct{}),
	}
	s.flows = append(s.flows, conn)
	s.setDestLocked(conn.dst, conn)
	if u.policy.idle != nil {
		conn.idle = u.policy.idle(*first.dest, first.data)
		conn.timer = time.AfterFunc(conn.idle, func() { u.idleCheck(conn) })
	}
	conn.sendLocked(first)
	if u.checker != nil && !s.identified {
		u.checker.ask(s.src, func(identity socketIdentity) { u.identified(conn, identity) })
		return conn
	}

	go u.handleConnection(conn, conn.dst)
	return conn
}

// identified records the socket behind a new flow's source and hands the flow to routing. The
// checker answers in the order asked, so this always lands before any re-check asked after it. A
// flow retired before the answer (its idle time ran out first) is not routed: its queue is closed.
//
// An unknown answer (the table could not be read) is not recorded: unknown is the same as anything,
// so a source that kept it would pass every re-check for life. The flow is routed all the same, as
// without a table, and the next known answer, at a re-check, is taken as the first (rechecked).
func (u *udpConnectionHandler) identified(conn *udpConn, identity socketIdentity) {
	u.Lock()
	defer u.Unlock()
	if s := conn.source; !s.gone && !s.identified && identity.known {
		s.ident, s.identified = identity, true
	}
	if !conn.retired.Load() {
		go u.handleConnection(conn, conn.dst)
	}
}

// rechecked lets the held packets go on if the source's socket is still the one its flows began
// with: each to the flow of its destination's route (deliverLocked). Otherwise every flow of the
// source is finished, and its packets — those waiting for a route, then the held ones, in the order
// the program sent them — start the source afresh, routed from scratch. A source whose flows all
// ended while it was being checked stayed in the table until now (forgetIfEmptyLocked), so its
// packets, the held ones and any sent meanwhile, go on in order in a flow of their own.
func (u *udpConnectionHandler) rechecked(s *udpSource, fresh socketIdentity) {
	u.Lock()
	defer u.Unlock()
	held := s.held
	s.held = nil
	s.checking = false
	if s.gone {
		return // a source under a check stays in the table: not reached
	}
	if !s.identified && fresh.known {
		s.ident, s.identified = fresh, true // the first known answer (identified)
	}
	if s.ident.same(fresh) {
		for _, p := range held {
			u.deliverLocked(s, p)
		}
		u.forgetIfEmptyLocked(s)
		return
	}
	// No address in the log: which programs talk to whom is not the log's business.
	errors.LogDebug(context.Background(), "[tun] udp: the source socket changed; its flows are finished and its packets are routed again")

	pending := append(s.waiting, held...)
	s.waiting = nil
	u.endLocked(s) // out of the table now: nothing else can have taken its source meanwhile
	if len(pending) == 0 {
		return
	}
	// An unknown answer names no socket for the successor: its first flow asks for its own.
	next := u.newSourceLocked(s.src, fresh, time.Now())
	next.lastDst = *pending[len(pending)-1].dest
	next.lastSent = s.lastSent // the program's own last packet, not this answer
	u.openLocked(next, pending[0])
	for _, p := range pending[1:] {
		u.deliverLocked(next, p)
	}
}

// deliverLocked sends a packet of s on its way: into the flow its destination travels in; into a
// new flow when the source has none left and nothing waiting; and otherwise to wait until its
// destination's route is known (routeWaiting). Packets to one destination keep their order.
func (u *udpConnectionHandler) deliverLocked(s *udpSource, p *packet) {
	if conn := s.dests[*p.dest]; conn != nil {
		conn.sendLocked(p)
		return
	}
	if len(s.flows) == 0 && len(s.waiting) == 0 {
		u.openLocked(s, p)
		return
	}
	if len(s.waiting) >= udpHeldLimit {
		errors.LogDebug(context.Background(), "drop udp with size ", len(p.data), " > route queue full")
		return
	}
	s.waiting = append(s.waiting, p)
	if !s.routing {
		s.routing = true
		go u.routeWaiting(s)
		return
	}
	s.wakeLocked()
}

// routeWaiting finds a flow for each packet of s that waits for one, oldest first, off the packet
// path. It asks the dispatcher where the packets waiting for a destination would be routed as the
// first packets of a flow of their own (session.FlowRoute.RouteOf: their destination, and what
// sniffing finds in them; as long as routing takes: a rule may look up a process or a name), and
// sends them in the source's flow that went there, or in a new flow of their own when none did —
// which the dispatcher then sniffs and routes as it does every flow. A destination the policy gives
// a flow of its own (ownFlow: an address of fake DNS) is matched against none: when its datagram is
// the next one in line it opens a flow, ahead of the wait for flows that have not reported, and no
// route is asked for. Behind a datagram that waits for a flow or an answer it waits too: the queue
// is the source's, not a destination's. It passes one that waits only for the rest of its packets,
// as every destination does (below).
//
// Packets that cannot tell their route yet (a ClientHello split over two QUIC Initials, and only the
// first is here) wait for the rest, as the dispatcher's sniffing waits for a new flow's next
// packets: they are asked about again, together with the next packet to their destination, and past
// sniffWait they are routed with nothing sniffed. The source's other destinations are routed
// meanwhile. A flow opened for them instead would hold a proxy association of its own for each such
// destination, and the source's next destinations would wait for its sniffing.
//
// A flow of the source that has not been routed yet is waited for first, for at most routeWait:
// until it reports, nobody knows where it goes, and a destination matched against it could land on
// another route than its own.
func (u *udpConnectionHandler) routeWaiting(s *udpSource) {
	u.Lock()
	defer u.Unlock()
	untold := map[net.Destination]udpUntold{} // destinations whose packets wait for the rest
	for !s.gone && len(s.waiting) > 0 {
		p, until := s.nextLocked(untold, time.Now())
		if p == nil {
			u.waitLocked(s, until)
			continue
		}
		dst := *p.dest
		if conn := s.dests[dst]; conn != nil {
			delete(untold, dst)
			s.releaseLocked(dst, conn)
			continue
		}
		if len(s.flows) == 0 {
			delete(untold, dst)
			s.releaseLocked(dst, u.openLocked(s, s.takeLocked(dst)))
			continue
		}
		if own := u.policy.ownFlow; own != nil && own(dst) {
			// A destination with a flow of its own has nothing to be matched against and nothing to wait
			// for (udp_flow_policy.go). Its flow takes a place among the source's like any other: past
			// udpFlowLimit the one used least recently ends. Should udpDestLimit make the source forget
			// this destination while its flow lives, the next datagram opens a second flow for it. That
			// does no harm: the destination goes into the newer flow from then on, and the older one,
			// with nothing new to carry, ends as flows do: when its idle time runs out, its outbound is
			// done, or the limit is reached.
			delete(untold, dst)
			s.releaseLocked(dst, u.openLocked(s, s.takeLocked(dst)))
			continue
		}
		if unsettled := u.unsettledLocked(s); unsettled != nil {
			timer := time.NewTimer(time.Until(unsettled.opened.Add(u.routeWait)))
			u.Unlock()
			select {
			case <-unsettled.settled:
			case <-timer.C:
			}
			timer.Stop()
			u.Lock()
			continue
		}
		tag, known := "", false
		if routeOf := s.routeOf; routeOf != nil {
			datagrams := s.datagramsLocked(dst)
			waited, waiting := untold[dst]
			if waiting && (waited.late || len(datagrams) == waited.asked) {
				datagrams = nil // its time is up: nothing sniffed
			}
			asked := time.Now()
			u.Unlock()
			routed, err := routeOf(dst, datagrams)
			u.Lock()
			if s.gone || s.dests[dst] != nil || u.unsettledLocked(s) != nil {
				continue // the source changed meanwhile: look again
			}
			if err == protocol.ErrProtoNeedMoreData && len(datagrams) > 0 {
				if !waiting {
					waited.until = asked.Add(u.sniffWait)
				}
				waited.asked, waited.late = len(datagrams), !asked.Before(waited.until)
				untold[dst] = waited
				continue
			}
			tag, known = routed, err == nil
		}
		delete(untold, dst)
		var conn *udpConn
		if known {
			for _, flow := range s.flows {
				if flow.routed && flow.route == tag {
					conn = flow
					break
				}
			}
		}
		if conn == nil {
			conn = u.openLocked(s, s.takeLocked(dst))
		} else {
			s.setDestLocked(dst, conn)
		}
		s.releaseLocked(dst, conn)
	}
	s.routing = false
	u.forgetIfEmptyLocked(s)
}

// udpUntold is a destination whose waiting packets could not tell RouteOf their route yet.
type udpUntold struct {
	asked int       // how many of its packets RouteOf was last given
	until time.Time // when they are routed with nothing sniffed: sniffWait after the first question
	late  bool      // the last question was asked past `until`: the next one sniffs nothing
}

// nextLocked is the oldest packet of s that waits for a route and whose destination can be asked
// about now: any destination but an untold one with no packet since its last question and time
// left. With none, `until` is when the first of those runs out of time.
func (s *udpSource) nextLocked(untold map[net.Destination]udpUntold, now time.Time) (next *packet, until time.Time) {
	if len(untold) == 0 {
		return s.waiting[0], time.Time{}
	}
	count := make(map[net.Destination]int)
	for _, p := range s.waiting {
		count[*p.dest]++
	}
	for _, p := range s.waiting {
		waited, waiting := untold[*p.dest]
		if !waiting || count[*p.dest] > waited.asked || !now.Before(waited.until) {
			return p, time.Time{}
		}
		if until.IsZero() || waited.until.Before(until) {
			until = waited.until
		}
	}
	return nil, until
}

// waitLocked waits, with the handler's lock released, for news of s (wakeLocked) or until `until`.
func (u *udpConnectionHandler) waitLocked(s *udpSource, until time.Time) {
	timer := time.NewTimer(time.Until(until))
	u.Unlock()
	select {
	case <-s.wake:
	case <-timer.C:
	}
	timer.Stop()
	u.Lock()
}

// unsettledLocked is a flow of s whose route is not known yet and may still be reported.
func (u *udpConnectionHandler) unsettledLocked(s *udpSource) *udpConn {
	now := time.Now()
	for _, conn := range s.flows {
		if !conn.routed && now.Before(conn.opened.Add(u.routeWait)) {
			return conn
		}
	}
	return nil
}

// idleCheck ends a flow whose program has been quiet in it for the flow's idle time. Replies do not
// count.
func (u *udpConnectionHandler) idleCheck(conn *udpConn) {
	u.Lock()
	defer u.Unlock()
	if conn.retired.Load() {
		return
	}
	if conn.source.checking {
		conn.timer.Reset(conn.idle)
		return
	}
	if quiet := time.Since(conn.lastSent); quiet < conn.idle {
		conn.timer.Reset(conn.idle - quiet)
		return
	}
	u.retireLocked(conn)
}

// retireLocked ends a flow: its queue closed (the outbound reads EOF and winds down), its replies
// refused from now on, and out of its source, whose next packet to one of its destinations is
// routed again. A source left with nothing leaves the table (forgetIfEmptyLocked) — but not while it
// is being checked: its packets keep waiting behind the ones already held, instead of overtaking
// them in a flow of their own (rechecked delivers them).
//
// "From now on": every reply checks the flag before it is written (writeReply), so none starts
// once this has set it. A reply whose write had already begun finishes; retiring does not wait for
// it — this runs under the table's lock, which every source's packets need.
func (u *udpConnectionHandler) retireLocked(conn *udpConn) {
	if conn.retired.Load() {
		return
	}
	conn.retired.Store(true)
	if conn.timer != nil {
		conn.timer.Stop()
	}
	close(conn.egress)
	conn.settleLocked()
	s := conn.source
	s.flows = slices.DeleteFunc(s.flows, func(flow *udpConn) bool { return flow == conn })
	for dst, flow := range s.dests {
		if flow == conn {
			delete(s.dests, dst)
		}
	}
	u.forgetIfEmptyLocked(s)
}

// endLocked finishes every flow of s and takes it out of the table: its socket changed hands.
func (u *udpConnectionHandler) endLocked(s *udpSource) {
	for len(s.flows) > 0 {
		u.retireLocked(s.flows[0])
	}
	u.dropLocked(s)
}

// forgetIfEmptyLocked takes a source out of the table once it has nothing left: no flow, no check
// under way, no packet waiting for a route. Its next packet starts it afresh.
func (u *udpConnectionHandler) forgetIfEmptyLocked(s *udpSource) {
	if len(s.flows) == 0 && !s.checking && len(s.waiting) == 0 {
		u.dropLocked(s)
	}
}

// dropLocked takes s out of the table if the table still holds IT: a source that was ended early has
// a successor under the same key by then.
func (u *udpConnectionHandler) dropLocked(s *udpSource) {
	s.gone = true
	s.wakeLocked()
	if u.sources[s.src] == s {
		delete(u.sources, s.src)
	}
}

// connectionFinished runs when the flow's dispatch is over (udpConn.Close). A flow retired early is
// left as it is: its source, or the successor under the same key, is not its to end.
func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	u.Lock()
	u.retireLocked(conn)
	u.Unlock()
}

func (s *udpSource) holdLocked(p *packet) {
	if len(s.held) >= udpHeldLimit {
		errors.LogDebug(context.Background(), "drop udp with size ", len(p.data), " > re-check queue full")
		return
	}
	s.held = append(s.held, p)
}

// setDestLocked records the flow dst travels in, forgetting another destination when the source
// already remembers udpDestLimit.
func (s *udpSource) setDestLocked(dst net.Destination, conn *udpConn) {
	if _, known := s.dests[dst]; !known && len(s.dests) >= udpDestLimit {
		for other := range s.dests {
			delete(s.dests, other)
			break
		}
	}
	s.dests[dst] = conn
}

// wakeLocked tells routeWaiting, if it waits for more of a destination's packets (waitLocked), that
// there is news: another packet waits, or the source is gone. One pending word is enough.
func (s *udpSource) wakeLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// datagramsLocked is what waits for dst, in the order the program sent it.
func (s *udpSource) datagramsLocked(dst net.Destination) [][]byte {
	var datagrams [][]byte
	for _, p := range s.waiting {
		if *p.dest == dst {
			datagrams = append(datagrams, p.data)
		}
	}
	return datagrams
}

// takeLocked removes the first waiting packet to dst and returns it.
func (s *udpSource) takeLocked(dst net.Destination) *packet {
	i := slices.IndexFunc(s.waiting, func(p *packet) bool { return *p.dest == dst })
	p := s.waiting[i]
	s.waiting = slices.Delete(s.waiting, i, i+1)
	return p
}

// releaseLocked sends every waiting packet to dst into conn, in order.
func (s *udpSource) releaseLocked(dst net.Destination, conn *udpConn) {
	s.waiting = slices.DeleteFunc(s.waiting, func(p *packet) bool {
		if *p.dest != dst {
			return false
		}
		conn.sendLocked(p)
		return true
	})
}

// udp connection abstraction: one flow of a source, handed to the dispatcher once and routed once.
type udpConn struct {
	handler *udpConnectionHandler
	source  *udpSource

	egress chan *packet
	src    net.Destination
	dst    net.Destination // its first packet's destination

	// guarded by the handler's lock, except retired, which is set under it and read by the replies
	// without it. A retired flow is in no source: nothing hands a packet to a closed queue.
	opened        time.Time
	lastSent      time.Time // when the program last sent in this flow; replies do not move it
	used          uint64    // the handler's sends when the program last sent in this flow
	idle          time.Duration
	timer         *time.Timer
	retired       atomic.Bool
	route         string        // the outbound the dispatcher handed the flow to (settle)
	routed        bool          // route holds the dispatcher's report
	settled       chan struct{} // closed once the flow is routed or retired
	settledClosed bool
}

// settle is the dispatcher's report on the flow (session.FlowRoute), made after it routed the flow
// and before it hands the flow to the outbound: where the flow went, and how the source's other
// destinations are routed.
func (c *udpConn) settle(route session.FlowRoute) {
	u := c.handler
	u.Lock()
	defer u.Unlock()
	if c.routed || c.retired.Load() {
		return
	}
	c.route, c.routed = route.Tag, true
	c.settleLocked()
	if s := c.source; s.routeOf == nil {
		s.routeOf = route.RouteOf
	}
}

func (c *udpConn) settleLocked() {
	if !c.settledClosed {
		c.settledClosed = true
		close(c.settled)
	}
}

func (c *udpConn) sendLocked(p *packet) {
	c.lastSent = time.Now()
	c.handler.sends++
	c.used = c.handler.sends
	select {
	case c.egress <- p:
	default:
		errors.LogDebug(context.Background(), "drop udp with size ", len(p.data), " to ", p.dest.NetAddr(), " original ", c.dst.NetAddr(), " > queue full")
	}
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		e, ok := <-c.egress
		if !ok {
			return nil, io.EOF
		}

		b := buf.New()
		if _, err := b.Write(e.data); err != nil {
			errors.LogErrorInner(context.Background(), err, "drop packet to ", e.dest, " with size ", len(e.data))
			b.Release()
			continue
		}
		b.UDP = e.dest

		return buf.MultiBuffer{b}, nil
	}
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	e, ok := <-c.egress
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, e.data)
	if n != len(e.data) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

// writeReply writes one reply to the tun side unless the flow has ended — checked for each reply,
// not once for a batch.
func (c *udpConn) writeReply(data []byte, dst net.Destination) error {
	if c.retired.Load() {
		return errUDPFlowRetired
	}
	return c.handler.writePacket(data, dst, c.src)
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		err := c.writeReply(b.Bytes(), dst)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	// sending packets back mean sending payload with source/destination reversed
	err := c.writeReply(p, c.dst)
	if err == errUDPFlowRetired {
		return 0, err
	}
	if err != nil {
		return 0, nil
	}

	return len(p), nil
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *udpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}
