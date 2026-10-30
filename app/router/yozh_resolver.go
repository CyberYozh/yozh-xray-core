package router

// Routing by application for the macOS client ("yozh" labels).
//
// A `process` entry spelled `yozh:rule-<N>`, `yozh:unresolved` or `yozh:nolocal` is not a process
// name. It is a label the app's config builder put there, and the engine does not look the owner
// of the connection up itself: it asks the routing resolver, a service in the app's root component
// that owns the socket table, the process trees and the rules, over a unix socket whose path is in
// YOZH_ROUTING_SOCKET. The resolver answers with a verdict — `rule N`, `none`, `failed`,
// `nolocal` — and a label matches when the verdict is its own:
//
//	yozh:rule-N      the answer "rule N"
//	yozh:unresolved  the answer "failed" (the owner could not be determined, or the resolver did
//	                 not answer in time: the config sends this through the base proxy, never direct)
//	yozh:nolocal     the answer "nolocal" (no local socket: VM or internet-sharing traffic)
//
// Wire, one line per message, "\n"-terminated, numbers in decimal:
//
//	question  <reqid> q <tcp|udp> <src ip> <src port> <dst ip> <dst port>
//	answer    <reqid> a <rule N|none|failed|nolocal>
//
// The destination is the ORIGINAL target (session.Outbound.OriginalTarget), not the one routing
// sees: with sniffing and routeOnly=false the dispatcher replaces the target with the sniffed name
// before routing (app/dispatcher/default.go), so GetTargetIPs() is empty exactly for the flows a
// host rule could name, and the socket table knows only the address the application dialled.
//
// Why a question per routing pass and not per label. The config carries labels in several rules
// (the app's order puts host rules between them), and the router walks rules one by one. Every
// label of one connection must see the SAME verdict — a pass that saw "failed" at one label and
// "rule 1" at a later one skips both the failure's row and the rule's and falls to a tail that may
// send it direct, although rule 1 blocks the program. So Router.PickRoute wraps the context it is
// given in a yozhPass, the first label of the call asks, and the pass itself keeps the answer for
// the rest of the call — both walks of IpIfNonMatch included. Nothing else holds it: it is not in a
// shared cache that thousands of other connections routed between two labels could push it out of,
// and it ends with the call, so no later connection on the same addresses (under the tunnel every
// program has the utun's source address, and the kernel hands a closed socket's port out again)
// is ever given an earlier one's verdict without a question. A label applied outside a pass has
// nowhere to keep an answer; it asks nothing and is a failure.
//
// Why a failure is an answer ("failed") and never "no match". A label that silently did not match
// would let the connection fall past every yozh rule into the config's tail, which may be "direct".
// A failure matches yozh:unresolved instead, and the config sends that through the base proxy.
//
// Starting is all or nothing: a config with yozh labels and no YOZH_ROUTING_SOCKET, or with a socket
// that does not open or that another user listens on (checkPeer), refuses to build its router, and
// the engine exits ("Failed to start", code 23) instead of running with rules that could never match
// or that a stranger answers.
//
// Privacy: nothing here logs an address, a port or a verdict. The resolver answers with a rule
// number or a word, never with a path.

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	routing_dns "github.com/xtls/xray-core/features/routing/dns"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

const (
	// yozhSocketEnv names the resolver's unix socket. Only the app's root component sets it.
	yozhSocketEnv = "YOZH_ROUTING_SOCKET"
	// yozhOpenTimeout bounds the one dial at start. The resolver listens before the engine is
	// spawned, so a socket that is there answers the dial at once; this is the ceiling for one
	// that is not.
	yozhOpenTimeout = time.Second
	// yozhMaxLine: an answer line is at most ~40 bytes; a longer one is a broken peer, and the
	// connection is dropped rather than buffered without end.
	yozhMaxLine = 256
	// yozhMaxRule mirrors the label pattern's three digits.
	yozhMaxRule = 999
	// yozhStallLimit: a connection whose writes have found no room for this long, with no question
	// written and no line read since, is stuck and is dialled again (ask).
	yozhStallLimit = time.Second
	// yozhRedialPause, yozhRedialPauseMax: the pause before the next dial once connections have
	// failed twice in a row, doubling with every failure after, at most the max (failedLocked).
	yozhRedialPause    = 50 * time.Millisecond
	yozhRedialPauseMax = time.Second
)

// yozhAskTimeout: a question not answered by then is a failure (through the base). The engine never
// assigns it. It is a variable only for the tests: one whose subject is not the timeout sets a long
// one (UseYozhAskTimeoutForTest), so that a question the stub answered is never failed because the
// machine was too busy to hand the answer over within 50 ms.
var yozhAskTimeout = 50 * time.Millisecond

// yozhSocketPath is YOZH_ROUTING_SOCKET as the engine found it when it started: read once, while the
// package is initialised, before any config is read. A config's root "env" object is applied with
// os.Setenv while the config is built (infra/conf, Config.Build), before the router is; read then,
// the variable would be whatever the config said, and a config could name a resolver of its own.
var yozhSocketPath = os.Getenv(yozhSocketEnv)

// The only spellings a yozh label has. Case-sensitive on purpose: the app writes exactly these,
// and a "Yozh:rule-1" is refused (below) rather than read as a process name that never matches.
var yozhLabelPattern = regexp.MustCompile(`^yozh:(?:rule-([0-9]{1,3})|(unresolved)|(nolocal))$`)

type yozhAnswerKind uint8

const (
	yozhNone yozhAnswerKind = iota
	yozhRule
	yozhFailed
	yozhNoLocal
)

type yozhAnswer struct {
	kind yozhAnswerKind
	rule int
}

var yozhFailedAnswer = yozhAnswer{kind: yozhFailed}

// yozhLabels is the set of labels one rule's `process` list carries.
type yozhLabels struct {
	rules      map[int]bool
	unresolved bool
	nolocal    bool
}

func (l *yozhLabels) match(answer yozhAnswer) bool {
	switch answer.kind {
	case yozhRule:
		return l.rules[answer.rule]
	case yozhFailed:
		return l.unresolved
	case yozhNoLocal:
		return l.nolocal
	default:
		return false
	}
}

// parseYozhLabels answers (nil, nil) for a list with no yozh entry at all — upstream's matcher then
// takes it, untouched. An entry that starts with "yozh:" in any letter case, after any blanks, must
// be exactly one of the three labels, and labels may not share a list with process names: either
// would otherwise become a process name that never matches, and a block rule that never matches is
// a leak.
func parseYozhLabels(names []string) (*yozhLabels, error) {
	var labels *yozhLabels
	plain := 0
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "yozh:") {
			plain++
			continue
		}
		// The entry itself is not quoted into the error: whatever follows "yozh:" is not ours to
		// print.
		match := yozhLabelPattern.FindStringSubmatch(name)
		if match == nil {
			return nil, errors.New("a process entry starting with yozh: is not a routing label (yozh:rule-N, yozh:unresolved, yozh:nolocal)")
		}
		if labels == nil {
			labels = &yozhLabels{rules: map[int]bool{}}
		}
		switch {
		case match[1] != "":
			n, _ := strconv.Atoi(match[1]) // at most three digits: cannot fail
			labels.rules[n] = true
		case match[2] != "":
			labels.unresolved = true
		default:
			labels.nolocal = true
		}
	}
	if labels != nil && plain > 0 {
		return nil, errors.New("yozh routing labels cannot share a rule with process names")
	}
	return labels, nil
}

// newProcessCondition is what BuildCondition builds a rule's `process` list with (config.go).
func newProcessCondition(names []string) (*ProcessNameMatcher, error) {
	labels, err := parseYozhLabels(names)
	if err != nil {
		return nil, err
	}
	if labels == nil {
		return NewProcessNameMatcher(names), nil
	}
	resolver, err := yozhResolverFromEnvironment()
	if err != nil {
		return nil, err
	}
	return &ProcessNameMatcher{yozh: &yozhLabelMatch{labels: labels, resolver: resolver}}, nil
}

// yozhLabelMatch is what a ProcessNameMatcher made of labels does instead of a process lookup.
type yozhLabelMatch struct {
	labels   *yozhLabels
	resolver *yozhResolver
}

func (m *yozhLabelMatch) apply(ctx routing.Context) bool {
	return m.labels.match(m.resolver.answerFor(ctx))
}

// ---- The routing pass --------------------------------------------------------------------------

// yozhPass is one Router.PickRoute call: the context it was given, and the one answer every yozh
// label of the call reads (see the file comment). PickRoute runs its walks in one goroutine; the
// Once is there so that no caller could ever see two answers even if that changed.
type yozhPass struct {
	routing.Context
	once   sync.Once
	answer yozhAnswer
}

func newYozhPass(ctx routing.Context) routing.Context {
	return &yozhPass{Context: ctx}
}

// yozhPassOf finds the pass a label is applied in. The router may have wrapped it in a
// ResolvableContext (IpOnDemand, and the second walk of IpIfNonMatch).
func yozhPassOf(ctx routing.Context) *yozhPass {
	for {
		switch c := ctx.(type) {
		case *yozhPass:
			return c
		case *routing_dns.ResolvableContext:
			ctx = c.Context
		default:
			return nil
		}
	}
}

// ---- The question: network, source, original target -------------------------------------------

type yozhKey struct {
	network string // "tcp" | "udp"
	source  netip.AddrPort
	target  netip.AddrPort
}

// yozhKeyOf answers false when the connection has no key to ask about — no IP source, no IP
// original target, a network that is neither TCP nor UDP. The caller treats that as a failure.
func yozhKeyOf(ctx routing.Context) (yozhKey, bool) {
	var network string
	switch ctx.GetNetwork() {
	case xnet.Network_TCP:
		network = "tcp"
	case xnet.Network_UDP:
		network = "udp"
	default:
		return yozhKey{}, false
	}
	sources := ctx.GetSourceIPs()
	if len(sources) == 0 {
		return yozhKey{}, false
	}
	source, ok := yozhAddrPort(sources[0], ctx.GetSourcePort())
	if !ok {
		return yozhKey{}, false
	}
	inner := yozhUnwrap(ctx)
	targetIP, targetPort, ok := yozhOriginalTarget(inner)
	if !ok {
		return yozhKey{}, false
	}
	target, ok := yozhAddrPort(targetIP, targetPort)
	if !ok {
		return yozhKey{}, false
	}
	return yozhKey{network: network, source: source, target: target}, true
}

// yozhUnwrap answers the dispatcher's own routing context. The router may have wrapped it in a
// ResolvableContext (IpOnDemand / IpIfNonMatch), whose GetTargetIPs would resolve the SNIFFED name
// — so it is unwrapped, never asked.
func yozhUnwrap(ctx routing.Context) routing.Context {
	inner := ctx
	for {
		resolvable, ok := inner.(*routing_dns.ResolvableContext)
		if !ok {
			return inner
		}
		inner = resolvable.Context
	}
}

// yozhOriginalTarget digs the pre-sniffing destination out of an unwrapped routing context
// (yozhUnwrap).
func yozhOriginalTarget(inner routing.Context) (xnet.IP, xnet.Port, bool) {
	if session, ok := inner.(*routing_session.Context); ok && session.Outbound != nil {
		original := session.Outbound.OriginalTarget
		if original.IsValid() && original.Address != nil && original.Address.Family().IsIP() {
			return original.Address.IP(), original.Port, true
		}
	}
	// No OriginalTarget: every context the dispatcher builds has one (Dispatch, DispatchLink), so
	// this is some other caller's context. Its own target IP is the best there is; with none, there
	// is no key and the answer is a failure.
	if ips := inner.GetTargetIPs(); len(ips) > 0 {
		return ips[0], inner.GetTargetPort(), true
	}
	return nil, 0, false
}

// yozhAddrPort normalises IPv4-mapped IPv6 to IPv4, so one socket has one key and one spelling on
// the wire (the socket table records a dual-stack socket's IPv4 peer either way).
func yozhAddrPort(ip xnet.IP, port xnet.Port) (netip.AddrPort, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), true
}

// ---- The resolver client ---------------------------------------------------------------------

// yozhResolver is one connection to the resolver, shared by every label in the config. Questions
// carry a number and answers come back in any order; the reader hands each answer to the question
// with its number. A connection that breaks fails every question on it at once, and the next
// question dials again — after a pause when connections keep failing (failedLocked).
type yozhResolver struct {
	path    string
	timeout time.Duration
	peer    func(net.Conn) (uint32, error) // reads the listener's user (yozhPeerUID)
	// now and startTimer are the resolver's clock, time.Now and a time.Timer. The engine never
	// replaces them. They are fields only for the tests: a test of the stall limit, the pauses
	// between dials or a question's deadline puts in a clock that moves when the test moves it, so
	// that what it checks does not depend on how busy the machine is.
	now        func() time.Time
	startTimer func(time.Duration) (fired <-chan time.Time, stop func() bool)

	mu      sync.Mutex // guards everything below
	conn    net.Conn
	closed  bool
	nextID  uint64
	pending map[uint64]chan yozhAnswer
	// blocked: when the first write that found no room began, if none has been written and no line
	// read since; zero while the connection moves. Blocked for yozhStallLimit, it is stuck (ask).
	blocked time.Time
	// refusing: the last connection dialled was refused by the peer check, and that was logged. A
	// run of refusals is one line (a refused socket is dialled again and again); a connection that
	// passes ends it.
	refusing bool
	// answered: the connection has given a line. failures: connections that failed in a row — the
	// dial failed, the peer check refused it, or it was lost before it gave a line. redialAt: no
	// dial before then (failedLocked).
	answered bool
	failures int
	redialAt time.Time
}

func newYozhResolver(path string, timeout time.Duration) *yozhResolver {
	return &yozhResolver{
		path:       path,
		timeout:    timeout,
		peer:       yozhPeerUID,
		now:        time.Now,
		startTimer: yozhStartTimer,
		pending:    map[uint64]chan yozhAnswer{},
	}
}

func yozhStartTimer(d time.Duration) (<-chan time.Time, func() bool) {
	timer := time.NewTimer(d)
	return timer.C, timer.Stop
}

// The engine's one resolver. Keyed by path only so a test that points YOZH_ROUTING_SOCKET at a new
// stub gets a new client; an engine process builds its router once.
var yozhShared struct {
	sync.Mutex
	resolver *yozhResolver
}

func yozhResolverFromEnvironment() (*yozhResolver, error) {
	path := yozhSocketPath
	if path == "" {
		return nil, errors.New("the config routes by yozh labels but ", yozhSocketEnv, " is not set: refusing to start without the routing resolver")
	}
	yozhShared.Lock()
	defer yozhShared.Unlock()
	if current := yozhShared.resolver; current != nil && current.path == path {
		return current, nil
	}
	resolver := newYozhResolver(path, yozhAskTimeout)
	if err := resolver.open(yozhOpenTimeout); err != nil {
		return nil, errors.New("the routing resolver socket did not open: refusing to start").Base(err)
	}
	if previous := yozhShared.resolver; previous != nil {
		previous.close()
	}
	yozhShared.resolver = resolver
	return resolver, nil
}

// open is the dial at start: the one moment a missing resolver refuses the whole engine instead of
// failing one connection through the base.
func (r *yozhResolver) open(timeout time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.connectLocked(r.now().Add(timeout))
	return err
}

func (r *yozhResolver) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.conn != nil {
		r.dropLocked(r.conn)
	}
}

// connectLocked dials under the lock, and that is safe only because the socket is a unix one: an
// AF_UNIX connect completes or fails inside the kernel at once — ENOENT with no socket file,
// ECONNREFUSED with nobody listening or the accept queue full (XNU bsd/kern/uipc_usrreq.c,
// unp_connect: `sonewconn(so2, …) == 0` → ECONNREFUSED) — and never waits on a peer, so no
// question queues behind a dial for longer than a system call.
//
// While a pause after failed connections lasts (failedLocked), nothing is dialled: the question
// fails at once, as any question the resolver cannot answer does.
func (r *yozhResolver) connectLocked(deadline time.Time) (net.Conn, error) {
	if r.closed {
		return nil, errors.New("the routing resolver client is closed")
	}
	if r.conn != nil {
		return r.conn, nil
	}
	if r.now().Before(r.redialAt) {
		return nil, errYozhRedialPause
	}
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.Dial("unix", r.path)
	if err != nil {
		r.failedLocked()
		return nil, err
	}
	if err := yozhPeerCheck(r, conn); err != nil {
		conn.Close()
		r.failedLocked()
		if !r.refusing {
			r.refusing = true
			errors.LogWarningInner(context.Background(), err, "yozh routing resolver: refused the socket at the resolver's path; questions fail through the base until a connection passes the check")
		}
		return nil, err
	}
	r.refusing = false
	r.conn = conn
	r.answered = false
	r.blocked = time.Time{}
	go r.read(conn)
	return conn, nil
}

var errYozhRedialPause = errors.New("the routing resolver is not dialled again yet: its last connections failed")

// failedLocked counts a connection that failed: the dial failed, the peer check refused it, or it
// was lost before it gave a line. The first dial after a failure is made at once: a resolver that
// restarts drops the connection it had, answered or not, and the new one is dialled without a wait.
// From the second failure in a row the next dial waits yozhRedialPause, doubling with every failure
// after, at most yozhRedialPauseMax. Without the pause, a resolver that accepts and closes at once
// is dialled by every question. A line read on a connection ends the run (read).
func (r *yozhResolver) failedLocked() {
	r.failures++
	if r.failures < 2 {
		return
	}
	pause := yozhRedialPause
	for i := 2; i < r.failures && pause < yozhRedialPauseMax; i++ {
		pause *= 2
	}
	r.redialAt = r.now().Add(min(pause, yozhRedialPauseMax))
}

// yozhPeerCheck is the check every dialled resolver connection passes before a question is written
// on it: checkPeer. The engine never assigns it. It is a variable only for the tests: where the
// listener's user cannot be read (every platform but macOS, FreeBSD, Linux and Android), checkPeer
// refuses every resolver, and a test whose subject is anything else about the resolver lets its own
// stub through here.
var yozhPeerCheck = (*yozhResolver).checkPeer

// errYozhPeerUnreadable is yozhPeerUID's answer on a platform with no peer credential to read. It
// has a name so that the tests can tell that refusal from every other.
var errYozhPeerUnreadable = errors.New("the routing resolver's user cannot be read on this platform")

// checkPeer lets the engine talk only to a resolver of its own user. The resolver is the app's root
// component and the engine it serves runs as the same user; a socket at the resolver's path that
// another user listens on is not the resolver, whoever put it there, and its answers would route
// every program. It is refused before a question is written: at start the engine does not start,
// later the question fails (through the base) and the next one dials again.
func (r *yozhResolver) checkPeer(conn net.Conn) error {
	uid, err := r.peer(conn)
	if err != nil {
		return errors.New("the routing resolver's user cannot be read").Base(err)
	}
	if int64(uid) != int64(os.Geteuid()) {
		return errors.New("the routing resolver socket is another user's")
	}
	return nil
}

// dropLocked retires a connection: closed, and every question still waiting on it failed. A
// connection already replaced is left alone — its reader and a writer can both report it broken.
func (r *yozhResolver) dropLocked(conn net.Conn) {
	if r.conn != conn {
		return
	}
	r.conn = nil
	conn.Close()
	if !r.answered {
		r.failedLocked()
	}
	for id, reply := range r.pending {
		reply <- yozhFailedAnswer // buffered 1, and each id is removed before its one send
		delete(r.pending, id)
	}
}

func (r *yozhResolver) read(conn net.Conn) {
	lines := bufio.NewScanner(conn)
	lines.Buffer(make([]byte, 0, 64), yozhMaxLine)
	for lines.Scan() {
		id, answer, ok := parseYozhAnswer(lines.Text())
		r.mu.Lock()
		if r.conn == conn {
			r.blocked = time.Time{}
			r.answered = true
			r.failures = 0
		}
		if !ok {
			r.mu.Unlock()
			continue // no number to hand it to; its question fails at its timeout
		}
		reply, waiting := r.pending[id]
		delete(r.pending, id)
		r.mu.Unlock()
		if waiting {
			reply <- answer
		}
	}
	r.mu.Lock()
	live := r.conn == conn && !r.closed
	r.dropLocked(conn)
	r.mu.Unlock()
	if live {
		errors.LogWarning(context.Background(), "yozh routing resolver: connection lost; questions go through the base until it is back")
	}
}

// answerFor is a label's whole question: the pass's answer, asked by its first label. A connection
// with no key is a failure without a question; so is a label outside a pass.
func (r *yozhResolver) answerFor(ctx routing.Context) yozhAnswer {
	pass := yozhPassOf(ctx)
	if pass == nil {
		return yozhFailedAnswer
	}
	pass.once.Do(func() {
		pass.answer = yozhFailedAnswer
		if key, ok := yozhKeyOf(pass.Context); ok {
			pass.answer = r.ask(key)
		}
	})
	return pass.answer
}

// ask counts its deadline from the call, so the time it waits for the connection's lock is part of
// it. A question whose deadline passed while it waited fails by itself and touches nothing: it
// dials nothing and writes nothing. Dialled with that deadline, it would be a failed connection,
// and two of them pause every dial after (failedLocked); written with it, it would fail at once as
// a write that found no room, which counts towards a stuck connection.
//
// A write that fails is this question's failure. The connection is dropped (and every question on
// it failed) only when the stream is broken: part of the line went out, so the resolver would read
// the next question glued to half of this one, or the socket itself failed. A timeout with nothing
// written leaves the stream whole — a resolver that is slow for a moment keeps its connection —
// unless the connection is stuck: its writes have found no room for yozhStallLimit, counted from
// the start of the first of them, with no question written and no line read since. That is a
// resolver whose handler for this connection hangs while it serves others, and nothing else would
// notice: no EOF, no error, only writes that never find room. Kept, it would fail every question
// until the engine restarted; dropped, the next question dials again. The time the connection was
// quiet before is not counted: a connection with nothing to ask is not stuck, and its first slow
// write starts the count.
func (r *yozhResolver) ask(key yozhKey) yozhAnswer {
	deadline := r.now().Add(r.timeout)
	reply := make(chan yozhAnswer, 1)

	r.mu.Lock()
	if !r.now().Before(deadline) {
		r.mu.Unlock()
		return yozhFailedAnswer
	}
	conn, err := r.connectLocked(deadline)
	if err != nil {
		r.mu.Unlock()
		return yozhFailedAnswer
	}
	r.nextID++
	id := r.nextID
	r.pending[id] = reply
	conn.SetWriteDeadline(deadline)
	writing := r.now()
	if n, err := conn.Write(yozhQuestion(id, key)); err != nil {
		delete(r.pending, id)
		switch {
		case n > 0 || !os.IsTimeout(err):
			r.dropLocked(conn)
		default:
			if r.blocked.IsZero() {
				r.blocked = writing
			}
			if r.now().Sub(r.blocked) >= yozhStallLimit {
				r.dropLocked(conn)
				errors.LogWarning(context.Background(), "yozh routing resolver: the connection stopped taking questions; dialling again")
			}
		}
		r.mu.Unlock()
		return yozhFailedAnswer
	}
	r.blocked = time.Time{}
	r.mu.Unlock()

	fired, stop := r.startTimer(deadline.Sub(r.now()))
	defer stop()
	select {
	case answer := <-reply:
		return answer
	case <-fired:
	}
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
	// An answer that landed between the timer and the lock is taken; one that lands after this is
	// dropped by the reader (its number is no longer pending) and never overturns the failure.
	select {
	case answer := <-reply:
		return answer
	default:
		return yozhFailedAnswer
	}
}

func yozhQuestion(id uint64, key yozhKey) []byte {
	b := make([]byte, 0, 96)
	b = strconv.AppendUint(b, id, 10)
	b = append(b, " q "...)
	b = append(b, key.network...)
	b = append(b, ' ')
	b = key.source.Addr().AppendTo(b)
	b = append(b, ' ')
	b = strconv.AppendUint(b, uint64(key.source.Port()), 10)
	b = append(b, ' ')
	b = key.target.Addr().AppendTo(b)
	b = append(b, ' ')
	b = strconv.AppendUint(b, uint64(key.target.Port()), 10)
	return append(b, '\n')
}

// parseYozhAnswer answers ok=false only when the line has no usable number. A numbered line whose
// verdict is not one of the four words (or whose rule number is not 0…999) is a failure for that
// question, not something to wait out.
func parseYozhAnswer(line string) (uint64, yozhAnswer, bool) {
	fields := strings.Split(line, " ")
	if len(fields) < 3 || fields[1] != "a" {
		return 0, yozhAnswer{}, false
	}
	id, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, yozhAnswer{}, false
	}
	switch {
	case len(fields) == 4 && fields[2] == "rule":
		n, err := strconv.ParseUint(fields[3], 10, 16)
		if err != nil || n > yozhMaxRule {
			return id, yozhFailedAnswer, true
		}
		return id, yozhAnswer{kind: yozhRule, rule: int(n)}, true
	case len(fields) == 3 && fields[2] == "none":
		return id, yozhAnswer{kind: yozhNone}, true
	case len(fields) == 3 && fields[2] == "nolocal":
		return id, yozhAnswer{kind: yozhNoLocal}, true
	default:
		return id, yozhFailedAnswer, true
	}
}
