package dispatcher

import (
	"context"
	stderrors "errors"
	"io"
	stdnet "net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// endRouter routes every dispatch to `tag` ("" — no rule matched) and says whether ends are reported.
type endRouter struct {
	routing.Router
	reports bool
	tag     string
	ends    chan routing.ConnEnd
	mu      sync.Mutex
	asked   []routing.Context
}

func (r *endRouter) ReportsEnd() bool { return r.reports }

func (r *endRouter) PickRoute(ctx routing.Context) (routing.Route, error) {
	r.mu.Lock()
	r.asked = append(r.asked, ctx)
	r.mu.Unlock()
	if r.tag == "" {
		return nil, common.ErrNoClue
	}
	return &endRoute{tag: r.tag, ends: r.ends}, nil
}

type endRoute struct {
	routing.Route
	tag  string
	ends chan routing.ConnEnd
}

func (r *endRoute) GetOutboundTag() string        { return r.tag }
func (r *endRoute) GetRuleTag() string            { return "main" }
func (r *endRoute) ReportEnd(end routing.ConnEnd) { r.ends <- end }

// pumpHandler reads the link to its end, answers `reply`, and submits `fail` as an outbound would.
type pumpHandler struct {
	outbound.Handler
	tag   string
	reply []byte
	fail  error
	seen  chan *transport.Link
	ctxs  chan context.Context
}

func (h *pumpHandler) Tag() string { return h.tag }

func (h *pumpHandler) Dispatch(ctx context.Context, link *transport.Link) {
	if h.seen != nil {
		h.seen <- link
	}
	if h.ctxs != nil {
		h.ctxs <- ctx
	}
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err != nil {
			break
		}
	}
	if len(h.reply) > 0 {
		link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, h.reply))
	}
	if h.fail != nil {
		session.SubmitOutboundErrorToOriginator(ctx, h.fail)
	}
	common.Close(link.Writer)
}

type endOutbounds struct {
	outbound.Manager
	handlers map[string]outbound.Handler
}

func (m endOutbounds) GetHandler(tag string) outbound.Handler { return m.handlers[tag] }
func (m endOutbounds) GetDefaultHandler() outbound.Handler    { return nil }

func endDispatcher(reports bool, routeTo string, handler *pumpHandler) (*DefaultDispatcher, *endRouter) {
	router := &endRouter{reports: reports, tag: routeTo, ends: make(chan routing.ConnEnd, 4)}
	handlers := map[string]outbound.Handler{}
	if handler != nil {
		handlers[handler.tag] = handler
	}
	return &DefaultDispatcher{ohm: endOutbounds{handlers: handlers}, router: router}, router
}

func endCtx() context.Context {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag: "tun", Name: "tun", Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 53811),
	})
	return session.ContextWithContent(ctx, &session.Content{})
}

var endTarget = net.TCPDestination(net.ParseAddress("203.0.113.10"), 443)

func readAll(r buf.Reader) []byte {
	var got []byte
	for {
		mb, err := r.ReadMultiBuffer()
		for _, b := range mb {
			got = append(got, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			return got
		}
	}
}

// viaDispatchLink pushes `up` through DispatchLink and returns what came back down.
func viaDispatchLink(t *testing.T, d *DefaultDispatcher, ctx context.Context, target net.Destination, up []byte) []byte {
	t.Helper()
	upReader, upWriter := pipe.New()
	downReader, downWriter := pipe.New()
	upWriter.WriteMultiBuffer(buf.MergeBytes(nil, up))
	common.Close(upWriter)
	done := make(chan error, 1)
	go func() { done <- d.DispatchLink(ctx, target, &transport.Link{Reader: upReader, Writer: downWriter}) }()
	down := readAll(downReader)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return down
}

// viaDispatch pushes `up` through Dispatch and returns what came back down.
func viaDispatch(t *testing.T, d *DefaultDispatcher, ctx context.Context, up []byte) []byte {
	t.Helper()
	link, err := d.Dispatch(ctx, endTarget)
	if err != nil {
		t.Fatal(err)
	}
	link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, up))
	common.Close(link.Writer)
	return readAll(link.Reader)
}

func nextEnd(t *testing.T, ends chan routing.ConnEnd) routing.ConnEnd {
	t.Helper()
	select {
	case end := <-ends:
		return end
	case <-time.After(5 * time.Second):
		t.Fatal("no end was reported")
		return routing.ConnEnd{}
	}
}

func noEnd(t *testing.T, ends chan routing.ConnEnd) {
	t.Helper()
	select {
	case end := <-ends:
		t.Fatalf("an end was reported: %+v", end)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWithoutReportEndTheDispatchIsAsUpstreamHasIt(t *testing.T) {
	handler := &pumpHandler{tag: "proxy", seen: make(chan *transport.Link, 2), ctxs: make(chan context.Context, 2)}
	d, router := endDispatcher(false, "proxy", handler)

	viaDispatchLink(t, d, endCtx(), endTarget, []byte("hello"))
	link, ctx := <-handler.seen, <-handler.ctxs
	if session.ConnReportFromContext(ctx) != nil {
		t.Fatal("DispatchLink put a report in ctx")
	}
	if _, wrapped := link.Writer.(*SizeStatWriter); wrapped {
		t.Fatal("DispatchLink wrapped the writer")
	}
	if link.Reader.(*buf.TimeoutWrapperReader).Counter != nil {
		t.Fatal("DispatchLink counts the reader")
	}

	inbound, err := d.Dispatch(endCtx(), endTarget)
	if err != nil {
		t.Fatal(err)
	}
	if _, plain := inbound.Writer.(*pipe.Writer); !plain {
		t.Fatalf("Dispatch wrapped the inbound writer in %T", inbound.Writer)
	}
	common.Close(inbound.Writer)
	<-handler.seen
	if session.ConnReportFromContext(<-handler.ctxs) != nil {
		t.Fatal("Dispatch put a report in ctx")
	}
	noEnd(t, router.ends)
}

func TestTheEndCarriesTheTotalsOfBothPaths(t *testing.T) {
	for _, path := range []string{"DispatchLink", "Dispatch"} {
		t.Run(path, func(t *testing.T) {
			handler := &pumpHandler{tag: "proxy", reply: []byte("seven!!")}
			d, router := endDispatcher(true, "proxy", handler)
			var down []byte
			if path == "Dispatch" {
				down = viaDispatch(t, d, endCtx(), []byte("hello"))
			} else {
				down = viaDispatchLink(t, d, endCtx(), endTarget, []byte("hello"))
			}
			end := nextEnd(t, router.ends)
			if string(down) != "seven!!" || end.Up != 5 || end.Down != 7 || end.Error != "" || end.Conn == 0 {
				t.Fatalf("down %q, end %+v", down, end)
			}
			if end.FirstDownMs < 0 || end.LastUpMs < 0 || end.LastDownMs < end.FirstDownMs || end.DurMs < end.LastDownMs || end.TsMs <= 0 {
				t.Fatalf("times of the end: %+v", end)
			}
			noEnd(t, router.ends) // exactly one end per dispatch
		})
	}
}

// A dial through the real retry, wrapped as the outbound handler wraps a failure. Fewer attempts
// than the outbounds' five: the shape of the error is the same, the test is shorter.
func viaRetry(dial func() error) error {
	return errors.New("failed to process outbound traffic").Base(retry.ExponentialBackoff(2, 10).On(dial))
}

func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	l, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	return address
}

func TestTheOutboundsErrorIsClassed(t *testing.T) {
	refusedDial := viaRetry(func() error {
		_, err := (&stdnet.Dialer{Timeout: 5 * time.Second}).Dial("tcp", closedLoopbackPort(t))
		return err
	})
	if stderrors.Is(refusedDial, refusedErrno) {
		t.Fatal("errors.Is sees the errno through retry: the refused case no longer tests the walk")
	}
	timeoutDial := viaRetry(func() error {
		_, err := (&stdnet.Dialer{Timeout: time.Millisecond}).Dial("tcp", "192.0.2.1:80")
		return err
	})
	timedOutErrnoDial := viaRetry(func() error {
		return &stdnet.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", timedOutErrno)}
	})
	cases := []struct {
		name    string
		err     error
		network net.Network
		want    string
	}{
		{"refused dial through retry", refusedDial, net.Network_TCP, "refused"},
		{"timed out dial through retry", timeoutDial, net.Network_TCP, "timeout"},
		{"timed out errno through retry", timedOutErrnoDial, net.Network_TCP, "timeout"},
		{"socks REP 2", errors.New("server rejects request: ", byte(2)), net.Network_TCP, "refused"},
		{"socks REP 5", errors.New("server rejects request: ", byte(5)), net.Network_TCP, "refused"},
		{"socks REP 7 on udp", errors.New("server rejects request: ", byte(7)), net.Network_UDP, "udp-not-supported"},
		{"socks REP 7 on tcp", errors.New("server rejects request: ", byte(7)), net.Network_TCP, "other"},
		{"http not 200 through retry", viaRetry(func() error {
			return errors.New("Proxy responded with non 200 code: 407 Proxy Authentication Required")
		}), net.Network_TCP, "refused"},
		{"http outbound without udp", errors.New("UDP is not supported by HTTP outbound"), net.Network_UDP, "udp-not-supported"},
		{"deadline", errors.New("dial").Base(context.DeadlineExceeded), net.Network_TCP, "timeout"},
		{"foreign", errors.New("tls: handshake failure"), net.Network_TCP, "other"},
		{"eof", io.EOF, net.Network_TCP, ""},
		{"canceled", context.Canceled, net.Network_TCP, ""},
		{"none", nil, net.Network_TCP, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err, tc.network); got != tc.want {
				t.Fatalf("class %q, want %q (error: %v)", got, tc.want, tc.err)
			}
		})
	}
}

func TestEarlyExits(t *testing.T) {
	t.Run("a rule names an outbound that does not exist: the start went out, so the end does", func(t *testing.T) {
		d, router := endDispatcher(true, "gone", &pumpHandler{tag: "proxy"})
		viaDispatchLink(t, d, endCtx(), endTarget, []byte("x"))
		if end := nextEnd(t, router.ends); end.Error != "other" {
			t.Fatalf("end %+v, want class other", end)
		}
		noEnd(t, router.ends) // exactly one end per dispatch
	})
	t.Run("a forced tag without its outbound: no start, no end", func(t *testing.T) {
		d, router := endDispatcher(true, "proxy", &pumpHandler{tag: "proxy"})
		viaDispatchLink(t, d, session.SetForcedOutboundTagToContext(endCtx(), "missing"), endTarget, []byte("x"))
		noEnd(t, router.ends)
	})
	t.Run("no rule and no default outbound: no start, no end", func(t *testing.T) {
		d, router := endDispatcher(true, "", nil)
		viaDispatchLink(t, d, endCtx(), endTarget, []byte("x"))
		noEnd(t, router.ends)
	})
}

func TestRouteOfAsksAsAProbeOfItsFlow(t *testing.T) {
	d, router := endDispatcher(true, "proxy", &pumpHandler{tag: "proxy"})
	ctx, report := session.WithConnReport(endCtx())
	if _, err := d.routeOf(ctx, net.UDPDestination(net.ParseAddress("198.51.100.7"), 3478), nil); err != nil {
		t.Fatal(err)
	}
	asked := router.asked[len(router.asked)-1].(*routing_session.Context)
	if !asked.Probe || asked.Report != report {
		t.Fatalf("probe %v, the flow's report %v", asked.Probe, asked.Report == report)
	}
}

type tracker struct{ got []error }

func (t *tracker) SubmitError(err error) { t.got = append(t.got, err) }

func TestATrackerAlreadyInCtxStillGetsTheError(t *testing.T) {
	failure := errors.New("tls: handshake failure")
	d, router := endDispatcher(true, "proxy", &pumpHandler{tag: "proxy", fail: failure})
	before := &tracker{}
	viaDispatchLink(t, d, session.TrackedConnectionError(endCtx(), before), endTarget, []byte("x"))
	if end := nextEnd(t, router.ends); end.Error != "other" {
		t.Fatalf("end %+v", end)
	}
	if len(before.got) != 1 || before.got[0] != failure {
		t.Fatalf("the tracker before got %v", before.got)
	}
}

type severityTrap struct {
	mu   sync.Mutex
	seen []log.Message
}

func (s *severityTrap) Handle(msg log.Message) {
	if m, ok := msg.(*log.GeneralMessage); ok && m.Severity <= log.Severity_Warning {
		s.mu.Lock()
		s.seen = append(s.seen, msg)
		s.mu.Unlock()
	}
}

func TestReportingEndsWritesNoWarning(t *testing.T) {
	trap := &severityTrap{}
	log.RegisterHandler(trap)
	// common/log gives no way to read the handler back, and RegisterHandler(nil) panics: an empty
	// trap stands in for the handler-less log a test binary starts with.
	defer log.RegisterHandler(&severityTrap{})
	d, router := endDispatcher(true, "proxy", &pumpHandler{tag: "proxy", fail: errors.New("tls: handshake failure"), reply: []byte("x")})
	viaDispatchLink(t, d, endCtx(), endTarget, []byte("x"))
	nextEnd(t, router.ends)
	trap.mu.Lock()
	defer trap.mu.Unlock()
	if len(trap.seen) != 0 {
		t.Fatalf("lines at warning or above: %v", trap.seen)
	}
}
