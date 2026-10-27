package dispatcher

import (
	"context"
	goerrors "errors"
	"io"
	stdnet "net"
	"strings"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
)

// errNoOutbound ends a dispatch whose rule names an outbound that does not exist: its start has
// gone out, so its end goes out too, classed as other.
var errNoOutbound = errors.New("no outbound has the tag of the rule")

// withConnReport starts the report of a dispatch when the router reports ends. Otherwise ctx stays
// as it is, and nothing below wraps a link or reads a clock.
func (d *DefaultDispatcher) withConnReport(ctx context.Context) context.Context {
	reporting, ok := d.router.(routing.EndReporting)
	if !ok || !reporting.ReportsEnd() {
		return ctx
	}
	ctx, _ = session.WithConnReport(ctx)
	return ctx
}

// reportEnd sends the end of a dispatch through the route whose rule sent its start. early is the
// reason of an early exit, nil once the outbound is done.
func (d *DefaultDispatcher) reportEnd(ctx context.Context, route routing.Route, early error) {
	report := session.ConnReportFromContext(ctx)
	if report == nil || route == nil {
		return
	}
	reporter, ok := route.(routing.ConnEndReporter)
	if !ok {
		return
	}
	err := report.Err()
	if early != nil {
		err = early
	}
	t := report.Totals()
	reporter.ReportEnd(routing.ConnEnd{
		Conn: report.Conn, TsMs: time.Now().UnixMilli(), DurMs: t.DurMs,
		FirstDownMs: t.FirstDownMs, LastUpMs: t.LastUpMs, LastDownMs: t.LastDownMs,
		Up: t.Up, Down: t.Down, Error: classify(err, networkOf(ctx)),
	})
}

func networkOf(ctx context.Context) net.Network {
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		return outbounds[len(outbounds)-1].Target.Network
	}
	return net.Network_Unknown
}

// classify names the error an outbound gave in one word, "" for none. Only the word leaves the
// engine: the text of the error carries addresses.
//
// A dial error comes wrapped by retry.On, whose Unwrap leads only to retry.ErrRetryFailed; the
// attempts are in the message, so the tree is walked by hand (anyCause). Errno is compared by
// number: Windows may word it in the system's language, and Timeout() of WSAETIMEDOUT is false.
func classify(err error, network net.Network) string {
	if err == nil || isNormalEnd(err) {
		return ""
	}
	text := err.Error()
	if network == net.Network_UDP &&
		(strings.Contains(text, "server rejects request: 7") || strings.Contains(text, "UDP is not supported by HTTP outbound")) {
		return "udp-not-supported"
	}
	if anyCause(err, isRefused) || strings.Contains(text, "server rejects request: 2") ||
		strings.Contains(text, "server rejects request: 5") || strings.Contains(text, "Proxy responded with non 200 code") {
		return "refused"
	}
	if anyCause(err, isTimeout) {
		return "timeout"
	}
	return "other"
}

// isNormalEnd is what the outbound handler itself turns into no error (outbound/handler.go).
func isNormalEnd(err error) bool {
	cause := errors.Cause(err)
	return goerrors.Is(cause, io.EOF) || goerrors.Is(cause, io.ErrClosedPipe) || goerrors.Is(cause, context.Canceled)
}

// maxCauses bounds the walk of one error tree.
const maxCauses = 64

// anyCause walks err's tree: Unwrap() error, Unwrap() []error, and the errors an *errors.Error
// keeps in its message (YozhCauses).
func anyCause(err error, match func(error) bool) bool {
	pending := []error{err}
	for visited := 0; len(pending) > 0 && visited < maxCauses; visited++ {
		e := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if e == nil {
			continue
		}
		if match(e) {
			return true
		}
		if xe, ok := e.(*errors.Error); ok {
			pending = append(pending, xe.YozhCauses()...)
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			pending = append(pending, u.Unwrap()...)
		case interface{ Unwrap() error }:
			pending = append(pending, u.Unwrap())
		}
	}
	return false
}

func isRefused(err error) bool {
	errno, ok := err.(syscall.Errno)
	return ok && errno == refusedErrno
}

func isTimeout(err error) bool {
	if err == context.DeadlineExceeded {
		return true
	}
	if errno, ok := err.(syscall.Errno); ok {
		return errno == timedOutErrno
	}
	timeout, ok := err.(stdnet.Error)
	return ok && timeout.Timeout()
}

// pairCounter adds to the user's counter and to the report's at once; its value is the user's.
type pairCounter struct {
	primary, extra stats.Counter
}

func (c pairCounter) Value() int64      { return c.primary.Value() }
func (c pairCounter) Set(v int64) int64 { return c.primary.Set(v) }
func (c pairCounter) Add(delta int64) int64 {
	c.extra.Add(delta)
	return c.primary.Add(delta)
}

func bothCounters(primary, extra stats.Counter) stats.Counter {
	if primary == nil {
		return extra
	}
	return pairCounter{primary: primary, extra: extra}
}
