package session

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// connSeq numbers the dispatches whose ends are reported, from 1, for the life of the process.
var connSeq atomic.Uint64

// ConnReport follows one dispatch while its router reports ends: its number, when it came in, the
// payload bytes and the times of its two directions, and the error its outbound gave. It is the
// error tracker of the dispatch's context; a tracker that was there before still gets every error.
type ConnReport struct {
	// Conn is unique in this process, unlike the session ID, which is random and shared by every
	// dispatch of one inbound connection.
	Conn uint64

	start time.Time
	up    reportDirection
	down  reportDirection

	mu   sync.Mutex
	err  error
	prev TrackedRequestErrorFeedback
}

type reportDirection struct {
	bytes atomic.Int64
	first atomic.Int64 // nanoseconds since start, plus one; 0 means no byte yet
	last  atomic.Int64
}

type connReportKey struct{}

type routeProbeKey struct{}

// WithConnReport starts the report of a dispatch: it numbers the dispatch and becomes the error
// tracker of the returned context.
func WithConnReport(ctx context.Context) (context.Context, *ConnReport) {
	r := &ConnReport{Conn: connSeq.Add(1), start: time.Now()}
	if prev, ok := ctx.Value(trackedConnectionErrorKey).(TrackedRequestErrorFeedback); ok {
		r.prev = prev
	}
	ctx = context.WithValue(ctx, connReportKey{}, r)
	return TrackedConnectionError(ctx, r), r
}

// ConnReportFromContext is the report of the dispatch in ctx, or nil when ends are not reported.
func ConnReportFromContext(ctx context.Context) *ConnReport {
	r, _ := ctx.Value(connReportKey{}).(*ConnReport)
	return r
}

// ContextWithRouteProbe marks a routing question asked for another destination of a flow rather
// than the routing of the dispatch itself.
func ContextWithRouteProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, routeProbeKey{}, true)
}

// IsRouteProbe tells whether ctx carries that mark.
func IsRouteProbe(ctx context.Context) bool {
	probe, _ := ctx.Value(routeProbeKey{}).(bool)
	return probe
}

// SubmitError implements TrackedRequestErrorFeedback. The first error stays.
func (r *ConnReport) SubmitError(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	if r.prev != nil {
		r.prev.SubmitError(err)
	}
}

// Err is the first error the outbound submitted, or nil.
func (r *ConnReport) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Up counts the program-to-destination payload, Down the way back.
func (r *ConnReport) Up() *ReportCounter { return &ReportCounter{report: r, dir: &r.up} }

func (r *ConnReport) Down() *ReportCounter { return &ReportCounter{report: r, dir: &r.down} }

// ReportCounter is a stats.Counter over one direction of a report. Only Add means anything: nothing
// resets the bytes of a dispatch, so Set leaves them.
type ReportCounter struct {
	report *ConnReport
	dir    *reportDirection
}

func (c *ReportCounter) Value() int64 { return c.dir.bytes.Load() }

func (c *ReportCounter) Set(int64) int64 { return c.dir.bytes.Load() }

func (c *ReportCounter) Add(delta int64) int64 {
	if delta > 0 {
		at := int64(time.Since(c.report.start)) + 1
		c.dir.first.CompareAndSwap(0, at)
		c.dir.last.Store(at)
	}
	return c.dir.bytes.Add(delta) - delta
}

// ConnTotals is a report read at its end. Times are milliseconds since the dispatch came in, -1
// where there was no such byte.
type ConnTotals struct {
	DurMs, FirstDownMs, LastUpMs, LastDownMs, Up, Down int64
}

func (r *ConnReport) Totals() ConnTotals {
	ms := func(at int64) int64 {
		if at == 0 {
			return -1
		}
		return (at - 1) / int64(time.Millisecond)
	}
	return ConnTotals{
		DurMs:       time.Since(r.start).Milliseconds(),
		FirstDownMs: ms(r.down.first.Load()),
		LastUpMs:    ms(r.up.last.Load()),
		LastDownMs:  ms(r.down.last.Load()),
		Up:          r.up.bytes.Load(),
		Down:        r.down.bytes.Load(),
	}
}
