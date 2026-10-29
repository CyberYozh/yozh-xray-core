package session_test

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/stats"
)

var _ stats.Counter = (*session.ReportCounter)(nil)

func TestConnNumbersAreUniqueAcross64Goroutines(t *testing.T) {
	const goroutines, each = 64, 1000
	seen := make(chan uint64, goroutines*each)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				_, report := session.WithConnReport(context.Background())
				seen <- report.Conn
			}
		}()
	}
	wg.Wait()
	close(seen)
	unique := map[uint64]bool{}
	for conn := range seen {
		if conn == 0 {
			t.Fatal("conn 0: numbers start at 1")
		}
		if unique[conn] {
			t.Fatalf("conn %d given twice", conn)
		}
		unique[conn] = true
	}
	if len(unique) != goroutines*each {
		t.Fatalf("%d numbers, want %d", len(unique), goroutines*each)
	}
}

func TestAReportCountsBytesAndTimesPerDirection(t *testing.T) {
	ctx, report := session.WithConnReport(context.Background())
	if session.ConnReportFromContext(ctx) != report {
		t.Fatal("the report is not in its context")
	}
	report.Up().Add(5)
	time.Sleep(3 * time.Millisecond)
	report.Down().Add(7)
	report.Down().Add(3)

	totals := report.Totals()
	if totals.Up != 5 || totals.Down != 10 {
		t.Fatalf("up %d down %d, want 5 and 10", totals.Up, totals.Down)
	}
	if totals.LastUpMs < 0 || totals.FirstDownMs < totals.LastUpMs || totals.LastDownMs < totals.FirstDownMs {
		t.Fatalf("times out of order: %+v", totals)
	}
	if totals.DurMs < totals.LastDownMs {
		t.Fatalf("duration %d before the last byte %d", totals.DurMs, totals.LastDownMs)
	}
}

func TestAReportWithoutBytesSaysThereWereNone(t *testing.T) {
	_, report := session.WithConnReport(context.Background())
	totals := report.Totals()
	if totals.FirstDownMs != -1 || totals.LastUpMs != -1 || totals.LastDownMs != -1 || totals.Up != 0 || totals.Down != 0 {
		t.Fatalf("totals of an empty report: %+v", totals)
	}
}

type recordingTracker struct{ got []error }

func (r *recordingTracker) SubmitError(err error) { r.got = append(r.got, err) }

// The observatory's tracker may already sit in ctx: it keeps getting every error.
func TestTheFirstErrorStaysAndTheTrackerBeforeGetsEveryOne(t *testing.T) {
	before := &recordingTracker{}
	ctx, report := session.WithConnReport(session.TrackedConnectionError(context.Background(), before))
	first, second := stderrors.New("first"), stderrors.New("second")

	session.SubmitOutboundErrorToOriginator(ctx, first)
	session.SubmitOutboundErrorToOriginator(ctx, second)

	if report.Err() != first {
		t.Fatalf("report keeps %v, want the first error", report.Err())
	}
	if len(before.got) != 2 || before.got[0] != first || before.got[1] != second {
		t.Fatalf("the tracker before got %v", before.got)
	}
}

func TestARouteProbeIsMarked(t *testing.T) {
	ctx := context.Background()
	if session.IsRouteProbe(ctx) {
		t.Fatal("a plain context is a probe")
	}
	if !session.IsRouteProbe(session.ContextWithRouteProbe(ctx)) {
		t.Fatal("the probe mark is lost")
	}
}
