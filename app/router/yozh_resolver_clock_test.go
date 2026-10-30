package router

import (
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
)

// yozhTestClock is a clock for a resolver (yozhResolver.now, startTimer) that moves only when the
// test moves it; a timer on it fires when the clock is moved to its time or past it. On it a test
// checks the stall limit, the pauses between dials and a question's deadline to the nanosecond, on a
// machine as busy as it happens to be.
//
// It starts at the machine's time and only moves forward. The deadlines the resolver hands the
// socket, a write's and a dial's, are read off it too; with the long ask timeout (YozhLongAskTimeout)
// they lie seconds past anything the test does, so the socket never times a write out: a write that
// finds no room is the test's own (yozhFailingWrites). The one test of the socket's own timeout
// starts the clock behind the machine's instead (yozhOnTestClockBehind).
type yozhTestClock struct {
	mu      sync.Mutex
	at      time.Time
	reads   int
	started int
	timers  []*yozhTestTimer
}

type yozhTestTimer struct {
	at    time.Time
	fired chan time.Time
}

// yozhOnTestClock puts a resolver on a clock of the test's own. Call it before the resolver's first
// question, so that every time the resolver keeps is read off the clock.
func yozhOnTestClock(resolver *yozhResolver) *yozhTestClock {
	return yozhOnClockAt(resolver, time.Now())
}

// yozhOnTestClockBehind puts a resolver that has dialled on a clock of the test's own standing
// `behind` the machine's. A deadline the resolver reads off it, less than `behind` after its time,
// has already passed on the machine's clock, and the socket times out at once any write it bounds.
func yozhOnTestClockBehind(resolver *yozhResolver, behind time.Duration) *yozhTestClock {
	return yozhOnClockAt(resolver, time.Now().Add(-behind))
}

func yozhOnClockAt(resolver *yozhResolver, at time.Time) *yozhTestClock {
	clock := &yozhTestClock{at: at}
	resolver.mu.Lock() // an opened resolver's reader may read the clock (dropLocked, failedLocked)
	defer resolver.mu.Unlock()
	resolver.now = clock.now
	resolver.startTimer = clock.startTimer
	return clock
}

func (c *yozhTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	return c.at
}

func (c *yozhTestClock) startTimer(d time.Duration) (<-chan time.Time, func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started++
	timer := &yozhTestTimer{at: c.at.Add(d), fired: make(chan time.Time, 1)}
	if d <= 0 {
		timer.fired <- c.at
		return timer.fired, func() bool { return false }
	}
	c.timers = append(c.timers, timer)
	return timer.fired, func() bool { return c.stop(timer) }
}

func (c *yozhTestClock) stop(timer *yozhTestTimer) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := slices.Index(c.timers, timer); i >= 0 {
		c.timers = slices.Delete(c.timers, i, i+1)
		return true
	}
	return false
}

// advance moves the clock by d and fires every timer whose time has come.
func (c *yozhTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
	c.timers = slices.DeleteFunc(c.timers, func(timer *yozhTestTimer) bool {
		if timer.at.After(c.at) {
			return false
		}
		timer.fired <- c.at
		return true
	})
}

// timesRead is how many times the resolver has read the clock. A question reads it first for its
// deadline, before it takes the connection's lock.
func (c *yozhTestClock) timesRead() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// timersStarted is how many timers the resolver has started: one for every question written, which
// then waits for its answer.
func (c *yozhTestClock) timersStarted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

// timersWaiting is how many timers are started and have neither fired nor been stopped: the
// questions waiting for their answers.
func (c *yozhTestClock) timersWaiting() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// yozhClockedResolver is a resolver of the test's own at path, with the long ask timeout, on a clock
// of the test's own, opened.
func yozhClockedResolver(t *testing.T, path string) (*yozhResolver, *yozhTestClock) {
	t.Helper()
	resolver := newYozhResolver(path, YozhLongAskTimeout)
	clock := yozhOnTestClock(resolver)
	if err := resolver.open(time.Second); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.close)
	return resolver, clock
}

// yozhWaitLimit is how long a test waits for something that must happen (a question to return, a
// line to be read) before it calls it a hang. It bounds nothing the resolver does, and a test that
// passes never comes near it.
const yozhWaitLimit = 30 * time.Second

// yozhAwait waits until done answers true.
func yozhAwait(t *testing.T, what string, done func() bool) {
	t.Helper()
	for start := time.Now(); !done(); time.Sleep(100 * time.Microsecond) {
		if time.Since(start) > yozhWaitLimit {
			t.Fatalf("waited %v for %s", yozhWaitLimit, what)
		}
	}
}

// yozhAskInBackground asks, and hands back where the answer will come.
func yozhAskInBackground(resolver *yozhResolver, key yozhKey) <-chan yozhAnswer {
	answer := make(chan yozhAnswer, 1)
	go func() { answer <- resolver.ask(key) }()
	return answer
}

// yozhReturned is the answer of a question asked with yozhAskInBackground. On a test clock a
// question waits for its answer until the test moves the clock, so a question the test expects to
// return by itself (answered, or failed at once) and that does not would hang the test instead of
// failing it.
func yozhReturned(t *testing.T, asked <-chan yozhAnswer) yozhAnswer {
	t.Helper()
	select {
	case answer := <-asked:
		return answer
	case <-time.After(yozhWaitLimit):
		t.Fatalf("a question has not returned after %v", yozhWaitLimit)
		return yozhAnswer{}
	}
}

// yozhAskStill asks with the clock standing still: the answer is the stub's, or a failure that does
// not wait for the clock.
func yozhAskStill(t *testing.T, resolver *yozhResolver, key yozhKey) yozhAnswer {
	t.Helper()
	return yozhReturned(t, yozhAskInBackground(resolver, key))
}

// yozhClockedResolverOnFailingWrites is yozhClockedResolver whose connection is behind
// yozhFailingWrites. The test dials it and hands it to the resolver as connectLocked hands over a
// connection it dialled, with a reader of its own on the same wrapper: a line read then counts as the
// connection's, which it would not for a wrapper put in front of a connection whose reader already
// runs (read checks that the connection it reads is still the resolver's).
func yozhClockedResolverOnFailingWrites(t *testing.T, path string) (*yozhResolver, *yozhTestClock, *yozhFailingWrites) {
	t.Helper()
	resolver := newYozhResolver(path, YozhLongAskTimeout)
	clock := yozhOnTestClock(resolver)
	dialled, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	conn := &yozhFailingWrites{Conn: dialled}
	resolver.mu.Lock()
	resolver.conn = conn
	resolver.mu.Unlock()
	go resolver.read(conn)
	t.Cleanup(resolver.close)
	return resolver, clock, conn
}

// yozhNoRoom asks with the connection's next write finding no room: it times out with nothing
// written, as a write does on a connection the resolver has stopped reading.
func yozhNoRoom(t *testing.T, resolver *yozhResolver, conn *yozhFailingWrites, key yozhKey) {
	t.Helper()
	conn.failNext(0, os.ErrDeadlineExceeded)
	if answer := yozhAskStill(t, resolver, key); answer != yozhFailedAnswer {
		t.Fatalf("a question whose write found no room got %+v", answer)
	}
}

// yozhConnOf is the resolver's connection now: nil once it has been dropped, until the next dial.
func yozhConnOf(resolver *yozhResolver) net.Conn {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.conn
}
