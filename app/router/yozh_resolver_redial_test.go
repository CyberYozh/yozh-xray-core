package router

import (
	"bufio"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// yozhClosingStub is a resolver that answers every question "rule 7" until closing(true); from then
// on it accepts every connection and closes it at once, as a resolver whose handler fails on its
// first byte, or one restarting in a loop, does — and it closes the connections it was serving.
// closing(false) makes it answer again.
func yozhClosingStub(t *testing.T) (path string, accepted func() int, closing func(bool)) {
	t.Helper()
	listener, path := yozhListen(t)
	yozhLetTheStubThrough(t, path)
	var mu sync.Mutex
	count := 0
	closes := false
	var serving []net.Conn
	dropServing := func() {
		for _, conn := range serving {
			conn.Close()
		}
		serving = nil
	}
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		dropServing()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			count++
			if closes {
				mu.Unlock()
				conn.Close()
				continue
			}
			serving = append(serving, conn)
			mu.Unlock()
			go func() {
				lines := bufio.NewScanner(conn)
				for lines.Scan() {
					if id, _, ok := strings.Cut(lines.Text(), " q "); ok {
						conn.Write([]byte(id + " a rule 7\n"))
					}
				}
			}()
		}
	}()
	return path, func() int {
			mu.Lock()
			defer mu.Unlock()
			return count
		}, func(on bool) {
			mu.Lock()
			defer mu.Unlock()
			closes = on
			if on {
				dropServing()
			}
		}
}

// The redial tests run on a clock of their own (yozhTestClock): a question comes every millisecond
// of that clock, and when each dial is made is exact, whatever the machine's load.

// yozhFailuresOf is how many connections have failed in a row.
func yozhFailuresOf(resolver *yozhResolver) int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.failures
}

// yozhDialsOverTime asks a question every step of the resolver's clock for span, on a resolver whose
// every connection fails, and answers when each question that dialled was asked, counted from the
// first. A question dialled when it counted one more failed connection. Every question must fail;
// one that dialled nothing must fail at once, without writing: without starting a timer to wait
// for an answer.
func yozhDialsOverTime(t *testing.T, resolver *yozhResolver, clock *yozhTestClock, step, span time.Duration) []time.Duration {
	t.Helper()
	var dials []time.Duration
	for i := 0; time.Duration(i)*step < span; i++ {
		failures, started := yozhFailuresOf(resolver), clock.timersStarted()
		if answer := yozhAskStill(t, resolver, yozhStallKey(1+i)); answer != yozhFailedAnswer {
			t.Fatalf("question %d: %+v from a resolver whose every connection fails", i, answer)
		}
		switch after := yozhFailuresOf(resolver); {
		case after == failures+1:
			dials = append(dials, time.Duration(i)*step)
		case after != failures:
			t.Fatalf("question %d: failed connections went from %d to %d", i, failures, after)
		case clock.timersStarted() != started:
			t.Fatalf("question %d dialled nothing, and waited for an answer", i)
		}
		clock.advance(step)
	}
	return dials
}

// yozhDialSchedule is when a resolver whose every connection fails is dialled by questions asked
// every step, counted from the first question after a connection that had answered was lost: the
// first dial and the one after it are made at once, by the first two questions, and from then on
// each dial waits yozhRedialPause, doubled after every failure, at most yozhRedialPauseMax. next is
// when the first dial after span is due.
func yozhDialSchedule(step, span time.Duration) (dials []time.Duration, next time.Duration) {
	dials = []time.Duration{0, step}
	at, pause := step, yozhRedialPause
	for at += pause; at < span; at += pause {
		dials = append(dials, at)
		pause = min(2*pause, yozhRedialPauseMax)
	}
	return dials, at
}

// A resolver that accepts a connection and closes it at once was dialled again by every question —
// 1342 questions made 1324 connections in 3 s. After a failed connection the dials are spaced by a
// pause that grows to a bound; the first dial after a loss is still made at once, and a question
// that comes during the pause fails at once, as any failure does (through the base), without a dial.
// Once the resolver answers again, the next dial after the pause finds it. The questions come a
// millisecond apart, about as often as they came in the measurement.
func TestYozhAResolverThatClosesAtOnceIsNotDialledForEveryQuestion(t *testing.T) {
	path, accepted, closing := yozhClosingStub(t)
	resolver, clock := yozhClockedResolver(t, path)
	if answer := yozhAskStill(t, resolver, yozhStallKey(0)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Fatalf("the resolver before it broke: %+v", answer)
	}

	closing(true)
	yozhAwaitNoConnection(t, resolver)
	before := accepted()
	const step, span = time.Millisecond, 3 * time.Second
	dials := yozhDialsOverTime(t, resolver, clock, step, span)
	want, next := yozhDialSchedule(step, span)
	t.Logf("%d questions a millisecond apart: dials at %v", span/step, dials)
	if !slices.Equal(dials, want) {
		t.Fatalf("%d questions a millisecond apart dialled at %v, want %v", span/step, dials, want)
	}
	yozhAwait(t, "the stub to accept every dial", func() bool { return accepted()-before >= len(want) })
	if got := accepted() - before; got != len(want) {
		t.Fatalf("the stub accepted %d connections, want the %d dials", got, len(want))
	}

	// The resolver answers again: the dial due when the last pause ends finds it, and no question
	// before that one dials.
	closing(false)
	for at := span; ; at += step {
		answer := yozhAskStill(t, resolver, yozhStallKey(0))
		if answer == (yozhAnswer{kind: yozhRule, rule: 7}) {
			if at != next {
				t.Fatalf("the resolver was back, and was answering at %v, before the pause ended at %v", at, next)
			}
			break
		}
		if answer != yozhFailedAnswer {
			t.Fatalf("at %v: %+v", at, answer)
		}
		if at >= next {
			t.Fatalf("the resolver was back, and the dial due at %v did not find it", next)
		}
		clock.advance(step)
	}
}

// A socket the peer check refuses is a failed connection too: it is not dialled for every question.
func TestYozhARefusedResolverSocketIsNotDialledForEveryQuestion(t *testing.T) {
	stub := StartYozhStub(t)
	stub.Fallback = "rule 1"
	resolver, clock := yozhClockedResolver(t, stub.Path)
	if answer := yozhAskStill(t, resolver, yozhStallKey(0)); answer != (yozhAnswer{kind: yozhRule, rule: 1}) {
		t.Fatalf("the resolver before its socket was refused: %+v", answer)
	}
	resolver.mu.Lock()
	resolver.peer = func(net.Conn) (uint32, error) { return uint32(os.Geteuid()) + 1, nil }
	resolver.dropLocked(resolver.conn) // it had answered: the next dial is made at once
	resolver.mu.Unlock()

	asked := len(stub.Questions())
	const step, span = time.Millisecond, 3 * time.Second
	dials := yozhDialsOverTime(t, resolver, clock, step, span)
	want, _ := yozhDialSchedule(step, span)
	t.Logf("%d questions a millisecond apart: dials to the refused socket at %v", span/step, dials)
	if !slices.Equal(dials, want) {
		t.Errorf("%d questions a millisecond apart dialled the refused socket at %v, want %v", span/step, dials, want)
	}
	if got := stub.Questions()[asked:]; len(got) != 0 {
		t.Errorf("questions written to a refused socket: %q", got)
	}
}

// A resolver socket that is not there fails every dial, and that too is paused: a resolver that
// comes back during the pause is not dialled until the pause ends, and then it is.
func TestYozhAMissingResolverSocketIsNotDialledDuringThePause(t *testing.T) {
	listener, path := yozhListen(t)
	yozhLetTheStubThrough(t, path)
	listener.Close() // and the socket file with it
	resolver := newYozhResolver(path, YozhLongAskTimeout)
	clock := yozhOnTestClock(resolver)
	t.Cleanup(resolver.close)
	for i := range 2 { // two failed dials in a row: the next one waits yozhRedialPause
		if answer := yozhAskStill(t, resolver, yozhStallKey(i)); answer != yozhFailedAnswer {
			t.Fatalf("question %d to a socket that is not there: %+v", i, answer)
		}
	}

	back, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	dials := 0
	var conns []net.Conn
	t.Cleanup(func() {
		back.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := back.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			dials++
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				lines := bufio.NewScanner(conn)
				for lines.Scan() {
					if id, _, ok := strings.Cut(lines.Text(), " q "); ok {
						conn.Write([]byte(id + " a rule 7\n"))
					}
				}
			}()
		}
	}()
	if answer := yozhAskStill(t, resolver, yozhStallKey(2)); answer != yozhFailedAnswer {
		t.Fatalf("the resolver came back during the pause and was dialled at once: %+v", answer)
	}
	clock.advance(yozhRedialPause - time.Nanosecond)
	if answer := yozhAskStill(t, resolver, yozhStallKey(3)); answer != yozhFailedAnswer {
		t.Fatalf("the resolver was dialled %v into a pause of %v: %+v", yozhRedialPause-time.Nanosecond, yozhRedialPause, answer)
	}
	clock.advance(time.Nanosecond)
	if answer := yozhAskStill(t, resolver, yozhStallKey(4)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Fatalf("the resolver was back, and the question when the pause ended got %+v", answer)
	}
	mu.Lock()
	defer mu.Unlock()
	if dials != 1 {
		t.Fatalf("%d dials to the resolver that came back, want the one when the pause ended", dials)
	}
}

// yozhAwaitNoConnection waits until the resolver has dropped its connection (its reader saw the
// stub close it), so that the next question dials.
func yozhAwaitNoConnection(t *testing.T, resolver *yozhResolver) {
	t.Helper()
	yozhAwait(t, "the resolver to drop the connection the stub closed", func() bool { return yozhConnOf(resolver) == nil })
}

// yozhRunOfFailures is how many connections have failed in a row, and how long, on the resolver's
// clock, the next dial waits.
func yozhRunOfFailures(resolver *yozhResolver) (int, time.Duration) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.failures, resolver.redialAt.Sub(resolver.now())
}

// A line read on a connection ends the run of failed connections. Without that, the run only grew:
// a resolver that had once failed twice had one failed dial after a later restart pause the next
// dial, and the question after it, in time and with the resolver back, failed through the base
// instead of dialling at once.
func TestYozhALineReadEndsTheRunOfFailedConnections(t *testing.T) {
	path, _, closing := yozhClosingStub(t)
	resolver, clock := yozhClockedResolver(t, path)
	if answer := yozhAskStill(t, resolver, yozhStallKey(0)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Fatalf("the resolver before it broke: %+v", answer)
	}

	// Two failed connections in a row: the next dial is paused.
	closing(true)
	yozhAwaitNoConnection(t, resolver)
	for i := 1; i <= 2; i++ {
		if answer := yozhAskStill(t, resolver, yozhStallKey(i)); answer != yozhFailedAnswer {
			t.Fatalf("question %d to a resolver that closes every connection: %+v", i, answer)
		}
	}
	failures, pause := yozhRunOfFailures(resolver)
	if failures != 2 || pause != yozhRedialPause {
		t.Fatalf("after two failed connections: failures=%d pause=%v, want 2 and %v", failures, pause, yozhRedialPause)
	}

	// The resolver answers again, and the dial when the pause ends finds it.
	closing(false)
	clock.advance(pause)
	if answer := yozhAskStill(t, resolver, yozhStallKey(3)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Fatalf("the resolver was back, and the question when the pause ended got %+v", answer)
	}
	if failures, _ := yozhRunOfFailures(resolver); failures != 0 {
		t.Fatalf("a line was read, and failures=%d, want 0", failures)
	}

	// It restarts: the connection that answered is lost, and one dial fails.
	closing(true)
	yozhAwaitNoConnection(t, resolver)
	if answer := yozhAskStill(t, resolver, yozhStallKey(10)); answer != yozhFailedAnswer {
		t.Fatalf("a question to a resolver that closes every connection: %+v", answer)
	}
	failures, pause = yozhRunOfFailures(resolver)
	t.Logf("one failed dial after a connection that answered: failures=%d pause=%v", failures, pause)
	if failures != 1 || pause > 0 {
		t.Errorf("one failed dial after a connection that answered: failures=%d pause=%v, want 1 and no pause", failures, pause)
	}

	// Back at once: the next question dials without a wait and is answered.
	closing(false)
	if answer := yozhAskStill(t, resolver, yozhStallKey(11)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Errorf("the question after one failed dial: %+v, want rule 7 from a dial made at once", answer)
	}
}

// However many connections fail in a row, the pause before the next dial stays within its bound.
func TestYozhThePauseBeforeADialIsBounded(t *testing.T) {
	resolver := newYozhResolver("", time.Second)
	yozhOnTestClock(resolver)
	for failures := 1; failures <= 200; failures++ {
		resolver.mu.Lock()
		resolver.failedLocked()
		resolver.mu.Unlock()
		_, pause := yozhRunOfFailures(resolver)
		switch {
		case failures == 1 && pause > 0:
			t.Fatalf("after the first failure the next dial waits %v, want it made at once", pause)
		case failures == 2 && (pause <= 0 || pause > yozhRedialPause):
			t.Fatalf("after the second failure in a row the pause is %v, want %v", pause, yozhRedialPause)
		case failures > 2 && (pause <= 0 || pause > yozhRedialPauseMax):
			t.Fatalf("after %d failures in a row the pause is %v, want it within (0, %v]", failures, pause, yozhRedialPauseMax)
		}
	}
}
