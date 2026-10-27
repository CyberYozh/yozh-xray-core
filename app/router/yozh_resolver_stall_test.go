package router

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// yozhStallingStub is a resolver whose handler for its FIRST connection stops reading — until
// `resume` is closed, or for good when resume is nil — while the process goes on accepting and
// serving new connections. Every question it reads is answered "rule 7".
func yozhStallingStub(t *testing.T, resume <-chan struct{}) (path string, accepted func() int) {
	t.Helper()
	listener, path := yozhListen(t)
	yozhLetTheStubThrough(t, path)
	ended := make(chan struct{})
	var mu sync.Mutex
	var conns []net.Conn
	count := 0
	t.Cleanup(func() {
		close(ended)
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	serve := func(conn net.Conn, stalled bool) {
		if stalled {
			select {
			case <-resume: // a nil resume never fires
			case <-ended:
				return
			}
		}
		lines := bufio.NewScanner(conn)
		for lines.Scan() {
			id, _, ok := strings.Cut(lines.Text(), " q ")
			if ok {
				conn.Write([]byte(id + " a rule 7\n"))
			}
		}
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			count++
			first := count == 1
			conns = append(conns, conn)
			mu.Unlock()
			go serve(conn, first)
		}
	}()
	return path, func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

func yozhStallKey(i int) yozhKey {
	return yozhKey{
		network: "tcp",
		source:  netip.AddrPortFrom(netip.MustParseAddr("198.18.0.1"), uint16(20000+i%40000)),
		target:  netip.AddrPortFrom(netip.MustParseAddr("192.0.2.120"), 443),
	}
}

// The stall tests run on a clock of their own (yozhTestClock), and a write that finds no room is a
// timeout with nothing written that the test hands the resolver (yozhNoRoom): what a write does on a
// connection whose buffers the resolver has stopped emptying, without filling real buffers against
// the machine's clock.

// The socket times a question's write out at the question's deadline, which the resolver hands it.
// Without that deadline, a write on a connection whose buffers the resolver has stopped emptying
// waits for room for ever, holding the connection's lock, and every question after it waits behind
// it. A write timed out with nothing written fails its question alone: the connection stays, and
// the count of writes that found no room starts at that write.
//
// The resolver's clock stands an hour behind the machine's, so the deadline the resolver hands the
// socket has passed before the write begins, and the socket times the write out at once, with
// nothing written, as it does a write that has found no room until its deadline. Whether the
// connection has room does not matter, and the test fills no buffers.
func TestYozhTheSocketTimesAWriteOutAtItsQuestionsDeadline(t *testing.T) {
	stub := StartYozhStub(t)
	stub.Fallback = "rule 5"
	resolver := yozhTestResolver(t, stub, YozhLongAskTimeout) // dialled on the machine's clock
	clock := yozhOnTestClockBehind(resolver, time.Hour)
	conn := yozhConnOf(resolver)
	writing := clock.now()

	if answer := yozhAskStill(t, resolver, yozhStallKey(0)); answer != yozhFailedAnswer {
		t.Fatalf("a question whose deadline had passed for the socket got %+v: its write was not bounded by the deadline", answer)
	}
	if got := stub.Questions(); len(got) != 0 {
		t.Fatalf("written after its deadline: %q", got)
	}
	resolver.mu.Lock()
	blocked := resolver.blocked
	resolver.mu.Unlock()
	if yozhConnOf(resolver) != conn || !blocked.Equal(writing) {
		t.Fatalf("a write timed out with nothing written: connection kept %v, writes without room counted from %v; want it kept and counted from the write (%v)", yozhConnOf(resolver) == conn, blocked, writing)
	}

	// With the clock an hour ahead of the machine's, the deadline lies ahead of the socket too: the
	// next question is written and answered on the same connection, and that write ends the count.
	clock.advance(2 * time.Hour)
	if answer := yozhAskStill(t, resolver, yozhStallKey(1)); answer != (yozhAnswer{kind: yozhRule, rule: 5}) {
		t.Fatalf("a question with its deadline ahead got %+v", answer)
	}
	resolver.mu.Lock()
	blocked = resolver.blocked
	resolver.mu.Unlock()
	if yozhConnOf(resolver) != conn || stub.Connections() != 1 || !blocked.IsZero() {
		t.Fatalf("after a write that went through: %d connections, writes without room counted from %v; want the first one, and no count", stub.Connections(), blocked)
	}
}

// A resolver that stopped reading our connection but still serves new ones: its handler for that
// connection is stuck. Nothing breaks the connection — no EOF, no error, only writes that find no
// room and time out with nothing written, which by themselves leave a stream whole. Kept for that,
// the connection failed every question until the engine restarted: every program through the base,
// or blocked in strict mode. A connection whose writes have found no room for yozhStallLimit, with
// nothing written and no line read since the first of them, is given up, and the next question
// dials again.
func TestYozhAConnectionTheResolverStoppedReadingIsReplaced(t *testing.T) {
	path, _ := yozhStallingStub(t, nil)
	resolver, clock, stuck := yozhClockedResolverOnFailingWrites(t, path)

	yozhNoRoom(t, resolver, stuck, yozhStallKey(0)) // the first write that finds no room starts the count
	clock.advance(yozhStallLimit - time.Nanosecond)
	yozhNoRoom(t, resolver, stuck, yozhStallKey(1))
	if yozhConnOf(resolver) != stuck {
		t.Fatalf("the connection was given up after its writes found no room for %v, short of the limit", yozhStallLimit-time.Nanosecond)
	}
	clock.advance(time.Nanosecond)
	yozhNoRoom(t, resolver, stuck, yozhStallKey(2))
	if yozhConnOf(resolver) == stuck {
		t.Fatalf("the connection's writes found no room for %v, the limit, and it was kept", yozhStallLimit)
	}
	if _, err := stuck.Conn.Write([]byte("\n")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the connection given up was not closed: a write on it gave %v", err)
	}
	if answer := yozhAskStill(t, resolver, yozhStallKey(3)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Fatalf("the question after the stuck connection was given up got %+v, want rule 7 from a new connection", answer)
	}
}

// The other side of the limit: a resolver that stops reading for a moment (busy, a burst) and then
// reads again keeps its connection. The questions of that moment fail by themselves, as any late
// question does; the stream is whole and nothing is dialled again.
func TestYozhAResolverThatPausesKeepsItsConnection(t *testing.T) {
	resume := make(chan struct{})
	path, accepted := yozhStallingStub(t, resume)
	resolver, clock, paused := yozhClockedResolverOnFailingWrites(t, path)

	yozhNoRoom(t, resolver, paused, yozhStallKey(0))
	clock.advance(yozhStallLimit / 2)
	yozhNoRoom(t, resolver, paused, yozhStallKey(1))
	clock.advance(yozhStallLimit/2 - time.Nanosecond)
	yozhNoRoom(t, resolver, paused, yozhStallKey(2))
	close(resume)
	if answer := yozhAskStill(t, resolver, yozhStallKey(3)); answer != (yozhAnswer{kind: yozhRule, rule: 7}) {
		t.Fatalf("the resolver read again, and the question got %+v", answer)
	}
	if yozhConnOf(resolver) != paused || accepted() != 1 {
		t.Fatalf("a resolver that paused for just under the limit had its connection replaced (%d connections)", accepted())
	}
}

// yozhTalkingStub is a resolver that never reads a question and writes a line on the connections it
// has accepted whenever the test calls say: one that is behind on reading while it still sends what
// it has.
func yozhTalkingStub(t *testing.T) (path string, accepted func() int, say func()) {
	t.Helper()
	listener, path := yozhListen(t)
	yozhLetTheStubThrough(t, path)
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	return path, func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(conns)
		}, func() {
			mu.Lock()
			defer mu.Unlock()
			for _, conn := range conns {
				conn.Write([]byte("999999 a none\n"))
			}
		}
}

// A line read ends the count of writes that found no room, as a question written does: the
// resolver is there and sending. A resolver that keeps sending lines while our writes find no room
// for longer than the limit keeps its connection. Counted through its lines, the connection was
// dropped as stuck, and every question waiting on it failed.
func TestYozhAConnectionThatKeepsGivingLinesIsNotStuck(t *testing.T) {
	path, accepted, say := yozhTalkingStub(t)
	resolver, clock, deaf := yozhClockedResolverOnFailingWrites(t, path)
	yozhAwait(t, "the stub to accept the connection", func() bool { return accepted() == 1 })

	yozhNoRoom(t, resolver, deaf, yozhStallKey(0))
	clock.advance(yozhStallLimit - time.Nanosecond)
	say()
	yozhAwait(t, "the resolver to read the stub's line", func() bool {
		resolver.mu.Lock()
		defer resolver.mu.Unlock()
		return resolver.answered
	})
	clock.advance(time.Nanosecond)
	yozhNoRoom(t, resolver, deaf, yozhStallKey(1)) // the limit since the first write that found no room
	if yozhConnOf(resolver) != deaf {
		t.Fatal("a resolver that sent a line had its connection replaced: the line did not end the count")
	}

	// The line ended the count; it did not stop it. From the write after it, the limit is counted again.
	clock.advance(yozhStallLimit - time.Nanosecond)
	yozhNoRoom(t, resolver, deaf, yozhStallKey(2))
	if yozhConnOf(resolver) != deaf {
		t.Fatalf("replaced %v after the line, short of the limit", yozhStallLimit-time.Nanosecond)
	}
	clock.advance(time.Nanosecond)
	yozhNoRoom(t, resolver, deaf, yozhStallKey(3))
	if yozhConnOf(resolver) == deaf {
		t.Fatal("writes found no room for the limit after the line, and the connection was kept")
	}
}

// The limit is how long writes have found no room, not how long the connection has been quiet. A
// connection with nothing to ask for longer than the limit is healthy, and a write that then times
// out once with nothing written (the resolver busy for a moment) leaves it in place. Measured from
// the connection's last movement, that one timeout replaced it, failing every question waiting on
// it. A write that goes through ends the count of an earlier slow one: the resolver read.
func TestYozhAQuietConnectionKeepsItsPlaceThroughOneSlowWrite(t *testing.T) {
	stub := StartYozhStub(t)
	stub.Fallback = "rule 4"
	stub.Answer("tcp 198.18.0.1 20001 192.0.2.120 443", "silent")
	resolver, clock, conn := yozhClockedResolverOnFailingWrites(t, stub.Path)

	yozhNoRoom(t, resolver, conn, yozhStallKey(0)) // a moment after the dial
	// Written, read by the resolver, never answered: the write alone is the connection's movement.
	unanswered := yozhAskInBackground(resolver, yozhStallKey(1))
	yozhAwait(t, "the question to wait for its answer", func() bool { return clock.timersWaiting() == 1 })
	clock.advance(resolver.timeout)
	if answer := yozhReturned(t, unanswered); answer != yozhFailedAnswer {
		t.Fatalf("a question the resolver does not answer got %+v", answer)
	}
	clock.advance(yozhStallLimit) // quiet for longer than the limit
	yozhNoRoom(t, resolver, conn, yozhStallKey(2))
	if answer := yozhAskStill(t, resolver, yozhStallKey(3)); answer != (yozhAnswer{kind: yozhRule, rule: 4}) {
		t.Fatalf("the question after the slow write: %+v", answer)
	}
	if yozhConnOf(resolver) != conn || stub.Connections() != 1 {
		t.Fatalf("%d connections: one slow write after a quiet spell replaced a healthy connection", stub.Connections())
	}
}
