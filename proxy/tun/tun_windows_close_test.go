//go:build windows

package tun

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// driverlessSession stands in for a Wintun session. It records the calls it
// gets and counts the ones that arrive after End, when the memory of a real
// session would already be freed.
type driverlessSession struct {
	mu       sync.Mutex
	inbound  [][]byte
	receives int
	released int
	ended    int
	late     int
	onEnd    func()
}

// touch must be called with mu held.
func (s *driverlessSession) touch() {
	if s.ended > 0 {
		s.late++
	}
}

func (s *driverlessSession) AllocateSendPacket(size int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touch()
	return make([]byte, size), nil
}

func (s *driverlessSession) SendPacket([]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touch()
}

func (s *driverlessSession) ReceivePacket() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touch()
	s.receives++
	if len(s.inbound) == 0 {
		return nil, windows.ERROR_NO_MORE_ITEMS
	}
	next := s.inbound[0]
	s.inbound = s.inbound[1:]
	return next, nil
}

func (s *driverlessSession) ReleaseReceivePacket([]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touch()
	s.released++
}

func (s *driverlessSession) End() {
	s.mu.Lock()
	s.touch()
	s.ended++
	hook := s.onEnd
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
}

type sessionCounts struct {
	receives, released, ended, late int
}

func (s *driverlessSession) counts() sessionCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sessionCounts{s.receives, s.released, s.ended, s.late}
}

// newDriverlessTun builds a WindowsTun over a fake session and an auto-reset
// read event, which is what Wintun hands out.
func newDriverlessTun(t *testing.T, session *driverlessSession) (*WindowsTun, windows.Handle) {
	t.Helper()
	readWait, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(readWait) })
	tun, err := newWindowsTun(&Config{MTU: 1400}, nil, session, readWait)
	if err != nil {
		t.Fatal(err)
	}
	return tun, readWait
}

// awaitOrRelease waits for cond. On timeout it signals the read event, so a
// goroutine stuck in Wait can leave before the test fails.
func awaitOrRelease(t *testing.T, what string, readWait windows.Handle, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			_ = windows.SetEvent(readWait)
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWindowsTunCloseWakesAParkedWait(t *testing.T) {
	session := &driverlessSession{}
	tun, readWait := newDriverlessTun(t, session)

	var returned atomic.Bool
	go func() {
		tun.Wait()
		returned.Store(true)
	}()
	time.Sleep(20 * time.Millisecond)
	if returned.Load() {
		t.Fatal("Wait returned although nothing was signalled")
	}

	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	awaitOrRelease(t, "Wait to return after Close", readWait, returned.Load)
	if c := session.counts(); c.ended != 1 || c.late != 0 {
		t.Fatalf("session after Close: %+v, want ended once and no late calls", c)
	}
}

func TestWindowsTunEndsTheSessionOnlyAfterWaitLeft(t *testing.T) {
	session := &driverlessSession{}
	tun, readWait := newDriverlessTun(t, session)
	parkedAtEnd := int32(-1)
	session.onEnd = func() { parkedAtEnd = tun.parked.Load() }

	go tun.Wait()
	awaitOrRelease(t, "Wait to park", readWait, func() bool { return tun.parked.Load() == 1 })
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if parkedAtEnd != 0 {
		t.Fatalf("the session was ended with %d calls still inside Wait", parkedAtEnd)
	}
}

func TestWindowsTunLeavesTheSessionAloneAfterClose(t *testing.T) {
	session := &driverlessSession{inbound: [][]byte{{0x45, 0x00, 0x00, 0x04}}}
	tun, readWait := newDriverlessTun(t, session)

	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}

	_, pkt, err := tun.ReadPacket()
	if pkt != nil {
		pkt.DecRef()
	}
	if err == nil || errors.Is(err, ErrQueueEmpty) {
		t.Fatalf("ReadPacket after Close = %v, want a closed-device error", err)
	}

	out := newOutboundPacket(1)
	defer out.DecRef()
	if werr := tun.WritePacket(out); werr == nil {
		t.Fatal("WritePacket after Close succeeded")
	} else if _, ok := werr.(*tcpip.ErrClosedForSend); !ok {
		t.Fatalf("WritePacket after Close = %v, want ErrClosedForSend", werr)
	}

	var returned atomic.Bool
	go func() {
		tun.Wait()
		returned.Store(true)
	}()
	awaitOrRelease(t, "Wait on a closed device to return", readWait, returned.Load)

	if c := session.counts(); c.ended != 1 || c.late != 0 {
		t.Fatalf("session after Close: %+v, want ended once and no late calls", c)
	}
}

func TestWindowsTunReturnsTheRingSlotAtOnce(t *testing.T) {
	slot := []byte{0x45, 0x00, 0x00, 0x05, 0xaa}
	want := append([]byte(nil), slot...)
	session := &driverlessSession{inbound: [][]byte{slot}}
	tun, _ := newDriverlessTun(t, session)
	defer tun.Close()

	version, pkt, err := tun.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("version = %d, want 4", version)
	}
	if c := session.counts(); c.released != 1 {
		t.Fatalf("%d ring slots returned while the packet is still held, want 1", c.released)
	}

	// Wintun may hand the slot out again as soon as it is returned.
	for i := range slot {
		slot[i] = 0xee
	}
	view := pkt.ToView()
	got := append([]byte(nil), view.AsSlice()...)
	view.Release()
	if !bytes.Equal(got, want) {
		t.Fatalf("packet bytes = %x, want %x", got, want)
	}

	pkt.DecRef()
	if c := session.counts(); c.released != 1 {
		t.Fatalf("%d ring slots returned after the packet was released, want exactly 1", c.released)
	}
}

// waitCountingDevice counts the goroutines inside Wait of the device it wraps.
type waitCountingDevice struct {
	GVisorDevice
	inside atomic.Int32
}

func (d *waitCountingDevice) Wait() {
	d.inside.Add(1)
	defer d.inside.Add(-1)
	d.GVisorDevice.Wait()
}

func TestWindowsTunCloseReleasesTheEndpointReader(t *testing.T) {
	session := &driverlessSession{}
	tun, readWait := newDriverlessTun(t, session)
	dev := &waitCountingDevice{GVisorDevice: tun}
	ep := &LinkEndpoint{deviceMTU: 1400, device: dev}
	ep.Attach(&capturingDispatcher{})

	awaitOrRelease(t, "the reader to park in Wait", readWait, func() bool { return dev.inside.Load() == 1 })

	// Handler.Close tears the stack down first, which detaches the endpoint,
	// and closes the device after it.
	ep.Close()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	awaitOrRelease(t, "the reader to leave Wait", readWait, func() bool { return dev.inside.Load() == 0 })

	before := session.counts()
	time.Sleep(30 * time.Millisecond)
	after := session.counts()
	if after.receives != before.receives {
		t.Fatalf("the reader kept polling a closed device: %d -> %d", before.receives, after.receives)
	}
	if after.late != 0 {
		t.Fatalf("%d session calls after End", after.late)
	}
}
