package tun

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// readOutcome is one scripted answer of scriptedDevice.ReadPacket.
type readOutcome struct {
	version byte
	payload []byte
	err     error
}

func packetOf(version byte, payload ...byte) readOutcome {
	return readOutcome{version: version, payload: payload}
}

func failureOf(err error) readOutcome {
	return readOutcome{err: err}
}

// scriptedDevice is a GVisorDevice that replays scripted reads, reports
// ErrQueueEmpty when the script runs dry, and records everything else the
// endpoint does to it.
type scriptedDevice struct {
	mu     sync.Mutex
	script []readOutcome
	reads  int
	handed int
	writes []*stack.PacketBuffer

	// failWriteAt makes the write with this index fail with writeErr.
	failWriteAt int
	writeErr    tcpip.Error

	// readDelay widens the window in which two readers would overlap.
	readDelay time.Duration
	// beforeReturn runs inside ReadPacket right before a buffer is returned.
	beforeReturn func()
	// park, when set, makes Wait block until it is closed.
	park chan struct{}

	released     atomic.Int64
	waits        atomic.Int64
	inside       atomic.Int32
	maxInside    atomic.Int32
	insideRecord sync.Mutex
}

func newScriptedDevice(script ...readOutcome) *scriptedDevice {
	return &scriptedDevice{script: script, failWriteAt: -1}
}

func (d *scriptedDevice) push(more ...readOutcome) {
	d.mu.Lock()
	d.script = append(d.script, more...)
	d.mu.Unlock()
}

func (d *scriptedDevice) readCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reads
}

func (d *scriptedDevice) handedCount() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return int64(d.handed)
}

func (d *scriptedDevice) ReadPacket() (byte, *stack.PacketBuffer, error) {
	now := d.inside.Add(1)
	defer d.inside.Add(-1)
	d.insideRecord.Lock()
	if now > d.maxInside.Load() {
		d.maxInside.Store(now)
	}
	d.insideRecord.Unlock()
	if d.readDelay > 0 {
		time.Sleep(d.readDelay)
	}

	d.mu.Lock()
	d.reads++
	if len(d.script) == 0 {
		d.mu.Unlock()
		return 0, nil, ErrQueueEmpty
	}
	next := d.script[0]
	d.script = d.script[1:]
	if next.err != nil {
		d.mu.Unlock()
		return 0, nil, next.err
	}
	d.handed++
	hook := d.beforeReturn
	d.mu.Unlock()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:   buffer.MakeWithData(append([]byte(nil), next.payload...)),
		OnRelease: func() { d.released.Add(1) },
	})
	if hook != nil {
		hook()
	}
	return next.version, pkt, nil
}

func (d *scriptedDevice) Wait() {
	d.waits.Add(1)
	if d.park != nil {
		<-d.park
		return
	}
	time.Sleep(50 * time.Microsecond)
}

func (d *scriptedDevice) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	d.mu.Lock()
	defer d.mu.Unlock()
	index := len(d.writes)
	d.writes = append(d.writes, pkt)
	if index == d.failWriteAt {
		return d.writeErr
	}
	return nil
}

type capturedPacket struct {
	proto tcpip.NetworkProtocolNumber
	data  []byte
}

// capturingDispatcher records what the endpoint hands to the stack.
type capturingDispatcher struct {
	mu   sync.Mutex
	seen []capturedPacket
}

func (c *capturingDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	data := pkt.Data().AsRange().ToSlice()
	c.mu.Lock()
	c.seen = append(c.seen, capturedPacket{proto: proto, data: data})
	c.mu.Unlock()
}

func (c *capturingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (c *capturingDispatcher) snapshot() []capturedPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]capturedPacket(nil), c.seen...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// settled waits until the device stops seeing new ReadPacket calls.
func settled(t *testing.T, dev *scriptedDevice) {
	t.Helper()
	waitFor(t, "the reader to go quiet", func() bool {
		before := dev.readCount()
		time.Sleep(20 * time.Millisecond)
		return dev.readCount() == before
	})
}

func newTestEndpoint(dev GVisorDevice) *LinkEndpoint {
	return &LinkEndpoint{deviceMTU: 1400, device: dev}
}

func TestLinkEndpointDeliversPacketsByIPVersion(t *testing.T) {
	dev := newScriptedDevice(
		packetOf(4, 0x45, 1),
		packetOf(6, 0x60, 2),
		packetOf(5, 0x50, 3),
		packetOf(4, 0x45, 4),
	)
	ep := newTestEndpoint(dev)
	disp := &capturingDispatcher{}
	ep.Attach(disp)
	defer ep.Close()

	waitFor(t, "all buffers to be released", func() bool { return dev.released.Load() == 4 })

	want := []capturedPacket{
		{header.IPv4ProtocolNumber, []byte{0x45, 1}},
		{header.IPv6ProtocolNumber, []byte{0x60, 2}},
		{header.IPv4ProtocolNumber, []byte{0x45, 4}},
	}
	got := disp.snapshot()
	if len(got) != len(want) {
		t.Fatalf("delivered %d packets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].proto != want[i].proto || !bytes.Equal(got[i].data, want[i].data) {
			t.Fatalf("packet %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLinkEndpointWaitsOnDeviceWhenQueueIsEmpty(t *testing.T) {
	dev := newScriptedDevice()
	ep := newTestEndpoint(dev)
	disp := &capturingDispatcher{}
	ep.Attach(disp)
	defer ep.Close()

	waitFor(t, "device.Wait to be called", func() bool { return dev.waits.Load() >= 3 })
	if n := len(disp.snapshot()); n != 0 {
		t.Fatalf("delivered %d packets from an empty queue", n)
	}
	if reads, waits := int64(dev.readCount()), dev.waits.Load(); reads > waits+1 {
		t.Fatalf("reader spun without waiting: %d reads, %d waits", reads, waits)
	}
	if !ep.IsAttached() {
		t.Fatal("an empty queue detached the endpoint")
	}

	dev.push(packetOf(4, 0x45, 9))
	waitFor(t, "the late packet", func() bool { return len(disp.snapshot()) == 1 })
}

func TestLinkEndpointStopsReadingOnDeviceFailure(t *testing.T) {
	dev := newScriptedDevice(
		packetOf(4, 0x45, 1),
		failureOf(errors.New("device is gone")),
		packetOf(4, 0x45, 2),
	)
	ep := newTestEndpoint(dev)
	disp := &capturingDispatcher{}
	ep.Attach(disp)
	defer ep.Close()

	waitFor(t, "the endpoint to report detachment", func() bool { return !ep.IsAttached() })
	settled(t, dev)
	if reads := dev.readCount(); reads != 2 {
		t.Fatalf("ReadPacket called %d times, want 2", reads)
	}
	if n := len(disp.snapshot()); n != 1 {
		t.Fatalf("delivered %d packets, want 1", n)
	}
	if released, handed := dev.released.Load(), dev.handedCount(); released != handed {
		t.Fatalf("released %d of %d buffers", released, handed)
	}

	// A failed device stays failed: attaching again must not restart reading.
	ep.Attach(disp)
	time.Sleep(30 * time.Millisecond)
	if reads := dev.readCount(); reads != 2 {
		t.Fatalf("reading restarted after a device failure: %d reads", reads)
	}
	if ep.IsAttached() {
		t.Fatal("IsAttached is true after a device failure")
	}
}

func TestLinkEndpointDetachStopsDeliveryAndReattachResumes(t *testing.T) {
	dev := newScriptedDevice(packetOf(4, 0x45, 1))
	dev.readDelay = 100 * time.Microsecond
	ep := newTestEndpoint(dev)
	first := &capturingDispatcher{}
	ep.Attach(first)
	defer ep.Close()

	waitFor(t, "the first packet", func() bool { return len(first.snapshot()) == 1 })
	ep.Attach(nil)
	if ep.IsAttached() {
		t.Fatal("IsAttached is true after Attach(nil)")
	}
	settled(t, dev)

	dev.push(packetOf(4, 0x45, 2))
	time.Sleep(30 * time.Millisecond)
	if n := len(first.snapshot()); n != 1 {
		t.Fatalf("delivered %d packets to a detached dispatcher", n)
	}

	second := &capturingDispatcher{}
	ep.Attach(second)
	ep.Attach(second)
	ep.Attach(second)
	if !ep.IsAttached() {
		t.Fatal("IsAttached is false after re-attaching")
	}
	waitFor(t, "the queued packet", func() bool { return len(second.snapshot()) == 1 })

	dev.push(packetOf(6, 0x60, 3), packetOf(4, 0x45, 4))
	waitFor(t, "two more packets", func() bool { return len(second.snapshot()) == 3 })
	time.Sleep(30 * time.Millisecond)
	if n := len(second.snapshot()); n != 3 {
		t.Fatalf("delivered %d packets, want 3 (duplicate reader?)", n)
	}
	if n := len(first.snapshot()); n != 1 {
		t.Fatalf("old dispatcher got %d packets, want 1", n)
	}
	if peak := dev.maxInside.Load(); peak != 1 {
		t.Fatalf("%d readers were inside ReadPacket at once", peak)
	}
}

func TestLinkEndpointReleasesBufferWhenDetachedMidRead(t *testing.T) {
	dev := newScriptedDevice(packetOf(4, 0x45, 1))
	ep := newTestEndpoint(dev)
	dev.beforeReturn = func() { ep.Attach(nil) }
	disp := &capturingDispatcher{}
	ep.Attach(disp)
	defer ep.Close()

	waitFor(t, "the in-flight buffer to be released", func() bool { return dev.released.Load() == 1 })
	settled(t, dev)
	if n := len(disp.snapshot()); n != 0 {
		t.Fatalf("delivered %d packets after detaching", n)
	}
	if ep.IsAttached() {
		t.Fatal("IsAttached is true after Attach(nil)")
	}
}

func TestLinkEndpointWaitAndCloseDoNotBlockOnParkedReader(t *testing.T) {
	dev := newScriptedDevice()
	dev.park = make(chan struct{})
	ep := newTestEndpoint(dev)
	ep.Attach(&capturingDispatcher{})

	waitFor(t, "the reader to park in device.Wait", func() bool { return dev.waits.Load() >= 1 })

	done := make(chan struct{})
	go func() {
		ep.Wait()
		ep.Attach(nil)
		ep.Wait()
		ep.Close()
		ep.Close()
		ep.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(dev.park)
		t.Fatal("Wait/Close blocked on a reader parked inside device.Wait")
	}
	if ep.IsAttached() {
		t.Fatal("IsAttached is true after Close")
	}

	readsBefore := dev.readCount()
	close(dev.park)
	time.Sleep(30 * time.Millisecond)
	if reads := dev.readCount(); reads != readsBefore {
		t.Fatalf("closed endpoint kept reading: %d -> %d", readsBefore, reads)
	}
}

func TestLinkEndpointCloseBeforeAttachIsFinal(t *testing.T) {
	dev := newScriptedDevice(packetOf(4, 0x45, 1))
	ep := newTestEndpoint(dev)
	ep.Close()
	ep.Close()
	ep.Wait()

	disp := &capturingDispatcher{}
	ep.Attach(disp)
	time.Sleep(30 * time.Millisecond)
	if ep.IsAttached() {
		t.Fatal("a closed endpoint accepted a dispatcher")
	}
	if reads := dev.readCount(); reads != 0 {
		t.Fatalf("a closed endpoint started reading: %d reads", reads)
	}
}

func newOutboundPacket(marker byte) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{0x45, marker}),
	})
}

func TestLinkEndpointWritePacketsInOrder(t *testing.T) {
	dev := newScriptedDevice()
	ep := newTestEndpoint(dev)

	pkts := []*stack.PacketBuffer{newOutboundPacket(1), newOutboundPacket(2), newOutboundPacket(3)}
	defer func() {
		for _, p := range pkts {
			p.DecRef()
		}
	}()
	var list stack.PacketBufferList
	for _, p := range pkts {
		list.PushBack(p)
	}

	n, err := ep.WritePackets(list)
	if err != nil || n != 3 {
		t.Fatalf("WritePackets = (%d, %v), want (3, nil)", n, err)
	}
	if len(dev.writes) != 3 {
		t.Fatalf("device saw %d writes, want 3", len(dev.writes))
	}
	for i, p := range pkts {
		if dev.writes[i] != p {
			t.Fatalf("write %d is out of order", i)
		}
		if refs := p.ReadRefs(); refs != 1 {
			t.Fatalf("packet %d has %d references after WritePackets, want 1", i, refs)
		}
	}
}

func TestLinkEndpointWritePacketsStopsAtFirstFailure(t *testing.T) {
	dev := newScriptedDevice()
	dev.failWriteAt = 1
	dev.writeErr = &tcpip.ErrWouldBlock{}
	ep := newTestEndpoint(dev)

	pkts := []*stack.PacketBuffer{newOutboundPacket(1), newOutboundPacket(2), newOutboundPacket(3)}
	defer func() {
		for _, p := range pkts {
			p.DecRef()
		}
	}()
	var list stack.PacketBufferList
	for _, p := range pkts {
		list.PushBack(p)
	}

	n, err := ep.WritePackets(list)
	if n != 1 {
		t.Fatalf("WritePackets wrote %d, want 1", n)
	}
	if err != dev.writeErr {
		t.Fatalf("WritePackets error = %v, want the device error %v", err, dev.writeErr)
	}
	if len(dev.writes) != 2 {
		t.Fatalf("device saw %d writes, want 2 (stop after the failure)", len(dev.writes))
	}
	for i, p := range pkts {
		if refs := p.ReadRefs(); refs != 1 {
			t.Fatalf("packet %d has %d references after WritePackets, want 1", i, refs)
		}
	}
}

func TestLinkEndpointStaticProperties(t *testing.T) {
	ep := &LinkEndpoint{deviceMTU: 1420, device: newScriptedDevice()}

	if got := ep.MTU(); got != 1420 {
		t.Fatalf("MTU = %d, want 1420", got)
	}
	ep.SetMTU(9000)
	if got := ep.MTU(); got != 1420 {
		t.Fatalf("SetMTU changed MTU to %d", got)
	}
	if got := ep.MaxHeaderLength(); got != 0 {
		t.Fatalf("MaxHeaderLength = %d, want 0", got)
	}
	ep.SetLinkAddress(tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01"))
	if got := ep.LinkAddress(); got != "" {
		t.Fatalf("LinkAddress = %q, want empty", got)
	}
	if got := ep.Capabilities(); got != stack.CapabilityRXChecksumOffload {
		t.Fatalf("Capabilities = %#x, want only RX checksum offload", got)
	}
	if got := ep.ARPHardwareType(); got != header.ARPHardwareNone {
		t.Fatalf("ARPHardwareType = %v, want none", got)
	}

	pkt := newOutboundPacket(7)
	defer pkt.DecRef()
	before := pkt.Size()
	ep.AddHeader(pkt)
	if !ep.ParseHeader(pkt) {
		t.Fatal("ParseHeader rejected a raw IP packet")
	}
	if pkt.Size() != before || len(pkt.LinkHeader().Slice()) != 0 {
		t.Fatal("AddHeader/ParseHeader changed the packet")
	}

	ep.SetOnCloseAction(nil)
	ep.SetOnCloseAction(func() {})
	if ep.IsAttached() {
		t.Fatal("a fresh endpoint reports being attached")
	}
}

func TestLinkEndpointSurvivesConcurrentAttachDetachClose(t *testing.T) {
	dev := newScriptedDevice()
	dev.readDelay = 20 * time.Microsecond
	ep := newTestEndpoint(dev)
	disp := &capturingDispatcher{}

	stopFeed := make(chan struct{})
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for {
			select {
			case <-stopFeed:
				return
			default:
			}
			dev.push(packetOf(4, 0x45, 0), packetOf(9, 0x90, 0))
			time.Sleep(50 * time.Microsecond)
		}
	}()

	ep.Attach(disp)
	// The churn below takes a fraction of a millisecond; without this wait
	// the reader may not have run at all before Close, and the test would
	// then prove nothing about overlapping readers.
	waitFor(t, "the reader to start", func() bool { return dev.readCount() > 0 })

	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				switch (i + worker) % 3 {
				case 0:
					ep.Attach(disp)
				case 1:
					ep.Attach(nil)
				default:
					_ = ep.IsAttached()
				}
			}
		}(worker)
	}
	wg.Wait()
	ep.Close()
	close(stopFeed)
	<-fed

	waitFor(t, "every handed buffer to be released", func() bool {
		return dev.released.Load() == dev.handedCount()
	})
	settled(t, dev)
	if released, handed := dev.released.Load(), dev.handedCount(); released != handed {
		t.Fatalf("released %d of %d buffers", released, handed)
	}
	if peak := dev.maxInside.Load(); peak > 1 {
		t.Fatalf("%d readers were inside ReadPacket at once", peak)
	}
	if ep.IsAttached() {
		t.Fatal("IsAttached is true after Close")
	}
}
