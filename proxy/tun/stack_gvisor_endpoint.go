package tun

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	xerrors "github.com/xtls/xray-core/common/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var ErrQueueEmpty = errors.New("queue is empty")

type GVisorDevice interface {
	WritePacket(packet *stack.PacketBuffer) tcpip.Error
	ReadPacket() (byte, *stack.PacketBuffer, error)
	Wait()
}

// LinkEndpoint implements GVisor stack.LinkEndpoint
var _ stack.LinkEndpoint = (*LinkEndpoint)(nil)

// LinkEndpoint connects a GVisorDevice, a TUN device that carries bare IP
// packets, to the link layer of a gVisor stack.
//
// Outbound packets are written to the device synchronously, on whatever
// goroutine the stack sends from. Inbound packets are pulled by one reader
// goroutine, which exists while a dispatcher is attached. The endpoint never
// owns the device: closing the endpoint stops using the device, it does not
// close it.
type LinkEndpoint struct {
	deviceMTU uint32
	device    GVisorDevice

	// target is the dispatcher that inbound packets are handed to; nil
	// means detached. It is only stored with mu held, but the reader loads
	// it without the lock for every packet.
	target atomic.Pointer[dispatchTarget]

	// mu guards the flags below. It is never held while calling into the
	// device or the dispatcher: gVisor may call Attach(nil) while holding
	// the stack mutex, and delivery may need that very mutex.
	mu sync.Mutex
	// readerRunning is set while the reader goroutine is alive.
	readerRunning bool
	// deviceBroken is set once the device reported a fatal read error.
	deviceBroken bool
	// closed is set by Close and forbids any further reader.
	closed bool
}

type dispatchTarget struct {
	dispatcher stack.NetworkDispatcher
}

// MTU implements stack.LinkEndpoint.
func (e *LinkEndpoint) MTU() uint32 { return e.deviceMTU }

// SetMTU implements stack.LinkEndpoint. The MTU comes from the configuration
// and is not changed at runtime.
func (e *LinkEndpoint) SetMTU(uint32) {}

// MaxHeaderLength implements stack.LinkEndpoint. A TUN device carries IP
// packets without any link-layer header.
func (e *LinkEndpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements stack.LinkEndpoint. A point-to-point IP link has no
// hardware address.
func (e *LinkEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

// SetLinkAddress implements stack.LinkEndpoint; there is no address to set.
func (e *LinkEndpoint) SetLinkAddress(tcpip.LinkAddress) {}

// Capabilities implements stack.LinkEndpoint. Inbound checksums are not
// verified again by the stack. Nothing is promised for outbound checksums,
// so the stack computes them, and no neighbour resolution is needed.
func (e *LinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

// Attach implements stack.LinkEndpoint. A non-nil dispatcher becomes the
// receiver of inbound packets and a reader goroutine is started unless one is
// already running. A nil dispatcher detaches the endpoint and lets the reader
// wind down on its own; Attach does not wait for it.
func (e *LinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if dispatcher == nil || e.closed {
		e.target.Store(nil)
		return
	}
	e.target.Store(&dispatchTarget{dispatcher: dispatcher})
	if e.readerRunning || e.deviceBroken {
		return
	}
	e.readerRunning = true
	go e.readLoop()
}

// IsAttached implements stack.LinkEndpoint.
func (e *LinkEndpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.target.Load() != nil && !e.deviceBroken
}

// Wait implements stack.LinkEndpoint. It deliberately returns at once. The
// reader may be parked inside device.Wait until the device itself is closed,
// which happens only after the stack is torn down, and gVisor calls Wait with
// the stack mutex held; waiting here could hang that teardown forever.
func (e *LinkEndpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.
func (e *LinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint. There is no link header to add.
func (e *LinkEndpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint. There is no link header to
// parse, so every packet is accepted as it is.
func (e *LinkEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close implements stack.LinkEndpoint. It detaches the endpoint for good; the
// device stays open because its owner closes it separately.
func (e *LinkEndpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.target.Store(nil)
}

// SetOnCloseAction implements stack.LinkEndpoint. The device's lifetime is
// managed by its owner, not by the endpoint, so there is nothing to run.
func (e *LinkEndpoint) SetOnCloseAction(func()) {}

// WritePackets implements stack.LinkEndpoint. Packets go to the device one by
// one, in order; the first failure stops the batch. The caller keeps its
// references: the device copies each packet before WritePacket returns.
// No endpoint lock is taken, so concurrent senders are serialised by the
// device alone.
func (e *LinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	written := 0
	for _, pkt := range pkts.AsSlice() {
		if err := e.device.WritePacket(pkt); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// readLoop pulls packets from the device and hands them to the dispatcher
// until the endpoint is detached or closed, or the device fails.
func (e *LinkEndpoint) readLoop() {
	for {
		if e.target.Load() == nil && e.stopReading() {
			return
		}

		version, pkt, err := e.device.ReadPacket()
		switch {
		case errors.Is(err, ErrQueueEmpty):
			// How to wait for more input is the device's business.
			e.device.Wait()
		case err != nil:
			e.markDeviceBroken(err)
			return
		case pkt == nil:
			// Success without a packet breaks the device contract; treat it
			// like an empty queue rather than crash the reader.
			e.device.Wait()
		default:
			e.dispatch(version, pkt)
		}
	}
}

// stopReading retires the reader if the endpoint is still detached. The
// re-check under mu pairs with Attach: either Attach already stored a new
// dispatcher and this reader keeps serving it, or Attach will find
// readerRunning false and start a fresh reader.
func (e *LinkEndpoint) stopReading() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.target.Load() != nil {
		return false
	}
	e.readerRunning = false
	return true
}

func (e *LinkEndpoint) markDeviceBroken(cause error) {
	e.mu.Lock()
	e.deviceBroken = true
	e.readerRunning = false
	e.mu.Unlock()
	xerrors.LogInfoInner(context.Background(), cause, "[tun] reading from the device failed, no more inbound packets")
}

// dispatch hands one inbound packet to the current dispatcher and always
// drops the reference the device gave us, whatever happens to the packet.
func (e *LinkEndpoint) dispatch(version byte, pkt *stack.PacketBuffer) {
	defer pkt.DecRef()

	var proto tcpip.NetworkProtocolNumber
	switch version {
	case header.IPv4Version:
		proto = header.IPv4ProtocolNumber
	case header.IPv6Version:
		proto = header.IPv6ProtocolNumber
	default:
		return
	}

	// Detached while the read was in progress: drop the packet; the loop
	// notices the detachment on its next turn.
	target := e.target.Load()
	if target == nil {
		return
	}
	target.dispatcher.DeliverNetworkPacket(proto, pkt)
}
