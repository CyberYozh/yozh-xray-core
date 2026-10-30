//go:build windows

package tun

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fragmentedPacket builds a PacketBuffer whose bytes live in several separate
// chunks: two pushed headers in reserved space and a payload made of three
// independent views.
func fragmentedPacket(t *testing.T) *stack.PacketBuffer {
	t.Helper()
	var payload buffer.Buffer
	for _, chunk := range [][]byte{
		bytes.Repeat([]byte{0xa1}, 7),
		bytes.Repeat([]byte{0xb2}, 1),
		bytes.Repeat([]byte{0xc3}, 300),
	} {
		if err := payload.Append(buffer.NewViewWithData(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 64,
		Payload:            payload,
	})
	copy(pkt.TransportHeader().Push(8), []byte{1, 2, 3, 4, 5, 6, 7, 8})
	network := pkt.NetworkHeader().Push(20)
	for i := range network {
		network[i] = byte(0x40 + i)
	}
	return pkt
}

func TestFlattenPacketMatchesToView(t *testing.T) {
	pkt := fragmentedPacket(t)
	defer pkt.DecRef()
	if len(pkt.AsSlices()) < 2 {
		t.Fatal("test packet is not fragmented")
	}

	view := pkt.ToView()
	want := append([]byte(nil), view.AsSlice()...)
	view.Release()

	got := make([]byte, pkt.Size())
	if n := flattenPacket(got, pkt); n != len(want) {
		t.Fatalf("flattenPacket copied %d bytes, want %d", n, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("flattened bytes differ from ToView:\n got %x\nwant %x", got, want)
	}
	if refs := pkt.ReadRefs(); refs != 1 {
		t.Fatalf("flattenPacket changed the reference count to %d", refs)
	}
}

func TestFlattenPacketHandlesConsumedHeaders(t *testing.T) {
	// A packet read from the wire: headers are consumed from the payload
	// instead of pushed into reserved space.
	raw := make([]byte, 60)
	for i := range raw {
		raw[i] = byte(i)
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	defer pkt.DecRef()
	if _, ok := pkt.NetworkHeader().Consume(20); !ok {
		t.Fatal("cannot consume the network header")
	}

	got := make([]byte, pkt.Size())
	if n := flattenPacket(got, pkt); n != len(raw) || !bytes.Equal(got, raw) {
		t.Fatalf("flattenPacket = %d bytes %x, want %x", n, got, raw)
	}
}

func TestFlattenPacketStopsAtDestinationSize(t *testing.T) {
	pkt := fragmentedPacket(t)
	defer pkt.DecRef()
	short := make([]byte, 10)
	if n := flattenPacket(short, pkt); n != len(short) {
		t.Fatalf("flattenPacket wrote %d bytes into a %d-byte buffer", n, len(short))
	}
}
