package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	tunicmp "github.com/xtls/xray-core/proxy/tun/icmp"
	"github.com/xtls/xray-core/transport"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Documentation-only addresses (RFC 5737): a client behind the TUN and an
// arbitrary internet server it connects to.
var (
	// testClient lies inside testPool (udp_flow_test.go), the stand-in for the fake DNS pool. That is
	// harmless: the rule looks only at destinations.
	testClient = netip.MustParseAddrPort("198.51.100.7:40000")
	testServer = netip.MustParseAddrPort("203.0.113.10:443")
)

type tcpSegment struct {
	src, dst netip.AddrPort
	seq, ack uint32
	flags    header.TCPFlags
}

func (s tcpSegment) encode() []byte {
	srcAddr := tcpip.AddrFrom4(s.src.Addr().As4())
	dstAddr := tcpip.AddrFrom4(s.dst.Addr().As4())
	raw := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)

	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(raw)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	seg := header.TCP(raw[header.IPv4MinimumSize:])
	seg.Encode(&header.TCPFields{
		SrcPort:    s.src.Port(),
		DstPort:    s.dst.Port(),
		SeqNum:     s.seq,
		AckNum:     s.ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      s.flags,
		WindowSize: 65535,
	})
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, header.TCPMinimumSize)
	seg.SetChecksum(^seg.CalculateChecksum(pseudo))
	return raw
}

// expectSynAck checks that raw is the server's SYN-ACK to clientSeq and
// returns the server's initial sequence number.
func expectSynAck(t *testing.T, raw []byte, clientSeq uint32) uint32 {
	t.Helper()
	ip := header.IPv4(raw)
	if len(raw) < header.IPv4MinimumSize || !ip.IsValid(len(raw)) {
		t.Fatalf("outbound packet is not IPv4: %x", raw)
	}
	if got := ip.SourceAddress(); got != tcpip.AddrFrom4(testServer.Addr().As4()) {
		t.Fatalf("SYN-ACK source = %v, want %v", got, testServer.Addr())
	}
	if got := ip.DestinationAddress(); got != tcpip.AddrFrom4(testClient.Addr().As4()) {
		t.Fatalf("SYN-ACK destination = %v, want %v", got, testClient.Addr())
	}
	seg := header.TCP(ip.Payload())
	if seg.Flags() != header.TCPFlagSyn|header.TCPFlagAck {
		t.Fatalf("expected SYN-ACK, got flags %v", seg.Flags())
	}
	if seg.SourcePort() != testServer.Port() || seg.DestinationPort() != testClient.Port() {
		t.Fatalf("SYN-ACK ports %d -> %d", seg.SourcePort(), seg.DestinationPort())
	}
	if seg.AckNumber() != clientSeq+1 {
		t.Fatalf("SYN-ACK acknowledges %d, want %d", seg.AckNumber(), clientSeq+1)
	}
	return seg.SequenceNumber()
}

func destroyStack(s *stack.Stack) {
	for id := range s.NICInfo() {
		_ = s.RemoveNIC(id)
	}
	s.Close()
	s.Wait()
}

func TestCreateStackAppliesTCPTuning(t *testing.T) {
	link := channel.New(16, 1500, "")
	s, err := createStack(link)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyStack(s)

	if !s.HasNIC(bridgeNICID) {
		t.Fatalf("NIC %d is missing", bridgeNICID)
	}
	if !link.IsAttached() {
		t.Fatal("link endpoint is not attached to the stack")
	}

	var cc tcpip.CongestionControlOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil || cc != "cubic" {
		t.Fatalf("congestion control = %q (%v), want cubic", cc, err)
	}
	var sack tcpip.TCPSACKEnabled
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil || !bool(sack) {
		t.Fatalf("SACK = %v (%v), want enabled", sack, err)
	}
	var moderate tcpip.TCPModerateReceiveBufferOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil || !bool(moderate) {
		t.Fatalf("receive buffer moderation = %v (%v), want enabled", moderate, err)
	}
	recovery := tcpip.TCPRecovery(-1)
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil || recovery != 0 {
		t.Fatalf("recovery = %v (%v), want 0", recovery, err)
	}
	var rcv tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		t.Fatal(err)
	}
	if want := (tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 1 << 20, Max: 8 << 20}); rcv != want {
		t.Fatalf("receive buffer range = %+v, want %+v", rcv, want)
	}
	var snd tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		t.Fatal(err)
	}
	if want := (tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: 1 << 20, Max: 6 << 20}); snd != want {
		t.Fatalf("send buffer range = %+v, want %+v", snd, want)
	}
}

func TestCreateStackAcceptsConnectionsToAnyAddress(t *testing.T) {
	link := channel.New(16, 1500, "")
	s, err := createStack(link)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyStack(s)

	requests := make(chan stack.TransportEndpointID, 1)
	forwarder := tcp.NewForwarder(s, 0, 16, func(r *tcp.ForwarderRequest) {
		requests <- r.ID()
		go func() {
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err == nil {
				ep.Close()
			}
			r.Complete(err != nil)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	const clientSeq = 1000
	syn := tcpSegment{src: testClient, dst: testServer, seq: clientSeq, flags: header.TCPFlagSyn}.encode()
	link.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(syn),
	}))

	// Promiscuous mode: the SYN to an address the stack does not own reaches TCP.
	select {
	case id := <-requests:
		if id.LocalAddress != tcpip.AddrFrom4(testServer.Addr().As4()) || id.LocalPort != testServer.Port() {
			t.Fatalf("forwarder saw %v:%d, want %v", id.LocalAddress, id.LocalPort, testServer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SYN to an arbitrary address never reached the TCP handler")
	}

	// Spoofing: the stack answers from that foreign address.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out := link.ReadContext(ctx)
	if out == nil {
		t.Fatal("no SYN-ACK left the stack")
	}
	view := out.ToView()
	raw := append([]byte(nil), view.AsSlice()...)
	view.Release()
	out.DecRef()
	expectSynAck(t, raw, clientSeq)
}

func goroutinesSettleTo(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			t.Fatalf("goroutines leaked: %d > %d\n%s", runtime.NumGoroutine(), baseline, buf[:n])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAssembleStackFailureOnBusyNICLeavesNothingBehind(t *testing.T) {
	baseline := runtime.NumGoroutine()

	squatter := channel.New(4, 1500, "")
	ours := channel.New(4, 1500, "")
	occupy := stackSetupStep{
		name: "occupy the NIC id",
		run: func(s *stack.Stack, _ stack.LinkEndpoint) tcpip.Error {
			return s.CreateNIC(bridgeNICID, squatter)
		},
	}
	s, err := assembleStack(ours, append([]stackSetupStep{occupy}, tunStackSetup()...))
	if err == nil {
		destroyStack(s)
		t.Fatal("expected a duplicate NIC error")
	}
	if s != nil {
		t.Fatal("a stack was returned together with an error")
	}
	if !strings.Contains(err.Error(), "NIC") {
		t.Fatalf("error does not name the failed step: %v", err)
	}
	if squatter.IsAttached() || ours.IsAttached() {
		t.Fatal("a link endpoint stayed attached after the failure")
	}
	goroutinesSettleTo(t, baseline)
}

func TestAssembleStackFailureAfterAttachDetachesReader(t *testing.T) {
	baseline := runtime.NumGoroutine()

	dev := newScriptedDevice()
	ep := newTestEndpoint(dev)
	broken := stackSetupStep{
		name: "late failing step",
		run: func(*stack.Stack, stack.LinkEndpoint) tcpip.Error {
			return &tcpip.ErrInvalidOptionValue{}
		},
	}
	s, err := assembleStack(ep, append(tunStackSetup(), broken))
	if err == nil {
		destroyStack(s)
		t.Fatal("expected the injected failure")
	}
	if !strings.Contains(err.Error(), "late failing step") {
		t.Fatalf("error does not name the failed step: %v", err)
	}
	if ep.IsAttached() {
		t.Fatal("endpoint is still attached after the failure")
	}
	goroutinesSettleTo(t, baseline)
}

// pipeDevice is an in-memory GVisorDevice: the test writes inbound IP
// packets into it and reads what the stack sends back.
type pipeDevice struct {
	inbound  chan []byte
	outbound chan []byte
}

func newPipeDevice() *pipeDevice {
	return &pipeDevice{inbound: make(chan []byte, 64), outbound: make(chan []byte, 64)}
}

func (p *pipeDevice) ReadPacket() (byte, *stack.PacketBuffer, error) {
	select {
	case raw := <-p.inbound:
		return raw[0] >> 4, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(raw),
		}), nil
	default:
		return 0, nil, ErrQueueEmpty
	}
}

func (p *pipeDevice) Wait() {
	time.Sleep(100 * time.Microsecond)
}

func (p *pipeDevice) WritePacket(pkt *stack.PacketBuffer) tcpip.Error {
	view := pkt.ToView()
	raw := append([]byte(nil), view.AsSlice()...)
	view.Release()
	select {
	case p.outbound <- raw:
		return nil
	default:
		return &tcpip.ErrWouldBlock{}
	}
}

func (p *pipeDevice) nextOutbound(t *testing.T) []byte {
	t.Helper()
	select {
	case raw := <-p.outbound:
		return raw
	case <-time.After(5 * time.Second):
		t.Fatal("nothing left the stack")
		return nil
	}
}

// pipeTun is a Tun over a pipeDevice. It keeps the endpoint it handed out, so
// that a test can see whether the stack still has it attached.
type pipeTun struct {
	dev *pipeDevice
	ep  *LinkEndpoint
}

func (p *pipeTun) Start() error          { return nil }
func (p *pipeTun) Close() error          { return nil }
func (p *pipeTun) Name() (string, error) { return "pipe0", nil }
func (p *pipeTun) Index() (int, error)   { return 0, nil }
func (p *pipeTun) newEndpoint() (stack.LinkEndpoint, error) {
	p.ep = &LinkEndpoint{deviceMTU: 1500, device: p.dev}
	return p.ep, nil
}

// holdingDispatcher keeps every connection open by reading from it until the
// read fails, and reports that failure.
type holdingDispatcher struct {
	entered   chan struct{}
	enterOnce sync.Once
	readErr   chan error
}

func newHoldingDispatcher() *holdingDispatcher {
	return &holdingDispatcher{entered: make(chan struct{}), readErr: make(chan error, 4)}
}

func (d *holdingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *holdingDispatcher) Start() error      { return nil }
func (d *holdingDispatcher) Close() error      { return nil }
func (d *holdingDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *holdingDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	d.enterOnce.Do(func() { close(d.entered) })
	for {
		mb, err := link.Reader.ReadMultiBuffer()
		buf.ReleaseMulti(mb)
		if err != nil {
			d.readErr <- err
			return err
		}
	}
}

func TestNetBridgeCloseWithoutStart(t *testing.T) {
	br := &netBridge{}
	if err := br.Close(); err != nil {
		t.Fatalf("first Close = %v", err)
	}
	if err := br.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func startPipeBridge(t *testing.T) (*netBridge, *pipeTun, *holdingDispatcher) {
	t.Helper()
	pipe := &pipeTun{dev: newPipeDevice()}
	disp := newHoldingDispatcher()
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: disp}
	br, err := newNetBridge(context.Background(), pipe, handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := br.Start(); err != nil {
		t.Fatal(err)
	}
	return br, pipe, disp
}

func TestNetBridgeCloseAbortsConnectionsAndDetaches(t *testing.T) {
	br, pipe, disp := startPipeBridge(t)
	dev := pipe.dev

	const clientSeq = 5000
	dev.inbound <- tcpSegment{src: testClient, dst: testServer, seq: clientSeq, flags: header.TCPFlagSyn}.encode()
	serverSeq := expectSynAck(t, dev.nextOutbound(t), clientSeq)
	dev.inbound <- tcpSegment{src: testClient, dst: testServer, seq: clientSeq + 1, ack: serverSeq + 1, flags: header.TCPFlagAck}.encode()

	select {
	case <-disp.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection never reached the handler")
	}

	if err := br.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	select {
	case err := <-disp.readErr:
		if err == nil {
			t.Fatal("reader finished without an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an established connection kept blocking after Close")
	}
	if pipe.ep.IsAttached() {
		t.Fatal("link endpoint is still attached after Close")
	}
	if err := br.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}

	// Late replies from goroutines that outlive the stack must fail, not panic.
	reply := xnet.UDPDestination(xnet.IPAddress(testServer.Addr().AsSlice()), 53)
	client := xnet.UDPDestination(xnet.IPAddress(testClient.Addr().AsSlice()), 40000)
	if err := br.writeRawUDPPacket([]byte("late"), reply, client); err == nil {
		t.Fatal("a UDP reply went through a closed stack")
	}
	echo := []byte{byte(header.ICMPv4EchoReply), 0, 0, 0, 0, 1, 0, 1}
	if err := br.writeRawICMPPacket(header.IPv4ProtocolNumber, echo,
		tcpip.AddrFrom4(testServer.Addr().As4()), tcpip.AddrFrom4(testClient.Addr().As4())); err == nil {
		t.Fatal("an ICMP reply went through a closed stack")
	}
}

func TestNetBridgeConcurrentClose(t *testing.T) {
	br, pipe, _ := startPipeBridge(t)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- br.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close calls did not finish")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	}
	if pipe.ep.IsAttached() {
		t.Fatal("link endpoint is still attached after Close")
	}
}

// Documentation-only IPv6 addresses (RFC 3849), the counterparts of
// testClient and testServer.
var (
	testClient6 = netip.MustParseAddrPort("[2001:db8::7]:40000")
	testServer6 = netip.MustParseAddrPort("[2001:db8::10]:443")
)

// testPeers is a client and a server of one address family.
type testPeers struct {
	family         string
	client, server netip.AddrPort
}

var bothFamilies = []testPeers{
	{"IPv4", testClient, testServer},
	{"IPv6", testClient6, testServer6},
}

func stackAddr(a netip.Addr) tcpip.Address {
	if a.Is4() {
		return tcpip.AddrFrom4(a.As4())
	}
	return tcpip.AddrFrom16(a.As16())
}

func netipAddr(a tcpip.Address) netip.Addr {
	addr, _ := netip.AddrFromSlice(a.AsSlice())
	return addr
}

func tcpDest(ap netip.AddrPort) xnet.Destination {
	return xnet.TCPDestination(xnet.IPAddress(ap.Addr().AsSlice()), xnet.Port(ap.Port()))
}

func udpDest(ap netip.AddrPort) xnet.Destination {
	return xnet.UDPDestination(xnet.IPAddress(ap.Addr().AsSlice()), xnet.Port(ap.Port()))
}

// ipPacket puts message behind an IPv4 or an IPv6 header, whichever family
// src and dst belong to.
func ipPacket(src, dst netip.Addr, proto tcpip.TransportProtocolNumber, message []byte) []byte {
	if src.Is4() {
		raw := make([]byte, header.IPv4MinimumSize+len(message))
		ip := header.IPv4(raw)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(raw)),
			TTL:         64,
			Protocol:    uint8(proto),
			SrcAddr:     stackAddr(src),
			DstAddr:     stackAddr(dst),
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		copy(raw[header.IPv4MinimumSize:], message)
		return raw
	}
	raw := make([]byte, header.IPv6MinimumSize+len(message))
	header.IPv6(raw).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(message)),
		TransportProtocol: proto,
		HopLimit:          64,
		SrcAddr:           stackAddr(src),
		DstAddr:           stackAddr(dst),
	})
	copy(raw[header.IPv6MinimumSize:], message)
	return raw
}

// tcpPacket is a TCP segment with a valid checksum, in either family.
func tcpPacket(src, dst netip.AddrPort, seq, ack uint32, flags header.TCPFlags, payload []byte) []byte {
	seg := make([]byte, header.TCPMinimumSize+len(payload))
	hdr := header.TCP(seg)
	hdr.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     seq,
		AckNum:     ack,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(seg[header.TCPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, stackAddr(src.Addr()), stackAddr(dst.Addr()), uint16(len(seg)))
	hdr.SetChecksum(^hdr.CalculateChecksum(checksum.Checksum(payload, xsum)))
	return ipPacket(src.Addr(), dst.Addr(), header.TCPProtocolNumber, seg)
}

// udpPacket is a UDP datagram with a valid checksum, in either family.
func udpPacket(src, dst netip.AddrPort, payload []byte) []byte {
	return udpPacketWithLength(src, dst, payload, header.UDPMinimumSize+len(payload))
}

// udpPacketWithLength is udpPacket with the UDP length field set to length,
// whatever the payload's size.
func udpPacketWithLength(src, dst netip.AddrPort, payload []byte, length int) []byte {
	dgram := make([]byte, header.UDPMinimumSize+len(payload))
	hdr := header.UDP(dgram)
	hdr.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(length),
	})
	copy(dgram[header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, stackAddr(src.Addr()), stackAddr(dst.Addr()), uint16(len(dgram)))
	hdr.SetChecksum(^hdr.CalculateChecksum(checksum.Checksum(payload, xsum)))
	return ipPacket(src.Addr(), dst.Addr(), header.UDPProtocolNumber, dgram)
}

// paddedUDPPacket is udpPacket followed by padding zero bytes that the IP
// packet carries and the UDP length field does not count. Zero bytes leave the
// checksum the same whether it is summed over them or not.
func paddedUDPPacket(src, dst netip.AddrPort, payload []byte, padding int) []byte {
	length := header.UDPMinimumSize + len(payload)
	dgram := make([]byte, length+padding)
	hdr := header.UDP(dgram)
	hdr.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(length),
	})
	copy(dgram[header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, stackAddr(src.Addr()), stackAddr(dst.Addr()), uint16(length))
	hdr.SetChecksum(^hdr.CalculateChecksum(checksum.Checksum(payload, xsum)))
	return ipPacket(src.Addr(), dst.Addr(), header.UDPProtocolNumber, dgram)
}

// echoRequest is an ICMP echo request, ICMPv4 or ICMPv6 after the family of
// src.
func echoRequest(t *testing.T, src, dst netip.Addr, ident, sequence uint16, payload []byte) []byte {
	t.Helper()
	netProto, transProto, kind := header.IPv4ProtocolNumber, header.ICMPv4ProtocolNumber, byte(header.ICMPv4Echo)
	if !src.Is4() {
		netProto, transProto, kind = header.IPv6ProtocolNumber, header.ICMPv6ProtocolNumber, byte(header.ICMPv6EchoRequest)
	}
	msg := make([]byte, 8+len(payload))
	msg[0] = kind
	binary.BigEndian.PutUint16(msg[4:], ident)
	binary.BigEndian.PutUint16(msg[6:], sequence)
	copy(msg[8:], payload)
	if err := tunicmp.RewriteChecksum(netProto, msg, stackAddr(src), stackAddr(dst)); err != nil {
		t.Fatal(err)
	}
	return ipPacket(src, dst, transProto, msg)
}

// outboundPacket is one packet that left the stack, taken apart.
type outboundPacket struct {
	src, dst  netip.Addr
	proto     tcpip.TransportProtocolNumber
	transport []byte
}

// parseOutbound takes apart a packet the stack sent to the device. It fails
// the test unless the packet is a well-formed IPv4 packet with a correct
// header checksum or a well-formed IPv6 packet.
func parseOutbound(t *testing.T, raw []byte) outboundPacket {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("an empty packet left the stack")
	}
	switch raw[0] >> 4 {
	case header.IPv4Version:
		ip := header.IPv4(raw)
		if len(raw) < header.IPv4MinimumSize || !ip.IsValid(len(raw)) {
			t.Fatalf("malformed IPv4 packet: %x", raw)
		}
		if !ip.IsChecksumValid() {
			t.Fatalf("IPv4 header checksum is wrong: %x", raw)
		}
		return outboundPacket{netipAddr(ip.SourceAddress()), netipAddr(ip.DestinationAddress()), ip.TransportProtocol(), ip.Payload()}
	case header.IPv6Version:
		ip := header.IPv6(raw)
		if !ip.IsValid(len(raw)) {
			t.Fatalf("malformed IPv6 packet: %x", raw)
		}
		return outboundPacket{netipAddr(ip.SourceAddress()), netipAddr(ip.DestinationAddress()), ip.TransportProtocol(), ip.Payload()}
	}
	t.Fatalf("not an IP packet: %x", raw)
	return outboundPacket{}
}

// transportChecksumValid checks the checksum of a TCP, UDP or ICMPv6 message
// over its pseudo-header, or of an ICMPv4 message on its own.
func (p outboundPacket) transportChecksumValid() bool {
	var initial uint16
	if p.proto != header.ICMPv4ProtocolNumber {
		initial = header.PseudoHeaderChecksum(p.proto, stackAddr(p.src), stackAddr(p.dst), uint16(len(p.transport)))
	}
	return checksum.Checksum(p.transport, initial) == 0xffff
}

// nextOutboundOf returns the next packet of the given transport protocol that
// leaves the stack, skipping the others (acknowledgements and the like).
func nextOutboundOf(t *testing.T, dev *pipeDevice, proto tcpip.TransportProtocolNumber) outboundPacket {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case raw := <-dev.outbound:
			if p := parseOutbound(t, raw); p.proto == proto {
				return p
			}
		case <-deadline:
			t.Fatalf("no packet of protocol %d left the stack", proto)
			return outboundPacket{}
		}
	}
}

func expectNoOutbound(t *testing.T, dev *pipeDevice, wait time.Duration) {
	t.Helper()
	select {
	case raw := <-dev.outbound:
		t.Fatalf("unexpected packet left the stack: %x", raw)
	case <-time.After(wait):
	}
}

// handledConn is one connection a recordingHandler was given. The handler
// keeps it open until release is called.
type handledConn struct {
	conn    xnet.Conn
	dest    xnet.Destination
	release func()
}

// recordingHandler is a ConnectionHandler that reports every connection it
// is given and serves it until the test releases it. Like the real handler,
// it closes the connection before returning.
type recordingHandler struct {
	got chan handledConn
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{got: make(chan handledConn, 16)}
}

func (h *recordingHandler) HandleConnection(conn xnet.Conn, dest xnet.Destination) {
	released := make(chan struct{})
	var once sync.Once
	h.got <- handledConn{conn: conn, dest: dest, release: func() { once.Do(func() { close(released) }) }}
	<-released
	conn.Close()
}

// next waits for the next connection; the test releases it at the latest
// when it ends.
func (h *recordingHandler) next(t *testing.T) handledConn {
	t.Helper()
	select {
	case c := <-h.got:
		t.Cleanup(c.release)
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection reached the handler")
		return handledConn{}
	}
}

// returningHandler returns from every connection at once, without closing it.
type returningHandler struct {
	calls atomic.Int32
}

func (h *returningHandler) HandleConnection(xnet.Conn, xnet.Destination) {
	h.calls.Add(1)
}

// countingTun is a pipeTun that counts the endpoints asked of it and can be
// told to refuse them.
type countingTun struct {
	pipeTun
	calls atomic.Int32
	fail  error
}

func newCountingTun() *countingTun {
	return &countingTun{pipeTun: pipeTun{dev: newPipeDevice()}}
}

func (c *countingTun) newEndpoint() (stack.LinkEndpoint, error) {
	c.calls.Add(1)
	if c.fail != nil {
		return nil, c.fail
	}
	return c.pipeTun.newEndpoint()
}

func newTestBridge(t *testing.T, conns ConnectionHandler) (*netBridge, *countingTun) {
	t.Helper()
	tun := newCountingTun()
	br, err := newNetBridge(context.Background(), tun, conns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = br.Close() })
	return br, tun
}

func startTestBridge(t *testing.T) (*netBridge, *countingTun, *recordingHandler) {
	t.Helper()
	conns := newRecordingHandler()
	br, tun := newTestBridge(t, conns)
	if err := br.Start(); err != nil {
		t.Fatal(err)
	}
	return br, tun, conns
}

// handshake completes a TCP handshake from client to server through dev and
// returns the server's initial sequence number.
func handshake(t *testing.T, dev *pipeDevice, client, server netip.AddrPort, clientSeq uint32) uint32 {
	t.Helper()
	dev.inbound <- tcpPacket(client, server, clientSeq, 0, header.TCPFlagSyn, nil)
	serverSeq := expectSynAckFrom(t, parseOutbound(t, dev.nextOutbound(t)), client, server, clientSeq)
	dev.inbound <- tcpPacket(client, server, clientSeq+1, serverSeq+1, header.TCPFlagAck, nil)
	return serverSeq
}

func expectSynAckFrom(t *testing.T, p outboundPacket, client, server netip.AddrPort, clientSeq uint32) uint32 {
	t.Helper()
	if p.proto != header.TCPProtocolNumber || p.src != server.Addr() || p.dst != client.Addr() {
		t.Fatalf("expected TCP from %v to %v, got protocol %d from %v to %v", server.Addr(), client.Addr(), p.proto, p.src, p.dst)
	}
	seg := header.TCP(p.transport)
	if seg.Flags() != header.TCPFlagSyn|header.TCPFlagAck {
		t.Fatalf("expected SYN-ACK, got flags %v", seg.Flags())
	}
	if seg.SourcePort() != server.Port() || seg.DestinationPort() != client.Port() {
		t.Fatalf("SYN-ACK ports %d -> %d, want %d -> %d", seg.SourcePort(), seg.DestinationPort(), server.Port(), client.Port())
	}
	if seg.AckNumber() != clientSeq+1 {
		t.Fatalf("SYN-ACK acknowledges %d, want %d", seg.AckNumber(), clientSeq+1)
	}
	return seg.SequenceNumber()
}

func TestNetBridgeRejectsMissingParts(t *testing.T) {
	tun := newCountingTun()
	conns := newRecordingHandler()
	var noContext context.Context
	cases := []struct {
		name  string
		ctx   context.Context
		tun   Tun
		conns ConnectionHandler
	}{
		{"context", noContext, tun, conns},
		{"device", context.Background(), nil, conns},
		{"connection handler", context.Background(), tun, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br, err := newNetBridge(tc.ctx, tc.tun, tc.conns)
			if err == nil {
				_ = br.Close()
				t.Fatalf("newNetBridge accepted a missing %s", tc.name)
			}
		})
	}
	if n := tun.calls.Load(); n != 0 {
		t.Fatalf("newEndpoint was called %d times", n)
	}
}

func TestNetBridgeConstructorOpensNothing(t *testing.T) {
	baseline := runtime.NumGoroutine()
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "bridge")
	tun := newCountingTun()
	br, err := newNetBridge(ctx, tun, newRecordingHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	if br.ns != nil {
		t.Fatal("a stack exists before Start")
	}
	if br.logCtx != ctx {
		t.Fatal("logCtx is not the given context")
	}
	if n := tun.calls.Load(); n != 0 {
		t.Fatalf("newEndpoint was called %d times before Start", n)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Fatalf("the constructor started %d goroutines", n-baseline)
	}
}

func TestNetBridgeStartTwiceFails(t *testing.T) {
	br, tun, _ := startTestBridge(t)
	running := br.ns

	if err := br.Start(); err == nil {
		t.Fatal("a second Start succeeded")
	}
	if n := tun.calls.Load(); n != 1 {
		t.Fatalf("newEndpoint was called %d times, want 1", n)
	}
	if br.ns != running {
		t.Fatal("the second Start replaced the running stack")
	}

	const clientSeq = 300
	tun.dev.inbound <- tcpSegment{src: testClient, dst: testServer, seq: clientSeq, flags: header.TCPFlagSyn}.encode()
	expectSynAck(t, tun.dev.nextOutbound(t), clientSeq)
}

func TestNetBridgeStartAfterCloseFails(t *testing.T) {
	br, tun := newTestBridge(t, newRecordingHandler())
	if err := br.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := br.Start(); err == nil {
		t.Fatal("Start succeeded on a closed bridge")
	}
	if n := tun.calls.Load(); n != 0 {
		t.Fatalf("newEndpoint was called %d times after Close", n)
	}
	if br.ns != nil {
		t.Fatal("a closed bridge got a stack")
	}
}

func TestNetBridgeEndpointFailure(t *testing.T) {
	sentinel := errors.New("no endpoint today")
	br, tun := newTestBridge(t, newRecordingHandler())
	tun.fail = sentinel

	err := br.Start()
	if !errors.Is(err, sentinel) {
		t.Fatalf("Start = %v, want an error wrapping %v", err, sentinel)
	}
	if !strings.HasPrefix(err.Error(), "proxy/tun: ") {
		t.Fatalf("error text %q does not start with the package", err)
	}
	if br.ns != nil {
		t.Fatal("a stack exists after a failed Start")
	}
	if err := br.Close(); err != nil {
		t.Fatalf("Close after a failed Start = %v", err)
	}
	if err := br.Start(); err == nil {
		t.Fatal("Start after Close succeeded")
	}
	if n := tun.calls.Load(); n != 1 {
		t.Fatalf("newEndpoint was called %d times, want 1", n)
	}
}

func TestNetBridgeAssemblyFailureLeavesNothingBehind(t *testing.T) {
	baseline := runtime.NumGoroutine()

	br, tun := newTestBridge(t, newRecordingHandler())
	// The failure comes after every step of the bridge, handlers included.
	br.setup = func() []stackSetupStep {
		return append(br.bridgeStackSetup(), stackSetupStep{
			name: "injected failure",
			run: func(*stack.Stack, stack.LinkEndpoint) tcpip.Error {
				return &tcpip.ErrInvalidOptionValue{}
			},
		})
	}
	// A packet is already waiting: a reader that ran even briefly would
	// take it and answer it.
	tun.dev.inbound <- tcpSegment{src: testClient, dst: testServer, seq: 1, flags: header.TCPFlagSyn}.encode()

	err := br.Start()
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Start = %v, want the injected failure", err)
	}
	if tun.ep == nil {
		t.Fatal("the endpoint was never asked for")
	}
	if tun.ep.IsAttached() {
		t.Fatal("the endpoint is attached after a failed Start")
	}
	if br.ns != nil {
		t.Fatal("ns is set after a failed Start")
	}
	if len(tun.dev.inbound) != 1 {
		t.Fatal("the device was read although the stack never went into service")
	}
	if err := br.Close(); err != nil {
		t.Fatalf("Close after a failed Start = %v", err)
	}
	expectNoOutbound(t, tun.dev, 50*time.Millisecond)
	goroutinesSettleTo(t, baseline)
}

func TestNetBridgeFirstPacketMeetsTheHandlers(t *testing.T) {
	const clientSeq = 900
	for round := 0; round < 200; round++ {
		tun := newCountingTun()
		// The SYN waits in the device, so it is the very first packet the
		// endpoint delivers once it is attached.
		tun.dev.inbound <- tcpSegment{src: testClient, dst: testServer, seq: clientSeq, flags: header.TCPFlagSyn}.encode()
		br, err := newNetBridge(context.Background(), tun, newRecordingHandler())
		if err != nil {
			t.Fatal(err)
		}
		if err := br.Start(); err != nil {
			t.Fatal(err)
		}
		// A reset here means the SYN reached the stack before the TCP
		// handler; nothing at all means it was dropped before promiscuous
		// mode was on.
		expectSynAck(t, tun.dev.nextOutbound(t), clientSeq)
		if err := br.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNetBridgeHandsTCPConnectionsToTheHandler(t *testing.T) {
	for _, peers := range bothFamilies {
		t.Run(peers.family, func(t *testing.T) {
			_, tun, conns := startTestBridge(t)
			const clientSeq = 7000
			serverSeq := handshake(t, tun.dev, peers.client, peers.server, clientSeq)

			got := conns.next(t)
			if want := tcpDest(peers.server); got.dest != want {
				t.Fatalf("destination = %v, want %v", got.dest, want)
			}
			remote := got.conn.RemoteAddr()
			if remote == nil {
				t.Fatal("RemoteAddr is nil")
			}
			if src, want := xnet.DestinationFromAddr(remote), tcpDest(peers.client); src != want {
				t.Fatalf("RemoteAddr = %v, want %v", src, want)
			}

			payload := []byte("hello through the tunnel")
			tun.dev.inbound <- tcpPacket(peers.client, peers.server, clientSeq+1, serverSeq+1, header.TCPFlagAck|header.TCPFlagPsh, payload)
			if err := got.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			read := make([]byte, len(payload))
			if _, err := io.ReadFull(got.conn, read); err != nil {
				t.Fatalf("reading the client's data: %v", err)
			}
			if !bytes.Equal(read, payload) {
				t.Fatalf("read %q, want %q", read, payload)
			}
		})
	}
}

func TestNetBridgeReleasesConnectionsTheHandlerLeftOpen(t *testing.T) {
	conns := &returningHandler{}
	br, tun := newTestBridge(t, conns)
	if err := br.Start(); err != nil {
		t.Fatal(err)
	}
	handshake(t, tun.dev, testClient, testServer, 40)

	// The handler returned without closing its conn; the endpoint must be
	// closed all the same, which the client sees as a FIN.
	for {
		p := nextOutboundOf(t, tun.dev, header.TCPProtocolNumber)
		if header.TCP(p.transport).Flags()&header.TCPFlagFin != 0 {
			break
		}
	}
	if n := conns.calls.Load(); n != 1 {
		t.Fatalf("HandleConnection was called %d times, want 1", n)
	}
}

func TestNetBridgeBoundsHandshakesAndFreesTheirSlots(t *testing.T) {
	if tcpHandshakeLimit < 1024 || tcpHandshakeLimit > 65535 {
		t.Fatalf("handshake bound %d is outside [1024, 65535]", tcpHandshakeLimit)
	}

	conns := newRecordingHandler()
	br, tun := newTestBridge(t, conns)
	br.handshakeLimit = 1
	if err := br.Start(); err != nil {
		t.Fatal(err)
	}
	first, second := testClient, netip.AddrPortFrom(testClient.Addr(), testClient.Port()+1)

	// The first handshake is in progress: a second SYN finds no free slot
	// and is ignored.
	tun.dev.inbound <- tcpPacket(first, testServer, 10, 0, header.TCPFlagSyn, nil)
	serverSeq := expectSynAckFrom(t, parseOutbound(t, tun.dev.nextOutbound(t)), first, testServer, 10)
	tun.dev.inbound <- tcpPacket(second, testServer, 20, 0, header.TCPFlagSyn, nil)
	expectNoOutbound(t, tun.dev, 200*time.Millisecond)

	// Once established, the first connection stays open but no longer
	// holds the slot: the retransmitted second SYN goes through.
	tun.dev.inbound <- tcpPacket(first, testServer, 11, serverSeq+1, header.TCPFlagAck, nil)
	conns.next(t)
	tun.dev.inbound <- tcpPacket(second, testServer, 20, 0, header.TCPFlagSyn, nil)
	expectSynAckFrom(t, parseOutbound(t, tun.dev.nextOutbound(t)), second, testServer, 20)
}

func TestNetBridgeCarriesUDPBothWays(t *testing.T) {
	for _, peers := range bothFamilies {
		t.Run(peers.family, func(t *testing.T) {
			_, tun, conns := startTestBridge(t)
			server := netip.AddrPortFrom(peers.server.Addr(), 53)

			query := []byte("where is example.test")
			tun.dev.inbound <- udpPacket(peers.client, server, query)

			got := conns.next(t)
			if want := udpDest(server); got.dest != want {
				t.Fatalf("destination = %v, want %v", got.dest, want)
			}
			if src, want := xnet.DestinationFromAddr(got.conn.RemoteAddr()), udpDest(peers.client); src != want {
				t.Fatalf("RemoteAddr = %v, want %v", src, want)
			}
			read := make([]byte, 512)
			n, err := got.conn.Read(read)
			if err != nil || !bytes.Equal(read[:n], query) {
				t.Fatalf("Read = %q, %v; want %q", read[:n], err, query)
			}

			answer := []byte("right here")
			if _, err := got.conn.Write(answer); err != nil {
				t.Fatal(err)
			}
			// The first packet out is the reply: no ICMP error was sent for
			// the query.
			p := parseOutbound(t, tun.dev.nextOutbound(t))
			if p.proto != header.UDPProtocolNumber || p.src != server.Addr() || p.dst != peers.client.Addr() {
				t.Fatalf("reply: protocol %d from %v to %v", p.proto, p.src, p.dst)
			}
			dgram := header.UDP(p.transport)
			if dgram.SourcePort() != server.Port() || dgram.DestinationPort() != peers.client.Port() {
				t.Fatalf("reply ports %d -> %d", dgram.SourcePort(), dgram.DestinationPort())
			}
			if !bytes.Equal(dgram.Payload(), answer) {
				t.Fatalf("reply payload %q, want %q", dgram.Payload(), answer)
			}
			if !p.transportChecksumValid() {
				t.Fatal("reply UDP checksum is wrong")
			}
		})
	}
}

// flowListingDispatcher reports the destination and the first datagram of every UDP flow it is given,
// and keeps the flow open until done is closed. It reports the flow's route as the engine's dispatcher
// does (one route for every flow), so that the flow table can match the source's next destination to
// the flow instead of waiting for the report.
//
// The bridge's Close does not end UDP flows, so the test closes done when it finishes, and the flows
// return then and not before: once the first flow is gone the table holds nothing of the source, and
// the second pool address opens a flow of its own with the rule or without it.
type flowListingDispatcher struct {
	*holdingDispatcher
	flows chan listedFlow
	done  chan struct{}
}

type listedFlow struct {
	dest  xnet.Destination
	first string
}

func (d *flowListingDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	if report := session.FlowRouteReportFromContext(ctx); report != nil {
		report(session.FlowRoute{Tag: "out", RouteOf: func(xnet.Destination, [][]byte) (string, error) { return "out", nil }})
	}
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	first := ""
	if len(mb) > 0 {
		first = string(mb[0].Bytes())
	}
	buf.ReleaseMulti(mb)
	d.flows <- listedFlow{dest: dest, first: first}
	<-d.done
	return nil
}

// The bridge builds its flow table by the function the tests of the real engine build theirs by, so
// the tun handler's rule for fake DNS reaches it: two pool addresses from one socket are two flows,
// though the route of the first is the second's too.
func TestNetBridgeGivesTheAddressesOfFakeDNSFlowsOfTheirOwn(t *testing.T) {
	disp := &flowListingDispatcher{holdingDispatcher: newHoldingDispatcher(), flows: make(chan listedFlow, 4), done: make(chan struct{})}
	handler := &Handler{ctx: context.Background(), config: &Config{}, dispatcher: disp, fakeDNS: &stubFakeDNS{pool: testPool}}
	br, tun := newTestBridge(t, handler)
	t.Cleanup(func() { close(disp.done) })
	if err := br.Start(); err != nil {
		t.Fatal(err)
	}

	one, two := netip.MustParseAddrPort("198.51.100.1:3478"), netip.MustParseAddrPort("198.51.100.2:3478")
	tun.dev.inbound <- udpPacket(testClient, one, []byte("one"))
	tun.dev.inbound <- udpPacket(testClient, two, []byte("two"))

	got := map[xnet.Destination]string{}
	for len(got) < 2 {
		select {
		case flow := <-disp.flows:
			got[flow.dest] = flow.first
		case <-time.After(3 * time.Second):
			t.Fatalf("the dispatcher was given %d flow(s), %v; want one for each pool address", len(got), got)
		}
	}
	if got[udpDest(one)] != "one" || got[udpDest(two)] != "two" {
		t.Fatalf("the dispatcher was given %v; want %v with its first datagram \"one\" and %v with \"two\"", got, udpDest(one), udpDest(two))
	}
}

func TestNetBridgeUDPPayloadEndsAtTheLengthField(t *testing.T) {
	for _, peers := range bothFamilies {
		t.Run(peers.family, func(t *testing.T) {
			_, tun, conns := startTestBridge(t)
			server := netip.AddrPortFrom(peers.server.Addr(), 53)

			// The IP packet goes on past the datagram's end: those bytes
			// are not part of the payload.
			query := []byte("where is example.test")
			tun.dev.inbound <- paddedUDPPacket(peers.client, server, query, 6)

			got := conns.next(t)
			read := make([]byte, 512)
			n, err := got.conn.Read(read)
			if err != nil || !bytes.Equal(read[:n], query) {
				t.Fatalf("Read = %q, %v; want %q", read[:n], err, query)
			}
		})
	}
}

func TestNetBridgeDropsDatagramsItCannotCarry(t *testing.T) {
	server := netip.AddrPortFrom(testServer6.Addr(), 53)
	mapped := netip.AddrPortFrom(netip.AddrFrom16(testClient.Addr().As16()), testClient.Port())
	cases := []struct {
		name   string
		packet []byte
	}{
		// gVisor's IPv6 layer refuses this one already; datagramEnd would
		// too (TestDatagramEndTakesOnlyPlainAddresses).
		{"IPv4-mapped source", udpPacket(mapped, server, []byte("mapped"))},
		{"length beyond the data", udpPacketWithLength(testClient6, server, []byte("short"), header.UDPMinimumSize+64)},
		{"length below the header", udpPacketWithLength(testClient6, server, []byte("tiny"), header.UDPMinimumSize-1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, tun, conns := startTestBridge(t)
			tun.dev.inbound <- tc.packet
			// A good datagram right behind it: the first flow and the first
			// packet out must both be about the good one.
			tun.dev.inbound <- udpPacket(testClient6, server, []byte("good"))

			got := conns.next(t)
			if want := udpDest(testClient6); xnet.DestinationFromAddr(got.conn.RemoteAddr()) != want {
				t.Fatalf("the first flow comes from %v, want %v", got.conn.RemoteAddr(), want)
			}
			read := make([]byte, 64)
			if n, _ := got.conn.Read(read); string(read[:n]) != "good" {
				t.Fatalf("the first flow carried %q", read[:n])
			}
			if _, err := got.conn.Write([]byte("reply")); err != nil {
				t.Fatal(err)
			}
			if p := parseOutbound(t, tun.dev.nextOutbound(t)); p.proto != header.UDPProtocolNumber {
				t.Fatalf("the stack answered the dropped datagram with protocol %d", p.proto)
			}
		})
	}
}

func TestDatagramEndTakesOnlyPlainAddresses(t *testing.T) {
	cases := []struct {
		name string
		addr tcpip.Address
		want xnet.Destination
		ok   bool
	}{
		{"IPv4", stackAddr(testClient.Addr()), udpDest(testClient), true},
		{"IPv6", stackAddr(testClient6.Addr()), udpDest(netip.AddrPortFrom(testClient6.Addr(), testClient.Port())), true},
		{"IPv4-mapped IPv6", tcpip.AddrFrom16(testClient.Addr().As16()), xnet.Destination{}, false},
		{"no address", tcpip.Address{}, xnet.Destination{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := datagramEnd(tc.addr, testClient.Port())
			if ok != tc.ok || got != tc.want {
				t.Fatalf("datagramEnd = %v, %v; want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNetBridgeAnswersEchoRequests(t *testing.T) {
	for _, peers := range bothFamilies {
		t.Run(peers.family, func(t *testing.T) {
			_, tun, _ := startTestBridge(t)
			const ident, sequence = 0x1234, 7
			payload := []byte("are you there")
			tun.dev.inbound <- echoRequest(t, peers.client.Addr(), peers.server.Addr(), ident, sequence, payload)

			p := parseOutbound(t, tun.dev.nextOutbound(t))
			if p.src != peers.server.Addr() || p.dst != peers.client.Addr() {
				t.Fatalf("echo reply from %v to %v", p.src, p.dst)
			}
			if !p.transportChecksumValid() {
				t.Fatal("echo reply checksum is wrong")
			}
			var gotIdent, gotSequence uint16
			var gotPayload []byte
			if peers.client.Addr().Is4() {
				msg := header.ICMPv4(p.transport)
				if p.proto != header.ICMPv4ProtocolNumber || msg.Type() != header.ICMPv4EchoReply {
					t.Fatalf("expected an ICMPv4 echo reply, got protocol %d type %d", p.proto, p.transport[0])
				}
				gotIdent, gotSequence, gotPayload = msg.Ident(), msg.Sequence(), msg.Payload()
			} else {
				msg := header.ICMPv6(p.transport)
				if p.proto != header.ICMPv6ProtocolNumber || msg.Type() != header.ICMPv6EchoReply {
					t.Fatalf("expected an ICMPv6 echo reply, got protocol %d type %d", p.proto, p.transport[0])
				}
				gotIdent, gotSequence, gotPayload = msg.Ident(), msg.Sequence(), p.transport[header.ICMPv6EchoMinimumSize:]
			}
			if gotIdent != ident || gotSequence != sequence || !bytes.Equal(gotPayload, payload) {
				t.Fatalf("echo reply id=%#x seq=%d payload=%q", gotIdent, gotSequence, gotPayload)
			}
		})
	}
}

func TestNetBridgeUDPReplyWithoutAStackFails(t *testing.T) {
	var br netBridge
	if err := br.writeRawUDPPacket([]byte("early"), udpDest(testServer), udpDest(testClient)); err == nil {
		t.Fatal("a UDP reply went out of a bridge without a stack")
	}
}

func TestNetBridgeKeepsItsStackAfterClose(t *testing.T) {
	br, _, _ := startTestBridge(t)
	running := br.ns
	if running == nil {
		t.Fatal("no stack after Start")
	}
	if err := br.Close(); err != nil {
		t.Fatal(err)
	}
	if br.ns != running {
		t.Fatal("Close changed ns")
	}
}

func TestNetBridgeStartAgainstClose(t *testing.T) {
	baseline := runtime.NumGoroutine()
	for round := 0; round < 100; round++ {
		tun := newCountingTun()
		br, err := newNetBridge(context.Background(), tun, newRecordingHandler())
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = br.Start()
		}()
		go func() {
			defer wg.Done()
			if err := br.Close(); err != nil {
				t.Errorf("round %d: Close = %v", round, err)
			}
		}()
		wg.Wait()
		if tun.ep != nil && tun.ep.IsAttached() {
			t.Fatalf("round %d: the endpoint is attached after Start and Close", round)
		}
		if n := tun.calls.Load(); n > 1 {
			t.Fatalf("round %d: newEndpoint was called %d times", round, n)
		}
	}
	goroutinesSettleTo(t, baseline)
}

func TestAssembleStackAttachesTheEndpointLast(t *testing.T) {
	link := channel.New(4, 1500, "")
	attachedDuringSetup := false
	probe := stackSetupStep{
		name: "look at the endpoint",
		run: func(*stack.Stack, stack.LinkEndpoint) tcpip.Error {
			attachedDuringSetup = attachedDuringSetup || link.IsAttached()
			return nil
		},
	}
	steps := append(tunStackSetup(), probe)
	s, err := assembleStack(link, steps)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyStack(s)
	if attachedDuringSetup {
		t.Fatal("the endpoint was attached before the setup was complete")
	}
	if !link.IsAttached() {
		t.Fatal("the endpoint is not attached after assembly")
	}
}

// joiningLink imitates a link endpoint that, when detached, waits for its
// reader to finish; the reader is in the middle of a delivery that needs the
// stack's lock at that moment.
type joiningLink struct {
	*channel.Endpoint
	stack *stack.Stack

	mu   sync.Mutex
	stop chan struct{}
	done chan struct{}
}

func (l *joiningLink) Attach(dispatcher stack.NetworkDispatcher) {
	l.Endpoint.Attach(dispatcher)
	l.mu.Lock()
	defer l.mu.Unlock()
	if dispatcher != nil {
		if l.stop == nil {
			l.stop, l.done = make(chan struct{}), make(chan struct{})
			go l.read(l.stop, l.done)
		}
		return
	}
	if l.stop != nil {
		close(l.stop)
		<-l.done
		l.stop = nil
	}
}

func (l *joiningLink) read(stop, done chan struct{}) {
	defer close(done)
	<-stop
	// Anything that takes the stack's lock, as routing a reply does.
	_ = l.stack.NICInfo()
}

func TestShutDownStackDetachesWithoutTheStackLock(t *testing.T) {
	baseline := runtime.NumGoroutine()
	link := &joiningLink{Endpoint: channel.New(4, 1500, "")}
	s, err := createStack(link)
	if err != nil {
		t.Fatal(err)
	}
	link.stack = s

	done := make(chan struct{})
	go func() {
		shutDownStack(s)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutDownStack waited for a reader that waits for the stack")
	}
	if link.IsAttached() {
		t.Fatal("the endpoint is still attached")
	}
	s.Wait()
	goroutinesSettleTo(t, baseline)
}

// leakCheckChild marks the process that runs the traffic of
// TestNetBridgeLeavesNoPacketReferences with leak checking on from the start:
// an object created before leak checking is switched on fails the check when
// it is released.
const leakCheckChild = "TUN_BRIDGE_LEAK_CHECK_CHILD"

func TestNetBridgeLeavesNoPacketReferences(t *testing.T) {
	if os.Getenv(leakCheckChild) != "" {
		runLeakCheckedTraffic(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetBridgeLeavesNoPacketReferences$", "-test.count=1")
	cmd.Env = append(os.Environ(), leakCheckChild+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the leak-checked run failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("the leak-checked run did not pass:\n%s", out)
	}
}

func runLeakCheckedTraffic(t *testing.T) {
	refs.SetLeakMode(refs.LeaksPanic)
	defer refs.SetLeakMode(refs.NoLeakChecking)
	// The log writer starts with the first line and outlives the run; start
	// it before counting goroutines.
	xlog.Record(&xlog.GeneralMessage{Severity: xlog.Severity_Debug, Content: "leak-checked bridge run"})
	baseline := runtime.NumGoroutine()

	conns := newRecordingHandler()
	tun := newCountingTun()
	br, err := newNetBridge(context.Background(), tun, conns)
	if err != nil {
		t.Fatal(err)
	}
	if err := br.Start(); err != nil {
		t.Fatal(err)
	}

	// TCP: a connection with data in both directions.
	serverSeq := handshake(t, tun.dev, testClient, testServer, 100)
	tcpConn := conns.next(t)
	tun.dev.inbound <- tcpPacket(testClient, testServer, 101, serverSeq+1, header.TCPFlagAck|header.TCPFlagPsh, []byte("up"))
	_ = tcpConn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(tcpConn.conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := tcpConn.conn.Write([]byte("down")); err != nil {
		t.Fatal(err)
	}
	tcpConn.release()

	// UDP in both families, with replies.
	for _, peers := range bothFamilies {
		server := netip.AddrPortFrom(peers.server.Addr(), 53)
		tun.dev.inbound <- udpPacket(peers.client, server, []byte("query"))
		flow := conns.next(t)
		if _, err := flow.conn.Read(make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
		if _, err := flow.conn.Write([]byte("answer")); err != nil {
			t.Fatal(err)
		}
		nextOutboundOf(t, tun.dev, header.UDPProtocolNumber)
		flow.release()
	}

	// ICMP echo in both families.
	tun.dev.inbound <- echoRequest(t, testClient.Addr(), testServer.Addr(), 1, 1, []byte("ping"))
	nextOutboundOf(t, tun.dev, header.ICMPv4ProtocolNumber)
	tun.dev.inbound <- echoRequest(t, testClient6.Addr(), testServer6.Addr(), 1, 1, []byte("ping"))
	nextOutboundOf(t, tun.dev, header.ICMPv6ProtocolNumber)

	if err := br.Close(); err != nil {
		t.Fatal(err)
	}
	goroutinesSettleTo(t, baseline)
	br.ns.Wait()
	refs.DoRepeatedLeakCheck()
}
