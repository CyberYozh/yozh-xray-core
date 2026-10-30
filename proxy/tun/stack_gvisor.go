package tun

import (
	"context"
	"math"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// bridgeNICID is the ID of the one NIC of the bridge's stack.
const bridgeNICID tcpip.NICID = 1

// tcpHandshakeLimit bounds the TCP handshakes in progress at once. A SYN that
// finds every slot taken is ignored; the application sends it again.
const tcpHandshakeLimit = 2048

// netBridge carries traffic between a TUN device and a ConnectionHandler
// through a gVisor network stack.
//
// Start builds the stack over the device's link endpoint and puts it into
// service, Close takes it down; each does its work at most once. The device
// belongs to the caller: the bridge neither starts nor closes it.
type netBridge struct {
	// logCtx is the context of every log line of the bridge. The
	// constructor sets it and nothing changes it afterwards.
	logCtx context.Context
	// ns is the running stack; nil until a successful Start. It is set once,
	// before the stack can deliver or send anything, and kept after Close:
	// a late reply then fails inside the stack instead of on a nil pointer.
	ns *stack.Stack

	device Tun
	conns  ConnectionHandler

	// setup lists the steps that build the stack; nil means
	// bridgeStackSetup. Tests replace it to make the assembly fail.
	setup func() []stackSetupStep
	// handshakeLimit replaces tcpHandshakeLimit when positive.
	handshakeLimit int

	// mu guards started, closed and the writing of ns. It is never held
	// while calling the device, the connection handler or the flow table,
	// and nothing that delivers packets or sends replies takes it, so Close
	// may hold it while it takes the stack down.
	mu sync.Mutex
	// started is set by the first Start, whatever comes of it.
	started bool
	// closed is set by the first Close.
	closed bool
}

// newNetBridge returns a bridge between device and conns that has not started.
// It opens nothing and does not touch the device.
func newNetBridge(ctx context.Context, device Tun, conns ConnectionHandler) (*netBridge, error) {
	switch {
	case ctx == nil:
		return nil, errors.New("the network bridge needs a context")
	case device == nil:
		return nil, errors.New("the network bridge needs a TUN device")
	case conns == nil:
		return nil, errors.New("the network bridge needs a connection handler")
	}
	return &netBridge{logCtx: ctx, device: device, conns: conns}, nil
}

// Start brings the bridge up: it takes the link endpoint of the device, builds
// the stack over it and puts the stack into service. The endpoint delivers
// nothing until the handlers are installed and ns is set, so the very first
// packet from the device already meets the complete stack.
func (b *netBridge) Start() error {
	if err := b.claimStart(); err != nil {
		return err
	}

	ep, err := b.device.newEndpoint()
	if err != nil {
		return errors.New("failed to open the link endpoint of the TUN device").Base(err)
	}
	if ep == nil {
		return errors.New("the TUN device returned no link endpoint")
	}

	steps := b.bridgeStackSetup
	if b.setup != nil {
		steps = b.setup
	}
	s, link, err := buildStack(ep, steps())
	if err != nil {
		return err
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		// Close came while the stack was being built. No packet has reached
		// it, so it goes the way of a stack whose setup failed.
		discardStack(s)
		return errors.New("the network bridge was closed while it was starting")
	}
	b.ns = s
	b.mu.Unlock()

	// From here on the stack is Close's to take down. Should Close get there
	// first, it has closed the endpoint, and attach does nothing.
	link.attach()
	return nil
}

// claimStart lets Start do its work once, and never after Close.
func (b *netBridge) claimStart() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.closed:
		return errors.New("the network bridge is closed")
	case b.started:
		return errors.New("the network bridge has already been started")
	case b.logCtx == nil || b.device == nil || b.conns == nil:
		return errors.New("the network bridge was not made by newNetBridge")
	}
	b.started = true
	return nil
}

// bridgeStackSetup lists the steps that build the bridge's stack: the TUN-side
// stack of createStack, then the transport handlers.
func (b *netBridge) bridgeStackSetup() []stackSetupStep {
	return append(tunStackSetup(), stackSetupStep{
		name: "install transport handlers",
		run:  b.installHandlers,
	})
}

// installHandlers makes the bridge the stack's default handler for TCP, UDP,
// ICMPv4 and ICMPv6. gVisor allows this only while a stack is being set up,
// before any packet has reached it, which is when setup steps run.
func (b *netBridge) installHandlers(s *stack.Stack, _ stack.LinkEndpoint) tcpip.Error {
	limit := tcpHandshakeLimit
	if b.handshakeLimit > 0 {
		limit = b.handshakeLimit
	}
	// A zero window keeps gVisor's default receive window for handshakes.
	forwarder := tcp.NewForwarder(s, 0, limit, b.acceptTCP)
	// The table takes the handler's own rule for the addresses of fake DNS from b.conns, when that is
	// the tun's handler.
	flows := newUdpConnectionHandler(b.conns, b.writeRawUDPPacket)

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		deliverDatagram(flows, id, pkt)
		// Carried or dropped, the datagram is dealt with: the stack must not
		// answer it with "port unreachable".
		return true
	})
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, b.handleICMPv4Packet)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, b.handleICMPv6Packet)
	return nil
}

// acceptTCP serves one connection request of the TCP forwarder. The forwarder
// calls it on a goroutine of its own, which then serves the connection for as
// long as it lives.
//
// The request is completed as soon as the handshake has an outcome. Completing
// it when the connection ends instead would keep a handshake slot taken for the
// whole life of the connection.
func (b *netBridge) acceptTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	dialled, ok := hostAddress(id.LocalAddress)
	if !ok {
		req.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		// The line names no addresses: at the log levels clients run with,
		// the log must not show where the user went.
		errors.LogError(b.logCtx, "[tun] TCP handshake failed: ", err.String())
		req.Complete(true)
		return
	}
	req.Complete(false)
	// Whatever the handler did with its conn, the endpoint is released
	// once the handler is done with it.
	defer ep.Close()

	// No keepalive probes towards the applications behind the device.
	ep.SocketOptions().SetKeepAlive(false)
	b.conns.HandleConnection(gonet.NewTCPConn(&wq, ep), net.TCPDestination(dialled, net.Port(id.LocalPort)))
}

// deliverDatagram hands one UDP datagram from the device to the flow table,
// with a copy of its payload: the stack reuses the packet once its handler has
// returned. A datagram that cannot become part of a flow is dropped.
func deliverDatagram(flows *udpConnectionHandler, id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	src, ok := datagramEnd(id.RemoteAddress, id.RemotePort)
	if !ok {
		return
	}
	dst, ok := datagramEnd(id.LocalAddress, id.LocalPort)
	if !ok {
		return
	}
	payload, ok := datagramPayload(id, pkt)
	if !ok {
		return
	}
	flows.HandlePacket(src, dst, payload)
}

// datagramEnd turns one end of a datagram into a destination. Only a plain
// IPv4 or IPv6 address will do: an IPv4-mapped IPv6 address would come back as
// IPv4, and the replies of its flow would be built for the wrong family.
func datagramEnd(addr tcpip.Address, port uint16) (net.Destination, bool) {
	ip, ok := hostAddress(addr)
	if !ok || ip.Family().IsIPv4() != (addr.Len() == header.IPv4AddressSize) {
		return net.Destination{}, false
	}
	return net.UDPDestination(ip, net.Port(port)), true
}

// datagramPayload copies out the payload of a UDP datagram, as much of it as
// the length field covers. A datagram whose length field does not fit the
// packet is refused, and so is one with a wrong checksum where the link
// endpoint has not already vouched for it.
func datagramPayload(id stack.TransportEndpointID, pkt *stack.PacketBuffer) ([]byte, bool) {
	hdr := header.UDP(pkt.TransportHeader().Slice())
	data := pkt.Data()
	size := data.Size()
	if len(hdr) < header.UDPMinimumSize || size > math.MaxUint16 {
		return nil, false
	}
	lengthValid, checksumValid := header.UDPValid(hdr, data.Checksum, uint16(size), pkt.NetworkProtocolNumber,
		id.RemoteAddress, id.LocalAddress, pkt.RXChecksumValidated)
	if !lengthValid || !checksumValid {
		return nil, false
	}
	return data.AsRange().Capped(int(hdr.Length()) - header.UDPMinimumSize).ToSlice(), true
}

// hostAddress converts a stack address into an Xray one. It reports false for
// anything that is not a whole IPv4 or IPv6 address.
func hostAddress(addr tcpip.Address) (net.Address, bool) {
	switch addr.Len() {
	case header.IPv4AddressSize, header.IPv6AddressSize:
		return net.IPAddress(addr.AsSlice()), true
	default:
		return nil, false
	}
}

func (b *netBridge) writeRawUDPPacket(payload []byte, src net.Destination, dst net.Destination) error {
	s := b.ns
	if s == nil {
		return errors.New("the network bridge has no stack to write to")
	}

	udpLen := header.UDPMinimumSize + len(payload)
	srcIP := tcpip.AddrFromSlice(src.Address.IP())
	dstIP := tcpip.AddrFromSlice(dst.Address.IP())

	// build packet with appropriate IP header size
	isIPv4 := dst.Address.Family().IsIPv4()
	ipHdrSize := header.IPv6MinimumSize
	ipProtocol := header.IPv6ProtocolNumber
	if isIPv4 {
		ipHdrSize = header.IPv4MinimumSize
		ipProtocol = header.IPv4ProtocolNumber
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: ipHdrSize + header.UDPMinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	// Build UDP header
	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udpHdr.Encode(&header.UDPFields{
		SrcPort: uint16(src.Port),
		DstPort: uint16(dst.Port),
		Length:  uint16(udpLen),
	})

	// Calculate and set UDP checksum
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcIP, dstIP, uint16(udpLen))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	// Build IP header
	if isIPv4 {
		ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + udpLen),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     srcIP,
			DstAddr:     dstIP,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize))
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpLen),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           srcIP,
			DstAddr:           dstIP,
		})
	}

	// dispatch the packet
	err := s.WriteRawPacket(bridgeNICID, ipProtocol, buffer.MakeWithView(pkt.ToView()))
	if err != nil {
		return errors.New("failed to write raw udp packet back to stack", err)
	}

	return nil
}

// Close takes the bridge down. The TUN device stays open.
//
// Established connections are reset, the link endpoint is detached, and no
// connection or flow can appear afterwards. Close does not wait for the
// goroutines that serve connections. Detaching LinkEndpoint does not wait for
// its reader either; an endpoint that does wait (the fd-based one) is detached
// without the stack's lock held, so that its reader can finish a delivery.
// Close is safe on a bridge that never started or failed to start, on the zero
// value, twice and from several goroutines at once, and it always returns nil.
func (b *netBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if b.ns != nil {
		shutDownStack(b.ns)
	}
	return nil
}

// shutDownStack stops a running stack. The stack object stays usable in the
// sense that late calls into it (for example a reply written by a handler
// goroutine that is still finishing) fail with a gVisor error instead of
// panicking.
func shutDownStack(s *stack.Stack) {
	// Reset every connection while the link is still attached: the resets
	// reach the applications behind the TUN device, so they fail over at
	// once instead of waiting for their own timeouts. This includes
	// endpoints parked for cleanup, such as TIME-WAIT.
	abortAll(s.RegisteredEndpoints())
	abortAll(s.CleanupEndpoints())

	// Stop inbound delivery before the NIC goes. Removing the NIC detaches
	// the link endpoint as well, but with the stack's lock held, and an
	// endpoint that waits for its reader when detached would then wait for
	// a delivery that may itself need that lock, to route a reply.
	stopInbound(s)

	// Removing the NIC detaches and closes the link endpoint. From here on
	// no packet enters or leaves the stack, so no new connection can appear.
	detachAllNICs(s)

	// Abort anything that registered in the meantime and close the
	// protocols. Stack.Close leaves the cleanup set alone, hence the last
	// sweep over it.
	s.Close()
	abortAll(s.CleanupEndpoints())
}

func abortAll(endpoints []stack.TransportEndpoint) {
	for _, ep := range endpoints {
		ep.Abort()
	}
}

func detachAllNICs(s *stack.Stack) {
	for id := range s.NICInfo() {
		_ = s.RemoveNIC(id)
	}
}

// stopInbound detaches the link endpoint of every NIC without holding the
// stack's lock. The NICs stay in place; removing them detaches the endpoints
// again, which endpoints take as a no-op.
func stopInbound(s *stack.Stack) {
	for id := range s.NICInfo() {
		if nic, err := s.GetNICByID(id); err == nil {
			nic.NetworkLinkEndpoint.Attach(nil)
		}
	}
}

// Buffer sizes for TCP connections terminated by the stack.
const (
	tcpBufferDefaultSize    = 1 << 20 // 1 MiB
	tcpReceiveBufferMaxSize = 8 << 20 // 8 MiB
	tcpSendBufferMaxSize    = 6 << 20 // 6 MiB
)

// stackSetupStep is one named configuration step of a new stack.
type stackSetupStep struct {
	name string
	run  func(s *stack.Stack, ep stack.LinkEndpoint) tcpip.Error
}

// tunStackSetup lists the steps that turn a bare gVisor stack into the
// TUN-side stack: TCP tuning first, so that every connection ever accepted
// uses it, then the NIC over the device and its routing.
func tunStackSetup() []stackSetupStep {
	congestion := tcpip.CongestionControlOption("cubic")
	sack := tcpip.TCPSACKEnabled(true)
	moderateReceive := tcpip.TCPModerateReceiveBufferOption(true)
	// No RACK/TLP loss detection: with it, connections were seen stalling
	// under heavy load.
	recovery := tcpip.TCPRecovery(0)
	receiveRange := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcpBufferDefaultSize,
		Max:     tcpReceiveBufferMaxSize,
	}
	sendRange := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcpBufferDefaultSize,
		Max:     tcpSendBufferMaxSize,
	}

	return []stackSetupStep{
		tcpOptionStep("set TCP congestion control", &congestion),
		tcpOptionStep("enable TCP SACK", &sack),
		tcpOptionStep("enable TCP receive buffer moderation", &moderateReceive),
		tcpOptionStep("set TCP loss recovery", &recovery),
		tcpOptionStep("set TCP receive buffer range", &receiveRange),
		tcpOptionStep("set TCP send buffer range", &sendRange),
		{
			name: "create NIC",
			run: func(s *stack.Stack, ep stack.LinkEndpoint) tcpip.Error {
				return s.CreateNIC(bridgeNICID, ep)
			},
		},
		{
			name: "install default routes",
			run: func(s *stack.Stack, _ stack.LinkEndpoint) tcpip.Error {
				s.SetRouteTable([]tcpip.Route{
					{Destination: header.IPv4EmptySubnet, NIC: bridgeNICID},
					{Destination: header.IPv6EmptySubnet, NIC: bridgeNICID},
				})
				return nil
			},
		},
		{
			// Replies leave from the remote addresses the applications
			// dialled, none of which belong to the stack.
			name: "enable spoofing on NIC",
			run: func(s *stack.Stack, _ stack.LinkEndpoint) tcpip.Error {
				return s.SetSpoofing(bridgeNICID, true)
			},
		},
		{
			// Connections go to arbitrary internet addresses, so the NIC
			// must take packets for any destination.
			name: "enable promiscuous mode on NIC",
			run: func(s *stack.Stack, _ stack.LinkEndpoint) tcpip.Error {
				return s.SetPromiscuousMode(bridgeNICID, true)
			},
		},
	}
}

func tcpOptionStep(name string, option tcpip.SettableTransportProtocolOption) stackSetupStep {
	return stackSetupStep{
		name: name,
		run: func(s *stack.Stack, _ stack.LinkEndpoint) tcpip.Error {
			return s.SetTransportProtocolOption(tcp.ProtocolNumber, option)
		},
	}
}

// createStack configure gVisor ip stack
func createStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	return assembleStack(ep, tunStackSetup())
}

// assembleStack builds a stack with the IP, TCP, UDP and ICMP protocols, runs
// the setup steps over it and then attaches the link endpoint, which starts
// delivering packets. If a step fails, everything built so far is taken apart
// before the error is returned; the endpoint was never attached.
func assembleStack(ep stack.LinkEndpoint, steps []stackSetupStep) (*stack.Stack, error) {
	s, link, err := buildStack(ep, steps)
	if err != nil {
		return nil, err
	}
	link.attach()
	return s, nil
}

// buildStack is assembleStack without the last move: the NIC the steps create
// sits on a heldLink, and the link endpoint behind it is attached only when
// the caller calls attach. Until then no packet from the device reaches the
// stack. If a step fails, everything built so far is taken apart before the
// error is returned.
func buildStack(ep stack.LinkEndpoint, steps []stackSetupStep) (*stack.Stack, *heldLink, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	link := &heldLink{LinkEndpoint: ep}
	for _, step := range steps {
		if err := step.run(s, link); err != nil {
			discardStack(s)
			return nil, nil, errors.New("failed to set up the gVisor stack: ", step.name, ": ", err.String())
		}
	}
	return s, link, nil
}

// discardStack tears down a stack that never went into service. No packet
// ever reached it, so it holds no transport endpoints, and waiting for its
// protocol goroutines is bounded.
func discardStack(s *stack.Stack) {
	detachAllNICs(s)
	s.Close()
	s.Wait()
}

// heldLink stands between a NIC and its link endpoint while the stack is set
// up. A NIC attaches its endpoint the moment it is created, and an endpoint
// starts delivering packets as soon as it is attached. A packet delivered then
// would meet a stack without promiscuous mode, spoofing or transport handlers,
// which drops it or answers it with a reset. So until attach is called the
// dispatcher is only recorded; afterwards every call passes straight through.
//
// Only the methods of stack.LinkEndpoint pass through. Optional interfaces of
// the endpoint, GSO support in particular, are not visible behind it; none of
// the endpoints of this package offers any.
type heldLink struct {
	stack.LinkEndpoint

	mu sync.Mutex
	// released is set by attach; from then on Attach passes through.
	released bool
	// closed is set when the NIC closes the endpoint; nothing is attached
	// after that.
	closed bool
	// pending is the dispatcher the NIC attached while the link was held.
	pending stack.NetworkDispatcher
}

var _ stack.LinkEndpoint = (*heldLink)(nil)

// Attach implements stack.LinkEndpoint.
func (l *heldLink) Attach(dispatcher stack.NetworkDispatcher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.released {
		l.pending = dispatcher
		return
	}
	l.LinkEndpoint.Attach(dispatcher)
}

// Close implements stack.LinkEndpoint.
func (l *heldLink) Close() {
	l.mu.Lock()
	l.closed = true
	l.pending = nil
	l.mu.Unlock()
	l.LinkEndpoint.Close()
}

// attach hands the endpoint the dispatcher the NIC attached while the link
// was held, unless the NIC has been removed since.
func (l *heldLink) attach() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if l.closed || l.pending == nil {
		return
	}
	l.LinkEndpoint.Attach(l.pending)
	l.pending = nil
}
