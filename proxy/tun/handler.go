package tun

import (
	"context"
	"net/netip"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	ctx             context.Context
	config          *Config
	bridge          *netBridge
	tun             Tun
	policyManager   policy.Manager
	dispatcher      routing.Dispatcher
	tag             string
	sniffingRequest session.SniffingRequest
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
	activeCounter   stats.Counter
	handledCounter  stats.Counter
	// fakeDNS is the engine's fake DNS; nil when the engine has none. The constructor registered for
	// the config asks for it (init, below).
	fakeDNS dns.FakeDNSEngine

	uplinkTcpCounter   stats.Counter
	downlinkTcpCounter stats.Counter
	uplinkUdpCounter   stats.Counter
	downlinkUdpCounter stats.Counter
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

// Handler implements common.Runnable
var _ common.Runnable = (*Handler)(nil)

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	// Retrieve tag and sniffing config from context (set by AlwaysOnInboundHandler)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		t.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		t.sniffingRequest = content.SniffingRequest
	}

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher

	if len(t.tag) > 0 && pm.ForSystem().Stats.InboundUplink {
		statsManager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + t.tag + ">>>traffic>>>uplink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			t.uplinkCounter = c
		}
		// Per-network split. The suffix goes on the FOURTH segment instead of adding a
		// fifth or replacing the third: app/metrics/metrics.go splits the name on the
		// separator, requires at least four segments and keeps [0], [1], [3]. A suffix on
		// the third segment would land in the same /debug/vars cell as the aggregate, and
		// one number would silently overwrite the other.
		if tcp, _ := statsManager.GetOrRegisterCounter(name + "-tcp"); tcp != nil {
			t.uplinkTcpCounter = tcp
		}
		if udp, _ := statsManager.GetOrRegisterCounter(name + "-udp"); udp != nil {
			t.uplinkUdpCounter = udp
		}
	}
	if len(t.tag) > 0 && pm.ForSystem().Stats.InboundDownlink {
		statsManager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + t.tag + ">>>traffic>>>downlink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			t.downlinkCounter = c
		}
		// Per-network split. The suffix goes on the FOURTH segment instead of adding a
		// fifth or replacing the third: app/metrics/metrics.go splits the name on the
		// separator, requires at least four segments and keeps [0], [1], [3]. A suffix on
		// the third segment would land in the same /debug/vars cell as the aggregate, and
		// one number would silently overwrite the other.
		if tcp, _ := statsManager.GetOrRegisterCounter(name + "-tcp"); tcp != nil {
			t.downlinkTcpCounter = tcp
		}
		if udp, _ := statsManager.GetOrRegisterCounter(name + "-udp"); udp != nil {
			t.downlinkUdpCounter = udp
		}
	}

	// Connection counters for a client's live view: flows in the tunnel right now and
	// the total handled. Unlike the byte counters there is no policy switch for these;
	// the gate is the stats feature itself being configured.
	if len(t.tag) > 0 {
		if f := core.MustFromContext(ctx).GetFeature(stats.ManagerType()); f != nil {
			statsManager := f.(stats.Manager)
			active, _ := statsManager.GetOrRegisterCounter("inbound>>>" + t.tag + ">>>connection>>>active")
			t.activeCounter = active
			handled, _ := statsManager.GetOrRegisterCounter("inbound>>>" + t.tag + ">>>connection>>>handled")
			t.handledCounter = handled
		}
	}

	return nil
}

func (t *Handler) Start() error {
	tunName := t.config.Name
	tunInterface, err := NewTun(t.config)
	if err != nil {
		return err
	}

	if t.config.AutoOutboundsInterface != "" {
		tunIndex, err := tunInterface.Index()
		if err != nil {
			_ = tunInterface.Close()
			return err
		}
		if t.config.AutoOutboundsInterface == "auto" {
			t.config.AutoOutboundsInterface = ""
		}
		updater = &InterfaceUpdater{tunIndex: tunIndex, fixedName: t.config.AutoOutboundsInterface}
		updater.Update()
		internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
			iface := updater.Get()
			if iface == nil {
				// Raised from Info to Warning in this fork: a client that runs the engine
				// at loglevel "warning" (so that nothing on disk shows where the user
				// went) never saw either line at Info. Yet they report a failure to bind
				// outbound connections to the chosen interface: traffic goes somewhere
				// other than where TUN expects, and the only symptom left is "connected,
				// but nothing works".
				errors.LogWarning(context.Background(), "[tun] falied to set interface > iface == nil")
				return nil
			}
			return c.Control(func(fd uintptr) {
				addrPort, _ := netip.ParseAddrPort(address)
				// skip loopback
				if addrPort.Addr().IsLoopback() || strings.HasPrefix(strings.ToLower(address), "localhost:") {
					return
				}
				err := setinterface(network, address, fd, iface)
				if err != nil {
					// Same reason as above: at loglevel "warning" a binding failure was
					// invisible, although it is a failure, not a detail.
					errors.LogWarningInner(context.Background(), err, "[tun] falied to set interface")
				}
			})
		})
	}

	errors.LogInfo(t.ctx, tunName, " created")

	bridge, err := newNetBridge(t.ctx, tunInterface, t)
	if err != nil {
		_ = tunInterface.Close()
		return err
	}

	err = bridge.Start()
	if err != nil {
		_ = bridge.Close()
		_ = tunInterface.Close()
		return err
	}

	err = tunInterface.Start()
	if err != nil {
		_ = bridge.Close()
		_ = tunInterface.Close()
		return err
	}

	t.bridge = bridge
	t.tun = tunInterface

	errors.LogInfo(t.ctx, tunName, " up")
	return nil
}

// HandleConnection pass the connection coming from the ip stack to the routing dispatcher
func (t *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	// when handling is done with any outcome, always signal back to the incoming connection
	// to close, send completion packets back to the network, and cleanup
	defer conn.Close()

	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())
	// A UDP flow wants to know where the dispatcher sends it, and where its datagrams to other
	// destinations would go (udp_fullcone.go, settle).
	if flow, ok := conn.(*udpConn); ok {
		ctx = session.ContextWithFlowRouteReport(ctx, flow.settle)
	}

	// if the connection is already closed, conn.RemoteAddr() will be nil
	// due to gvisor weird behavior
	remote := conn.RemoteAddr()
	if remote == nil {
		errors.LogInfo(t.ctx, "dropped quickly closed connection")
		return
	}
	source := net.DestinationFromAddr(remote)
	if t.handledCounter != nil {
		t.handledCounter.Add(1)
	}
	if t.activeCounter != nil {
		t.activeCounter.Add(1)
		defer t.activeCounter.Add(-1)
	}
	if t.uplinkCounter != nil || t.downlinkCounter != nil {
		// The network comes from destination, NOT from whether conn implements
		// buf.Reader. Today a packet-aware conn and UDP coincide, but that is a property
		// of the gvisor stack, not a contract: the ConnectionHandler interface is declared
		// in terms of net.Destination, and that is what reports the network.
		up, down := t.uplinkCounter, t.downlinkCounter
		if destination.Network == net.Network_UDP {
			up, down = fanOut(up, t.uplinkUdpCounter), fanOut(down, t.downlinkUdpCounter)
		} else {
			up, down = fanOut(up, t.uplinkTcpCounter), fanOut(down, t.downlinkTcpCounter)
		}
		// Fullcone UDP conns speak MultiBuffer with a per-packet destination
		// (b.UDP); stat.CounterConnection exposes only Read/Write and would
		// hide those methods, silently collapsing fullcone to the flow's first
		// destination in both directions. Count packet-aware conns with a
		// wrapper that forwards the MultiBuffer path instead.
		if mr, isPacketReader := conn.(buf.Reader); isPacketReader {
			if mw, isPacketWriter := conn.(buf.Writer); isPacketWriter {
				conn = &counterPacketConn{
					Conn:         conn,
					reader:       mr,
					writer:       mw,
					readCounter:  up,
					writeCounter: down,
				}
			}
		}
		if _, wrapped := conn.(*counterPacketConn); !wrapped {
			conn = &stat.CounterConnection{
				Connection:   conn,
				ReadCounter:  up,
				WriteCounter: down,
			}
		}
	}

	inbound := session.Inbound{
		Name:          "tun",
		Tag:           t.tag,
		CanSpliceCopy: 3,
		Source:        source,
		User: &protocol.MemoryUser{
			Level: t.config.UserLevel,
		},
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: t.sniffingRequest,
	})
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", destination)

	link := &transport.Link{
		Reader: &buf.TimeoutWrapperReader{Reader: buf.NewReader(conn)},
		Writer: buf.NewWriter(conn),
	}
	if err := t.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

// fanOutCounter sends one Add to two counters: the aggregate and the per-network one.
// It exists because stat.CounterConnection and counterPacketConn each take exactly one
// counter per direction, while the traffic has to be counted in both.
//
// It is NOT registered in stats.Manager and must not be: everything registered is walked
// by VisitCounters every second and read through Value() (app/metrics/metrics.go), so a
// fan-out under the aggregate name would instantly corrupt the aggregate figure. Only the
// six real counters are registered; this one lives on a single connection and dies with it.
type fanOutCounter struct {
	primary stats.Counter // aggregate: its value is the wrapper's value
	extra   stats.Counter // per-network
}

func fanOut(primary, extra stats.Counter) stats.Counter {
	if primary == nil {
		return extra
	}
	if extra == nil {
		return primary
	}
	return &fanOutCounter{primary: primary, extra: extra}
}

// The return value comes from the aggregate, like the production app/stats.Counter, which
// returns the NEW value despite the doc in features/stats/stats.go. Nothing uses it, but
// there is no reason to diverge from production gratuitously.
func (c *fanOutCounter) Add(delta int64) int64 { c.extra.Add(delta); return c.primary.Add(delta) }
func (c *fanOutCounter) Set(value int64) int64 { c.extra.Set(value); return c.primary.Set(value) }
func (c *fanOutCounter) Value() int64          { return c.primary.Value() }

// counterPacketConn counts traffic without hiding the packet-aware interfaces:
// ReadMultiBuffer/WriteMultiBuffer forward to the underlying conn, so per-packet
// destinations (b.UDP) survive and buf.NewReader/NewWriter pick the MultiBuffer
// path exactly as they would for the bare conn.
type counterPacketConn struct {
	net.Conn
	reader       buf.Reader
	writer       buf.Writer
	readCounter  stats.Counter
	writeCounter stats.Counter
}

func (c *counterPacketConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.reader.ReadMultiBuffer()
	if c.readCounter != nil {
		c.readCounter.Add(int64(mb.Len()))
	}
	return mb, err
}

func (c *counterPacketConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if c.writeCounter != nil {
		c.writeCounter.Add(int64(mb.Len()))
	}
	return c.writer.WriteMultiBuffer(mb)
}

// ownUDPFlow is this handler's rule for the UDP flow table (udpFlowPolicy.ownFlow): an address of the
// engine's fake DNS pool has a flow of its own. nil when the engine has no fake DNS, or one that cannot
// tell whether an address is in its pool.
//
// The rule is the dispatcher's test in restoreUDPTarget (app/dispatcher/default.go): a UDP flow whose
// first destination is a pool address keeps the sniffed name as its target there, and the outbound then
// puts the name's real address in place of that address alone (udp_flow_policy.go). Whoever widens the
// one widens the other.
//
// The pool is asked on every call and never cached, so the rule does not depend on the order in which
// features start: building the table needs the engine itself, not its pool. The table calls the rule
// with its lock held, and the engine's answer is a range check.
func (t *Handler) ownUDPFlow() func(dst net.Destination) bool {
	engine, ok := t.fakeDNS.(dns.FakeDNSEngineRev0)
	if !ok {
		return nil
	}
	return func(dst net.Destination) bool { return engine.IsIPInIPPool(dst.Address) }
}

// Close implements common.Closable.
func (t *Handler) Close() error {
	return errors.Combine(common.CloseIfExists(t.bridge), common.CloseIfExists(t.tun))
}

// Network implements proxy.Inbound
// and exists only to comply to proxy interface, declaring it doesn't listen on any network,
// making the process not open any port for this inbound (input will be network interface)
func (t *Handler) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound
// and exists only to comply to proxy interface, which should never get any inputs due to no listening ports
func (t *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		t := &Handler{config: config.(*Config)}
		err := core.RequireFeatures(ctx, func(pm policy.Manager, dispatcher routing.Dispatcher) error {
			// Fake DNS is optional, and asked for as dns.FakeDNSEngine: the engine matches a callback's
			// parameter to a feature by that exact type, so one of dns.FakeDNSEngineRev0 would match
			// none, and fakeDNS would stay nil without a word. ownUDPFlow casts it, as the dispatcher does.
			core.OptionalFeatures(ctx, func(fakeDNS dns.FakeDNSEngine) { t.fakeDNS = fakeDNS })
			return t.Init(ctx, pm, dispatcher)
		})
		return t, err
	}))
}
