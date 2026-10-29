package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// A UDP flow handed to the handler with a name for its target, while the program sent its datagrams
// to an address, leaves with that name on every datagram: the handler rewrites each datagram's
// address to the target (buf.EndpointOverrideReader), and a SOCKS5 outbound relays it addressed by
// name. That is why the dispatcher gives a sniffed UDP flow its address back before handing it over
// (app/dispatcher restoreUDPTarget); these tests pin the handler's side of the reason.

// datagramRecorder is an outbound that only notes the address of the first datagram it reads.
type datagramRecorder struct {
	proxy.Outbound
	got chan net.Destination
}

func (r *datagramRecorder) Process(ctx context.Context, link *transport.Link, _ internet.Dialer) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	for _, b := range mb {
		if b.UDP != nil {
			r.got <- *b.UDP
		}
	}
	buf.ReleaseMulti(mb)
	return nil
}

var programsAddress = net.UDPDestination(net.ParseAddress("192.0.2.10"), 443)

// datagramAtTheOutbound is the address a datagram the program sent to programsAddress carries when
// the outbound reads it, the flow being handed to the handler with `target`.
func datagramAtTheOutbound(t *testing.T, target net.Destination) net.Destination {
	t.Helper()
	recorder := &datagramRecorder{got: make(chan net.Destination, 1)}
	h := &Handler{tag: "proxy", proxy: recorder}
	ctx := session.ContextWithOutbounds(context.Background(),
		[]*session.Outbound{{OriginalTarget: programsAddress, Target: target}})
	upReader, upWriter := pipe.New()
	_, downWriter := pipe.New()
	b := buf.New()
	b.WriteString("datagram")
	destination := programsAddress
	b.UDP = &destination
	if err := upWriter.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatal(err)
	}
	common.Close(upWriter)
	h.Dispatch(ctx, &transport.Link{Reader: upReader, Writer: downWriter})
	select {
	case got := <-recorder.got:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("the outbound read no datagram")
		return net.Destination{}
	}
}

func TestADatagramLeavesByNameWhileTheTargetIsAName(t *testing.T) {
	name := net.UDPDestination(net.DomainAddress("quic.example"), 443)

	got := datagramAtTheOutbound(t, name)

	if !got.Address.Family().IsDomain() || got.Address.Domain() != "quic.example" {
		t.Fatalf("the outbound read a datagram to %v, want it rewritten to the target's name quic.example", got)
	}
}

func TestADatagramLeavesToTheProgramsAddressWhenTheTargetIsThatAddress(t *testing.T) {
	got := datagramAtTheOutbound(t, programsAddress)

	if got != programsAddress {
		t.Fatalf("the outbound read a datagram to %v, want the program's address %v", got, programsAddress)
	}
}
