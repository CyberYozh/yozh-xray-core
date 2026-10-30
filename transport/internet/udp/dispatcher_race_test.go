package udp_test

import (
	"context"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport"
	. "github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
)

// A connection ends on its own goroutine: its reader hits EOF, or its inactivity timer fires, and
// either way it is marked closed outside the dispatcher's lock. The dispatcher reads that mark
// under its lock whenever a datagram asks for a connection. The two must not race; run with -race.
func TestAConnectionEndingOnItsOwnDoesNotRaceTheNextDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var links sync.WaitGroup
	td := &TestDispatcher{
		OnDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			uplinkReader, uplinkWriter := pipe.New()
			downlinkReader, downlinkWriter := pipe.New()
			links.Add(1)
			go func() { // the outbound: drains the datagrams, then ends at once
				defer links.Done()
				downlinkWriter.Close()
				for {
					if _, err := uplinkReader.ReadMultiBuffer(); err != nil {
						return
					}
				}
			}()
			return &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, nil
		},
	}
	dispatcher := NewDispatcher(td, func(context.Context, *udp.Packet) {})
	dest := net.UDPDestination(net.LocalHostIP, 53)

	for range 200 {
		b := buf.New()
		b.WriteString("datagram")
		dispatcher.Dispatch(ctx, dest, b)
	}
	dispatcher.RemoveRay()
	cancel()
	links.Wait()
}
