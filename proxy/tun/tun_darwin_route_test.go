//go:build darwin

package tun

import (
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var routeTestGateway = netip.MustParsePrefix("169.254.10.1/30")

func TestDarwinRouteMessageAddsIPv4RouteThroughGateway(t *testing.T) {
	// An unmasked destination must still produce the network address.
	msg, err := darwinRouteMessage(unix.RTM_ADD, 7, netip.MustParsePrefix("198.51.100.77/24"), routeTestGateway)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Version != unix.RTM_VERSION || msg.Type != unix.RTM_ADD {
		t.Fatalf("version/type = %d/%d, want %d/%d", msg.Version, msg.Type, unix.RTM_VERSION, unix.RTM_ADD)
	}
	if want := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY; msg.Flags != want {
		t.Fatalf("flags = %#x, want %#x", msg.Flags, want)
	}
	if msg.ID != uintptr(os.Getpid()) {
		t.Fatalf("sender id = %d, want the process id %d", msg.ID, os.Getpid())
	}

	dst, ok := msg.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
	if !ok || dst.IP != [4]byte{198, 51, 100, 0} {
		t.Fatalf("destination = %#v, want 198.51.100.0", msg.Addrs[unix.RTAX_DST])
	}
	hop, ok := msg.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
	if !ok || hop.IP != [4]byte{169, 254, 10, 1} {
		t.Fatalf("gateway = %#v, want 169.254.10.1", msg.Addrs[unix.RTAX_GATEWAY])
	}
	mask, ok := msg.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
	if !ok || mask.IP != [4]byte{255, 255, 255, 0} {
		t.Fatalf("netmask = %#v, want 255.255.255.0", msg.Addrs[unix.RTAX_NETMASK])
	}

	if wire, err := msg.Marshal(); err != nil || len(wire) == 0 {
		t.Fatalf("Marshal = %d bytes, %v", len(wire), err)
	}
}

func TestDarwinRouteMessageDeletesIPv6RouteOnTheInterface(t *testing.T) {
	msg, err := darwinRouteMessage(unix.RTM_DELETE, 7, netip.MustParsePrefix("2001:db8::/32"), routeTestGateway)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != unix.RTM_DELETE {
		t.Fatalf("type = %d, want %d", msg.Type, unix.RTM_DELETE)
	}
	if msg.Flags != unix.RTF_STATIC {
		t.Fatalf("flags = %#x, want only RTF_STATIC (no gateway, no up on delete)", msg.Flags)
	}

	dst, ok := msg.Addrs[unix.RTAX_DST].(*route.Inet6Addr)
	if !ok || dst.IP != netip.MustParseAddr("2001:db8::").As16() {
		t.Fatalf("destination = %#v, want 2001:db8::", msg.Addrs[unix.RTAX_DST])
	}
	link, ok := msg.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
	if !ok || link.Index != 7 {
		t.Fatalf("gateway = %#v, want the link address of interface 7", msg.Addrs[unix.RTAX_GATEWAY])
	}
	mask, ok := msg.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr)
	if !ok || mask.IP != [16]byte{0xff, 0xff, 0xff, 0xff} {
		t.Fatalf("netmask = %#v, want ffff:ffff::", msg.Addrs[unix.RTAX_NETMASK])
	}

	if wire, err := msg.Marshal(); err != nil || len(wire) == 0 {
		t.Fatalf("Marshal = %d bytes, %v", len(wire), err)
	}
}

func TestDarwinRouteMessageDeletesIPv6RouteWithoutInterfaceIndex(t *testing.T) {
	// The kernel finds the route to delete by its destination and netmask.
	// Without the utun's index there is no link address to name, and the
	// route must still be removable rather than left behind.
	msg, err := darwinRouteMessage(unix.RTM_DELETE, 0, netip.MustParsePrefix("2001:db8::/32"), routeTestGateway)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != unix.RTM_DELETE || msg.Flags != unix.RTF_STATIC {
		t.Fatalf("type/flags = %d/%#x, want %d/%#x", msg.Type, msg.Flags, unix.RTM_DELETE, unix.RTF_STATIC)
	}

	dst, ok := msg.Addrs[unix.RTAX_DST].(*route.Inet6Addr)
	if !ok || dst.IP != netip.MustParseAddr("2001:db8::").As16() {
		t.Fatalf("destination = %#v, want 2001:db8::", msg.Addrs[unix.RTAX_DST])
	}
	mask, ok := msg.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr)
	if !ok || mask.IP != [16]byte{0xff, 0xff, 0xff, 0xff} {
		t.Fatalf("netmask = %#v, want ffff:ffff::", msg.Addrs[unix.RTAX_NETMASK])
	}
	if hop := msg.Addrs[unix.RTAX_GATEWAY]; hop != nil {
		t.Fatalf("gateway = %#v, want none when the interface index is unknown", hop)
	}

	wire, err := msg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// rtm_addrs is the 32-bit field at offset 12 of rt_msghdr.
	if len(wire) < 16 {
		t.Fatalf("Marshal = %d bytes, shorter than the message header", len(wire))
	}
	if got, want := binary.NativeEndian.Uint32(wire[12:16]), uint32(unix.RTA_DST|unix.RTA_NETMASK); got != want {
		t.Fatalf("rtm_addrs = %#x, want %#x (destination and netmask only)", got, want)
	}
}

func TestDarwinRouteMessageRejectsBadRequests(t *testing.T) {
	cases := []struct {
		name        string
		messageType int
		index       int
		destination netip.Prefix
		gateway     netip.Prefix
	}{
		{"unsupported type", unix.RTM_GET, 7, netip.MustParsePrefix("198.51.100.0/24"), routeTestGateway},
		{"empty destination", unix.RTM_ADD, 7, netip.Prefix{}, routeTestGateway},
		{"IPv6 add without interface", unix.RTM_ADD, 0, netip.MustParsePrefix("2001:db8::/32"), routeTestGateway},
		{"IPv4 with IPv6 gateway", unix.RTM_ADD, 7, netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::1/64")},
	}
	for _, c := range cases {
		if msg, err := darwinRouteMessage(c.messageType, c.index, c.destination, c.gateway); err == nil {
			t.Errorf("%s: got message %#v, want an error", c.name, msg)
		}
		if err := execDarwinRoute(c.messageType, c.index, c.destination, c.gateway); err == nil {
			t.Errorf("%s: execDarwinRoute accepted the request", c.name)
		}
	}
}

func TestDarwinRouteMessageNumbersEachMessage(t *testing.T) {
	first, err := darwinRouteMessage(unix.RTM_ADD, 7, netip.MustParsePrefix("198.51.100.0/24"), routeTestGateway)
	if err != nil {
		t.Fatal(err)
	}
	second, err := darwinRouteMessage(unix.RTM_DELETE, 7, netip.MustParsePrefix("198.51.100.0/24"), routeTestGateway)
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq == second.Seq {
		t.Fatalf("two messages share sequence number %d", first.Seq)
	}
}

func TestDarwinUnsetSystemRoutesKeepsOnlyTheRoutesItCouldNotDelete(t *testing.T) {
	refusedIPv4 := netip.MustParsePrefix("192.0.2.0/24")
	deleted := netip.MustParsePrefix("198.51.100.0/24")
	alreadyGone := netip.MustParsePrefix("203.0.113.0/24")
	deletedIPv6 := netip.MustParsePrefix("2001:db8::/32")
	refusedIPv6 := netip.MustParsePrefix("2001:db8:ffff::/48")

	var sent []netip.Addr
	refuse := true
	previous := sendDarwinRoute
	t.Cleanup(func() { sendDarwinRoute = previous })
	sendDarwinRoute = func(msg *route.RouteMessage) error {
		if msg.Type != unix.RTM_DELETE {
			t.Errorf("message type = %d, want only deletes", msg.Type)
		}
		var destination netip.Addr
		switch dst := msg.Addrs[unix.RTAX_DST].(type) {
		case *route.Inet4Addr:
			destination = netip.AddrFrom4(dst.IP)
		case *route.Inet6Addr:
			destination = netip.AddrFrom16(dst.IP)
		default:
			t.Fatalf("destination = %#v, want an IP address", msg.Addrs[unix.RTAX_DST])
		}
		sent = append(sent, destination)
		switch destination {
		case alreadyGone.Addr():
			return os.NewSyscallError("write", unix.ESRCH)
		case refusedIPv4.Addr(), refusedIPv6.Addr():
			if refuse {
				return os.NewSyscallError("write", unix.EPERM)
			}
		}
		return nil
	}

	// No utun behind the descriptor, so the interface index cannot be read.
	tun := &DarwinTun{
		tunFd:        -1,
		gateway:      routeTestGateway,
		systemRoutes: []netip.Prefix{refusedIPv4, deleted, alreadyGone, deletedIPv6, refusedIPv6},
	}
	if index, err := tun.Index(); err == nil {
		t.Fatalf("Index = %d without a utun, want an error", index)
	}

	if err := tun.unsetSystemRoutes(); err == nil {
		t.Fatal("a refused delete was not reported")
	}
	// Newest first.
	wantSent := []netip.Addr{refusedIPv6.Addr(), deletedIPv6.Addr(), alreadyGone.Addr(), deleted.Addr(), refusedIPv4.Addr()}
	if !slices.Equal(sent, wantSent) {
		t.Errorf("deletes sent for %v, want %v", sent, wantSent)
	}
	// The routes left keep the order they were added in.
	if want := []netip.Prefix{refusedIPv4, refusedIPv6}; !slices.Equal(tun.systemRoutes, want) {
		t.Fatalf("routes left to delete = %v, want %v", tun.systemRoutes, want)
	}

	// A later call retries what is left, newest first, and succeeds
	// without the index.
	sent, refuse = nil, false
	if err := tun.unsetSystemRoutes(); err != nil {
		t.Fatalf("retry = %v, want nil", err)
	}
	if want := []netip.Addr{refusedIPv6.Addr(), refusedIPv4.Addr()}; !slices.Equal(sent, want) {
		t.Fatalf("retry sent deletes for %v, want %v", sent, want)
	}
	if len(tun.systemRoutes) != 0 {
		t.Fatalf("routes left to delete = %v, want none", tun.systemRoutes)
	}
}
