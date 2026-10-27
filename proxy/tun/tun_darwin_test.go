//go:build darwin

package tun

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"unsafe"

	xerrors "github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

func TestSelectDarwinGatewayDefault(t *testing.T) {
	gateway, err := selectDarwinGateway(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != defaultDarwinGateway {
		t.Fatalf("unexpected default gateway: got %s, want %s", got, defaultDarwinGateway)
	}
}

func TestSelectDarwinGatewayConfiguredIPv4(t *testing.T) {
	gateway, err := selectDarwinGateway([]string{"198.18.0.1/15"})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != "198.18.0.1/15" {
		t.Fatalf("unexpected gateway: got %s", got)
	}
}

func TestSelectDarwinGatewaySkipsIPv6(t *testing.T) {
	gateway, err := selectDarwinGateway([]string{"fc00::1/64", "198.18.0.1/15"})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != "198.18.0.1/15" {
		t.Fatalf("unexpected gateway: got %s", got)
	}
}

func TestSelectDarwinGatewayRequiresIPv4(t *testing.T) {
	if _, err := selectDarwinGateway([]string{"fc00::1/64"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestSelectDarwinGatewayRequiresUsableLocalAddress(t *testing.T) {
	if _, err := selectDarwinGateway([]string{"198.18.0.1/32"}); err == nil {
		t.Fatal("expected error")
	}
}

// The numbers below are the layout the macOS SDK compiles for both arm64 and
// amd64; tun_darwin_layout_test.go checks the same thing against the headers
// with cgo, this one also runs without a C compiler.
func TestDarwinRequestLayoutFromSpec(t *testing.T) {
	var r4 inAliasReq
	var r6 in6AliasReq
	var lt in6AddrLifetime
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof(inAliasReq)", unsafe.Sizeof(r4), 64},
		{"inAliasReq.Name", unsafe.Offsetof(r4.Name), 0},
		{"inAliasReq.Addr", unsafe.Offsetof(r4.Addr), 16},
		{"inAliasReq.Broadaddr", unsafe.Offsetof(r4.Broadaddr), 32},
		{"inAliasReq.Mask", unsafe.Offsetof(r4.Mask), 48},

		{"sizeof(in6AliasReq)", unsafe.Sizeof(r6), 128},
		{"in6AliasReq.Name", unsafe.Offsetof(r6.Name), 0},
		{"in6AliasReq.Addr", unsafe.Offsetof(r6.Addr), 16},
		{"in6AliasReq.Dstaddr", unsafe.Offsetof(r6.Dstaddr), 44},
		{"in6AliasReq.Prefixmask", unsafe.Offsetof(r6.Prefixmask), 72},
		{"in6AliasReq.Flags", unsafe.Offsetof(r6.Flags), 100},
		{"in6AliasReq.Lifetime", unsafe.Offsetof(r6.Lifetime), 104},

		{"sizeof(in6AddrLifetime)", unsafe.Sizeof(lt), 24},
		{"in6AddrLifetime.Expire", unsafe.Offsetof(lt.Expire), 0},
		{"in6AddrLifetime.Preferred", unsafe.Offsetof(lt.Preferred), 8},
		{"in6AddrLifetime.Vltime", unsafe.Offsetof(lt.Vltime), 16},
		{"in6AddrLifetime.Pltime", unsafe.Offsetof(lt.Pltime), 20},

		// The kernel copies in as many bytes as the request number says (bits 16..28).
		{"argument size in SIOCAIFADDR", (unix.SIOCAIFADDR >> 16) & 0x1fff, 64},
		{"SIOCAIFADDR_IN6", uintptr(siocAIFADDRIn6), 0x8080691a},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %d (%#x), want %d (%#x)", c.name, c.got, c.got, c.want, c.want)
		}
	}
}

func TestDarwinLinkLocalFromIPv4(t *testing.T) {
	cases := []struct{ local, want string }{
		{"198.18.0.2", "fe80::c612:2"},
		{"169.254.10.2", "fe80::a9fe:a02"},
	}
	for _, c := range cases {
		got := darwinLinkLocalFromIPv4(netip.MustParseAddr(c.local))
		if got != netip.MustParseAddr(c.want) {
			t.Errorf("link-local for %s: got %s, want %s", c.local, got, c.want)
		}
	}
}

func TestDarwinInAliasReqMakesGatewayThePeer(t *testing.T) {
	cases := []struct {
		gateway string
		mask    [4]byte
	}{
		{"198.18.0.1/30", [4]byte{255, 255, 255, 252}},
		{"198.18.0.1/15", [4]byte{255, 254, 0, 0}},
	}
	for _, c := range cases {
		got := newInAliasReq("utun10", netip.MustParseAddr("198.18.0.2"), netip.MustParsePrefix(c.gateway))
		want := inAliasReq{
			Name:      [16]byte{'u', 't', 'u', 'n', '1', '0'},
			Addr:      unix.RawSockaddrInet4{Len: 16, Family: 2, Addr: [4]byte{198, 18, 0, 2}},
			Broadaddr: unix.RawSockaddrInet4{Len: 16, Family: 2, Addr: [4]byte{198, 18, 0, 1}},
			Mask:      unix.RawSockaddrInet4{Len: 16, Family: 2, Addr: c.mask},
		}
		if got != want {
			t.Errorf("gateway %s:\n got %+v\nwant %+v", c.gateway, got, want)
		}
	}
}

func TestDarwinIn6AliasReqAddsLinkLocalWithoutDAD(t *testing.T) {
	got := newIn6AliasReq("utun10", netip.MustParseAddr("fe80::c612:2"))
	want := in6AliasReq{
		Name: [16]byte{'u', 't', 'u', 'n', '1', '0'},
		Addr: unix.RawSockaddrInet6{Len: 28, Family: 30, Addr: [16]byte{0xfe, 0x80, 12: 198, 18, 0, 2}},
		// Dstaddr stays all zero: no IPv6 peer on the utun.
		Prefixmask: unix.RawSockaddrInet6{Len: 28, Family: 30, Addr: [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		Flags:      0x20,
		Lifetime:   in6AddrLifetime{Vltime: 0xffffffff, Pltime: 0xffffffff},
	}
	if got != want {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
}

func TestDarwinSetIPAddressRejectsGatewayWithoutLocalAddress(t *testing.T) {
	for _, gateway := range []string{"198.18.0.1/32", "255.255.255.255/32"} {
		err := setIPAddress("utun10", netip.MustParsePrefix(gateway))
		var xerr *xerrors.Error
		if !errors.As(err, &xerr) {
			t.Fatalf("gateway %s: want the package error type, got %T %v", gateway, err, err)
		}
		want := "macOS gateway " + gateway + " must contain at least one usable local IPv4 address after the gateway address"
		if !strings.HasSuffix(err.Error(), want) {
			t.Errorf("gateway %s: got %q, want it to end with %q", gateway, err.Error(), want)
		}
	}
}

func TestDarwinSetIPAddressNamesTheFailedIoctl(t *testing.T) {
	// No interface has this name, so the kernel refuses the IPv4 request whether
	// or not the test runs as root, and nothing on the machine changes.
	err := setIPAddress("xtestnoif0", netip.MustParsePrefix("198.18.0.1/30"))
	var syscallErr *os.SyscallError
	if !errors.As(err, &syscallErr) {
		t.Fatalf("want *os.SyscallError, got %T %v", err, err)
	}
	if syscallErr.Syscall != "SIOCAIFADDR" {
		t.Errorf("syscall name %q, want SIOCAIFADDR", syscallErr.Syscall)
	}
	var errno unix.Errno
	if !errors.As(err, &errno) || errno == 0 {
		t.Errorf("want the raw errno inside, got %v", err)
	}
}
