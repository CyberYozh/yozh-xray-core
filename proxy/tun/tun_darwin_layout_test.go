//go:build darwin && cgo

package tun

// The utun address requests are handed to the kernel as raw memory, so the Go
// structures must have exactly the C layout. These tests compare them with what
// the C compiler makes of the macOS SDK headers (through the cgo helper package,
// since cgo is not allowed in _test.go files). No root needed.

import (
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/proxy/tun/internal/darwinsdk"
	"golang.org/x/sys/unix"
)

func checkLayoutAgainstSDK(t *testing.T, want darwinsdk.Struct, goSize uintptr, goFields []darwinsdk.Field) {
	t.Helper()
	if goSize != want.Size {
		t.Errorf("%s: Go size %d, C sizeof %d", want.Name, goSize, want.Size)
	}
	if len(goFields) != len(want.Fields) {
		t.Fatalf("%s: Go mirror lists %d fields, C has %d", want.Name, len(goFields), len(want.Fields))
	}
	for i, c := range want.Fields {
		g := goFields[i]
		if g.Name != c.Name {
			t.Errorf("%s field %d: Go mirror is %s, C declares %s", want.Name, i, g.Name, c.Name)
			continue
		}
		if g.Offset != c.Offset {
			t.Errorf("%s.%s: Go offset %d, C offsetof %d", want.Name, c.Name, g.Offset, c.Offset)
		}
		if g.Size != c.Size {
			t.Errorf("%s.%s: Go size %d, C sizeof %d", want.Name, c.Name, g.Size, c.Size)
		}
	}
}

func TestDarwinLayoutInAliasReqMatchesSDK(t *testing.T) {
	var r inAliasReq
	checkLayoutAgainstSDK(t, darwinsdk.IfAliasReq, unsafe.Sizeof(r), []darwinsdk.Field{
		{Name: "ifra_name", Offset: unsafe.Offsetof(r.Name), Size: unsafe.Sizeof(r.Name)},
		{Name: "ifra_addr", Offset: unsafe.Offsetof(r.Addr), Size: unsafe.Sizeof(r.Addr)},
		{Name: "ifra_broadaddr", Offset: unsafe.Offsetof(r.Broadaddr), Size: unsafe.Sizeof(r.Broadaddr)},
		{Name: "ifra_mask", Offset: unsafe.Offsetof(r.Mask), Size: unsafe.Sizeof(r.Mask)},
	})
}

func TestDarwinLayoutIn6AliasReqMatchesSDK(t *testing.T) {
	var r in6AliasReq
	checkLayoutAgainstSDK(t, darwinsdk.In6AliasReq, unsafe.Sizeof(r), []darwinsdk.Field{
		{Name: "ifra_name", Offset: unsafe.Offsetof(r.Name), Size: unsafe.Sizeof(r.Name)},
		{Name: "ifra_addr", Offset: unsafe.Offsetof(r.Addr), Size: unsafe.Sizeof(r.Addr)},
		{Name: "ifra_dstaddr", Offset: unsafe.Offsetof(r.Dstaddr), Size: unsafe.Sizeof(r.Dstaddr)},
		{Name: "ifra_prefixmask", Offset: unsafe.Offsetof(r.Prefixmask), Size: unsafe.Sizeof(r.Prefixmask)},
		{Name: "ifra_flags", Offset: unsafe.Offsetof(r.Flags), Size: unsafe.Sizeof(r.Flags)},
		{Name: "ifra_lifetime", Offset: unsafe.Offsetof(r.Lifetime), Size: unsafe.Sizeof(r.Lifetime)},
	})
}

func TestDarwinLayoutIn6AddrLifetimeMatchesSDK(t *testing.T) {
	var r in6AddrLifetime
	checkLayoutAgainstSDK(t, darwinsdk.In6AddrLifetime, unsafe.Sizeof(r), []darwinsdk.Field{
		{Name: "ia6t_expire", Offset: unsafe.Offsetof(r.Expire), Size: unsafe.Sizeof(r.Expire)},
		{Name: "ia6t_preferred", Offset: unsafe.Offsetof(r.Preferred), Size: unsafe.Sizeof(r.Preferred)},
		{Name: "ia6t_vltime", Offset: unsafe.Offsetof(r.Vltime), Size: unsafe.Sizeof(r.Vltime)},
		{Name: "ia6t_pltime", Offset: unsafe.Offsetof(r.Pltime), Size: unsafe.Sizeof(r.Pltime)},
	})
}

func TestDarwinLayoutConstantsMatchSDK(t *testing.T) {
	checks := []struct {
		name      string
		got, want uint64
	}{
		{"SIOCAIFADDR", unix.SIOCAIFADDR, darwinsdk.SIOCAIFADDR},
		{"SIOCAIFADDR_IN6", uint64(siocAIFADDRIn6), darwinsdk.SIOCAIFADDR_IN6},
		{"IN6_IFF_NODAD", in6IFFNoDAD, darwinsdk.IN6_IFF_NODAD},
		{"ND6_INFINITE_LIFETIME", nd6InfiniteLifetime, darwinsdk.ND6_INFINITE_LIFETIME},
		{"IFNAMSIZ", unix.IFNAMSIZ, darwinsdk.IFNAMSIZ},
		{"AF_INET", unix.AF_INET, darwinsdk.AF_INET},
		{"AF_INET6", unix.AF_INET6, darwinsdk.AF_INET6},
		{"sizeof(struct sockaddr_in)", unix.SizeofSockaddrInet4, darwinsdk.SizeofSockaddrIn},
		{"sizeof(struct sockaddr_in6)", unix.SizeofSockaddrInet6, darwinsdk.SizeofSockaddrIn6},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: Go value %#x, SDK header value %#x", c.name, c.got, c.want)
		}
	}
}
