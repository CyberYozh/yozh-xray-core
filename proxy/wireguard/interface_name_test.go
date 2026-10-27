package wireguard

import (
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestPickInterfaceNameStartsAtZero(t *testing.T) {
	if got := pickInterfaceName("linux", "wg", nil); got != "wg0" {
		t.Fatalf("got %q, want wg0", got)
	}
}

func TestPickInterfaceNameGoesPastTheHighestIndex(t *testing.T) {
	orders := [][]string{
		{"wg0", "wg3", "wg1"},
		{"wg3", "wg1", "wg0"},
		{"wg1", "wg0", "wg3"},
	}
	for _, taken := range orders {
		if got := pickInterfaceName("linux", "wg", taken); got != "wg4" {
			t.Fatalf("taken %v: got %q, want wg4", taken, got)
		}
	}
}

func TestPickInterfaceNameIgnoresForeignNames(t *testing.T) {
	taken := []string{"wg-foo", "wgx", "eth0", "wg", "wg+1", "wg-2", "xwg7", "lo"}
	if got := pickInterfaceName("linux", "wg", taken); got != "wg0" {
		t.Fatalf("got %q, want wg0", got)
	}
	taken = append(taken, "wg2")
	if got := pickInterfaceName("linux", "wg", taken); got != "wg3" {
		t.Fatalf("got %q, want wg3", got)
	}
}

func TestPickInterfaceNameDefaultsToTunBase(t *testing.T) {
	if got := pickInterfaceName("linux", "", []string{"wg5", "eth0"}); got != "tun0" {
		t.Fatalf("got %q, want tun0", got)
	}
	if got := pickInterfaceName("linux", "", []string{"tun0", "tun7"}); got != "tun8" {
		t.Fatalf("got %q, want tun8", got)
	}
}

func TestPickInterfaceNameUsesUtunOnDarwin(t *testing.T) {
	taken := []string{"lo0", "en0", "utun0", "utun1", "utun4", "wg9"}
	if got := pickInterfaceName("darwin", "wg", taken); got != "utun5" {
		t.Fatalf("got %q, want utun5", got)
	}
	if got := pickInterfaceName("darwin", "", nil); got != "utun0" {
		t.Fatalf("got %q, want utun0", got)
	}
}

func TestPickInterfaceNameNeverReturnsATakenName(t *testing.T) {
	sets := [][]string{
		nil,
		{"wg0"},
		{"wg00", "wg01"},
		{"wg007", "wg2"},
		{"wg4294967295"},
		{"wg99999999999999999999999", "wg1"},
	}
	for _, taken := range sets {
		got := pickInterfaceName("linux", "wg", taken)
		if slices.Contains(taken, got) {
			t.Fatalf("taken %v: picked an existing name %q", taken, got)
		}
	}
}

func TestCalculateInterfaceNameAvoidsLiveInterfaces(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot list interfaces here: %v", err)
	}
	got := CalculateInterfaceName("wg")
	if got == "" {
		t.Fatal("empty interface name")
	}
	for _, iface := range ifaces {
		if iface.Name == got {
			t.Fatalf("picked the name of an existing interface: %q", got)
		}
	}
}
