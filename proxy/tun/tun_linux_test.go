//go:build linux && !android

package tun

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func openDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot count open descriptors: %v", err)
	}
	return len(entries)
}

func TestOpenRejectsOverlongNameWithoutLeaking(t *testing.T) {
	before := openDescriptorCount(t)
	// IFNAMSIZ is 16 including the terminating NUL, so 16 characters are one too many.
	fd, err := open("abcdefghijklmnop")
	if err == nil {
		_ = unix.Close(fd)
		t.Fatal("expected an error for a 16-character interface name")
	}
	if fd != -1 {
		t.Fatalf("descriptor on error = %d, want -1", fd)
	}
	if after := openDescriptorCount(t); after != before {
		t.Fatalf("open descriptors changed from %d to %d", before, after)
	}
}

func TestOpenCreatesNonblockingTunInterface(t *testing.T) {
	const name = "xrtuntest0"
	fd, err := open(name)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
			errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
			t.Skipf("creating a TUN device needs CAP_NET_ADMIN and /dev/net/tun: %v", err)
		}
		t.Fatal(err)
	}
	defer unix.Close(fd)

	if fd < 0 {
		t.Fatalf("invalid descriptor %d", fd)
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("descriptor is blocking")
	}

	req, err := unix.NewIfreq("")
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, req); err != nil {
		t.Fatal(err)
	}
	if got := req.Name(); got != name {
		t.Fatalf("device name = %q, want %q", got, name)
	}
	if mode := req.Uint16(); mode&unix.IFF_TUN == 0 || mode&unix.IFF_NO_PI == 0 {
		t.Fatalf("device flags = %#x, want IFF_TUN|IFF_NO_PI", mode)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("interface %q is not visible: %v", name, err)
	}
}

func TestLinuxNewEndpointUsesDescriptorAndMTU(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	tun := &LinuxTun{tunFd: fds[0], options: &Config{MTU: 1400}}
	ep, err := tun.newEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close()

	if got := ep.MTU(); got != 1400 {
		t.Fatalf("MTU = %d, want 1400", got)
	}
	if got := ep.MaxHeaderLength(); got != 0 {
		t.Fatalf("MaxHeaderLength = %d, want 0 (no link header)", got)
	}
	if ep.Capabilities()&stack.CapabilityRXChecksumOffload == 0 {
		t.Fatal("RX checksum offload is not enabled")
	}
}
