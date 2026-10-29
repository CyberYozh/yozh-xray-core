package icmp

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	docSrc6 = tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a})
	docDst6 = tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b})
	docAlt6 = tcpip.AddrFromSlice([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c})
)

// verifiesV4 reports whether an ICMPv4 message sums to all ones, which is how
// a receiver (gVisor included) validates the Internet checksum.
func verifiesV4(message []byte) bool {
	return checksum.Checksum(message, 0) == 0xffff
}

// verifiesV6 is the ICMPv6 counterpart: the sum also covers the IPv6
// pseudo-header.
func verifiesV6(message []byte, src, dst tcpip.Address) bool {
	pseudo := header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber, src, dst, uint16(len(message)))
	return checksum.Checksum(message, pseudo) == 0xffff
}

func TestRewriteChecksumRejectsShortMessagesUntouched(t *testing.T) {
	cases := []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
		size  int
	}{
		{"ipv4", header.IPv4ProtocolNumber, header.ICMPv4MinimumSize - 1},
		{"ipv6", header.IPv6ProtocolNumber, header.ICMPv6MinimumSize - 1},
		{"ipv4 empty", header.IPv4ProtocolNumber, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message := bytes.Repeat([]byte{0xa5}, tc.size)
			original := append([]byte(nil), message...)
			if err := RewriteChecksum(tc.proto, message, docSrc6, docDst6); err == nil {
				t.Fatalf("expected an error for a %d-byte message", tc.size)
			}
			if !bytes.Equal(message, original) {
				t.Fatalf("short message was modified: got %x, want %x", message, original)
			}
		})
	}
}

func TestRewriteChecksumRejectsUnknownNetworkProtocol(t *testing.T) {
	message := []byte{byte(header.ICMPv4Echo), 0, 0x12, 0x34, 0, 1, 0, 2, 0xde, 0xad}
	original := append([]byte(nil), message...)
	if err := RewriteChecksum(tcpip.NetworkProtocolNumber(0x0806), message, docSrc6, docDst6); err == nil {
		t.Fatal("expected an error for a non-IP network protocol")
	}
	if !bytes.Equal(message, original) {
		t.Fatalf("message was modified: got %x, want %x", message, original)
	}
}

func TestRewriteChecksumProducesVerifiableIPv4Sum(t *testing.T) {
	// Odd length on purpose: the trailing byte must be padded, not dropped.
	message := []byte{byte(header.ICMPv4EchoReply), 0, 0xbe, 0xef, 0x00, 0x07, 0x00, 0x2a, 0x01, 0x02, 0x03}
	if err := RewriteChecksum(header.IPv4ProtocolNumber, message, tcpip.Address{}, tcpip.Address{}); err != nil {
		t.Fatal(err)
	}
	if !verifiesV4(message) {
		t.Fatalf("ICMPv4 checksum does not verify: %x", message)
	}

	// The IPv4 sum has no pseudo-header, so the addresses must not matter.
	again := append([]byte(nil), message...)
	if err := RewriteChecksum(header.IPv4ProtocolNumber, again, docSrc6, docAlt6); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, message) {
		t.Fatalf("ICMPv4 checksum depends on addresses: %x vs %x", again, message)
	}
}

func TestRewriteChecksumProducesVerifiableIPv6Sum(t *testing.T) {
	message := []byte{byte(header.ICMPv6EchoReply), 0, 0x00, 0x00, 0x43, 0x21, 0x00, 0x09, 0x10, 0x20, 0x30}
	if err := RewriteChecksum(header.IPv6ProtocolNumber, message, docSrc6, docDst6); err != nil {
		t.Fatal(err)
	}
	if !verifiesV6(message, docSrc6, docDst6) {
		t.Fatalf("ICMPv6 checksum does not verify: %x", message)
	}
	first := header.ICMPv6(message).Checksum()

	if err := RewriteChecksum(header.IPv6ProtocolNumber, message, docSrc6, docAlt6); err != nil {
		t.Fatal(err)
	}
	if header.ICMPv6(message).Checksum() == first {
		t.Fatal("ICMPv6 checksum did not change with the destination address")
	}
	if !verifiesV6(message, docSrc6, docAlt6) {
		t.Fatalf("ICMPv6 checksum does not verify after the destination change: %x", message)
	}
}

func TestRewriteChecksumIgnoresStaleSum(t *testing.T) {
	fresh := []byte{byte(header.ICMPv4Echo), 0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}
	stale := []byte{byte(header.ICMPv4Echo), 0, 0x5a, 0xa5, 0x00, 0x01, 0x00, 0x01}
	for _, m := range [][]byte{fresh, stale} {
		if err := RewriteChecksum(header.IPv4ProtocolNumber, m, tcpip.Address{}, tcpip.Address{}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(fresh, stale) {
		t.Fatalf("a stale checksum leaked into the new one: %x vs %x", fresh, stale)
	}
}
