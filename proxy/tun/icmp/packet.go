package icmp

import (
	"github.com/xtls/xray-core/common/errors"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func ProtocolLabel(netProto tcpip.NetworkProtocolNumber) string {
	switch netProto {
	case header.IPv4ProtocolNumber:
		return "ipv4"
	case header.IPv6ProtocolNumber:
		return "ipv6"
	default:
		return "unknown"
	}
}

func ParseEchoRequest(netProto tcpip.NetworkProtocolNumber, message []byte) (uint16, uint16, bool) {
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return 0, 0, false
		}
		icmpHdr := header.ICMPv4(message)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != header.ICMPv4UnusedCode {
			return 0, 0, false
		}
		return icmpHdr.Ident(), icmpHdr.Sequence(), true
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return 0, 0, false
		}
		icmpHdr := header.ICMPv6(message)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != header.ICMPv6UnusedCode {
			return 0, 0, false
		}
		return icmpHdr.Ident(), icmpHdr.Sequence(), true
	default:
		return 0, 0, false
	}
}

// RewriteChecksum recomputes, in place, the checksum of an ICMP message (the
// ICMP header and its body, without the IP header). ICMPv4 sums the message
// alone; ICMPv6 also covers the IPv6 pseudo-header built from srcIP, dstIP and
// the message length. The message is left untouched when an error is returned.
func RewriteChecksum(netProto tcpip.NetworkProtocolNumber, message []byte, srcIP, dstIP tcpip.Address) error {
	var initial uint16
	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(message) < header.ICMPv4MinimumSize {
			return errors.New("icmpv4 message too short for a checksum: ", len(message), " bytes")
		}
	case header.IPv6ProtocolNumber:
		if len(message) < header.ICMPv6MinimumSize {
			return errors.New("icmpv6 message too short for a checksum: ", len(message), " bytes")
		}
		initial = header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber, srcIP, dstIP, uint16(len(message)))
	default:
		return errors.New("cannot checksum icmp over network protocol ", uint32(netProto))
	}

	// Both ICMP families keep the checksum in bytes 2..3. It has to be zero
	// while the sum is taken, then receives the one's complement of the sum.
	message[2], message[3] = 0, 0
	sum := ^checksum.Checksum(message, initial)
	message[2], message[3] = byte(sum>>8), byte(sum)
	return nil
}

func BuildLocalEchoReply(netProto tcpip.NetworkProtocolNumber, request []byte, srcIP, dstIP tcpip.Address) ([]byte, error) {
	reply := append([]byte(nil), request...)

	switch netProto {
	case header.IPv4ProtocolNumber:
		if len(reply) < header.ICMPv4MinimumSize {
			return nil, errors.New("invalid icmpv4 echo packet")
		}
		icmpHdr := header.ICMPv4(reply)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != header.ICMPv4UnusedCode {
			return nil, errors.New("not an icmpv4 echo request")
		}
		reply[0] = byte(header.ICMPv4EchoReply)
	case header.IPv6ProtocolNumber:
		if len(reply) < header.ICMPv6MinimumSize {
			return nil, errors.New("invalid icmpv6 echo packet")
		}
		icmpHdr := header.ICMPv6(reply)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != header.ICMPv6UnusedCode {
			return nil, errors.New("not an icmpv6 echo request")
		}
		reply[0] = byte(header.ICMPv6EchoReply)
	default:
		return nil, errors.New("unsupported icmp network protocol")
	}

	if err := RewriteChecksum(netProto, reply, srcIP, dstIP); err != nil {
		return nil, err
	}

	return reply, nil
}
