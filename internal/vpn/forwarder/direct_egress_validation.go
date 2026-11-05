package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

var (
	// ErrInvalidIPv4Packet indicates an IPv4 packet header is truncated or malformed.
	ErrInvalidIPv4Packet = errors.New("forwarder: invalid ipv4 packet")
	// ErrPacketFragmented indicates a fragmented IPv4 packet, which is not supported for direct egress.
	ErrPacketFragmented = errors.New("forwarder: fragmented ipv4 packets not supported")
	// ErrInvalidTransportHdr indicates a truncated or invalid TCP or UDP transport header.
	ErrInvalidTransportHdr = errors.New("forwarder: invalid transport header")
	// ErrInvalidSourceIP indicates an unspecified, zero, or mismatched client source IP.
	ErrInvalidSourceIP = errors.New("forwarder: source ip mismatch or unspecified")
	// ErrStaleSessionReply indicates a reply matching a recycled NAT port from an inactive session.
	ErrStaleSessionReply = errors.New("forwarder: stale reply for inactive or mismatched session")
)

var prohibitedCIDRs = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // RFC 6598 CGNAT
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // Link-local & cloud metadata
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"), // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),      // Benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),        // Multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // Reserved
	netip.MustParsePrefix("255.255.255.255/32"), // Broadcast
}

// IsProhibitedIPv4Destination returns true if dst is private, loopback, link-local,
// CGNAT (100.64.0.0/10), multicast, broadcast, or reserved.
func IsProhibitedIPv4Destination(dst netip.Addr) bool {
	if !dst.IsValid() || !dst.Is4() {
		return true
	}
	if dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsPrivate() || dst.IsMulticast() || dst.IsUnspecified() {
		return true
	}
	if dst.As4()[0] == 0 {
		return true
	}
	for i := range prohibitedCIDRs {
		if prohibitedCIDRs[i].Contains(dst) {
			return true
		}
	}
	return false
}

// ValidateDirectDestination checks whether dst is permitted for direct egress.
// If dst matches the designated gateway DNS address, it is permitted ONLY on port 53.
func ValidateDirectDestination(dst netip.Addr, dstPort uint16, gwDNS netip.Addr) error {
	if gwDNS.IsValid() && dst == gwDNS {
		if dstPort == 53 {
			return nil
		}
		return ErrProhibitedDestination
	}
	if IsProhibitedIPv4Destination(dst) {
		return ErrProhibitedDestination
	}
	return nil
}

// ParsedClientPacket contains extracted and validated IPv4 & transport header metadata.
type ParsedClientPacket struct {
	IHL      int
	TotalLen int
	Protocol uint8
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
}

// ParseAndValidateClientIPv4 thoroughly validates an IPv4 packet from a client:
// - Version 4 check
// - IHL >= 5 (minimum 20 bytes) and buffer length >= IHL
// - Total Length >= IHL and Total Length <= buffer length
// - Drop fragmented packets (MF=1 or FragmentOffset > 0)
// - Transport protocol is TCP (6) or UDP (17)
// - Minimum transport header size (TCP >= 20, UDP >= 8) and header offset bounds
// - Source IP is valid, not 0.0.0.0/unspecified, and matches assignedIP (if provided)
func ParseAndValidateClientIPv4(packet []byte, assignedIP string) (*ParsedClientPacket, error) {
	if len(packet) < 20 {
		return nil, ErrInvalidIPv4Packet
	}
	if (packet[0] >> 4) != 4 {
		return nil, ErrInvalidIPv4Packet
	}

	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return nil, ErrInvalidIPv4Packet
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return nil, ErrInvalidIPv4Packet
	}

	// Fragmentation: byte 6 bit 5 is More Fragments (MF), bits 0-4 of byte 6 + byte 7 are Fragment Offset.
	// If flags & 0x2000 != 0 (MF) or flags & 0x1fff != 0 (offset > 0), drop.
	fragField := binary.BigEndian.Uint16(packet[6:8])
	if (fragField & 0x3fff) != 0 {
		return nil, ErrPacketFragmented
	}

	proto := packet[9]
	var srcPort, dstPort uint16
	switch proto {
	case 6: // TCP
		if totalLen < ihl+20 {
			return nil, ErrInvalidTransportHdr
		}
		dataOffset := int(packet[ihl+12]>>4) * 4
		if dataOffset < 20 || ihl+dataOffset > totalLen {
			return nil, ErrInvalidTransportHdr
		}
		srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	case 17: // UDP
		if totalLen < ihl+8 {
			return nil, ErrInvalidTransportHdr
		}
		udpLen := int(binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]))
		if udpLen < 8 || ihl+udpLen > totalLen {
			return nil, ErrInvalidTransportHdr
		}
		srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	case 1: // ICMP
		if totalLen < ihl+8 {
			return nil, ErrInvalidTransportHdr
		}
	default:
		// Unsupported DIRECT transport protocol; passes IPv4 validation for PROXY fallback.
	}

	// Source IP validation
	srcIP := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	if !srcIP.IsValid() || !srcIP.Is4() || srcIP.IsUnspecified() || srcIP.As4() == [4]byte{0, 0, 0, 0} {
		return nil, ErrInvalidSourceIP
	}
	if assignedIP != "" {
		expectedIP, err := netip.ParseAddr(assignedIP)
		if err != nil || srcIP != expectedIP {
			return nil, ErrInvalidSourceIP
		}
	}

	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})

	return &ParsedClientPacket{
		IHL:      ihl,
		TotalLen: totalLen,
		Protocol: proto,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}, nil
}

// ValidateWANReplyIPv4 thoroughly validates an inbound response packet from the WAN:
// - Version 4 check
// - IHL >= 5 (minimum 20 bytes) and buffer length >= IHL
// - Total Length >= IHL and Total Length <= buffer length
// - Drop fragmented packets (MF=1 or FragmentOffset > 0)
// - Protocol is TCP (6) or UDP (17)
// - Destination IP matches hostWAN (if hostWAN is valid)
// - Minimum transport header size (TCP >= 20, UDP >= 8)
func ValidateWANReplyIPv4(packet []byte, hostWAN netip.Addr) (ihl int, proto uint8, natPort uint16, srcIP netip.Addr, srcPort uint16, err error) {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return 0, 0, 0, netip.Addr{}, 0, ErrInvalidIPv4Packet
	}
	ihl = int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0, 0, 0, netip.Addr{}, 0, ErrInvalidIPv4Packet
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return 0, 0, 0, netip.Addr{}, 0, ErrInvalidIPv4Packet
	}

	fragField := binary.BigEndian.Uint16(packet[6:8])
	if (fragField & 0x3fff) != 0 {
		return 0, 0, 0, netip.Addr{}, 0, ErrPacketFragmented
	}

	proto = packet[9]
	if proto != 6 && proto != 17 {
		return 0, 0, 0, netip.Addr{}, 0, errors.New("unsupported protocol in wan reply")
	}

	if proto == 6 {
		if totalLen < ihl+20 {
			return 0, 0, 0, netip.Addr{}, 0, ErrInvalidTransportHdr
		}
		dataOffset := int(packet[ihl+12]>>4) * 4
		if dataOffset < 20 || ihl+dataOffset > totalLen {
			return 0, 0, 0, netip.Addr{}, 0, ErrInvalidTransportHdr
		}
	} else {
		if totalLen < ihl+8 {
			return 0, 0, 0, netip.Addr{}, 0, ErrInvalidTransportHdr
		}
		udpLen := int(binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]))
		if udpLen < 8 || ihl+udpLen > totalLen {
			return 0, 0, 0, netip.Addr{}, 0, ErrInvalidTransportHdr
		}
	}

	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	if hostWAN.IsValid() && dstIP != hostWAN {
		return 0, 0, 0, netip.Addr{}, 0, errors.New("destination ip does not match host wan ip")
	}

	natPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	srcIP = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	return ihl, proto, natPort, srcIP, srcPort, nil
}

func applySNAT(packet []byte, ihl int, proto uint8, hostWAN netip.Addr, dstIP [4]byte, natPort uint16) []byte {
	out := make([]byte, len(packet))
	copy(out, packet)
	wanBytes := hostWAN.As4()
	copy(out[12:16], wanBytes[:])
	binary.BigEndian.PutUint16(out[ihl:ihl+2], natPort)

	// Recalculate IPv4 Header Checksum
	binary.BigEndian.PutUint16(out[10:12], 0)
	ipCS := computeIPv4Checksum(out[:ihl])
	binary.BigEndian.PutUint16(out[10:12], ipCS)

	// Recalculate L4 Checksum
	if proto == 6 {
		if len(out) >= ihl+20 {
			binary.BigEndian.PutUint16(out[ihl+16:ihl+18], 0)
			tcpCS := computeL4Checksum(wanBytes, dstIP, 6, out[ihl:])
			binary.BigEndian.PutUint16(out[ihl+16:ihl+18], tcpCS)
		}
	} else if proto == 17 {
		if len(out) >= ihl+8 {
			binary.BigEndian.PutUint16(out[ihl+6:ihl+8], 0)
			udpCS := computeL4Checksum(wanBytes, dstIP, 17, out[ihl:])
			binary.BigEndian.PutUint16(out[ihl+6:ihl+8], udpCS)
		}
	}
	return out
}

func applyDNAT(packet []byte, ihl int, proto uint8, clientIP netip.Addr, clientPort uint16) []byte {
	reply := make([]byte, len(packet))
	copy(reply, packet)
	clientIPBytes := clientIP.As4()
	copy(reply[16:20], clientIPBytes[:])
	binary.BigEndian.PutUint16(reply[ihl+2:ihl+4], clientPort)

	// Recalculate IPv4 Header Checksum
	binary.BigEndian.PutUint16(reply[10:12], 0)
	ipCS := computeIPv4Checksum(reply[:ihl])
	binary.BigEndian.PutUint16(reply[10:12], ipCS)

	// Recalculate L4 Checksum
	srcIPBytes := [4]byte{reply[12], reply[13], reply[14], reply[15]}
	if proto == 6 && len(reply) >= ihl+20 {
		binary.BigEndian.PutUint16(reply[ihl+16:ihl+18], 0)
		tcpCS := computeL4Checksum(srcIPBytes, clientIPBytes, 6, reply[ihl:])
		binary.BigEndian.PutUint16(reply[ihl+16:ihl+18], tcpCS)
	} else if proto == 17 && len(reply) >= ihl+8 {
		binary.BigEndian.PutUint16(reply[ihl+6:ihl+8], 0)
		udpCS := computeL4Checksum(srcIPBytes, clientIPBytes, 17, reply[ihl:])
		binary.BigEndian.PutUint16(reply[ihl+6:ihl+8], udpCS)
	}
	return reply
}

func computeIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func computeL4Checksum(srcIP, dstIP [4]byte, protocol uint8, l4Data []byte) uint16 {
	var sum uint32
	// Pseudo-header
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(protocol)
	length := uint16(len(l4Data)) // #nosec G115 -- l4Data bounded by IP MTU <= 65535
	sum += uint32(length)

	// L4 Data
	for i := 0; i < len(l4Data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4Data[i : i+2]))
	}
	if len(l4Data)%2 != 0 {
		sum += uint32(l4Data[len(l4Data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	if protocol == 17 && c == 0 {
		return 0xffff
	}
	return c
}

// IsProhibitedDestination checks whether dst is permitted for direct egress.
// Traffic to the designated gateway DNS address is permitted without port qualification here
// (strict port 53 scoping is enforced on full packets in RouteDirect/pumps).
func (m *DirectEgressManager) IsProhibitedDestination(dst netip.Addr) bool {
	if m != nil {
		gw := m.GatewayDNSIP()
		if gw.IsValid() && dst == gw {
			return false
		}
	}
	return IsProhibitedIPv4Destination(dst)
}

func (m *DirectEgressManager) isFlowExpiredLocked(f *flowEntry, proto uint8, now time.Time) bool {
	timeout := m.cfg.UDPTimeout
	if proto == 6 {
		if f.closeSeen {
			timeout = 5 * time.Second
		} else {
			timeout = m.cfg.TCPTimeout
		}
	}
	return now.Sub(f.lastSeen) > timeout
}

func parseGenerationArg(v any) (uint64, bool) {
	switch g := v.(type) {
	case uint64:
		return g, true
	case int:
		if g >= 0 {
			return uint64(g), true // #nosec G115
		}
	case uint:
		return uint64(g), true
	case int64:
		if g >= 0 {
			return uint64(g), true // #nosec G115
		}
	}
	return 0, false
}
