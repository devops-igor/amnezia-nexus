package gatewaydns

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Intercepted TCP DNS needs an address translation that UDP does not: the
// gateway's netstack only terminates connections addressed to the gateway
// address, so a query to a foreign resolver must be rewritten to the gateway on
// the way in and rewritten back to the queried resolver on the way out. The
// translation is keyed by the client flow's source address and retained only
// while that flow is alive, bounded by dnsTCPNATMaxEntries per session.

const (
	// dnsTCPNATMaxEntries bounds the per-session TCP DNS translations that
	// interception retains. One entry is one client TCP flow; a client that
	// opens more concurrent connections ages the oldest entries out instead
	// of growing the session's state without bound.
	dnsTCPNATMaxEntries = 256

	// dnsTCPNATIdleTimeout is how long an idle translation is retained. TCP
	// DNS connections are short-lived; an entry older than this is evicted on
	// the next translation that needs room and ignored on lookup, so a stale
	// translation can never rewrite an unrelated later reply.
	dnsTCPNATIdleTimeout = 60 * time.Second
)

type dnsTCPNAT struct {
	mu      sync.Mutex
	entries map[netip.AddrPort]*dnsTCPNATTranslation
}

type dnsTCPNATTranslation struct {
	destination netip.AddrPort
	lastSeen    time.Time
}

// outbound records the flow's real destination and rewrites the packet so the
// gateway netstack terminates it on the gateway address. It returns the packet
// unchanged (and forgets any translation) when the flow already targets the
// gateway, and reports false for a packet that cannot be safely rewritten
// (fragmented or malformed), which the caller must drop rather than forward to
// the wrong destination.
func (n *dnsTCPNAT) outbound(packet []byte, ihl int, gateway netip.Addr, now time.Time) ([]byte, bool) {
	if ihl < 20 || len(packet) < ihl+20 {
		return nil, false
	}
	totalLen, ok := ipv4TotalLength(packet, ihl)
	if !ok || fragmentedIPv4(packet) {
		return nil, false
	}
	srcIP := ipv4Addr(packet, 12)
	dstIP := ipv4Addr(packet, 16)
	srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
	key := netip.AddrPortFrom(srcIP, srcPort)

	if dstIP == gateway {
		n.forget(key)
		return packet, true
	}
	rewritten, ok := rewriteIPv4Endpoints(packet, ihl, totalLen, srcIP, gateway)
	if !ok {
		return nil, false
	}
	n.remember(key, netip.AddrPortFrom(dstIP, 53), now)
	return rewritten, true
}

// inbound rewrites the source of a reply emitted by the gateway netstack back
// to the address the client originally queried. A packet that is not a TCP
// reply from the gateway, or that has no live translation, is returned
// unchanged; a translation that cannot be applied drops the packet.
func (n *dnsTCPNAT) inbound(packet []byte, gateway netip.Addr, now time.Time) ([]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return packet, true
	}
	ihl := int(packet[0]&0x0f) * 4
	totalLen, ok := ipv4TotalLength(packet, ihl)
	if !ok || packet[9] != 6 || fragmentedIPv4(packet) {
		return packet, true
	}
	if ipv4Addr(packet, 12) != gateway {
		return packet, true
	}
	if binary.BigEndian.Uint16(packet[ihl:ihl+2]) != 53 {
		return packet, true
	}

	clientKey := netip.AddrPortFrom(ipv4Addr(packet, 16), binary.BigEndian.Uint16(packet[ihl+2:ihl+4]))
	destination, ok := n.lookup(clientKey, now)
	if !ok {
		return packet, true
	}
	rewritten, ok := rewriteIPv4Endpoints(packet, ihl, totalLen, destination.Addr(), clientKey.Addr())
	if !ok {
		return nil, false
	}
	return rewritten, true
}

func (n *dnsTCPNAT) remember(key, destination netip.AddrPort, now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.entries == nil {
		n.entries = make(map[netip.AddrPort]*dnsTCPNATTranslation, 8)
	}
	if _, exists := n.entries[key]; !exists && len(n.entries) >= dnsTCPNATMaxEntries {
		n.evictLocked(now)
	}
	n.entries[key] = &dnsTCPNATTranslation{destination: destination, lastSeen: now}
}

func (n *dnsTCPNAT) lookup(key netip.AddrPort, now time.Time) (netip.AddrPort, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry := n.entries[key]
	if entry == nil {
		return netip.AddrPort{}, false
	}
	if now.Sub(entry.lastSeen) > dnsTCPNATIdleTimeout {
		delete(n.entries, key)
		return netip.AddrPort{}, false
	}
	entry.lastSeen = now
	return entry.destination, true
}

func (n *dnsTCPNAT) forget(key netip.AddrPort) {
	n.mu.Lock()
	delete(n.entries, key)
	n.mu.Unlock()
}

// evictLocked removes expired translations first and the oldest remaining one
// when the session is still at capacity. The caller holds n.mu.
func (n *dnsTCPNAT) evictLocked(now time.Time) {
	var oldestKey netip.AddrPort
	var oldestAt time.Time
	for key, entry := range n.entries {
		if now.Sub(entry.lastSeen) > dnsTCPNATIdleTimeout {
			delete(n.entries, key)
			continue
		}
		if oldestAt.IsZero() || entry.lastSeen.Before(oldestAt) {
			oldestKey = key
			oldestAt = entry.lastSeen
		}
	}
	if len(n.entries) >= dnsTCPNATMaxEntries && !oldestAt.IsZero() {
		delete(n.entries, oldestKey)
	}
}

func ipv4TotalLength(packet []byte, ihl int) (int, bool) {
	if ihl < 20 || len(packet) < ihl+20 {
		return 0, false
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl+20 || totalLen > len(packet) {
		return 0, false
	}
	return totalLen, true
}

func fragmentedIPv4(packet []byte) bool {
	if len(packet) < 8 {
		return true
	}
	flagsFrag := binary.BigEndian.Uint16(packet[6:8])
	return flagsFrag&0x1fff != 0 || flagsFrag&0x2000 != 0
}

func ipv4Addr(packet []byte, offset int) netip.Addr {
	return netip.AddrFrom4([4]byte{packet[offset], packet[offset+1], packet[offset+2], packet[offset+3]})
}

// rewriteIPv4Endpoints writes the new source and destination addresses into a
// copy of the packet and recomputes the IPv4 and TCP checksums over the new
// pseudo-header. Trailing bytes beyond the IP total length are preserved.
func rewriteIPv4Endpoints(packet []byte, ihl, totalLen int, src, dst netip.Addr) ([]byte, bool) {
	if totalLen < ihl+20 || totalLen > len(packet) {
		return nil, false
	}
	if !src.Is4() || !dst.Is4() {
		return nil, false
	}
	out := make([]byte, len(packet))
	copy(out, packet)

	srcBytes := src.As4()
	dstBytes := dst.As4()
	copy(out[12:16], srcBytes[:])
	copy(out[16:20], dstBytes[:])

	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:12], calculateChecksum(out[:ihl]))

	segment := out[ihl:totalLen]
	segment[16], segment[17] = 0, 0
	binary.BigEndian.PutUint16(segment[16:18], tcpChecksum(srcBytes, dstBytes, segment))
	return out, true
}

// tcpChecksum computes the TCP checksum over the IPv4 pseudo-header and the TCP
// segment (whose checksum field must already be zero).
func tcpChecksum(src, dst [4]byte, segment []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += 6 // TCP protocol number
	// #nosec G115 -- segment length is bounded by the IPv4 total length (<= 65535).
	sum += uint32(len(segment))
	for i := 0; i+1 < len(segment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i : i+2]))
	}
	if len(segment)%2 != 0 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
