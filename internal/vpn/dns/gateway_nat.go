package gatewaydns

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Intercepted TCP DNS needs more than an address rewrite: the gateway's
// netstack terminates connections on the gateway address and identifies a
// connection by both endpoints. Two original client connections may legally
// share the client address and port while addressing different resolvers, so a
// destination-only rewrite would collapse them onto one internal connection and
// one reply would appear from the wrong resolver.
//
// Every intercepted TCP DNS connection therefore receives its own internal
// source port from a small bounded range. The netstack sees a distinct
// connection for every original client/resolver tuple, and a reply is
// reverse-mapped from the internal port back to exactly the tuple that produced
// it. The table is per session, capped by dnsTCPNATMaxEntries and expired by
// dnsTCPNATIdleTimeout; a live connection is never overwritten by another
// connection's translation.

const (
	// dnsTCPNATMaxEntries bounds the per-session TCP DNS translations that
	// interception retains. One entry is one original client/resolver
	// connection; a client that opens more concurrent connections ages the
	// oldest entries out instead of growing the session's state without
	// bound.
	dnsTCPNATMaxEntries = 256

	// dnsTCPNATIdleTimeout is how long an idle translation is retained. TCP
	// DNS connections are short-lived; an entry older than this is evicted on
	// the next translation that needs room and ignored on lookup, so a stale
	// translation can never rewrite an unrelated later reply.
	dnsTCPNATIdleTimeout = 60 * time.Second

	// dnsTCPNATTranslatedPortBase is the first internal source port allocated
	// for an intercepted TCP DNS connection.
	dnsTCPNATTranslatedPortBase = 20000

	// dnsTCPNATTranslatedPortSpan is the size of the internal port range. It
	// must equal dnsTCPNATMaxEntries: a distinct internal connection identity
	// for every live translation needs one unique port per entry.
	dnsTCPNATTranslatedPortSpan = dnsTCPNATMaxEntries
)

// dnsTCPNATKey is the original connection tuple a translation stands for. The
// resolver is part of the key because the same client endpoint may address
// several resolvers at the same time.
type dnsTCPNATKey struct {
	client   netip.AddrPort
	resolver netip.AddrPort
}

type dnsTCPNATTranslation struct {
	key      dnsTCPNATKey
	lastSeen time.Time
}

type dnsTCPNAT struct {
	mu sync.Mutex
	// byInternal maps the internal source port the netstack sees to the
	// original tuple it represents.
	byInternal map[uint16]*dnsTCPNATTranslation
	// byOriginal maps an original tuple to its internal port, so every packet
	// of one connection reuses the same internal identity.
	byOriginal map[dnsTCPNATKey]uint16
	// nextPort rotates the allocation cursor so freed ports are reused fairly.
	nextPort int
}

// outbound rewrites an intercepted TCP DNS packet so the gateway netstack
// terminates it on the gateway address with a connection identity unique to the
// original client/resolver tuple. It reports false for a packet that cannot be
// translated safely (fragmented or malformed), which the caller must drop rather
// than deliver to the wrong destination.
func (n *dnsTCPNAT) outbound(packet []byte, ihl int, gateway netip.AddrPort, now time.Time) ([]byte, bool) {
	if ihl < 20 || len(packet) < ihl+20 {
		return nil, false
	}
	totalLen, ok := ipv4TotalLength(packet, ihl)
	if !ok || fragmentedIPv4(packet) {
		return nil, false
	}
	key := dnsTCPNATKey{
		client:   netip.AddrPortFrom(ipv4Addr(packet, 12), binary.BigEndian.Uint16(packet[ihl:ihl+2])),
		resolver: netip.AddrPortFrom(ipv4Addr(packet, 16), binary.BigEndian.Uint16(packet[ihl+2:ihl+4])),
	}
	internalPort, ok := n.internalPort(key, now)
	if !ok {
		return nil, false
	}
	return rewriteTCPEndpoints(packet, ihl, totalLen,
		key.client.Addr(), internalPort,
		gateway.Addr(), gateway.Port())
}

// inbound rewrites a reply emitted by the gateway netstack back to the exact
// client/resolver tuple its internal connection represents. A packet that is not
// a TCP reply from the gateway, or whose translation expired, is returned
// unchanged; a translation that cannot be applied drops the packet.
func (n *dnsTCPNAT) inbound(packet []byte, gateway netip.AddrPort, now time.Time) ([]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return packet, true
	}
	ihl := int(packet[0]&0x0f) * 4
	totalLen, ok := ipv4TotalLength(packet, ihl)
	if !ok || packet[9] != 6 || fragmentedIPv4(packet) {
		return packet, true
	}
	if ipv4Addr(packet, 12) != gateway.Addr() || binary.BigEndian.Uint16(packet[ihl:ihl+2]) != gateway.Port() {
		return packet, true
	}

	internalPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	key, ok := n.original(internalPort, now)
	if !ok {
		return packet, true
	}
	return rewriteTCPEndpoints(packet, ihl, totalLen,
		key.resolver.Addr(), key.resolver.Port(),
		key.client.Addr(), key.client.Port())
}

// internalPort returns the internal port reserved for an original tuple,
// allocating one when the tuple is new. A live sibling translation is never
// overwritten: when the table is at capacity the oldest entry is evicted first
// and the caller keeps every live tuple distinct up to that bound.
func (n *dnsTCPNAT) internalPort(key dnsTCPNATKey, now time.Time) (uint16, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.byInternal == nil {
		n.byInternal = make(map[uint16]*dnsTCPNATTranslation, 8)
		n.byOriginal = make(map[dnsTCPNATKey]uint16, 8)
	}
	if port, ok := n.byOriginal[key]; ok {
		if entry := n.byInternal[port]; entry != nil && now.Sub(entry.lastSeen) <= dnsTCPNATIdleTimeout {
			entry.lastSeen = now
			return port, true
		}
		n.dropLocked(port)
	}
	if len(n.byInternal) >= dnsTCPNATMaxEntries {
		n.evictLocked(now)
	}
	port, ok := n.allocateLocked()
	if !ok {
		return 0, false
	}
	n.byInternal[port] = &dnsTCPNATTranslation{key: key, lastSeen: now}
	n.byOriginal[key] = port
	return port, true
}

// original resolves an internal port back to its original tuple.
func (n *dnsTCPNAT) original(port uint16, now time.Time) (dnsTCPNATKey, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	entry := n.byInternal[port]
	if entry == nil {
		return dnsTCPNATKey{}, false
	}
	if now.Sub(entry.lastSeen) > dnsTCPNATIdleTimeout {
		n.dropLocked(port)
		return dnsTCPNATKey{}, false
	}
	entry.lastSeen = now
	return entry.key, true
}

// allocateLocked reserves a port that no live translation uses. The caller holds
// n.mu and has ensured the table has room.
func (n *dnsTCPNAT) allocateLocked() (uint16, bool) {
	for i := 0; i < dnsTCPNATTranslatedPortSpan; i++ {
		port := uint16(dnsTCPNATTranslatedPortBase + (n.nextPort+i)%dnsTCPNATTranslatedPortSpan)
		if _, used := n.byInternal[port]; !used {
			n.nextPort = (n.nextPort + i + 1) % dnsTCPNATTranslatedPortSpan
			return port, true
		}
	}
	return 0, false
}

// dropLocked removes one translation and its reverse entry. The caller holds
// n.mu.
func (n *dnsTCPNAT) dropLocked(port uint16) {
	entry := n.byInternal[port]
	if entry == nil {
		return
	}
	if current, ok := n.byOriginal[entry.key]; ok && current == port {
		delete(n.byOriginal, entry.key)
	}
	delete(n.byInternal, port)
}

// evictLocked removes expired translations first and the oldest remaining one
// when the session is still at capacity. The caller holds n.mu.
func (n *dnsTCPNAT) evictLocked(now time.Time) {
	var oldestPort uint16
	var oldestAt time.Time
	for port, entry := range n.byInternal {
		if now.Sub(entry.lastSeen) > dnsTCPNATIdleTimeout {
			n.dropLocked(port)
			continue
		}
		if oldestAt.IsZero() || entry.lastSeen.Before(oldestAt) {
			oldestPort = port
			oldestAt = entry.lastSeen
		}
	}
	if len(n.byInternal) >= dnsTCPNATMaxEntries && !oldestAt.IsZero() {
		n.dropLocked(oldestPort)
	}
}

// size reports the number of retained translations, for bounded-state tests.
func (n *dnsTCPNAT) size() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.byInternal)
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

// rewriteTCPEndpoints writes new addresses and ports into a copy of the packet
// and recomputes the IPv4 and TCP checksums over the new pseudo-header. Trailing
// bytes beyond the IP total length are preserved.
func rewriteTCPEndpoints(packet []byte, ihl, totalLen int, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16) ([]byte, bool) {
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
	binary.BigEndian.PutUint16(out[ihl:ihl+2], srcPort)
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], dstPort)

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
