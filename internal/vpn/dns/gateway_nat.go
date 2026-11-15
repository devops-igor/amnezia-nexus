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
// source port. The netstack sees a distinct connection for every original
// client/resolver tuple, and a reply is reverse-mapped from the internal port
// back to exactly the tuple that produced it.
//
// A translation is a mapping, not the connection itself: dropping one does not
// terminate the TCP connection the gateway netstack still holds, and that
// connection may emit a reply on its port at any later time, however long the
// translation has been gone. An internal port is therefore issued once per
// session and never returned: consumption is monotonic, and a retired
// translation's port stays permanently unassigned, so a delayed reply finds no
// translation and is dropped instead of being rewritten to whichever tuple
// happened to receive the port next. The table is per session, capped by
// dnsTCPNATMaxEntries and expired by dnsTCPNATIdleTimeout; when the session has
// issued every identity it owns, a new connection is refused and its packets
// are dropped rather than given a port an older connection could still use.

const (
	// dnsTCPNATMaxEntries bounds the per-session TCP DNS translations that
	// interception retains. One entry is one original client/resolver
	// connection; a client that opens more concurrent connections ages the
	// oldest entries out instead of growing the session's state without
	// bound.
	dnsTCPNATMaxEntries = 256

	// dnsTCPNATIdleTimeout is how long an idle translation is retained. TCP
	// DNS connections are short-lived; an entry older than this is evicted on
	// the next translation that needs room and ignored on lookup, so an idle
	// translation cannot rewrite an unrelated later reply.
	dnsTCPNATIdleTimeout = 60 * time.Second

	// dnsTCPNATTranslatedPortBase is the first internal source port issued for
	// an intercepted TCP DNS connection.
	dnsTCPNATTranslatedPortBase = 20000

	// dnsTCPNATTranslatedPortSpan is the number of internal identities a
	// session may issue, covering the rest of the port range from
	// dnsTCPNATTranslatedPortBase. It is deliberately far larger than
	// dnsTCPNATMaxEntries: because an identity is never reused, the span is the
	// session's total budget of intercepted TCP DNS connections, not its
	// concurrency bound. Running out is a clean refusal, never a reuse.
	dnsTCPNATTranslatedPortSpan = 1<<16 - dnsTCPNATTranslatedPortBase
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
	// nextIdentity is the monotonic identity cursor: each allocation consumes
	// the next never-issued internal port. A port is never returned to the
	// pool, because a retired translation cannot terminate the netstack
	// connection that held it, and that connection may emit a reply on its port
	// at any later time.
	nextIdentity int
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
// a TCP reply from the gateway is returned unchanged. A TCP reply from the
// gateway whose internal port holds no live translation is dropped: the netstack
// may still emit it for a connection whose translation was retired or expired,
// and the packet carries nothing but that internal port, so delivering it
// unchanged could hand it to an unrelated client socket.
func (n *dnsTCPNAT) inbound(packet []byte, gateway netip.AddrPort, now time.Time) ([]byte, bool) {
	ihl, totalLen, ok := ipv4TCPReply(packet)
	if !ok {
		return packet, true
	}
	if ipv4Addr(packet, 12) != gateway.Addr() || binary.BigEndian.Uint16(packet[ihl:ihl+2]) != gateway.Port() {
		return packet, true
	}

	internalPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	key, ok := n.original(internalPort, now)
	if !ok {
		// No live translation owns this port. It was retired, expired, or never
		// issued, and the connection that held it may still emit; fail closed
		// rather than deliver a packet nobody can be proven to own.
		return nil, false
	}
	return rewriteTCPEndpoints(packet, ihl, totalLen,
		key.resolver.Addr(), key.resolver.Port(),
		key.client.Addr(), key.client.Port())
}

// ipv4TCPReply validates that packet is a complete, unfragmented IPv4 TCP
// segment and returns its IP header length and total length.
func ipv4TCPReply(packet []byte) (ihl, totalLen int, ok bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, 0, false
	}
	ihl = int(packet[0]&0x0f) * 4
	totalLen, ok = ipv4TotalLength(packet, ihl)
	if !ok || packet[9] != 6 || fragmentedIPv4(packet) {
		return 0, 0, false
	}
	return ihl, totalLen, true
}

// internalPort returns the internal port reserved for an original tuple,
// allocating one when the tuple is new. A live sibling translation is never
// overwritten: when the table is at capacity the oldest entry is retired first.
// The identity is claimed before any entry is retired, so an exhausted identity
// space refuses the packet without disturbing the table.
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
	port, ok := n.allocateLocked()
	if !ok {
		return 0, false
	}
	if len(n.byInternal) >= dnsTCPNATMaxEntries {
		n.evictLocked(now)
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

// allocateLocked consumes the next never-issued internal port. The caller holds
// n.mu. Identities are issued monotonically and never reused: a retired
// translation cannot terminate the netstack connection that held its port, so
// that connection may still emit a reply on it. Skipping the port forever is
// what stops such a reply from being rewritten to whichever tuple received the
// port next. Exhaustion is a clean refusal; the caller drops the packet.
func (n *dnsTCPNAT) allocateLocked() (uint16, bool) {
	for n.nextIdentity < dnsTCPNATTranslatedPortSpan {
		// #nosec G115 -- nextIdentity is bounded by the span, so the sum stays
		// within the uint16 port range.
		port := uint16(dnsTCPNATTranslatedPortBase + n.nextIdentity)
		n.nextIdentity++
		if _, used := n.byInternal[port]; used {
			continue
		}
		return port, true
	}
	return 0, false
}

// dropLocked removes one translation and its reverse entry. The port is not
// returned to the allocation pool, so no later connection can inherit it. The
// caller holds n.mu.
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
// when the session is still at capacity. Retiring a translation frees its table
// slot but not its identity: the port stays permanently unassigned so the
// retired connection's late replies cannot reach the tuple that takes the slot.
// The caller holds n.mu.
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
