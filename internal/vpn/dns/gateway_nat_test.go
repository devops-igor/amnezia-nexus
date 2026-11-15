package gatewaydns

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// natTestGateway is the endpoint the gateway netstack answers every intercepted
// TCP DNS connection from.
var natTestGateway = netip.MustParseAddrPort("10.8.0.1:53")

// natTestTuple builds a distinct original client/resolver tuple per index. The
// client endpoint varies so a single test can drive more tuples than the port
// space of one client address allows.
func natTestTuple(i int) dnsTCPNATKey {
	return dnsTCPNATKey{
		client: netip.AddrPortFrom(
			// #nosec G115 -- every component is masked to one octet.
			netip.AddrFrom4([4]byte{10, byte(1 + i/65536), byte((i / 256) % 256), byte(i % 256)}),
			40000),
		resolver: netip.MustParseAddrPort("94.140.14.14:53"),
	}
}

// natFillLive allocates n distinct live translations and returns their tuples in
// allocation order.
func natFillLive(t *testing.T, nat *dnsTCPNAT, n int, now time.Time) []dnsTCPNATKey {
	t.Helper()
	tuples := make([]dnsTCPNATKey, 0, n)
	for i := 0; i < n; i++ {
		key := natTestTuple(i)
		if _, ok := nat.internalPort(key, now); !ok {
			t.Fatalf("live translation %d of %d could not be allocated", i, n)
		}
		tuples = append(tuples, key)
	}
	return tuples
}

// natPortOf reports the internal port an original tuple currently holds.
func natPortOf(t *testing.T, nat *dnsTCPNAT, key dnsTCPNATKey) (uint16, bool) {
	t.Helper()
	nat.mu.Lock()
	defer nat.mu.Unlock()
	port, ok := nat.byOriginal[key]
	return port, ok
}

// natEndpoints decodes the endpoints of a minimal IPv4 TCP packet built by
// buildIPv4TCPPacket, whose header length is always 20 bytes.
func natEndpoints(packet []byte) (src, dst netip.AddrPort) {
	return netip.AddrPortFrom(ipv4Addr(packet, 12), binary.BigEndian.Uint16(packet[20:22])),
		netip.AddrPortFrom(ipv4Addr(packet, 16), binary.BigEndian.Uint16(packet[22:24]))
}

// TestDNSTCPNAT_NonReplyPacketsPassThroughUnchanged pins the other half of the
// inbound contract: only a TCP segment emitted by the gateway endpoint is
// subject to translation, and everything else is forwarded exactly as the
// netstack produced it.
func TestDNSTCPNAT_NonReplyPacketsPassThroughUnchanged(t *testing.T) {
	now := time.Now()
	var nat dnsTCPNAT
	key := natTestTuple(0)
	if _, ok := nat.internalPort(key, now); !ok {
		t.Fatal("could not allocate a translation")
	}
	port, _ := natPortOf(t, &nat, key)

	cases := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "udp segment from the gateway",
			packet: buildIPv4UDPPacket(natTestGateway.Addr(), natTestGateway.Port(), key.client.Addr(), port, []byte{1, 2, 3}),
		},
		{
			name:   "fragmented tcp segment",
			packet: buildIPv4TCPPacket(natTestGateway.Addr(), natTestGateway.Port(), key.client.Addr(), port, true),
		},
		{
			name:   "tcp segment from another source",
			packet: buildIPv4TCPPacket(netip.MustParseAddr("10.9.9.9"), 53, key.client.Addr(), port, false),
		},
		{
			name:   "truncated packet",
			packet: []byte{0x45, 0x00, 0x00},
		},
		{
			name:   "not ipv4",
			packet: append([]byte{0x65}, make([]byte, 39)...),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, keep := nat.inbound(tc.packet, natTestGateway, now)
			if !keep {
				t.Fatalf("%s was dropped; only a TCP reply from the gateway is subject to translation", tc.name)
			}
			if !bytes.Equal(got, tc.packet) {
				t.Fatalf("%s was modified", tc.name)
			}
		})
	}
}

// TestDNSTCPNAT_EvictedPortIsNotReused is the regression for the reused-port
// defect: at capacity a new tuple forces an eviction, and the identity it
// receives must not be one any earlier translation ever held. Dropping a
// translation cannot terminate the connection the gateway netstack still holds
// for it, so that connection may emit a reply on its port at any later time.
func TestDNSTCPNAT_EvictedPortIsNotReused(t *testing.T) {
	now := time.Now()
	var nat dnsTCPNAT
	tuples := natFillLive(t, &nat, dnsTCPNATMaxEntries, now)
	if size := nat.size(); size != dnsTCPNATMaxEntries {
		t.Fatalf("table size = %d, want %d", size, dnsTCPNATMaxEntries)
	}
	issued := make(map[uint16]dnsTCPNATKey, dnsTCPNATMaxEntries+1)
	for _, key := range tuples {
		port, ok := natPortOf(t, &nat, key)
		if !ok {
			t.Fatalf("filled tuple %s holds no translation", key.client)
		}
		issued[port] = key
	}

	newcomer := dnsTCPNATKey{
		client:   netip.MustParseAddrPort("10.10.0.7:55555"),
		resolver: netip.MustParseAddrPort("94.140.15.15:53"),
	}
	newPort, ok := nat.internalPort(newcomer, now.Add(time.Second))
	if !ok {
		t.Fatal("newcomer refused although the session still holds unused identities")
	}
	if holder, reused := issued[newPort]; reused {
		t.Fatalf("newcomer %s was issued internal port %d, which an earlier translation for %s still owns: an internal port must never be reused while its previous connection can emit",
			newcomer.client, newPort, holder.client)
	}
	if size := nat.size(); size != dnsTCPNATMaxEntries {
		t.Fatalf("table size after eviction = %d, want %d", size, dnsTCPNATMaxEntries)
	}
}

// TestDNSTCPNAT_DelayedReplyFromEvictedTupleIsNotMisdelivered fills the table,
// forces an eviction, and feeds the reply the evicted connection can still emit.
// Such a reply must be dropped or stay confined to the tuple that produced it;
// it must never reach the tuple that inherited the table slot.
func TestDNSTCPNAT_DelayedReplyFromEvictedTupleIsNotMisdelivered(t *testing.T) {
	now := time.Now()
	var nat dnsTCPNAT
	tuples := natFillLive(t, &nat, dnsTCPNATMaxEntries, now)
	before := make(map[dnsTCPNATKey]uint16, len(tuples))
	for _, key := range tuples {
		port, ok := natPortOf(t, &nat, key)
		if !ok {
			t.Fatalf("filled tuple %s holds no translation", key.client)
		}
		before[key] = port
	}

	newcomer := dnsTCPNATKey{
		client:   netip.MustParseAddrPort("10.10.0.7:55555"),
		resolver: netip.MustParseAddrPort("94.140.15.15:53"),
	}
	newPort, ok := nat.internalPort(newcomer, now.Add(time.Second))
	if !ok {
		t.Fatal("newcomer refused although only live identities were occupied; the capacity case must still retire the oldest translation")
	}

	var evictedKey dnsTCPNATKey
	var evictedPort uint16
	for key, port := range before {
		if _, still := natPortOf(t, &nat, key); !still {
			if evictedPort != 0 {
				t.Fatalf("expected one retired translation at capacity, found a second (%s)", key.client)
			}
			evictedKey, evictedPort = key, port
		}
	}
	if evictedPort == 0 {
		t.Fatalf("no translation was retired at capacity (table size %d)", nat.size())
	}
	t.Logf("evicted tuple client=%s resolver=%s internal_port=%d", evictedKey.client, evictedKey.resolver, evictedPort)
	t.Logf("newcomer tuple client=%s resolver=%s internal_port=%d", newcomer.client, newcomer.resolver, newPort)
	t.Logf("evicted port reused by the newcomer: %v", evictedPort == newPort)

	// Exactly the segment the evicted connection still emits: from the gateway
	// resolver endpoint to that client on the internal port it used.
	stale := buildIPv4TCPPacket(natTestGateway.Addr(), natTestGateway.Port(),
		evictedKey.client.Addr(), evictedPort, false)
	rewritten, keep := nat.inbound(stale, natTestGateway, now.Add(time.Second))
	if !keep {
		t.Logf("stale reply dropped: internal port %d no longer holds a live translation", evictedPort)
	} else {
		src, dst := natEndpoints(rewritten)
		t.Logf("stale reply kept and rewritten to src=%s dst=%s", src, dst)
		switch {
		case dst == evictedKey.client && src == evictedKey.resolver:
			t.Logf("stale reply confined to the tuple that produced it")
		case dst == newcomer.client || src == newcomer.resolver:
			t.Fatalf("misdelivered: reply from the retired tuple (client %s, internal port %d) reached the newcomer (client %s, resolver %s) as %s -> %s",
				evictedKey.client, evictedPort, newcomer.client, newcomer.resolver, src, dst)
		default:
			t.Fatalf("reply from the retired tuple (client %s, internal port %d) was rewritten to an unrelated tuple %s -> %s",
				evictedKey.client, evictedPort, src, dst)
		}
	}

	// The live translation must keep mapping exactly, in both directions.
	reply := buildIPv4TCPPacket(natTestGateway.Addr(), natTestGateway.Port(),
		newcomer.client.Addr(), newPort, false)
	back, ok := nat.inbound(reply, natTestGateway, now.Add(time.Second))
	if !ok {
		t.Fatal("reply of the live newcomer translation was dropped")
	}
	if src, dst := natEndpoints(back); src != newcomer.resolver || dst != newcomer.client {
		t.Fatalf("live newcomer reply rewritten to %s -> %s, want %s -> %s",
			src, dst, newcomer.resolver, newcomer.client)
	}
	if size := nat.size(); size > dnsTCPNATMaxEntries {
		t.Fatalf("translation table grew past its bound: %d", size)
	}
}

// TestDNSTCPNAT_LiveCapacityPressureKeepsIdentitiesDistinct is the companion
// case for a table full of live entries: every accepted new tuple must receive
// an identity no earlier tuple held, and the table must never exceed its bound
// however many tuples arrive.
func TestDNSTCPNAT_LiveCapacityPressureKeepsIdentitiesDistinct(t *testing.T) {
	now := time.Now()
	var nat dnsTCPNAT
	issued := make(map[uint16]dnsTCPNATKey, 2*dnsTCPNATMaxEntries)
	for _, key := range natFillLive(t, &nat, dnsTCPNATMaxEntries, now) {
		port, ok := natPortOf(t, &nat, key)
		if !ok {
			t.Fatalf("filled tuple %s holds no translation", key.client)
		}
		issued[port] = key
	}

	for i := 0; i < 64; i++ {
		key := dnsTCPNATKey{
			// #nosec G115 -- the offset is bounded by the loop above.
			client:   netip.AddrPortFrom(netip.MustParseAddr("10.10.0.7"), uint16(55555+i)),
			resolver: netip.MustParseAddrPort("94.140.15.15:53"),
		}
		port, ok := nat.internalPort(key, now.Add(time.Duration(i+1)*time.Second))
		if !ok {
			t.Fatalf("new tuple %d refused although the session still holds unused identities", i)
		}
		if holder, reused := issued[port]; reused {
			t.Fatalf("new tuple %d was issued internal port %d, which an earlier translation for %s still owns", i, port, holder.client)
		}
		issued[port] = key
		if size := nat.size(); size > dnsTCPNATMaxEntries {
			t.Fatalf("translation table grew past its bound at tuple %d: %d", i, size)
		}
		reply := buildIPv4TCPPacket(natTestGateway.Addr(), natTestGateway.Port(),
			key.client.Addr(), port, false)
		back, ok := nat.inbound(reply, natTestGateway, now.Add(time.Duration(i+1)*time.Second))
		if !ok {
			t.Fatalf("reply of new tuple %d was dropped", i)
		}
		if src, dst := natEndpoints(back); src != key.resolver || dst != key.client {
			t.Fatalf("reply of new tuple %d rewritten to %s -> %s, want %s -> %s",
				i, src, dst, key.resolver, key.client)
		}
	}
}

// TestDNSTCPNAT_IdentityExhaustionFailsClosed drives the session's identity
// space to its end. Once no never-issued identity remains, a new tuple must be
// refused cleanly: dropping the packet is correct, reusing an identity is not.
func TestDNSTCPNAT_IdentityExhaustionFailsClosed(t *testing.T) {
	now := time.Now()
	var nat dnsTCPNAT
	issued := make(map[uint16]int, dnsTCPNATTranslatedPortSpan)
	limit := dnsTCPNATTranslatedPortSpan + 8
	refused := -1
	for i := 0; i < limit; i++ {
		port, ok := nat.internalPort(natTestTuple(i), now)
		if !ok {
			refused = i
			break
		}
		if previous, reused := issued[port]; reused {
			t.Fatalf("internal port %d was issued to tuple %d and again to tuple %d", port, previous, i)
		}
		issued[port] = i
		if size := nat.size(); size > dnsTCPNATMaxEntries {
			t.Fatalf("translation table grew past its bound at allocation %d: %d", i, size)
		}
	}
	if refused < 0 {
		t.Fatalf("identity space was never exhausted after %d allocations: an internal port was reused", limit)
	}
	if refused != dnsTCPNATTranslatedPortSpan {
		t.Fatalf("refused at allocation %d, want %d distinct identities", refused, dnsTCPNATTranslatedPortSpan)
	}
	if size := nat.size(); size != dnsTCPNATMaxEntries {
		t.Fatalf("refused allocation changed the table: size = %d, want %d", size, dnsTCPNATMaxEntries)
	}

	// The oldest surviving translation keeps its identity and still maps back
	// exactly; an exhausted identity space must not disturb live state.
	oldest, ok := natPortOf(t, &nat, natTestTuple(refused-1))
	if !ok {
		t.Fatal("live translation was lost by the refused allocation")
	}
	reply := buildIPv4TCPPacket(natTestGateway.Addr(), natTestGateway.Port(),
		natTestTuple(refused-1).client.Addr(), oldest, false)
	back, ok := nat.inbound(reply, natTestGateway, now)
	if !ok {
		t.Fatal("reply of a live translation was dropped after a refused allocation")
	}
	if src, dst := natEndpoints(back); src != natTestTuple(refused-1).resolver || dst != natTestTuple(refused-1).client {
		t.Fatalf("reply after refusal rewritten to %s -> %s", src, dst)
	}
}
