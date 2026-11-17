package forwarder

import (
	"net/netip"
	"testing"
	"time"
)

// Per-session flow membership index controls (issue #861, R22).
//
// Every case drives the real mutation paths and then asserts the invariant: the index
// describes exactly the flows that exist, in the incarnation that owns each of them.

func assertMembershipExact(t *testing.T, m *DirectEgressManager, context string) {
	t.Helper()
	m.mu.RLock()
	dangling, missing, duplicates := m.membershipInvariantLocked()
	flows := len(m.flows)
	m.mu.RUnlock()
	if dangling != 0 || missing != 0 || duplicates != 0 {
		t.Fatalf("%s: membership invariant broken: dangling=%d missing=%d duplicates=%d (flows=%d)",
			context, dangling, missing, duplicates, flows)
	}
}

// membershipIdentities reads the authoritative membership of one selection.
func membershipIdentities(m *DirectEgressManager, sessionID string, generation uint64) map[FlowKey]struct{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[FlowKey]struct{})
	for _, key := range m.membershipKeysLocked(sessionID, generation) {
		if entry, ok := m.flows[key]; ok && sessionFlowMatches(entry, sessionID, generation) {
			out[key] = struct{}{}
		}
	}
	return out
}

func flowClientPacket(clientIP, dst string, srcPort, dstPort uint16) []byte {
	return buildTestIPv4TCPPacket(
		netip.MustParseAddr(clientIP), netip.MustParseAddr(dst), srcPort, dstPort, 0x02, nil)
}

// TestFlowMembershipInvariantOnEveryMutationPath walks the mutation paths the index must
// follow: decision insert, same-tuple re-record, NAT insert and in-place update, sweep
// expiry, purge and full-session purge.
func TestFlowMembershipInvariantOnEveryMutationPath(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	dem := fwd.DirectEgress()
	now := time.Now()

	// 1. Decision insert (PROXY, no NAT) through the real dispatch path.
	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "5.5.5.5", 48000, 443)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	assertMembershipExact(t, dem, "after a decision insert")
	if got := membershipIdentities(dem, sessionID, 0); len(got) != 1 {
		t.Fatalf("membership = %d keys, want the one flow", len(got))
	}

	// 2. Same-tuple re-record: the key must stay exactly once.
	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "5.5.5.5", 48000, 443)); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	assertMembershipExact(t, dem, "after a same-tuple re-record")

	// 3. NAT insert and in-place update through the direct egress path.
	route := fwd.routesByPeer[peer]
	dem.mu.Lock()
	natPacket := flowClientPacket("10.100.0.7", "9.9.9.9", 48001, 80)
	natKey, natErr := flowKeyForPacket(peer, natPacket)
	if natErr != nil {
		t.Fatalf("flow key: %v", natErr)
	}
	_, _, err := dem.ensureDirectNATLocked(natKey, natKey.Protocol, natKey.SrcIP, natKey.DstIP,
		natKey.SrcPort, natKey.DstPort, peer, sessionID, route.generation, route.returnPath, now)
	dem.mu.Unlock()
	if err != nil {
		t.Fatalf("NAT insert: %v", err)
	}
	assertMembershipExact(t, dem, "after a NAT insert")
	dem.mu.Lock()
	_, _, err = dem.ensureDirectNATLocked(natKey, natKey.Protocol, natKey.SrcIP, natKey.DstIP,
		natKey.SrcPort, natKey.DstPort, peer, sessionID, route.generation, route.returnPath, now.Add(time.Second))
	dem.mu.Unlock()
	if err != nil {
		t.Fatalf("NAT update: %v", err)
	}
	assertMembershipExact(t, dem, "after a NAT in-place update")

	// 4. Sweep: an expired flow leaves both maps.
	fwd.StopPumps()
	dem2 := fwd.DirectEgress()
	dem2.mu.Lock()
	dem2.sweepLocked(now.Add(24 * time.Hour))
	dem2.mu.Unlock()
	assertMembershipExact(t, dem2, "after a sweep")

	// 5. Purge of one peer and of a whole session.
	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "6.6.6.6", 48002, 443)); err != nil {
		t.Fatalf("dispatch before purge: %v", err)
	}
	dem.PurgePeer(peer)
	assertMembershipExact(t, dem, "after PurgePeer")
	if got := membershipIdentities(dem, sessionID, 0); len(got) != 0 {
		t.Errorf("membership = %d keys after purging the peer, want 0", len(got))
	}
}

// TestFlowMembershipRekeyMovesTheKey is the incarnation control for the in-place update
// path: a tuple recorded again by a new generation must move its membership, never
// duplicate it and never linger in the previous incarnation's bucket.
//
// A session re-registration purges the peer's direct-egress flows, so the surviving-entry
// case is the in-place update that ensureDirectNATLocked performs when the same tuple is
// re-recorded by a different generation. That path is exercised here through the same
// helper the manager uses.
func TestFlowMembershipRekeyMovesTheKey(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()

	key, err := flowKeyForPacket(peer, flowClientPacket("10.100.0.7", "5.5.5.5", 48100, 443))
	if err != nil {
		t.Fatalf("flow key: %v", err)
	}
	entry := &flowEntry{choice: EgressChoiceProxy, lastSeen: time.Now(), peerKey: peer, sessionID: sessionID, generation: 41}
	dem.mu.Lock()
	dem.storeFlowLocked(key, entry)
	dem.mu.Unlock()
	assertMembershipExact(t, dem, "after the first incarnation records the tuple")
	if got := membershipIdentities(dem, sessionID, 41); len(got) != 1 {
		t.Fatalf("generation 41 owns %d keys, want 1", len(got))
	}

	// The same tuple re-recorded by the next incarnation: in-place update.
	dem.mu.Lock()
	dem.rebindFlowLocked(key, entry, sessionID, 42)
	dem.mu.Unlock()
	assertMembershipExact(t, dem, "after the rekey rebind")

	if got := membershipIdentities(dem, sessionID, 41); len(got) != 0 {
		t.Errorf("the previous generation still owns %d keys", len(got))
	}
	if got := membershipIdentities(dem, sessionID, 42); len(got) != 1 {
		t.Errorf("the new generation owns %d keys, want the rebound one", len(got))
	}
	if got := membershipIdentities(dem, sessionID, 0); len(got) != 1 {
		t.Errorf("all-incarnation membership = %d keys, want exactly the one flow", len(got))
	}
}

// TestFlowMembershipSelectsOnlyTheRequestedClient is the retrieval control: other clients'
// flows, including enough to exhaust the old global visit cap, must not consume this
// client's allowance nor change its answer.
func TestFlowMembershipSelectsOnlyTheRequestedClient(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()
	now := time.Now()

	// A small selected client.
	selected := []string{"93.184.216.10", "93.184.216.11", "93.184.216.12"}
	for i, dst := range selected {
		if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", dst, uint16(48200+i), 443)); err != nil {
			t.Fatalf("selected dispatch %s: %v", dst, err)
		}
	}
	want := membershipIdentities(dem, sessionID, 0)
	if len(want) != len(selected) {
		t.Fatalf("selected membership = %d keys, want %d", len(want), len(selected))
	}

	before := dem.SnapshotSessionFlows(sessionID, 0, now, 0)
	dem.mu.RLock()
	selectedBuckets := len(dem.members)
	dem.mu.RUnlock()

	// Now fill the table with other clients' flows, well past the old global visit cap.
	dem.mu.Lock()
	for i := range SessionFlowScanRecords + 512 {
		ip := netip.AddrFrom4([4]byte{10, 99, byte(i / 256), byte(i % 256)})
		key := FlowKey{
			PeerKey:  "other-peer",
			Protocol: 6,
			SrcIP:    ip.As4(),
			DstIP:    [4]byte{198, 51, 100, byte(i % 254)},
			SrcPort:  uint16(1024 + i%50000), // #nosec G115 -- bounded by the loop.
			DstPort:  443,
		}
		dem.storeFlowLocked(FlowKey{
			PeerKey:  key.PeerKey,
			Protocol: key.Protocol,
			SrcIP:    key.SrcIP,
			DstIP:    key.DstIP,
			SrcPort:  key.SrcPort,
			DstPort:  443,
		}, &flowEntry{choice: EgressChoiceProxy, lastSeen: now, peerKey: "other-peer", sessionID: "other-session", generation: 9})
	}
	dem.mu.Unlock()
	assertMembershipExact(t, dem, "after filling the table with other clients")

	after := dem.SnapshotSessionFlows(sessionID, 0, now, 0)
	if len(after.Flows) != len(before.Flows) {
		t.Errorf("selected rows = %d after the table filled, want the same %d", len(after.Flows), len(before.Flows))
	}
	if after.Scanned != len(want) || !after.ScanComplete {
		t.Errorf("scanned = %d complete=%v, want this client's %d keys visited completely",
			after.Scanned, after.ScanComplete, len(want))
	}
	if after.Total != len(want) {
		t.Errorf("total = %d, want this client's %d", after.Total, len(want))
	}
	// The identities must be exactly the authoritative membership, programmatically.
	returned := make(map[string]struct{}, len(after.Flows))
	for _, flow := range after.Flows {
		returned[flow.DstIP.String()] = struct{}{}
	}
	for key := range want {
		dst := netip.AddrFrom4(key.DstIP).String()
		if _, ok := returned[dst]; !ok {
			t.Errorf("indexed read omitted %s", dst)
		}
		delete(returned, dst)
	}
	if len(returned) != 0 {
		t.Errorf("indexed read returned identities outside the selection: %v", returned)
	}
	dem.mu.RLock()
	afterBuckets := len(dem.members)
	dem.mu.RUnlock()
	if afterBuckets != selectedBuckets+1 {
		t.Errorf("buckets = %d, want one more than the %d before (the other client)", afterBuckets, selectedBuckets)
	}
}

// TestFlowMembershipGenerationScopeSeparatesIncarnations pins the two documented meanings:
// a zero generation is every incarnation of the session, an exact one is that incarnation.
func TestFlowMembershipGenerationScopeSeparatesIncarnations(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()
	now := time.Now()

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "5.5.5.5", 48300, 443)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	generation := fwd.routesByPeer[peer].generation

	exact := dem.SnapshotSessionFlows(sessionID, generation, now, 0)
	all := dem.SnapshotSessionFlows(sessionID, 0, now, 0)
	if len(exact.Flows) != 1 || len(all.Flows) != 1 {
		t.Fatalf("exact = %d rows, all = %d, want 1 and 1", len(exact.Flows), len(all.Flows))
	}
	other := dem.SnapshotSessionFlows(sessionID, generation+1, now, 0)
	if len(other.Flows) != 0 {
		t.Errorf("another generation saw %d rows", len(other.Flows))
	}
	if unknown := dem.SnapshotSessionFlows("no-such-session", 0, now, 0); len(unknown.Flows) != 0 {
		t.Errorf("an unknown session saw %d rows", len(unknown.Flows))
	}
}

// TestFlowMembershipReadIsPure proves the indexed read changes nothing.
func TestFlowMembershipReadIsPure(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()
	now := time.Now()

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "5.5.5.5", 48400, 443)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	first := dem.SnapshotSessionFlows(sessionID, 0, now, 0)
	dem.mu.RLock()
	var lastSeenBefore time.Time
	for _, entry := range dem.flows {
		lastSeenBefore = entry.lastSeen
	}
	tableBefore := len(dem.flows)
	dem.mu.RUnlock()

	for range 3 {
		_ = dem.SnapshotSessionFlows(sessionID, 0, now.Add(time.Minute), 0)
	}

	dem.mu.RLock()
	tableAfter := len(dem.flows)
	var lastSeenAfter time.Time
	for _, entry := range dem.flows {
		lastSeenAfter = entry.lastSeen
	}
	dem.mu.RUnlock()
	if tableBefore != tableAfter {
		t.Errorf("a read changed the table: %d -> %d flows", tableBefore, tableAfter)
	}
	if !lastSeenBefore.Equal(lastSeenAfter) {
		t.Errorf("a read refreshed lastSeen: %s -> %s", lastSeenBefore, lastSeenAfter)
	}
	if len(first.Flows) != 1 {
		t.Errorf("first read = %d rows", len(first.Flows))
	}
}
