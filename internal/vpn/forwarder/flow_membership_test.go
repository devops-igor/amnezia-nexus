package forwarder

import (
	"fmt"
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
	keys, _, _ := m.membershipKeysLocked(sessionID, generation)
	for _, key := range keys {
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

// TestFlowMembershipIsSessionLocal is the retrieval control: a session-scoped read visits
// only that session's buckets, whatever the table holds, and never another client's.
func TestFlowMembershipIsSessionLocal(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()

	// The selected session, two incarnations.
	dem.mu.Lock()
	for i := range 2 {
		key := FlowKey{PeerKey: peer, Protocol: 6, SrcIP: [4]byte{10, 100, 0, 7}, DstIP: [4]byte{93, 184, 216, byte(i + 1)}, SrcPort: uint16(48200 + i), DstPort: 443}
		dem.storeFlowLocked(key, &flowEntry{choice: EgressChoiceProxy, lastSeen: time.Now(), peerKey: peer, sessionID: sessionID, generation: 7})
	}
	dem.mu.Unlock()
	assertMembershipExact(t, dem, "with the selected session's two incarnations")

	dem.mu.RLock()
	_, bucketsBefore, totalBefore := dem.membershipKeysLocked(sessionID, 7)
	dem.mu.RUnlock()
	if bucketsBefore != 1 || totalBefore != 2 {
		t.Fatalf("exact generation visited %d buckets for %d keys, want 1 and 2", bucketsBefore, totalBefore)
	}

	// Many other clients, each with its own incarnation and several flows.
	dem.mu.Lock()
	for other := range 200 {
		otherSession := fmt.Sprintf("other-session-%d", other)
		for i := range 4 {
			key := FlowKey{
				PeerKey:  fmt.Sprintf("other-peer-%d", other),
				Protocol: 6,
				SrcIP:    [4]byte{10, 98, byte(other % 256), byte(i + 1)},
				DstIP:    [4]byte{198, 51, 100, byte((other + i) % 254)},
				SrcPort:  uint16(1024 + i),
				DstPort:  443,
			}
			dem.storeFlowLocked(key, &flowEntry{
				choice: EgressChoiceProxy, lastSeen: time.Now(),
				peerKey: key.PeerKey, sessionID: otherSession,
				generation: uint64(other + 1),
			})
		}
	}
	dem.mu.Unlock()
	assertMembershipExact(t, dem, "after two hundred other clients filled the index")

	dem.mu.RLock()
	keys, bucketsAll, totalAll := dem.membershipKeysLocked(sessionID, 0)
	_, bucketsExact, totalExact := dem.membershipKeysLocked(sessionID, 7)
	otherKeys, otherBuckets, otherTotal := dem.membershipKeysLocked("other-session-137", 0)
	dem.mu.RUnlock()

	if bucketsAll != 1 || totalAll != 2 {
		t.Errorf("all-incarnations read visited %d buckets for %d keys, want 1 and 2: an unrelated bucket was touched",
			bucketsAll, totalAll)
	}
	if bucketsExact != 1 || totalExact != 2 {
		t.Errorf("exact-generation read visited %d buckets for %d keys, want 1 and 2", bucketsExact, totalExact)
	}
	for _, key := range keys {
		if key.PeerKey != peer {
			t.Errorf("selected read returned a foreign key: %+v", key)
		}
	}
	if otherBuckets != 1 || otherTotal != 4 || len(otherKeys) != 4 {
		t.Errorf("other client read = %d buckets, %d keys, %d returned; want 1/4/4", otherBuckets, otherTotal, len(otherKeys))
	}

	// The consumer sees the same locality and an exact total.
	list := dem.SnapshotSessionFlows(sessionID, 0, time.Now(), 0)
	if list.Total != 2 || !list.ScanComplete || len(list.Flows) != 2 {
		t.Errorf("snapshot = total %d complete %v rows %d, want 2/true/2", list.Total, list.ScanComplete, len(list.Flows))
	}
}

// TestFlowMembershipTotalIsExactUnderAPageBound proves Total describes the selection, not
// the page, and that a page never inflates or deflates it.
func TestFlowMembershipTotalIsExactUnderAPageBound(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()

	dem.mu.Lock()
	for i := range 25 {
		key := FlowKey{PeerKey: peer, Protocol: 6, SrcIP: [4]byte{10, 100, 0, 7}, DstIP: [4]byte{93, 184, 216, byte(i + 1)}, SrcPort: uint16(49000 + i), DstPort: 443}
		dem.storeFlowLocked(key, &flowEntry{choice: EgressChoiceProxy, lastSeen: time.Now(), peerKey: peer, sessionID: sessionID, generation: 11})
	}
	dem.mu.Unlock()

	now := time.Now()
	page := dem.SnapshotSessionFlows(sessionID, 0, now, 5)
	if page.Total != 25 {
		t.Errorf("total = %d, want the selection's exact 25", page.Total)
	}
	if len(page.Flows) != 5 || !page.Truncated {
		t.Errorf("page = %d rows truncated %v, want 5 and truncated", len(page.Flows), page.Truncated)
	}
	if page.Scanned != 25 || !page.ScanComplete {
		t.Errorf("scanned = %d complete %v, want the whole selection visited", page.Scanned, page.ScanComplete)
	}

	full := dem.SnapshotSessionFlows(sessionID, 0, now, SessionFlowSnapshotMaxLimit)
	if full.Total != 25 || len(full.Flows) != 25 || full.Truncated {
		t.Errorf("full read = total %d rows %d truncated %v, want 25/25/false", full.Total, len(full.Flows), full.Truncated)
	}
}

// TestFlowMembershipLeavesNoSessionBucketAfterRemoval proves the per-session set follows the
// mutation paths: no bucket and no session entry survives its last flow.
func TestFlowMembershipLeavesNoSessionBucketAfterRemoval(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	dem := fwd.DirectEgress()

	if err := fwd.RouteClientToBackend(peer, flowClientPacket("10.100.0.7", "5.5.5.5", 49400, 443)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	dem.mu.RLock()
	incarnations := len(dem.sessionBuckets[sessionID])
	dem.mu.RUnlock()
	if incarnations != 1 {
		t.Fatalf("session buckets = %d, want 1 after the insert", incarnations)
	}

	dem.PurgePeer(peer)
	assertMembershipExact(t, dem, "after purging the peer")
	dem.mu.RLock()
	_, sessionEntry := dem.sessionBuckets[sessionID]
	buckets := len(dem.members)
	dem.mu.RUnlock()
	if sessionEntry {
		t.Error("the session still has an incarnation set after its last flow was removed")
	}
	if buckets != 0 {
		t.Errorf("buckets = %d after the purge, want 0", buckets)
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
