package vpn

// Regression coverage for issue #424 round 6.
//
// The round 5 divergence test was rejected by the reviewer for a specific
// reason, quoted from the review:
//
//	"it manually changes DesiredPeers/ActualPeers and manually calls
//	 noteDivergenceState() on convergence rather than exercising
//	 reconcileNow()".
//
// That is precisely why finding 1 shipped: the manual-field test exercised
// the bookkeeping function but never the reconciliation pass, so it could not
// observe that the pass only ever calls the function ONCE, from the
// PRE-repair counts. The test below therefore drives reconcileNow, in order,
// through a real divergence, a real repair, and a second real divergence.
//
// The round 5 collision test for forwarder_route_queues shipped for the
// opposite reason: it compared the decoded map length against the
// ALREADY-COLLAPSED status map, so it could only ever agree. The test below
// asserts the decoded length against the number of peers actually registered.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// failingAddPeerDevice refuses every AddPeer while delegating reads and
// removals to the real device. It is how the test makes the durable desired
// set genuinely exceed the upstream actual set without hand-writing any
// status field: production reaches the same state whenever a device refuses
// an install.
type failingAddPeerDevice struct{ real *clientawg.ClientAWGDevice }

func (d failingAddPeerDevice) Status() (clientawg.Status, error) { return d.real.Status() }
func (d failingAddPeerDevice) AddPeer(clientawg.Peer) error {
	return errors.New("injected add failure")
}
func (d failingAddPeerDevice) RemovePeer(key string) error { return d.real.RemovePeer(key) }

// round6Clock is a hand-advanceable clock for the divergence tests. The
// synchronizer stamps DivergenceSince from its injectable time source, so the
// ages under test are exact rather than wall-clock dependent.
type round6Clock struct{ at time.Time }

func (c *round6Clock) now() time.Time          { return c.at.UTC() }
func (c *round6Clock) advance(d time.Duration) { c.at = c.at.Add(d) }
func (c *round6Clock) current() time.Time      { return c.at.UTC() }

// round6PeerSyncFixture repairs newIngressEngineService's half-populated seed
// row and returns a synchronizer with a settled baseline.
//
// The seed row genuinely cannot be resolved, so without the repair the very
// first reconcile reports InvalidRows > 0 and holds peer_sync DEGRADED on its
// own. No assertion is relaxed to accommodate that; the precondition is made
// true instead.
func round6PeerSyncFixture(t *testing.T, db *database.DB, svc *Service) (*peerSynchronizer, *round6Clock, enginePeer, *clientawg.ClientAWGDevice) {
	t.Helper()
	ctx := t.Context()
	peer, _ := newEnginePeer(t, svc, db, "round6-divergence")
	ownerUserID := peerOwnerUserID(t, db, peer.publicKey)

	for _, c := range mustGetConnections(t, db) {
		if _, err := db.DeleteConnection(ctx, c.ID); err != nil {
			t.Fatalf("repair seeded fixture rows: %v", err)
		}
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: ownerUserID, ServerID: 0, Protocol: "awg",
		ClientID: peer.publicKey, ClientParams: map[string]any{"assigned_ip": peer.assignedIP},
	}); err != nil {
		t.Fatalf("restore the engine peer row: %v", err)
	}

	ps, _, portal := newTestPeerSynchronizer(t, svc, db)
	clock := &round6Clock{at: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)}
	ps.setNowFuncForTest(clock.now)
	ps.quiesceNotifyWorker()
	// The REAL device, handed back so a test can restore it after an injected
	// failure window instead of leaving the wrapper installed.
	t.Cleanup(func() { ps.setPortalDeviceForTest(portal) })

	// The FIRST pass installs the peer, so on that pass the pre-repair read
	// legitimately shows a divergence (desired=1, actual=0) that the same
	// pass then repairs. That is the situation finding 1 is about, so the
	// baseline is settled with a SECOND pass: it begins with the counts
	// already equal, so the pre-repair evaluation clears the start and the
	// post-repair evaluation has nothing left to do. This precondition
	// therefore holds with or without the fix, and the test below fails only
	// on the assertion it is actually about.
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("baseline install reconcile: %v", err)
	}
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("baseline settle reconcile: %v", err)
	}
	stats := ps.Status()
	if stats.InvalidRows != 0 {
		t.Fatalf("precondition: the repaired fixture must have no invalid rows, got %+v", stats)
	}
	if stats.DesiredPeers != stats.ActualPeers {
		t.Fatalf("precondition: the baseline must be converged, got %+v", stats)
	}
	if !stats.DivergenceSince.IsZero() {
		t.Fatalf("precondition: a converged baseline must record no divergence start, got %v",
			stats.DivergenceSince)
	}
	return ps, clock, peer, portal
}

// TestReconcileNowClearsDivergenceStartAfterItRepairsThePeer is the finding-1
// regression, driven through the REAL reconciliation pass.
//
// The sequence is the reviewer's, in production order:
//
//	T0   baseline: desired=1 actual=1, converged
//	T1   a second peer is created durably and the device refuses the install:
//	     desired=2 actual=1. DivergenceSince = T1.
//	T2   hours later the device accepts: the pass installs the peer, so
//	     verifyPeers re-reads actual=2 and the pass SUCCEEDS.
//	     DivergenceSince must now be CLEAR. Under the pre-change code it was
//	     never re-evaluated after the pre-repair evaluation, so T1 survived a
//	     divergence that no longer existed.
//	T3   a THIRD peer is created and again refused. The new incident's age is
//	     measured from T3, not from T1. Under the pre-change code the reported
//	     age would be the two hours between T1 and T3, and the very first
//	     sample would already report DEGRADED for an incident seconds old.
func TestReconcileNowClearsDivergenceStartAfterItRepairsThePeer(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, clock, _, portal := round6PeerSyncFixture(t, db, svc)

	// The clock moves off the baseline instant first, so a stale start
	// inherited from the baseline can never be mistaken for the T1 stamp.
	clock.advance(time.Minute)

	// T1: a genuine divergence through a real reconcile. The durable desired
	// set grows by one and the device refuses the install, which is exactly
	// how the mismatch arises in production.
	// The refusing device is installed BEFORE the peer is created. Order
	// matters: the notify worker reconciles in the background, so a device
	// swapped in after the durable row appears can lose the race and the real
	// device installs the peer, leaving nothing for this test to observe.
	ps.setPortalDeviceForTest(failingAddPeerDevice{real: portal})
	late, _ := newEnginePeer(t, svc, db, "round6-late-peer")
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err == nil {
		t.Fatal("expected the reconcile to report the injected add failure")
	}
	diverged := ps.Status()
	if diverged.DesiredPeers != 2 || diverged.ActualPeers != 1 {
		t.Fatalf("precondition: the reconcile must have produced a real 2/1 divergence, got %+v", diverged)
	}
	if !diverged.DivergenceSince.Equal(clock.current()) {
		t.Fatalf("the divergence must start at the injected clock, got %v want %v",
			diverged.DivergenceSince, clock.current())
	}

	// T2: hours later the device works again. The SAME reconcile installs the
	// missing peer and its post-repair verify read moves actual to 2.
	clock.advance(2 * time.Hour)
	ps.quiesceNotifyWorker()
	ps.setPortalDeviceForTest(portal)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("repair reconcile must SUCCEED, got %v", err)
	}
	repaired := ps.Status()
	if repaired.DesiredPeers != repaired.ActualPeers {
		t.Fatalf("the repair reconcile must leave the counts converged, got %+v", repaired)
	}
	if repaired.LastError != "" {
		t.Fatalf("the repair reconcile must succeed cleanly, got LastError %q", repaired.LastError)
	}
	if !repaired.DivergenceSince.IsZero() {
		t.Fatalf("a reconcile that actually repaired the peer must CLEAR the divergence start, got %v",
			repaired.DivergenceSince)
	}
	// The repaired peer really is upstream. Without this the assertions above
	// could pass on a reconciler that simply forgot the peer everywhere.
	ps.quiesceNotifyWorker()
	upstream, err := ps.portal.Status()
	if err != nil {
		t.Fatalf("upstream status: %v", err)
	}
	if len(upstream.Peers) != 2 {
		t.Fatalf("the repaired peer must be installed upstream, got %d peers", len(upstream.Peers))
	}
	found := false
	for _, p := range upstream.Peers {
		if p.PublicKey == late.publicKey {
			found = true
		}
	}
	if !found {
		t.Fatal("the late peer's key is not installed upstream")
	}

	// T3: a NEW, unrelated divergence hours later. Its reported age must be
	// small. This is the assertion that fails against the pre-change code,
	// where the age inherited T1 and read as hours.
	clock.advance(3 * time.Hour)
	ps.setPortalDeviceForTest(failingAddPeerDevice{real: portal})
	newer, _ := newEnginePeer(t, svc, db, "round6-newer-peer")
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err == nil {
		t.Fatal("expected the second injected add failure")
	}
	regressed := ps.Status()
	if regressed.DesiredPeers != 3 || regressed.ActualPeers != 2 {
		t.Fatalf("precondition: the second divergence must be 3/2, got %+v", regressed)
	}
	if !regressed.DivergenceSince.Equal(clock.current()) {
		t.Fatalf("the new divergence must start from scratch at %v, got %v (it inherited a stale start)",
			clock.current(), regressed.DivergenceSince)
	}
	if age := clock.current().Sub(regressed.DivergenceSince); age != 0 {
		t.Fatalf("the new incident is %s old, want 0s", age)
	}
	// And through the real diagnostics consumer, not just the raw field: a
	// seconds-old divergence must emit no condition at all.
	if c := peerSyncDivergenceCondition(&regressed, clock.current()); c != nil {
		t.Fatalf("a 0s divergence must emit no condition, got %s: %q", c.Severity, c.Message)
	}
	if newer.assignedIP == "" {
		t.Fatal("fixture did not mint the second peer")
	}
}

// TestDivergenceStartSurvivesReconcileThatDidNotConvergeTheCounts is the
// negative control for the same change.
//
// Clearing on success would be the wrong fix: a pass can complete every
// operation and still leave the counts disagreeing. Here the install is
// REFUSED, so verifyPeers re-reads actual=1 against desired=2 and returns an
// error even though nothing "failed" in the operations sense. The recorded
// start must survive that pass rather than being cleared and re-armed, which
// would report a two-hour standing divergence as brand new.
func TestDivergenceStartSurvivesReconcileThatDidNotConvergeTheCounts(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, clock, _, portal := round6PeerSyncFixture(t, db, svc)

	clock.advance(time.Minute)
	ps.setPortalDeviceForTest(failingAddPeerDevice{real: portal})
	if _, err := newEnginePeer(t, svc, db, "round6-never-installs"); err != "" {
		_ = err // newEnginePeer reports through t, nothing to do here
	}
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err == nil {
		t.Fatal("expected the reconcile to report the injected add failure")
	}
	first := ps.Status()
	if first.DesiredPeers != 2 || first.ActualPeers != 1 {
		t.Fatalf("precondition: expected a 2/1 divergence, got %+v", first)
	}

	clock.advance(2 * time.Hour)
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err == nil {
		t.Fatal("expected the reconcile to fail again")
	}
	second := ps.Status()
	if second.DesiredPeers != 2 || second.ActualPeers != 1 {
		t.Fatalf("the standing divergence must persist, got %+v", second)
	}
	if !second.DivergenceSince.Equal(first.DivergenceSince) {
		t.Fatalf("an ongoing divergence must keep its original start %v, got %v",
			first.DivergenceSince, second.DivergenceSince)
	}
	if age := clock.current().Sub(second.DivergenceSince); age != 2*time.Hour {
		t.Fatalf("the standing divergence must be 2h old, got %s", age)
	}
	c := peerSyncDivergenceCondition(&second, clock.current())
	if c == nil || c.Severity != "DEGRADED" {
		t.Fatalf("a 2h standing divergence must be DEGRADED, got %+v", c)
	}
}

// --- Finding 2: colliding map keys deleted routes ---

// TestForwarderRouteQueuesKeysDoNotCollide is the finding-2 regression.
//
// round5PeerKeyA and round5PeerKeyB share their first 8 characters, so under
// ingress.RedactKey both produced the map key "r5SHARED…". The second write
// silently overwrote the first and one route disappeared from
// /api/vpn/status with no error anywhere. The round 5 test could not catch it
// because it compared the decoded map length against status.ForwarderRouteQueues,
// which is the collapsed map: the two always agreed by construction.
func TestForwarderRouteQueuesKeysDoNotCollide(t *testing.T) {
	fwd, err := newRound6Forwarder(t)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	// Four distinct peers, TWO of which share an 8-character prefix with each
	// other. This is the exact fixture the review named.
	routes := []struct {
		session, connection, peerKey, ip string
	}{
		{"sess-a", "conn-a", round5PeerKeyA, "10.100.0.2"},
		{"sess-b", "conn-b", round5PeerKeyB, "10.100.0.3"},
		{"sess-c", "conn-c", round5PeerKeyC, "10.100.0.4"},
		{"sess-d", "conn-d", round5PeerKeyD, "10.100.0.5"},
	}
	for _, r := range routes {
		fwd.RegisterSession(r.session, r.connection, r.peerKey, r.ip, 1)
	}

	// The collision is real in the display convention. If it were not, this
	// test could pass for the wrong reason, so the premise is asserted rather
	// than assumed.
	if ingress.RedactKey(round5PeerKeyA) == ingress.RedactKey(round5PeerKeyB) {
		// expected; documented rather than treated as the bug
	} else {
		t.Fatal("precondition: the two fixture keys must share a redaction prefix for this test to mean anything")
	}

	status := round6StatusFor(t, fwd)

	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Queues map[string]json.RawMessage `json:"forwarder_route_queues"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The decisive assertion: the number of DISTINCT peers registered, not
	// the length of the already-collapsed status map.
	if len(decoded.Queues) != len(routes) {
		t.Fatalf("forwarder_route_queues lost routes: %d entries for %d registered peers (%v)",
			len(decoded.Queues), len(routes), keysOfRaw(decoded.Queues))
	}
	for _, r := range routes {
		fingerprint := ingress.PeerKeyFingerprint(r.peerKey)
		entry, ok := decoded.Queues[fingerprint]
		if !ok {
			t.Errorf("peer %s is missing from forwarder_route_queues (fingerprint %s)", r.peerKey, fingerprint)
			continue
		}
		var stats struct {
			PeerKeyDisplay string `json:"peer_key_display"`
		}
		if err := json.Unmarshal(entry, &stats); err != nil {
			t.Fatalf("decode entry %s: %v", fingerprint, err)
		}
		if stats.PeerKeyDisplay != ingress.RedactKey(r.peerKey) {
			t.Errorf("entry %s display = %q, want the redacted display form %q",
				fingerprint, stats.PeerKeyDisplay, ingress.RedactKey(r.peerKey))
		}
	}
}

// TestPeerKeyFingerprintIsDeterministicAndDistinct pins the two properties the
// fingerprint has to have for the map to be usable at all: the same input must
// always produce the same identifier (otherwise the dashboard flickers and a
// consumer cannot correlate rows across polls), and distinct inputs must not
// share one (otherwise routes collide again).
func TestPeerKeyFingerprintIsDeterministicAndDistinct(t *testing.T) {
	all := []string{round5PeerKeyA, round5PeerKeyB, round5PeerKeyC, round5PeerKeyD}

	// Determinism: repeated calls, including interleaved with other inputs,
	// return the identical string.
	for round := 0; round < 5; round++ {
		for _, key := range all {
			first := ingress.PeerKeyFingerprint(key)
			second := ingress.PeerKeyFingerprint(key)
			if first != second {
				t.Fatalf("fingerprint is not deterministic for %q: %q then %q", key, first, second)
			}
		}
	}
	// Distinctness across the keys that share a prefix, and across a key of a
	// different length.
	seen := map[string]string{}
	for _, key := range append(all, "short", "a-much-longer-peer-key-value-than-the-others") {
		got := ingress.PeerKeyFingerprint(key)
		if prev, dup := seen[got]; dup {
			t.Errorf("fingerprint collision: %q and %q both render as %q", prev, key, got)
		}
		seen[got] = key
	}

	// Opaqueness: the identifier must not carry any character run of the key,
	// and in particular must not be a truncation of it.
	for _, key := range all {
		got := ingress.PeerKeyFingerprint(key)
		if strings.Contains(got, key) {
			t.Errorf("fingerprint %q embeds the raw peer key", got)
		}
		if strings.Contains(got, key[:8]) {
			t.Errorf("fingerprint %q carries the raw 8-character key prefix", got)
		}
		if !strings.HasPrefix(got, "pk") {
			t.Errorf("fingerprint %q must carry the pk prefix so a reader can tell it is a digest", got)
		}
	}

	// A short key must not collapse to the display masking form. RedactKey
	// returns a fixed-width run of "*" for any key of 8 characters or fewer,
	// so every such key rendered identically.
	if ingress.PeerKeyFingerprint("abc") == ingress.PeerKeyFingerprint("xyz") {
		t.Fatal("short keys must still fingerprint distinctly")
	}
}

// TestForwarderRouteQueuesStillCarriesNoRawPeerKey keeps the round 5 recursive
// assertion honest against the NEW identifier. The old form was scanned with
// no exemption; so is this one, and the scan now covers the fingerprint field
// and the peer_key_display field inside every map entry.
func TestForwarderRouteQueuesStillCarriesNoRawPeerKey(t *testing.T) {
	fwd, err := newRound6Forwarder(t)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	fwd.RegisterSession("sess-a", "conn-a", round5PeerKeyA, "10.100.0.2", 1)
	fwd.RegisterSession("sess-b", "conn-b", round5PeerKeyB, "10.100.0.3", 1)
	fwd.RegisterSession("sess-c", "conn-c", round5PeerKeyC, "10.100.0.4", 1)
	fwd.RegisterSession("sess-d", "conn-d", round5PeerKeyD, "10.100.0.5", 1)

	status := round6StatusFor(t, fwd)
	assertPayloadHasNoRawPeerKey(t, status, allRound5PeerKeys)

	// Belt and braces on the specific field: neither the map key nor any
	// decoded value may contain a raw key.
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var queues map[string]json.RawMessage
	if err := json.Unmarshal(decoded["forwarder_route_queues"], &queues); err != nil {
		t.Fatalf("unmarshal forwarder_route_queues: %v", err)
	}
	if len(queues) != len(allRound5PeerKeys) {
		t.Fatalf("expected %d routes, got %d", len(allRound5PeerKeys), len(queues))
	}
	for key, entry := range queues {
		for _, peerKey := range allRound5PeerKeys {
			if strings.Contains(key, peerKey) || strings.Contains(string(entry), peerKey) {
				t.Errorf("raw peer key %q present in forwarder_route_queues at key %q", peerKey, key)
			}
		}
	}
}

// newRound6Forwarder builds the production forwarder the diagnostics surface
// reads from.
func newRound6Forwarder(t *testing.T) (*forwarder.Forwarder, error) {
	t.Helper()
	f, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	return f, err
}

// round6StatusFor runs the REAL status assembly against a forwarder.
func round6StatusFor(t *testing.T, f *forwarder.Forwarder) *Status {
	t.Helper()
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	svc.mu.Lock()
	svc.forwarder = f
	svc.mu.Unlock()
	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	return status
}

// keysOfRaw lists a decoded JSON map's keys for a failure message.
func keysOfRaw(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
