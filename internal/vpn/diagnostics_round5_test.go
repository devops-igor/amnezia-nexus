package vpn

// Regression coverage for issue #424 round 5.
//
// Item 1 (PRIVACY): the round 4 commit message claimed the diagnostics JSON no
// longer carried a full peer public key. It did, through three separate paths:
//   1a. checkRoutingInvariants appended RAW map keys to SessionsWithoutRoute,
//       RoutesWithoutSession and RoutesWithoutReturn (they are built by
//       iterating maps keyed by the raw peer key).
//   1b. collectHandshakeDiagnostics appended sess.PeerPublicKey verbatim to
//       StaleLiveSessions, serialized as handshake_freshness.stale_live_sessions.
//   1c. ForwarderRouteQueues used raw peer keys as MAP KEYS.
//
// The round 4 test only asserted problem_routes[*].peer_key, which is exactly
// why all three slipped through. The test below therefore does not assert on a
// field: it walks the ENTIRE marshalled payload recursively and asserts that no
// known full test peer key appears anywhere, including nested arrays, nested
// objects and map keys. A targeted assertion cannot catch the next leak; this
// one can.
//
// Item B (LOGIC): the divergence "age" was computed from
// LastSuccessfulReconcile, which is when reconciliation last SUCCEEDED, not
// when the current divergence began. On a system healthy for hours that then
// fails to add one new peer, the divergence is seconds old but the age
// computed to hours, so the health surface immediately claimed a multi-hour
// divergence and reported DEGRADED. The divergence start is now recorded by the
// peerSynchronizer during reconcile and read by the diagnostics layer.

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// round5Backend creates the server and backend tunnel the session FKs require,
// and returns the tunnel id. The sessions are persisted, so a real parent row
// is mandatory; the rows are never used for anything else.
func round5Backend(t *testing.T, db *database.DB, ctx context.Context, name string) int64 {
	t.Helper()
	srv := &models.Server{
		Name: name, Host: "127.0.0.1", SSHPort: 22, SSHUser: "root", SSHPass: "pass",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, PrivateKey: name + "-private-key",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel: %v", err)
	}
	return tunnelID
}

// Full-length base64 test peer keys. They are deliberately chosen so that:
//
//   - they are all DISTINCT, so asserting on "any of them" is meaningful;
//   - the first two SHARE an 8 character prefix, which is the length
//     ingress.RedactKey keeps, so the recursive assertion cannot be satisfied
//     by a check that only looks at one of them;
//   - the third has a different prefix, so a test that passed only because two
//     keys collided would still be caught.
const (
	round5PeerKeyA = "r5SHAREDaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	round5PeerKeyB = "r5SHAREDbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="
	round5PeerKeyC = "r5OTHERcccccccccccccccccccccccccccccccccccc="
	round5PeerKeyD = "r5THIRDdddddddddddddddddddddddddddddddddddddd="
)

// allRound5PeerKeys is the full set the recursive assertion scans for.
var allRound5PeerKeys = []string{
	round5PeerKeyA, round5PeerKeyB, round5PeerKeyC, round5PeerKeyD,
}

// jsonLocation renders a JSON path like "handshake_freshness.stale_live_sessions[0]"
// or "forwarder_route_queues.<map key>", so a failure names the exact leak site
// rather than just the payload.
func jsonLocation(path string, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// assertNoRawPeerKeyAnywhere recursively walks an arbitrary decoded JSON value
// and fails if any of keys appears as a string VALUE, an object KEY, or inside
// a longer string. It deliberately does not stop at the first hit: a single run
// reports every leak site at once, so fixing one path and re-running still
// shows the next one.
func assertNoRawPeerKeyAnywhere(t *testing.T, path string, node any, keys []string) {
	t.Helper()
	switch v := node.(type) {
	case map[string]any:
		// Sorted so the reported locations are stable across runs.
		names := make([]string, 0, len(v))
		for name := range v {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			// A MAP KEY is a disclosure site in its own right: this is
			// precisely how forwarder_route_queues leaked a full peer key.
			for _, raw := range keys {
				if name == raw {
					t.Errorf("raw peer key disclosed as an object KEY at %s: %q",
						jsonLocation(path, "<key>"), name)
				}
			}
			assertNoRawPeerKeyAnywhere(t, jsonLocation(path, name), v[name], keys)
		}
	case []any:
		for i, item := range v {
			assertNoRawPeerKeyAnywhere(t, fmt.Sprintf("%s[%d]", path, i), item, keys)
		}
	case string:
		for _, raw := range keys {
			if v == raw {
				t.Errorf("raw peer key disclosed as a string VALUE at %s: %q", path, v)
				continue
			}
			// A SUBSTRING hit matters too: an error message or a detail
			// string that embeds a key is just as disclosed as a bare value.
			if strings.Contains(v, raw) {
				t.Errorf("raw peer key embedded in a string at %s: %q", path, v)
			}
		}
	default:
		// Numbers, booleans and null cannot carry a key.
	}
}

// assertPayloadHasNoRawPeerKey marshals status and runs the recursive walk.
func assertPayloadHasNoRawPeerKey(t *testing.T, status *Status, keys []string) {
	t.Helper()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	assertNoRawPeerKeyAnywhere(t, "", decoded, keys)
}

// round5Status builds a Status through the REAL production collectors with a
// deliberately inconsistent world, so every round 5 leak path is populated at
// once:
//
//   - three forwarder routes exist but only one has a live session, so
//     RoutesWithoutSession and RoutesWithoutReturn are non-empty (path 1a);
//   - a fourth session exists with no route at all, so SessionsWithoutRoute is
//     non-empty (path 1a, the third of the three slices);
//   - the live sessions have no fresh handshake, so StaleLiveSessions is
//     non-empty (path 1b);
//   - the forwarder holds routes, so ForwarderRouteQueues is non-empty with the
//     raw peer keys as MAP KEYS (path 1c);
//   - and the routes produce ProblemRoutes, so the round 4 path is covered too.
func round5Status(t *testing.T) *Status {
	t.Helper()
	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	// Three routes: A and B have return owners, C does not (so C lands in
	// RoutesWithoutReturn).
	fwd.RegisterSession("sess-a", "conn-a", round5PeerKeyA, "10.100.0.2", 1)
	fwd.RegisterSession("sess-b", "conn-b", round5PeerKeyB, "10.100.0.3", 1)
	fwd.RegisterSession("sess-c", "conn-c", round5PeerKeyC, "10.100.0.4", 0)

	// The ingress engine is what collectHandshakeDiagnostics needs before it
	// will look at live sessions at all. Without it the collector returns
	// early and handshake_freshness.stale_live_sessions is empty, so the
	// recursive walk would never see path 1b and the test would pass without
	// covering it. The fixture provides a real suspended-reads portal device.
	fxSvc, _, _, _, _ := newSingleOwnerFixture(t)

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}

	// Point the real service at the populated forwarder so GetStatus collects
	// from it, and at the fixture's ingress engine so the handshake half of
	// the payload is real. The forwarder built above is the same type and API
	// as the one the service owns; swapping the reference is what lets a
	// single Status carry every leak path at once.
	svc.mu.Lock()
	svc.forwarder = fwd
	svc.ingressEngine = fxSvc.ingressEngine
	svc.mu.Unlock()

	// Live sessions: A has a route, C and D do not. D therefore lands in
	// SessionsWithoutRoute.
	ctx := t.Context()
	userID, err := db.CreateUser(ctx, &models.User{
		Username: "round5-user", Role: models.RoleUser, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	backendID := round5Backend(t, db, ctx, "round5-backend")
	for _, spec := range []struct {
		peerKey string
		ip      string
	}{
		{round5PeerKeyA, "10.100.0.2"},
		{round5PeerKeyC, "10.100.0.4"},
		{round5PeerKeyD, "10.100.0.5"},
	} {
		if _, err := svc.sessionMgr.CreateSession(ctx, userID, spec.peerKey, spec.ip, backendID, "conn-round5"); err != nil {
			t.Fatalf("CreateSession for %s: %v", ingress.RedactKey(spec.peerKey), err)
		}
	}

	status, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	// The fixture is only meaningful if it actually populated every path. A
	// recursive walk over an EMPTY payload passes trivially, so each path is
	// asserted non-empty here, and a failure names the setup, not the
	// assertion under test.
	if len(status.RoutingConsistency.SessionsWithoutRoute) == 0 {
		t.Fatal("fixture did not populate SessionsWithoutRoute, so path 1a is untested")
	}
	if len(status.RoutingConsistency.RoutesWithoutSession) == 0 {
		t.Fatal("fixture did not populate RoutesWithoutSession, so path 1a is untested")
	}
	if len(status.RoutingConsistency.RoutesWithoutReturn) == 0 {
		t.Fatal("fixture did not populate RoutesWithoutReturn, so path 1a is untested")
	}
	if len(status.ForwarderRouteQueues) == 0 {
		t.Fatal("fixture did not populate ForwarderRouteQueues, so path 1c is untested")
	}
	if len(status.HandshakeFreshness.StaleLiveSessions) == 0 {
		t.Fatal("fixture did not populate StaleLiveSessions, so path 1b is untested")
	}
	return status
}

// TestDiagnosticsAPIPayloadCarriesNoRawPeerKey is the item 1 regression, and the
// test the round 4 suite was missing.
//
// It asserts the property that actually matters (no known full test peer key
// occurs ANYWHERE in the marshalled payload, at any depth, as a value, inside a
// string, or as a map key) rather than asserting on the fields that happen to
// exist today. A future field that leaks a key is caught by this test without
// anyone having to think of it.
func TestDiagnosticsAPIPayloadCarriesNoRawPeerKey(t *testing.T) {
	status := round5Status(t)
	assertPayloadHasNoRawPeerKey(t, status, allRound5PeerKeys)
}

// TestStaleLiveSessionsAreRedacted covers path 1b directly, at the collector
// that produced it. The recursive test above asserts the property; this one
// pins the specific field so a regression names the field rather than only
// "something in the payload".
func TestStaleLiveSessionsAreRedacted(t *testing.T) {
	// The collector needs BOTH halves: an ingress engine, because it reads
	// the upstream portal status for handshake ages, and a session manager,
	// because the live sessions are the thing being reported. A bare service
	// has no engine, the collector returns early, and the field is never
	// populated, so the assertion would pass vacuously. The fixture supplies a
	// real suspended-reads portal device.
	fxSvc, _, _, _, _ := newSingleOwnerFixture(t)

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	// Borrow the fully wired session manager, which needs the real database
	// and IPAM, while keeping the fixture's ingress engine.
	fxSvc.sessionMgr = svc.sessionMgr

	userID, err := db.CreateUser(t.Context(), &models.User{
		Username: "round5-stale", Role: models.RoleUser, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	backendID := round5Backend(t, db, t.Context(), "round5-stale-backend")

	// A live session whose peer has NO handshake entry at all is stale by
	// definition: the portal status has no record of it.
	if _, err := svc.sessionMgr.CreateSession(t.Context(), userID, round5PeerKeyA, "10.100.0.9", backendID, "conn-round5"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	diag := collectHandshakeDiagnostics(fxSvc)
	for _, sess := range diag.StaleLiveSessions {
		for _, raw := range allRound5PeerKeys {
			if sess == raw {
				t.Errorf("stale_live_sessions carried the raw peer key %q", raw)
			}
		}
	}
	if len(diag.StaleLiveSessions) == 0 {
		t.Fatal("fixture did not populate StaleLiveSessions, so path 1b is untested")
	}
	want := ingress.RedactKey(round5PeerKeyA)
	if diag.StaleLiveSessions[0] != want {
		t.Errorf("stale_live_sessions[0] = %q, want the shared redaction convention %q",
			diag.StaleLiveSessions[0], want)
	}
}

// TestRoutingInvariantSlicesAreRedactedAndSorted covers path 1a directly.
//
// The ordering half is asserted deliberately: redaction truncates to 8
// characters, so sorting the REDACTED values would order by the surviving
// prefix and two keys sharing that prefix would be indistinguishable by
// position. The implementation sorts the raw keys first and redacts second, so
// the emitted order is the raw key order. This test pins that choice by using
// two keys that share a prefix and are therefore in a DIFFERENT raw order than
// any prefix-based order could produce deterministically.
func TestRoutingInvariantSlicesAreRedactedAndSorted(t *testing.T) {
	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	// Round 5 keys B and C, in an order that makes the raw sort observable.
	routes := []forwarder.RouteInfo{
		{PeerKey: round5PeerKeyC, AssignedIP: "10.100.0.4", BackendTunnelID: 0},
		{PeerKey: round5PeerKeyB, AssignedIP: "10.100.0.3", BackendTunnelID: 0},
	}
	svc := &Service{forwarder: fwd}
	diag := checkRoutingInvariants(svc, routes, ReturnStatsSnapshot{})

	if len(diag.RoutesWithoutSession) != 2 {
		t.Fatalf("expected two routes without a session, got %v", diag.RoutesWithoutSession)
	}
	for i, v := range diag.RoutesWithoutSession {
		for _, raw := range allRound5PeerKeys {
			if v == raw {
				t.Errorf("RoutesWithoutSession[%d] carried the raw peer key %q", i, raw)
			}
		}
	}
	// Raw key order: "r5OTHER..." sorts before "r5SHARED..." ('O' < 'S'), and
	// the implementation sorts the RAW keys, so the emitted order is C then B.
	// A prefix-based sort could not distinguish them at all: A and B share the
	// 8 character prefix redaction keeps, so any order derived from the
	// redacted values would be an artifact of the masking.
	want := []string{ingress.RedactKey(round5PeerKeyC), ingress.RedactKey(round5PeerKeyB)}
	for i := range want {
		if diag.RoutesWithoutSession[i] != want[i] {
			t.Errorf("RoutesWithoutSession[%d] = %q, want %q (raw sort order, not prefix order)",
				i, diag.RoutesWithoutSession[i], want[i])
		}
	}
	// Both are also missing a return owner here, and must be redacted too.
	if len(diag.RoutesWithoutReturn) != 2 {
		t.Fatalf("expected two routes without a return owner, got %v", diag.RoutesWithoutReturn)
	}
	for i, v := range diag.RoutesWithoutReturn {
		if v != want[i] {
			t.Errorf("RoutesWithoutReturn[%d] = %q, want %q", i, v, want[i])
		}
	}
}

// TestForwarderRouteQueuesKeysAreRedacted covers path 1c directly, including
// the explicit trade-off. Under decision (a) the map KEY is redacted, so a
// consumer matching these keys against a full peer public key stops matching.
// That is the accepted cost, and this test is where it is pinned: the map
// still exists, still has the same number of entries, still has the same stats,
// and every key is redacted.
//
// Note there is NO scope-out of a legacy raw field here. Options (b) and (c)
// would each have required an explicit exemption in the recursive test; (a)
// does not, so the recursive test above scans this field with no exemption at
// all.
func TestForwarderRouteQueuesKeysAreRedacted(t *testing.T) {
	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	fwd.RegisterSession("sess-a", "conn-a", round5PeerKeyA, "10.100.0.2", 1)
	fwd.RegisterSession("sess-b", "conn-b", round5PeerKeyB, "10.100.0.3", 1)
	fwd.RegisterSession("sess-c", "conn-c", round5PeerKeyC, "10.100.0.4", 1)
	fwd.RegisterSession("sess-d", "conn-d", round5PeerKeyD, "10.100.0.5", 1)

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	svc.mu.Lock()
	svc.forwarder = fwd
	svc.mu.Unlock()

	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if len(status.ForwarderRouteQueues) == 0 {
		t.Fatal("fixture did not populate ForwarderRouteQueues")
	}
	for key := range status.ForwarderRouteQueues {
		for _, raw := range allRound5PeerKeys {
			if key == raw {
				t.Errorf("forwarder_route_queues carried a raw peer key as a map key: %q", key)
			}
		}
	}
	// The JSON map must survive intact as a map, and must be scanned by the
	// recursive walk like any other field.
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
	if len(decoded.Queues) != len(status.ForwarderRouteQueues) {
		t.Errorf("forwarder_route_queues changed shape: got %d entries, want %d",
			len(decoded.Queues), len(status.ForwarderRouteQueues))
	}
}

// --- Item B: divergence age semantics ---

// TestPeerSyncDivergenceAgeIsNotLastSuccessfulReconcileAge is the reviewer's
// exact production sequence:
//
//	10:00  successful reconcile, desired=10 actual=10
//	12:00  new peer created, add fails, desired=11 actual=10
//
// The divergence is TWO MINUTES old. The old code measured from the last
// successful reconcile and so reported an age of two HOURS, escalating straight
// past both thresholds to DEGRADED and stating a multi-hour divergence for an
// incident that had just begun.
//
// This is the core assertion of item B, and it is separated from the lifecycle
// test below so that the specific regression (age sourced from the wrong
// timestamp) fails on its own, with its own message.
func TestPeerSyncDivergenceAgeIsNotLastSuccessfulReconcileAge(t *testing.T) {
	base := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)
	now := base.Add(2 * time.Hour)

	ps := &PeerSyncStatus{
		DesiredPeers:            11,
		ActualPeers:             10,
		LastSuccessfulReconcile: base, // two hours ago, the trap
		DivergenceSince:         now,  // the divergence began just now
	}
	got := peerSyncDivergenceCondition(ps, now)
	if got != nil {
		t.Fatalf("a 2 minute old divergence must emit no condition, got %s: %q",
			got.Severity, got.Message)
	}

	// And the same status with the divergence start left at the last
	// successful reconcile, which is what the pre-change code computed, must
	// have escalated. This pins that the test is not vacuous: the two
	// timestamps in the same struct produce different verdicts, and the one
	// the implementation now reads is the fresh one.
	trap := &PeerSyncStatus{
		DesiredPeers:            11,
		ActualPeers:             10,
		LastSuccessfulReconcile: base,
		DivergenceSince:         base,
	}
	if trapCond := peerSyncDivergenceCondition(trap, now); trapCond == nil || trapCond.Severity != "DEGRADED" {
		t.Fatalf("sanity check failed: a 2 hour old divergence must be DEGRADED, got %+v", trapCond)
	}
}

// TestPeerSyncDivergenceLifecycle is the mandatory five-step lifecycle test
// from the review, driven through the REAL peerSynchronizer bookkeeping rather
// than a hand-built status, so it also proves the synchronizer maintains the
// field the diagnostics layer reads.
//
// Steps, in order:
//  1. old successful reconcile hours ago, desired == actual (converged);
//  2. a fresh mismatch appears, with a FRESH start time;
//  3. the reported age is small, with no WARNING and no DEGRADED, and the
//     message asserts no multi-hour divergence;
//  4. advancing past 30s then 60s yields WARNING then DEGRADED;
//  5. converging CLEARS the start, so a later fresh divergence does not inherit
//     the old age.
//
// Step 5 is the one that is easiest to omit and the most consequential: with no
// clear on convergence, the recorded start from the first incident would
// silently accumulate and a second, unrelated incident would be reported as a
// continuation of the first.
func TestPeerSyncDivergenceLifecycle(t *testing.T) {
	// Anchored HERE, at the top of this test, not at package init. Step 3
	// deliberately asserts through the real wall clock, and this package runs
	// for minutes under -race, so a package-level anchor would leave the
	// divergence minutes old by the time the assertion runs and the test
	// would fail for the elapsed test-suite time rather than for anything it
	// is testing. Observed directly: an earlier package-init anchor made this
	// test fail under -race with a spurious DEGRADED at "3h0m0s".
	now := time.Now().UTC()
	ps := &PeerSyncStatus{
		DesiredPeers: 10,
		ActualPeers:  10,
		// Hours ago. This is the trap the test exists for: it is the ONLY
		// thing that is hours old in this state.
		LastSuccessfulReconcile: now.Add(-2 * time.Hour),
	}
	sync := &peerSynchronizer{status: *ps}
	sync.setNowFuncForTest(func() time.Time { return now })

	// Step 1: converged, hours since the last successful reconcile. A
	// converged system must have NO recorded divergence.
	sync.mu.Lock()
	sync.noteDivergenceState(sync.now())
	sync.mu.Unlock()
	if !sync.status.DivergenceSince.IsZero() {
		t.Fatalf("step 1: a converged system must have no divergence start, got %v",
			sync.status.DivergenceSince)
	}

	// Step 2: a fresh mismatch. desired=11 (a new peer was created), actual=10
	// (adding it failed).
	//
	// The injected clock is NOT advanced here. Step 3 deliberately goes
	// through evaluatePeerSyncAndBackendConditions, which reads the REAL wall
	// clock, so the recorded start must be recent for that assertion to be
	// about the divergence age rather than about the gap between the injected
	// clock and the wall clock. The "hours ago" part of the reviewer's
	// scenario lives in LastSuccessfulReconcile, which is exactly the trap.
	sync.mu.Lock()
	sync.status.DesiredPeers = 11
	sync.status.ActualPeers = 10
	sync.noteDivergenceState(sync.now())
	sync.mu.Unlock()

	// Step 3: the age is small, so nothing is claimed.
	if sync.status.DivergenceSince.IsZero() {
		t.Fatal("step 2/3: a fresh mismatch must record a divergence start")
	}
	if age := now.Sub(sync.status.DivergenceSince); age != 0 {
		t.Fatalf("step 3: a freshly observed divergence must start at now, got age %s", age)
	}
	conds := evaluatePeerSyncAndBackendConditions(&sync.status, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	for _, c := range conds {
		if c.Category == "peer_sync" && strings.Contains(c.Message, "divergence") {
			t.Fatalf("step 3: a 0s divergence must emit no condition, got %s: %q", c.Severity, c.Message)
		}
	}
	// The message must never assert a multi-hour divergence for this state.
	if c := peerSyncDivergenceCondition(&sync.status, now); c != nil {
		t.Fatalf("step 3: unexpected condition %q", c.Message)
	}

	// Step 4: past the warning threshold, then past the degraded one. The
	// recorded start does NOT move, which is what makes the age grow.
	for _, tc := range []struct {
		advance  time.Duration
		severity string
	}{
		{advance: DefaultHealthThresholds.PeerSyncDivergenceWarningAge + time.Second, severity: "WARNING"},
		{advance: DefaultHealthThresholds.PeerSyncDivergenceDegradedAge + time.Second, severity: "DEGRADED"},
	} {
		probe := now.Add(tc.advance)
		// A subsequent reconcile observes the SAME mismatch and must leave
		// the start alone.
		sync.mu.Lock()
		sync.noteDivergenceState(probe)
		sync.mu.Unlock()
		if got := sync.status.DivergenceSince; !got.Equal(now) {
			t.Fatalf("an ongoing divergence must keep its original start, got %v want %v", got, now)
		}
		c := peerSyncDivergenceCondition(&sync.status, probe)
		if c == nil {
			t.Fatalf("step 4: a %s old divergence must emit a condition", tc.advance)
		}
		if c.Severity != tc.severity {
			t.Errorf("step 4: a %s old divergence is %s, want %s (%q)",
				tc.advance, c.Severity, tc.severity, c.Message)
		}
		if !strings.Contains(c.Message, tc.advance.Round(time.Second).String()) {
			t.Errorf("step 4: the message must state the age %s, got %q",
				tc.advance.Round(time.Second), c.Message)
		}
	}

	// Step 5: converge. The start MUST be cleared.
	convergedAt := now.Add(10 * time.Minute)
	sync.mu.Lock()
	sync.status.DesiredPeers = 11
	sync.status.ActualPeers = 11
	sync.noteDivergenceState(convergedAt)
	sync.mu.Unlock()
	if !sync.status.DivergenceSince.IsZero() {
		t.Fatalf("step 5: convergence must CLEAR the divergence start, got %v",
			sync.status.DivergenceSince)
	}

	// Step 5, second half: a LATER, unrelated fresh divergence must not
	// inherit the age of the first. With a stale start still recorded, the
	// age here would be 10 minutes and the condition would be DEGRADED
	// immediately, which is exactly the bug class item B is about.
	later := convergedAt.Add(2 * time.Second)
	sync.mu.Lock()
	sync.status.DesiredPeers = 12
	sync.status.ActualPeers = 11
	sync.noteDivergenceState(later)
	sync.mu.Unlock()
	if age := later.Sub(sync.status.DivergenceSince); age != 0 {
		t.Fatalf("step 5: a new divergence must start from scratch, got age %s", age)
	}
	if c := peerSyncDivergenceCondition(&sync.status, later); c != nil {
		t.Fatalf("step 5: a new 0s divergence must emit no condition, got %s: %q",
			c.Severity, c.Message)
	}
}

// base2 is a convenience anchor for the tests that assert ONLY through the
// injected now, where a package-level value is harmless. Any test that asserts
// through the real wall clock MUST take its own anchor inside the test body;
// see TestPeerSyncDivergenceLifecycle.
var base2 = time.Now().UTC()

// TestPeerSyncDivergenceUnknownAgeOnlyWhenNeverTimed pins the explicit decision
// for the two zero-DivergenceSince cases, which are NOT the same thing.
//
// Case 1, genuinely never reconciled: no reconcile has ever reached the point
// where both counts are known, so the age is unknown and WARNING is right.
// Inventing a large age would report DEGRADED on a system that has never
// synchronized anything.
//
// Case 2, fresh divergence on a system with no prior SUCCESSFUL reconcile:
// DivergenceSince IS set, because the synchronizer stamps it on first
// observation regardless of whether any earlier reconcile succeeded. The age is
// therefore known and the divergence is held to the same thresholds as any
// other. This is the decision made explicit rather than inherited.
func TestPeerSyncDivergenceUnknownAgeOnlyWhenNeverTimed(t *testing.T) {
	now := base2

	t.Run("never_reconciled_is_unknown", func(t *testing.T) {
		ps := &PeerSyncStatus{DesiredPeers: 4, ActualPeers: 0}
		c := peerSyncDivergenceCondition(ps, now)
		if c == nil {
			t.Fatal("a never-reconciled mismatch must still be reported")
		}
		if c.Severity != "WARNING" {
			t.Errorf("an unknown age must not be DEGRADED, got %q (%q)", c.Severity, c.Message)
		}
		if !strings.Contains(c.Message, "age unknown") {
			t.Errorf("the message must state the age is unknown, got %q", c.Message)
		}
	})

	t.Run("fresh_divergence_with_no_prior_successful_reconcile_has_a_known_age", func(t *testing.T) {
		// LastSuccessfulReconcile is zero: no reconcile has EVER succeeded.
		// The counts nevertheless disagree and a start was recorded, so the
		// age is known and is timed normally.
		ps := &PeerSyncStatus{
			DesiredPeers:            4,
			ActualPeers:             3,
			LastSuccessfulReconcile: time.Time{},
			DivergenceSince:         now,
		}
		if c := peerSyncDivergenceCondition(ps, now); c != nil {
			t.Fatalf("a 0s fresh divergence must emit no condition, got %s: %q", c.Severity, c.Message)
		}
		// Past the warning threshold it escalates, exactly like any other.
		probe := now.Add(DefaultHealthThresholds.PeerSyncDivergenceWarningAge + time.Second)
		c := peerSyncDivergenceCondition(ps, probe)
		if c == nil || c.Severity != "WARNING" {
			t.Fatalf("a fresh divergence past the warning threshold must be WARNING, got %+v", c)
		}
		// And it must NOT claim an unknown age.
		if strings.Contains(c.Message, "age unknown") {
			t.Errorf("a stamped divergence start must not report an unknown age, got %q", c.Message)
		}
	})
}

// TestPeerSyncDivergenceFutureStampDoesNotEscalate covers the clock-step
// guard: DivergenceSince stamped in the future (a backwards clock step, or a
// synchronizer and diagnostics host disagreeing) must not produce a negative
// age that reads as a huge one.
func TestPeerSyncDivergenceFutureStampDoesNotEscalate(t *testing.T) {
	now := base2
	ps := &PeerSyncStatus{
		DesiredPeers:    5,
		ActualPeers:     4,
		DivergenceSince: now.Add(time.Hour), // in the future
	}
	if c := peerSyncDivergenceCondition(ps, now); c != nil {
		t.Fatalf("a future divergence stamp must not escalate, got %s: %q", c.Severity, c.Message)
	}
}

// TestDivergenceSinceIsAdditiveJSONKey pins the additive-only constraint for
// the new field: present, correctly named, and marshalled. Removing or
// renaming it would break a consumer, so the name is asserted literally.
func TestDivergenceSinceIsAdditiveJSONKey(t *testing.T) {
	raw, err := json.Marshal(&PeerSyncStatus{})
	if err != nil {
		t.Fatalf("marshal PeerSyncStatus: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal PeerSyncStatus: %v", err)
	}
	if _, ok := decoded["divergence_since"]; !ok {
		t.Fatalf("divergence_since must be present in the JSON, got keys %v", keysOf(decoded))
	}
	// The pre-existing round 4 keys must still be there: 0 removed, 0 renamed.
	for _, key := range []string{
		"desired_peers", "actual_peers", "invalid_rows", "sync_failures",
		"add_failures", "remove_failures", "update_failures",
		"last_successful_reconcile", "portal_config_restart_required",
		"enqueue_failures", "sync_failures_recent", "enqueue_failures_recent",
		"failures_window_sec",
	} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("pre-existing key %q was removed or renamed", key)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPeerKeyStaysPresentAndNonEmpty pins the constraint that redaction must
// not degrade the field into uselessness: peer_key remains present, non-empty,
// and non-omitempty, and carries the shared convention.
func TestPeerKeyStaysPresentAndNonEmpty(t *testing.T) {
	items := collectProblemRoutes([]forwarder.RouteInfo{
		{PeerKey: round5PeerKeyA, AssignedIP: "10.100.0.2", BackendTunnelID: 1},
	})
	raw, err := json.Marshal(&Status{ProblemRoutes: items})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		ProblemRoutes []struct {
			PeerKey string `json:"peer_key"`
		} `json:"problem_routes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.ProblemRoutes) != 1 {
		t.Fatalf("expected one problem route, got %d", len(decoded.ProblemRoutes))
	}
	got := decoded.ProblemRoutes[0].PeerKey
	if got == "" {
		t.Error("peer_key must be present and non-empty after redaction")
	}
	if got != ingress.RedactKey(round5PeerKeyA) {
		t.Errorf("peer_key = %q, want %q", got, ingress.RedactKey(round5PeerKeyA))
	}
	// The struct tag must stay non-omitempty, so a reviewer can see the
	// guarantee rather than infer it from a populated fixture.
	if tag := jsonTagOf(Status{}, "ProblemRoutes"); strings.Contains(tag, "omitempty") {
		t.Errorf("peer_key field must remain non-omitempty, got tag %q", tag)
	}
}

// jsonTagOf returns the json struct tag of a named field, or "" when absent.
func jsonTagOf(v any, field string) string {
	typ := reflect.TypeOf(v)
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return ""
	}
	sf, ok := typ.FieldByName(field)
	if !ok {
		return ""
	}
	return sf.Tag.Get("json")
}
