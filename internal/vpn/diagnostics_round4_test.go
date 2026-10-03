package vpn

// Regression coverage for issue #424 round 4, items E, F and G.
//
// E: the diagnostics API shipped the RAW peer public key in
//    ProblemRouteItem.PeerKey. The JSON payload is the disclosure surface, so
//    masking in the template would not have fixed it. The value is now
//    redacted at the API boundary with ingress.RedactKey, the convention the
//    rest of the system already uses.
//
// F: peer-sync divergence was a BOOLEAN (desired != actual), so a mismatch that
//    resolved inside the next reconcile was indistinguishable from one that had
//    persisted for hours. It is now timed from the last successful reconcile:
//    WARNING past 30s, DEGRADED past 60s, nothing below that, and an explicit
//    UNKNOWN age when no reconcile has ever succeeded.
//
// G: invalid_rows was DISPLAYED but health-neutral. It is durable state, so it
//    is sticky: it survives a transient read glitch and clears only on genuine
//    repair.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// round4PeerKeyA and round4PeerKeyB are two full-length base64 peer keys that
// deliberately share their first 8 characters, so the 8-character redaction
// prefix cannot distinguish them.
const (
	round4PeerKeyA = "SHAREDpfxAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	round4PeerKeyB = "SHAREDpfxBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb="
	round4PeerKeyC = "OTHERpfxCcccccccccccccccccccccccccccccccccccc="
)

// TestProblemRoutesAPIRedactsRawPeerKey is the item E regression: a full peer
// key must never appear verbatim anywhere in the marshalled status JSON.
func TestProblemRoutesAPIRedactsRawPeerKey(t *testing.T) {
	items := collectProblemRoutes([]forwarder.RouteInfo{
		{PeerKey: round4PeerKeyA, AssignedIP: "10.100.0.2", BackendTunnelID: 1},
	})
	status := &Status{ProblemRoutes: items}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	payload := string(raw)
	for _, key := range []string{round4PeerKeyA, round4PeerKeyB, round4PeerKeyC} {
		if strings.Contains(payload, key) {
			t.Fatalf("the raw peer key leaked verbatim into the diagnostics JSON: %q", key)
		}
	}
	// The key must still be present, non-empty, and under its original name.
	if !strings.Contains(payload, `"peer_key":"`+ingress.RedactKey(round4PeerKeyA)+`"`) {
		t.Fatalf("peer_key must be present and carry the redacted value; payload was %s", payload)
	}
	var decoded struct {
		ProblemRoutes []struct {
			PeerKey string `json:"peer_key"`
		} `json:"problem_routes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if len(decoded.ProblemRoutes) != 1 {
		t.Fatalf("expected one problem route, got %+v", decoded.ProblemRoutes)
	}
	if got := decoded.ProblemRoutes[0].PeerKey; got == "" {
		t.Fatal("peer_key must not be empty after redaction")
	}
	if got := decoded.ProblemRoutes[0].PeerKey; got != ingress.RedactKey(round4PeerKeyA) {
		t.Errorf("peer_key = %q, want the shared redaction convention %q",
			got, ingress.RedactKey(round4PeerKeyA))
	}
}

// TestRedactedPeerKeysShareAnEightCharacterPrefix documents the collision
// property of the chosen convention rather than asserting it away.
//
// ingress.RedactKey keeps 8 characters, so two keys sharing an 8-character
// prefix DO render identically. That is accepted, deliberately:
//
//   - inventing a second, wider redaction format just for diagnostics would
//     break the "one convention" rule the rest of the system follows;
//   - widening it project-wide would change every existing error message and
//     counter, which is out of scope for this PR;
//   - 8 base64 characters of a 44-character key is 48 bits, so real keys do
//     not collide in practice;
//   - and the row is still unambiguous to an admin, because assigned_ip is
//     carried in the SAME object and is unique per route.
//
// The test pins both halves of that argument: the redacted values do collide,
// and the per-route identifier that disambiguates them survives.
func TestRedactedPeerKeysShareAnEightCharacterPrefix(t *testing.T) {
	items := collectProblemRoutes([]forwarder.RouteInfo{
		{PeerKey: round4PeerKeyA, AssignedIP: "10.100.0.2", BackendTunnelID: 1},
		{PeerKey: round4PeerKeyB, AssignedIP: "10.100.0.3", BackendTunnelID: 1},
		{PeerKey: round4PeerKeyC, AssignedIP: "10.100.0.4", BackendTunnelID: 1},
	})
	if items[0].PeerKey != items[1].PeerKey {
		t.Errorf("keys sharing an 8-character prefix must render identically under the "+
			"shared convention, got %q and %q", items[0].PeerKey, items[1].PeerKey)
	}
	if items[0].PeerKey == items[2].PeerKey {
		t.Errorf("keys with different prefixes must stay distinguishable, got %q twice",
			items[0].PeerKey)
	}
	seen := map[string]bool{}
	for _, it := range items {
		if it.AssignedIP == "" {
			t.Fatal("assigned_ip must survive so colliding redacted keys stay attributable")
		}
		if seen[it.AssignedIP] {
			t.Fatalf("assigned_ip must disambiguate colliding redacted keys, duplicate %q", it.AssignedIP)
		}
		seen[it.AssignedIP] = true
	}
}

// TestPeerSyncDivergenceTimingThresholds is the item F regression. The old gate
// emitted WARNING for ANY mismatch, so a 45 second divergence and a 45 minute
// divergence were indistinguishable, and a mismatch 1 second old was reported at
// all.
//
// The threshold boundaries are asserted against peerSyncDivergenceCondition
// directly with an INJECTED now. Going through
// evaluatePeerSyncAndBackendConditions would make "exactly 30s" unobservable:
// that function reads the wall clock itself, so an age of exactly the threshold
// is a few microseconds past it by the time it is evaluated. The end-to-end
// wiring is covered separately, below, at ages clear of the boundary.
func TestPeerSyncDivergenceTimingThresholds(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		age      time.Duration
		severity string // "" means no condition expected
	}{
		{name: "just_converging", age: 0, severity: ""},
		{name: "below_warning", age: 29 * time.Second, severity: ""},
		{name: "at_warning_boundary", age: DefaultHealthThresholds.PeerSyncDivergenceWarningAge, severity: ""},
		{name: "just_above_warning", age: DefaultHealthThresholds.PeerSyncDivergenceWarningAge + time.Millisecond, severity: "WARNING"},
		{name: "at_degraded_boundary", age: DefaultHealthThresholds.PeerSyncDivergenceDegradedAge, severity: "WARNING"},
		{name: "just_above_degraded", age: DefaultHealthThresholds.PeerSyncDivergenceDegradedAge + time.Millisecond, severity: "DEGRADED"},
		{name: "long_divergence", age: 45 * time.Minute, severity: "DEGRADED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := &PeerSyncStatus{
				DesiredPeers: 12,
				ActualPeers:  11,
				// The age is measured from the recorded divergence START
				// (issue #424 round 5, item B), not from the last
				// successful reconcile. The test drives the start back by the
				// age under test; the reviewer's production sequence, where
				// the last successful reconcile is hours old but the
				// divergence is seconds old, is covered by
				// TestPeerSyncDivergenceAgeIsNotLastSuccessfulReconcileAge.
				DivergenceSince: now.Add(-tc.age),
			}
			got := peerSyncDivergenceCondition(ps, now)
			if tc.severity == "" {
				if got != nil {
					t.Fatalf("a %s divergence must emit no condition, got %+v", tc.age, *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("a %s divergence must emit a %s condition, got none", tc.age, tc.severity)
			}
			if got.Severity != tc.severity {
				t.Errorf("a %s divergence is %q, want %q (message: %q)",
					tc.age, got.Severity, tc.severity, got.Message)
			}
			// The message must state the AGE, not just the counts.
			if !strings.Contains(got.Message, tc.age.Round(time.Second).String()) {
				t.Errorf("the divergence message must state the age %s, got %q",
					tc.age.Round(time.Second), got.Message)
			}
			if !strings.Contains(got.Message, "12 desired vs 11 actual") {
				t.Errorf("the divergence message must state the counts, got %q", got.Message)
			}
		})
	}
}

// TestPeerSyncDivergenceReachesHealthSurface wires the timing through the real
// consumer, away from the boundary so the wall clock cannot move the verdict.
func TestPeerSyncDivergenceReachesHealthSurface(t *testing.T) {
	for _, tc := range []struct {
		name     string
		age      time.Duration
		severity string
	}{
		{name: "converging", age: 5 * time.Second, severity: ""},
		{name: "warning", age: 45 * time.Second, severity: "WARNING"},
		{name: "degraded", age: 5 * time.Minute, severity: "DEGRADED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conds := evaluatePeerSyncAndBackendConditions(divergenceAt(tc.age),
				BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
			var divergence []HealthCondition
			for _, c := range conds {
				if c.Category == "peer_sync" && strings.Contains(c.Message, "divergence") {
					divergence = append(divergence, c)
				}
			}
			if tc.severity == "" {
				if len(divergence) != 0 {
					t.Fatalf("a %s divergence must emit no condition, got %+v", tc.age, divergence)
				}
				return
			}
			if len(divergence) != 1 || divergence[0].Severity != tc.severity {
				t.Fatalf("expected one %s divergence condition, got %+v", tc.severity, divergence)
			}
			if !strings.Contains(divergence[0].Message, tc.age.Round(time.Second).String()) {
				t.Errorf("the message must state the age %s, got %q",
					tc.age.Round(time.Second), divergence[0].Message)
			}
		})
	}
}

// divergenceAt builds a diverged peer sync whose divergence STARTED age ago,
// for the end-to-end consumer test.
func divergenceAt(age time.Duration) *PeerSyncStatus {
	return &PeerSyncStatus{
		DesiredPeers:    12,
		ActualPeers:     11,
		DivergenceSince: time.Now().UTC().Add(-age),
	}
}

// TestPeerSyncDivergenceWithNoReconcileYet pins the never-reconciled case. A
// zero LastSuccessfulReconcile is an UNKNOWN age. Defaulting it to a large age
// would report DEGRADED on a system that has never synchronized anything, so
// the age is stated as unknown instead and the severity stays WARNING.
func TestPeerSyncDivergenceWithNoReconcileYet(t *testing.T) {
	ps := &PeerSyncStatus{DesiredPeers: 4, ActualPeers: 0}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	var divergence []HealthCondition
	for _, c := range conds {
		if c.Category == "peer_sync" && strings.Contains(c.Message, "divergence") {
			divergence = append(divergence, c)
		}
	}
	if len(divergence) != 1 {
		t.Fatalf("expected exactly one divergence condition, got %+v", divergence)
	}
	if divergence[0].Severity != "WARNING" {
		t.Errorf("an unknown divergence age must not be reported as DEGRADED, got %q (%q)",
			divergence[0].Severity, divergence[0].Message)
	}
	if !strings.Contains(divergence[0].Message, "age unknown") {
		t.Errorf("the message must state that the age is unknown, got %q", divergence[0].Message)
	}
}

// TestPeerSyncConvergedReportsNoDivergence is the negative control: equal
// counts are not a divergence regardless of how stale the last reconcile is.
func TestPeerSyncConvergedReportsNoDivergence(t *testing.T) {
	ps := &PeerSyncStatus{DesiredPeers: 12, ActualPeers: 12, LastSuccessfulReconcile: time.Now().UTC()}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	for _, c := range conds {
		if strings.Contains(c.Message, "divergence") {
			t.Errorf("converged peer counts must not emit a divergence condition, got %+v", conds)
		}
	}
}

// TestInvalidDurableRowsContributeToHealth is the item G regression, degrade
// path. It drives the REAL producer (peerSynchronizer.reconcileNow over two
// durable rows that collide on their assigned IP) into the REAL consumer
// (evaluatePeerSyncAndBackendConditions). Nothing is poked by hand.
func TestInvalidDurableRowsContributeToHealth(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	userID, err := db.CreateUser(ctx, &models.User{Username: "sync-invalid-rows", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const ip = "10.100.7.11"
	keys := make([]string, 2)
	for i := range keys {
		_, k := engineKeys(t)
		keys[i] = k
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID: userID, ServerID: 0, Protocol: "awg", ClientID: keys[i],
			ClientParams: map[string]any{"assigned_ip": ip},
		}); err != nil {
			t.Fatal(err)
		}
	}
	ps, _, _ := newTestPeerSynchronizer(t, svc, db)
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile with invalid rows: %v", err)
	}

	stats := ps.Status()
	if stats.InvalidRows < 2 {
		t.Fatalf("precondition: the colliding rows must be reported invalid, got %+v", stats)
	}
	conds := evaluatePeerSyncAndBackendConditions(&stats, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	if !hasCondition(conds, "peer_sync", "DEGRADED") {
		t.Fatalf("invalid durable rows must degrade peer_sync health, got %+v", conds)
	}
	var msg string
	for _, c := range conds {
		if c.Category == "peer_sync" && c.Severity == "DEGRADED" && strings.Contains(c.Message, "invalid durable peer row") {
			msg = c.Message
		}
	}
	if msg == "" {
		t.Fatalf("the condition must name the invalid rows, got %+v", conds)
	}
	if !strings.Contains(msg, "until the rows are repaired") {
		t.Errorf("the condition must say what clears it, got %q", msg)
	}
}

// TestInvalidDurableRowsClearWhenRepaired is the item G recovery path. The same
// producer and consumer, with the durable rows genuinely repaired: the count
// returns to 0 and health recovers.
func TestInvalidDurableRowsClearWhenRepaired(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	userID, err := db.CreateUser(ctx, &models.User{Username: "sync-invalid-repair", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const ip = "10.100.7.12"
	keys := make([]string, 2)
	ids := make([]string, 2)
	for i := range keys {
		_, k := engineKeys(t)
		keys[i] = k
		id, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID: userID, ServerID: 0, Protocol: "awg", ClientID: keys[i],
			ClientParams: map[string]any{"assigned_ip": ip},
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	ps, _, _ := newTestPeerSynchronizer(t, svc, db)
	ps.quiesceNotifyWorker()
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile with invalid rows: %v", err)
	}
	broken := ps.Status()
	if broken.InvalidRows < 2 {
		t.Fatalf("precondition: expected invalid rows before repair, got %+v", broken)
	}
	if !hasCondition(evaluatePeerSyncAndBackendConditions(&broken, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{}),
		"peer_sync", "DEGRADED") {
		t.Fatal("precondition: invalid rows must degrade health before repair")
	}

	// Genuine repair: remove every durable row that cannot be resolved. The
	// fixture also seeds a blank row (newIngressEngineService), which is
	// excluded for the same reason, so the repair has to cover it too for
	// InvalidRows to genuinely reach 0.
	conns, err := db.GetAllConnections(ctx)
	if err != nil {
		t.Fatalf("enumerate connections: %v", err)
	}
	if len(conns) != len(ids)+1 {
		t.Fatalf("precondition: expected the two colliding rows plus the seeded blank row, got %d", len(conns))
	}
	for _, c := range conns {
		if ok, err := db.DeleteConnection(ctx, c.ID); err != nil || !ok {
			t.Fatalf("repair: delete connection %s: ok=%v err=%v", c.ID, ok, err)
		}
	}
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile after repair: %v", err)
	}
	repaired := ps.Status()
	if repaired.InvalidRows != 0 {
		t.Fatalf("repair must clear InvalidRows, got %+v", repaired)
	}
	conds := evaluatePeerSyncAndBackendConditions(&repaired, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	if hasCondition(conds, "peer_sync", "DEGRADED") {
		t.Errorf("health must recover once the rows are repaired, got %+v", conds)
	}
}

// TestLifetimeFailureCountersStillDoNotPinHealth is the guard on the round-3
// principle: gating on InvalidRows (a durable level) must not have been
// implemented by reintroducing a gate on the LIFETIME counters, which only ever
// grow.
func TestLifetimeFailureCountersStillDoNotPinHealth(t *testing.T) {
	ps := &PeerSyncStatus{
		DesiredPeers:          3,
		ActualPeers:           3,
		InvalidRows:           0,
		SyncFailures:          99,
		AddFailures:           40,
		RemoveFailures:        30,
		UpdateFailures:        29,
		EnqueueFailures:       11,
		LastEnqueueError:      "transient enqueue failure",
		SyncFailuresRecent:    0,
		EnqueueFailuresRecent: 0,
	}
	conds := evaluatePeerSyncAndBackendConditions(ps, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	for _, c := range conds {
		if c.Category == "peer_sync" && c.Severity == "DEGRADED" {
			t.Errorf("lifetime counters must not degrade current health, got %+v", conds)
		}
	}
}
