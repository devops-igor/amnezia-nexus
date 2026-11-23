package vpn

import (
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Issue #964: an idle peer whose upstream handshake has aged out is not a
// fault. Handshake age is a diagnostic measurement, so it must produce neither
// a health condition nor an actionable problem: it can neither move the
// summary severity nor add a row, an affected entity or a problem count.
//
// The test drives the REAL production path (Service.GetStatus). The handshake
// collector sees a live session whose peer key has no upstream handshake
// record, which is exactly the input both removed producers consumed: the
// sessions/WARNING HealthCondition and the per-session ActionableProblem. The
// stale measurement is asserted PRESENT first, so the absence assertions below
// cannot pass vacuously on an empty snapshot.
func TestGetStatusStaleHandshakeYieldsNoConditionAndNoProblem(t *testing.T) {
	_, fwd, engine, _, _ := newSingleOwnerFixture(t)

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}

	// The health evaluation only runs its producers when the engine reports
	// running; a stopped engine short-circuits to UNAVAILABLE and the sessions
	// producer would never be reached.
	engine.peerSync = &peerSynchronizer{}
	engine.running = true
	svc.mu.Lock()
	svc.forwarder = fwd
	svc.ingressEngine = engine
	svc.running = true
	svc.mu.Unlock()

	userID, err := db.CreateUser(t.Context(), &models.User{
		Username: "stale-handshake-user", Role: models.RoleUser, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	backendID := round5Backend(t, db, t.Context(), "stale-handshake-backend")

	// A live session whose peer key has no entry in the upstream portal: the
	// handshake collector classifies it stale.
	if _, err := svc.sessionMgr.CreateSession(t.Context(), userID, round5PeerKeyA,
		"10.100.0.9", backendID, "conn-stale-handshake"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	// Fixture validity: the raw diagnostic measurement IS present in the
	// payload. It is a measurement, not a classification, and it stays.
	if len(status.HandshakeFreshness.StaleLiveSessions) == 0 {
		t.Fatal("fixture did not populate handshake_freshness.stale_live_sessions; " +
			"no stale handshake is actually present, so the no-signal assertions would be vacuous")
	}

	// Producer one: no health condition, so the summary cannot describe it and
	// no severity can be derived from it.
	for _, c := range status.HealthAssessment.Conditions {
		if c.MessageKey == "vpn_problem_stale_handshake" {
			t.Errorf("health condition for a stale upstream handshake: %+v", c)
		}
		if c.Category == "sessions" {
			t.Errorf("sessions health condition produced from handshake age: %+v", c)
		}
	}

	// Producer two: no actionable problem, so no row, affected entity,
	// highlight or problem count comes from handshake age.
	for _, p := range status.HealthAssessment.ActionableProblems {
		if p.MessageKey == "vpn_problem_stale_handshake" {
			t.Errorf("actionable problem for a stale upstream handshake: %+v", p)
		}
		if p.Category == "sessions" {
			t.Errorf("sessions actionable problem produced from handshake age: %+v", p)
		}
	}

	if summary := status.HealthAssessment.Summary; strings.Contains(strings.ToLower(summary), "handshake") {
		t.Errorf("health summary describes handshake age: %q", summary)
	}
}

// The same property for an otherwise healthy fleet: a stale upstream handshake
// must leave the assessment HEALTHY with no conditions at all.
//
// On the previous code this test fails at the conditions assertion, because
// EvaluateForwarderHealth turned a non-empty stale-session list into a
// sessions/WARNING condition. The freshness section is still part of the
// status document, so it stays an argument of the evaluator; the assignment is
// deliberate, and this test is what keeps it non-classifying.
func TestStaleHandshakeHealthyFleetStaysHealthy(t *testing.T) {
	now := time.Now().UTC()

	sessions := []Session{{
		ID:              "sess-stale",
		UserID:          "user-stale",
		Username:        "user-stale",
		ConnectionID:    "conn-stale",
		ConnectionName:  "user-stale-client",
		PeerPublicKey:   "pk-stale",
		AssignedIP:      "10.8.0.60",
		BackendTunnelID: 106,
		ConnectedAt:     now.Add(-10 * time.Minute),
		Status:          "connected",
	}}
	routes := []forwarder.RouteInfo{{
		PeerKey:         "pk-stale",
		AssignedIP:      "10.8.0.60",
		SessionID:       "sess-stale",
		ConnectionID:    "conn-stale",
		BackendTunnelID: 106,
	}}

	// The session is routable, so the surviving synthesisers have nothing to
	// report: the fleet is healthy apart from the aged handshake.
	problems := SynthesizeActionableProblemsAt(routes, sessions, now)
	if len(problems) != 0 {
		t.Fatalf("a routable session with an aged handshake produced %d problem(s): %+v", len(problems), problems)
	}

	queue := QueuePressureDiagnostics{Occupancy: 10, Capacity: 1000, UtilizationPct: 1.0, HighWaterPct: 5.0}
	latency := ForwardLatencyDiagnostics{P50MS: 1.5, P95MS: 5.0, P99MS: 8.0, OldestInFlightMS: 10}
	drops := DropCategoryBreakdown{TotalDrops: 0, TotalDropRatePps: 0}
	vtun := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5, Peak: 20},
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5, Peak: 20},
	}
	peerSync := &PeerSyncStatus{DesiredPeers: 10, ActualPeers: 10}
	routing := RoutingConsistencyDiagnostics{ActiveSessionsCount: 1, ActiveRoutesCount: 1, ReturnOwnersCount: 1, IsConsistent: true}
	backends := BackendsDiagnostics{HealthyCount: 2, TotalCount: 2, LatencyP95MS: 15}
	handshake := HandshakeFreshnessDiagnostics{TotalPeers: 2, StaleLiveSessions: []string{"pk-stale"}}

	health := EvaluateForwarderHealth(true, true, queue, latency, drops, vtun,
		peerSync, routing, handshake, backends, problems...)

	if health.Status != HealthHealthy {
		t.Fatalf("a healthy fleet with one aged handshake must stay HEALTHY, got %s (%s)",
			health.Status, health.Summary)
	}
	if len(health.Conditions) != 0 {
		t.Fatalf("a healthy fleet with one aged handshake must emit no condition, got %+v", health.Conditions)
	}
	for _, p := range health.ActionableProblems {
		if p.MessageKey == "vpn_problem_stale_handshake" || p.Category == "sessions" {
			t.Errorf("actionable problem produced from handshake age: %+v", p)
		}
	}
}
