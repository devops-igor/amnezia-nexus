package vpn

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

func TestProblemRouteItem_IncludesSessionAndConnectionID(t *testing.T) {
	routes := []forwarder.RouteInfo{
		{
			PeerKey:         "client-peer-key-1",
			AssignedIP:      "10.8.0.2",
			SessionID:       "sess-test-1",
			ConnectionID:    "conn-test-1",
			BackendTunnelID: 42,
			HasPressure:     true,
			Stats: forwarder.RouteQueueStats{
				Occupancy:            50,
				Capacity:             100,
				HighWater:            80,
				QueueFullDrops:       10,
				QueueFullDropsRecent: 5,
				P95WriteMS:           15,
				P95WriteSamples:      60,
				MaxWriteDurationMS:   35,
			},
		},
	}

	items := collectProblemRoutes(routes)
	if len(items) != 1 {
		t.Fatalf("expected 1 ProblemRouteItem, got %d", len(items))
	}

	item := items[0]
	if item.SessionID != "sess-test-1" {
		t.Errorf("expected SessionID 'sess-test-1', got %q", item.SessionID)
	}
	if item.ConnectionID != "conn-test-1" {
		t.Errorf("expected ConnectionID 'conn-test-1', got %q", item.ConnectionID)
	}
	if item.Reservoir == nil {
		t.Fatal("expected Reservoir to be populated, got nil")
	}
	if item.Reservoir.P95MS != 15.0 || item.Reservoir.Samples != 60 || item.Reservoir.MaxMS != 35.0 {
		t.Errorf("unexpected Reservoir stats: %+v", item.Reservoir)
	}

	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	raw := string(data)
	if !strings.Contains(raw, `"session_id":"sess-test-1"`) {
		t.Errorf("JSON missing session_id: %s", raw)
	}
	if !strings.Contains(raw, `"connection_id":"conn-test-1"`) {
		t.Errorf("JSON missing connection_id: %s", raw)
	}
	if !strings.Contains(raw, `"reservoir"`) {
		t.Errorf("JSON missing reservoir: %s", raw)
	}
}

func TestSynthesizeActionableProblems_PopulatesIdentityFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	sessions := []Session{
		{
			ID:              "sess-unroutable",
			UserID:          "user-1",
			ConnectionName:  "user1-laptop",
			PeerPublicKey:   "pk-unroutable",
			AssignedIP:      "10.8.0.10",
			BackendTunnelID: 101,
			ConnectedAt:     now.Add(-10 * time.Minute),
			Status:          "connected",
		},
		{
			ID:              "sess-drops",
			UserID:          "user-2",
			ConnectionName:  "user2-phone",
			PeerPublicKey:   "pk-drops",
			AssignedIP:      "10.8.0.20",
			BackendTunnelID: 102,
			ConnectedAt:     now.Add(-5 * time.Minute),
			Status:          "connected",
		},
		{
			ID:              "sess-stalls",
			UserID:          "user-3",
			ConnectionName:  "user3-desktop",
			PeerPublicKey:   "pk-stalls",
			AssignedIP:      "10.8.0.30",
			BackendTunnelID: 103,
			ConnectedAt:     now.Add(-2 * time.Minute),
			Status:          "connected",
		},
		{
			ID:              "sess-healthy",
			UserID:          "user-4",
			ConnectionName:  "user4-home",
			PeerPublicKey:   "pk-healthy",
			AssignedIP:      "10.8.0.40",
			BackendTunnelID: 104,
			ConnectedAt:     now.Add(-20 * time.Minute),
			Status:          "connected",
		},
	}

	routes := []forwarder.RouteInfo{
		{
			PeerKey:         "pk-drops",
			AssignedIP:      "10.8.0.20",
			SessionID:       "sess-drops",
			ConnectionID:    "conn-2",
			BackendTunnelID: 102,
			HasPressure:     true,
			Stats: forwarder.RouteQueueStats{
				QueueFullDrops:       15,
				QueueFullDropsRecent: 5,
			},
		},
		{
			PeerKey:         "pk-stalls",
			AssignedIP:      "10.8.0.30",
			SessionID:       "sess-stalls",
			ConnectionID:    "conn-3",
			BackendTunnelID: 103,
			HasPressure:     true,
			Stats: forwarder.RouteQueueStats{
				OldestWriteMS:     2500,
				WriteStallsRecent: 2,
			},
		},
		{
			PeerKey:         "pk-healthy",
			AssignedIP:      "10.8.0.40",
			SessionID:       "sess-healthy",
			ConnectionID:    "conn-4",
			BackendTunnelID: 104,
			HasPressure:     false,
			Stats: forwarder.RouteQueueStats{
				QueueFullDrops:       100, // Historical drops ONLY; no recent drops
				QueueFullDropsRecent: 0,
			},
		},
	}

	problems := SynthesizeActionableProblemsAt(routes, sessions, now)
	if len(problems) != 3 {
		t.Fatalf("expected 3 actionable problems (unroutable, drops, stalls), got %d: %+v", len(problems), problems)
	}

	var unroutableProb, dropsProb, stallsProb *ActionableProblem
	for i := range problems {
		p := &problems[i]
		switch p.MessageKey {
		case "vpn_problem_session_without_route":
			unroutableProb = p
		case "vpn_problem_route_queue_drops":
			dropsProb = p
		case "vpn_problem_write_stall":
			stallsProb = p
		}
	}

	if unroutableProb == nil {
		t.Fatal("missing vpn_problem_session_without_route problem")
	}
	if unroutableProb.Severity != "CRITICAL" {
		t.Errorf("unroutable severity: got %q, want CRITICAL", unroutableProb.Severity)
	}
	if unroutableProb.Category != "routing" {
		t.Errorf("unroutable category: got %q, want routing", unroutableProb.Category)
	}
	if unroutableProb.UserID != "user-1" {
		t.Errorf("unroutable user_id: got %q, want user-1", unroutableProb.UserID)
	}
	if unroutableProb.ConnectionName != "user1-laptop" {
		t.Errorf("unroutable connection_name: got %q, want user1-laptop", unroutableProb.ConnectionName)
	}
	if unroutableProb.AssignedIP != "10.8.0.10" {
		t.Errorf("unroutable assigned_ip: got %q, want 10.8.0.10", unroutableProb.AssignedIP)
	}
	if unroutableProb.BackendID != 101 {
		t.Errorf("unroutable backend_id: got %d, want 101", unroutableProb.BackendID)
	}
	if unroutableProb.FirstObserved.Equal(sessions[0].ConnectedAt) {
		t.Errorf("unroutable first_observed must not equal ConnectedAt: got %v", unroutableProb.FirstObserved)
	}
	if !unroutableProb.FirstObserved.Equal(now) {
		t.Errorf("unroutable first_observed: got %v, want onset %v", unroutableProb.FirstObserved, now)
	}

	if dropsProb == nil {
		t.Fatal("missing vpn_problem_route_queue_drops problem")
	}
	if dropsProb.Severity != "DEGRADED" {
		t.Errorf("drops severity: got %q, want DEGRADED", dropsProb.Severity)
	}
	if dropsProb.Category != "dataplane" {
		t.Errorf("drops category: got %q, want dataplane", dropsProb.Category)
	}
	if dropsProb.UserID != "user-2" {
		t.Errorf("drops user_id: got %q, want user-2", dropsProb.UserID)
	}
	if dropsProb.ConnectionID != "conn-2" {
		t.Errorf("drops connection_id: got %q, want conn-2", dropsProb.ConnectionID)
	}
	if dropsProb.ConnectionName != "user2-phone" {
		t.Errorf("drops connection_name: got %q, want user2-phone", dropsProb.ConnectionName)
	}
	if dropsProb.AssignedIP != "10.8.0.20" {
		t.Errorf("drops assigned_ip: got %q, want 10.8.0.20", dropsProb.AssignedIP)
	}
	if dropsProb.BackendID != 102 {
		t.Errorf("drops backend_id: got %d, want 102", dropsProb.BackendID)
	}
	if dropsProb.ObservedRate != "5 drops/window" {
		t.Errorf("drops observed_rate: got %q, want '5 drops/window'", dropsProb.ObservedRate)
	}
	if dropsProb.FirstObserved.Equal(sessions[1].ConnectedAt) {
		t.Errorf("drops first_observed must not equal ConnectedAt: got %v", dropsProb.FirstObserved)
	}
	if !dropsProb.FirstObserved.Equal(now) {
		t.Errorf("drops first_observed: got %v, want onset %v", dropsProb.FirstObserved, now)
	}

	if stallsProb == nil {
		t.Fatal("missing vpn_problem_write_stall problem")
	}
	if stallsProb.Severity != "CRITICAL" {
		t.Errorf("stalls severity: got %q, want CRITICAL", stallsProb.Severity)
	}
	if stallsProb.Category != "dataplane" {
		t.Errorf("stalls category: got %q, want dataplane", stallsProb.Category)
	}
	if stallsProb.UserID != "user-3" {
		t.Errorf("stalls user_id: got %q, want user-3", stallsProb.UserID)
	}
	if stallsProb.ConnectionID != "conn-3" {
		t.Errorf("stalls connection_id: got %q, want conn-3", stallsProb.ConnectionID)
	}
	if stallsProb.ConnectionName != "user3-desktop" {
		t.Errorf("stalls connection_name: got %q, want user3-desktop", stallsProb.ConnectionName)
	}
	if stallsProb.AssignedIP != "10.8.0.30" {
		t.Errorf("stalls assigned_ip: got %q, want 10.8.0.30", stallsProb.AssignedIP)
	}
	if stallsProb.BackendID != 103 {
		t.Errorf("stalls backend_id: got %d, want 103", stallsProb.BackendID)
	}
	if stallsProb.FirstObserved.Equal(sessions[2].ConnectedAt) {
		t.Errorf("stalls first_observed must not equal ConnectedAt: got %v", stallsProb.FirstObserved)
	}
	expectedStallOnset := now.Add(-time.Duration(routes[1].Stats.OldestWriteMS) * time.Millisecond)
	if !stallsProb.FirstObserved.Equal(expectedStallOnset) {
		t.Errorf("stalls first_observed: got %v, want onset %v", stallsProb.FirstObserved, expectedStallOnset)
	}

	for _, p := range problems {
		if p.AssignedIP == "10.8.0.40" {
			t.Errorf("healthy route with historical drops only must not be flagged as active problem: %+v", p)
		}
	}
}

func TestSynthesizeActionableProblems_StaleHandshakes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	freshSession := Session{
		ID:              "sess-fresh",
		UserID:          "user-fresh",
		Username:        "user-fresh",
		ConnectionID:    "conn-fresh",
		ConnectionName:  "user-fresh-client",
		PeerPublicKey:   "pk-fresh",
		AssignedIP:      "10.8.0.50",
		BackendTunnelID: 105,
		ConnectedAt:     now.Add(-10 * time.Minute),
		Status:          "connected",
	}

	staleSession := Session{
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
	}

	sessions := []Session{freshSession, staleSession}

	// Supply matching routes with no pressure so only handshake issues can trigger problems
	routes := []forwarder.RouteInfo{
		{
			PeerKey:         "pk-fresh",
			AssignedIP:      "10.8.0.50",
			SessionID:       "sess-fresh",
			ConnectionID:    "conn-fresh",
			BackendTunnelID: 105,
		},
		{
			PeerKey:         "pk-stale",
			AssignedIP:      "10.8.0.60",
			SessionID:       "sess-stale",
			ConnectionID:    "conn-stale",
			BackendTunnelID: 106,
		},
	}

	// Case 1: peerHandshakes == nil -> returns nil (telemetry unavailable)
	t.Run("nil_peer_handshakes_returns_nil", func(t *testing.T) {
		nilProblems := SynthesizeActionableProblemsWithHandshakes(routes, sessions, nil, now)
		if len(nilProblems) != 0 {
			t.Errorf("expected 0 problems when peerHandshakes is nil, got %d: %+v", len(nilProblems), nilProblems)
		}

		// Backwards-compatible call without peerHandshakes should not emit stale handshake problem
		compatProblems := SynthesizeActionableProblemsAt(routes, sessions, now)
		if len(compatProblems) != 0 {
			t.Errorf("expected 0 problems from SynthesizeActionableProblemsAt, got %d: %+v", len(compatProblems), compatProblems)
		}
	})

	// Case 2: peerHandshakes != nil && len(peerHandshakes) == 0 -> emits ActionableProblem for active session (peer missing in portal)
	t.Run("empty_non_nil_peer_handshakes_emits_problems", func(t *testing.T) {
		emptyHandshakes := make(map[string]time.Time)
		problems := SynthesizeActionableProblemsWithHandshakes(routes, sessions, emptyHandshakes, now)
		if len(problems) != 2 {
			t.Fatalf("expected 2 problems for active sessions missing from peer snapshot, got %d: %+v", len(problems), problems)
		}

		for _, prob := range problems {
			if prob.MessageKey != "vpn_problem_stale_handshake" {
				t.Errorf("expected MessageKey vpn_problem_stale_handshake, got %q", prob.MessageKey)
			}
			if prob.Severity != "WARNING" {
				t.Errorf("expected Severity WARNING, got %q", prob.Severity)
			}
			if prob.Category != "sessions" {
				t.Errorf("expected Category sessions, got %q", prob.Category)
			}
			switch prob.SessionID {
			case "sess-fresh":
				if prob.UserID != "user-fresh" {
					t.Errorf("expected UserID user-fresh, got %q", prob.UserID)
				}
				if prob.Username != "user-fresh" {
					t.Errorf("expected Username user-fresh, got %q", prob.Username)
				}
				if prob.ConnectionID != "conn-fresh" {
					t.Errorf("expected ConnectionID conn-fresh, got %q", prob.ConnectionID)
				}
				if prob.ConnectionName != "user-fresh-client" {
					t.Errorf("expected ConnectionName user-fresh-client, got %q", prob.ConnectionName)
				}
				if prob.AssignedIP != "10.8.0.50" {
					t.Errorf("expected AssignedIP 10.8.0.50, got %q", prob.AssignedIP)
				}
				if prob.BackendID != 105 {
					t.Errorf("expected BackendID 105, got %d", prob.BackendID)
				}
			case "sess-stale":
				if prob.UserID != "user-stale" {
					t.Errorf("expected UserID user-stale, got %q", prob.UserID)
				}
				if prob.Username != "user-stale" {
					t.Errorf("expected Username user-stale, got %q", prob.Username)
				}
				if prob.ConnectionID != "conn-stale" {
					t.Errorf("expected ConnectionID conn-stale, got %q", prob.ConnectionID)
				}
				if prob.ConnectionName != "user-stale-client" {
					t.Errorf("expected ConnectionName user-stale-client, got %q", prob.ConnectionName)
				}
				if prob.AssignedIP != "10.8.0.60" {
					t.Errorf("expected AssignedIP 10.8.0.60, got %q", prob.AssignedIP)
				}
				if prob.BackendID != 106 {
					t.Errorf("expected BackendID 106, got %d", prob.BackendID)
				}
			default:
				t.Errorf("unexpected SessionID %q", prob.SessionID)
			}
		}
	})

	// Case 3 & 4: peerHandshakes populated with fresh (30s) and stale (> 3m) handshakes
	t.Run("populated_peer_handshakes_stale_and_fresh", func(t *testing.T) {
		peerHandshakes := map[string]time.Time{
			"pk-fresh": now.Add(-30 * time.Second),
			"pk-stale": now.Add(-5 * time.Minute),
		}

		problems := SynthesizeActionableProblemsWithHandshakes(routes, sessions, peerHandshakes, now)
		if len(problems) != 1 {
			t.Fatalf("expected 1 problem for stale session, got %d: %+v", len(problems), problems)
		}

		prob := problems[0]
		if prob.MessageKey != "vpn_problem_stale_handshake" {
			t.Errorf("expected MessageKey vpn_problem_stale_handshake, got %q", prob.MessageKey)
		}
		if prob.Severity != "WARNING" {
			t.Errorf("expected Severity WARNING, got %q", prob.Severity)
		}
		if prob.Category != "sessions" {
			t.Errorf("expected Category sessions, got %q", prob.Category)
		}

		// Verify all identity fields (SessionID, UserID, Username, ConnectionID, ConnectionName, AssignedIP, BackendID)
		if prob.SessionID != "sess-stale" {
			t.Errorf("expected SessionID sess-stale, got %q", prob.SessionID)
		}
		if prob.UserID != "user-stale" {
			t.Errorf("expected UserID user-stale, got %q", prob.UserID)
		}
		if prob.Username != "user-stale" {
			t.Errorf("expected Username user-stale, got %q", prob.Username)
		}
		if prob.ConnectionID != "conn-stale" {
			t.Errorf("expected ConnectionID conn-stale, got %q", prob.ConnectionID)
		}
		if prob.ConnectionName != "user-stale-client" {
			t.Errorf("expected ConnectionName user-stale-client, got %q", prob.ConnectionName)
		}
		if prob.AssignedIP != "10.8.0.60" {
			t.Errorf("expected AssignedIP 10.8.0.60, got %q", prob.AssignedIP)
		}
		if prob.BackendID != 106 {
			t.Errorf("expected BackendID 106, got %d", prob.BackendID)
		}

		// Case 4: Assert fresh session does not emit a problem
		for _, p := range problems {
			if p.SessionID == "sess-fresh" || p.AssignedIP == "10.8.0.50" {
				t.Errorf("fresh session must not emit a problem: %+v", p)
			}
		}
	})
}

func TestPipeline_EmptyPeerSnapshotProducesMatchingConditionAndActionableProblem(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	staleSession := Session{
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
	}

	sessions := []Session{staleSession}
	routes := []forwarder.RouteInfo{
		{
			PeerKey:         "pk-stale",
			AssignedIP:      "10.8.0.60",
			SessionID:       "sess-stale",
			ConnectionID:    "conn-stale",
			BackendTunnelID: 106,
		},
	}

	// Portal device read succeeds with 0 peers: peerHandshakes is non-nil but empty
	emptyHandshakes := make(map[string]time.Time)

	handshakeDiag := HandshakeFreshnessDiagnostics{
		TotalPeers:        0,
		StaleLiveSessions: []string{"pk-stale"},
		PeerHandshakes:    emptyHandshakes,
	}

	var (
		q   QueuePressureDiagnostics
		lat ForwardLatencyDiagnostics
		dr  DropCategoryBreakdown
		vt  VirtualTUNDiagnostics
		rc  RoutingConsistencyDiagnostics
		be  BackendsDiagnostics
	)

	// 1. Collector/evaluator produces HealthCondition with MessageKey "vpn_problem_stale_handshake"
	conds := evaluatePeerSyncAndBackendConditions(nil, be, handshakeDiag)
	var foundCondition bool
	for _, c := range conds {
		if c.MessageKey == "vpn_problem_stale_handshake" {
			foundCondition = true
			if c.Category != "sessions" || c.Severity != "WARNING" {
				t.Errorf("condition category/severity mismatch: %+v", c)
			}
		}
	}
	if !foundCondition {
		t.Fatalf("expected HealthCondition for stale handshake, got: %+v", conds)
	}

	// 2. Synthesizer produces matching ActionableProblem
	problems := SynthesizeActionableProblemsWithHandshakes(routes, sessions, emptyHandshakes, now)
	if len(problems) != 1 {
		t.Fatalf("expected 1 actionable problem, got %d: %+v", len(problems), problems)
	}
	prob := problems[0]
	if prob.MessageKey != "vpn_problem_stale_handshake" {
		t.Errorf("expected MessageKey vpn_problem_stale_handshake, got %q", prob.MessageKey)
	}
	if prob.UserID != "user-stale" || prob.Username != "user-stale" || prob.ConnectionID != "conn-stale" || prob.ConnectionName != "user-stale-client" {
		t.Errorf("identity attribution mismatch: %+v", prob)
	}

	// 3. HealthAssessment includes both the condition and the actionable problem
	health := EvaluateForwarderHealth(
		true,
		true,
		q,
		lat,
		dr,
		vt,
		nil,
		rc,
		handshakeDiag,
		be,
		prob,
	)

	var hasMatchingCond bool
	for _, c := range health.Conditions {
		if c.MessageKey == "vpn_problem_stale_handshake" {
			hasMatchingCond = true
			break
		}
	}
	if !hasMatchingCond {
		t.Errorf("expected health.Conditions to contain vpn_problem_stale_handshake")
	}
	if len(health.ActionableProblems) != 1 {
		t.Errorf("expected 1 actionable problem in health assessment, got %d", len(health.ActionableProblems))
	}
}

func TestSynthesizeActionableProblems_OnsetSemanticsTable(t *testing.T) {
	now := time.Date(2026, 10, 8, 15, 30, 0, 0, time.UTC)
	connectedAt := now.Add(-3 * time.Hour) // User connected 3 hours ago

	tests := []struct {
		name              string
		routes            []forwarder.RouteInfo
		sessions          []Session
		wantKey           string
		wantFirstObserved time.Time
	}{
		{
			name:   "unroutable session onset is observation time, not connectedAt",
			routes: []forwarder.RouteInfo{},
			sessions: []Session{
				{
					ID:          "sess-unrouted",
					Status:      "connected",
					AssignedIP:  "10.8.0.50",
					ConnectedAt: connectedAt,
				},
			},
			wantKey:           "vpn_problem_session_without_route",
			wantFirstObserved: now,
		},
		{
			name: "route queue full drops onset is observation time",
			routes: []forwarder.RouteInfo{
				{
					SessionID:  "sess-drops",
					AssignedIP: "10.8.0.51",
					Stats: forwarder.RouteQueueStats{
						QueueFullDropsRecent: 4,
					},
				},
			},
			sessions: []Session{
				{
					ID:          "sess-drops",
					Status:      "connected",
					AssignedIP:  "10.8.0.51",
					ConnectedAt: connectedAt,
				},
			},
			wantKey:           "vpn_problem_route_queue_drops",
			wantFirstObserved: now,
		},
		{
			name: "write stall with oldest write onset reflects tracking duration",
			routes: []forwarder.RouteInfo{
				{
					SessionID:  "sess-stall",
					AssignedIP: "10.8.0.52",
					Stats: forwarder.RouteQueueStats{
						OldestWriteMS:     3500,
						WriteStallsRecent: 1,
					},
				},
			},
			sessions: []Session{
				{
					ID:          "sess-stall",
					Status:      "connected",
					AssignedIP:  "10.8.0.52",
					ConnectedAt: connectedAt,
				},
			},
			wantKey:           "vpn_problem_write_stall",
			wantFirstObserved: now.Add(-3500 * time.Millisecond),
		},
		{
			name: "write stall without oldest write onset is observation time",
			routes: []forwarder.RouteInfo{
				{
					SessionID:  "sess-stall-recent",
					AssignedIP: "10.8.0.53",
					Stats: forwarder.RouteQueueStats{
						OldestWriteMS:     0,
						WriteStallsRecent: 2,
					},
				},
			},
			sessions: []Session{
				{
					ID:          "sess-stall-recent",
					Status:      "connected",
					AssignedIP:  "10.8.0.53",
					ConnectedAt: connectedAt,
				},
			},
			wantKey:           "vpn_problem_write_stall",
			wantFirstObserved: now,
		},
		{
			name: "write errors onset is observation time",
			routes: []forwarder.RouteInfo{
				{
					SessionID:  "sess-err",
					AssignedIP: "10.8.0.54",
					Stats: forwarder.RouteQueueStats{
						WriteErrorsRecent: 3,
					},
				},
			},
			sessions: []Session{
				{
					ID:          "sess-err",
					Status:      "connected",
					AssignedIP:  "10.8.0.54",
					ConnectedAt: connectedAt,
				},
			},
			wantKey:           "vpn_problem_write_errors",
			wantFirstObserved: now,
		},
		{
			name: "queue pressure onset is observation time",
			routes: []forwarder.RouteInfo{
				{
					SessionID:   "sess-press",
					AssignedIP:  "10.8.0.55",
					HasPressure: true,
					Stats: forwarder.RouteQueueStats{
						Occupancy: 80,
						Capacity:  100,
					},
				},
			},
			sessions: []Session{
				{
					ID:          "sess-press",
					Status:      "connected",
					AssignedIP:  "10.8.0.55",
					ConnectedAt: connectedAt,
				},
			},
			wantKey:           "vpn_problem_route_queue_pressure",
			wantFirstObserved: now,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probs := SynthesizeActionableProblemsAt(tt.routes, tt.sessions, now)
			if len(probs) != 1 {
				t.Fatalf("expected 1 problem, got %d: %+v", len(probs), probs)
			}
			p := probs[0]
			if p.MessageKey != tt.wantKey {
				t.Errorf("MessageKey = %q, want %q", p.MessageKey, tt.wantKey)
			}
			if p.FirstObserved.Equal(connectedAt) {
				t.Errorf("FirstObserved must NEVER equal ConnectedAt (%v)", connectedAt)
			}
			if !p.FirstObserved.Equal(tt.wantFirstObserved) {
				t.Errorf("FirstObserved = %v, want %v", p.FirstObserved, tt.wantFirstObserved)
			}
		})
	}
}

func TestBackendCorrelation_DoesNotMisattributeContradictoryIP(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	// Stale route on IP 10.8.0.10 with old session/peer identity and packet drops
	staleRoute := forwarder.RouteInfo{
		PeerKey:         "pk-stale-1",
		SessionID:       "sess-stale-1",
		ConnectionID:    "conn-stale-1",
		AssignedIP:      "10.8.0.10",
		BackendTunnelID: 101,
		HasPressure:     true,
		Stats: forwarder.RouteQueueStats{
			QueueFullDrops:       20,
			QueueFullDropsRecent: 5,
		},
	}

	// New active session on same IP 10.8.0.10 with distinct session/peer identity
	newSession := Session{
		ID:              "sess-new-2",
		UserID:          "user-alice",
		ConnectionName:  "alice-laptop",
		PeerPublicKey:   "pk-new-2",
		AssignedIP:      "10.8.0.10",
		BackendTunnelID: 101,
		ConnectedAt:     now.Add(-5 * time.Minute),
		Status:          "connected",
	}

	t.Run("findSessionForRoute refuses contradictory durable IDs on same IP", func(t *testing.T) {
		matched, found := findSessionForRoute(staleRoute, []Session{newSession})
		if found {
			t.Fatalf("expected findSessionForRoute to refuse correlation for contradictory durable IDs on same IP, got session: %+v", matched)
		}
	})

	t.Run("stale route does not suppress unroutable session problem for new session", func(t *testing.T) {
		problems := SynthesizeActionableProblemsAt([]forwarder.RouteInfo{staleRoute}, []Session{newSession}, now)

		var unroutableProb *ActionableProblem
		var routeDropsProb *ActionableProblem
		for i := range problems {
			p := &problems[i]
			switch p.MessageKey {
			case "vpn_problem_session_without_route":
				unroutableProb = p
			case "vpn_problem_route_queue_drops":
				routeDropsProb = p
			}
		}

		if unroutableProb == nil {
			t.Fatalf("expected vpn_problem_session_without_route for newSession, got problems: %+v", problems)
		}
		if unroutableProb.UserID != "user-alice" {
			t.Errorf("unroutable problem UserID = %q, want user-alice", unroutableProb.UserID)
		}
		if unroutableProb.SessionID != "sess-new-2" {
			t.Errorf("unroutable problem SessionID = %q, want sess-new-2", unroutableProb.SessionID)
		}
		if unroutableProb.AssignedIP != "10.8.0.10" {
			t.Errorf("unroutable problem AssignedIP = %q, want 10.8.0.10", unroutableProb.AssignedIP)
		}

		// The route problem must NOT be attributed to user-alice
		if routeDropsProb == nil {
			t.Fatalf("expected vpn_problem_route_queue_drops on stale route, got problems: %+v", problems)
		}
		if routeDropsProb.UserID != "" {
			t.Errorf("stale route problem must NOT carry new session's UserID, got %q", routeDropsProb.UserID)
		}
		if routeDropsProb.ConnectionName != "" {
			t.Errorf("stale route problem must NOT carry new session's ConnectionName, got %q", routeDropsProb.ConnectionName)
		}
	})

	t.Run("untagged route on same IP successfully routes session", func(t *testing.T) {
		untaggedRoute := forwarder.RouteInfo{
			PeerKey:         "",
			SessionID:       "",
			ConnectionID:    "",
			AssignedIP:      "10.8.0.10",
			BackendTunnelID: 101,
		}
		matched, found := findSessionForRoute(untaggedRoute, []Session{newSession})
		if !found {
			t.Fatal("expected findSessionForRoute to match untagged route by IP")
		}
		if matched.ID != newSession.ID {
			t.Errorf("matched ID = %q, want %q", matched.ID, newSession.ID)
		}

		problems := SynthesizeActionableProblemsAt([]forwarder.RouteInfo{untaggedRoute}, []Session{newSession}, now)
		for _, p := range problems {
			if p.MessageKey == "vpn_problem_session_without_route" {
				t.Fatalf("untagged route should have routed newSession, but found unroutable problem: %+v", p)
			}
		}
	})
}

func TestActionableProblemOnset_PreservedAcrossPolls(t *testing.T) {
	tracker := NewProblemOnsetTracker()
	baseTime := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)

	activeRoute := forwarder.RouteInfo{
		PeerKey:         "pk-client-1",
		SessionID:       "sess-client-1",
		ConnectionID:    "conn-client-1",
		AssignedIP:      "10.8.0.22",
		BackendTunnelID: 42,
		HasPressure:     true,
		Stats: forwarder.RouteQueueStats{
			QueueFullDrops:       10,
			QueueFullDropsRecent: 5,
		},
	}
	activeSession := Session{
		ID:              "sess-client-1",
		UserID:          "user-bob",
		ConnectionName:  "bob-phone",
		PeerPublicKey:   "pk-client-1",
		AssignedIP:      "10.8.0.22",
		BackendTunnelID: 42,
		Status:          "connected",
		ConnectedAt:     baseTime.Add(-1 * time.Hour),
	}

	t.Run("first observation establishes initial onset", func(t *testing.T) {
		t0 := baseTime
		probs := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{activeRoute}, []Session{activeSession}, t0, tracker)
		if len(probs) != 1 {
			t.Fatalf("expected 1 problem, got %d", len(probs))
		}
		if !probs[0].FirstObserved.Equal(t0) {
			t.Errorf("FirstObserved = %v, want %v", probs[0].FirstObserved, t0)
		}
	})

	t.Run("subsequent polls while problem remains active preserve original onset", func(t *testing.T) {
		t1 := baseTime.Add(5 * time.Second)
		routeStillDropping := activeRoute
		routeStillDropping.Stats.QueueFullDropsRecent = 8
		probs := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{routeStillDropping}, []Session{activeSession}, t1, tracker)
		if len(probs) != 1 {
			t.Fatalf("expected 1 problem, got %d", len(probs))
		}
		if !probs[0].FirstObserved.Equal(baseTime) {
			t.Errorf("FirstObserved shifted to %v; expected original onset %v preserved", probs[0].FirstObserved, baseTime)
		}

		t2 := baseTime.Add(10 * time.Second)
		probs2 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{routeStillDropping}, []Session{activeSession}, t2, tracker)
		if len(probs2) != 1 {
			t.Fatalf("expected 1 problem, got %d", len(probs2))
		}
		if !probs2[0].FirstObserved.Equal(baseTime) {
			t.Errorf("FirstObserved shifted to %v; expected original onset %v preserved", probs2[0].FirstObserved, baseTime)
		}
	})

	t.Run("problem resolution clears onset from tracker", func(t *testing.T) {
		tRecovered := baseTime.Add(15 * time.Second)
		recoveredRoute := activeRoute
		recoveredRoute.HasPressure = false
		recoveredRoute.Stats.QueueFullDropsRecent = 0
		probs := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{recoveredRoute}, []Session{activeSession}, tRecovered, tracker)
		if len(probs) != 0 {
			t.Fatalf("expected 0 problems after recovery, got %d", len(probs))
		}

		// Ensure key was pruned from tracker internal map
		tracker.mu.Lock()
		count := len(tracker.onsets)
		tracker.mu.Unlock()
		if count != 0 {
			t.Fatalf("expected tracker to have 0 onsets after resolution, got %d", count)
		}
	})

	t.Run("re-occurring impairment receives fresh onset timestamp", func(t *testing.T) {
		tReoccurred := baseTime.Add(20 * time.Second)
		probs := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{activeRoute}, []Session{activeSession}, tReoccurred, tracker)
		if len(probs) != 1 {
			t.Fatalf("expected 1 problem, got %d", len(probs))
		}
		if !probs[0].FirstObserved.Equal(tReoccurred) {
			t.Errorf("FirstObserved = %v, want fresh onset %v", probs[0].FirstObserved, tReoccurred)
		}
	})

	t.Run("write stall back-computed onset is preserved across polls", func(t *testing.T) {
		stallTracker := NewProblemOnsetTracker()
		t0 := baseTime
		stallRoute := forwarder.RouteInfo{
			PeerKey:         "pk-stall",
			SessionID:       "sess-stall",
			ConnectionID:    "conn-stall",
			AssignedIP:      "10.8.0.33",
			BackendTunnelID: 42,
			HasPressure:     true,
			Stats: forwarder.RouteQueueStats{
				OldestWriteMS:     3000,
				WriteStallsRecent: 1,
			},
		}
		stallSession := Session{
			ID:              "sess-stall",
			UserID:          "user-charlie",
			PeerPublicKey:   "pk-stall",
			AssignedIP:      "10.8.0.33",
			BackendTunnelID: 42,
			Status:          "connected",
		}

		probs1 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{stallRoute}, []Session{stallSession}, t0, stallTracker)
		if len(probs1) != 1 {
			t.Fatalf("expected 1 stall problem, got %d", len(probs1))
		}
		expectedInitialOnset := t0.Add(-3000 * time.Millisecond)
		if !probs1[0].FirstObserved.Equal(expectedInitialOnset) {
			t.Errorf("initial stall onset = %v, want %v", probs1[0].FirstObserved, expectedInitialOnset)
		}

		// Later poll at t0 + 5s with growing stall duration
		t1 := t0.Add(5 * time.Second)
		stallRoute.Stats.OldestWriteMS = 8000
		probs2 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{stallRoute}, []Session{stallSession}, t1, stallTracker)
		if len(probs2) != 1 {
			t.Fatalf("expected 1 stall problem, got %d", len(probs2))
		}
		if !probs2[0].FirstObserved.Equal(expectedInitialOnset) {
			t.Errorf("stall onset shifted to %v; want original onset %v", probs2[0].FirstObserved, expectedInitialOnset)
		}
	})

	t.Run("co-occurring drops and write stall on same route retain independent onsets", func(t *testing.T) {
		multiTracker := NewProblemOnsetTracker()
		t0 := baseTime
		multiRoute := forwarder.RouteInfo{
			PeerKey:         "pk-multi",
			SessionID:       "sess-multi",
			ConnectionID:    "conn-multi",
			AssignedIP:      "10.8.0.77",
			BackendTunnelID: 10,
			HasPressure:     true,
			Stats: forwarder.RouteQueueStats{
				QueueFullDrops:       10,
				QueueFullDropsRecent: 4,
				OldestWriteMS:        4000,
				WriteStallsRecent:    1,
			},
		}
		multiSession := Session{
			ID:              "sess-multi",
			UserID:          "user-multi",
			PeerPublicKey:   "pk-multi",
			AssignedIP:      "10.8.0.77",
			BackendTunnelID: 10,
			Status:          "connected",
		}

		// Initial poll: both drops and stalls are active
		p1 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{multiRoute}, []Session{multiSession}, t0, multiTracker)
		if len(p1) != 2 {
			t.Fatalf("expected 2 problems (drops + stall), got %d: %+v", len(p1), p1)
		}
		var dropsP1, stallP1 *ActionableProblem
		for i := range p1 {
			if p1[i].MessageKey == "vpn_problem_route_queue_drops" {
				dropsP1 = &p1[i]
			} else if p1[i].MessageKey == "vpn_problem_write_stall" {
				stallP1 = &p1[i]
			}
		}
		if dropsP1 == nil || stallP1 == nil {
			t.Fatalf("missing expected problems: drops=%v, stall=%v", dropsP1, stallP1)
		}
		if !dropsP1.FirstObserved.Equal(t0) {
			t.Errorf("drops onset = %v, want %v", dropsP1.FirstObserved, t0)
		}
		expectedStallOnset := t0.Add(-4000 * time.Millisecond)
		if !stallP1.FirstObserved.Equal(expectedStallOnset) {
			t.Errorf("stall onset = %v, want %v", stallP1.FirstObserved, expectedStallOnset)
		}

		// Next poll: drops resolve, but stall continues
		t1 := t0.Add(6 * time.Second)
		multiRoute.Stats.QueueFullDropsRecent = 0
		multiRoute.Stats.OldestWriteMS = 9000
		p2 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{multiRoute}, []Session{multiSession}, t1, multiTracker)
		if len(p2) != 1 {
			t.Fatalf("expected 1 problem (stall only), got %d", len(p2))
		}
		if p2[0].MessageKey != "vpn_problem_write_stall" {
			t.Fatalf("expected write stall problem, got %q", p2[0].MessageKey)
		}
		if !p2[0].FirstObserved.Equal(expectedStallOnset) {
			t.Errorf("stall onset = %v, want original %v", p2[0].FirstObserved, expectedStallOnset)
		}

		// Check tracker: drops key pruned, stall key kept
		multiTracker.mu.Lock()
		activeCount := len(multiTracker.onsets)
		multiTracker.mu.Unlock()
		if activeCount != 1 {
			t.Errorf("expected 1 active onset in tracker, got %d", activeCount)
		}
	})

	t.Run("unroutable session onset is preserved while unrouted and pruned when routed", func(t *testing.T) {
		unroutedTracker := NewProblemOnsetTracker()
		t0 := baseTime
		unroutedSession := Session{
			ID:              "sess-unrouted-1",
			UserID:          "user-dave",
			ConnectionName:  "dave-tablet",
			PeerPublicKey:   "pk-dave",
			AssignedIP:      "10.8.0.88",
			BackendTunnelID: 15,
			Status:          "connected",
			ConnectedAt:     baseTime.Add(-2 * time.Hour),
		}

		// Initial poll: no route exists for this session
		probs1 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{}, []Session{unroutedSession}, t0, unroutedTracker)
		if len(probs1) != 1 {
			t.Fatalf("expected 1 unrouted problem, got %d", len(probs1))
		}
		if probs1[0].MessageKey != "vpn_problem_session_without_route" {
			t.Fatalf("expected vpn_problem_session_without_route, got %q", probs1[0].MessageKey)
		}
		if !probs1[0].FirstObserved.Equal(t0) {
			t.Errorf("unrouted onset = %v, want %v", probs1[0].FirstObserved, t0)
		}

		// Subsequent poll: still unrouted at t0 + 10s
		t1 := t0.Add(10 * time.Second)
		probs2 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{}, []Session{unroutedSession}, t1, unroutedTracker)
		if len(probs2) != 1 {
			t.Fatalf("expected 1 unrouted problem, got %d", len(probs2))
		}
		if !probs2[0].FirstObserved.Equal(t0) {
			t.Errorf("unrouted onset shifted to %v, want preserved %v", probs2[0].FirstObserved, t0)
		}

		// Route is added: problem resolves
		t2 := t0.Add(20 * time.Second)
		matchingRoute := forwarder.RouteInfo{
			PeerKey:         "pk-dave",
			SessionID:       "sess-unrouted-1",
			ConnectionID:    "conn-dave",
			AssignedIP:      "10.8.0.88",
			BackendTunnelID: 15,
		}
		probs3 := SynthesizeActionableProblemsWithTracker([]forwarder.RouteInfo{matchingRoute}, []Session{unroutedSession}, t2, unroutedTracker)
		if len(probs3) != 0 {
			t.Fatalf("expected 0 problems once routed, got %d", len(probs3))
		}

		// Verify tracker pruned key
		unroutedTracker.mu.Lock()
		count := len(unroutedTracker.onsets)
		unroutedTracker.mu.Unlock()
		if count != 0 {
			t.Errorf("expected 0 onsets in tracker after routing, got %d", count)
		}
	})
}

func TestProblemRouteItem_IncludesDropRatePPS(t *testing.T) {
	tests := []struct {
		name         string
		route        forwarder.RouteInfo
		wantRatePPS  float64
		wantHasPress bool
	}{
		{
			name: "computed from recent drops and traffic window",
			route: forwarder.RouteInfo{
				SessionID:    "sess-1",
				ConnectionID: "conn-1",
				AssignedIP:   "10.8.0.11",
				Stats: forwarder.RouteQueueStats{
					QueueFullDrops:       20,
					QueueFullDropsRecent: 5,
					QueueFullDropRatePPS: 2.5,
				},
				Traffic: forwarder.TrafficSnapshot{
					WindowSec: 2.0,
				},
				HasPressure: true,
			},
			wantRatePPS:  2.5,
			wantHasPress: true,
		},
		{
			name: "pre-computed rate on route stats is preserved",
			route: forwarder.RouteInfo{
				SessionID:    "sess-2",
				ConnectionID: "conn-2",
				AssignedIP:   "10.8.0.12",
				Stats: forwarder.RouteQueueStats{
					QueueFullDrops:       100,
					QueueFullDropsRecent: 15,
					QueueFullDropRatePPS: 4.38,
				},
				HasPressure: true,
			},
			wantRatePPS:  4.38,
			wantHasPress: true,
		},
		{
			name: "zero recent drops yields zero drop rate",
			route: forwarder.RouteInfo{
				SessionID:    "sess-3",
				ConnectionID: "conn-3",
				AssignedIP:   "10.8.0.13",
				Stats: forwarder.RouteQueueStats{
					QueueFullDrops:       100,
					QueueFullDropsRecent: 0,
				},
				Traffic: forwarder.TrafficSnapshot{
					WindowSec: 5.0,
				},
				HasPressure: false,
			},
			wantRatePPS:  0.0,
			wantHasPress: false,
		},
		{
			name: "rate comes directly from route stats without borrowing traffic window",
			route: forwarder.RouteInfo{
				SessionID:    "sess-4",
				ConnectionID: "conn-4",
				AssignedIP:   "10.8.0.14",
				Stats: forwarder.RouteQueueStats{
					QueueFullDrops:       10,
					QueueFullDropsRecent: 7,
					QueueFullDropRatePPS: 0.0,
				},
				Traffic: forwarder.TrafficSnapshot{
					WindowSec: 5.0,
				},
				HasPressure: true,
			},
			wantRatePPS:  0.0,
			wantHasPress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := collectProblemRoutes([]forwarder.RouteInfo{tt.route})
			if len(items) != 1 {
				t.Fatalf("expected 1 ProblemRouteItem, got %d", len(items))
			}
			item := items[0]
			if math.Abs(item.QueueFullDropRatePPS-tt.wantRatePPS) > 1e-6 {
				t.Errorf("QueueFullDropRatePPS = %v, want %v", item.QueueFullDropRatePPS, tt.wantRatePPS)
			}

			// Verify JSON marshaling includes queue_full_drop_rate_pps field
			data, err := json.Marshal(item)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			rawRate, ok := m["queue_full_drop_rate_pps"]
			if !ok {
				t.Fatalf("JSON output missing queue_full_drop_rate_pps: %s", string(data))
			}
			rateVal, ok := rawRate.(float64)
			if !ok {
				t.Fatalf("queue_full_drop_rate_pps in JSON is not float64: %T", rawRate)
			}
			if math.Abs(rateVal-tt.wantRatePPS) > 1e-6 {
				t.Errorf("JSON queue_full_drop_rate_pps = %v, want %v", rateVal, tt.wantRatePPS)
			}
		})
	}
}

func TestEnrichActionableProblemsWithDatabase_MultiConfigDisambiguation(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}

	ctx := context.Background()
	_, err = db.ExecContext(ctx, "INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'alice', 'hash', 'user'), ('u2', 'bob', 'hash', 'user')")
	if err != nil {
		t.Fatalf("insert users: %v", err)
	}

	_, err = db.ExecContext(ctx, `INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, name) VALUES
		('conn-1', 'u1', 1, 'awg', 'pk-alice-phone', 'Alice Phone'),
		('conn-2', 'u1', 1, 'awg', 'pk-alice-laptop', 'Alice Laptop'),
		('conn-3', 'u2', 1, 'awg', 'pk-bob-desktop', 'Bob Desktop')`)
	if err != nil {
		t.Fatalf("insert user_connections: %v", err)
	}

	sessions := []Session{
		{
			ID:             "sess-1",
			UserID:         "u1",
			ConnectionName: "Alice Phone",
			PeerPublicKey:  "pk-alice-phone",
		},
		{
			ID:             "sess-2",
			UserID:         "u1",
			ConnectionName: "Alice Laptop",
			PeerPublicKey:  "pk-alice-laptop",
		},
		{
			ID:             "sess-3",
			UserID:         "u2",
			ConnectionName: "Bob Desktop",
			PeerPublicKey:  "pk-bob-desktop",
		},
	}

	p1 := ActionableProblem{
		SessionID: "sess-1",
		UserID:    "u1",
	}
	p2 := ActionableProblem{
		SessionID: "sess-2",
		UserID:    "u1",
	}
	p3 := ActionableProblem{
		SessionID: "",
		UserID:    "u1",
	}
	p4 := ActionableProblem{
		SessionID: "",
		UserID:    "u2",
	}

	enriched := svc.enrichActionableProblemsWithDatabase([]ActionableProblem{p1, p2, p3, p4}, sessions)
	if len(enriched) != 4 {
		t.Fatalf("expected 4 enriched problems, got %d", len(enriched))
	}

	// Assert Problem 1: correlated to sess-1 / conn-1 (Alice Phone)
	if enriched[0].Username != "alice" {
		t.Errorf("p1 username: got %q, want 'alice'", enriched[0].Username)
	}
	if enriched[0].ConnectionID != "conn-1" {
		t.Errorf("p1 connectionID: got %q, want 'conn-1'", enriched[0].ConnectionID)
	}
	if enriched[0].ConnectionName != "Alice Phone" {
		t.Errorf("p1 connectionName: got %q, want 'Alice Phone'", enriched[0].ConnectionName)
	}

	// Assert Problem 2: correlated to sess-2 / conn-2 (Alice Laptop)
	if enriched[1].Username != "alice" {
		t.Errorf("p2 username: got %q, want 'alice'", enriched[1].Username)
	}
	if enriched[1].ConnectionID != "conn-2" {
		t.Errorf("p2 connectionID: got %q, want 'conn-2'", enriched[1].ConnectionID)
	}
	if enriched[1].ConnectionName != "Alice Laptop" {
		t.Errorf("p2 connectionName: got %q, want 'Alice Laptop'", enriched[1].ConnectionName)
	}

	// Assert Problem 3: multi-config user with missing session_id must NOT clobber ConnectionID or ConnectionName
	if enriched[2].Username != "alice" {
		t.Errorf("p3 username: got %q, want 'alice'", enriched[2].Username)
	}
	if enriched[2].ConnectionID != "" {
		t.Errorf("p3 connectionID: expected empty, got %q (must not ambiguously clobber config for multi-session user)", enriched[2].ConnectionID)
	}
	if enriched[2].ConnectionName != "" {
		t.Errorf("p3 connectionName: expected empty, got %q (must not ambiguously clobber config for multi-session user)", enriched[2].ConnectionName)
	}

	// Assert Problem 4: single-session user safely falls back to single active config
	if enriched[3].Username != "bob" {
		t.Errorf("p4 username: got %q, want 'bob'", enriched[3].Username)
	}
	if enriched[3].ConnectionID != "conn-3" {
		t.Errorf("p4 connectionID: got %q, want 'conn-3'", enriched[3].ConnectionID)
	}
	if enriched[3].ConnectionName != "Bob Desktop" {
		t.Errorf("p4 connectionName: got %q, want 'Bob Desktop'", enriched[3].ConnectionName)
	}
}

func TestSynthesizeActionableProblems_ObservedRateFormatting(t *testing.T) {
	now := time.Now()
	sessions := []Session{
		{
			ID:          "sess-1",
			AssignedIP:  "10.8.0.2",
			ConnectedAt: now.Add(-5 * time.Minute),
			Status:      "connected",
		},
	}

	tests := []struct {
		name         string
		route        forwarder.RouteInfo
		wantKey      string
		wantRate     string
		wantSeverity string
	}{
		{
			name: "drops with pps rate",
			route: forwarder.RouteInfo{
				SessionID:   "sess-1",
				AssignedIP:  "10.8.0.2",
				HasPressure: true,
				Stats: forwarder.RouteQueueStats{
					QueueFullDropsRecent: 10,
					QueueFullDropRatePPS: 4.5,
				},
			},
			wantKey:      "vpn_problem_route_queue_drops",
			wantRate:     "4.5 drops/s",
			wantSeverity: "DEGRADED",
		},
		{
			name: "drops fallback to recent drops per window",
			route: forwarder.RouteInfo{
				SessionID:   "sess-1",
				AssignedIP:  "10.8.0.2",
				HasPressure: true,
				Stats: forwarder.RouteQueueStats{
					QueueFullDropsRecent: 7,
					QueueFullDropRatePPS: 0,
				},
			},
			wantKey:      "vpn_problem_route_queue_drops",
			wantRate:     "7 drops/window",
			wantSeverity: "DEGRADED",
		},
		{
			name: "write stall duration ms",
			route: forwarder.RouteInfo{
				SessionID:   "sess-1",
				AssignedIP:  "10.8.0.2",
				HasPressure: true,
				Stats: forwarder.RouteQueueStats{
					OldestWriteMS:     350,
					WriteStallsRecent: 0,
				},
			},
			wantKey:      "vpn_problem_write_stall",
			wantRate:     "350ms stall",
			wantSeverity: "WARNING",
		},
		{
			name: "queue pressure occupancy and percentage",
			route: forwarder.RouteInfo{
				SessionID:   "sess-1",
				AssignedIP:  "10.8.0.2",
				HasPressure: true,
				Stats: forwarder.RouteQueueStats{
					Occupancy: 85,
					Capacity:  100,
				},
			},
			wantKey:      "vpn_problem_route_queue_pressure",
			wantRate:     "85/100 queued (85%)",
			wantSeverity: "WARNING",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := SynthesizeActionableProblemsAt([]forwarder.RouteInfo{tt.route}, sessions, now)
			var matched *ActionableProblem
			for i := range problems {
				if problems[i].MessageKey == tt.wantKey {
					matched = &problems[i]
					break
				}
			}
			if matched == nil {
				t.Fatalf("expected problem with key %q, got %+v", tt.wantKey, problems)
			}
			if matched.ObservedRate != tt.wantRate {
				t.Errorf("ObservedRate: got %q, want %q", matched.ObservedRate, tt.wantRate)
			}
			if matched.Severity != tt.wantSeverity {
				t.Errorf("Severity: got %q, want %q", matched.Severity, tt.wantSeverity)
			}
		})
	}
}

func TestBackendCorrelation_ReconnectContradictorySessionIDDisqualified(t *testing.T) {
	oldRoute := forwarder.RouteInfo{
		SessionID: "old-123",
		PeerKey:   "peer-A",
	}
	newSess := Session{
		ID:            "new-456",
		PeerPublicKey: "peer-A",
		Status:        "connected",
	}

	// 1. findSessionForRoute must NOT correlate contradictory session IDs
	if sess, ok := findSessionForRoute(oldRoute, []Session{newSess}); ok {
		t.Fatalf("findSessionForRoute unexpectedly correlated route %s with session %s", oldRoute.SessionID, sess.ID)
	}

	// 2. synthesizeUnroutableSessionProblems must emit an unroutable problem for new-456
	problems := synthesizeUnroutableSessionProblems([]forwarder.RouteInfo{oldRoute}, []Session{newSess}, time.Now())
	if len(problems) != 1 {
		t.Fatalf("expected 1 unroutable problem, got %d: %+v", len(problems), problems)
	}
	if problems[0].SessionID != "new-456" {
		t.Errorf("expected problem for session %q, got %q", "new-456", problems[0].SessionID)
	}
	if problems[0].MessageKey != "vpn_problem_session_without_route" {
		t.Errorf("expected MessageKey %q, got %q", "vpn_problem_session_without_route", problems[0].MessageKey)
	}

	// 3. auditRoutingConsistencyDetails must report SessionsWithoutRoute for new-456 and RoutesWithoutSession for old-123
	diag := auditRoutingConsistencyDetails([]forwarder.RouteInfo{oldRoute}, []Session{newSess})
	if diag.IsConsistent {
		t.Errorf("expected routing to be inconsistent, got IsConsistent == true")
	}
	expectedRedacted := ingress.RedactKey("peer-A")
	if len(diag.SessionsWithoutRoute) != 1 || diag.SessionsWithoutRoute[0] != expectedRedacted {
		t.Errorf("SessionsWithoutRoute: got %v, want [%s]", diag.SessionsWithoutRoute, expectedRedacted)
	}
	if len(diag.RoutesWithoutSession) != 1 || diag.RoutesWithoutSession[0] != expectedRedacted {
		t.Errorf("RoutesWithoutSession: got %v, want [%s]", diag.RoutesWithoutSession, expectedRedacted)
	}
}
