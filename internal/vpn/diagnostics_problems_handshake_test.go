package vpn

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

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
