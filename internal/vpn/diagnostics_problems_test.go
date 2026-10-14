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
