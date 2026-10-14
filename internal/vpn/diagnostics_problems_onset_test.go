package vpn

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

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
