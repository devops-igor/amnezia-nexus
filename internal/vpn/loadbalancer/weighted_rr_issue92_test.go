package loadbalancer

// Regression tests for issue #92: the WRR scheduler must keep ALL state on a
// single identity domain (ServerID) and must not carry stale scheduler state
// from a removed backend into a recreated/new backend.

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// TestWRRStaleSchedulerStateDoesNotCorruptRecreatedBackend is the review's
// regression scenario: backend created → traffic → removed → new tunnel →
// the scheduler state for the new tunnel starts clean, i.e. scheduling
// matches the configured weights as if the backend were brand new. Because
// scheduler state is keyed by ServerID (issue #92), a recreated tunnel for a
// pruned server starts from that server's current-weight entry at 0 — never
// from a stale per-tunnel-ID entry that no longer corresponds to any live
// tunnel.
func TestWRRStaleSchedulerStateDoesNotCorruptRecreatedBackend(t *testing.T) {
	ctx := context.Background()
	weights := map[int64]int{
		1: 100,
		2: 100,
	}
	caps := CapacityConfig{MaxTotalPeers: 1000, MaxPeersPerBackend: 500}
	lb := NewWeightedRoundRobinBalancer(weights, caps)

	// Phase 1: two tunnels, traffic flows, scheduler state accumulates.
	first := []*models.BackendTunnel{
		{ID: 201, ServerID: 1, Status: "active"},
		{ID: 202, ServerID: 2, Status: "active"},
	}
	for i := 0; i < 37; i++ {
		req := &RoutingRequest{AvailableTunnels: first}
		if _, err := lb.SelectBackend(ctx, req); err != nil {
			t.Fatalf("phase 1 select %d: %v", i, err)
		}
	}

	// Phase 2: both tunnels removed — UpdateBackends must prune the
	// scheduler state for their servers (no stale entries survive removal).
	lb.UpdateBackends(nil)
	lb.mu.Lock()
	if len(lb.currentWeights) != 0 {
		t.Errorf("INVARIANT VIOLATED: currentWeights not pruned on removal: %v (issue #92)", lb.currentWeights)
	}
	if len(lb.weights) != 0 {
		t.Errorf("INVARIANT VIOLATED: configured weights not pruned on removal: %v", lb.weights)
	}
	lb.mu.Unlock()

	// Phase 3: a NEW tunnel is created (same server, fresh tunnel ID — in
	// production AUTOINCREMENT guarantees the ID differs). Its scheduling
	// must start clean: with a single remaining backend, smooth WRR must
	// deterministically select it on every request. A stale entry from a
	// pre-#92 dual-domain design (keyed by the old tunnel ID 201/202) would
	// be invisible to the new tunnel's ServerID keying and could corrupt the
	// sequence — assert the exact deterministic sequence instead of merely
	// "non-nil".
	recreated := []*models.BackendTunnel{
		{ID: 999, ServerID: 1, Status: "active"},
	}
	for i := 0; i < 3; i++ {
		req := &RoutingRequest{AvailableTunnels: recreated}
		got, err := lb.SelectBackend(ctx, req)
		if err != nil {
			t.Fatalf("phase 3 select %d: %v", i, err)
		}
		if got.ID != 999 {
			t.Errorf("phase 3 select %d: recreated backend ID %d not selected, got %d", i, 999, got.ID)
		}
	}

	// Phase 4: recreated state must be genuinely fresh — after the removal,
	// the single-backend smooth WRR with weight 100 must produce the exact
	// canonical alternating current-weight trajectory (100, 200, 100, 0, ...)
	// of a freshly initialized scheduler, proving no leftover state skews it.
	lb.mu.Lock()
	if got := lb.currentWeights[1]; got != 0 {
		t.Errorf("currentWeights[ServerID 1] = %d after 3 single-candidate selections, want 0 (fresh smooth-WRR trajectory)", got)
	}
	lb.mu.Unlock()
}

// TestWRRStateSurvivesMembershipUpdateForPresentServers: unlike a removed
// backend, a backend that REMAINS through an UpdateBackends call keeps its
// smooth state, so the distribution stays stable across membership churn.
func TestWRRStateSurvivesMembershipUpdateForPresentServers(t *testing.T) {
	ctx := context.Background()
	weights := map[int64]int{1: 50, 2: 25, 3: 25}
	caps := CapacityConfig{MaxTotalPeers: 1000, MaxPeersPerBackend: 500}
	lb := NewWeightedRoundRobinBalancer(weights, caps)

	alive := []*models.BackendTunnel{
		{ID: 301, ServerID: 1, Status: "active"},
		{ID: 302, ServerID: 2, Status: "active"},
		{ID: 303, ServerID: 3, Status: "active"},
	}
	// Run exactly one full cycle (100 selections) so smooth state lands in a
	// known periodic phase; a full cycle returns all counters to the same
	// values (totalWeight subtracted per cycle).
	for i := 0; i < 100; i++ {
		if _, err := lb.SelectBackend(ctx, &RoutingRequest{AvailableTunnels: alive}); err != nil {
			t.Fatalf("select %d: %v", i, err)
		}
	}

	// Server 2's tunnel is REPLACED by a new tunnel (new ID, same server):
	// smooth state for ServerID 2 must survive, and the next full cycle must
	// still produce the exact 50/25/25 distribution.
	after := []*models.BackendTunnel{
		{ID: 301, ServerID: 1, Status: "active"},
		{ID: 777, ServerID: 2, Status: "active"},
		{ID: 303, ServerID: 3, Status: "active"},
	}
	lb.UpdateBackends(after)
	lb.mu.Lock()
	if _, ok := lb.currentWeights[2]; !ok {
		t.Errorf("currentWeights entry for surviving ServerID 2 was pruned")
	}
	lb.mu.Unlock()

	counts := make(map[int64]int)
	for i := 0; i < 100; i++ {
		got, err := lb.SelectBackend(ctx, &RoutingRequest{AvailableTunnels: after})
		if err != nil {
			t.Fatalf("post-update select %d: %v", i, err)
		}
		counts[got.ServerID]++
	}
	if counts[1] != 50 || counts[2] != 25 || counts[3] != 25 {
		t.Errorf("distribution after membership update: 1=%d, 2=%d, 3=%d, want 50/25/25", counts[1], counts[2], counts[3])
	}
}
