package vpn

import (
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestCollectBackendDiagnosticsEligibilityDecomposition pins the contract that
// survives the extraction of collectBackendDiagnostics into its component
// helpers: the enabled/disabled/healthy tallies must keep counting each tunnel
// exactly once, a disabled tunnel must stay in the disabled inventory only, and
// only "enabled AND active" tunnels may contribute load share, latency samples,
// or fleet skew.
//
// The cases below are the ones a careless future split breaks silently: a
// tunnel that is disabled but still reporting active status (inventory-only,
// never eligible), a tunnel that is enabled but not active (enabled inventory,
// never eligible), and a single eligible tunnel (skew must stay zero because
// there is nothing to be skewed against).
func TestCollectBackendDiagnosticsEligibilityDecomposition(t *testing.T) {
	svc, a, b, _, _ := setupTestVPNService(t, setupTestDB(t))
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name                       string
		enabledA, enabledB         bool
		statusA, statusB           string
		latencyA, latencyB         int64
		enabled, disabled, healthy int
		latencySamples             int
		routableA, routableB       bool
		shareOfA, shareOfB         float64
		skew                       float64
		wantP95                    float64
	}{
		{
			name:     "both eligible split share evenly",
			enabledA: true, enabledB: true,
			statusA: TunnelStatusActive, statusB: TunnelStatusActive,
			latencyA: 10, latencyB: 1000,
			enabled: 2, disabled: 0, healthy: 2,
			latencySamples: 2,
			routableA:      true, routableB: true,
			// Neither tunnel reports active connections, so the eligible
			// connection total is zero and no load share is attributed.
			shareOfA: 0, shareOfB: 0,
			skew:    0,
			wantP95: 1000,
		},
		{
			// The regression this case exists for: an active-looking tunnel
			// that is administratively disabled belongs to the disabled
			// inventory and must never be counted as healthy, contribute a
			// latency sample, or be marked Routable.
			name:     "disabled but active is inventory only",
			enabledA: true, enabledB: false,
			statusA: TunnelStatusActive, statusB: TunnelStatusActive,
			latencyA: 10, latencyB: 20,
			enabled: 1, disabled: 1, healthy: 1,
			latencySamples: 1,
			routableA:      true, routableB: false,
			shareOfA: 0, shareOfB: 0,
			skew:    0,
			wantP95: 10,
		},
		{
			// The mirror image: enabled but not active is counted in the
			// enabled inventory yet is not eligible either.
			name:     "enabled but not active is not eligible",
			enabledA: true, enabledB: true,
			statusA: TunnelStatusActive, statusB: TunnelStatusDegraded,
			latencyA: 10, latencyB: 20,
			enabled: 2, disabled: 0, healthy: 1,
			latencySamples: 1,
			routableA:      true, routableB: false,
			shareOfA: 0, shareOfB: 0,
			skew:    0,
			wantP95: 10,
		},
		{
			name:     "all disabled yields no eligibility and no samples",
			enabledA: false, enabledB: false,
			statusA: TunnelStatusActive, statusB: TunnelStatusActive,
			latencyA: 10, latencyB: 20,
			enabled: 0, disabled: 2, healthy: 0,
			latencySamples: 0,
			routableA:      false, routableB: false,
			shareOfA: 0, shareOfB: 0,
			skew:    0,
			wantP95: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, state := range []struct {
				id      int64
				enabled bool
				status  string
				latency int64
			}{{a, tc.enabledA, tc.statusA, tc.latencyA}, {b, tc.enabledB, tc.statusB, tc.latencyB}} {
				if err := svc.pool.SetTunnelEnabled(t.Context(), state.id, state.enabled, models.DisableReasonNone); err != nil {
					t.Fatal(err)
				}
				if err := svc.pool.SetTunnelStatus(t.Context(), state.id, state.status, state.latency); err != nil {
					t.Fatal(err)
				}
			}

			d := collectBackendDiagnostics(svc)

			// Every tunnel must land in exactly one enabled/disabled bucket and
			// the two buckets must account for the whole inventory.
			if d.TotalCount != 2 {
				t.Fatalf("TotalCount=%d, want 2", d.TotalCount)
			}
			if d.EnabledCount != tc.enabled || d.DisabledCount != tc.disabled {
				t.Errorf("enabled=%d disabled=%d, want %d/%d",
					d.EnabledCount, d.DisabledCount, tc.enabled, tc.disabled)
			}
			if d.EnabledCount+d.DisabledCount != d.TotalCount {
				t.Errorf("enabled(%d)+disabled(%d) must account for TotalCount(%d)",
					d.EnabledCount, d.DisabledCount, d.TotalCount)
			}
			if d.HealthyCount != tc.healthy {
				t.Errorf("HealthyCount=%d, want %d", d.HealthyCount, tc.healthy)
			}
			if d.HealthyCount > d.EnabledCount {
				t.Errorf("HealthyCount=%d exceeds EnabledCount=%d: only enabled+active is eligible",
					d.HealthyCount, d.EnabledCount)
			}
			if d.LatencySamples != tc.latencySamples {
				t.Errorf("LatencySamples=%d, want %d", d.LatencySamples, tc.latencySamples)
			}
			if d.LatencyP95MS != tc.wantP95 {
				t.Errorf("LatencyP95MS=%v, want %v", d.LatencyP95MS, tc.wantP95)
			}
			if d.LoadSkewPct != tc.skew {
				t.Errorf("LoadSkewPct=%v, want %v", d.LoadSkewPct, tc.skew)
			}
			if !d.EligibilityKnown {
				t.Error("EligibilityKnown must be true on the pooled path")
			}
			if len(d.Backends) != 2 {
				t.Fatalf("Backends=%d items, want 2", len(d.Backends))
			}

			// Bind the per-item assertions to the expected backend IDs, never
			// to slice positions. Pool.ListTunnels ranges over a map, so the
			// order d.Backends arrives in is randomised per run; keying off
			// d.Backends[0]/[1] would make itemA/itemB whatever the pool
			// happened to yield first and let a swapped pair pass.
			var itemA, itemB *BackendTelemetryItem
			for i := range d.Backends {
				switch d.Backends[i].ID {
				case a:
					itemA = &d.Backends[i]
				case b:
					itemB = &d.Backends[i]
				}
			}
			if itemA == nil || itemB == nil {
				t.Fatalf("expected items for both backend IDs %d and %d, got %d item(s) (a=%v b=%v)",
					a, b, len(d.Backends), itemA != nil, itemB != nil)
			}
			if itemA.ID == itemB.ID {
				t.Fatalf("backends %d and %d must map to distinct items, both bound to ID %d",
					a, b, itemA.ID)
			}

			// Routable is the same eligibility predicate as the healthy count:
			// the number of Routable items must equal HealthyCount exactly, so
			// a future split cannot make the two disagree.
			routable := 0
			for _, b := range d.Backends {
				if b.Routable {
					routable++
				}
				if b.Routable && !b.Enabled {
					t.Errorf("backend %d is Routable but not enabled", b.ID)
				}
			}
			if routable != d.HealthyCount {
				t.Errorf("Routable items=%d but HealthyCount=%d", routable, d.HealthyCount)
			}

			if itemA.Routable != tc.routableA || itemB.Routable != tc.routableB {
				t.Errorf("routable flags=(%v,%v), want (%v,%v)",
					itemA.Routable, itemB.Routable, tc.routableA, tc.routableB)
			}
			if itemA.LoadSharePct != tc.shareOfA || itemB.LoadSharePct != tc.shareOfB {
				t.Errorf("load shares=(%v,%v), want (%v,%v)",
					itemA.LoadSharePct, itemB.LoadSharePct, tc.shareOfA, tc.shareOfB)
			}
		})
	}
}

// TestCollectBackendDiagnosticsNoPoolBranch pins the pool==nil early return: it
// must still report eligibility as known, emit an empty (non-nil) backend fleet
// so the JSON encodes [] rather than null, and total exactly the retired
// lifetime drops plus every live device's drop count while skipping nil map
// entries. That drop population is the one behaviour both branches share, so a
// split that computes it twice must still agree.
func TestCollectBackendDiagnosticsNoPoolBranch(t *testing.T) {
	svc, _, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	svc.pool = nil
	svc.retiredBackendDeviceDrops = backendDeviceDropStats{ClientQueueFull: 7}

	withDrops := &testBackendDevice{}
	withDrops.dropCount.Add(5)
	svc.backendDevices = map[int64]BackendDevice{
		1: withDrops,
		2: nil, // a nil entry must be skipped, not panic
	}

	d := collectBackendDiagnostics(svc)

	if !d.EligibilityKnown {
		t.Error("no-pool branch must still report EligibilityKnown=true")
	}
	if d.Backends == nil {
		t.Error("no-pool branch must emit a non-nil empty fleet so JSON encodes [] not null")
	}
	if len(d.Backends) != 0 {
		t.Errorf("no-pool branch emitted %d backend items, want 0", len(d.Backends))
	}
	// 7 retired + 5 from the single non-nil device.
	if d.TotalDrops != 12 {
		t.Errorf("TotalDrops=%d, want 12", d.TotalDrops)
	}
	// With no pool there is no inventory and no eligibility at all.
	if d.TotalCount != 0 || d.EnabledCount != 0 || d.DisabledCount != 0 || d.HealthyCount != 0 {
		t.Errorf("no-pool branch must report an empty inventory, got %+v", d)
	}
	if d.LatencySamples != 0 || d.LatencyP95MS != 0 || d.LoadSkewPct != 0 {
		t.Errorf("no-pool branch must report no fleet stats, got %+v", d)
	}

	// totalBackendDeviceDrops is the single implementation both branches use;
	// assert it directly so a second divergent copy cannot creep in.
	if got := totalBackendDeviceDrops(svc); got != 12 {
		t.Errorf("totalBackendDeviceDrops=%d, want 12", got)
	}
}

// TestTotalBackendDeviceDropsSkipsNilEntries pins the shared drop arithmetic
// on its own: the retired lifetime total is the base, nil device entries are
// skipped rather than dereferenced, and multiple devices sum.
func TestTotalBackendDeviceDropsSkipsNilEntries(t *testing.T) {
	first := &testBackendDevice{}
	first.dropCount.Add(3)
	second := &testBackendDevice{}
	second.dropCount.Add(11)

	for _, tc := range []struct {
		name    string
		retired backendDeviceDropStats
		devices map[int64]BackendDevice
		want    uint64
	}{
		{"no devices keeps the retired total", backendDeviceDropStats{ClientQueueFull: 42}, nil, 42},
		{"single device adds onto retired", backendDeviceDropStats{ClientQueueFull: 1}, map[int64]BackendDevice{1: first}, 4},
		{"multiple devices sum onto retired", backendDeviceDropStats{}, map[int64]BackendDevice{1: first, 2: second}, 14},
		{"nil entries are skipped", backendDeviceDropStats{ReturnQueueFull: 5}, map[int64]BackendDevice{1: first, 2: nil, 3: nil}, 8},
		{"only nil entries keep the retired total", backendDeviceDropStats{ClientShutdown: 9}, map[int64]BackendDevice{1: nil}, 9},
		{"retired directions sum, not just the client half", backendDeviceDropStats{ClientQueueFull: 1, ReturnQueueFull: 2}, nil, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{retiredBackendDeviceDrops: tc.retired, backendDevices: tc.devices}
			if got := totalBackendDeviceDrops(svc); got != tc.want {
				t.Errorf("totalBackendDeviceDrops=%d, want %d", got, tc.want)
			}
		})
	}
}
