package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestBackendDiagnosticsEligibilityAndFleetPercentile(t *testing.T) {
	svc, a, b, _, _ := setupTestVPNService(t, setupTestDB(t))
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		enabledA, enabledB bool
		stateA, stateB     string
		latencyA, latencyB int64
		healthy            int
		percentile         float64
		critical           bool
		warning            bool
	}{
		{"two eligible", true, true, TunnelStatusActive, TunnelStatusActive, 10, 1000, 2, 1000, false, false},
		{"singleton", true, false, TunnelStatusActive, TunnelStatusActive, 10, 1000, 1, 10, false, false},
		{"all disabled", false, false, TunnelStatusActive, TunnelStatusActive, 10, 1000, 0, 0, true, false},
		{"failed enabled", true, true, TunnelStatusActive, TunnelStatusDegraded, 10, 1000, 1, 10, false, true},
		{"no latency", true, true, TunnelStatusActive, TunnelStatusActive, 0, 0, 2, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, state := range []struct {
				id      int64
				enabled bool
				status  string
				latency int64
			}{{a, tc.enabledA, tc.stateA, tc.latencyA}, {b, tc.enabledB, tc.stateB, tc.latencyB}} {
				if err := svc.pool.SetTunnelEnabled(t.Context(), state.id, state.enabled, models.DisableReasonNone); err != nil {
					t.Fatal(err)
				}
				if err := svc.pool.SetTunnelStatus(t.Context(), state.id, state.status, state.latency); err != nil {
					t.Fatal(err)
				}
			}
			status, err := svc.GetStatus(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			diag := status.Backends
			if diag.HealthyCount != tc.healthy || diag.LatencyP95MS != tc.percentile {
				t.Errorf("healthy=%d p95=%v; want %d/%v", diag.HealthyCount, diag.LatencyP95MS, tc.healthy, tc.percentile)
			}
			health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{}, DropCategoryBreakdown{}, VirtualTUNDiagnostics{}, nil, RoutingConsistencyDiagnostics{IsConsistent: true}, HandshakeFreshnessDiagnostics{}, diag)
			if (health.Status == HealthCritical) != tc.critical {
				t.Errorf("health=%s: %s; critical=%v", health.Status, health.Summary, tc.critical)
			}
			backendWarning := false
			for _, c := range health.Conditions {
				if c.Category == "backend" && c.Severity == "WARNING" {
					backendWarning = true
				}
			}
			if backendWarning != tc.warning {
				t.Errorf("backend warning=%v; want %v", backendWarning, tc.warning)
			}
			if tc.name == "all disabled" && !strings.Contains(strings.ToLower(health.Summary), "disabled") {
				t.Errorf("all-disabled inventory must be explained: %s", health.Summary)
			}
		})
	}
	empty, _ := NewVPNService(setupTestDB(t), nil)
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{}, DropCategoryBreakdown{}, VirtualTUNDiagnostics{}, nil, RoutingConsistencyDiagnostics{IsConsistent: true}, HandshakeFreshnessDiagnostics{}, collectBackendDiagnostics(empty))
	if health.Status != HealthCritical || !strings.Contains(strings.ToLower(health.Summary), "configured") {
		t.Errorf("empty fleet: %+v", health)
	}
}

func TestDiagnosticsDisjointMixedLossProductionPaths(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)
	f, err := forwarder.NewForwarderWithLimits(nil, "", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	svc.forwarder = f
	f.SetReturnRejectClassifier(engine.classifyForwarderReject)
	f.RegisterSessionWithReturnPath("s", "c", "peer", "192.0.2.1", 1, engine.returnPath)
	dev := &testBackendDevice{lastHandshakeFn: func() time.Time { return time.Time{} }}
	svc.backendDevices = map[int64]BackendDevice{1: dev}
	var first Status
	svc.populateOperationalDiagnostics(&first)
	p := returnPacket("192.0.2.1")
	for range 2 {
		if err := f.RouteBackendToClient(1, p, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if !errors.Is(f.RouteBackendToClient(1, p, "192.0.2.1"), forwarder.ErrQueueFull) {
			t.Fatal("expected return queue overflow")
		}
	}
	oversize := make([]byte, forwarder.MaxClientQueuePacketBytes+1)
	copy(oversize, p)
	oversize[2], oversize[3] = byte(len(oversize)>>8), byte(len(oversize))
	if !errors.Is(f.RouteBackendToClient(1, oversize, "192.0.2.1"), forwarder.ErrPacketTooLarge) {
		t.Fatal("expected oversized return drop")
	}
	_ = f.RouteBackendToClient(1, []byte{1}, "192.0.2.1")
	_ = f.RouteBackendToClient(1, p, "192.0.2.2")
	_ = f.RouteBackendToClient(2, p, "192.0.2.1")
	_ = engine.Router().HandlePacket([]byte{1})
	dev.dropCount.Add(42)
	time.Sleep(250 * time.Millisecond)
	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories
	if d.ClientTotalDrops != 43 || d.ReturnTotalDrops != 7 || d.TotalDrops != 50 {
		t.Errorf("disjoint client/return/overall=%d/%d/%d; want 43/7/50", d.ClientTotalDrops, d.ReturnTotalDrops, d.TotalDrops)
	}
	if d.ReturnMalformed != 1 || d.ReturnUnmapped != 1 || d.ReturnMismatch != 1 {
		t.Errorf("engine-classified drops must not overlap forwarder totals: %+v", d)
	}
	if d.ClientDropRatePps <= 0 || d.ReturnDropRatePps <= 0 || status.Rates.DropRatePps <= 0 {
		t.Errorf("omitted populations must produce current rates: %+v", d)
	}
	encoded, _ := json.Marshal(d)
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	// The fixture's directly-recorded device loss has no direction and no
	// reason, so it is published under the EXTERNAL key. It must NOT appear
	// as queue-full: that is the mislabelling this rework removes
	// (issue #424 round 3, finding 1).
	for key, want := range map[string]float64{
		"client_backend_device_external": 42,
		"return_queue_full":              3,
		"return_packet_too_large":        1,
	} {
		if fields[key] != want {
			t.Errorf("%s=%v; want %v", key, fields[key], want)
		}
	}
	if fields["client_backend_device_queue_full"] != float64(0) {
		t.Errorf("reason-less device loss reported as queue-full: %v", fields["client_backend_device_queue_full"])
	}
}

func TestAdmissionNoBackendCauseThroughService(t *testing.T) {
	svc, a, b, _, _ := setupTestVPNService(t, setupTestDB(t))
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	peer := seedIngressPeer(t, svc.db, "expanded-admission", "expanded-peer", "192.0.2.4")
	for _, id := range []int64{a, b} {
		adminDisableBackend(t, svc, id)
	}
	resolver := ingress.NewResolver()
	if err := resolver.Update(ownershipFor(peer)); err != nil {
		t.Fatal(err)
	}
	router := ingress.NewRouter(resolver, serviceIngressAdmission{svc: svc}, svc.forwarder, nil)
	if err := router.HandlePacket(ownedIngressPacket("192.0.2.4")); !errors.Is(err, loadbalancer.ErrNoActiveBackends) {
		t.Fatalf("expected typed no-backend rejection, got %v", err)
	}
	// A separate generic admission failure remains in the rejection population.
	generic := ingress.NewRouter(resolver, ingress.AdmissionFunc(func(ingress.PeerOwnership) (ingress.SessionHandle, ingress.BackendHandle, error) {
		return nil, nil, fmt.Errorf("policy refused")
	}), svc.forwarder, nil)
	_ = generic.HandlePacket(ownedIngressPacket("192.0.2.4"))
	encoded, _ := json.Marshal(router.StatsSnapshot())
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	if fields["no_active_backend_drops"] != float64(1) {
		t.Errorf("no-backend admission cause missing: %s", encoded)
	}
	if generic.StatsSnapshot().AdmissionRejectedDrops != 1 {
		t.Fatal("generic rejection lost")
	}
	_, _, engine, _, _ := newSingleOwnerFixture(t)
	engine.router = router
	svc.ingressEngine = engine
	var status Status
	svc.populateOperationalDiagnostics(&status)
	if status.DropCategories.ClientNoHealthyBackend != 1 || status.DropCategories.ClientRejected != 0 || status.DropCategories.ClientTotalDrops != 1 {
		t.Errorf("specific cause must remain disjoint: %+v", status.DropCategories)
	}
}

func TestHistoryCoreSeriesBoundsOwnershipAndBackendChurn(t *testing.T) {
	rh := NewRollingHistory()
	rates := map[string]float64{"return_queue_full": 3, "client_backend_device_queue_full": 42, "unrecognized": 999}
	fleet := make([]BackendHistoryPoint, MaxHistoryBackends*4)
	for i := range fleet {
		fleet[i].ID = int64(i + 1)
		fleet[i].TrafficAvailable = true
		fleet[i].RxBps = float64(i + 1)
	}
	point := HistoryPoint{Timestamp: 1, RxBps: 100, TxBps: 200, RxPps: 2, TxPps: 3, ActiveSessions: 4, ActiveRoutes: 4, BackendLatencySamples: 1, BackendP95MS: 10, TrafficAvailable: true, DropRatesAvailable: true, DropReasonRates: rates, Backends: fleet}
	rh.Add(point)
	rates["return_queue_full"] = 999
	fleet[0].RxBps = 999
	first := rh.Snapshot().Window15m[0]
	if first.DropReasonRates["return_queue_full"] != 3 || first.Backends[0].RxBps != 1 {
		t.Fatal("history aliases caller-owned mutable data")
	}
	if _, ok := first.DropReasonRates["unrecognized"]; ok {
		t.Fatal("unbounded reason keys entered history")
	}
	if len(first.Backends) != MaxHistoryBackends || cap(first.Backends) > MaxHistoryBackends || first.BackendsOmitted != MaxHistoryBackends*3 {
		t.Fatalf("history did not bound owned fleet backing storage: len=%d cap=%d omitted=%d", len(first.Backends), cap(first.Backends), first.BackendsOmitted)
	}
	first.Backends[0].RxBps = 1000
	first.DropReasonRates["return_queue_full"] = 1000
	if rh.Snapshot().Window15m[0].Backends[0].RxBps != 1 || rh.Snapshot().Window15m[0].DropReasonRates["return_queue_full"] != 3 {
		t.Fatal("history snapshots alias stored mutable data")
	}
	for i := 1; i <= 9000; i++ {
		point.Timestamp = int64(1 + i*10)
		point.Backends = []BackendHistoryPoint{{ID: int64(i), TrafficAvailable: i%2 == 0}}
		rh.Add(point)
	}
	snap := rh.Snapshot()
	for _, w := range []struct {
		points []HistoryPoint
		max    int
	}{{snap.Window15m, 90}, {snap.Window1h, 60}, {snap.Window6h, 72}, {snap.Window24h, 96}} {
		if len(w.points) != w.max {
			t.Errorf("window len=%d; bound=%d", len(w.points), w.max)
		}
		for _, p := range w.points {
			if len(p.DropReasonRates) > len(dropReasonTotals(DropCategoryBreakdown{})) || cap(p.Backends) > MaxHistoryBackends {
				t.Fatal("per-point storage escaped bounds")
			}
			encoded, _ := json.Marshal(p)
			var fields map[string]any
			_ = json.Unmarshal(encoded, &fields)
			for _, key := range []string{"rx_bps", "tx_bps", "rx_pps", "tx_pps", "q_pct", "drop_rate", "drop_reason_rates", "fwd_p95_ms", "fwd_p95_samples", "sessions", "routes", "be_p95_ms", "be_latency_samples", "backends", "traffic_available", "drop_rates_available"} {
				if _, ok := fields[key]; !ok {
					t.Errorf("window missing core field %s", key)
				}
			}
		}
	}
}

func TestBackendLossRetirementAndClosedReturnPathPreserveLifetime(t *testing.T) {
	svc, a, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(a)
	if err != nil {
		t.Fatal(err)
	}
	// Use a real device so Close follows production lifecycle; fixture-owned
	// dropCount is the device's separate queue-loss population, recorded the
	// way an external owner records it: with neither a direction nor a reason,
	// so it is published under the external key rather than as queue-full
	// (issue #424 round 3, finding 1).
	_, pub, priv := createTestServerAndKey(t, svc.db, "retirement-fixture", "192.0.2.20")
	real, err := tunnel.NewAWGClientDevice("loss-retirement", "192.0.2.20:51820", priv, pub, 1340, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev := &testBackendDevice{AWGClientDevice: real}
	dev.dropCount.Add(42)
	svc.SetBackendDeviceForTest(tun.ID, dev)
	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.DropCategories.ClientBackendDeviceExternal != 42 || status.DropCategories.ClientBackendDeviceQueueFull != 0 {
		t.Fatalf("active backend loss missing or misattributed as queue-full: %+v", status.DropCategories)
	}
	if err := svc.DisableBackend(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	next, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Retirement is a TRANSFER of the device's real breakdown, not a move into
	// a reasonless bucket (issue #424 round 5, finding 1). This loss was
	// recorded as EXTERNAL — it had no direction and no reason — so it is
	// published under the same key after the device is gone. Before that
	// change it migrated to client_backend_device_retired_drops, which made
	// five historical RETURN losses look like fresh client loss at the
	// instant of retirement.
	//
	// The retired key is now the directionless-retired population only, so it
	// is correctly 0 for a device that did report its axes.
	if next.DropCategories.ClientBackendDeviceExternal != 42 || next.DropCategories.ClientBackendDeviceRetired != 0 {
		t.Fatalf("retirement reclassified or lost the lifetime loss: %+v", next.DropCategories)
	}
	if next.DropCategories.TotalDrops != status.DropCategories.TotalDrops || next.DropCategories.TotalDropRatePps != 0 {
		t.Fatalf("retirement lost lifetime counters or invented loss: %+v", next.DropCategories)
	}
	if next.Backends.TotalDrops != 42 {
		t.Fatal("retired backend losses disappeared from fleet summary")
	}
	// Closed return owners retire route generations, not forwarder lifetime loss.
	svc2, f, engine, _, _ := newSingleOwnerFixture(t)
	f.RegisterSessionWithReturnPath("s", "c", "p", "192.0.2.1", 1, engine.returnPath)
	p := returnPacket("192.0.2.1")
	for range 11 {
		_ = f.RouteBackendToClient(1, p, "192.0.2.1")
	}
	var before Status
	svc2.populateOperationalDiagnostics(&before)
	engine.returnPath.Close()
	wait := f.RetireRoutesByReturnPath(engine.returnPath)
	if err := wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	var after Status
	svc2.populateOperationalDiagnostics(&after)
	if before.DropCategories.ReturnQueueFull != 1 || after.DropCategories.ReturnQueueFull != 1 || after.DropCategories.TotalDropRatePps != 0 {
		t.Fatalf("closed owner discarded counted losses: before=%+v after=%+v", before.DropCategories, after.DropCategories)
	}
}

func TestBackendEnableFailureStagePreservesTypedCauses(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.EnableBackend(t.Context(), 999)
	if !errors.Is(err, ErrServerNotFound) || BackendEnableStage(err) != "load_server" {
		t.Fatalf("stage discarded sentinel cause: %v / %s", err, BackendEnableStage(err))
	}
	cancelled := backendEnableFailure("register_data_peer", fmt.Errorf("provider: %w", context.DeadlineExceeded))
	if !errors.Is(cancelled, context.DeadlineExceeded) || BackendEnableStage(cancelled) != "register_data_peer" {
		t.Fatal("provider cause/stage lost")
	}
}

func TestNoBackendHistoryMarshalsEmptyFleet(t *testing.T) {
	rh := NewRollingHistory()
	rh.Add(HistoryPoint{Timestamp: 1, Backends: []BackendHistoryPoint{}})
	encoded, err := json.Marshal(rh.Snapshot().Window15m[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	if fleet, ok := fields["backends"].([]any); !ok || len(fleet) != 0 {
		t.Fatalf("empty history fleet must be [], not unavailable/null: %s", encoded)
	}
}

func TestBackendFleetP95NormalPopulation(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 10; i++ {
		id, err := svc.db.CreateServer(t.Context(), &models.Server{Name: fmt.Sprintf("fleet-%d", i), Host: "192.0.2.20"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.pool.AddTunnel(t.Context(), id, "192.0.2.20:51820", "fixture-public-key"); err != nil {
			t.Fatal(err)
		}
		if err := svc.pool.SetTunnelStatus(t.Context(), id, TunnelStatusActive, int64(i*100)); err != nil {
			t.Fatal(err)
		}
	}
	d := collectBackendDiagnostics(svc)
	if d.LatencyP95MS != 1000 || d.LatencySamples != 10 {
		t.Fatalf("nearest-rank fleet p95=%v, samples=%d", d.LatencyP95MS, d.LatencySamples)
	}
}

func TestServiceBackendTrafficAndAllHistoryFromProductionCounters(t *testing.T) {
	svc, server, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(t.Context(), server, TunnelStatusActive, 10); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		f := forwarder.NewForwarder(nil, "")
		svc.forwarder = f
		f.RegisterSession("session", "connection", "peer", "192.0.2.1", tun.ID)
		dev := &testBackendDevice{lastHandshakeFn: func() time.Time { return time.Time{} }}
		svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}
		first, err := svc.GetStatus(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range first.Backends.Backends {
			if b.ID == tun.ID && b.TrafficAvailable {
				t.Fatal("initial backend rate must be unknown")
			}
		}
		rx := ownedIngressPacket("192.0.2.1")
		tx := returnPacket("192.0.2.1")
		if err := f.RouteClientToBackend("peer", rx); err != nil {
			t.Fatal(err)
		}
		if err := f.RouteBackendToClient(tun.ID, tx, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		dev.dropCount.Add(3)
		time.Sleep(time.Second)
		status, err := svc.GetStatus(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var item BackendTelemetryItem
		for _, b := range status.Backends.Backends {
			if b.ID == tun.ID {
				item = b
			}
		}
		if !item.TrafficAvailable || item.RxBytesPerSec != float64(len(rx)) || item.TxBytesPerSec != float64(len(tx)) || item.RxPps != 1 || item.TxPps != 1 {
			t.Fatalf("service did not publish directional real traffic: %+v", item)
		}
		if len(status.AllRoutes) != 1 || !status.AllRoutes[0].Traffic.Available || status.AllRoutes[0].SessionAgeSec != 1 || status.AllRoutes[0].LastTrafficAgeSec != 1 {
			t.Fatalf("service route fields do not match measured source: %+v", status.AllRoutes)
		}
		svc.sampleRollingHistory()
		history := svc.rollingHistory.Snapshot()
		for _, points := range [][]HistoryPoint{history.Window15m, history.Window1h, history.Window6h, history.Window24h} {
			if len(points) != 1 {
				t.Fatalf("first rich sample missing: %d", len(points))
			}
			point := points[0]
			if !point.TrafficAvailable || !point.DropRatesAvailable || point.RxPps != 1 || point.TxPps != 1 || point.ActiveRoutes != 1 || point.BackendLatencySamples != 2 || point.BackendP95MS != 50 {
				t.Fatalf("history missing current core data: %+v", point)
			}
			sum := 0.0
			for _, rate := range point.DropReasonRates {
				sum += rate
			}
			if point.DropReasonRates["client_backend_device_external"] != 3 || sum != point.TotalDropRate {
				t.Fatalf("history reason ownership does not match total: reasons=%v total=%v", point.DropReasonRates, point.TotalDropRate)
			}
			found := false
			for _, b := range point.Backends {
				if b.ID == tun.ID {
					found = true
					if !b.TrafficAvailable || b.RxBps != float64(len(rx))*8 || b.TxBps != float64(len(tx))*8 || !b.ProbeAvailable {
						t.Fatalf("backend history lost measured context: %+v", b)
					}
				}
			}
			if !found {
				t.Fatal("backend missing from actual history sample")
			}
		}
	})
}

func TestServiceStopRetainsEngineLossesWithoutInventingRates(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)
	svc.running = true
	_ = engine.Router().HandlePacket([]byte{1})
	var before Status
	svc.populateOperationalDiagnostics(&before)
	if before.DropCategories.ClientMalformed != 1 {
		t.Fatal("production ingress did not count malformed loss")
	}
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(250 * time.Millisecond)
	var after Status
	svc.populateOperationalDiagnostics(&after)
	if after.DropCategories.ClientMalformed != 1 || after.DropCategories.TotalDrops != before.DropCategories.TotalDrops || after.DropCategories.TotalDropRatePps != 0 {
		t.Fatalf("engine retirement lost/invented loss: before=%+v after=%+v", before.DropCategories, after.DropCategories)
	}
	if after.VirtualTUN.UpstreamToNexus.Occupancy != 0 || after.VirtualTUN.NexusToUpstream.Occupancy != 0 {
		t.Fatal("retirement retained live gauges")
	}
}

func TestLossSamplingAvailabilityAndRatesAtExactBoundary(t *testing.T) {
	svc := &Service{diagDeltas: diagDeltaTrackers{}}
	start := time.Unix(100, 0)
	d := DropCategoryBreakdown{ClientMalformed: 10, ClientTotalDrops: 10, ReturnQueueFull: 20, ReturnTotalDrops: 20, TotalDrops: 30}
	if rate := svc.sampleDropRates(start, &d, 4); rate != 0 || d.RatesAvailable || d.TotalDropRatePps != 0 {
		t.Fatal("first lifetime baseline must be unknown")
	}
	d.ClientMalformed += 2
	d.ClientTotalDrops += 2
	d.ReturnQueueFull += 3
	d.ReturnTotalDrops += 3
	d.TotalDrops += 5
	if rate := svc.sampleDropRates(start.Add(200*time.Millisecond-time.Nanosecond), &d, 5); rate != 0 || d.RatesAvailable || d.TotalDropRatePps != 0 {
		t.Fatalf("aggregate/reason availability disagreed before boundary: %+v", d)
	}
	for _, rate := range d.ReasonRates {
		if rate != 0 {
			t.Fatal("unknown aggregate interval published fresh reason rate")
		}
	}
	if rate := svc.sampleDropRates(start.Add(200*time.Millisecond), &d, 5); rate != 5 || !d.RatesAvailable || d.ClientDropRatePps != 10 || d.ReturnDropRatePps != 15 || d.TotalDropRatePps != 25 || d.ReasonRates["client_malformed"] != 10 || d.ReasonRates["return_queue_full"] != 15 {
		t.Fatalf("aggregate/reasons did not share exact boundary and interval: %+v writeErrors=%v", d, rate)
	}
	if rate := svc.sampleDropRates(start.Add(400*time.Millisecond), &d, 5); rate != 0 || !d.RatesAvailable || d.TotalDropRatePps != 0 {
		t.Fatal("measured idle lost availability")
	}
	for _, rate := range d.ReasonRates {
		if rate != 0 {
			t.Fatal("idle reason rate retained a fresh incident")
		}
	}
}

func TestConcurrentLossSamplingKeepsAggregateAndReasonsInSameWindow(t *testing.T) {
	svc := &Service{diagDeltas: diagDeltaTrackers{}, diagRates: newDiagRatesTracker()}
	start := time.Unix(100, 0)
	var prime DropCategoryBreakdown
	svc.sampleDropRates(start, &prime, 0)
	failures := make(chan DropCategoryBreakdown, 1)
	var group sync.WaitGroup
	for i := uint64(1); i <= 800; i++ {
		group.Go(func() {
			count := i * i // Nonlinear totals distinguish every sampled interval.
			d := DropCategoryBreakdown{ClientMalformed: count, ClientTotalDrops: count, ReturnQueueFull: 2 * count, ReturnTotalDrops: 2 * count, TotalDrops: 3 * count}
			svc.sampleDropRates(start.Add(time.Duration(i)*time.Second), &d, 0)
			sum := 0.0
			for _, rate := range d.ReasonRates {
				sum += rate
			}
			if !d.RatesAvailable || sum != d.TotalDropRatePps || d.ClientDropRatePps != d.ReasonRates["client_malformed"] || d.ReturnDropRatePps != d.ReasonRates["return_queue_full"] {
				select {
				case failures <- d:
				default:
				}
			}
		})
	}
	group.Wait()
	select {
	case d := <-failures:
		t.Fatalf("concurrent sampling returned mixed loss windows: %+v", d)
	default:
	}
}
