package vpn

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestEvaluateForwarderHealth_States(t *testing.T) {
	// Baseline healthy inputs
	baseQueue := QueuePressureDiagnostics{
		Occupancy:             10,
		Capacity:              1000,
		UtilizationPct:        1.0,
		HighWaterPct:          5.0,
		ConsecutiveAbove50Sec: 0,
		ConsecutiveAbove80Sec: 0,
		QueueFullDrops:        0,
	}
	baseLatency := ForwardLatencyDiagnostics{
		P50MS:            1.5,
		P95MS:            5.0,
		P99MS:            8.0,
		OldestInFlightMS: 10,
		Stalls:           0,
		WriteErrors:      0,
	}
	baseDrops := DropCategoryBreakdown{
		TotalDrops:       0,
		TotalDropRatePps: 0.0,
	}
	baseVTUN := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5, Peak: 20, Drops: 0},
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5, Peak: 20, Drops: 0},
	}
	basePeerSync := &PeerSyncStatus{
		DesiredPeers: 10,
		ActualPeers:  10,
		SyncFailures: 0,
	}
	baseRouting := RoutingConsistencyDiagnostics{
		ActiveSessionsCount: 5,
		ActiveRoutesCount:   5,
		ReturnOwnersCount:   5,
		IsConsistent:        true,
	}
	baseHandshake := HandshakeFreshnessDiagnostics{
		TotalPeers: 10,
	}
	baseBackends := BackendsDiagnostics{
		HealthyCount: 2,
		TotalCount:   2,
		LatencyP95MS: 15.0,
	}

	// 1. Healthy
	h := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if h.Status != HealthHealthy {
		t.Errorf("expected HEALTHY, got %s (summary: %s)", h.Status, h.Summary)
	}

	// 2. Unavailable
	u := EvaluateForwarderHealth(false, false, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if u.Status != HealthUnavailable {
		t.Errorf("expected UNAVAILABLE, got %s", u.Status)
	}

	// 3. Degraded on queue drops
	qDrops := baseQueue
	qDrops.QueueFullDrops = 10
	deg := EvaluateForwarderHealth(true, true, qDrops, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if deg.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for queue drops, got %s", deg.Status)
	}

	// 4. Critical on queue saturation >= 95%
	qSat := baseQueue
	qSat.UtilizationPct = 96.0
	crit := EvaluateForwarderHealth(true, true, qSat, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if crit.Status != HealthCritical {
		t.Errorf("expected CRITICAL for queue saturation, got %s", crit.Status)
	}

	// 5. Critical on write stall >= 1000ms
	latStall := baseLatency
	latStall.OldestInFlightMS = 1200
	critStall := EvaluateForwarderHealth(true, true, baseQueue, latStall, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if critStall.Status != HealthCritical {
		t.Errorf("expected CRITICAL for write stall, got %s", critStall.Status)
	}

	// 6. Critical on 0 healthy backends
	beDown := baseBackends
	beDown.HealthyCount = 0
	critBE := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, beDown)
	if critBE.Status != HealthCritical {
		t.Errorf("expected CRITICAL for 0 healthy backends, got %s", critBE.Status)
	}

	// 7. Critical on duplicate IP routing inconsistency
	routeDup := baseRouting
	routeDup.IsConsistent = false
	routeDup.DuplicateIPs = []string{"10.100.0.5"}
	routeDup.InconsistencyDetails = []string{"1 duplicate IP detected"}
	critRoute := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, routeDup, baseHandshake, baseBackends)
	if critRoute.Status != HealthCritical {
		t.Errorf("expected CRITICAL for duplicate IP, got %s", critRoute.Status)
	}

	// 8. Degraded on VirtualTUN drops
	vtunDrops := baseVTUN
	vtunDrops.NexusToUpstream.Drops = 5
	degVTUN := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, vtunDrops, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degVTUN.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for VirtualTUN drops, got %s", degVTUN.Status)
	}
}

func TestCheckRoutingInvariants(t *testing.T) {
	// Create mock service
	svc := &Service{
		sessionMgr: nil, // empty sessions
	}

	// Case 1: Empty routes, empty sessions -> consistent
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{})
	if !diag.IsConsistent {
		t.Errorf("expected consistent for empty sessions/routes, got inconsistencies: %v", diag.InconsistencyDetails)
	}

	// Case 2: Routes without session and without return path
	routes := []forwarder.RouteInfo{
		{
			PeerKey:          "peer-a",
			AssignedIP:       "10.100.0.2",
			BackendTunnelID:  0,
			HasReturnPath:    false,
			ReturnPathClosed: true,
		},
	}
	diag2 := checkRoutingInvariants(svc, routes, ReturnStatsSnapshot{})
	if diag2.IsConsistent {
		t.Errorf("expected inconsistency for route without session and without return")
	}
	if len(diag2.RoutesWithoutSession) != 1 || diag2.RoutesWithoutSession[0] != "peer-a" {
		t.Errorf("expected peer-a in RoutesWithoutSession, got %v", diag2.RoutesWithoutSession)
	}
	if len(diag2.RoutesWithoutReturn) != 1 || diag2.RoutesWithoutReturn[0] != "peer-a" {
		t.Errorf("expected peer-a in RoutesWithoutReturn, got %v", diag2.RoutesWithoutReturn)
	}

	// Case 3: Duplicate IP across routes
	routesDup := []forwarder.RouteInfo{
		{
			PeerKey:         "peer-1",
			AssignedIP:      "10.100.0.3",
			BackendTunnelID: 1,
			HasReturnPath:   true,
		},
		{
			PeerKey:         "peer-2",
			AssignedIP:      "10.100.0.3",
			BackendTunnelID: 1,
			HasReturnPath:   true,
		},
	}
	diagDup := checkRoutingInvariants(svc, routesDup, ReturnStatsSnapshot{})
	if diagDup.IsConsistent {
		t.Errorf("expected inconsistency for duplicate IPs")
	}
	if len(diagDup.DuplicateIPs) != 1 || diagDup.DuplicateIPs[0] != "10.100.0.3" {
		t.Errorf("expected 10.100.0.3 in DuplicateIPs, got %v", diagDup.DuplicateIPs)
	}
}

func TestRollingHistory_WindowsAndConcurrency(t *testing.T) {
	rh := NewRollingHistory()
	now := time.Now()

	// Add 100 points spaced by 10 seconds (total 1000s ~ 16m)
	for i := 0; i < 100; i++ {
		tPoint := now.Add(time.Duration(i*10) * time.Second)
		rh.Add(HistoryPoint{
			Timestamp:      tPoint.Unix(),
			RxBps:          float64(i * 1000),
			TxBps:          float64(i * 2000),
			QueueUtilPct:   float64(i % 100),
			TotalDropRate:  float64(i % 5),
			ForwardP95MS:   1.5,
			ActiveSessions: i,
			BackendP95MS:   10.0,
		})
	}

	snap := rh.Snapshot()
	// buf15m has maxCap 90, so len must be exactly 90
	if len(snap.Window15m) != 90 {
		t.Errorf("expected Window15m len=90, got %d", len(snap.Window15m))
	}
	// buf1h has samples every 1m, so in 1000s (~16m) we expect ~17 points
	if len(snap.Window1h) < 15 || len(snap.Window1h) > 20 {
		t.Errorf("expected Window1h len between 15 and 20, got %d", len(snap.Window1h))
	}

	// Concurrent read and write stress
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				rh.Add(HistoryPoint{
					Timestamp: time.Now().Unix(),
					RxBps:     float64(workerID * 100),
				})
			}
		}(w)
	}

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = rh.Snapshot()
			}
		}()
	}

	wg.Wait()
}

func TestCollectRuntimeResources(t *testing.T) {
	res := collectRuntimeResources()
	if res.Goroutines <= 0 {
		t.Errorf("expected Goroutines > 0, got %d", res.Goroutines)
	}
	if res.MemoryAllocBytes == 0 {
		t.Errorf("expected non-zero MemoryAllocBytes")
	}
	if res.MemoryLimitBytes == 0 {
		t.Errorf("expected non-zero MemoryLimitBytes")
	}
	if res.MaxFileDesc == 0 {
		t.Errorf("expected MaxFileDesc > 0")
	}
}

func TestGetStatus_OperationalDiagnostics(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}

	st, err := svc.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	if st.HealthAssessment.Status == "" {
		t.Errorf("expected non-empty HealthAssessment.Status")
	}
	if st.RuntimeResources.Goroutines <= 0 {
		t.Errorf("expected positive Goroutines count")
	}
	if st.HistoricalSeries.Window15m == nil {
		t.Errorf("expected non-nil HistoricalSeries.Window15m")
	}
	if st.Backends.Backends == nil {
		t.Errorf("expected non-nil Backends.Backends")
	}
	if st.ProblemRoutes == nil {
		t.Errorf("expected non-nil ProblemRoutes")
	}
}
