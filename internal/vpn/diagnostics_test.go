package vpn

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
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
	if h.Conditions == nil {
		t.Errorf("expected non-nil h.Conditions for healthy forwarder")
	}
	hJSON, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal(h): %v", err)
	}
	if !strings.Contains(string(hJSON), `"conditions":[]`) {
		t.Errorf("expected JSON to contain '\"conditions\":[]', got %s", string(hJSON))
	}

	// 2. Unavailable
	u := EvaluateForwarderHealth(false, false, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if u.Status != HealthUnavailable {
		t.Errorf("expected UNAVAILABLE, got %s", u.Status)
	}

	// 3. Degraded on active queue drops
	qDrops := baseQueue
	qDrops.QueueDropRatePps = 1.0
	deg := EvaluateForwarderHealth(true, true, qDrops, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if deg.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for active queue drops, got %s", deg.Status)
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

	// 8. Degraded on VirtualTUN queue saturation
	vtunSat := baseVTUN
	vtunSat.NexusToUpstream.Capacity = 1000
	vtunSat.NexusToUpstream.Occupancy = 950 // 95% utilization
	degVTUN := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, vtunSat, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degVTUN.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for VirtualTUN saturation, got %s", degVTUN.Status)
	}

	// 9. Degraded on write errors
	latErr := baseLatency
	latErr.WriteErrorRatePps = 2.0
	degLat := EvaluateForwarderHealth(true, true, baseQueue, latErr, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degLat.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for write errors, got %s", degLat.Status)
	}

	// 10. Degraded on active dataplane drops
	dropsActive := baseDrops
	dropsActive.TotalDropRatePps = 12.0
	degDrops := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, dropsActive, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degDrops.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for elevated drop rate, got %s", degDrops.Status)
	}
}

func TestEvaluateForwarderHealth_Recovery(t *testing.T) {
	// Lifetime cumulative counters are non-zero (previous incident)
	histQueue := QueuePressureDiagnostics{
		Occupancy:             5,
		Capacity:              1000,
		UtilizationPct:        0.5,
		HighWaterPct:          85.0,
		ConsecutiveAbove50Sec: 0,
		ConsecutiveAbove80Sec: 0,
		QueueFullDrops:        100, // Historical drops
		QueueDropRatePps:      0.0, // Active rate is 0
	}
	histLatency := ForwardLatencyDiagnostics{
		P50MS:             1.5,
		P95MS:             5.0,
		P99MS:             8.0,
		OldestInFlightMS:  0,
		Stalls:            10, // Historical stalls
		WriteErrors:       50, // Historical errors
		WriteTotal:        5000,
		WriteErrorRatePps: 0.0, // Active rate is 0
	}
	histDrops := DropCategoryBreakdown{
		ClientBackendQueueFull: 100,
		ClientTotalDrops:       100,
		ReturnVirtualTUNDrops:  20,
		ReturnTotalDrops:       20,
		TotalDrops:             120, // Historical total
		ClientDropRatePps:      0.0,
		ReturnDropRatePps:      0.0,
		TotalDropRatePps:       0.0, // Active rate is 0
	}
	histVTUN := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 10, Peak: 800, Drops: 20}, // Historical drops
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 10, Peak: 800, Drops: 15}, // Historical drops
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

	// Dynamic recovery: when active rates and stalls are 0, status MUST evaluate to HEALTHY
	assessment := EvaluateForwarderHealth(true, true, histQueue, histLatency, histDrops, histVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if assessment.Status != HealthHealthy {
		t.Fatalf("expected HEALTHY status upon recovery, got %s (conditions: %+v)", assessment.Status, assessment.Conditions)
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

	svc.cfg = &models.VPNConfig{PublicEndpoint: "127.0.0.1:51820"}
	st, err := svc.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	if st.HealthAssessment.Status == "" {
		t.Errorf("expected non-empty HealthAssessment.Status")
	}
	if st.HealthAssessment.Conditions == nil {
		t.Errorf("expected non-nil HealthAssessment.Conditions")
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

type testSingleOwnerAdmission struct {
	divergentIP string
	rejectErr   error
}

func (a *testSingleOwnerAdmission) EnsureSession(owner ingress.PeerOwnership) (ingress.SessionHandle, ingress.BackendHandle, error) {
	if a.rejectErr != nil {
		return nil, nil, a.rejectErr
	}
	ip := owner.IP.String()
	if a.divergentIP != "" {
		ip = a.divergentIP
	}
	return &testAdmissionSessionHandle{id: "sess-" + owner.PeerPublicKey, assignedIP: ip}, &testAdmissionBackendHandle{tunnelID: 1}, nil
}

type testAdmissionSessionHandle struct {
	id         string
	assignedIP string
}

func (s *testAdmissionSessionHandle) SessionID() string  { return s.id }
func (s *testAdmissionSessionHandle) AssignedIP() string { return s.assignedIP }

type testAdmissionBackendHandle struct {
	tunnelID int64
}

func (b *testAdmissionBackendHandle) TunnelID() int64 { return b.tunnelID }

func buildTestIPv4Packet(srcIP, dstIP net.IP, length int) []byte {
	pkt := make([]byte, length)
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	return pkt
}

func newSingleOwnerFixture(t *testing.T) (*Service, *forwarder.Forwarder, *IngressEngine, *ingress.Resolver, *testSingleOwnerAdmission) {
	t.Helper()

	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}

	resolver := ingress.NewResolver()
	adm := &testSingleOwnerAdmission{}
	router := ingress.NewRouter(resolver, adm, fwd, nil)

	key := [32]byte{17}
	pub, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	peerKey := [32]byte{33}
	peerPub, err := curve25519.X25519(peerKey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519 peer: %v", err)
	}

	portal, err := clientawg.NewDevice(clientawg.Config{
		PrivateKey: base64.StdEncoding.EncodeToString(key[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		TUN: virtualtun.Config{
			Name:            "test-portal",
			MTU:             1280,
			InboundCapacity: 2,
		},
		Peers: []clientawg.Peer{
			{
				PublicKey: base64.StdEncoding.EncodeToString(peerPub),
				AllowedIP: netip.MustParsePrefix("10.40.0.2/32"),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	t.Cleanup(func() { _ = portal.Close() })

	engine := &IngressEngine{
		portal:   portal,
		router:   router,
		resolver: resolver,
	}
	engine.returnPath = forwarder.NewReturnPath(engine.writeReturnPacket)
	fwd.SetReturnRejectClassifier(engine.classifyForwarderReject)

	svc := &Service{
		forwarder:     fwd,
		ingressEngine: engine,
		cfg:           &models.VPNConfig{PublicEndpoint: "127.0.0.1:51820"},
	}

	return svc, fwd, engine, resolver, adm
}

func assertDropBreakdown(t *testing.T, b DropCategoryBreakdown, expected string) {
	t.Helper()
	m := map[string]uint64{
		"ClientMalformed":        b.ClientMalformed,
		"ClientUnmappedSource":   b.ClientUnmappedSource,
		"ClientMismatch":         b.ClientMismatch,
		"ClientRejected":         b.ClientRejected,
		"ClientBackendQueueFull": b.ClientBackendQueueFull,
		"ClientRateLimited":      b.ClientRateLimited,
		"ClientNoHealthyBackend": b.ClientNoHealthyBackend,
		"ReturnMalformed":        b.ReturnMalformed,
		"ReturnUnmapped":         b.ReturnUnmapped,
		"ReturnMismatch":         b.ReturnMismatch,
		"ReturnInjectionErrors":  b.ReturnInjectionErrors,
		"ReturnVirtualTUNDrops":  b.ReturnVirtualTUNDrops,
	}

	clientCategories := map[string]bool{
		"ClientMalformed":        true,
		"ClientUnmappedSource":   true,
		"ClientMismatch":         true,
		"ClientRejected":         true,
		"ClientBackendQueueFull": true,
		"ClientRateLimited":      true,
		"ClientNoHealthyBackend": true,
	}

	for k, v := range m {
		if k == expected {
			if v != 1 {
				t.Errorf("[%s] expected 1, got %d", k, v)
			}
		} else {
			if v != 0 {
				t.Errorf("[%s] expected 0, got %d (while expecting %s)", k, v, expected)
			}
		}
	}

	if b.TotalDrops != 1 {
		t.Errorf("TotalDrops: expected 1, got %d", b.TotalDrops)
	}

	if clientCategories[expected] {
		if b.ClientTotalDrops != 1 {
			t.Errorf("ClientTotalDrops: expected 1, got %d", b.ClientTotalDrops)
		}
		if b.ReturnTotalDrops != 0 {
			t.Errorf("ReturnTotalDrops: expected 0, got %d", b.ReturnTotalDrops)
		}
	} else {
		if b.ReturnTotalDrops != 1 {
			t.Errorf("ReturnTotalDrops: expected 1, got %d", b.ReturnTotalDrops)
		}
		if b.ClientTotalDrops != 0 {
			t.Errorf("ClientTotalDrops: expected 0, got %d", b.ClientTotalDrops)
		}
	}
}

func TestDropCategoryBreakdown_SingleOwnerAccounting(t *testing.T) {
	t.Run("ClientMalformed", func(t *testing.T) {
		svc, _, engine, _, _ := newSingleOwnerFixture(t)
		_ = engine.router.HandlePacket([]byte{1, 2, 3})
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientMalformed")
	})

	t.Run("ClientUnmappedSource", func(t *testing.T) {
		svc, _, engine, _, _ := newSingleOwnerFixture(t)
		pkt := buildTestIPv4Packet(net.ParseIP("198.51.100.99"), net.ParseIP("10.100.0.1"), 40)
		_ = engine.router.HandlePacket(pkt)
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientUnmappedSource")
	})

	t.Run("ClientMismatch", func(t *testing.T) {
		svc, _, engine, resolver, adm := newSingleOwnerFixture(t)
		const peer = "test-peer-mismatch"
		_ = resolver.Update(ingress.PeerOwnership{PeerPublicKey: peer, IP: netip.MustParseAddr("10.40.0.2"), ConnectionID: "c1", UserID: "u1"})
		adm.divergentIP = "10.40.0.99"
		pkt := buildTestIPv4Packet(net.ParseIP("10.40.0.2"), net.ParseIP("10.100.0.1"), 40)
		_ = engine.router.HandlePacket(pkt)
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientMismatch")
	})

	t.Run("ClientRejected", func(t *testing.T) {
		svc, _, engine, resolver, adm := newSingleOwnerFixture(t)
		const peer = "test-peer-rejected"
		_ = resolver.Update(ingress.PeerOwnership{PeerPublicKey: peer, IP: netip.MustParseAddr("10.40.0.3"), ConnectionID: "c1", UserID: "u1"})
		adm.rejectErr = errors.New("admission rejected: disabled user")
		pkt := buildTestIPv4Packet(net.ParseIP("10.40.0.3"), net.ParseIP("10.100.0.1"), 40)
		_ = engine.router.HandlePacket(pkt)
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientRejected")
	})

	t.Run("ClientBackendQueueFull", func(t *testing.T) {
		svc, fwd, _, _, _ := newSingleOwnerFixture(t)
		fwd.RegisterSession("s5", "c5", "p5", "10.100.0.5", 5)
		ch := make(chan []byte, 1)
		ch <- []byte{0}
		fwd.SetBackendQueueForTest(5, ch)
		pkt := buildTestIPv4Packet(net.ParseIP("10.100.0.5"), net.ParseIP("1.1.1.1"), 40)
		err := fwd.RouteClientToBackend("p5", pkt)
		if !errors.Is(err, forwarder.ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull, got %v", err)
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientBackendQueueFull")
	})

	t.Run("ClientRateLimited", func(t *testing.T) {
		svc, fwd, _, _, _ := newSingleOwnerFixture(t)
		fwd.RegisterSession("s6", "c6", "p6", "10.100.0.6", 6)
		if err := fwd.SetPeerRateLimit("p6", 0, 10); err != nil {
			t.Fatalf("SetPeerRateLimit: %v", err)
		}
		pkt := buildTestIPv4Packet(net.ParseIP("10.100.0.6"), net.ParseIP("1.1.1.1"), 100)
		err := fwd.RouteClientToBackend("p6", pkt)
		if !errors.Is(err, forwarder.ErrRateLimitExceeded) {
			t.Fatalf("expected ErrRateLimitExceeded, got %v", err)
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientRateLimited")
	})

	t.Run("ClientNoHealthyBackend", func(t *testing.T) {
		svc, fwd, _, _, _ := newSingleOwnerFixture(t)
		fwd.RegisterSession("s7", "c7", "p7", "10.100.0.7", 999)
		fwd.SetBackendQueueForTest(999, nil)
		pkt := buildTestIPv4Packet(net.ParseIP("10.100.0.7"), net.ParseIP("1.1.1.1"), 40)
		err := fwd.RouteClientToBackend("p7", pkt)
		if !errors.Is(err, forwarder.ErrBackendNotFound) {
			t.Fatalf("expected ErrBackendNotFound, got %v", err)
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ClientNoHealthyBackend")
	})

	t.Run("ReturnMalformed", func(t *testing.T) {
		svc, fwd, engine, _, _ := newSingleOwnerFixture(t)
		fwd.RegisterSessionWithReturnPath("s8", "c8", "p8", "10.100.0.8", 1, engine.returnPath)
		err := fwd.RouteBackendToClient(1, []byte{0x00, 0x01}, "10.100.0.8")
		if err == nil {
			t.Fatalf("expected error on malformed return packet")
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ReturnMalformed")
	})

	t.Run("ReturnUnmapped", func(t *testing.T) {
		svc, fwd, _, _, _ := newSingleOwnerFixture(t)
		pkt := buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.99"), 40)
		err := fwd.RouteBackendToClient(1, pkt, "10.100.0.99")
		if err == nil {
			t.Fatalf("expected error on unmapped return packet")
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ReturnUnmapped")
	})

	t.Run("ReturnMismatch", func(t *testing.T) {
		svc, fwd, engine, _, _ := newSingleOwnerFixture(t)
		fwd.RegisterSessionWithReturnPath("s10", "c10", "p10", "10.100.0.10", 1, engine.returnPath)
		pkt := buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.10"), 40)
		err := fwd.RouteBackendToClient(2, pkt, "10.100.0.10")
		if err == nil {
			t.Fatalf("expected error on backend mismatch return packet")
		}
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ReturnMismatch")
	})

	t.Run("ReturnInjectionErrors", func(t *testing.T) {
		svc, _, engine, _, _ := newSingleOwnerFixture(t)
		engine.returnCounters.injectionErrors.Add(1)
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ReturnInjectionErrors")
	})

	t.Run("ReturnVirtualTUNDrops", func(t *testing.T) {
		svc, _, engine, _, _ := newSingleOwnerFixture(t)
		if err := engine.portal.DownForTest(); err != nil {
			t.Fatalf("DownForTest: %v", err)
		}
		pkt := buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.1"), 40)
		var err error
		for i := 0; i < 10; i++ {
			err = engine.portal.InjectInbound(pkt)
			if errors.Is(err, virtualtun.ErrQueueFull) {
				break
			}
		}
		if !errors.Is(err, virtualtun.ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull, got %v", err)
		}
		engine.returnCounters.injectionErrors.Add(1)
		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ReturnVirtualTUNDrops")
	})
}
