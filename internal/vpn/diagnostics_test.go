package vpn

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
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
	diag := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
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
	diag2 := checkRoutingInvariants(svc, routes, ReturnStatsSnapshot{}, 0)
	if diag2.IsConsistent {
		t.Errorf("expected inconsistency for route without session and without return")
	}
	// These two slices carry REDACTED peer keys: they are built by iterating
	// maps keyed by the raw key, and ingress.RedactKey is applied before they
	// reach the API (issue #424 round 5, item 1a). "peer-a" is 6 characters,
	// so RedactKey fully masks it.
	if len(diag2.RoutesWithoutSession) != 1 || diag2.RoutesWithoutSession[0] != "******" {
		t.Errorf("expected the redacted key in RoutesWithoutSession, got %v", diag2.RoutesWithoutSession)
	}
	if len(diag2.RoutesWithoutReturn) != 1 || diag2.RoutesWithoutReturn[0] != "******" {
		t.Errorf("expected the redacted key in RoutesWithoutReturn, got %v", diag2.RoutesWithoutReturn)
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
	diagDup := checkRoutingInvariants(svc, routesDup, ReturnStatsSnapshot{}, 0)
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
	// buf1m has maxCap 6, so len must be exactly 6
	if len(snap.Window1m) != 6 {
		t.Errorf("expected Window1m len=6, got %d", len(snap.Window1m))
	}
	// buf5m has maxCap 30, so len must be exactly 30
	if len(snap.Window5m) != 30 {
		t.Errorf("expected Window5m len=30, got %d", len(snap.Window5m))
	}
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
	// The runtime memory capacity oracle reports what the kernel actually
	// discloses and nothing else: readMemoryLimit returns 0 when no finite
	// cgroup limit is discoverable (the common case on hosts and CI runners
	// without a cgroup memory file). So assert the availability contract, not
	// a hardcoded non-zero capacity: a reported limit must be finite (> 0) and
	// the two fields must agree in both directions. Never assert a specific
	// numeric limit — that is host-dependent and was the invented-capacity
	// behavior this oracle deliberately rejects.
	if res.MemoryLimitAvailable != (res.MemoryLimitBytes > 0) {
		t.Errorf("MemoryLimitAvailable=%v inconsistent with MemoryLimitBytes=%d",
			res.MemoryLimitAvailable, res.MemoryLimitBytes)
	}
	if res.MemoryLimitAvailable && res.MemoryLimitBytes == 0 {
		t.Errorf("MemoryLimitAvailable is true but MemoryLimitBytes is 0")
	}
	if !res.MemoryLimitAvailable && res.MemoryLimitBytes != 0 {
		t.Errorf("MemoryLimitAvailable is false but MemoryLimitBytes=%d is non-zero",
			res.MemoryLimitBytes)
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
	if st.HistoricalSeries.Window1m == nil {
		t.Errorf("expected non-nil HistoricalSeries.Window1m")
	}
	if st.HistoricalSeries.Window5m == nil {
		t.Errorf("expected non-nil HistoricalSeries.Window5m")
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

	// The device is built with inbound reads ALREADY suspended, not suspended
	// after construction. The upstream engine starts its TUN reader goroutine
	// inside device.NewDevice and parks it inside VirtualTUN.Read, already
	// past the suspension gate at the top of Read. Arming the gate afterwards
	// never reaches that goroutine: it dequeues the next injected packet, and
	// every assertion below on inbound occupancy, inbound peak or a Close()
	// drain then races it. Building the device suspended makes the reader's
	// FIRST Read call block on the gate, so the inbound queue is provably
	// never drained.
	//
	// This is test-only determinism. Production construction is
	// clientawg.NewDevice, which never suspends; the queue, the reader
	// goroutine and the direction mapping under test are unchanged.
	portal, err := clientawg.NewDeviceWithSuspendedReadsForTest(clientawg.Config{
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
	if !portal.ReadsSuspendedForTest() {
		t.Fatal("fixture built a device whose inbound reads are NOT suspended: " +
			"every inbound occupancy, peak and drain assertion would race the upstream reader")
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
		"ClientVirtualTUNDrops":  b.ClientVirtualTUNDrops,
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
		"ClientVirtualTUNDrops":  true,
	}

	// ReturnInjectionTUNDrops is deliberately absent from this map: it is an
	// ownership annotation on an injection rejection already counted by
	// ReturnVirtualTUNDrops, not an additional loss. Counting it here would
	// assert exclusivity between a loss and its own overlap marker.
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

	// A queue-full injection rejection is owned by the VirtualTUN inbound drop
	// bucket, so it must surface once as ReturnVirtualTUNDrops and never also
	// as a non-TUN injection error. The rejection is produced through the real
	// injection site so the ownership counter is exercised, rather than the
	// counters being incremented by hand (issue #424 round 2, finding 3).
	t.Run("ReturnVirtualTUNDrops", func(t *testing.T) {
		svc, _, engine, resolver, _ := newSingleOwnerFixture(t)
		// Must precede the priming packets: the upstream TUN reader is started
		// in NewDevice and its Down() cannot stop it, so without suspension it
		// drains the queue below and it never fills, silently skipping this
		// subtest instead of covering the ownership annotation (issue #424
		// round 3, finding 1).
		requireDeterministicInboundQueue(t, engine)
		resolver.Update(ingress.PeerOwnership{
			PeerPublicKey: "ps-peer", IP: netip.MustParseAddr("10.100.0.1"), ConnectionID: "c", UserID: "u",
		})
		pkt := buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.1"), 40)

		// Fill the inbound queue, then push through writeReturnPacket until the
		// device rejects with ErrQueueFull.
		for i := 0; i < 2; i++ {
			if err := engine.portal.InjectInbound(pkt); err != nil {
				t.Fatalf("priming InjectInbound %d: %v", i, err)
			}
		}
		var err error
		for i := 0; i < 10; i++ {
			_, err = engine.writeReturnPacket("ps-peer", "10.100.0.1", pkt)
			if errors.Is(err, virtualtun.ErrQueueFull) {
				break
			}
		}
		if !errors.Is(err, virtualtun.ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull, got %v", err)
		}

		stats := engine.ReturnStats()
		if stats.InjectionErrors != 1 || stats.InjectionTunDrops != 1 {
			t.Fatalf("expected the injection site to own exactly 1 of 1 rejections, got %d/%d",
				stats.InjectionErrors, stats.InjectionTunDrops)
		}

		var status Status
		svc.populateOperationalDiagnostics(&status)
		assertDropBreakdown(t, status.DropCategories, "ReturnVirtualTUNDrops")
	})
}

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
	if dropsProb.ObservedRate != "5 drops" {
		t.Errorf("drops observed_rate: got %q, want '5 drops'", dropsProb.ObservedRate)
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

func TestForwarderDrops_RestartDoesNotAttributePreRestartDrops(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if svc.forwarder == nil {
		t.Fatal("expected non-nil forwarder on service")
	}

	// 1. Start forwarder in initial generation
	svc.forwarder.Start(ctx)

	// 2. Seed pre-restart drops into forwarder
	svc.forwarder.SeedDropsForTest(10, 5, 2, 7, 3, 1)

	qF, noRoute, total := svc.forwarder.DropStats()
	if qF != 10 || noRoute != 5 || total != 17 {
		t.Fatalf("expected seeded drops before restart: qF=10 noRoute=5 total=17, got (%d, %d, %d)", qF, noRoute, total)
	}
	cqF, crL, cnB, cTot := svc.forwarder.ClientDropStats()
	if cqF != 7 || crL != 3 || cnB != 1 || cTot != 11 {
		t.Fatalf("expected seeded client drops before restart: got (%d, %d, %d, %d)", cqF, crL, cnB, cTot)
	}

	// 3. Stop forwarder and restart (simulating restart lifecycle)
	_ = svc.forwarder.Stop()
	svc.forwarder.Start(ctx)

	// 4. Verify that drops since startup are now ZERO
	qF, noRoute, total = svc.forwarder.DropStats()
	if qF != 0 || noRoute != 0 || total != 0 {
		t.Fatalf("expected 0 drops after restart: got qF=%d noRoute=%d total=%d", qF, noRoute, total)
	}
	cqF, crL, cnB, cTot = svc.forwarder.ClientDropStats()
	if cqF != 0 || crL != 0 || cnB != 0 || cTot != 0 {
		t.Fatalf("expected 0 client drops after restart: got (%d, %d, %d, %d)", cqF, crL, cnB, cTot)
	}
	if qfSince := svc.forwarder.DropsQueueFullSinceStartup(); qfSince != 0 {
		t.Fatalf("expected DropsQueueFullSinceStartup=0, got %d", qfSince)
	}
	if ovSince := svc.forwarder.DropsPacketTooLargeSinceStartup(); ovSince != 0 {
		t.Fatalf("expected DropsPacketTooLargeSinceStartup=0, got %d", ovSince)
	}

	// 5. Verify diagnosticsInputs and collectDropCategories reflect zero forwarder drops
	inputs := svc.captureDiagnosticsInputs()
	drops := inputs.collectDropCategories()
	if drops.ReturnQueueFull != 0 {
		t.Errorf("ReturnQueueFull = %d, want 0 after restart", drops.ReturnQueueFull)
	}
	if drops.ReturnPacketTooLarge != 0 {
		t.Errorf("ReturnPacketTooLarge = %d, want 0 after restart", drops.ReturnPacketTooLarge)
	}
	if drops.ClientBackendQueueFull != 0 {
		t.Errorf("ClientBackendQueueFull = %d, want 0 after restart", drops.ClientBackendQueueFull)
	}
	if drops.ClientRateLimited != 0 {
		t.Errorf("ClientRateLimited = %d, want 0 after restart", drops.ClientRateLimited)
	}

	// 6. Seed fresh drops in the new epoch and verify they ARE reported
	svc.forwarder.SeedDropsForTest(3, 0, 1, 4, 0, 0)
	qF, _, total = svc.forwarder.DropStats()
	if qF != 3 || total != 4 {
		t.Fatalf("expected fresh drops: qF=3 total=4, got (%d, %d)", qF, total)
	}
	dropsAfter := svc.captureDiagnosticsInputs().collectDropCategories()
	if dropsAfter.ReturnQueueFull != 3 {
		t.Errorf("ReturnQueueFull = %d, want 3 for fresh drops", dropsAfter.ReturnQueueFull)
	}
	if dropsAfter.ReturnPacketTooLarge != 1 {
		t.Errorf("ReturnPacketTooLarge = %d, want 1 for fresh drops", dropsAfter.ReturnPacketTooLarge)
	}
	if dropsAfter.ClientBackendQueueFull != 4 {
		t.Errorf("ClientBackendQueueFull = %d, want 4 for fresh drops", dropsAfter.ClientBackendQueueFull)
	}
}

func TestHistoricalSeries_Populates1mAnd5m(t *testing.T) {
	rh := NewRollingHistory()
	baseTime := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	// Before adding any points, windows must be initialized non-nil empty slices
	initial := rh.Snapshot()
	if initial.Window1m == nil || initial.Window5m == nil || initial.Window15m == nil {
		t.Fatal("expected non-nil windows in initial snapshot")
	}
	if len(initial.Window1m) != 0 || len(initial.Window5m) != 0 {
		t.Fatalf("expected empty initial windows, got 1m=%d 5m=%d", len(initial.Window1m), len(initial.Window5m))
	}

	// Add 3 samples at 10s intervals
	for i := 0; i < 3; i++ {
		rh.Add(HistoryPoint{
			Timestamp: baseTime.Add(time.Duration(i*10) * time.Second).Unix(),
			RxBps:     float64((i + 1) * 1000),
		})
	}
	snap3 := rh.Snapshot()
	if len(snap3.Window1m) != 3 {
		t.Fatalf("expected Window1m len=3, got %d", len(snap3.Window1m))
	}
	if len(snap3.Window5m) != 3 {
		t.Fatalf("expected Window5m len=3, got %d", len(snap3.Window5m))
	}

	// Add up to 50 samples to saturate 1m (cap 6) and 5m (cap 30)
	for i := 3; i < 50; i++ {
		rh.Add(HistoryPoint{
			Timestamp: baseTime.Add(time.Duration(i*10) * time.Second).Unix(),
			RxBps:     float64((i + 1) * 1000),
		})
	}
	snapFull := rh.Snapshot()
	if len(snapFull.Window1m) != 6 {
		t.Fatalf("expected Window1m capped at 6, got %d", len(snapFull.Window1m))
	}
	if len(snapFull.Window5m) != 30 {
		t.Fatalf("expected Window5m capped at 30, got %d", len(snapFull.Window5m))
	}
	if len(snapFull.Window15m) != 50 {
		t.Fatalf("expected Window15m len=50, got %d", len(snapFull.Window15m))
	}

	// Verify the latest point in Window1m is the last added sample
	lastSampleTime := baseTime.Add(49 * 10 * time.Second).Unix()
	if snapFull.Window1m[5].Timestamp != lastSampleTime {
		t.Errorf("Window1m last point timestamp=%d, want %d", snapFull.Window1m[5].Timestamp, lastSampleTime)
	}
	if snapFull.Window5m[29].Timestamp != lastSampleTime {
		t.Errorf("Window5m last point timestamp=%d, want %d", snapFull.Window5m[29].Timestamp, lastSampleTime)
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
