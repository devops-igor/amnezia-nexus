package vpn

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

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
