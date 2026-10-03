package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

func TestProblemRoutesRankCurrentPressureBeforeLifetimeHistory(t *testing.T) {
	routes := []forwarder.RouteInfo{
		{
			PeerKey:     "historical",
			HasPressure: true,
			Stats: forwarder.RouteQueueStats{
				Capacity:       10,
				Occupancy:      8,
				QueueFullDrops: 1000,
				WriteErrors:    100,
				WriteStalls:    100,
			},
		},
		{
			PeerKey:     "fresh-loss",
			HasPressure: true,
			Stats: forwarder.RouteQueueStats{
				Capacity:             10,
				QueueFullDrops:       1,
				QueueFullDropsRecent: 1,
			},
		},
	}

	got := forwarder.ProblemRoutesFromSnapshot(routes, 10)
	if len(got) != 2 {
		t.Fatalf("expected two problem routes, got %d", len(got))
	}
	if got[0].PeerKey != "fresh-loss" {
		t.Fatalf("fresh packet loss must outrank historical totals, got order %q then %q",
			got[0].PeerKey, got[1].PeerKey)
	}
}

func TestProblemRoutePressureNoteDescribesCurrentCause(t *testing.T) {
	items := collectProblemRoutes([]forwarder.RouteInfo{
		{
			PeerKey:     "peer-current",
			HasPressure: true,
			Stats: forwarder.RouteQueueStats{
				QueueFullDrops:    900,
				WriteErrors:       901,
				WriteErrorsRecent: 1,
			},
		},
		{
			PeerKey:     "peer-recovered",
			HasPressure: false,
			Stats: forwarder.RouteQueueStats{
				QueueFullDrops: 500,
				WriteErrors:    500,
				WriteStalls:    500,
			},
		},
	})
	if len(items) != 2 {
		t.Fatalf("expected two route items, got %d", len(items))
	}
	if items[0].PressureNote != "Recent write errors: 1" {
		t.Fatalf("current cause must win over lifetime drop history, got %q", items[0].PressureNote)
	}
	if strings.Contains(items[0].PressureNote, "900") {
		t.Fatalf("pressure note surfaced lifetime history as the current cause: %q", items[0].PressureNote)
	}
	if items[1].PressureNote != "" {
		t.Fatalf("recovered route must not carry a current-pressure reason, got %q", items[1].PressureNote)
	}
}

func TestGetStatusReusesOneRoutePressureSnapshotAcrossSlowAssembly(t *testing.T) {
	const (
		peer = "round7-peer-public-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa="
		ip   = "10.100.0.3"
	)

	fwd, err := forwarder.NewForwarderWithLimits(nil, "10.100.0.0/16", 2, 10)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	fwd.RegisterSession("round7-session", "round7-connection", peer, ip, 1)

	// Prime the route-pressure baseline, then move beyond the 200ms sampling
	// floor before creating the incident.
	fwd.InspectRoutes()
	time.Sleep(250 * time.Millisecond)

	queue, ok := fwd.GetClientPacketChannel(peer)
	if !ok {
		t.Fatal("client queue missing")
	}
	packet := returnPacket(ip)
	for i := 0; i < cap(queue); i++ {
		if err := fwd.RouteBackendToClient(1, packet, ip); err != nil {
			t.Fatalf("fill queue %d: %v", i, err)
		}
	}
	if err := fwd.RouteBackendToClient(1, packet, ip); !errors.Is(err, forwarder.ErrQueueFull) {
		t.Fatalf("expected queue-full drop, got %v", err)
	}
	// The queue itself is no longer pressured. The only current signal for
	// this assertion is the recent drop delta.
	for len(queue) > 0 {
		<-queue
	}

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	svc.mu.Lock()
	svc.forwarder = fwd
	svc.mu.Unlock()

	// Force the status request to spend longer than the route recency floor
	// between the legacy status assembly and operational diagnostics. Before
	// the fix, AllRouteQueueStats consumed the delta, this delay elapsed, and
	// the later InspectRoutes/ProblemRoutes read observed zero.
	oldDetector := externalIPDetector
	externalIPDetector = func(context.Context) string {
		time.Sleep(350 * time.Millisecond)
		return "8.8.8.8"
	}
	t.Cleanup(func() { externalIPDetector = oldDetector })
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")

	status, err := svc.GetStatus(t.Context())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	fp := ingress.PeerKeyFingerprint(peer)
	legacy, ok := status.ForwarderRouteQueues[fp]
	if !ok {
		t.Fatalf("legacy route telemetry missing fingerprint %q", fp)
	}
	if legacy.QueueFullDropsRecent != 1 {
		t.Fatalf("legacy snapshot recent drops = %d, want 1", legacy.QueueFullDropsRecent)
	}
	if len(status.ProblemRoutes) != 1 {
		t.Fatalf("same response lost the recent incident from problem_routes: %+v", status.ProblemRoutes)
	}
	if !status.ProblemRoutes[0].HasPressure {
		t.Fatalf("problem route from the coherent snapshot must retain pressure: %+v", status.ProblemRoutes[0])
	}
	if status.ProblemRoutes[0].PressureNote != "Recent queue drops: 1" {
		t.Fatalf("problem route reason = %q, want recent-drop reason", status.ProblemRoutes[0].PressureNote)
	}
	if len(status.AllRoutes) != 1 || !status.AllRoutes[0].HasPressure {
		t.Fatalf("all_routes must reuse the same pressure observation: %+v", status.AllRoutes)
	}
}
