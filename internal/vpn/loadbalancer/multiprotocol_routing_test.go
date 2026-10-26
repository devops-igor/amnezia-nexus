package loadbalancer

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestFilterTunnelsByProtocol(t *testing.T) {
	t1 := &models.BackendTunnel{ID: 1, Protocol: "awg"}
	t2 := &models.BackendTunnel{ID: 2, Protocol: ""}     // empty defaults to awg
	t3 := &models.BackendTunnel{ID: 3, Protocol: "awg2"} // alias normalizes to awg
	t4 := &models.BackendTunnel{ID: 4, Protocol: "vless"}
	t5 := &models.BackendTunnel{ID: 5, Protocol: "naive"}

	all := []*models.BackendTunnel{t1, t2, t3, t4, t5, nil}

	awgOnly := models.FilterTunnelsByProtocol(all, "awg")
	if len(awgOnly) != 3 {
		t.Fatalf("expected 3 AWG tunnels, got %d", len(awgOnly))
	}
	for _, tun := range awgOnly {
		if models.NormalizeTunnelProtocol(tun.Protocol) != models.ProtocolAWG {
			t.Fatalf("expected AWG tunnel, got protocol %s", tun.Protocol)
		}
	}

	vlessOnly := models.FilterTunnelsByProtocol(all, "vless")
	if len(vlessOnly) != 1 || vlessOnly[0].ID != 4 {
		t.Fatalf("expected tunnel 4 for vless, got: %+v", vlessOnly)
	}

	naiveOnly := models.FilterTunnelsByProtocol(all, "naive")
	if len(naiveOnly) != 1 || naiveOnly[0].ID != 5 {
		t.Fatalf("expected tunnel 5 for naive, got: %+v", naiveOnly)
	}

	// Unknown protocol returns empty slice
	none := models.FilterTunnelsByProtocol(all, "unknown")
	if len(none) != 0 {
		t.Fatalf("expected empty slice for unknown protocol, got %d", len(none))
	}

	// Verify original slice was not mutated
	if len(all) != 6 {
		t.Fatalf("input slice length was mutated: %d", len(all))
	}
}

func TestStickySessionManager_HandleFailover_EmptyListCacheGuard(t *testing.T) {
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 10,
		AffinityTTL:        10 * time.Minute,
	}
	base := NewRoundRobinBalancer(caps)

	// Pre-populate balancer's cache with an AWG tunnel via UpdateBackends
	awgCached := &models.BackendTunnel{
		ID:       1,
		Status:   "active",
		Enabled:  true,
		Protocol: models.ProtocolAWG,
	}
	base.UpdateBackends([]*models.BackendTunnel{awgCached})

	ctx := context.Background()
	// Confirm that if SelectBackend is called with an empty list directly, it returns the cached AWG tunnel
	b, err := base.SelectBackend(ctx, &RoutingRequest{})
	if err != nil || b == nil || b.ID != 1 {
		t.Fatalf("precondition failed: balancer should use cached tunnel on empty list, got b=%+v err=%v", b, err)
	}

	// Now create sticky manager wrapping base
	sm := NewStickySessionManager(nil, base, caps)
	sm.AssignPeerAffinity("peer-vless-1", 10) // peer is on degraded VLESS tunnel 10

	// Degraded tunnel 10 is VLESS. Available pool only contains AWG tunnels (e.g. tunnel 1).
	availablePool := []*models.BackendTunnel{awgCached}

	// HandleFailover for VLESS degraded tunnel MUST return ErrNoActiveBackends
	// and MUST NOT fall back to the cached AWG tunnel!
	res, err := sm.HandleFailover(ctx, 10, availablePool, models.ProtocolVLESS)
	if err != ErrNoActiveBackends {
		t.Fatalf("expected ErrNoActiveBackends on empty same-family candidate list, got err=%v res=%+v", err, res)
	}
}

func TestStickySessionManager_HandleFailover_SameFamilyIsolation(t *testing.T) {
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 10,
		AffinityTTL:        10 * time.Minute,
	}
	base := NewRoundRobinBalancer(caps)
	sm := NewStickySessionManager(nil, base, caps)
	ctx := context.Background()

	awgDegraded := &models.BackendTunnel{ID: 1, Protocol: models.ProtocolAWG}
	awgHealthy := &models.BackendTunnel{ID: 2, Status: "active", Enabled: true, Protocol: models.ProtocolAWG}

	vlessDegraded := &models.BackendTunnel{ID: 10, Protocol: models.ProtocolVLESS}
	vlessHealthy := &models.BackendTunnel{ID: 11, Status: "active", Enabled: true, Protocol: models.ProtocolVLESS}

	allAvailable := []*models.BackendTunnel{awgHealthy, vlessHealthy}

	// Peer 1 on degraded AWG tunnel 1
	sm.AssignPeerAffinity("peer-awg", awgDegraded.ID)
	resAWG, err := sm.HandleFailover(ctx, awgDegraded.ID, allAvailable, models.ProtocolAWG)
	if err != nil {
		t.Fatalf("HandleFailover AWG failed: %v", err)
	}
	if len(resAWG.Migrations) != 1 || resAWG.Migrations[0].NewBackendTunnelID != awgHealthy.ID {
		t.Fatalf("expected AWG peer to fail over to AWG target %d, got: %+v", awgHealthy.ID, resAWG.Migrations)
	}

	// Peer 2 on degraded VLESS tunnel 10
	sm.AssignPeerAffinity("peer-vless", vlessDegraded.ID)
	resVLESS, err := sm.HandleFailover(ctx, vlessDegraded.ID, allAvailable, models.ProtocolVLESS)
	if err != nil {
		t.Fatalf("HandleFailover VLESS failed: %v", err)
	}
	if len(resVLESS.Migrations) != 1 || resVLESS.Migrations[0].NewBackendTunnelID != vlessHealthy.ID {
		t.Fatalf("expected VLESS peer to fail over to VLESS target %d, got: %+v", vlessHealthy.ID, resVLESS.Migrations)
	}
}
