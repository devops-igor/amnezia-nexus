package loadbalancer

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestLoadBalancer_MixedPool_IPv6Selection(t *testing.T) {
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 20,
		AffinityTTL:        10 * time.Minute,
	}

	tunIPv4 := &models.BackendTunnel{
		ID:                1,
		ServerID:          10,
		Endpoint:          "198.51.100.1:443",
		Protocol:          models.ProtocolNaive,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 5,
		LatencyMS:         50,
	}
	tunIPv6 := &models.BackendTunnel{
		ID:                2,
		ServerID:          20,
		Endpoint:          "[2001:db8::10]:443",
		Protocol:          models.ProtocolNaive,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 1, // lowest connections
		LatencyMS:         20,
	}
	tunDualStack := &models.BackendTunnel{
		ID:                3,
		ServerID:          30,
		Endpoint:          "dualstack.example.com:443",
		Protocol:          models.ProtocolNaive,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 3,
		LatencyMS:         30,
	}
	tunAWG := &models.BackendTunnel{
		ID:                4,
		ServerID:          40,
		Endpoint:          "198.51.100.2:51820",
		Protocol:          models.ProtocolAWG,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 0,
	}

	naiveTunnels := []*models.BackendTunnel{tunIPv4, tunIPv6, tunDualStack}
	ctx := context.Background()

	// 1. LeastConnections: selects tunIPv6 because ActiveConnections=1 is minimum among Naive
	t.Run("LeastConnections_SelectsIPv6", func(t *testing.T) {
		lb := NewLeastConnectionsBalancer(caps)
		req := &RoutingRequest{
			UserID:           "u1",
			AvailableTunnels: naiveTunnels,
		}
		selected, err := lb.SelectBackend(ctx, req)
		if err != nil {
			t.Fatalf("SelectBackend failed: %v", err)
		}
		if selected.ID != tunIPv6.ID {
			t.Fatalf("expected IPv6 tunnel %d, got %d (endpoint: %s)", tunIPv6.ID, selected.ID, selected.Endpoint)
		}
	})

	// 2. RoundRobin: uniformly rotates through all 3 Naive backends including IPv6
	t.Run("RoundRobin_IncludesIPv6", func(t *testing.T) {
		rb := NewRoundRobinBalancer(caps)
		seen := make(map[int64]bool)
		for i := 0; i < 6; i++ {
			req := &RoutingRequest{
				UserID:           "u1",
				AvailableTunnels: naiveTunnels,
			}
			sel, err := rb.SelectBackend(ctx, req)
			if err != nil {
				t.Fatalf("round %d: SelectBackend failed: %v", i, err)
			}
			seen[sel.ID] = true
		}
		if !seen[tunIPv6.ID] {
			t.Errorf("RoundRobin never selected IPv6 tunnel %d", tunIPv6.ID)
		}
		if len(seen) != 3 {
			t.Errorf("expected all 3 Naive tunnels to be seen, saw %d", len(seen))
		}
	})

	// 3. WeightedRoundRobin: weighted distribution favors IPv6 when higher weight is configured
	t.Run("WeightedRoundRobin_FavorsIPv6", func(t *testing.T) {
		weights := map[int64]int{
			tunIPv4.ServerID:      1,
			tunIPv6.ServerID:      8, // heavy weight on IPv6 backend
			tunDualStack.ServerID: 1,
		}
		wb := NewWeightedRoundRobinBalancer(weights, caps)
		wb.UpdateBackends(naiveTunnels)

		counts := make(map[int64]int)
		for i := 0; i < 50; i++ {
			req := &RoutingRequest{
				UserID:           "u1",
				AvailableTunnels: naiveTunnels,
			}
			sel, err := wb.SelectBackend(ctx, req)
			if err != nil {
				t.Fatalf("iteration %d: SelectBackend failed: %v", i, err)
			}
			counts[sel.ID]++
		}
		if counts[tunIPv6.ID] <= counts[tunIPv4.ID] || counts[tunIPv6.ID] <= counts[tunDualStack.ID] {
			t.Errorf("expected IPv6 tunnel %d to dominate weighted selections, got counts: %+v", tunIPv6.ID, counts)
		}
	})

	// 4. Protocol isolation guard: mixed pool with AWG must not route Naive request to AWG
	t.Run("ProtocolFilter_ExcludesAWG", func(t *testing.T) {
		mixedPool := []*models.BackendTunnel{tunIPv4, tunIPv6, tunDualStack, tunAWG}
		filtered := models.FilterTunnelsByProtocol(mixedPool, models.ProtocolNaive)
		if len(filtered) != 3 {
			t.Fatalf("expected 3 filtered naive tunnels, got %d", len(filtered))
		}
		for _, tun := range filtered {
			if tun.Protocol != models.ProtocolNaive {
				t.Errorf("unexpected non-naive tunnel in filtered pool: %+v", tun)
			}
		}
	})
}

func TestLoadBalancer_IPv6_DegradationAndFailover(t *testing.T) {
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 10,
		AffinityTTL:        10 * time.Minute,
	}

	tunIPv6 := &models.BackendTunnel{
		ID:                20,
		ServerID:          200,
		Endpoint:          "[2001:db8::10]:443",
		Protocol:          models.ProtocolNaive,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 1,
	}
	tunIPv4Healthy := &models.BackendTunnel{
		ID:                21,
		ServerID:          201,
		Endpoint:          "198.51.100.1:443",
		Protocol:          models.ProtocolNaive,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 0,
	}
	tunAWG := &models.BackendTunnel{
		ID:                1,
		ServerID:          100,
		Endpoint:          "198.51.100.2:51820",
		Protocol:          models.ProtocolAWG,
		Status:            "active",
		Enabled:           true,
		ActiveConnections: 0,
	}

	base := NewRoundRobinBalancer(caps)
	sm := NewStickySessionManager(nil, base, caps)
	ctx := context.Background()

	// Initial affinity assigned to IPv6 Naive tunnel
	sm.AssignPeerAffinity("peer-naive-ipv6", tunIPv6.ID)

	// Verify affinity routes to IPv6 tunnel while healthy
	activePool := []*models.BackendTunnel{tunIPv6, tunIPv4Healthy, tunAWG}
	aff, ok := sm.GetPeerAffinity("peer-naive-ipv6")
	if !ok || aff != tunIPv6.ID {
		t.Fatalf("expected initial affinity %d (ok=true), got %d (ok=%v)", tunIPv6.ID, aff, ok)
	}

	// 1. Simulate unreachability / degradation of IPv6 backend
	tunIPv6.Status = "degraded"

	// Available pool now reflects degraded status for tunIPv6
	res, err := sm.HandleFailover(ctx, tunIPv6.ID, activePool, models.ProtocolNaive)
	if err != nil {
		t.Fatalf("HandleFailover failed on IPv6 degradation: %v", err)
	}

	// Verify session migrated strictly to healthy Naive backend (tunIPv4Healthy)
	if len(res.Migrations) != 1 {
		t.Fatalf("expected 1 migration, got %d", len(res.Migrations))
	}
	mig := res.Migrations[0]
	if mig.PeerPublicKey != "peer-naive-ipv6" {
		t.Errorf("migration peer key = %q, want peer-naive-ipv6", mig.PeerPublicKey)
	}
	if mig.NewBackendTunnelID != tunIPv4Healthy.ID {
		t.Fatalf("expected failover target to be healthy Naive backend %d, got %d (AWG crossover prohibited!)",
			tunIPv4Healthy.ID, mig.NewBackendTunnelID)
	}

	// 2. FilterHealthy excludes degraded IPv6 backend
	healthy := FilterHealthy(activePool, caps.MaxPeersPerBackend)
	for _, h := range healthy {
		if h.ID == tunIPv6.ID {
			t.Errorf("degraded IPv6 tunnel %d must not appear in FilterHealthy", tunIPv6.ID)
		}
	}

	// 3. Complete degradation of all Naive backends returns ErrNoActiveBackends
	tunIPv4Healthy.Status = "degraded"
	_, err = sm.HandleFailover(ctx, tunIPv4Healthy.ID, activePool, models.ProtocolNaive)
	if err != ErrNoActiveBackends {
		t.Fatalf("expected ErrNoActiveBackends when all Naive backends degrade, got: %v", err)
	}

	// 4. Recovery: IPv6 backend restored to active is selected again
	tunIPv6.Status = "active"
	recoveredPool := []*models.BackendTunnel{tunIPv6}
	req := &RoutingRequest{
		UserID:           "u2",
		AvailableTunnels: recoveredPool,
	}
	sel, err := base.SelectBackend(ctx, req)
	if err != nil {
		t.Fatalf("SelectBackend after recovery failed: %v", err)
	}
	if sel.ID != tunIPv6.ID {
		t.Errorf("expected recovered IPv6 tunnel %d to be selected, got %d", tunIPv6.ID, sel.ID)
	}
}
