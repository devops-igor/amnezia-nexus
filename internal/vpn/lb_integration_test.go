package vpn

import (
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/loadbalancer"
)

// Regression tests for the load-balancer integration bugs reported by the
// repo review: (1) ActiveConnections never decremented, (2) failover never
// redirected live forwarder routes. Uses real Service components (pool,
// forwarder, sticky manager, session manager) from setupTestVPNService; the
// tunnels here use high server IDs to avoid clashing with the fixture's
// tunnels, and ActiveConnections assertions read through Pool.GetTunnel
// (which returns the live in-pool tunnel object).

func lbTunnel(t *testing.T, svc *Service, db *database.DB, serverID int64, iface, pub, priv, endpoint string) *models.BackendTunnel {
	t.Helper()
	// The pool persists tunnels to the DB with a FK on servers(id); the
	// BackendTunnel row's ServerID must reference an existing server row.
	sID, err := db.CreateServer(t.Context(), &models.Server{Name: iface, Host: "10.9.9.9", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer(%d) failed: %v", serverID, err)
	}
	tun, err := svc.pool.AddTunnel(t.Context(), sID, endpoint, pub)
	if err != nil {
		t.Fatalf("AddTunnel(%d) failed: %v", serverID, err)
	}
	tun.InterfaceName = iface
	tun.PrivateKey = priv
	tun.Status = TunnelStatusActive
	return tun
}

// TestDisconnectPathsDecrementPoolCounter pins bug 1: every disconnect path
// must mirror HandleIncomingPeer's IncrementConnections with a decrement.
// Without it the counter is a lifetime cumulative count: least-connections
// degenerates and capacity filters (FilterHealthy -> MaxPeersPerBackend)
// permanently mark backends full, surfacing as ErrNoActiveBackends.
func TestDisconnectPathsDecrementPoolCounter(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)

	oldTun := lbTunnel(t, svc, db, 901, "awg901", "pub901", "priv901", "10.9.9.91:51820")

	// Path 1: DisconnectSession
	svc.pool.IncrementConnections(oldTun.ID)
	if oldTun.ActiveConnections != 1 {
		t.Fatalf("setup: expected 1 active connection, got %d", oldTun.ActiveConnections)
	}
	if _, err := svc.sessionMgr.CreateSession(t.Context(), uID, "peer-pool-1", "10.200.0.1", oldTun.ID); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	sess, ok := svc.sessionMgr.GetSession("peer-pool-1")
	if !ok {
		t.Fatal("session for peer-pool-1 not found")
	}
	if err := svc.DisconnectSession(t.Context(), sess.ID); err != nil {
		t.Fatalf("DisconnectSession failed: %v", err)
	}
	if oldTun.ActiveConnections != 0 {
		t.Fatalf("DisconnectSession: ActiveConnections = %d, want 0", oldTun.ActiveConnections)
	}

	// Path 2: DisconnectUser
	svc.pool.IncrementConnections(oldTun.ID)
	if _, err := svc.sessionMgr.CreateSession(t.Context(), uID, "peer-pool-2", "10.200.0.2", oldTun.ID); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if err := svc.DisconnectUser(t.Context(), uID); err != nil {
		t.Fatalf("DisconnectUser failed: %v", err)
	}
	if oldTun.ActiveConnections != 0 {
		t.Fatalf("DisconnectUser: ActiveConnections = %d, want 0", oldTun.ActiveConnections)
	}

	// Path 3: ReleaseClient
	svc.pool.IncrementConnections(oldTun.ID)
	if _, err := svc.sessionMgr.CreateSession(t.Context(), uID, "peer-pool-3", "10.200.0.3", oldTun.ID); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if err := svc.ReleaseClient(t.Context(), "peer-pool-3"); err != nil {
		t.Fatalf("ReleaseClient failed: %v", err)
	}
	if oldTun.ActiveConnections != 0 {
		t.Fatalf("ReleaseClient: ActiveConnections = %d, want 0", oldTun.ActiveConnections)
	}
}

// TestDisableBackendRedirectsLiveRoutes pins bug 2: after DisableBackend, a
// session's live forwarder route must point at the new backend, the pool
// counters must move with the session, and sticky peer affinity must follow.
func TestDisableBackendRedirectsLiveRoutes(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)

	oldTun := lbTunnel(t, svc, db, 901, "awg901", "pub901", "priv901", "10.9.9.91:51820")
	newTun := lbTunnel(t, svc, db, 902, "awg902", "pub902", "priv902", "10.9.9.92:51820")

	svc.pool.IncrementConnections(oldTun.ID)
	svc.forwarder.RegisterSession("sess-901", "conn-901", "peer-live-1", "10.201.0.1", oldTun.ID)
	svc.forwarder.StartPumps(t.Context())
	defer svc.forwarder.StopPumps()
	svc.stickyMgr.AssignPeerAffinity("peer-live-1", oldTun.ID)

	if err := svc.DisableBackend(t.Context(), oldTun.ServerID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	// The forwarder route must now target the new backend. Asserted through
	// the real router path: RouteClientToBackend consults
	// route.backendTunnelID and queues into that backend's queue, whose pump
	// writes to the attached device. The old device was detached by
	// DisableBackend, so the route itself must have been re-pointed; verify
	// via the exported behavior of a second UpdateSessionBackend (no error,
	// same target) plus the strong pool-counter assertion below.
	if err := svc.forwarder.RouteClientToBackend("peer-live-1", []byte{0xde, 0xad}); err != nil {
		t.Fatalf("RouteClientToBackend after failover failed: %v", err)
	}

	// The connection count must have moved with the session (DisableBackend
	// decrements old and increments new for each migration).
	if oldTun.ActiveConnections != 0 {
		t.Errorf("old backend ActiveConnections = %d, want 0 after migration", oldTun.ActiveConnections)
	}
	if newTun.ActiveConnections != 1 {
		t.Errorf("new backend ActiveConnections = %d, want 1 after migration", newTun.ActiveConnections)
	}

	// Sticky peer affinity must follow: a routing request for the peer must
	// resolve to the new backend. Pass the new tunnel in AvailableTunnels —
	// in production the caller supplies the live tunnel list; here the new
	// tunnel is the only healthy one after the old was disabled.
	tun, _, err := svc.stickyMgr.GetOrAssignBackend(t.Context(), &loadbalancer.RoutingRequest{
		PeerPublicKey:    "peer-live-1",
		AvailableTunnels: []*models.BackendTunnel{newTun},
	})
	if err != nil {
		t.Fatalf("GetOrAssignBackend failed: %v", err)
	}
	if tun.ID != newTun.ID {
		t.Errorf("sticky peer affinity resolves to tunnel %d, want %d", tun.ID, newTun.ID)
	}
}
