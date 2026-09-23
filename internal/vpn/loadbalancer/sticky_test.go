package loadbalancer

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func setupTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_vpn_lb.db")
	db, err := database.Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func TestStickySessionManager(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 50}
	base := NewLeastConnectionsBalancer(caps)
	sticky := NewStickySessionManager(db, base, caps)

	tunnels := []*models.BackendTunnel{
		{ID: 1, Status: "active", ActiveConnections: 10},
		{ID: 2, Status: "active", ActiveConnections: 5},
	}

	// 1. Nil request check
	if _, _, err := sticky.GetOrAssignBackend(ctx, nil); err == nil {
		t.Errorf("expected error for nil request")
	}

	// 2. First request (new assignment)
	reqUserA := &RoutingRequest{
		UserID:           "user-a",
		PeerPublicKey:    "peer-a",
		AvailableTunnels: tunnels,
	}
	backend1, isNew, err := sticky.GetOrAssignBackend(ctx, reqUserA)
	if err != nil || !isNew || backend1.ID != 2 {
		t.Fatalf("expected new assignment to tunnel 2, got %+v (isNew: %v, err: %v)", backend1, isNew, err)
	}

	// 3. Second request for same user (sticky hit)
	// Even if tunnel 1 now has 0 connections, user-a should stick to tunnel 2!
	tunnels[0].ActiveConnections = 0
	backend2, isNew, err := sticky.GetOrAssignBackend(ctx, reqUserA)
	if err != nil || isNew || backend2.ID != 2 {
		t.Fatalf("expected sticky hit on tunnel 2, got %+v (isNew: %v, err: %v)", backend2, isNew, err)
	}

	// 4. Query affinity
	tid, ok := sticky.GetAffinity("user-a")
	if !ok || tid != 2 {
		t.Errorf("GetAffinity mismatch: tid=%d, ok=%v", tid, ok)
	}
	if _, ok := sticky.GetAffinity("ghost"); ok {
		t.Errorf("expected ghost to have no affinity")
	}

	// 5. Failover when assigned backend degrades
	tunnels[1].Status = "degraded" // Tunnel 2 degraded
	backendFailover, isNew, err := sticky.GetOrAssignBackend(ctx, reqUserA)
	if err != nil || !isNew || backendFailover.ID != 1 {
		t.Fatalf("expected failover to tunnel 1, got %+v (isNew: %v, err: %v)", backendFailover, isNew, err)
	}

	// 6. Manual affinities and clearing
	sticky.AssignAffinity("user-b", 1)
	sticky.AssignPeerAffinity("peer-b", 1)
	if tid, _ := sticky.GetAffinity("user-b"); tid != 1 {
		t.Errorf("expected user-b affinity to be 1")
	}
	sticky.ClearAffinity("user-b")
	if _, ok := sticky.GetAffinity("user-b"); ok {
		t.Errorf("expected user-b affinity cleared")
	}
	sticky.ClearPeerAffinity("peer-b")

	// 7. HandleFailover with DB Sessions
	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Host", Host: "1.1.1.1"})
	t1ID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "pub1",
		PrivateKey:    "priv1",
		Endpoint:      "1.1.1.1:51820",
		Status:        "active",
	})
	t2ID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-2",
		PublicKey:     "pub2",
		PrivateKey:    "priv2",
		Endpoint:      "1.1.1.1:51821",
		Status:        "active",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "failover_user"})

	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sess-failover-1",
		UserID:          uID,
		BackendTunnelID: t1ID,
		PeerPublicKey:   "peer-failover-1",
		AssignedIP:      "10.100.0.99",
		Status:          "connected",
	})

	sticky.AssignAffinity(uID, t1ID)
	sticky.AssignPeerAffinity("peer-failover-1", t1ID)

	healthyPool := []*models.BackendTunnel{
		{ID: t2ID, Status: "active", ActiveConnections: 0},
	}

	failover, err := sticky.HandleFailover(ctx, t1ID, healthyPool)
	if err != nil {
		t.Fatalf("HandleFailover failed: %v", err)
	}
	if failover == nil {
		t.Fatal("HandleFailover returned nil result without error")
	}
	if len(failover.Skipped) != 0 {
		t.Errorf("expected no skipped peers, got %+v", failover.Skipped)
	}
	migrated := failover.Migrations
	// HandleFailover emits records in a deterministic order (sorted by peer
	// key): callers iterate the full set to redirect forwarder routes, so
	// order itself carries no signal - but a stable order makes failover
	// observable and repeatable. Two peers were affinitized to t1ID here:
	// peer-a (moved to t1 in step 5) and peer-failover-1. Both must migrate
	// to t2 (the only healthy tunnel in the pool). Find each record by peer
	// key rather than asserting an index.
	if len(migrated) != 2 {
		t.Fatalf("expected 2 migrations (peer-a, peer-failover-1), got %d: %+v", len(migrated), migrated)
	}
	byPeer := make(map[string]FailoverMigration, len(migrated))
	for _, m := range migrated {
		byPeer[m.PeerPublicKey] = m
	}
	if m, ok := byPeer["peer-failover-1"]; !ok || m.NewBackendTunnelID != t2ID {
		t.Errorf("expected migration peer-failover-1 -> %d, got %+v (all: %+v)", t2ID, m, migrated)
	}
	if m, ok := byPeer["peer-a"]; !ok || m.NewBackendTunnelID != t2ID {
		t.Errorf("expected migration peer-a -> %d, got %+v (all: %+v)", t2ID, m, migrated)
	}
	if !sort.SliceIsSorted(migrated, func(i, j int) bool { return migrated[i].PeerPublicKey < migrated[j].PeerPublicKey }) {
		t.Errorf("migration records not sorted by peer key: %+v", migrated)
	}

	// Verify DB session was updated to t2ID
	updatedSess, _ := db.GetVPNSessionByID(ctx, "sess-failover-1")
	if updatedSess.BackendTunnelID != t2ID {
		t.Errorf("expected session backend tunnel ID to be updated to %d, got %d", t2ID, updatedSess.BackendTunnelID)
	}

	// HandleFailover when no healthy backends exist
	if _, err := sticky.HandleFailover(ctx, t2ID, nil); err != ErrNoActiveBackends {
		t.Errorf("expected ErrNoActiveBackends when no healthy tunnels for failover, got %v", err)
	}
}

func TestStickySessionManager_AffinityTTL_Expires(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ttl := 10 * time.Minute
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
		AffinityTTL:        ttl,
	}
	base := NewLeastConnectionsBalancer(caps)
	sm := NewStickySessionManager(db, base, caps)

	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currTime := t0
	sm.SetNowFunc(func() time.Time { return currTime })

	tunnels := []*models.BackendTunnel{
		{ID: 1, Status: "active", ActiveConnections: 10},
		{ID: 2, Status: "active", ActiveConnections: 2},
	}

	req := &RoutingRequest{
		UserID:           "user-ttl-1",
		PeerPublicKey:    "peer-ttl-1",
		AvailableTunnels: tunnels,
	}

	// First request at t0: least-connections assigns to tunnel 2 (2 < 10)
	backend, isNew, err := sm.GetOrAssignBackend(ctx, req)
	if err != nil || !isNew || backend.ID != 2 {
		t.Fatalf("expected new assignment to tunnel 2, got %+v (isNew: %v, err: %v)", backend, isNew, err)
	}

	// Change connection counts so tunnel 1 becomes optimal (0 < 10)
	tunnels[0].ActiveConnections = 0
	tunnels[1].ActiveConnections = 10

	// Advance time within TTL (5 minutes < 10 minutes)
	currTime = t0.Add(5 * time.Minute)

	// Affinity must still hold: user sticks to tunnel 2
	backend, isNew, err = sm.GetOrAssignBackend(ctx, req)
	if err != nil || isNew || backend.ID != 2 {
		t.Fatalf("expected affinity hit on tunnel 2 within TTL, got %+v (isNew: %v, err: %v)", backend, isNew, err)
	}

	// Advance time past TTL (15 minutes > 10 minutes)
	currTime = currTime.Add(15 * time.Minute)

	// In-memory queries should report affinity expired
	if tid, ok := sm.GetAffinity("user-ttl-1"); ok {
		t.Errorf("expected GetAffinity to report expired (false), got tid=%d", tid)
	}
	if tid, ok := sm.GetPeerAffinity("peer-ttl-1"); ok {
		t.Errorf("expected GetPeerAffinity to report expired (false), got tid=%d", tid)
	}

	// Next request after expiration: balancer selects optimal backend (tunnel 1 with 0 connections)
	backend, isNew, err = sm.GetOrAssignBackend(ctx, req)
	if err != nil || !isNew || backend.ID != 1 {
		t.Fatalf("expected re-assignment to tunnel 1 after TTL expiration, got %+v (isNew: %v, err: %v)", backend, isNew, err)
	}

	// New affinity on tunnel 1 must be active
	if tid, ok := sm.GetAffinity("user-ttl-1"); !ok || tid != 1 {
		t.Errorf("expected GetAffinity to be tunnel 1, got tid=%d, ok=%v", tid, ok)
	}
	if tid, ok := sm.GetPeerAffinity("peer-ttl-1"); !ok || tid != 1 {
		t.Errorf("expected GetPeerAffinity to be tunnel 1, got tid=%d, ok=%v", tid, ok)
	}
}

func TestStickySessionManager_AffinityTTL_RefreshedByActiveUse(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ttl := 10 * time.Minute
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
		AffinityTTL:        ttl,
	}
	base := NewLeastConnectionsBalancer(caps)
	sm := NewStickySessionManager(db, base, caps)

	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currTime := t0
	sm.SetNowFunc(func() time.Time { return currTime })

	tunnels := []*models.BackendTunnel{
		{ID: 1, Status: "active", ActiveConnections: 20},
		{ID: 2, Status: "active", ActiveConnections: 5},
	}

	req := &RoutingRequest{
		UserID:           "user-refresh",
		PeerPublicKey:    "peer-refresh",
		AvailableTunnels: tunnels,
	}

	// Initial assignment at t0 -> Tunnel 2
	b1, isNew, err := sm.GetOrAssignBackend(ctx, req)
	if err != nil || !isNew || b1.ID != 2 {
		t.Fatalf("initial assignment failed: backend=%+v isNew=%v err=%v", b1, isNew, err)
	}

	// Tunnel 1 drops to 0 connections
	tunnels[0].ActiveConnections = 0
	tunnels[1].ActiveConnections = 25

	// Active request at t0 + 6m (< 10m): affinity preserved and lastSeen refreshed to t0 + 6m
	currTime = t0.Add(6 * time.Minute)
	b2, isNew, err := sm.GetOrAssignBackend(ctx, req)
	if err != nil || isNew || b2.ID != 2 {
		t.Fatalf("expected sticky hit at t0+6m: backend=%+v isNew=%v err=%v", b2, isNew, err)
	}

	// At t0 + 12m: 12 minutes from t0, but only 6 minutes from lastSeen (t0+6m)
	// Because of refresh, affinity MUST STILL BE VALID
	currTime = t0.Add(12 * time.Minute)
	if tid, ok := sm.GetAffinity("user-refresh"); !ok || tid != 2 {
		t.Fatalf("expected affinity alive at t0+12m due to refresh, got tid=%d, ok=%v", tid, ok)
	}

	b3, isNew, err := sm.GetOrAssignBackend(ctx, req)
	if err != nil || isNew || b3.ID != 2 {
		t.Fatalf("expected sticky hit at t0+12m: backend=%+v isNew=%v err=%v", b3, isNew, err)
	}

	// Advance time by 11 minutes (t0 + 23m, which is 11m > 10m after t0+12m)
	currTime = t0.Add(23 * time.Minute)

	// Now idle for 11m > 10m TTL -> should expire
	if tid, ok := sm.GetAffinity("user-refresh"); ok {
		t.Fatalf("expected affinity to expire after 11m inactivity, got tid=%d", tid)
	}

	b4, isNew, err := sm.GetOrAssignBackend(ctx, req)
	if err != nil || !isNew || b4.ID != 1 {
		t.Fatalf("expected re-assignment to tunnel 1 after TTL expiry, got backend=%+v isNew=%v err=%v", b4, isNew, err)
	}
}

func TestStickySessionManager_CustomNowFunc(t *testing.T) {
	db := setupTestDB(t)

	// Verify default TTL when AffinityTTL <= 0
	capsDefault := CapacityConfig{}
	base := NewLeastConnectionsBalancer(capsDefault)
	smDefault := NewStickySessionManager(db, base, capsDefault)

	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	fakeTime := t0
	smDefault.SetNowFunc(func() time.Time { return fakeTime })

	smDefault.AssignAffinity("u-default", 101)
	smDefault.AssignPeerAffinity("p-default", 101)

	// Valid at t0
	if tid, ok := smDefault.GetAffinity("u-default"); !ok || tid != 101 {
		t.Errorf("expected valid affinity at t0, got tid=%d, ok=%v", tid, ok)
	}
	if tid, ok := smDefault.GetPeerAffinity("p-default"); !ok || tid != 101 {
		t.Errorf("expected valid peer affinity at t0, got tid=%d, ok=%v", tid, ok)
	}

	// Advance by 29 minutes (less than DefaultAffinityTTL of 30 minutes)
	fakeTime = t0.Add(29 * time.Minute)
	if tid, ok := smDefault.GetAffinity("u-default"); !ok || tid != 101 {
		t.Errorf("expected valid affinity at t0+29m, got tid=%d, ok=%v", tid, ok)
	}

	// Advance past 30 minutes (31 minutes)
	fakeTime = t0.Add(31 * time.Minute)
	if _, ok := smDefault.GetAffinity("u-default"); ok {
		t.Errorf("expected affinity to be expired at t0+31m with DefaultAffinityTTL")
	}
	if _, ok := smDefault.GetPeerAffinity("p-default"); ok {
		t.Errorf("expected peer affinity to be expired at t0+31m with DefaultAffinityTTL")
	}
}

func TestStickySessionManager_Failover_ExpiredAffinityNotRevived(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ttl := 10 * time.Minute
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
		AffinityTTL:        ttl,
	}
	base := NewLeastConnectionsBalancer(caps)
	sm := NewStickySessionManager(db, base, caps)

	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currTime := t0
	sm.SetNowFunc(func() time.Time { return currTime })

	// Tunnel 1 and Tunnel 2
	t2 := &models.BackendTunnel{ID: 2, Status: "active", ActiveConnections: 0}

	// Assign user-1 and peer-1 to tunnel 1 at t0
	sm.AssignAffinity("user-1", 1)
	sm.AssignPeerAffinity("peer-1", 1)

	// Also assign an active peer-2 at t0 + 8m
	currTime = t0.Add(8 * time.Minute)
	sm.AssignAffinity("user-2", 1)
	sm.AssignPeerAffinity("peer-2", 1)

	// Advance time to t0 + 15m (user-1/peer-1 expired: 15m > 10m TTL, but user-2/peer-2 active: 7m < 10m TTL)
	currTime = t0.Add(15 * time.Minute)

	// Degrade tunnel 1 and trigger failover to tunnel 2
	res, err := sm.HandleFailover(ctx, 1, []*models.BackendTunnel{t2})
	if err != nil {
		t.Fatalf("HandleFailover failed: %v", err)
	}

	// Peer-2 should be migrated to tunnel 2
	if len(res.Migrations) != 1 || res.Migrations[0].PeerPublicKey != "peer-2" || res.Migrations[0].NewBackendTunnelID != 2 {
		t.Errorf("expected peer-2 to be migrated to tunnel 2, got %+v", res.Migrations)
	}

	// Peer-1 must NOT have been migrated, and its expired affinity must be purged
	if tid, ok := sm.GetPeerAffinity("peer-1"); ok {
		t.Errorf("expected expired peer-1 affinity to NOT be revived/present, got tid=%d", tid)
	}
	if tid, ok := sm.GetAffinity("user-1"); ok {
		t.Errorf("expected expired user-1 affinity to NOT be revived/present, got tid=%d", tid)
	}

	// Peer-2's affinity must be active on tunnel 2
	if tid, ok := sm.GetPeerAffinity("peer-2"); !ok || tid != 2 {
		t.Errorf("expected active peer-2 to have affinity to tunnel 2, got tid=%d (ok=%v)", tid, ok)
	}
}

func TestStickySessionManager_PruneExpired(t *testing.T) {
	db := setupTestDB(t)
	ttl := 10 * time.Minute
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
		AffinityTTL:        ttl,
	}
	base := NewLeastConnectionsBalancer(caps)
	sm := NewStickySessionManager(db, base, caps)

	t0 := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	currTime := t0
	sm.SetNowFunc(func() time.Time { return currTime })

	// Assign user-1 and peer-1 at t0
	sm.AssignAffinity("user-1", 1)
	sm.AssignPeerAffinity("peer-1", 1)

	// Advance time to t0 + 5m and assign user-2 and peer-2
	currTime = t0.Add(5 * time.Minute)
	sm.AssignAffinity("user-2", 2)
	sm.AssignPeerAffinity("peer-2", 2)

	// Verify total count
	uCount, pCount := sm.AffinityCount()
	if uCount != 2 || pCount != 2 {
		t.Fatalf("expected AffinityCount=(2, 2), got (%d, %d)", uCount, pCount)
	}

	// Advance time to t0 + 12m:
	// user-1 / peer-1 age = 12m > 10m TTL (expired)
	// user-2 / peer-2 age = 7m <= 10m TTL (active)
	currTime = t0.Add(12 * time.Minute)

	pruned := sm.PruneExpired()
	if pruned != 2 {
		t.Fatalf("expected 2 pruned records (1 user + 1 peer), got %d", pruned)
	}

	uCount, pCount = sm.AffinityCount()
	if uCount != 1 || pCount != 1 {
		t.Fatalf("expected AffinityCount=(1, 1) after prune, got (%d, %d)", uCount, pCount)
	}

	// Verify expired records are gone
	if _, ok := sm.GetAffinity("user-1"); ok {
		t.Errorf("expected user-1 to be removed from memory")
	}
	if _, ok := sm.GetPeerAffinity("peer-1"); ok {
		t.Errorf("expected peer-1 to be removed from memory")
	}

	// Verify active records are preserved
	if tid, ok := sm.GetAffinity("user-2"); !ok || tid != 2 {
		t.Errorf("expected user-2 affinity to be preserved as 2, got %d (ok=%v)", tid, ok)
	}
	if tid, ok := sm.GetPeerAffinity("peer-2"); !ok || tid != 2 {
		t.Errorf("expected peer-2 affinity to be preserved as 2, got %d (ok=%v)", tid, ok)
	}

	// Advance past TTL for user-2 / peer-2
	currTime = t0.Add(20 * time.Minute)
	pruned2 := sm.PruneExpired()
	if pruned2 != 2 {
		t.Fatalf("expected 2 pruned records for second batch, got %d", pruned2)
	}

	uCount, pCount = sm.AffinityCount()
	if uCount != 0 || pCount != 0 {
		t.Fatalf("expected AffinityCount=(0, 0) after final prune, got (%d, %d)", uCount, pCount)
	}
}

func TestStickySessionManager_GetAffinity_PhysicalPruneOnLookup(t *testing.T) {
	db := setupTestDB(t)
	ttl := 10 * time.Minute
	caps := CapacityConfig{
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
		AffinityTTL:        ttl,
	}
	base := NewLeastConnectionsBalancer(caps)
	sm := NewStickySessionManager(db, base, caps)

	t0 := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	currTime := t0
	sm.SetNowFunc(func() time.Time { return currTime })

	sm.AssignAffinity("user-lookup", 1)
	sm.AssignPeerAffinity("peer-lookup", 1)

	uCount, pCount := sm.AffinityCount()
	if uCount != 1 || pCount != 1 {
		t.Fatalf("expected initial AffinityCount=(1, 1), got (%d, %d)", uCount, pCount)
	}

	// Advance time past TTL
	currTime = t0.Add(15 * time.Minute)

	// Lookup user-lookup: should return false AND physically remove from userAffinity
	if _, ok := sm.GetAffinity("user-lookup"); ok {
		t.Errorf("expected GetAffinity to return false for expired user")
	}

	uCount, pCount = sm.AffinityCount()
	if uCount != 0 || pCount != 1 {
		t.Fatalf("expected userAffinity to be physically pruned (0) and peerAffinity untouched (1), got (%d, %d)", uCount, pCount)
	}

	// Lookup peer-lookup: should return false AND physically remove from peerAffinity
	if _, ok := sm.GetPeerAffinity("peer-lookup"); ok {
		t.Errorf("expected GetPeerAffinity to return false for expired peer")
	}

	uCount, pCount = sm.AffinityCount()
	if uCount != 0 || pCount != 0 {
		t.Fatalf("expected both maps to be physically empty (0, 0), got (%d, %d)", uCount, pCount)
	}
}
