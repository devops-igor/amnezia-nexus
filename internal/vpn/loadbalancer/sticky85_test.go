package loadbalancer

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// Tests for issue #85: sticky failover must not do DB I/O while holding
// sm.mu, must never silently strand a peer on the disabled backend, and must
// surface persist errors instead of dropping them.

// failingBalancer fails selection for a configured peer key only; other peers
// are served by the wrapped fallback balancer.
type failingBalancer struct {
	inner      LoadBalancer
	failPeers  map[string]bool
	failErrors map[string]error
}

func (f *failingBalancer) SelectBackend(ctx context.Context, req *RoutingRequest) (*models.BackendTunnel, error) {
	if f.failPeers[req.PeerPublicKey] {
		err := f.failErrors[req.PeerPublicKey]
		if err == nil {
			err = ErrCapacityExceeded
		}
		return nil, err
	}
	return f.inner.SelectBackend(ctx, req)
}

func (f *failingBalancer) UpdateBackends(tunnels []*models.BackendTunnel) {
	f.inner.UpdateBackends(tunnels)
}

func (f *failingBalancer) GetAlgorithm() models.LoadBalancingAlgorithm {
	return f.inner.GetAlgorithm()
}

// slowDB wraps database.DB to inject a delay into GetActiveVPNSessions.
type slowDB struct {
	*database.DB
	delay time.Duration
}

func (s *slowDB) GetActiveVPNSessions(ctx context.Context) ([]models.VPNSession, error) {
	time.Sleep(s.delay)
	return s.DB.GetActiveVPNSessions(ctx)
}

func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "test_85.db"), "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fixture: DB with a server, one degraded tunnel t1 and one healthy tunnel t2.
func failoverFixture(t *testing.T) (*database.DB, int64, int64) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()
	sID, err := db.CreateServer(ctx, &models.Server{Name: "host85", Host: "10.8.5.5"})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	t1, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-t1", PublicKey: "pk1", PrivateKey: "pr1",
		Endpoint: "10.8.5.5:51820", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel t1: %v", err)
	}
	t2, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sID, InterfaceName: "awg-t2", PublicKey: "pk2", PrivateKey: "pr2",
		Endpoint: "10.8.5.5:51821", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel t2: %v", err)
	}
	return db, t1, t2
}

func mkSession(t *testing.T, db *database.DB, id, username, peer string, backend int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.CreateUser(ctx, &models.User{Username: username, Enabled: true}); err != nil {
		t.Fatalf("CreateUser %s: %v", username, err)
	}
	u, err := db.GetUserByUsername(ctx, username)
	if err != nil || u == nil {
		t.Fatalf("GetUserByUsername %s: %v, %v", username, u, err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: id, UserID: u.ID, BackendTunnelID: backend, PeerPublicKey: peer,
		AssignedIP: "10.85.0." + id[len(id)-1:] + "0", Status: "connected",
	}); err != nil {
		t.Fatalf("CreateVPNSession %s: %v", id, err)
	}
}

// TestFailoverSelectionFailureDoesNotStrandOthers pins issue #85: when
// backend selection fails for ONE peer, the other peers must still migrate,
// and the failing peer must be counted + reported — never silently left.
func TestFailoverSelectionFailureDoesNotStrandOthers(t *testing.T) {
	db, t1, t2 := failoverFixture(t)
	ctx := context.Background()

	base := NewLeastConnectionsBalancer(CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 50})
	lb := &failingBalancer{inner: base, failPeers: map[string]bool{"peer-bad": true}}
	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 50}
	sm := NewStickySessionManager(db, lb, caps)

	healthy := []*models.BackendTunnel{{ID: t2, Status: "active", ActiveConnections: 0}}

	sm.AssignPeerAffinity("peer-ok", t1)
	sm.AssignPeerAffinity("peer-bad", t1)

	res, err := sm.HandleFailover(ctx, t1, healthy)
	if err != nil {
		t.Fatalf("HandleFailover: %v", err)
	}

	// peer-ok migrated; peer-bad did not.
	foundOK := false
	for _, m := range res.Migrations {
		if m.PeerPublicKey == "peer-ok" {
			foundOK = true
			if m.NewBackendTunnelID != t2 {
				t.Errorf("peer-ok migrated to %d, want %d", m.NewBackendTunnelID, t2)
			}
		}
		if m.PeerPublicKey == "peer-bad" {
			t.Errorf("peer-bad must NOT appear in migrations: %+v", res.Migrations)
		}
	}
	if !foundOK {
		t.Errorf("peer-ok missing from migrations: %+v", res.Migrations)
	}

	// The skip is explicit: counted + reported.
	if sm.SkippedMigrationsTotal() != 1 {
		t.Errorf("SkippedMigrationsTotal = %d, want 1", sm.SkippedMigrationsTotal())
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("expected exactly 1 skipped peer, got %+v", res.Skipped)
	}
	if res.Skipped[0].PeerPublicKey != "peer-bad" || res.Skipped[0].Reason == "" {
		t.Errorf("skipped peer report malformed: %+v", res.Skipped[0])
	}
}

// TestFailoverNoSessionLeftOnDisabledBackendUnlessReported pins issue #85:
// after HandleFailover, every DB session on the degraded backend is either
// migrated or present in Skipped — nothing in between.
func TestFailoverNoSessionLeftOnDisabledBackendUnlessReported(t *testing.T) {
	db, t1, t2 := failoverFixture(t)
	ctx := context.Background()

	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 50}
	sm := NewStickySessionManager(db, NewLeastConnectionsBalancer(caps), caps)

	healthy := []*models.BackendTunnel{{ID: t2, Status: "active", ActiveConnections: 0}}

	// One peer with in-memory affinity, one DB-only peer (no affinity).
	mkSession(t, db, "sess-a", "u85a", "peer-aff", t1)
	mkSession(t, db, "sess-b", "u85b", "peer-dbonly", t1)
	sm.AssignPeerAffinity("peer-aff", t1)

	res, err := sm.HandleFailover(ctx, t1, healthy)
	if err != nil {
		t.Fatalf("HandleFailover: %v", err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("expected no skipped peers, got %+v", res.Skipped)
	}
	migrated := map[string]bool{}
	for _, m := range res.Migrations {
		migrated[m.PeerPublicKey] = true
	}
	if !migrated["peer-aff"] || !migrated["peer-dbonly"] {
		t.Errorf("expected both peers migrated, got %+v", res.Migrations)
	}

	// Every connected session row must be off the degraded backend.
	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions: %v", err)
	}
	for _, s := range sessions {
		if s.BackendTunnelID == t1 {
			t.Errorf("session %s (peer %s) still on disabled backend %d and NOT reported skipped", s.ID, s.PeerPublicKey, t1)
		}
	}
}

// persistFailingDB fails the first N CreateVPNSession calls, then delegates.
type persistFailingDB struct {
	*database.DB
	failures int
	mu       sync.Mutex
	calls    int
}

func (p *persistFailingDB) CreateVPNSession(ctx context.Context, s *models.VPNSession) error {
	p.mu.Lock()
	p.calls++
	shouldFail := p.calls <= p.failures
	p.mu.Unlock()
	if shouldFail {
		return errors.New("injected persist failure")
	}
	return p.DB.CreateVPNSession(ctx, s)
}

// TestFailoverPersistErrorSurfaced pins issue #85: a DB write failure during
// migration is retried once; if it still fails, it is REPORTED (Skipped) and
// never silently dropped. With only one transient failure the retry succeeds
// and the row is consistent with memory.
func TestFailoverPersistErrorSurfaced(t *testing.T) {
	db, t1, t2 := failoverFixture(t)
	ctx := context.Background()
	pdb := &persistFailingDB{DB: db, failures: 1}

	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 50}
	sm := NewStickySessionManager(pdb, NewLeastConnectionsBalancer(caps), caps)
	healthy := []*models.BackendTunnel{{ID: t2, Status: "active", ActiveConnections: 0}}

	mkSession(t, db, "sess-p", "u85p", "peer-persist", t1)

	res, err := sm.HandleFailover(ctx, t1, healthy)
	if err != nil {
		t.Fatalf("HandleFailover: %v", err)
	}
	// Retry succeeded: row updated, no skips.
	if len(res.Skipped) != 0 {
		t.Errorf("expected retry to succeed (no skips), got %+v", res.Skipped)
	}
	s, err := db.GetVPNSessionByID(ctx, "sess-p")
	if err != nil || s == nil {
		t.Fatalf("GetVPNSessionByID: %v, %v", s, err)
	}
	if s.BackendTunnelID != t2 {
		t.Errorf("session row backend = %d, want %d (retry must persist)", s.BackendTunnelID, t2)
	}

	// Now a hard failure (both attempts fail): must be reported.
	db2, t1b, t2b := failoverFixture(t)
	pdb2 := &persistFailingDB{DB: db2, failures: 2}
	sm2 := NewStickySessionManager(pdb2, NewLeastConnectionsBalancer(caps), caps)
	healthy2 := []*models.BackendTunnel{{ID: t2b, Status: "active", ActiveConnections: 0}}
	mkSession(t, db2, "sess-q", "uq", "peer-hardfail", t1b)

	res2, err := sm2.HandleFailover(ctx, t1b, healthy2)
	if err != nil {
		t.Fatalf("HandleFailover (hard fail): %v", err)
	}
	if len(res2.Skipped) != 1 || res2.Skipped[0].PeerPublicKey != "peer-hardfail" {
		t.Errorf("hard persist failure must be reported in Skipped, got %+v", res2.Skipped)
	}
	if sm2.SkippedMigrationsTotal() != 1 {
		t.Errorf("SkippedMigrationsTotal = %d, want 1 (persist failure counts as an un-migrated peer)", sm2.SkippedMigrationsTotal())
	}
	s2, _ := db2.GetVPNSessionByID(ctx, "sess-q")
	if s2 != nil && s2.BackendTunnelID != t1b {
		t.Errorf("un-persisted row must still point at the old backend, got %d", s2.BackendTunnelID)
	}
}

// TestGetAffinityNotBlockedBehindFailoverDBDelay pins issue #85: concurrent
// GetAffinity readers must complete while failover DB I/O is in flight.
// With the old code the reader would block for the full DB delay because
// HandleFailover held sm.mu (write) across the DB call.
func TestGetAffinityNotBlockedBehindFailoverDBDelay(t *testing.T) {
	db, t1, t2 := failoverFixture(t)
	ctx := context.Background()
	const dbDelay = 300 * time.Millisecond
	sdb := &slowDB{DB: db, delay: dbDelay}

	caps := CapacityConfig{MaxTotalPeers: 100, MaxPeersPerBackend: 50}
	sm := NewStickySessionManager(sdb, NewLeastConnectionsBalancer(caps), caps)
	healthy := []*models.BackendTunnel{{ID: t2, Status: "active", ActiveConnections: 0}}

	mkSession(t, db, "sess-r", "u85r", "peer-reader", t1)
	sm.AssignPeerAffinity("peer-reader", t1)
	sm.AssignAffinity("user-reader", t1)

	failoverStarted := make(chan struct{})
	failoverDone := make(chan struct{})
	go func() {
		close(failoverStarted)
		if _, err := sm.HandleFailover(ctx, t1, healthy); err != nil {
			t.Errorf("HandleFailover: %v", err)
		}
		close(failoverDone)
	}()
	<-failoverStarted
	time.Sleep(10 * time.Millisecond) // let the failover take sm.mu (snapshot) then enter the DB call

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		deadline := time.Now().Add(50 * time.Millisecond)
		for i := 0; i < 50; i++ {
			if _, ok := sm.GetAffinity("user-reader"); !ok {
				t.Errorf("GetAffinity(user-reader) lost affinity unexpectedly")
			}
			if time.Now().After(deadline) {
				break
			}
		}
	}()

	select {
	case <-readDone:
		// Readers finished while failover DB I/O was in flight: mutex not
		// held across DB I/O. (failoverDone intentionally not awaited yet.)
	case <-failoverDone:
		t.Fatal("failover completed before readers — reader was blocked behind DB delay")
	}
	<-failoverDone
}
