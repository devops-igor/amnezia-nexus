package endpoint

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestSessionManagerCRUD(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, err := NewIPAM("10.100.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAM failed: %v", err)
	}

	sm := NewSessionManager(db, ipam)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey",
		PrivateKey:    "tunnel-privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	u1ID, _ := db.CreateUser(ctx, &models.User{Username: "user1"})

	// Validation
	if _, err := sm.CreateSession(ctx, "", "peer1", "10.100.0.2", tID, ""); err == nil {
		t.Errorf("expected error for missing userID")
	}

	// 1. Create Session
	sess1, err := sm.CreateSession(ctx, u1ID, "peer1", "10.100.0.2", tID, "")
	if err != nil {
		t.Fatalf("CreateSession sess1 failed: %v", err)
	}
	if sess1.ID == "" || sess1.Status != "connected" || sess1.UserID != u1ID {
		t.Errorf("invalid sess1: %+v", sess1)
	}
	if sm.ActiveCount() != 1 {
		t.Errorf("expected active count 1, got %d", sm.ActiveCount())
	}

	// 2. Lookups
	byPeer, ok := sm.GetSession("peer1")
	if !ok || byPeer.ID != sess1.ID {
		t.Errorf("GetSession mismatch: %+v", byPeer)
	}
	if _, ok := sm.GetSession("ghost"); ok {
		t.Errorf("expected ghost session to not be found")
	}

	byID, ok := sm.GetSessionByID(sess1.ID)
	if !ok || byID.PeerPublicKey != "peer1" {
		t.Errorf("GetSessionByID mismatch: %+v", byID)
	}
	if _, ok := sm.GetSessionByID("ghost-id"); ok {
		t.Errorf("expected ghost id to not be found")
	}

	user1Sessions := sm.GetSessionsByUserID(u1ID)
	if len(user1Sessions) != 1 || user1Sessions[0].ID != sess1.ID {
		t.Errorf("GetSessionsByUserID mismatch: len=%d", len(user1Sessions))
	}
	if len(sm.GetSessionsByUserID("ghost-user")) != 0 {
		t.Errorf("expected 0 sessions for ghost-user")
	}

	// 3. Activity and Touch
	sm.UpdateActivity("peer1", 500, 1000)
	byPeer, _ = sm.GetSession("peer1")
	if byPeer.RxBytes != 500 || byPeer.TxBytes != 1000 {
		t.Errorf("UpdateActivity mismatch: rx=%d, tx=%d", byPeer.RxBytes, byPeer.TxBytes)
	}

	sm.TouchSession("peer1")
	sm.TouchSession("ghost")
	sm.UpdateActivity("ghost", 10, 20)

	// Close Session
	if err := sm.CloseSession(ctx, sess1.ID, "disconnected"); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}
	if sm.ActiveCount() != 0 {
		t.Errorf("expected active count 0, got %d", sm.ActiveCount())
	}
	if err := sm.CloseSession(ctx, "non-existent", ""); err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestSessionManagerTimeoutsAndDrain(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, _ := NewIPAM("10.100.0.0/24")
	sm := NewSessionManager(db, ipam)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey",
		PrivateKey:    "tunnel-privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	u1ID, _ := db.CreateUser(ctx, &models.User{Username: "user1"})
	u2ID, _ := db.CreateUser(ctx, &models.User{Username: "user2"})

	sess1, _ := sm.CreateSession(ctx, u1ID, "peer1", "10.100.0.2", tID, "")
	_, _ = sm.CreateSession(ctx, u2ID, "peer2", "10.100.0.3", tID, "")

	// Recreate with peer1 replaces old session
	sess1New, err := sm.CreateSession(ctx, u1ID, "peer1", "10.100.0.4", tID, "")
	if err != nil {
		t.Fatalf("Recreate peer1 session failed: %v", err)
	}
	if sm.ActiveCount() != 2 {
		t.Errorf("expected active count 2 after peer replace, got %d", sm.ActiveCount())
	}
	if _, ok := sm.GetSessionByID(sess1.ID); ok {
		t.Errorf("expected old session ID to be removed")
	}

	// Drain
	if err := sm.Drain(ctx, 5*time.Second); err != nil {
		t.Fatalf("Drain failed: %v", err)
	}
	activeList := sm.ListActiveSessions()
	if len(activeList) != 2 {
		t.Errorf("expected 2 active list sessions, got %d", len(activeList))
	}
	for _, s := range activeList {
		if s.Status != "draining" {
			t.Errorf("expected status draining, got %s", s.Status)
		}
	}

	_ = sm.CloseSession(ctx, sess1New.ID, "disconnected")

	// Timeouts: artificially age peer2 last seen
	peer2Sess, _ := sm.GetSession("peer2")
	peer2Sess.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	timedOut, err := sm.CheckTimeouts(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("CheckTimeouts failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].PeerPublicKey != "peer2" {
		t.Errorf("CheckTimeouts mismatch: len=%d", len(timedOut))
	}
	if sm.ActiveCount() != 0 {
		t.Errorf("expected active count 0 after timeout, got %d", sm.ActiveCount())
	}

	// zero timeout (noop)
	if to, err := sm.CheckTimeouts(ctx, 0); err != nil || len(to) != 0 {
		t.Errorf("expected noop on zero timeout")
	}
}

func TestSessionManagerSyncFromDB(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, _ := NewIPAM("10.100.0.0/24")

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey",
		PrivateKey:    "tunnel-privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "sync_user"})

	// Pre-insert into DB
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sync-sess-1",
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "sync-peer-1",
		AssignedIP:      "10.100.0.10",
		Status:          "connected",
	})

	sm := NewSessionManager(db, ipam)
	if err := sm.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	if sm.ActiveCount() != 1 {
		t.Fatalf("expected 1 active session after sync, got %d", sm.ActiveCount())
	}
	sess, ok := sm.GetSessionByID("sync-sess-1")
	if !ok || sess.PeerPublicKey != "sync-peer-1" {
		t.Errorf("synced session mismatch: %+v", sess)
	}

	if !ipam.IsAllocated(net.ParseIP("10.100.0.10")) {
		t.Errorf("expected 10.100.0.10 to be marked allocated in IPAM after sync")
	}

	// nil DB sync
	smNil := NewSessionManager(nil, ipam)
	if err := smNil.SyncFromDB(ctx); err != nil {
		t.Errorf("SyncFromDB nil db failed: %v", err)
	}
}

func TestSessionManagerPeerReconnectDBSync(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, _ := NewIPAM("10.100.0.0/24")
	sm := NewSessionManager(db, ipam)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey",
		PrivateKey:    "tunnel-privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "reconnect_user"})

	peerKey := "reconnect-peer-pubkey-1"

	// 1. Initial connection
	sess1, err := sm.CreateSession(ctx, uID, peerKey, "10.100.0.15", tID, "")
	if err != nil {
		t.Fatalf("CreateSession 1 failed: %v", err)
	}

	dbSess1, err := db.GetVPNSessionByPeerKey(ctx, peerKey)
	if err != nil || dbSess1 == nil || dbSess1.ID != sess1.ID {
		t.Fatalf("expected DB row id to match sess1.ID (%s), got: %+v", sess1.ID, dbSess1)
	}

	// 2. Peer Reconnect (creates new session with new UUID for same peer key)
	sess2, err := sm.CreateSession(ctx, uID, peerKey, "10.100.0.16", tID, "")
	if err != nil {
		t.Fatalf("CreateSession 2 failed: %v", err)
	}
	if sess2.ID == sess1.ID {
		t.Fatalf("expected new UUID for reconnected session")
	}

	// 3. Verify DB row ID was synchronized to new session ID
	dbSess2, err := db.GetVPNSessionByPeerKey(ctx, peerKey)
	if err != nil || dbSess2 == nil {
		t.Fatalf("failed to query DB session after reconnect: %v", err)
	}
	if dbSess2.ID != sess2.ID {
		t.Errorf("DB session ID not synchronized on reconnect: db=%s, sess2=%s", dbSess2.ID, sess2.ID)
	}

	// 4. Update traffic with new session ID and verify DB row is updated
	if err := db.UpdateVPNSessionTraffic(ctx, sess2.ID, 4096, 8192); err != nil {
		t.Fatalf("UpdateVPNSessionTraffic failed: %v", err)
	}

	updatedDBSess, err := db.GetVPNSessionByID(ctx, sess2.ID)
	if err != nil || updatedDBSess == nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if updatedDBSess.RxBytes != 4096 || updatedDBSess.TxBytes != 8192 {
		t.Errorf("traffic mismatch: rx=%d, tx=%d", updatedDBSess.RxBytes, updatedDBSess.TxBytes)
	}
}

// TestSessionManagerSnapshotByID verifies the copy-under-lock accessor:
// the returned struct is a detached snapshot whose mutation never leaks
// into manager state, and unknown IDs report not-found. Review rework for
// issue #189 (safe accessor for future readers; issue #205 will likely
// need it too).
func TestSessionManagerSnapshotByID(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sm := NewSessionManager(db, nil)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey",
		PrivateKey:    "tunnel-privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "snapshot_user"})

	sess, err := sm.CreateSession(ctx, uID, "snapshot-peer", "10.100.0.20", tID, "")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	got, ok := sm.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("GetSessionSnapshotByID: session %s not found", sess.ID)
	}
	if got.ID != sess.ID || got.PeerPublicKey != "snapshot-peer" || got.Status != "connected" {
		t.Errorf("snapshot fields mismatch: %+v", got)
	}

	// Mutating the snapshot must not touch the manager's stored session.
	got.RxBytes = 123456
	got.TxBytes = 654321
	got.Status = "disconnected"

	again, ok := sm.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("second GetSessionSnapshotByID: session %s not found", sess.ID)
	}
	if again.RxBytes != 0 || again.TxBytes != 0 || again.Status != "connected" {
		t.Errorf("snapshot mutation leaked into manager state: %+v", again)
	}

	if _, ok := sm.GetSessionSnapshotByID("ghost-id"); ok {
		t.Errorf("expected ghost id to not be found")
	}
}

func sessionIDs(sessions []models.VPNSession) []string {
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = s.ID
	}
	return ids
}

func TestListActiveSessionsSnapshot_DeterministicOrder(t *testing.T) {
	t.Run("EmptyAndSingleSession", testSnapshotEmptyAndSingleSession)
	t.Run("DeterministicOrderingAndTieBreaking", testSnapshotDeterministicOrderingAndTieBreaking)
	t.Run("ConcurrentReadSafety", testSnapshotConcurrentReadSafety)
}

func testSnapshotEmptyAndSingleSession(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	emptySnap := sm.ListActiveSessionsSnapshot()
	if len(emptySnap) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(emptySnap))
	}

	ctx := context.Background()
	sess, err := sm.CreateSession(ctx, "u1", "peer1", "10.100.0.10", 1, "conn1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	singleSnap := sm.ListActiveSessionsSnapshot()
	if len(singleSnap) != 1 || singleSnap[0].ID != sess.ID {
		t.Fatalf("expected 1 session matching ID %s, got %+v", sess.ID, singleSnap)
	}
}

func testSnapshotDeterministicOrderingAndTieBreaking(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	ctx := context.Background()

	baseTime := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

	testSessions := []struct {
		id          string
		peerKey     string
		ip          string
		connectedAt time.Time
	}{
		{id: "sess-mid-c", peerKey: "peer-mc", ip: "10.100.0.21", connectedAt: baseTime.Add(1 * time.Hour)},
		{id: "sess-old-y", peerKey: "peer-oy", ip: "10.100.0.22", connectedAt: baseTime},
		{id: "sess-new-z", peerKey: "peer-nz", ip: "10.100.0.23", connectedAt: baseTime.Add(2 * time.Hour)},
		{id: "sess-mid-a", peerKey: "peer-ma", ip: "10.100.0.24", connectedAt: baseTime.Add(1 * time.Hour)},
		{id: "sess-old-x", peerKey: "peer-ox", ip: "10.100.0.25", connectedAt: baseTime},
		{id: "sess-mid-b", peerKey: "peer-mb", ip: "10.100.0.26", connectedAt: baseTime.Add(1 * time.Hour)},
	}

	for _, ts := range testSessions {
		sess, err := sm.CreateSession(ctx, "user-test", ts.peerKey, ts.ip, 1, "test")
		if err != nil {
			t.Fatalf("CreateSession failed for %s: %v", ts.peerKey, err)
		}
		sm.mu.Lock()
		delete(sm.sessionsByID, sess.ID)
		sess.ID = ts.id
		sess.ConnectedAt = ts.connectedAt
		sm.sessionsByID[ts.id] = sess
		sm.mu.Unlock()
	}

	expectedIDs := []string{
		"sess-new-z",
		"sess-mid-a",
		"sess-mid-b",
		"sess-mid-c",
		"sess-old-x",
		"sess-old-y",
	}

	for iter := 0; iter < 50; iter++ {
		snapshot := sm.ListActiveSessionsSnapshot()
		verifySnapshotOrderInvariants(t, iter, snapshot, expectedIDs)
	}
}

func verifySnapshotOrderInvariants(t *testing.T, iter int, snapshot []models.VPNSession, expectedIDs []string) {
	t.Helper()
	if len(snapshot) != len(expectedIDs) {
		t.Fatalf("iteration %d: expected %d sessions, got %d", iter, len(expectedIDs), len(snapshot))
	}

	for i, wantID := range expectedIDs {
		if snapshot[i].ID != wantID {
			t.Fatalf("iteration %d: mismatch at index %d: got %s, want %s (all IDs: %v)",
				iter, i, snapshot[i].ID, wantID, sessionIDs(snapshot))
		}
	}

	for i := 0; i < len(snapshot)-1; i++ {
		curr := snapshot[i]
		next := snapshot[i+1]

		if curr.ConnectedAt.Before(next.ConnectedAt) {
			t.Fatalf("iteration %d: chronological ordering violated: index %d (%s at %v) is before index %d (%s at %v)",
				iter, i, curr.ID, curr.ConnectedAt, i+1, next.ID, next.ConnectedAt)
		}

		if curr.ConnectedAt.Equal(next.ConnectedAt) && curr.ID >= next.ID {
			t.Fatalf("iteration %d: tie-breaker ordering violated: index %d (%s) >= index %d (%s) with equal timestamp %v",
				iter, i, curr.ID, i+1, next.ID, curr.ConnectedAt)
		}
	}
}

func testSnapshotConcurrentReadSafety(t *testing.T) {
	sm := NewSessionManager(nil, nil)
	ctx := context.Background()

	baseTime := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		pKey := fmt.Sprintf("concurrent-peer-%02d", i)
		ip := fmt.Sprintf("10.100.0.%d", 100+i)
		sess, err := sm.CreateSession(ctx, "user-concurrent", pKey, ip, 1, "test")
		if err != nil {
			t.Fatalf("CreateSession %d failed: %v", i, err)
		}
		sm.mu.Lock()
		delete(sm.sessionsByID, sess.ID)
		sess.ID = fmt.Sprintf("sess-%02d", i)
		sess.ConnectedAt = baseTime.Add(time.Duration(i%3) * time.Minute)
		sm.sessionsByID[sess.ID] = sess
		sm.mu.Unlock()
	}

	var wg sync.WaitGroup
	readers := 8
	iterations := 100

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runConcurrentReader(t, sm, iterations)
		}()
	}

	writers := 4
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pKey := fmt.Sprintf("concurrent-peer-%02d", idx)
			for it := 0; it < iterations; it++ {
				sm.UpdateActivity(pKey, 10, 20)
				sm.TouchSession(pKey)
			}
		}(w)
	}

	wg.Wait()
}

func runConcurrentReader(t *testing.T, sm *SessionManager, iterations int) {
	t.Helper()
	for it := 0; it < iterations; it++ {
		snap := sm.ListActiveSessionsSnapshot()
		if len(snap) != 10 {
			t.Errorf("expected 10 sessions, got %d", len(snap))
			return
		}
		for i := 0; i < len(snap)-1; i++ {
			if snap[i].ConnectedAt.Before(snap[i+1].ConnectedAt) {
				t.Errorf("chronological invariant violated concurrently")
				return
			}
			if snap[i].ConnectedAt.Equal(snap[i+1].ConnectedAt) && snap[i].ID >= snap[i+1].ID {
				t.Errorf("tie-breaker invariant violated concurrently")
				return
			}
		}
	}
}

func TestSessionManager_GenerationPublishedAtomically(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, err := NewIPAM("10.100.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAM failed: %v", err)
	}

	sm := NewSessionManager(db, ipam)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey",
		PrivateKey:    "tunnel-privkey",
		Endpoint:      "10.0.0.1:51820",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "atom-user"})

	// 1. CreateSession without generation defaults to 0
	sess0, err := sm.CreateSession(ctx, uID, "peer-gen-0", "10.100.0.2", tID, "conn-0")
	if err != nil {
		t.Fatalf("CreateSession sess0 failed: %v", err)
	}
	if sess0.Generation != 0 {
		t.Fatalf("expected generation 0, got %d", sess0.Generation)
	}
	lookup0, ok := sm.GetSession("peer-gen-0")
	if !ok || lookup0.Generation != 0 {
		t.Fatalf("expected published generation 0, got %d (ok=%v)", lookup0.Generation, ok)
	}

	// 2. CreateSession with explicit generation publishes it atomically under sm.mu
	var expectedGen uint64 = 42
	sess1, err := sm.CreateSession(ctx, uID, "peer-gen-1", "10.100.0.3", tID, "conn-1", expectedGen)
	if err != nil {
		t.Fatalf("CreateSession sess1 failed: %v", err)
	}
	if sess1.Generation != expectedGen {
		t.Fatalf("expected generation %d, got %d", expectedGen, sess1.Generation)
	}

	// Immediate lookup from map under sm.mu must see the exact generation (no zero window)
	lookup1, ok := sm.GetSession("peer-gen-1")
	if !ok || lookup1.Generation != expectedGen {
		t.Fatalf("expected published generation %d, got %d (ok=%v)", expectedGen, lookup1.Generation, ok)
	}

	snap := sm.ListActiveSessionsSnapshot()
	found := false
	for _, s := range snap {
		if s.ID == sess1.ID {
			found = true
			if s.Generation != expectedGen {
				t.Fatalf("snapshot generation mismatch: got %d, want %d", s.Generation, expectedGen)
			}
		}
	}
	if !found {
		t.Fatal("session not found in active snapshot")
	}
}
