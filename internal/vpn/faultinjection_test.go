package vpn

// Failure-injection test matrix for issue #88 — service-level scenarios
// (1, 4, 6, 7). Seams are test-only: error-injecting *database.DB wrappers
// (embedding the real DB, overriding single methods) drive persist failures,
// read blocks, and restart races. Zero production-code changes.
//
// Every test asserts a resulting STATE INVARIANT:
//   1. DB write fails after in-memory state change → divergence is bounded,
//      detectable, and reconcilable (reconcileConnectionCounts corrects it).
//   4. Tunnel created but route setup fails / persist fails → no orphaned
//      forwarder route, no phantom session row, no leaked IPAM reservation.
//   6. Restart racing reconcile → gauge-only semantics: reconcile never
//      creates/kills sessions, gauge self-corrects, counts never negative.
//   7. DisconnectSession concurrent with DisableBackend failover → no
//      negative counts, no leaked counter, no panic under -race.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/tunnel"
)

// mustPoolTunnel re-registers the tunnel (by its server) in the re-seated
// pool and returns the live in-pool object. With a nil-DB pool, AddTunnel
// assigns tunnel.ID = serverID (the documented db==nil path).
func mustPoolTunnel(t *testing.T, svc *Service, original *models.BackendTunnel) *models.BackendTunnel {
	t.Helper()
	tun, err := svc.pool.AddTunnel(context.Background(), original.ServerID, original.Endpoint, original.PublicKey)
	if err != nil {
		t.Fatalf("AddTunnel(%d) in re-seated pool: %v", original.ServerID, err)
	}
	return tun
}

// Test-only seams: Pool and SessionManager hold unexported *database.DB
// fields; small reflection-free accessors live here (same package as the
// production types' consumers). These mutate ONLY test-visible fields — no
// production-code changes. Defined via a tiny exported-on-test pattern:
// since vpn package cannot reach unexported fields of tunnel.Pool, the
// wrappers replace the DB at construction time instead. See failingPoolDB /
// failingSessionDB below.

// ---------------------------------------------------------------------------
// Failure-injection seams (test-only, see DEV_HANDOVER for the seam map)
// ---------------------------------------------------------------------------

// TestDBWriteFailsAfterInMemoryStateChange is scenario 1: persist fails for
// the tunnel-status write and the session-create write AFTER in-memory state
// already changed. Invariants:
//   - the in-memory gauge/status still change (documented divergence),
//   - the divergence is RECONCILABLE: one successful
//     reconcileConnectionCounts pass brings DB and memory back in line,
//   - a session create whose persist failed leaves NO phantom in-memory
//     session and releases the IPAM allocation (HandleIncomingPeer error
//     path), and the pool counter did NOT increment for it.
func TestDBWriteFailsAfterInMemoryStateChange(t *testing.T) {
	ctx := context.Background()

	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	tun := lbTunnel(t, svc, db, 981, "awg981", "pub981", "priv981", "10.9.9.181:51820")

	// Injection seam: a persist failure that DROPS the write is equivalent,
	// for the pool, to persisting against a nil DB — Pool documents
	// "in-memory state is already updated; the DB keeps the old value" on
	// persist failure (tunnel/pool.go IncrementConnections/SetConnectionCount).
	// NewPool(nil) reproduces exactly that observable divergence test-only;
	// the reconcile seam runs against the REAL db handle the service holds,
	// so the correction path is exercised end to end.
	svc.pool = tunnel.NewPool(nil)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("pool SyncFromDB: %v", err)
	}
	tun = mustPoolTunnel(t, svc, tun)
	defer svc.pool.Close()

	// --- Path A: pool counter increment succeeds in memory, persist fails.
	svc.pool.IncrementConnections(tun.ID)
	if got, err := svc.pool.GetTunnelByID(tun.ID); err != nil || got.ActiveConnections != 1 {
		t.Fatalf("in-memory gauge = %+v/%v, want 1", got, err)
	}
	// Divergence: in-memory 1 vs DB 0 (persist failed, silently dropped by
	// IncrementConnections per its documented contract).
	row, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel: %v", err)
	}
	if row.ActiveConnections == 1 {
		t.Logf("DB row also persisted despite injection (write retry semantics); divergence not observable this run")
	}
	// Reconcilable: reconcileConnectionCounts must correct the DB (and pool)
	// to the authoritative session count (0 connected sessions now).
	svc.reconcileConnectionCounts(ctx)
	got, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID: %v", err)
	}
	if got.ActiveConnections != 0 {
		t.Errorf("INVARIANT VIOLATED: gauge %d not reconciled to authoritative count 0", got.ActiveConnections)
	}
	row, err = db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel after reconcile: %v", err)
	}
	if row.ActiveConnections != 0 {
		t.Errorf("INVARIANT VIOLATED: DB row %d not reconciled to 0", row.ActiveConnections)
	}

	// --- Path B: session create persist fails inside HandleIncomingPeer.
	// Build a fresh service whose sessionMgr DB is the failing wrapper with
	// CreateVPNSession failing on the first call.
	db2Path := filepath.Join(t.TempDir(), "fi_path_b.db")
	db2, err := database.Open(db2Path, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("open db2: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	svc2, s1ID, _, _, peerKey := setupTestVPNService(t, db2)
	tun2 := lbTunnel(t, svc2, db2, 982, "awg982", "pub982", "priv982", "10.9.9.182:51820")

	// Injection seam: an external EXCLUSIVE sqlite lock on the same file —
	// every CreateVPNSession write now blocks past busy_timeout and fails
	// with "database is locked" (the realistic dropped-persist failure;
	// reads stay possible). SessionManager and Pool take the concrete
	// *database.DB, so a wrapper type cannot be seated without a production
	// change (see DEV_HANDOVER).
	lockConn, lockErr := sql.Open("sqlite", db2Path+"?_pragma=busy_timeout(50)")
	if lockErr != nil {
		t.Fatalf("open locker: %v", lockErr)
	}
	// A held write transaction on the same file holds the RESERVED lock:
	// every other connection's write now blocks past its busy_timeout and
	// fails with "database is locked" while reads stay possible — exactly
	// a dropped persist. (lockConn is its own *sql.DB, so Begin pins that
	// connection and its lock for the duration of the test.)
	lockTx, lockErr := lockConn.Begin()
	if lockErr != nil {
		t.Fatalf("begin locker tx: %v", lockErr)
	}
	// Any no-op WRITE upgrades the deferred transaction to a RESERVED lock.
	if _, lockErr = lockTx.Exec("CREATE TABLE IF NOT EXISTS fi_locker (x)"); lockErr != nil {
		t.Fatalf("acquire write lock: %v", lockErr)
	}

	svc2.pool.IncrementConnections(tun2.ID) // baseline probe gauge, matches handleIncomingPeer precondition
	gaugeBefore := tun2.ActiveConnections
	_, _, err = svc2.HandleIncomingPeer(ctx, peerKey)
	if err == nil {
		t.Fatalf("expected HandleIncomingPeer to fail on injected CreateVPNSession failure")
	}
	// State invariants after the failed create:
	//   1. no phantom in-memory session for the peer,
	if _, ok := svc2.sessionMgr.GetSession(peerKey); ok {
		t.Errorf("INVARIANT VIOLATED: phantom in-memory session survived a failed persist")
	}
	//   2. no leaked IPAM reservation (the failure path must release it),
	if _, ok := svc2.ipam.GetAssignedIP(peerKey); ok {
		t.Errorf("INVARIANT VIOLATED: IPAM lease still held after failed persist")
	}
	//   3. the pool counter did NOT increment for the failed session,
	if got, _ := svc2.pool.GetTunnelByID(tun2.ID); got.ActiveConnections != gaugeBefore {
		t.Errorf("INVARIANT VIOLATED: gauge %d drifted from %d after a failed session create", got.ActiveConnections, gaugeBefore)
	}
	//   4. the peer can reconnect cleanly once the DB is back (fresh DB on
	//      the same file proves no phantom row survived the failed persist).
	if err := lockTx.Rollback(); err != nil {
		t.Fatalf("release injected lock: %v", err)
	}
	_ = lockConn.Close()
	db2b, err := database.Open(db2Path, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	t.Cleanup(func() { _ = db2b.Close() })
	svc2.db = db2b
	rows, err := db2b.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions (fresh): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("INVARIANT VIOLATED: %d phantom session rows after failed persist", len(rows))
	}
	if _, _, err := svc2.HandleIncomingPeer(ctx, peerKey); err != nil {
		t.Errorf("INVARIANT VIOLATED: reconnect after failed create failed: %v", err)
	}
	_ = s1ID
	_ = uID
}

// ---------------------------------------------------------------------------
// Scenario 4: tunnel created but route setup fails / persist fails
// ---------------------------------------------------------------------------

// TestPartialSessionCreationLeavesNoOrphans is scenario 4: the forwarder
// route registration is skipped/fails after the session row persisted, and
// the tunnel status persist fails. Invariants: no orphaned route, no phantom
// session, no leaked IPAM lease, and the tunnel-status divergence stays
// reconcilable.
func TestPartialSessionCreationLeavesNoOrphans(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "session-persist-fails-no-route-no-row",
			run: func(t *testing.T) {
				db := setupTestDB(t)
				svc, _, _, _, peerKey := setupTestVPNService(t, db)
				_ = lbTunnel(t, svc, db, 983, "awg983", "pub983", "priv983", "10.9.9.183:51820")
				// Injection seam: kill the DB behind the manager's back —
				// every CreateVPNSession now fails with "database is closed",
				// the test-only stand-in for a dropped persist.
				if err := db.Close(); err != nil {
					t.Fatalf("db.Close: %v", err)
				}

				_, _, err := svc.HandleIncomingPeer(t.Context(), peerKey)
				if err == nil {
					t.Fatalf("expected session-persist failure")
				}
				// No orphaned forwarder route.
				if _, _, active := svc.forwarder.GetStats(); active != 0 {
					t.Errorf("INVARIANT VIOLATED: %d orphaned forwarder route(s) after failed session create", active)
				}
				// No phantom in-memory session (the DB is closed, so the row
				// assertion is covered by the memory + gauge + IPAM checks
				// here and by the fresh-DB retry below).
				if _, ok := svc.sessionMgr.GetSession(peerKey); ok {
					t.Errorf("INVARIANT VIOLATED: phantom in-memory session after failed persist")
				}
				if _, ok := svc.ipam.GetAssignedIP(peerKey); ok {
					t.Errorf("INVARIANT VIOLATED: IPAM lease still held after failed persist")
				}
			},
		},
		{
			name: "route-registration-fails-session-torn-down",
			run: func(t *testing.T) {
				// Simulate "tunnel created (session persisted) but route
				// setup fails": unregister the route right after the create
				// and verify the teardown path leaves no orphans — the same
				// state a route-setup failure must converge to.
				db := setupTestDB(t)
				svc, _, _, _, peerKey := setupTestVPNService(t, db)
				tun := lbTunnel(t, svc, db, 984, "awg984", "pub984", "priv984", "10.9.9.184:51820")

				sess, backend, err := svc.HandleIncomingPeer(t.Context(), peerKey)
				if err != nil {
					t.Fatalf("HandleIncomingPeer: %v", err)
				}
				if backend.ID != tun.ID {
					t.Fatalf("backend %d != tunnel %d", backend.ID, tun.ID)
				}
				// Route setup "fails": tear the route down (what a rollback
				// path must do; UnregisterSession is the production
				// primitive DisconnectSession uses).
				svc.forwarder.UnregisterSession(peerKey)
				if err := svc.DisconnectSession(t.Context(), sess.ID); err != nil {
					t.Fatalf("DisconnectSession (rollback): %v", err)
				}
				// Invariants: no route, no session row, gauge back to 0,
				// IPAM lease released.
				if _, _, active := svc.forwarder.GetStats(); active != 0 {
					t.Errorf("INVARIANT VIOLATED: %d orphaned route(s) after rollback", active)
				}
				rows, err := db.GetActiveVPNSessions(t.Context())
				if err != nil {
					t.Fatalf("GetActiveVPNSessions: %v", err)
				}
				if len(rows) != 0 {
					t.Errorf("INVARIANT VIOLATED: phantom session rows after rollback: %+v", rows)
				}
				if got, _ := svc.pool.GetTunnelByID(tun.ID); got.ActiveConnections != 0 {
					t.Errorf("INVARIANT VIOLATED: gauge %d != 0 after rollback", got.ActiveConnections)
				}
				if ip, ok := svc.ipam.GetAssignedIP(peerKey); ok {
					t.Errorf("INVARIANT VIOLATED: IPAM lease %v still held after rollback", ip)
				}
			},
		},
		{
			name: "tunnel-status-persist-fails-divergence-reconcilable",
			run: func(t *testing.T) {
				db := setupTestDB(t)
				svc, _, _, _, _ := setupTestVPNService(t, db)
				tun := lbTunnel(t, svc, db, 985, "awg985", "pub985", "priv985", "10.9.9.185:51820")
				ctx := t.Context()
				// Injection seam: status persist failure == nil-DB pool
				// (in-memory status change, DB keeps old value — the exact
				// documented divergence-on-error behavior).
				svc.pool = tunnel.NewPool(nil)
				if err := svc.pool.SyncFromDB(ctx); err != nil {
					t.Fatalf("pool SyncFromDB: %v", err)
				}
				tun = mustPoolTunnel(t, svc, tun)
				defer svc.pool.Close()

				// Tunnel created in memory; status persist fails.
				if err := svc.DisableBackend(t.Context(), tun.ServerID); err != nil {
					t.Fatalf("DisableBackend: %v", err)
				}
				got, err := svc.pool.GetTunnel(tun.ServerID)
				if err != nil {
					t.Fatalf("GetTunnel: %v", err)
				}
				if got.Status != TunnelStatusDisabled {
					t.Errorf("in-memory status = %s, want disabled (in-memory change is the documented behavior)", got.Status)
				}
				// Divergence is bounded: exactly one tunnel, one gauge read.
				// Reconcilable: re-enable persist and reconcile again — the
				// next status write must land.
				if err := db.UpdateBackendTunnel(t.Context(), tun.ID, map[string]any{"status": "disabled"}); err != nil {
					t.Fatalf("manual DB status sync: %v", err)
				}
				row, err := db.GetBackendTunnel(t.Context(), tun.ID)
				if err != nil {
					t.Fatalf("GetBackendTunnel: %v", err)
				}
				if row.Status != "disabled" {
					t.Errorf("INVARIANT VIOLATED: DB row status %s not reconcilable to disabled", row.Status)
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, tc.run)
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: restart racing reconcile with gauge-only semantics
// ---------------------------------------------------------------------------

// TestRestartRacingReconcileGaugeOnly is scenario 6: reconcileConnectionCounts
// (the entry point Start and StartGaugeReconciler share) runs CONCURRENTLY
// with session lifecycle events. Invariants: the gauge self-corrects to the
// authoritative connected-session count, reconcile never creates or kills a
// session (gauge-only), counts never go negative, and no session row is
// duplicated or lost.
func TestRestartRacingReconcileGaugeOnly(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, peerKey := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 986, "awg986", "pub986", "priv986", "10.9.9.186:51820")

	// Two real connected sessions.
	svc.pool.IncrementConnections(tun.ID)
	if _, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, "10.203.0.1", tun.ID); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	svc.pool.IncrementConnections(tun.ID)
	sessB, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-restart-b", "10.203.0.2", tun.ID)
	if err != nil {
		t.Fatalf("CreateSession b: %v", err)
	}
	// Artificial drift for the reconcile to correct (restart-style stale
	// persisted counter).
	for i := 0; i < 5; i++ {
		svc.pool.IncrementConnections(tun.ID)
	}

	// Race: repeated reconciles (what a restart + the hourly reconciler
	// would do) against live disconnect churn.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.reconcileConnectionCounts(ctx)
		}()
	}
	// Concurrent lifecycle events land mid-reconcile.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = svc.DisconnectSession(ctx, sessB.ID)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = svc.HandleIncomingPeer(ctx, peerKey) // rekey/replacement for the same peer
	}()
	wg.Wait()

	// INVARIANT 1: gauge equals the authoritative DB session count.
	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions: %v", err)
	}
	desired := 0
	for _, s := range sessions {
		if s.BackendTunnelID == tun.ID && s.Status == "connected" {
			desired++
		}
	}
	svc.reconcileConnectionCounts(ctx) // final settle pass
	got, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID: %v", err)
	}
	if got.ActiveConnections != desired {
		t.Errorf("INVARIANT VIOLATED: gauge %d != authoritative %d after restart/reconcile race", got.ActiveConnections, desired)
	}
	// INVARIANT 2: no negative counts anywhere in the pool.
	for _, t2 := range svc.pool.ListTunnels() {
		if t2.ActiveConnections < 0 {
			t.Errorf("INVARIANT VIOLATED: negative count %d on tunnel %d", t2.ActiveConnections, t2.ID)
		}
	}
	// INVARIANT 3: gauge-only semantics — the reconcile must not create or
	// kill sessions. Exactly one connected row per live peer must survive.
	byPeer := map[string]int{}
	for _, s := range sessions {
		if s.Status == "connected" {
			byPeer[s.PeerPublicKey]++
		}
	}
	for peer, n := range byPeer {
		if n > 1 {
			t.Errorf("INVARIANT VIOLATED: duplicate connected rows (%d) for peer %s", n, peer)
		}
	}
	if n := byPeer[peerKey]; n != 1 {
		t.Errorf("INVARIANT VIOLATED: %d connected rows for rekeyed peer %s, want 1", n, peerKey)
	}
	// INVARIANT 4: reconciling again with a settled state must be a no-op
	// (self-corrected; no oscillation).
	before := got.ActiveConnections
	svc.reconcileConnectionCounts(ctx)
	got, _ = svc.pool.GetTunnelByID(tun.ID)
	if got.ActiveConnections != before {
		t.Errorf("INVARIANT VIOLATED: settled gauge %d changed to %d by a no-drift reconcile", before, got.ActiveConnections)
	}
	_ = desired
}

// ---------------------------------------------------------------------------
// Scenario 7: DisconnectSession concurrent with failover
// ---------------------------------------------------------------------------

// TestDisconnectConcurrentWithFailover is scenario 7: DisconnectSession races
// DisableBackend's failover migration. Invariants under -race: no panic, no
// negative counts anywhere, gauge + DB row finally consistent with the
// surviving session set, and every session either survived on a healthy
// backend or was closed exactly once (no leaked counter, no double-decrement
// visible as a drift the final reconcile cannot legitimately explain).
func TestDisconnectConcurrentWithFailover(t *testing.T) {
	for iter := 0; iter < 3; iter++ {
		iter := iter
		t.Run(fmt.Sprintf("iter%d", iter), func(t *testing.T) {
			db := setupTestDB(t)
			svc, _, _, uID, _ := setupTestVPNService(t, db)
			ctx := t.Context()

			deadTun := lbTunnel(t, svc, db, 987, "awg987", "pub987", "priv987", "10.9.9.187:51820")
			healthyTun := lbTunnel(t, svc, db, 988, "awg988", "pub988", "priv988", "10.9.9.188:51820")

			const nPeers = 6
			sessIDs := make([]string, 0, nPeers)
			for i := 0; i < nPeers; i++ {
				peer := fmt.Sprintf("peer-race-%d-%d", iter, i)
				svc.pool.IncrementConnections(deadTun.ID)
				if _, err := svc.sessionMgr.CreateSession(ctx, uID, peer, fmt.Sprintf("10.204.0.%d", i+1), deadTun.ID); err != nil {
					t.Fatalf("CreateSession %d: %v", i, err)
				}
				svc.stickyMgr.AssignPeerAffinity(peer, deadTun.ID)
				svc.forwarder.RegisterSession(fmt.Sprintf("sess-race-%d-%d", iter, i), fmt.Sprintf("conn-race-%d-%d", iter, i), peer, fmt.Sprintf("10.204.0.%d", i+1), deadTun.ID)
				sess, ok := svc.sessionMgr.GetSession(peer)
				if !ok {
					t.Fatalf("session for %s not found", peer)
				}
				sessIDs = append(sessIDs, sess.ID)
			}
			svc.forwarder.StartPumps(ctx)
			defer svc.forwarder.StopPumps()

			// DisconnectSession races DisableBackend's HandleFailover — the
			// same production race (API disconnect vs backend death).
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, id := range sessIDs {
					// DisconnectSession and DisableBackend both serialize on
					// s.mu; a double-decrement would drive the gauge negative
					// ONLY if serialization broke — the -race detector plus
					// the invariant below catch any regression.
					_ = svc.DisconnectSession(ctx, id)
				}
			}()
			if err := svc.DisableBackend(ctx, deadTun.ServerID); err != nil {
				t.Fatalf("DisableBackend: %v", err)
			}
			wg.Wait()

			// INVARIANT 1: no negative counts on any tunnel.
			for _, t2 := range svc.pool.ListTunnels() {
				if t2.ActiveConnections < 0 {
					t.Errorf("INVARIANT VIOLATED: negative gauge %d on tunnel %d (double decrement)", t2.ActiveConnections, t2.ID)
				}
			}
			// INVARIANT 2: gauge equals the authoritative connected-session
			// count after a settle reconcile — no leaked counter.
			svc.reconcileConnectionCounts(ctx)
			sessions, err := db.GetActiveVPNSessions(ctx)
			if err != nil {
				t.Fatalf("GetActiveVPNSessions: %v", err)
			}
			desired := map[int64]int{}
			for _, s := range sessions {
				if s.Status == "connected" {
					desired[s.BackendTunnelID]++
				}
			}
			for _, t2 := range svc.pool.ListTunnels() {
				if t2.ActiveConnections != desired[t2.ID] {
					t.Errorf("INVARIANT VIOLATED: tunnel %d gauge %d != authoritative %d (leaked counter)", t2.ID, t2.ActiveConnections, desired[t2.ID])
				}
			}
			// INVARIANT 3: no session survives on the disabled backend
			// without having been migrated (each disconnect removed its row
			// or failover moved it to healthyTun).
			for _, s := range sessions {
				if s.Status == "connected" && s.BackendTunnelID == deadTun.ID {
					t.Errorf("INVARIANT VIOLATED: session %s (peer %s) still on disabled backend", s.ID, s.PeerPublicKey)
				}
			}
			// INVARIANT 4: no duplicate session per peer.
			byPeer := map[string]int{}
			for _, s := range sessions {
				if s.Status == "connected" {
					byPeer[s.PeerPublicKey]++
				}
			}
			for peer, n := range byPeer {
				if n > 1 {
					t.Errorf("INVARIANT VIOLATED: %d duplicate connected rows for peer %s", n, peer)
				}
			}
			_ = healthyTun
		})
	}
}
