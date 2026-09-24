package vpn

import (
	"bytes"
	"log"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Tests for the Issue #54 startup reconciliation: the backend tunnels'
// active_connections gauge is a LIVE gauge recomputed from the authoritative
// vpn_sessions table (status='connected'), not a lifetime counter. Historical
// deploys killed sessions without decrementing, and because the counter is
// persisted in backend_tunnels it survived restarts and drifted (Server 6
// showed 183 with 0 connected sessions), distorting least_conn routing.

// TestReconcileConnectionCountsResetsStaleCounter pins the core #54 scenario:
// a stale persisted counter (the Server-6 production evidence: 183) with 2
// connected sessions on the tunnel must reconcile to exactly 2 in BOTH the
// pool and the DB row.
func TestReconcileConnectionCountsResetsStaleCounter(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 941, "awg941", "pub941", "priv941", "10.9.9.141:51820")

	// Simulate the drift: two connected sessions exist, but the persisted
	// counter says 183 (e.g. sessions were killed without decrement by an
	// older deploy and the value survived the restart).
	svc.pool.IncrementConnections(tun.ID) // counter := 1
	for i := 0; i < 182; i++ {
		svc.pool.IncrementConnections(tun.ID)
	}
	got, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("setup: GetTunnelByID failed: %v", err)
	}
	if got.ActiveConnections != 183 {
		t.Fatalf("setup: counter = %d, want 183", got.ActiveConnections)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.sessionMgr.CreateSession(ctx, uID,
			"peer-reconcile-"+string(rune('a'+i)),
			"10.201.1."+strconv.Itoa(10+i), tun.ID, ""); err != nil {
			t.Fatalf("setup: CreateSession %d failed: %v", i, err)
		}
	}

	// The reconcile must correct the drift without having to re-run Start.
	svc.reconcileConnectionCounts(ctx)

	poolTun, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if poolTun.ActiveConnections != 2 {
		t.Errorf("pool active_connections = %d, want 2 after reconcile", poolTun.ActiveConnections)
	}
	row, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if row.ActiveConnections != 2 {
		t.Errorf("DB active_connections = %d, want 2 after reconcile", row.ActiveConnections)
	}
}

// TestReconcileConnectionCountsZeroWhenNoSessions pins the zero case: a
// tunnel with no connected sessions must reconcile to 0, never negative —
// this is the exact Server 6 production drift (183 shown, 0 real sessions).
func TestReconcileConnectionCountsZeroWhenNoSessions(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 942, "awg942", "pub942", "priv942", "10.9.9.142:51820")

	// Inflate the counter without any real session, mirroring the drifted
	// production state.
	for i := 0; i < 183; i++ {
		svc.pool.IncrementConnections(tun.ID)
	}
	// One real session that gets disconnected BEFORE the reconcile: its row
	// flips to disconnected, so the desired count is 0, not 1.
	sess, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-reconcile-zero",
		"10.201.1.20", tun.ID, "")
	if err != nil {
		t.Fatalf("setup: CreateSession failed: %v", err)
	}
	if err := svc.sessionMgr.CloseSession(ctx, sess.ID, "disconnected"); err != nil {
		t.Fatalf("setup: DisconnectSession failed: %v", err)
	}

	svc.reconcileConnectionCounts(ctx)

	poolTun, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if poolTun.ActiveConnections != 0 {
		t.Errorf("pool active_connections = %d, want 0 after reconcile", poolTun.ActiveConnections)
	}
	row, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if row.ActiveConnections != 0 {
		t.Errorf("DB active_connections = %d, want 0 after reconcile", row.ActiveConnections)
	}
}

// TestReconcileConnectionCountsNoDriftNoChange pins the idempotence rule:
// when the gauge already matches reality, reconcile must leave pool and DB
// values untouched (the summary says "no drift").
func TestReconcileConnectionCountsNoDriftNoChange(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 943, "awg943", "pub943", "priv943", "10.9.9.143:51820")

	// Make the gauge TRUE: exactly one connected session.
	svc.pool.IncrementConnections(tun.ID)
	if _, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-reconcile-ok",
		"10.201.1.30", tun.ID, ""); err != nil {
		t.Fatalf("setup: CreateSession failed: %v", err)
	}

	before, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("setup: GetBackendTunnel failed: %v", err)
	}
	if before.ActiveConnections != 1 {
		t.Fatalf("setup: DB active_connections = %d, want 1", before.ActiveConnections)
	}

	// The gauge already matches the connected-session count, so reconcile
	// must change nothing and log the no-drift summary with the real count.
	var logBuf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prevLog) })

	svc.reconcileConnectionCounts(ctx)
	log.SetOutput(prevLog)

	if want := "connection gauge reconciliation: no drift detected across 1 tunnel(s)"; !strings.Contains(logBuf.String(), want) {
		t.Errorf("log output missing no-drift summary %q; got:\n%s", want, logBuf.String())
	}

	row, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if row.ActiveConnections != before.ActiveConnections {
		t.Errorf("DB active_connections changed on no-drift reconcile: %d -> %d",
			before.ActiveConnections, row.ActiveConnections)
	}
	poolTun, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if poolTun.ActiveConnections != 1 {
		t.Errorf("pool active_connections = %d, want 1 (unchanged)", poolTun.ActiveConnections)
	}
}

// TestReconcileConnectionCountsUnknownTunnelRefs pins the resilience rule:
// connected sessions referencing a tunnel ID that is NOT in the pool must be
// counted and logged, never crash the reconcile. The row here is created via
// CreateBackendTunnel but never registered in the pool, mirroring a DB row
// the pool has no in-memory twin for.
func TestReconcileConnectionCountsUnknownTunnelRefs(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 944, "awg944", "pub944", "priv944", "10.9.9.144:51820")

	// A backend_tunnels row the pool does NOT know (pool was populated via
	// AddTunnel before this row existed and is never synced again here).
	ghostID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      tun.ServerID,
		InterfaceName: "awg944-ghost",
		PublicKey:     "pub944-ghost",
		PrivateKey:    "priv944-ghost",
		Endpoint:      "10.9.9.144:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("setup: CreateBackendTunnel (ghost row) failed: %v", err)
	}
	if ghostID == tun.ID {
		t.Fatalf("setup: ghost row id %d collided with pool row id", ghostID)
	}

	// Two connected sessions attached to the ghost row, plus one normal
	// session on the known tunnel. Reconcile must complete, fix the known
	// tunnel to 1, and merely log the ghost references.
	for i := 0; i < 2; i++ {
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			UserID:          uID,
			BackendTunnelID: ghostID,
			PeerPublicKey:   "peer-ghost-" + strconv.Itoa(i),
			AssignedIP:      "10.201.1." + strconv.Itoa(40+i),
			Status:          "connected",
		}); err != nil {
			t.Fatalf("setup: ghost session %d failed: %v", i, err)
		}
	}
	svc.pool.IncrementConnections(tun.ID)
	if _, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-reconcile-known",
		"10.201.1.42", tun.ID, ""); err != nil {
		t.Fatalf("setup: CreateSession failed: %v", err)
	}

	// Must not panic. The two ghost sessions must produce exactly one
	// warning reporting "2 connected session(s)" — the known-tunnel session
	// must not be counted as out-of-pool.
	var logBuf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prevLog) })

	svc.reconcileConnectionCounts(ctx)
	log.SetOutput(prevLog)

	if want := "2 connected session(s) reference backend tunnels outside the pool"; !strings.Contains(logBuf.String(), want) {
		t.Errorf("log output missing out-of-pool warning %q; got:\n%s", want, logBuf.String())
	}

	poolTun, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if poolTun.ActiveConnections != 1 {
		t.Errorf("pool active_connections = %d, want 1 (ghost sessions must not leak into known tunnels)", poolTun.ActiveConnections)
	}
}

// TestReconcileConnectionCountsDBErrorDoesNotFail pins the startup-resilience
// rule from the #54 spec: if reconciliation errors (DB unavailable), the
// panel must still come up — reconcile logs and returns, it never panics or
// propagates a fatal error into the startup sequence.
func TestReconcileConnectionCountsDBErrorDoesNotFail(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)

	tun := lbTunnel(t, svc, db, 945, "awg945", "pub945", "priv945", "10.9.9.145:51820")
	svc.pool.IncrementConnections(tun.ID)

	// Kill the DB behind the service's back to force the error path.
	if err := db.Close(); err != nil {
		t.Fatalf("setup: db.Close failed: %v", err)
	}

	// Must not panic and must return normally.
	svc.reconcileConnectionCounts(t.Context())

	// In-memory counter untouched by the failed reconcile is acceptable;
	// the point is startup continuation, which reaching this line proves.
}

// TestStartReconcilesConnectionGauge wires the contract end to end: seeding
// drift into the DB, then running the real startup sequence. Under issue #297,
// startup invalidates pre-existing persisted sessions (since in-memory transport
// and forwarder routes are wiped on restart) and reconciles the drifted gauge to 0.
// When the peer reconnects post-startup, the gauge reflects the live session count (1).
func TestStartReconcilesConnectionGauge(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 946, "awg946", "pub946", "priv946", "10.9.9.146:51820")

	// Drift lives in the DB row directly: 7 persisted, 0 real sessions.
	if err := db.UpdateBackendTunnel(ctx, tun.ID, map[string]any{
		"active_connections": 7,
	}); err != nil {
		t.Fatalf("setup: poison DB counter failed: %v", err)
	}
	// Seed a persisted connected session row from before restart.
	peerKey := "peer-start-reconcile"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: tun.ServerID,
		Protocol: "awg",
		ClientID: peerKey,
		Name:     "reconcile-conn",
	}); err != nil {
		t.Fatalf("setup: CreateConnection failed: %v", err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		UserID:          uID,
		BackendTunnelID: tun.ID,
		PeerPublicKey:   peerKey,
		AssignedIP:      "10.201.1.50",
		Status:          "connected",
	}); err != nil {
		t.Fatalf("setup: CreateVPNSession failed: %v", err)
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Under issue #297, restart invalidates pre-existing sessions and reconciles the gauge to 0
	poolTun, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if poolTun.ActiveConnections != 0 {
		t.Errorf("after Start: pool active_connections = %d, want 0 (invalidated on restart)", poolTun.ActiveConnections)
	}
	row, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if row.ActiveConnections != 0 {
		t.Errorf("after Start: DB active_connections = %d, want 0", row.ActiveConnections)
	}

	// When the peer performs a fresh handshake post-restart, the gauge updates to 1
	_, backend, err := svc.HandleIncomingPeer(ctx, peerKey)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed: %v", err)
	}
	poolTunAfter, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil || poolTunAfter.ActiveConnections != 1 {
		t.Errorf("after peer handshake: pool active_connections for backend %d = %v, want 1 (err: %v)", backend.ID, poolTunAfter, err)
	}
}

// TestComputeDesiredTunnelConnections verifies the pure calculation of desired connection
// counts, drift detection, and out-of-pool session tracking.
func TestComputeDesiredTunnelConnections(t *testing.T) {
	now := time.Now().UTC()
	tunnels := []*models.BackendTunnel{
		{ID: 10, ServerID: 1, ActiveConnections: 2}, // Matches desired (2) -> no drift
		{ID: 20, ServerID: 2, ActiveConnections: 5}, // Desired is 1 -> drifted (want 1)
		{ID: 30, ServerID: 3, ActiveConnections: 0}, // Desired is 3 -> drifted (want 3)
	}

	sessions := []models.VPNSession{
		{ID: "s1", BackendTunnelID: 10, Status: "connected"},
		{ID: "s2", BackendTunnelID: 10, Status: "connected"},
		{ID: "s3", BackendTunnelID: 20, Status: "connected"},
		{ID: "s4", BackendTunnelID: 30, Status: "connected"},
		{ID: "s5", BackendTunnelID: 30, Status: "connected"},
		{ID: "s6", BackendTunnelID: 30, Status: "connected"},
		{ID: "s7", BackendTunnelID: 999, Status: "connected"}, // Unknown / unpooled tunnel
	}

	plan := computeDesiredTunnelConnections(tunnels, sessions, now)

	// Invariant 1: Desired counts match session breakdown
	if plan.desired[10] != 2 || plan.desired[20] != 1 || plan.desired[30] != 3 {
		t.Errorf("unexpected desired counts: %+v", plan.desired)
	}

	// Invariant 2: Drift detected only for tunnels whose ActiveConnections != desired
	if _, ok := plan.tunnelChanges[10]; ok {
		t.Errorf("tunnel 10 should not be in tunnelChanges since count matches (2)")
	}
	if want, ok := plan.tunnelChanges[20]; !ok || want != 1 {
		t.Errorf("tunnel 20 change = %d (present: %v), want 1", want, ok)
	}
	if want, ok := plan.tunnelChanges[30]; !ok || want != 3 {
		t.Errorf("tunnel 30 change = %d (present: %v), want 3", want, ok)
	}

	// Invariant 3: All known tunnels have staged reconcile timestamp
	for _, tun := range tunnels {
		ts, ok := plan.stagedReconcile[tun.ID]
		if !ok || ts != now {
			t.Errorf("tunnel %d stagedReconcile = %v, want %v", tun.ID, ts, now)
		}
	}

	// Invariant 4: Sessions on unpooled tunnels are identified
	if plan.unknownSessions != 1 {
		t.Errorf("unknownSessions = %d, want 1", plan.unknownSessions)
	}
}
