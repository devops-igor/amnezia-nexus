package orchestrator

// Issue #44 regression tests: rebalancer minimum-load gate + in-place session reassignment.
//
// Legacy bug: with 1 session / 2 tunnels the old code computed avg=0.5,
// threshold=int(0.5*1.4)=0 and "drained" the only session via a CreateVPNSession
// re-insert, producing misleading "overloaded" logs and duplicate bookkeeping rows.

import (
	"context"
	"fmt"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// rebalanceFixture holds a DB with two active backend tunnels and one portal user.
type rebalanceFixture struct {
	db     *database.DB
	t1     int64
	t2     int64
	userID string
	nextIP int
}

func setupRebalanceFixture(t *testing.T) *rebalanceFixture {
	t.Helper()
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	ctx := context.Background()
	if err := db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 300}); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "rebalance_test_user", Role: models.RoleUser})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	srv1ID, err := db.CreateServer(ctx, &models.Server{Name: "RebSrv1", Host: "10.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer(1) failed: %v", err)
	}
	srv2ID, err := db.CreateServer(ctx, &models.Server{Name: "RebSrv2", Host: "10.0.0.2", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer(2) failed: %v", err)
	}

	tID1, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: srv1ID, InterfaceName: "awg0", PublicKey: "reb-pub1", Endpoint: "127.0.0.1:55430", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel(1) failed: %v", err)
	}
	tID2, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: srv2ID, InterfaceName: "awg1", PublicKey: "reb-pub2", Endpoint: "127.0.0.1:55431", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel(2) failed: %v", err)
	}

	return &rebalanceFixture{db: db, t1: tID1, t2: tID2, userID: userID, nextIP: 0}
}

// session inserts one session with the given status on the given tunnel.
func (f *rebalanceFixture) session(t *testing.T, id string, tunnelID int64, status string) {
	t.Helper()
	f.nextIP++
	if err := f.db.CreateVPNSession(context.Background(), &models.VPNSession{
		ID:              id,
		UserID:          f.userID,
		BackendTunnelID: tunnelID,
		PeerPublicKey:   "peer-" + id,
		AssignedIP:      fmt.Sprintf("10.100.%d.%d", tunnelID%200, f.nextIP),
		Status:          status,
	}); err != nil {
		t.Fatalf("CreateVPNSession(%s) failed: %v", id, err)
	}
}

// allSessions returns every session row for the fixture user, regardless of status.
func (f *rebalanceFixture) allSessions(t *testing.T) []models.VPNSession {
	t.Helper()
	sessions, err := f.db.GetVPNSessionsByUserID(context.Background(), f.userID)
	if err != nil {
		t.Fatalf("GetVPNSessionsByUserID failed: %v", err)
	}
	return sessions
}

// countOnTunnel counts session rows pointing at the given tunnel, regardless of
// status — proves zero UPDATEs happened at the row level.
func (f *rebalanceFixture) countOnTunnel(t *testing.T, tunnelID int64) int {
	t.Helper()
	n := 0
	for _, s := range f.allSessions(t) {
		if s.BackendTunnelID == tunnelID {
			n++
		}
	}
	return n
}

// R1: a lone session on two tunnels is below the minimum-load gate — the rebalancer
// must not touch anything and must not error. (Live incident from the issue report.)
func TestRebalance_SingleSessionBelowGate_NoMoves(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()

	f.session(t, "lone-sess", f.t1, "connected")

	orch := New(f.db, nil)
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	if got := f.countOnTunnel(t, f.t1); got != 1 {
		t.Errorf("expected lone session to stay on tunnel %d, tunnel now holds %d sessions", f.t1, got)
	}
	if got := f.countOnTunnel(t, f.t2); got != 0 {
		t.Errorf("expected zero sessions on tunnel %d, got %d", f.t2, got)
	}
	sess, err := f.db.GetVPNSessionByID(ctx, "lone-sess")
	if err != nil || sess == nil {
		t.Fatalf("lone-sess not found after rebalance: %v", err)
	}
	if sess.Status != "connected" {
		t.Errorf("expected status connected, got %q", sess.Status)
	}
	if sess.BackendTunnelID != f.t1 {
		t.Errorf("expected backend_tunnel_id %d unchanged, got %d", f.t1, sess.BackendTunnelID)
	}
}

// R1: 20 sessions evenly split (10/10) is a balanced load — zero moves.
func TestRebalance_EvenSplit_NoMoves(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		f.session(t, fmt.Sprintf("even-t1-%d", i), f.t1, "connected")
	}
	for i := 1; i <= 10; i++ {
		f.session(t, fmt.Sprintf("even-t2-%d", i), f.t2, "connected")
	}

	orch := New(f.db, nil)
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	if got := f.countOnTunnel(t, f.t1); got != 10 {
		t.Errorf("expected 10 sessions on tunnel %d, got %d", f.t1, got)
	}
	if got := f.countOnTunnel(t, f.t2); got != 10 {
		t.Errorf("expected 10 sessions on tunnel %d, got %d", f.t2, got)
	}
}

// R1+R2: 20 sessions split 18/2 (avg=10, threshold=max(1,int(10*1.4))=14) drains
// exactly 18-14=4 sessions from tunnel 1 to tunnel 2.
func TestRebalance_OverflowDrainsExactlyThresholdExcess(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()

	for i := 1; i <= 18; i++ {
		f.session(t, fmt.Sprintf("ovf-t1-%02d", i), f.t1, "connected")
	}
	for i := 1; i <= 2; i++ {
		f.session(t, fmt.Sprintf("ovf-t2-%d", i), f.t2, "connected")
	}

	orch := New(f.db, nil)
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	if got := f.countOnTunnel(t, f.t1); got != 14 {
		t.Errorf("expected 14 sessions left on tunnel %d (18 - 4 excess), got %d", f.t1, got)
	}
	if got := f.countOnTunnel(t, f.t2); got != 6 {
		t.Errorf("expected 6 sessions on tunnel %d (2 + 4 moved), got %d", f.t2, got)
	}
}

// R4: moved sessions keep their original session IDs — in-place UPDATE, not
// CreateVPNSession re-inserts. Total row count must be unchanged.
func TestRebalance_MovedSessionsKeepIDs_InPlaceUpdate(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()

	for i := 1; i <= 18; i++ {
		f.session(t, fmt.Sprintf("inplace-t1-%02d", i), f.t1, "connected")
	}
	for i := 1; i <= 2; i++ {
		f.session(t, fmt.Sprintf("inplace-t2-%d", i), f.t2, "connected")
	}
	totalRowsBefore := len(f.allSessions(t))
	if totalRowsBefore != 20 {
		t.Fatalf("fixture expected 20 rows, got %d", totalRowsBefore)
	}

	orch := New(f.db, nil)
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	allAfter := f.allSessions(t)
	if len(allAfter) != totalRowsBefore {
		t.Errorf("expected total row count unchanged at %d (in-place UPDATE), got %d", totalRowsBefore, len(allAfter))
	}

	moved := 0
	for i := 1; i <= 18; i++ {
		id := fmt.Sprintf("inplace-t1-%02d", i)
		sess, err := f.db.GetVPNSessionByID(ctx, id)
		if err != nil || sess == nil {
			t.Fatalf("session %s lost by rebalance: %v", id, err)
		}
		switch sess.BackendTunnelID {
		case f.t2:
			moved++
			// R5: moved rows are marked "draining" so they are immediately
			// ineligible for another rebalance cycle (anti-ping-pong). The
			// session ID and connected_at are preserved (in-place UPDATE).
			if sess.Status != "draining" {
				t.Errorf("moved session %s: expected status draining per R5, got %q", id, sess.Status)
			}
		case f.t1:
			// stayed on the source tunnel
		default:
			t.Errorf("session %s: unexpected backend_tunnel_id %d", id, sess.BackendTunnelID)
		}
	}
	if moved != 4 {
		t.Errorf("expected exactly 4 sessions moved from tunnel %d to %d, got %d", f.t1, f.t2, moved)
	}
}

// R3: sessions with status != 'connected' are never counted nor moved.
func TestRebalance_NonConnectedSessionsIgnored(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()

	// 8 connected on tunnel 1 — the gate (MinRebalanceSessions=8) allows the
	// cycle to run; 2 draining sessions ride along and must be neither counted
	// nor moved even though the gate passed.
	drainIPs := make([]string, 0, 2)
	for i := 1; i <= 8; i++ {
		f.session(t, fmt.Sprintf("nc-conn-%d", i), f.t1, "connected")
	}
	for i := 1; i <= 2; i++ {
		f.session(t, fmt.Sprintf("nc-drain-%d", i), f.t1, "draining")
		sess, err := f.db.GetVPNSessionByID(ctx, fmt.Sprintf("nc-drain-%d", i))
		if err != nil || sess == nil {
			t.Fatalf("failed to seed nc-drain-%d: %v", i, err)
		}
		drainIPs = append(drainIPs, sess.AssignedIP)
	}

	orch := New(f.db, nil)
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	movedNonConnected := 0
	for _, s := range f.allSessions(t) {
		// R3 violation = one of the pre-seeded draining rows moved. Legitimately
		// moved connected sessions become "draining" per R5 and must NOT trip
		// this assertion — identify pre-seeded rows by their recorded IPs.
		for _, ip := range drainIPs {
			if s.AssignedIP == ip && s.BackendTunnelID != f.t1 {
				t.Errorf("pre-seeded draining session (assigned_ip %s) was moved to tunnel %d; R3 violated", s.AssignedIP, s.BackendTunnelID)
				movedNonConnected++
			}
		}
	}
	if movedNonConnected != 0 {
		t.Errorf("expected zero pre-seeded draining sessions moved off tunnel %d, got %d", f.t1, movedNonConnected)
	}
	for i := 1; i <= 2; i++ {
		sess, err := f.db.GetVPNSessionByID(ctx, fmt.Sprintf("nc-drain-%d", i))
		if err != nil || sess == nil {
			t.Fatalf("nc-drain-%d missing after rebalance: %v", i, err)
		}
		if sess.BackendTunnelID != f.t1 {
			t.Errorf("draining session nc-drain-%d moved to tunnel %d; must never be moved", i, sess.BackendTunnelID)
		}
		if sess.Status != "draining" {
			t.Errorf("draining session nc-drain-%d status changed to %q", i, sess.Status)
		}
	}
}

// R1 plumbing: MinRebalanceSessions persists through VPNConfig round-trip and
// defaults to 8 when absent from the stored JSON.
func TestVPNConfig_MinRebalanceSessions_DefaultAndRoundTrip(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()

	// Fresh fixture saves a config WITHOUT the new field populated (zero value).
	if err := f.db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 300}); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	cfg, err := f.db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if cfg.MinRebalanceSessions != 8 {
		t.Errorf("expected default MinRebalanceSessions=8 when zero/absent, got %d", cfg.MinRebalanceSessions)
	}

	cfg.MinRebalanceSessions = 12
	if err := f.db.SaveVPNConfig(ctx, cfg); err != nil {
		t.Fatalf("SaveVPNConfig(custom) failed: %v", err)
	}
	cfg2, err := f.db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig(custom) failed: %v", err)
	}
	if cfg2.MinRebalanceSessions != 12 {
		t.Errorf("expected MinRebalanceSessions round-trip as 12, got %d", cfg2.MinRebalanceSessions)
	}
}
