package database

// The durable session move carries the destination predicate into the statement.
//
// The Go-side decision is made from a snapshot; the mark is written by an independent cycle
// under this package's write lock. Carrying the predicate into the UPDATE is what closes the
// interval between deciding and committing: either the destination was still eligible at
// commit time, or the row is untouched. These tests exercise the statement itself, so a future
// edit that drops the predicate fails here even if every caller still filters correctly.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// moveFixture seeds one user, one connected session on a source tunnel and one alternative
// destination tunnel, which is the shape both move writers work with.
type moveFixture struct {
	db        *DB
	userID    string
	sessionID string
	sourceID  int64
	targetID  int64
	targetSrv int64
}

func newMoveFixture(t *testing.T) *moveFixture {
	t.Helper()
	db, _ := setupTestDB(t)
	ctx := context.Background()

	userID, err := db.CreateUser(ctx, &models.User{Username: "move-user", Role: models.RoleUser})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sourceSrv, err := db.CreateServer(ctx, &models.Server{Name: "Source", Host: "198.51.100.11"})
	if err != nil {
		t.Fatalf("create source server: %v", err)
	}
	targetSrv, err := db.CreateServer(ctx, &models.Server{Name: "Target", Host: "198.51.100.12"})
	if err != nil {
		t.Fatalf("create target server: %v", err)
	}
	sourceID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sourceSrv, InterfaceName: "awg-mv0", PublicKey: "mv-pub0", PrivateKey: "mv-priv0",
		Endpoint: "127.0.0.1:56100", Status: "active", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create source tunnel: %v", err)
	}
	targetID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: targetSrv, InterfaceName: "awg-mv1", PublicKey: "mv-pub1", PrivateKey: "mv-priv1",
		Endpoint: "127.0.0.1:56101", Status: "active", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create target tunnel: %v", err)
	}

	sessionID := "move-session-1"
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: sessionID, UserID: userID, PeerPublicKey: "move-peer", AssignedIP: "10.90.0.2",
		BackendTunnelID: sourceID, Status: "connected", ConnectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &moveFixture{db: db, userID: userID, sessionID: sessionID, sourceID: sourceID, targetID: targetID, targetSrv: targetSrv}
}

func (f *moveFixture) markTargetAbsent(t *testing.T) {
	t.Helper()
	if err := f.db.SetServerProviderAbsence(context.Background(), f.targetSrv, time.Now().UTC(), "acct-move"); err != nil {
		t.Fatalf("mark target absent: %v", err)
	}
}

func (f *moveFixture) clearTargetAbsent(t *testing.T) {
	t.Helper()
	if err := f.db.SetServerProviderAbsence(context.Background(), f.targetSrv, time.Time{}, ""); err != nil {
		t.Fatalf("clear target mark: %v", err)
	}
}

func (f *moveFixture) session(t *testing.T) *models.VPNSession {
	t.Helper()
	row, err := f.db.GetVPNSessionByID(context.Background(), f.sessionID)
	if err != nil || row == nil {
		t.Fatalf("read session: %v", err)
	}
	return row
}

// The DB-only rebalance write must not commit a destination that went absent after the caller
// chose it, and it must say why.
func TestUpdateVPNSessionBackendTunnelRefusesAbsentDestination(t *testing.T) {
	f := newMoveFixture(t)

	// Control: the ordinary move works.
	if err := f.db.UpdateVPNSessionBackendTunnel(context.Background(), f.sessionID, f.targetID); err != nil {
		t.Fatalf("the ordinary move was refused: %v", err)
	}
	if row := f.session(t); row.BackendTunnelID != f.targetID || row.Status != "draining" {
		t.Fatalf("after the ordinary move: backend %d status %q", row.BackendTunnelID, row.Status)
	}

	// Reset the row to the connected-on-source state the real caller starts from (the move
	// above marked it draining, and a draining row is deliberately never moved again), then
	// mark the destination and require a refusal that changes nothing.
	if _, err := f.db.sqlDB.ExecContext(context.Background(),
		"UPDATE vpn_sessions SET backend_tunnel_id = ?, status = 'connected' WHERE id = ?",
		f.sourceID, f.sessionID); err != nil {
		t.Fatalf("reset session: %v", err)
	}
	f.markTargetAbsent(t)

	err := f.db.UpdateVPNSessionBackendTunnel(context.Background(), f.sessionID, f.targetID)
	if err == nil {
		t.Fatal("a session was moved onto a provider-confirmed absent destination")
	}
	if !errors.Is(err, ErrDestinationProviderAbsent) {
		t.Fatalf("refusal is not the destination-specific error: %v", err)
	}
	if row := f.session(t); row.BackendTunnelID != f.sourceID || row.Status != "connected" {
		t.Fatalf("the refusal still changed the row: backend %d status %q", row.BackendTunnelID, row.Status)
	}

	// Clearing the mark restores the move through the same statement.
	f.clearTargetAbsent(t)
	if err := f.db.UpdateVPNSessionBackendTunnel(context.Background(), f.sessionID, f.targetID); err != nil {
		t.Fatalf("after clearing the mark the move was still refused: %v", err)
	}
}

// A session that is no longer connected is still reported as such, not as a destination
// problem: the two refusals must stay distinguishable for the caller's log.
func TestUpdateVPNSessionBackendTunnelKeepsRefusalReasonsDistinct(t *testing.T) {
	f := newMoveFixture(t)
	if err := f.db.CloseVPNSession(context.Background(), f.sessionID); err != nil {
		t.Fatalf("close session: %v", err)
	}
	err := f.db.UpdateVPNSessionBackendTunnel(context.Background(), f.sessionID, f.targetID)
	if err == nil {
		t.Fatal("a closed session was moved")
	}
	if errors.Is(err, ErrDestinationProviderAbsent) {
		t.Fatalf("a closed session was reported as a destination problem: %v", err)
	}
}

// The orchestrator's degraded-tunnel path uses this writer, which pins the source and the
// eligibility of the destination in one statement; the mark predicate is part of that.
func TestMigrateVPNSessionToActiveTunnelRefusesAbsentDestination(t *testing.T) {
	f := newMoveFixture(t)
	f.markTargetAbsent(t)

	err := f.db.MigrateVPNSessionToActiveTunnel(context.Background(), f.sessionID, f.sourceID, f.targetID)
	if err == nil {
		t.Fatal("the degraded-tunnel move committed a provider-confirmed absent destination")
	}
	if row := f.session(t); row.BackendTunnelID != f.sourceID {
		t.Fatalf("the refusal still moved the session to %d", row.BackendTunnelID)
	}

	f.clearTargetAbsent(t)
	if err := f.db.MigrateVPNSessionToActiveTunnel(context.Background(), f.sessionID, f.sourceID, f.targetID); err != nil {
		t.Fatalf("after clearing the mark the move was still refused: %v", err)
	}
}
