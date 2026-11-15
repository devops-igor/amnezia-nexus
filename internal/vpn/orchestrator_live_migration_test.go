package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// TestOrchestrator_LiveSessionMigratorDoesNotMigrateToDisabledTarget pins the
// #286 race through the real live migration path, not the orchestrator's
// DB-only fallback.
//
// The existing orchestrator regression wires only the tunnel status updater, so
// its session row is never in the SessionManager or the forwarder. This test
// builds a real live session on the source backend, wires vpn.Service as both
// the status updater and the SessionMigrator, and runs the same stale-probe
// sequence. It then calls MigrateSession directly with the disabled target to
// prove the live guard rejects it before touching any state.
func TestOrchestrator_LiveSessionMigratorDoesNotMigrateToDisabledTarget(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, sourceID, targetID, userID, peerKey := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB: %v", err)
	}
	source, err := svc.pool.GetTunnelByID(sourceID)
	if err != nil {
		t.Fatalf("source tunnel: %v", err)
	}
	target, err := svc.pool.GetTunnelByID(targetID)
	if err != nil {
		t.Fatalf("target tunnel: %v", err)
	}

	const (
		assignedIP   = "10.100.0.15"
		connectionID = "conn-live-migration"
	)
	sess, err := svc.sessionMgr.CreateSession(ctx, userID, peerKey, assignedIP, source.ID, "live-migration")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	svc.forwarder.RegisterSession(sess.ID, connectionID, peerKey, assignedIP, source.ID)
	svc.pool.IncrementConnections(source.ID)
	svc.stickyMgr.AssignPeerAffinity(peerKey, source.ID)

	started := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFailureThreshold(1),
		orchestrator.WithProbeFunc(func(_ context.Context, endpoint, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
			if endpoint == target.Endpoint {
				close(started)
				<-release
				return 25 * time.Millisecond, nil
			}
			return 0, errors.New("source probe failed")
		}),
	)
	// The production wiring: the same service is both the status updater and the
	// live session migrator.
	orch.SetTunnelStatusUpdater(svc)
	orch.SetSessionMigrator(svc)

	done := make(chan error, 1)
	go func() { done <- orch.CheckBackendTunnelHealth(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the target probe")
	}
	if err := svc.DisableBackend(ctx, target.ServerID); err != nil {
		t.Fatalf("administratively disable the target: %v", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("health check: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the health check")
	}

	requireLiveSessionOn(t, svc, sess.ID, source.ID, target.ID, peerKey, connectionID, assignedIP)

	// The orchestrator rechecks the target before calling the migrator; this
	// direct call proves the live migrator's own guard, which is the protection
	// the #286 race needs if a caller reaches it with a stale target.
	mutated := false
	svc.SetPreCommitMigrationHookForTest(func() { mutated = true })
	if err := svc.MigrateSession(ctx, sess.ID, target.ID); err == nil {
		t.Fatal("live MigrateSession accepted an administratively disabled target")
	}
	if mutated {
		t.Fatal("MigrateSession mutated the session before rejecting the disabled target")
	}
	requireLiveSessionOn(t, svc, sess.ID, source.ID, target.ID, peerKey, connectionID, assignedIP)
}

// requireLiveSessionOn asserts every layer the live migration coordinates:
// SessionManager, the durable row, the forwarder route, sticky affinity and the
// pool connection counters.
func requireLiveSessionOn(
	t *testing.T, svc *Service, sessionID string, sourceID, targetID int64,
	peerKey, connectionID, assignedIP string,
) {
	t.Helper()
	ctx := context.Background()

	snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sessionID)
	if !ok {
		t.Fatalf("session %s is missing from the SessionManager", sessionID)
	}
	if snap.BackendTunnelID != sourceID {
		t.Fatalf("SessionManager backend = %d, want source %d", snap.BackendTunnelID, sourceID)
	}
	if snap.Status != "connected" {
		t.Fatalf("SessionManager status = %q, want connected", snap.Status)
	}

	row, err := svc.db.GetVPNSessionByID(ctx, sessionID)
	if err != nil || row == nil {
		t.Fatalf("durable session: %+v err=%v", row, err)
	}
	if row.BackendTunnelID != sourceID {
		t.Fatalf("durable backend = %d, want source %d", row.BackendTunnelID, sourceID)
	}

	if !svc.forwarder.HasSessionRoute(peerKey, sessionID, connectionID, assignedIP, sourceID) {
		t.Fatal("forwarder route does not point at the source backend")
	}

	sourceLive, err := svc.pool.GetTunnelByID(sourceID)
	if err != nil {
		t.Fatalf("source tunnel: %v", err)
	}
	targetLive, err := svc.pool.GetTunnelByID(targetID)
	if err != nil {
		t.Fatalf("target tunnel: %v", err)
	}
	if sourceLive.ActiveConnections != 1 {
		t.Fatalf("source ActiveConnections = %d, want 1", sourceLive.ActiveConnections)
	}
	if targetLive.ActiveConnections != 0 {
		t.Fatalf("target ActiveConnections = %d, want 0", targetLive.ActiveConnections)
	}

	selected, _, err := svc.stickyMgr.GetOrAssignBackend(ctx, &loadbalancer.RoutingRequest{
		PeerPublicKey:    peerKey,
		AvailableTunnels: []*models.BackendTunnel{targetLive, sourceLive},
	})
	if err != nil {
		t.Fatalf("sticky affinity lookup: %v", err)
	}
	if selected.ID != sourceID {
		t.Fatalf("sticky affinity selected %d, want source %d", selected.ID, sourceID)
	}
}
