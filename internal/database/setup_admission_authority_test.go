package database

// Admission authority inside the promotion transaction (F14).
//
// The audit's finding was that a revoked setup approval could still have its
// backend admitted: the promotion CAS checked tunnel identity/version/enabled but
// never the approval that authorized the setup. These tests exercise the decision
// where it is made - inside the same transaction that commits the admission - so a
// refusal cannot be undone by anything the caller does afterwards.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// promotionFixture builds a server, a connecting tunnel and an approval owning it.
func promotionFixture(t *testing.T, db *DB, orderID string, revoked bool) (serverID, tunnelID int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	serverID, err := db.CreateServer(ctx, &models.Server{
		Name: "f14-" + orderID, Host: "198.51.100.150", SSHPort: 22, SSHUser: "root",
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tunnelID, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      serverID,
		InterfaceName: "f14-be-" + orderID,
		Endpoint:      "198.51.100.150:443",
		Enabled:       true,
		Status:        models.TunnelStatusConnecting,
		Protocol:      models.ProtocolVLESS,
		StateVersion:  1,
	})
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := db.SetBackendPendingEnrollment(ctx, serverID, true); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: orderID, Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	intent := newPendingIntent(orderID)
	intent.Protocol = models.ProtocolVLESS
	intent.Port = "443"
	intent.NexusServerID = serverID
	intent.State = models.SetupStateInstalling
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("create approval: %v", err)
	}
	if revoked {
		if _, changed, err := db.CancelGigahostSetupIntent(ctx, orderID, "revoked during qualification"); err != nil || !changed {
			t.Fatalf("revoke: changed=%v err=%v", changed, err)
		}
	}
	return serverID, tunnelID
}

// TestPromotionRefusesRevokedSetupApproval is the negative half at the exact
// transaction boundary: a revoked approval cannot admit, and the durable quarantine
// is not released.
func TestPromotionRefusesRevokedSetupApproval(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	serverID, tunnelID := promotionFixture(t, db, "ordf14revoked", true)

	swapped, err := db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if !errors.Is(err, ErrSetupApprovalRevoked) {
		t.Fatalf("promotion error = %v, want ErrSetupApprovalRevoked", err)
	}
	if swapped {
		t.Fatal("a revoked approval's backend was promoted")
	}

	tun, err := db.GetBackendTunnel(ctx, tunnelID)
	if err != nil || tun == nil {
		t.Fatalf("read tunnel: %+v err=%v", tun, err)
	}
	if tun.Status != models.TunnelStatusConnecting {
		t.Fatalf("status = %q, want the untouched %q", tun.Status, models.TunnelStatusConnecting)
	}
	if tun.StateVersion != 1 {
		t.Fatalf("state version = %d, want the untouched 1", tun.StateVersion)
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if !pending[serverID] {
		t.Fatal("a refused promotion released the durable quarantine marker")
	}
}

// TestPromotionAdmitsUnderLiveApproval is the positive half at the same boundary:
// the same call, with the approval still live, promotes and releases the marker.
// Without it, a guard that refused everything would also pass.
func TestPromotionAdmitsUnderLiveApproval(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	serverID, tunnelID := promotionFixture(t, db, "ordf14live", false)

	swapped, err := db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if err != nil {
		t.Fatalf("promotion: %v", err)
	}
	if !swapped {
		t.Fatal("a live approval was refused admission")
	}
	tun, err := db.GetBackendTunnel(ctx, tunnelID)
	if err != nil || tun == nil {
		t.Fatalf("read tunnel: %+v err=%v", tun, err)
	}
	if tun.Status != models.TunnelStatusActive {
		t.Fatalf("status = %q, want %q", tun.Status, models.TunnelStatusActive)
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if pending[serverID] {
		t.Fatal("an admitted backend is still quarantined")
	}
}

// TestPromotionUnaffectedForBackendWithNoApproval proves the guard is scoped: a
// backend that no saved-setup approval ever created - every backend outside this
// workflow - promotes exactly as before.
func TestPromotionUnaffectedForBackendWithNoApproval(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	serverID, err := db.CreateServer(ctx, &models.Server{
		Name: "no-approval", Host: "198.51.100.151", SSHPort: 22, SSHUser: "root", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "f14-be-plain", Endpoint: "198.51.100.151:443",
		Enabled: true, Status: models.TunnelStatusConnecting, Protocol: models.ProtocolVLESS, StateVersion: 1,
	})
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := db.SetBackendPendingEnrollment(ctx, serverID, true); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}

	swapped, err := db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if err != nil {
		t.Fatalf("promotion without an approval must not be refused: %v", err)
	}
	if !swapped {
		t.Fatal("a backend with no setup approval was refused admission")
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if pending[serverID] {
		t.Fatal("the admitted backend is still quarantined")
	}
}

// TestPromotionRefusalIsSerializedBehindRevocation proves the ordering property the
// guard relies on: because both writers take the database write mutex, a revocation
// that commits before the promotion transaction is always visible to it.
func TestPromotionRefusalIsSerializedBehindRevocation(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	serverID, tunnelID := promotionFixture(t, db, "ordf14order", false)

	// Revocation commits first, under the same mutex the promotion will take.
	if _, changed, err := db.CancelGigahostSetupIntent(ctx, "ordf14order", "revoked before promotion"); err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}
	if _, err := db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID); !errors.Is(err, ErrSetupApprovalRevoked) {
		t.Fatalf("promotion after a committed revocation = %v, want ErrSetupApprovalRevoked", err)
	}

	// And the reverse: a promotion that commits first is not retroactively undone,
	// which is why the revocation path must withdraw the backend itself.
	db2 := openSetupIntentTestDB(t)
	serverID2, tunnelID2 := promotionFixture(t, db2, "ordf14order2", false)
	if _, err := db2.PromoteTunnelAndClearEnrollment(ctx, tunnelID2,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID2); err != nil {
		t.Fatalf("promotion first: %v", err)
	}
	tun, err := db2.GetBackendTunnel(ctx, tunnelID2)
	if err != nil || tun == nil || tun.Status != models.TunnelStatusActive {
		t.Fatalf("promotion-first result: %+v err=%v", tun, err)
	}
	// A later revocation of that same approval succeeds at the intent level; the
	// withdrawal of the backend is the caller's lifecycle responsibility.
	if _, changed, err := db2.CancelGigahostSetupIntent(ctx, "ordf14order2", "revoked after admission"); err != nil || !changed {
		t.Fatalf("revoke after admission: changed=%v err=%v", changed, err)
	}
}
