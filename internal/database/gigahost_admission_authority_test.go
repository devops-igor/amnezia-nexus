package database

// Admission authority for the order a backend is being admitted for, at the store boundary.
//
// setup_admission_authority_test.go covers the sibling question - a revoked approval - at this
// same transaction. These cases cover the other durable fact that withdraws permission: the
// order itself has ended. The existing harness is reused, so the two guards are exercised
// through one fixture and the difference between them is only which row carries the ending.
//
// The negative direction is already pinned by TestPromotionUnaffectedForBackendWithNoApproval:
// a backend no panel record attributes to a gigahost order is admitted unchanged, which is what
// keeps every backend outside the onboarding path working.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestPromotionRefusesAnOrderThatEndedAttributedByTheSetupJob covers attribution through the
// saved job: the approval records the order beside the server it registered, so a job whose
// order has ended must not admit that backend even though the approval row itself is untouched.
func TestPromotionRefusesAnOrderThatEndedAttributedByTheSetupJob(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	serverID, tunnelID := promotionFixture(t, db, "ord_ended_by_job", false)

	// The provider inventory omits the order. Recorded through the store's own writer, which
	// is what the list read calls, so the fence reads the same fact the panel records.
	if err := db.SetGigahostOrderAbsence(ctx, "ord_ended_by_job", time.Now().UTC(), "1234"); err != nil {
		t.Fatalf("record the absence: %v", err)
	}
	if retired, err := db.IsGigahostOrderRetired(ctx, "ord_ended_by_job"); err != nil || !retired {
		t.Fatalf("fixture premise: retired=%v err=%v", retired, err)
	}

	swapped, err := db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if !errors.Is(err, ErrOrderEndedBeforeAdmission) {
		t.Fatalf("promotion error = %v, want ErrOrderEndedBeforeAdmission", err)
	}
	if swapped {
		t.Fatal("an ended order's backend was promoted")
	}

	tun, err := db.GetBackendTunnel(ctx, tunnelID)
	if err != nil || tun == nil {
		t.Fatalf("read tunnel: %+v err=%v", tun, err)
	}
	if tun.Status != models.TunnelStatusConnecting {
		t.Errorf("status = %q, want the untouched %q", tun.Status, models.TunnelStatusConnecting)
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if !pending[serverID] {
		t.Error("a refused promotion released the durable enrollment quarantine")
	}
}

// TestPromotionRefusesAnOrderThatEndedAttributedByTheLedger covers the other direction: an
// immediate setup never creates a setup row, so the order ledger's own nexus_server_id is the
// only record that attributes this backend to an order. It must be enough on its own.
func TestPromotionRefusesAnOrderThatEndedAttributedByTheLedger(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{
		Name: "ledger-attributed", Host: "198.51.100.152", SSHPort: 22, SSHUser: "root",
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "ord-be-ledger", Endpoint: "198.51.100.152:443",
		Enabled: true, Status: models.TunnelStatusConnecting, Protocol: models.ProtocolVLESS, StateVersion: 1,
	})
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	if err := db.SetBackendPendingEnrollment(ctx, serverID, true); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	// Only the ledger names this order, and it names this server.
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: "ord_immediate_attributed", Status: "canceled",
		NexusServerID: serverID, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}

	swapped, err := db.PromoteTunnelAndClearEnrollment(ctx, tunnelID,
		models.TunnelStatusConnecting, "", 1, models.TunnelStatusActive, models.DisableReasonNone, 3, serverID)
	if !errors.Is(err, ErrOrderEndedBeforeAdmission) {
		t.Fatalf("promotion error = %v, want ErrOrderEndedBeforeAdmission", err)
	}
	if swapped {
		t.Fatal("an ended order's backend was promoted through the ledger attribution alone")
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if !pending[serverID] {
		t.Error("a refused promotion released the durable enrollment quarantine")
	}
}
