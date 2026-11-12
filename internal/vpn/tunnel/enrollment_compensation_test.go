package tunnel

// Deploy-add compensation failure (issue #794 group B).
//
// A deploy add creates the tunnel row first and records the quarantine marker
// second. When the marker write fails the row is rolled back — but the rollback
// runs against the SAME store, so it can fail for the same reason. Claiming an
// unconditional rollback would be a silent lie: the row can survive without any
// quarantine. These tests drive that real double failure.

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestDeployAddReportsUnverifiedRollbackWhenCleanupAlsoFails drives recordDeployQuarantine
// directly with a store whose marker write fails AND whose delete fails, so the
// double-failure reporting path is exercised for real rather than contrived through
// table surgery (which cannot distinguish insert from delete on one connection).
//
// The claim under test is narrow and honest: when cleanup cannot be verified, the
// returned error must say so, and must not read like a clean rollback.
func TestDeployAddReportsUnverifiedRollbackWhenCleanupAlsoFails(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("precondition remove: %v", err)
	}
	// A row must exist for the compensation to have anything to delete.
	tun, err := f.pool.AddTunnel(context.Background(), f.server, "192.0.2.231:51820", "comp-row")
	if err != nil {
		t.Fatalf("seed row: %v", err)
	}

	// Mark the store unusable: BOTH the marker write and the compensating delete
	// fail at the real SQL boundary.
	f.breakSettingsTableOnly(t)
	if err := f.prober.db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err = f.pool.recordDeployQuarantine(context.Background(), tun.ID, f.server)
	if err == nil {
		t.Fatal("recordDeployQuarantine reported success although neither the marker nor its rollback could commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unverified") {
		t.Fatalf("error does not disclose that cleanup could not be verified: %v", err)
	}
	if !strings.Contains(msg, "unquarantined") {
		t.Fatalf("error does not disclose the unquarantined state: %v", err)
	}
}

// TestDeployAddReportsSuccessfulRollback is the control: when only the marker write
// fails and the store can still delete, the error says the row WAS rolled back and
// no unquarantined backend remains in the pool.
func TestDeployAddReportsSuccessfulRollback(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("precondition remove: %v", err)
	}
	f.breakSettingsTableOnly(t)

	ctx := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	_, err := f.pool.AddTunnel(ctx, f.server, "192.0.2.231:51820", "deploy-key")
	if err == nil {
		t.Fatal("deploy add reported success although the quarantine marker could not be written")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("error does not report the successful rollback: %v", err)
	}
	if strings.Contains(err.Error(), "unverified") {
		t.Fatalf("error claims an unverified rollback although cleanup ran: %v", err)
	}
	if cur, getErr := f.pool.GetTunnel(f.server); getErr == nil && cur != nil {
		t.Fatalf("rolled-back deploy add left backend %d present", cur.ID)
	}
	_ = models.TunnelStatusConnecting
}
