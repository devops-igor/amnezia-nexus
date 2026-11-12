package tunnel

// Deploy-add failure at the store boundary (issue #794 group B).
//
// A deploy add used to create the tunnel row first and record the quarantine marker
// second, compensating with a row delete when the marker write failed. The delete
// runs against the same store and can fail too, which left an enabled row with no
// quarantine for the next startup to admit. The row and its quarantine now commit
// in one transaction, so these tests drive the same two fault combinations and
// assert the stronger contract: the add fails and NOTHING is persisted.
// enrollment_durable_add_test.go adds the reload/selection consequences.

import (
	"context"
	"testing"
)

func (f *enrollmentLifecycleFixture) persistedRowCount(t *testing.T) int {
	t.Helper()
	rows, err := f.prober.db.GetBackendTunnelsByServerID(context.Background(), f.server)
	if err != nil {
		t.Fatalf("read persisted rows: %v", err)
	}
	return len(rows)
}

// TestDeployAddReportsUnverifiedRollbackWhenCleanupAlsoFails keeps the original
// double-failure scenario: the marker write fails AND a row delete would fail. With
// the transactional add there is no cleanup to fail; the add is refused and no row
// survives, so nothing is left in an unverified state.
func TestDeployAddReportsUnverifiedRollbackWhenCleanupAlsoFails(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("precondition remove: %v", err)
	}
	execSide(t, f.dbPath, dropSettings, refuseRowDelete)

	ctx := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	added, err := f.pool.AddTunnel(ctx, f.server, "192.0.2.231:51820", "deploy-key")
	if err == nil {
		t.Fatal("deploy add reported success although its quarantine could not commit")
	}
	if added != nil {
		t.Fatalf("failed deploy add returned a backend: %+v", added)
	}
	if n := f.persistedRowCount(t); n != 0 {
		t.Fatalf("failed deploy add persisted %d unquarantined row(s)", n)
	}
	if cur, getErr := f.pool.GetTunnel(f.server); getErr == nil && cur != nil {
		t.Fatalf("failed deploy add left backend %d in the running pool", cur.ID)
	}
}

// TestDeployAddReportsSuccessfulRollback is the single-failure control: only the
// marker write fails. The add is refused and leaves no row and no pool entry.
func TestDeployAddReportsSuccessfulRollback(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("precondition remove: %v", err)
	}
	f.breakSettingsTableOnly(t)

	ctx := context.WithValue(context.Background(), DeployEnrollmentKey, true)
	if _, err := f.pool.AddTunnel(ctx, f.server, "192.0.2.231:51820", "deploy-key"); err == nil {
		t.Fatal("deploy add reported success although the quarantine marker could not be written")
	}
	if n := f.persistedRowCount(t); n != 0 {
		t.Fatalf("failed deploy add persisted %d row(s)", n)
	}
	if cur, getErr := f.pool.GetTunnel(f.server); getErr == nil && cur != nil {
		t.Fatalf("failed deploy add left backend %d present", cur.ID)
	}
}
