package database

// Generation-bound enrollment quarantine (issue #794 group B).
//
// A deploy add or re-enrollment records the server's durable quarantine bound to
// the tunnel row it enrolled. Only that row's qualification or removal releases
// it; a server-keyed caller cannot tell generations apart, so it can neither
// downgrade nor clear a live bound mark. A bound mark whose row is gone (a row-only
// delete) belongs to no live generation: it must not quarantine the server's next
// backend and a server-keyed caller may replace or clear it.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func newBoundEnrollmentStore(t *testing.T) (*DB, int64) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "bound_enrollment.db"), "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sid, err := db.CreateServer(context.Background(), &models.Server{Name: "bound", Host: "192.0.2.90"})
	if err != nil {
		t.Fatal(err)
	}
	return db, sid
}

func enrolledRow(t *testing.T, db *DB, sid int64, ifName string) int64 {
	t.Helper()
	id, err := db.CreateBackendTunnelWithEnrollment(context.Background(), &models.BackendTunnel{
		ServerID: sid, InterfaceName: ifName, Endpoint: "192.0.2.90:51820", Status: models.TunnelStatusConnecting,
	})
	if err != nil {
		t.Fatalf("create enrolled row: %v", err)
	}
	return id
}

func ownerOf(t *testing.T, db *DB, sid int64) (int64, bool) {
	t.Helper()
	owners, err := db.GetBackendPendingEnrollmentOwners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := owners[sid]
	return owner, ok
}

func TestBoundEnrollmentSurvivesServerKeyedCallers(t *testing.T) {
	ctx := context.Background()
	db, sid := newBoundEnrollmentStore(t)
	id := enrolledRow(t, db, sid, "awg-bound-1")
	if owner, ok := ownerOf(t, db, sid); !ok || owner != id {
		t.Fatalf("enrolled row not bound: owner=%d ok=%v", owner, ok)
	}

	if err := db.SetBackendPendingEnrollment(ctx, sid, true); err != nil {
		t.Fatal(err)
	}
	if owner, _ := ownerOf(t, db, sid); owner != id {
		t.Fatalf("server-keyed mark downgraded the live bound quarantine to owner %d", owner)
	}
	if err := db.SetBackendPendingEnrollment(ctx, sid, false); err != nil {
		t.Fatal(err)
	}
	if owner, ok := ownerOf(t, db, sid); !ok || owner != id {
		t.Fatal("server-keyed release cleared a live generation's quarantine")
	}
}

func TestBoundEnrollmentReleasedOnlyByItsOwnRow(t *testing.T) {
	ctx := context.Background()
	db, sid := newBoundEnrollmentStore(t)
	retired := enrolledRow(t, db, sid, "awg-bound-retired")
	if err := db.DeleteBackendTunnel(ctx, retired); err != nil { // row-only delete
		t.Fatal(err)
	}
	replacement := enrolledRow(t, db, sid, "awg-bound-replacement")

	// A late removal of the retired row must not release the replacement.
	if err := db.DeleteBackendTunnelAndReleaseEnrollment(ctx, retired, sid); err != nil {
		t.Fatal(err)
	}
	if owner, _ := ownerOf(t, db, sid); owner != replacement {
		t.Fatalf("retired row's removal released the replacement's quarantine (owner=%d)", owner)
	}
	// Its own removal does.
	if err := db.DeleteBackendTunnelAndReleaseEnrollment(ctx, replacement, sid); err != nil {
		t.Fatal(err)
	}
	if _, ok := ownerOf(t, db, sid); ok {
		t.Fatal("the owning row's removal did not release its quarantine")
	}
}

func TestDanglingBoundEnrollmentDoesNotQuarantineNextBackend(t *testing.T) {
	ctx := context.Background()
	db, sid := newBoundEnrollmentStore(t)
	retired := enrolledRow(t, db, sid, "awg-dangling")
	if err := db.DeleteBackendTunnel(ctx, retired); err != nil { // row-only delete leaves the mark
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sid, InterfaceName: "awg-plain-next", Endpoint: "192.0.2.90:51820", Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[sid] {
		t.Fatal("a quarantine bound to a deleted row quarantined the server's next backend")
	}

	// A server-keyed caller may still quarantine the server, and clear its own mark.
	if err := db.SetBackendPendingEnrollment(ctx, sid, true); err != nil {
		t.Fatal(err)
	}
	if owner, ok := ownerOf(t, db, sid); !ok || owner != 0 {
		t.Fatalf("server-keyed mark did not replace the dangling bound mark: owner=%d ok=%v", owner, ok)
	}
	if err := db.SetBackendPendingEnrollment(ctx, sid, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := ownerOf(t, db, sid); ok {
		t.Fatal("server-keyed release did not clear its own mark")
	}
}

func TestEnrollmentResetBindsQuarantineAtomically(t *testing.T) {
	ctx := context.Background()
	db, sid := newBoundEnrollmentStore(t)
	id, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sid, InterfaceName: "awg-reset-bind", Endpoint: "192.0.2.90:51820",
		Status: models.TunnelStatusActive, StateVersion: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ResetBackendTunnelForEnrollment(ctx, id, 2, map[string]any{"endpoint": "192.0.2.91:51820"}); err != nil || ok {
		t.Fatalf("stale reset: ok=%v err=%v", ok, err)
	}
	if _, bound := ownerOf(t, db, sid); bound {
		t.Fatal("a refused reset recorded a quarantine")
	}
	if ok, err := db.ResetBackendTunnelForEnrollment(ctx, id, 3, map[string]any{"endpoint": "192.0.2.91:51820"}); err != nil || !ok {
		t.Fatalf("reset: ok=%v err=%v", ok, err)
	}
	if owner, _ := ownerOf(t, db, sid); owner != id {
		t.Fatalf("re-enrollment did not bind its quarantine to the row: owner=%d", owner)
	}
}
