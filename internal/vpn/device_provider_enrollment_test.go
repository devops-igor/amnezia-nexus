package vpn

import (
	"context"
	"testing"
)

// A failed qualification commit must not release durable quarantine.
func TestPromoteQualifiedTunnelFailurePreservesEnrollment(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	svc.SetPendingEnrollment(sid, true)
	if err := svc.DisableBackend(ctx, sid); err != nil {
		t.Fatal(err)
	}
	disabled, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, disabled, 1); err == nil {
		t.Fatal("disabled tunnel was promoted")
	}
	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pending[sid] || !svc.prober.IsPendingEnrollment(sid) {
		t.Fatal("failed promotion cleared enrollment quarantine")
	}
}
