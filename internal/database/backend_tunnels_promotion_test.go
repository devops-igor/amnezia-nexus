package database

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Finding F10: the qualification verdict and the durable enrollment release must
// commit together. If they could be split, a process exit in between would leave
// a genuinely qualified backend still marked unqualified — startup then resets it
// to connecting and it is permanently unselectable.
func TestPromoteTunnelAndClearEnrollmentReleasesAtomically(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "promotion.db")
	const key = "test-secret-key-1234567890123456"

	db, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := db.CreateServer(ctx, &models.Server{Name: "promotion", Host: "192.0.2.60"})
	if err != nil {
		t.Fatal(err)
	}
	tunID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sid,
		InterfaceName: "vless-be-1",
		Endpoint:      "192.0.2.60:443",
		Enabled:       true,
		Status:        models.TunnelStatusConnecting,
		Protocol:      models.ProtocolVLESS,
		StateVersion:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetBackendPendingEnrollment(ctx, sid, true); err != nil {
		t.Fatal(err)
	}

	swapped, err := db.PromoteTunnelAndClearEnrollment(
		ctx, tunID, models.TunnelStatusConnecting, models.DisableReasonNone, 1,
		models.TunnelStatusActive, models.DisableReasonNone, 12, sid,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !swapped {
		t.Fatal("expected promotion to commit")
	}

	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[sid] {
		t.Fatal("promotion committed but durable enrollment was not released")
	}
	reopened, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != models.TunnelStatusActive {
		t.Fatalf("expected promoted status %s, got %s", models.TunnelStatusActive, reopened.Status)
	}

	// A refused transition must not release the marker: an unqualified or
	// concurrently replaced backend has to stay safely ineligible.
	if err := db.SetBackendPendingEnrollment(ctx, sid, true); err != nil {
		t.Fatal(err)
	}
	swapped, err = db.PromoteTunnelAndClearEnrollment(
		ctx, tunID, models.TunnelStatusConnecting, models.DisableReasonNone, 1,
		models.TunnelStatusActive, models.DisableReasonNone, 12, sid,
	)
	if err != nil {
		t.Fatal(err)
	}
	if swapped {
		t.Fatal("expected stale-version promotion to be refused")
	}
	pending, err = db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pending[sid] {
		t.Fatal("refused promotion cleared the enrollment quarantine")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The release must be durable across a real reopen.
	db2, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	persisted, err := db2.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted[sid] {
		t.Fatal("enrollment quarantine lost across reopen")
	}
}
