package database

import (
	"errors"
	"testing"
	"time"
)

func TestCommitVPNSessionDestinationRefusesBeforePublication(t *testing.T) {
	f := newMoveFixture(t)
	row := f.session(t)
	row.BackendTunnelID = f.targetID
	f.markTargetAbsent(t)
	published := false
	err := f.db.CommitVPNSessionDestination(t.Context(), f.targetID, row, func() { published = true })
	if !errors.Is(err, ErrDestinationProviderAbsent) || published {
		t.Fatalf("marked destination: error=%v published=%t", err, published)
	}
	if got := f.session(t); got.BackendTunnelID != f.sourceID {
		t.Fatalf("refused move changed durable backend to %d", got.BackendTunnelID)
	}
	f.clearTargetAbsent(t)
	if err := f.db.CommitVPNSessionDestination(t.Context(), f.targetID, row, func() { published = true }); err != nil || !published {
		t.Fatalf("cleared destination: error=%v published=%t", err, published)
	}
	if got := f.session(t); got.BackendTunnelID != f.targetID {
		t.Fatalf("accepted move did not persist: %d", got.BackendTunnelID)
	}
}

func TestCommitVPNSessionDestinationSerializesPublicationWithInventory(t *testing.T) {
	f := newMoveFixture(t)
	row := f.session(t)
	row.BackendTunnelID = f.targetID
	writerDone := make(chan error, 1)
	err := f.db.CommitVPNSessionDestination(t.Context(), f.targetID, row, func() {
		// Holding exactly the inventory writer's lock proves the ordering
		// without relying on scheduling a competing writer within a delay.
		if f.db.writeMu.TryLock() {
			f.db.writeMu.Unlock()
			t.Error("publication is not serialized with inventory writes")
		}
		var persisted int64
		if err := f.db.sqlDB.QueryRowContext(t.Context(), "SELECT backend_tunnel_id FROM vpn_sessions WHERE id = ?", row.ID).Scan(&persisted); err != nil || persisted != f.targetID {
			t.Errorf("publication preceded durable assignment: backend=%d error=%v", persisted, err)
		}
		go func() {
			writerDone <- f.db.SetServerProviderAbsence(t.Context(), f.targetSrv, time.Now().UTC(), "fixture-account")
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	if got := f.session(t); got.BackendTunnelID != f.targetID {
		t.Fatal("a later mark invalidated the accepted placement")
	}
}

func TestCommitVPNSessionDestinationErrorsNeverPublish(t *testing.T) {
	for _, mode := range []string{"mismatch", "write_failure", "read_failure", "affinity_only_marked"} {
		t.Run(mode, func(t *testing.T) {
			f := newMoveFixture(t)
			row := f.session(t)
			row.BackendTunnelID = f.targetID
			switch mode {
			case "mismatch":
				row.BackendTunnelID = f.sourceID
			case "write_failure":
				row.UserID = "missing-user"
			case "read_failure":
				if _, err := f.db.sqlDB.ExecContext(t.Context(), "ALTER TABLE servers RENAME COLUMN provider_absent_at TO unavailable_observation"); err != nil {
					t.Fatal(err)
				}
			case "affinity_only_marked":
				f.markTargetAbsent(t)
				row = nil
			}
			published := false
			err := f.db.CommitVPNSessionDestination(t.Context(), f.targetID, row, func() { published = true })
			if err == nil || published {
				t.Fatalf("error=%v published=%t", err, published)
			}
		})
	}
}

func TestCommitVPNSessionDestinationWithoutARow(t *testing.T) {
	f := newMoveFixture(t)
	published := false
	if err := f.db.CommitVPNSessionDestination(t.Context(), f.targetID, nil, func() { published = true }); err != nil || !published {
		t.Fatalf("affinity-only destination: error=%v published=%t", err, published)
	}
	if got := f.session(t); got.BackendTunnelID != f.sourceID {
		t.Fatal("affinity-only move rewrote a durable session")
	}
}
