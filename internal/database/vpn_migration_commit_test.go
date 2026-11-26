package database

import (
	"errors"
	"testing"
	"time"
)

func TestConnectedMigrationCommitOrdersInventoryAndPublication(t *testing.T) {
	f := newMoveFixture(t)
	done := make(chan error, 1)
	err := f.db.CommitVPNSessionMigration(t.Context(), f.sessionID, f.sourceID, f.targetID, func() error {
		if f.db.writeMu.TryLock() {
			f.db.writeMu.Unlock()
			t.Error("inventory lock released before publication")
		}
		if got := f.session(t); got.BackendTunnelID != f.targetID {
			t.Error("durable acceptance did not precede publication")
		}
		go func() { done <- f.db.SetServerProviderAbsence(t.Context(), f.targetSrv, time.Now().UTC(), "fixture") }()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := f.session(t); got.BackendTunnelID != f.targetID {
		t.Fatal("later mark revoked held placement")
	}
}

func TestConnectedMigrationCommitRefusesWithoutPublishing(t *testing.T) {
	f := newMoveFixture(t)
	f.markTargetAbsent(t)
	published := false
	err := f.db.CommitVPNSessionMigration(t.Context(), f.sessionID, f.sourceID, f.targetID, func() error { published = true; return nil })
	if !errors.Is(err, ErrDestinationProviderAbsent) || published {
		t.Fatalf("error=%v published=%t", err, published)
	}
	if got := f.session(t); got.BackendTunnelID != f.sourceID {
		t.Fatal("refusal changed row")
	}
}

func TestConnectedMigrationPublicationFailureRestoresMarkedSource(t *testing.T) {
	f := newMoveFixture(t)
	source, err := f.db.GetBackendTunnelByID(t.Context(), f.sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetServerProviderAbsence(t.Context(), source.ServerID, time.Now().UTC(), "fixture"); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("publication refused")
	err = f.db.CommitVPNSessionMigration(t.Context(), f.sessionID, f.sourceID, f.targetID, func() error { return failure })
	if !errors.Is(err, failure) {
		t.Fatalf("lost publication error: %v", err)
	}
	if got := f.session(t); got.BackendTunnelID != f.sourceID {
		t.Fatal("compensation refused marked previous destination")
	}
}
