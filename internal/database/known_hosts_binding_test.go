package database

import (
	"context"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDeploymentHostIdentityAtomicBinding(t *testing.T) {
	db, _ := setupTestDB(t)
	s := &models.Server{Name: "fixture", Host: "198.51.100.10", SSHUser: "root", SSHPort: 22, SSHPass: "fixture-only"}
	id, err := db.CreateServerWithFingerprint(t.Context(), s, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := db.GetKnownHostFingerprint(t.Context(), id)
	if err != nil || fp == "" {
		t.Fatalf("missing atomic pin: %v", err)
	}
	if err := db.BindKnownHostFingerprint(t.Context(), id, fp); err != nil {
		t.Fatal(err)
	}
	if err := db.BindKnownHostFingerprint(t.Context(), id, "different"); err == nil {
		t.Fatal("replaced existing pin")
	}
	if err := db.BindKnownHostFingerprint(t.Context(), id, ""); err == nil {
		t.Fatal("empty pin accepted")
	}
	if err := db.BindKnownHostFingerprint(t.Context(), 999, "different"); err == nil {
		t.Fatal("nonexistent server accepted")
	}
	other := &models.Server{Name: "fixture2", Host: "198.51.100.11"}
	otherID, err := db.CreateServer(t.Context(), other)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, pin := range []string{"pin-a", "pin-b"} {
		wg.Add(1)
		go func() { defer wg.Done(); outcomes <- db.BindKnownHostFingerprint(t.Context(), otherID, pin) }()
	}
	wg.Wait()
	close(outcomes)
	success := 0
	for err := range outcomes {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("first-writer binding winners=%d", success)
	}
	// Force pin publication failure after server INSERT; rollback must remove it.
	if _, err := db.sqlDB.ExecContext(t.Context(), "DROP TABLE known_hosts"); err != nil {
		t.Fatal(err)
	}
	rejected := &models.Server{Name: "rollback", Host: "198.51.100.12"}
	if _, err := db.CreateServerWithFingerprint(t.Context(), rejected, fp); err == nil {
		t.Fatal("failed pin publication succeeded")
	}
	count, err := db.GetServerCount(t.Context())
	if err != nil || count != 2 || rejected.ID != 0 {
		t.Fatalf("partial server escaped transaction count=%d id=%d error=%v", count, rejected.ID, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := db.CreateServerWithFingerprint(canceled, rejected, fp); err == nil {
		t.Fatal("canceled transaction succeeded")
	}
	if _, err := db.CreateServerWithFingerprint(t.Context(), rejected, ""); err == nil {
		t.Fatal("empty pin accepted")
	}
}
