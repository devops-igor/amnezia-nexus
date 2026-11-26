package ssh

import (
	"context"
	"errors"
	"testing"
)

func TestClientOperationContext_PreservesOnlyAdmittedWork(t *testing.T) {
	store := &presenceStore{memoryHostKeyStore: newMemoryHostKeyStore()}
	id := int64(900)
	client := NewClient(Config{ServerID: &id, Store: store})
	ctx, err := client.operationContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	store.set(true, nil)
	if _, err := client.operationContext(ctx); err != nil {
		t.Errorf("nested in-flight step refused: %v", err)
	}
	if _, err := client.operationContext(context.Background()); !errors.Is(err, ErrProviderAbsent) {
		t.Errorf("new operation = %v", err)
	}
	other := NewClient(Config{ServerID: &id, Store: store})
	if _, err := other.operationContext(ctx); !errors.Is(err, ErrProviderAbsent) {
		t.Errorf("another client's operation adopted ownership: %v", err)
	}
}

func TestClientOperations_RefuseAbsentWithoutTraffic(t *testing.T) {
	store := &presenceStore{memoryHostKeyStore: newMemoryHostKeyStore()}
	store.set(true, nil)
	id := int64(901)
	client := NewClient(Config{ServerID: &id, Store: store})
	ctx := context.Background()
	checks := map[string]func() error{
		"command":       func() error { _, _, _, err := client.RunCommand(ctx, "echo forbidden"); return err },
		"sudo command":  func() error { _, _, _, err := client.RunSudoCommand(ctx, "echo forbidden"); return err },
		"script":        func() error { _, _, _, err := client.RunScript(ctx, "echo forbidden"); return err },
		"sudo script":   func() error { _, _, _, err := client.RunSudoScript(ctx, "echo forbidden"); return err },
		"upload":        func() error { return client.UploadFile(ctx, "unused", nil, 0600) },
		"sudo upload":   func() error { return client.UploadSudoFile(ctx, "unused", nil, 0600) },
		"download":      func() error { _, err := client.DownloadFile(ctx, "unused"); return err },
		"sudo download": func() error { _, err := client.DownloadSudoFile(ctx, "unused"); return err },
		"exists":        func() error { _, err := client.FileExists(ctx, "unused"); return err },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrProviderAbsent) {
				t.Errorf("got %v, want refusal", err)
			}
		})
	}
	if client.IsAlive() || client.GetUnderlyingClient() != nil {
		t.Error("absent transport exposed as live")
	}
	if client.InUse() {
		t.Error("refusal started an operation")
	}
}
