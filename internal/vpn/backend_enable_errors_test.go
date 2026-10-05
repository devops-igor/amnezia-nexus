package vpn

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestBackendEnableFailureStagePreservesTypedCauses(t *testing.T) {
	svc, err := NewVPNService(setupTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.EnableBackend(t.Context(), 999)
	if !errors.Is(err, ErrServerNotFound) || BackendEnableStage(err) != "load_server" {
		t.Fatalf("stage discarded sentinel cause: %v / %s", err, BackendEnableStage(err))
	}
	cancelled := backendEnableFailure("register_data_peer", fmt.Errorf("provider: %w", context.DeadlineExceeded))
	if !errors.Is(cancelled, context.DeadlineExceeded) || BackendEnableStage(cancelled) != "register_data_peer" {
		t.Fatal("provider cause/stage lost")
	}
}
