package tunnel

import (
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestConnectionTransferCommitPinsGenerationAndDefersPersistence(t *testing.T) {
	p := NewPool(nil)
	p.tunnelsByID[1] = &models.BackendTunnel{ID: 1, ActiveConnections: 1}
	p.tunnelsByID[2] = &models.BackendTunnel{ID: 2, Enabled: true, Status: "active", StateVersion: 7}
	persist, err := p.CommitConnectionTransfer(1, 2, 7, func(publish func()) error {
		if p.mu.TryLock() {
			p.mu.Unlock()
			t.Error("target generation not pinned during commit")
		}
		publish()
		return nil
	})
	if err != nil || persist == nil {
		t.Fatalf("commit error=%v persistence=%t", err, persist != nil)
	}
	persist()
	if p.tunnelsByID[1].ActiveConnections != 0 || p.tunnelsByID[2].ActiveConnections != 1 {
		t.Fatal("accepted transfer did not move exactly one connection")
	}
}

func TestConnectionTransferCommitRejectsWithoutGaugeMutation(t *testing.T) {
	for _, mode := range []string{"closed", "missing", "disabled", "inactive", "stale", "refused", "missing_source"} {
		t.Run(mode, func(t *testing.T) {
			p := NewPool(nil)
			p.tunnelsByID[1] = &models.BackendTunnel{ID: 1, ActiveConnections: 1}
			p.tunnelsByID[2] = &models.BackendTunnel{ID: 2, Enabled: true, Status: "active", StateVersion: 7}
			switch mode {
			case "closed":
				p.closed = true
			case "missing":
				delete(p.tunnelsByID, 2)
			case "disabled":
				p.tunnelsByID[2].Enabled = false
			case "inactive":
				p.tunnelsByID[2].Status = "degraded"
			case "stale":
				p.tunnelsByID[2].StateVersion++
			case "missing_source":
				delete(p.tunnelsByID, 1)
			}
			persist, err := p.CommitConnectionTransfer(1, 2, 7, func(publish func()) error {
				if mode == "missing_source" {
					publish()
					return nil
				}
				return errors.New("placement refused")
			})
			if mode == "missing_source" {
				if err != nil || persist == nil {
					t.Fatalf("missing source: %v", err)
				}
				persist()
				return
			}
			if err == nil || persist != nil || p.tunnelsByID[1].ActiveConnections != 1 {
				t.Fatalf("refusal: error=%v persistence=%t", err, persist != nil)
			}
		})
	}
}
