package session

import (
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestBackendMigrationCommitPinsObservedSession(t *testing.T) {
	observed := models.VPNSession{ID: "session", PeerPublicKey: "peer", BackendTunnelID: 1, Status: "connected", Generation: 4}
	for _, mode := range []string{"accepted", "refused", "replaced", "missing"} {
		t.Run(mode, func(t *testing.T) {
			live := observed
			sm := &SessionManager{sessionsByID: map[string]*models.VPNSession{observed.ID: &live}}
			if mode == "replaced" {
				live.Generation++
			}
			if mode == "missing" {
				delete(sm.sessionsByID, observed.ID)
			}
			err := sm.CommitBackendMigration(observed, 2, func(publish func()) error {
				if sm.mu.TryLock() {
					sm.mu.Unlock()
					t.Error("session owner not pinned")
				}
				if mode == "refused" {
					return errors.New("placement refused")
				}
				publish()
				return nil
			})
			if mode == "accepted" {
				if err != nil || live.BackendTunnelID != 2 || sm.LifecycleVersion() != 1 {
					t.Fatalf("accepted placement: live=%+v error=%v", live, err)
				}
			} else if err == nil || live.BackendTunnelID != 1 || sm.LifecycleVersion() != 0 {
				t.Fatalf("refused placement: live=%+v error=%v", live, err)
			}
		})
	}
}
