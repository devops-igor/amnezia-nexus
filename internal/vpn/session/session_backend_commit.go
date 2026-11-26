package session

import (
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// CommitBackendMigration pins the observed session while commit accepts its
// durable placement. commit calls publish only after acceptance; publish changes
// memory only and must run synchronously, at most once. The lock order is session
// then pool then database; commit must not re-enter the session manager.
func (sm *SessionManager) CommitBackendMigration(expected models.VPNSession, targetID int64, commit func(publish func()) error) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	live, ok := sm.sessionsByID[expected.ID]
	if !ok || live == nil {
		return ErrSessionNotFound
	}
	if live.Generation != expected.Generation || live.PeerPublicKey != expected.PeerPublicKey ||
		live.BackendTunnelID != expected.BackendTunnelID || live.Status != expected.Status {
		return fmt.Errorf("session %s changed before backend migration", expected.ID)
	}
	return commit(func() {
		live.BackendTunnelID = targetID
		live.Status = "connected"
		sm.lifecycleVersion.Add(1)
	})
}
