package awg

import (
	"context"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

var (
	RemoteLockAcquireCmd   = remoteLockAcquireCmd
	RemoteLockReleaseCmd   = remoteLockReleaseCmd
	RemoteLockHeartbeatCmd = remoteLockHeartbeatCmd
	RemoteLockPath         = remoteLockPath
	RemoteLockResourcePath = remoteLockResourcePath
	GenerateLockToken      = generateLockToken
)

func (m *AWGManager) AcquireRemoteServerLock(ctx context.Context, client ssh.SSHClient, serverID int64) (func(), error) {
	return m.acquireRemoteServerLock(ctx, client, serverID)
}

// SetServerLockRegistryForTest overrides the server lock registry for testing purposes.
func (m *AWGManager) SetServerLockRegistryForTest(r *ServerLockRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serverLocks = r
}

// NewAWGManagerWithServerLocks creates a new AWGManager instance with a custom ServerLockRegistry for test isolation.
func NewAWGManagerWithServerLocks(pool SSHProvider, r *ServerLockRegistry) *AWGManager {
	mgr := NewAWGManager(pool)
	if r != nil {
		mgr.serverLocks = r
	}
	return mgr
}
