package awg

import (
	"context"
	"sync"

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

// ServerLockForTest returns the in-process server mutex for testing preconditions.
func (m *AWGManager) ServerLockForTest(serverID int64) *sync.Mutex {
	return m.getServerLock(serverID)
}

// NewAWGManagerWithServerLocks creates a new AWGManager instance with a custom ServerLockRegistry for test isolation.
func NewAWGManagerWithServerLocks(pool SSHProvider, r *ServerLockRegistry) *AWGManager {
	if r == nil {
		panic("NewAWGManagerWithServerLocks: nil registry")
	}
	mgr := NewAWGManager(pool)
	mgr.serverLocks = r
	return mgr
}
