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
	GenerateLockToken      = generateLockToken
)

func (m *AWGManager) AcquireRemoteServerLock(ctx context.Context, client ssh.SSHClient, serverID int64) (func(), error) {
	return m.acquireRemoteServerLock(ctx, client, serverID)
}
