package awg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ReadConfiguration reads the installed AWG container, the same configuration
// used by provisioning and peer changes. A missing config is an error.
func (m *AWGManager) ReadConfiguration(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}
	lock := m.getServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getServerConfig(ctx, client)
}

// WriteConfiguration serializes with peer operations and applies both disk and
// runtime changes. If runtime application fails after the disk write, restore
// the preceding configuration under the same lock with a bounded cleanup context.
func (m *AWGManager) WriteConfiguration(ctx context.Context, server *models.Server, content string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}
	lock := m.getServerLock(server.ID)
	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.acquireRemoteServerLock(ctx, client, server.ID)
	if err != nil {
		return err
	}
	defer unlock()
	original, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}
	written, err := m.saveServerConfigTracked(ctx, client, content)
	if err == nil || !written {
		return err
	}
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, restoreErr := m.saveServerConfigTracked(restoreCtx, client, original); restoreErr != nil {
		return errors.Join(err, fmt.Errorf("failed to restore previous AWG configuration: %w", restoreErr))
	}
	return err
}
