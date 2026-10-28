package xray

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	XrayContainerName = "amnezia-xray"
	XrayConfigDir     = "/opt/amnezia/xray"
	XrayConfigPath    = "/opt/amnezia/xray/config.json"
	XrayBaseImage     = "ghcr.io/xtls/xray-core:26.10.21"
)

// SSHProvider abstracts obtaining an SSHClient for a server.
type SSHProvider interface {
	Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error)
}

// XrayManager implements manager.ProtocolManager for VLESS+REALITY via Xray-core.
//
//nolint:revive
type XrayManager struct {
	sshPool        SSHProvider
	containerCache *xrayContainerCache
	serverLocks    *awg.ServerLockRegistry
	mu             sync.Mutex
}

// NewXrayManager creates a new XrayManager instance.
func NewXrayManager(pool SSHProvider) *XrayManager {
	return &XrayManager{
		sshPool:        pool,
		containerCache: newXrayContainerCache(),
		serverLocks:    awg.GlobalServerLocks(),
	}
}

// NewXrayManagerWithServerLocks creates a new XrayManager with custom server locks for testing.
func NewXrayManagerWithServerLocks(pool SSHProvider, locks *awg.ServerLockRegistry) *XrayManager {
	return &XrayManager{
		sshPool:        pool,
		containerCache: newXrayContainerCache(),
		serverLocks:    locks,
	}
}

// recentClients is package-level so every manager instance (HTTP handlers, reconciler,
// orchestrator) sees clients created by any other instance during the creation grace window.
var (
	recentMu      sync.Mutex
	recentClients = make(map[string]time.Time)
)

func (m *XrayManager) recordClientCreation(clientID string, createdAt time.Time) {
	recentMu.Lock()
	defer recentMu.Unlock()
	recentClients[clientID] = createdAt
}

func (m *XrayManager) recentClientCreation(clientID string) (time.Time, bool) {
	recentMu.Lock()
	defer recentMu.Unlock()

	now := time.Now().UTC()
	for id, createdAt := range recentClients {
		if now.Sub(createdAt) >= 10*time.Minute {
			delete(recentClients, id)
		}
	}
	createdAt, ok := recentClients[clientID]
	return createdAt, ok && now.Sub(createdAt) < 5*time.Minute
}

// Protocol returns the canonical protocol identifier for VLESS.
func (m *XrayManager) Protocol() string {
	return models.ProtocolVLESS
}

func (m *XrayManager) getSSHClient(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if m.sshPool == nil {
		return nil, errors.New("ssh pool is not configured")
	}
	return m.sshPool.Get(ctx, server)
}

func (m *XrayManager) lockServer(ctx context.Context, client ssh.SSHClient, serverID int64) (func(), error) {
	var localUnlock func()
	if m.serverLocks != nil {
		mu := m.serverLocks.GetLock(serverID)
		mu.Lock()
		localUnlock = mu.Unlock
	} else {
		m.mu.Lock()
		localUnlock = m.mu.Unlock
	}

	remoteUnlock, err := awg.AcquireRemoteServerLock(ctx, client, fmt.Sprintf("server_%d", serverID))
	if err != nil {
		localUnlock()
		return nil, fmt.Errorf("acquire remote lock on server %d: %w", serverID, err)
	}

	return func() {
		defer localUnlock()
		remoteUnlock()
	}, nil
}

// GetServerStatus returns the runtime status of the xray container.
func (m *XrayManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	cacheKey := m.containerCache.keyForServer(server)
	if isRunning, ok := m.containerCache.get(cacheKey); ok && !isRunning {
		return map[string]any{"container_running": false}, nil
	}

	cmd := fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(XrayContainerName))
	out, _, code, err := client.RunSudoCommand(ctx, cmd)
	if err != nil || code != 0 {
		m.containerCache.set(cacheKey, false)
		return map[string]any{"container_running": false}, nil
	}

	isRunning := strings.Contains(strings.TrimSpace(out), XrayContainerName)
	m.containerCache.set(cacheKey, isRunning)
	status := map[string]any{
		"container_running": isRunning,
	}
	if !isRunning {
		return status, nil
	}

	cfgBytes, err := client.DownloadFile(ctx, XrayConfigPath)
	if err == nil {
		if cfg, err := ParseXrayConfig(cfgBytes); err == nil && len(cfg.Inbounds) > 0 {
			status["port"] = cfg.Inbounds[0].Port
			status["clients_count"] = len(cfg.Inbounds[0].Settings.Clients)
			if len(cfg.Inbounds[0].StreamSettings.RealitySettings.ServerNames) > 0 {
				status["server_name"] = cfg.Inbounds[0].StreamSettings.RealitySettings.ServerNames[0]
			}
			if len(cfg.Inbounds[0].StreamSettings.RealitySettings.ShortIDs) > 0 {
				status["short_id"] = cfg.Inbounds[0].StreamSettings.RealitySettings.ShortIDs[0]
			}
			if pubKey, err := DerivePublicKey(cfg.Inbounds[0].StreamSettings.RealitySettings.PrivateKey); err == nil {
				status["public_key"] = pubKey
			}
		}
	}

	return status, nil
}
