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

	// Pinned engine image tags and digests for reproducible deployments.
	XrayLegacyVersion = "1.8.24"
	XrayLegacyDigest  = "sha256:6b3ef1780d4be55c1bc4848232a90272d31c28cc3d0de1f2a50a56f48993be9d"
	XrayLegacyImage   = "ghcr.io/xtls/xray-core:1.8.24@sha256:6b3ef1780d4be55c1bc4848232a90272d31c28cc3d0de1f2a50a56f48993be9d"

	XrayModernPQVersion = "26.10.29"
	XrayModernPQDigest  = "sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044"
	XrayModernPQImage   = "ghcr.io/xtls/xray-core:26.10.29@sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044"

	// DefaultEngineProfile is the Legacy Compatibility Baseline (default for broad third-party client compatibility).
	DefaultEngineProfile = EngineProfileLegacy

	// XrayBaseImage remains for backward compatibility, pointing to the default legacy baseline image.
	XrayBaseImage = XrayLegacyImage
)

// EngineProfile represents the Xray-core deployment profile.
type EngineProfile string

const (
	EngineProfileLegacy   EngineProfile = "legacy"
	EngineProfileModernPQ EngineProfile = "modern_pq"
)

// EngineProfileInfo encapsulates pinned metadata for an Xray engine profile.
type EngineProfileInfo struct {
	Name        EngineProfile `json:"name"`
	Version     string        `json:"version"`
	ImageDigest string        `json:"image_digest"`
	Image       string        `json:"image"`
	Description string        `json:"description"`
}

// SupportedEngineProfiles holds verified, pinned profiles.
var SupportedEngineProfiles = map[EngineProfile]EngineProfileInfo{
	EngineProfileLegacy: {
		Name:        EngineProfileLegacy,
		Version:     XrayLegacyVersion,
		ImageDigest: XrayLegacyDigest,
		Image:       XrayLegacyImage,
		Description: "Legacy Compatibility Baseline (v1.8.24) — broad third-party client compatibility",
	},
	EngineProfileModernPQ: {
		Name:        EngineProfileModernPQ,
		Version:     XrayModernPQVersion,
		ImageDigest: XrayModernPQDigest,
		Image:       XrayModernPQImage,
		Description: "Modern PQ (v26.10.29) — Post-Quantum REALITY (X25519MLKEM768)",
	},
}

// ResolveEngineProfile normalizes user input into a known EngineProfileInfo.
func ResolveEngineProfile(profileName string) (EngineProfileInfo, error) {
	norm := strings.ToLower(strings.TrimSpace(profileName))
	switch {
	case norm == "" || norm == "legacy" || norm == "legacy_baseline" || norm == "legacy compatibility baseline" || norm == "baseline" || norm == "1.8.24" || norm == "v1.8.24":
		return SupportedEngineProfiles[EngineProfileLegacy], nil
	case norm == "modern_pq" || norm == "modern" || norm == "pq" || norm == "26.10.29" || norm == "v26.10.29" || norm == "modern pq" || norm == "post_quantum" || norm == "post-quantum" || strings.HasPrefix(norm, "26.10.") || strings.HasPrefix(norm, "v26.10."):
		return SupportedEngineProfiles[EngineProfileModernPQ], nil
	default:
		return EngineProfileInfo{}, fmt.Errorf("unknown xray engine profile %q (supported: legacy, modern_pq)", profileName)
	}
}

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

	// Inspect engine image and running version
	imgCmd := fmt.Sprintf("docker inspect -f '{{.Config.Image}}' %s 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	if imgOut, _, iCode, iErr := client.RunSudoCommand(ctx, imgCmd); iErr == nil && iCode == 0 && strings.TrimSpace(imgOut) != "" {
		status["engine_image"] = strings.TrimSpace(imgOut)
	}
	verCmd := fmt.Sprintf("docker exec %s xray version 2>/dev/null", ssh.EscapeShellArg(XrayContainerName))
	if verOut, _, vCode, vErr := client.RunSudoCommand(ctx, verCmd); vErr == nil && vCode == 0 && strings.TrimSpace(verOut) != "" {
		if fields := strings.Fields(strings.TrimSpace(verOut)); len(fields) >= 2 && strings.EqualFold(fields[0], "Xray") {
			status["running_engine_version"] = fields[1]
		}
	}

	return status, nil
}
