package naive

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	NaiveContainerName = "amnezia-caddy"
	NaiveConfigDir     = "/opt/amnezia/caddy"
	NaiveWWWDir        = "/opt/amnezia/caddy/www"
	NaiveHTMLDir       = NaiveWWWDir
	NaiveCaddyfilePath = "/opt/amnezia/caddy/Caddyfile"
	NaiveDataVolume    = "amnezia-caddy-data"
	NaiveBaseImage     = "amnezia-caddy:local"
)

// Decoy website theme identifiers.
const (
	DecoyThemeMinecraft      = "minecraft"
	DecoyThemeCreativeStudio = "creative-studio"
	DecoyThemeDefault        = "default"
)

//go:embed assets/decoy/minecraft/index.html
var minecraftDecoyHTML []byte

//go:embed assets/decoy/creative-studio/index.html
var creativeStudioDecoyHTML []byte

// GetDecoyHTML returns the static HTML content for the specified decoy theme.
// It returns the Creative Studio asset for "creative-studio" (or "portfolio"),
// and falls back to the Minecraft Community asset for "minecraft", "voxelnet",
// "default", or any empty/unknown theme.
func GetDecoyHTML(theme string) []byte {
	switch strings.ToLower(strings.TrimSpace(theme)) {
	case DecoyThemeCreativeStudio, "portfolio":
		return creativeStudioDecoyHTML
	case DecoyThemeMinecraft, "voxelnet", DecoyThemeDefault:
		return minecraftDecoyHTML
	default:
		return minecraftDecoyHTML
	}
}

// SSHProvider abstracts obtaining an SSHClient for a server.
type SSHProvider interface {
	Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error)
}

// DNSLookupFunc abstracts DNS resolution for pre-flight domain validation.
type DNSLookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// NaiveManager implements manager.ProtocolManager for NaiveProxy via Caddy forward_proxy.
//
//nolint:revive
type NaiveManager struct {
	sshPool     SSHProvider
	serverLocks *awg.ServerLockRegistry
	mu          sync.Mutex
	dnsLookup   DNSLookupFunc
}

// SetDNSLookup sets a custom DNS lookup function for pre-flight domain validation (used in tests).
func (m *NaiveManager) SetDNSLookup(fn DNSLookupFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsLookup = fn
}

func (m *NaiveManager) getDNSLookup() DNSLookupFunc {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dnsLookup
}

// NewNaiveManager creates a new NaiveManager instance.
func NewNaiveManager(pool SSHProvider) *NaiveManager {
	return &NaiveManager{
		sshPool:     pool,
		serverLocks: awg.GlobalServerLocks(),
	}
}

// NewNaiveManagerWithServerLocks creates a new NaiveManager with custom server locks for testing.
func NewNaiveManagerWithServerLocks(pool SSHProvider, locks *awg.ServerLockRegistry) *NaiveManager {
	return &NaiveManager{
		sshPool:     pool,
		serverLocks: locks,
	}
}

// recentClients is package-level so every manager instance (HTTP handlers, reconciler,
// orchestrator) sees clients created by any other instance during the creation grace window.
var (
	recentMu      sync.Mutex
	recentClients = make(map[string]time.Time)
)

func (m *NaiveManager) recordClientCreation(clientID string, createdAt time.Time) {
	recentMu.Lock()
	defer recentMu.Unlock()
	recentClients[clientID] = createdAt
}

func (m *NaiveManager) recentClientCreation(clientID string) (time.Time, bool) {
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

// Protocol returns the canonical protocol identifier for NaiveProxy.
func (m *NaiveManager) Protocol() string {
	return models.ProtocolNaive
}

func (m *NaiveManager) getSSHClient(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if m.sshPool == nil {
		return nil, errors.New("ssh pool is not configured")
	}
	return m.sshPool.Get(ctx, server)
}

func (m *NaiveManager) lockServer(ctx context.Context, client ssh.SSHClient, serverID int64) (func(), error) {
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

// GetServerStatus returns the runtime status of the caddy container.
func (m *NaiveManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	cmd := fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(NaiveContainerName))
	out, _, code, err := client.RunSudoCommand(ctx, cmd)
	if err != nil || code != 0 {
		return map[string]any{"container_running": false}, nil
	}

	isRunning := strings.Contains(strings.TrimSpace(out), NaiveContainerName)
	status := map[string]any{
		"container_running": isRunning,
	}
	if !isRunning {
		return status, nil
	}

	caddyfileBytes, err := client.DownloadFile(ctx, NaiveCaddyfilePath)
	if err == nil {
		domain, port, clients, err := ParseCaddyfile(string(caddyfileBytes))
		if err == nil {
			status["port"] = port
			status["clients_count"] = len(clients)
			if domain != "" {
				status["domain"] = domain
			}
		}
	}

	return status, nil
}
