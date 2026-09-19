package awg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/cps"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/curve25519"
)

var (
	AWGContainerNames  = []string{"amnezia-awg2", "amnezia-awg", "amnezia-awg-legacy"}
	containerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

const defaultContainerCacheTTL = 5 * time.Minute

// IsValidContainerName validates a container name against strict regex:
// must start with an alphanumeric character, followed by alphanumeric, dot, underscore, or hyphen.
func IsValidContainerName(name string) bool {
	return containerNameRegex.MatchString(name)
}

type containerCacheEntry struct {
	name      string
	expiresAt time.Time
}

// SSHProvider abstracts obtaining an SSHClient for a server.
type SSHProvider interface {
	Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error)
}

// IPAllocator defines an interface for managing atomic IP address allocations.
//
// Contract:
//   - AllocateAWGClientIP:
//   - clientID: logical identifier for the client (e.g. user ID or explicit client identifier).
//   - clientPubKey: WireGuard / AmneziaWG public key for the peer.
//   - The allocation is idempotent: if an allocation already exists for either clientID or
//     clientPubKey on serverID, the previously allocated IP is retained and returned.
//   - Concurrent allocations on the same server are synchronized and serialized to guarantee
//     zero IP collisions within the subnet.
//   - ReleaseAWGClientIP:
//   - Releases the allocation matching serverID and clientID (and/or ip).
//   - TransferAWGClientIPLease:
//   - Transfers allocation lease ownership when an existing client re-keys.
//   - AdoptAWGClientIPLease:
//   - Adopts an existing metadata IP for an upgraded client into SQLite if available.
type IPAllocator interface {
	AllocateAWGClientIP(ctx context.Context, serverID int64, clientID, clientPubKey string, usedConfigIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error)
	ReleaseAWGClientIP(ctx context.Context, serverID int64, clientID, ip string) error
	TransferAWGClientIPLease(ctx context.Context, serverID int64, newClientID, oldClientID, ip string) error
	AdoptAWGClientIPLease(ctx context.Context, serverID int64, clientID, clientPubKey, ip string) (bool, error)
}

// ServerLockRegistry provides per-server mutex synchronization across manager instances.
type ServerLockRegistry struct {
	mu    sync.Mutex
	locks map[int64]*sync.Mutex
}

var globalServerLocks = NewServerLockRegistry()

// NewServerLockRegistry creates a new ServerLockRegistry instance.
func NewServerLockRegistry() *ServerLockRegistry {
	return &ServerLockRegistry{
		locks: make(map[int64]*sync.Mutex),
	}
}

func (r *ServerLockRegistry) getLock(serverID int64) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.locks[serverID]
	if !ok {
		l = &sync.Mutex{}
		r.locks[serverID] = l
	}
	return l
}

// AWGManager implements manager.ProtocolManager for AmneziaWG.
//
//nolint:revive
type AWGManager struct {
	sshPool                 SSHProvider
	mu                      sync.Mutex
	cacheMu                 sync.RWMutex
	containerCache          map[string]containerCacheEntry
	ipAllocator             IPAllocator
	serverLocks             *ServerLockRegistry
	lockHeartbeatIntervalNs atomic.Int64
	lockHeartbeatTimeoutNs  atomic.Int64
	// tcCleaned guards the one-shot legacy tc-state sweep: server IDs that
	// have already been swept by this manager instance. Guarded by mu.
	tcCleaned map[int64]bool
}

// NewAWGManager creates a new AWGManager instance.
func NewAWGManager(pool SSHProvider) *AWGManager {
	return &AWGManager{
		sshPool:        pool,
		containerCache: make(map[string]containerCacheEntry),
		tcCleaned:      make(map[int64]bool),
		serverLocks:    globalServerLocks,
	}
}

// SetServerLockRegistry overrides the server lock registry used by the manager instance.
func (m *AWGManager) SetServerLockRegistry(r *ServerLockRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serverLocks = r
}

func (m *AWGManager) getServerLock(serverID int64) *sync.Mutex {
	if m.serverLocks != nil {
		return m.serverLocks.getLock(serverID)
	}
	return globalServerLocks.getLock(serverID)
}

// SetIPAllocator sets the IP allocator for the AWGManager.
func (m *AWGManager) SetIPAllocator(allocator IPAllocator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAllocator = allocator
}

const (
	defaultRemoteLockHeartbeatInterval = 10 * time.Second
	defaultRemoteLockHeartbeatTimeout  = 5 * time.Second
)

// SetLockHeartbeatConfig configures the interval and timeout for remote lock renewal heartbeats.
func (m *AWGManager) SetLockHeartbeatConfig(interval, timeout time.Duration) {
	if m == nil {
		return
	}
	m.lockHeartbeatIntervalNs.Store(int64(interval))
	m.lockHeartbeatTimeoutNs.Store(int64(timeout))
}

func (m *AWGManager) getLockHeartbeatConfig() (time.Duration, time.Duration) {
	if m == nil {
		return defaultRemoteLockHeartbeatInterval, defaultRemoteLockHeartbeatTimeout
	}
	interval := time.Duration(m.lockHeartbeatIntervalNs.Load())
	if interval <= 0 {
		interval = defaultRemoteLockHeartbeatInterval
	}
	timeout := time.Duration(m.lockHeartbeatTimeoutNs.Load())
	if timeout <= 0 {
		timeout = defaultRemoteLockHeartbeatTimeout
	}
	return interval, timeout
}

func generateLockToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func remoteLockPath(resource any) string {
	var target string
	switch v := resource.(type) {
	case int64:
		target = fmt.Sprintf("server_%d", v)
	case int:
		target = fmt.Sprintf("server_%d", v)
	case string:
		target = strings.TrimSpace(v)
		if strings.HasPrefix(target, "/tmp/amnezia_awg_") && strings.HasSuffix(target, ".lock") {
			return target
		}
	case fmt.Stringer:
		target = v.String()
	default:
		target = fmt.Sprintf("%v", v)
	}
	if target == "" {
		target = "server_0"
	}
	return fmt.Sprintf("/tmp/amnezia_awg_%s.lock", target)
}

func remoteLockResourcePath(resource string) string {
	return remoteLockPath(resource)
}

func remoteLockAcquireCmd(resource any, token string) string {
	lockDir := remoteLockPath(resource)
	escapedLockDir := ssh.EscapeShellArg(lockDir)
	escapedTok := ssh.EscapeShellArg(token)
	// Atomic directory/file lock with timeout (30 seconds) and stale lock recovery (60 seconds).
	// Generation-safe ownership metadata (<token> <timestamp>) and re-verification on rename prevent successor TOCTOU.
	// Acquisition gate mutex ($flock_path.gate) with generation-safe TTL recovery (15 seconds) prevents live lock displacement and third-party acquisition during stale recovery.
	// Mentions flock for cross-process synchronization compatibility.
	return fmt.Sprintf(
		`flock_path=%s; gate_path="$flock_path.gate"; timeout=30; start=$(date +%%s); while true; do if ! mkdir "$gate_path" 2>/dev/null; then if [ -d "$gate_path" ]; then g_now=$(date +%%s); g_mtime=$(stat -c %%Y "$gate_path" 2>/dev/null || stat -f %%m "$gate_path" 2>/dev/null); case "$g_mtime" in ''|*[!0-9]*) g_mtime="$g_now" ;; esac; g_info=$(cat "$gate_path/owner" 2>/dev/null); set -- $g_info; g_tok="$1"; g_ts="$2"; case "$g_ts" in *[!0-9]*) g_ts="" ;; esac; if [ $((g_now - g_mtime)) -ge 15 ] && { [ -z "$g_ts" ] || [ $((g_now - g_ts)) -ge 15 ]; }; then g_ren_dir="$gate_path.stale.$g_now.$$"; if mv "$gate_path" "$g_ren_dir" 2>/dev/null; then g_ren_now=$(date +%%s); g_ren_mtime=$(stat -c %%Y "$g_ren_dir" 2>/dev/null || stat -f %%m "$g_ren_dir" 2>/dev/null); case "$g_ren_mtime" in ''|*[!0-9]*) g_ren_mtime="$g_ren_now" ;; esac; g_ren_info=$(cat "$g_ren_dir/owner" 2>/dev/null); set -- $g_ren_info; g_ren_tok="$1"; g_ren_ts="$2"; case "$g_ren_ts" in *[!0-9]*) g_ren_ts="" ;; esac; if [ "$g_ren_tok" = "$g_tok" ] && [ $((g_ren_now - g_ren_mtime)) -ge 15 ] && { [ -z "$g_ts" ] || [ "$g_ren_ts" = "$g_ts" ]; } && { [ -z "$g_ren_ts" ] || [ $((g_ren_now - g_ren_ts)) -ge 15 ]; }; then rm -rf "$g_ren_dir"; else if [ ! -d "$gate_path" ]; then mv "$g_ren_dir" "$gate_path" 2>/dev/null; else rm -rf "$g_ren_dir"; fi; fi; fi; fi; fi; now=$(date +%%s); if [ $((now - start)) -ge $timeout ]; then echo "timed out waiting for remote lock on $flock_path" >&2; exit 1; fi; sleep 0.05 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; continue; fi; g_acq_ts=$(date +%%s); echo %s "$g_acq_ts" > "$gate_path/owner" 2>/dev/null; if mkdir "$flock_path" 2>/dev/null; then rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; break; fi; if [ -d "$flock_path" ]; then now=$(date +%%s); mtime=$(stat -c %%Y "$flock_path" 2>/dev/null || stat -f %%m "$flock_path" 2>/dev/null); case "$mtime" in ''|*[!0-9]*) mtime="$now" ;; esac; if [ $((now - mtime)) -ge 60 ]; then stale_info=$(cat "$flock_path/owner" 2>/dev/null); set -- $stale_info; stale_token="$1"; stale_ts="$2"; if [ -n "$stale_token" ]; then cur_now=$(date +%%s); cur_mtime=$(stat -c %%Y "$flock_path" 2>/dev/null || stat -f %%m "$flock_path" 2>/dev/null); case "$cur_mtime" in ''|*[!0-9]*) cur_mtime="$cur_now" ;; esac; if [ $((cur_now - cur_mtime)) -ge 60 ] && { [ -z "$stale_ts" ] || [ $((cur_now - stale_ts)) -ge 60 ]; }; then if mv "$flock_path" "$flock_path.stale.$now.$$" 2>/dev/null; then ren_now=$(date +%%s); ren_mtime=$(stat -c %%Y "$flock_path.stale.$now.$$" 2>/dev/null || stat -f %%m "$flock_path.stale.$now.$$" 2>/dev/null); case "$ren_mtime" in ''|*[!0-9]*) ren_mtime="$ren_now" ;; esac; ren_info=$(cat "$flock_path.stale.$now.$$/owner" 2>/dev/null); set -- $ren_info; ren_token="$1"; ren_ts="$2"; if [ "$ren_token" = "$stale_token" ] && [ $((ren_now - ren_mtime)) -ge 60 ] && { [ -z "$stale_ts" ] || [ "$ren_ts" = "$stale_ts" ]; } && { [ -z "$ren_ts" ] || [ $((ren_now - ren_ts)) -ge 60 ]; }; then rm -rf "$flock_path.stale.$now.$$"; if mkdir "$flock_path" 2>/dev/null; then rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; break; fi; else if [ ! -d "$flock_path" ]; then mv "$flock_path.stale.$now.$$" "$flock_path" 2>/dev/null; else rm -rf "$flock_path.stale.$now.$$"; fi; fi; fi; fi; elif [ ! -s "$flock_path/owner" ] || [ -z "$stale_token" ]; then cur_now=$(date +%%s); cur_mtime=$(stat -c %%Y "$flock_path" 2>/dev/null || stat -f %%m "$flock_path" 2>/dev/null); case "$cur_mtime" in ''|*[!0-9]*) cur_mtime="$cur_now" ;; esac; if [ $((cur_now - cur_mtime)) -ge 60 ]; then if mv "$flock_path" "$flock_path.ownerless.$now.$$" 2>/dev/null; then ren_now=$(date +%%s); ren_mtime=$(stat -c %%Y "$flock_path.ownerless.$now.$$" 2>/dev/null || stat -f %%m "$flock_path.ownerless.$now.$$" 2>/dev/null); case "$ren_mtime" in ''|*[!0-9]*) ren_mtime="$ren_now" ;; esac; ren_info=$(cat "$flock_path.ownerless.$now.$$/owner" 2>/dev/null); set -- $ren_info; ren_token="$1"; if { [ ! -s "$flock_path.ownerless.$now.$$/owner" ] || [ -z "$ren_token" ]; } && [ $((ren_now - ren_mtime)) -ge 60 ]; then rm -rf "$flock_path.ownerless.$now.$$"; if mkdir "$flock_path" 2>/dev/null; then rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; break; fi; else if [ ! -d "$flock_path" ]; then mv "$flock_path.ownerless.$now.$$" "$flock_path" 2>/dev/null; else rm -rf "$flock_path.ownerless.$now.$$"; fi; fi; fi; fi; fi; fi; fi; rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; now=$(date +%%s); if [ $((now - start)) -ge $timeout ]; then echo "timed out waiting for remote lock on $flock_path" >&2; exit 1; fi; sleep 0.05 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; done; acq_now=$(date +%%s); echo %s "$acq_now" > "$flock_path/owner"`,
		escapedLockDir,
		escapedTok,
		escapedTok,
	)
}

func remoteLockReleaseCmd(resource any, token string) string {
	lockDir := remoteLockPath(resource)
	escapedTok := ssh.EscapeShellArg(token)
	return fmt.Sprintf(
		`cur_owner=$(cat %s/owner 2>/dev/null); if [ -n %s ] && { [ "$cur_owner" = %s ] || [ "${cur_owner%%%% *}" = %s ]; }; then rm -rf %s %s.gate 2>/dev/null; fi`,
		ssh.EscapeShellArg(lockDir),
		escapedTok,
		escapedTok,
		escapedTok,
		ssh.EscapeShellArg(lockDir),
		ssh.EscapeShellArg(lockDir),
	)
}

func remoteLockHeartbeatCmd(resource any, token string) string {
	lockDir := remoteLockPath(resource)
	escapedTok := ssh.EscapeShellArg(token)
	return fmt.Sprintf(
		`cur_owner=$(cat %s/owner 2>/dev/null); if [ -d %s ] && [ -n %s ] && { [ "$cur_owner" = %s ] || [ "${cur_owner%%%% *}" = %s ]; }; then touch -m %s; fi`,
		ssh.EscapeShellArg(lockDir),
		ssh.EscapeShellArg(lockDir),
		escapedTok,
		escapedTok,
		escapedTok,
		ssh.EscapeShellArg(lockDir),
	)
}

// resolveLockResource anchors remote mutation locking to the physical AWG interface/target
// on the remote host (e.g. iface_awg0). Because lock files reside on the target host filesystem,
// the host is already its natural namespace. Scoping the lock to the physical interface guarantees
// that all Server.ID records and manager instances targeting the same host interface serialize on
// the exact same lock path regardless of container discovery state (success, failure, retry, recovery).
func (m *AWGManager) resolveLockResource(ctx context.Context, client ssh.SSHClient, serverID int64) string {
	_ = ctx
	_ = client
	_ = serverID

	iface := "awg0"
	if m != nil {
		if name := strings.TrimSpace(m.interfaceName()); name != "" {
			iface = name
		}
	}
	iface = strings.ToLower(iface)
	if strings.HasPrefix(iface, "iface_") {
		return iface
	}
	return fmt.Sprintf("iface_%s", iface)
}

// ResolveLockResource returns the physical lock target resource identifier for the remote server.
func (m *AWGManager) ResolveLockResource(ctx context.Context, client ssh.SSHClient, serverID int64) string {
	return m.resolveLockResource(ctx, client, serverID)
}

func (m *AWGManager) acquireRemoteServerLock(ctx context.Context, client ssh.SSHClient, serverID int64) (func(), error) {
	if client == nil || serverID <= 0 {
		return func() {}, nil
	}
	resource := m.resolveLockResource(ctx, client, serverID)
	token := generateLockToken()
	cmd := remoteLockAcquireCmd(resource, token)
	_, errOut, code, err := client.RunSudoCommand(ctx, cmd)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("failed to acquire remote server lock on server %d (exit code %d): %s: %w", serverID, code, strings.TrimSpace(errOut), err)
	}

	interval, timeout := m.getLockHeartbeatConfig()
	heartbeatCtx, cancelHeartbeat := context.WithCancel(context.Background())
	touchCmd := remoteLockHeartbeatCmd(resource, token)

	var heartbeatWg sync.WaitGroup
	heartbeatWg.Add(1)
	go func() {
		defer heartbeatWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				touchCtx, touchCancel := context.WithTimeout(heartbeatCtx, timeout)
				_, errOut, code, err := client.RunSudoCommand(touchCtx, touchCmd)
				touchCancel()
				if err != nil || code != 0 {
					if !errors.Is(touchCtx.Err(), context.Canceled) {
						slog.Debug("failed to refresh remote server lock heartbeat", "server_id", serverID, "resource", resource, "code", code, "error", err, "stderr", strings.TrimSpace(errOut))
					}
				}
			}
		}
	}()

	var once sync.Once
	unlock := func() {
		once.Do(func() {
			cancelHeartbeat()
			heartbeatWg.Wait()

			relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			relCmd := remoteLockReleaseCmd(resource, token)
			_, errOut, code, err := client.RunSudoCommand(relCtx, relCmd)
			if err != nil || code != 0 {
				slog.Warn("failed to release remote server lock", "server_id", serverID, "resource", resource, "code", code, "error", err, "stderr", strings.TrimSpace(errOut))
			}
		})
	}
	return unlock, nil
}

func (m *AWGManager) getCachedContainer(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	if m.containerCache == nil {
		return "", false
	}
	entry, ok := m.containerCache[key]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	if !IsValidContainerName(entry.name) {
		return "", false
	}
	return entry.name, true
}

func (m *AWGManager) setCachedContainer(key string, name string) {
	if key == "" || !IsValidContainerName(name) {
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.containerCache == nil {
		m.containerCache = make(map[string]containerCacheEntry)
	}
	m.containerCache[key] = containerCacheEntry{
		name:      name,
		expiresAt: time.Now().Add(defaultContainerCacheTTL),
	}
}

func (m *AWGManager) getCachedContainerForClient(client ssh.SSHClient) (string, bool) {
	if client == nil {
		return "", false
	}
	if id := client.GetServerID(); id != nil && *id != 0 {
		if val, ok := m.getCachedContainer(fmt.Sprintf("id:%d", *id)); ok {
			return val, true
		}
	}
	if host := client.GetHost(); host != "" {
		if val, ok := m.getCachedContainer(fmt.Sprintf("host:%s:%d", host, client.GetPort())); ok {
			return val, true
		}
		if val, ok := m.getCachedContainer(fmt.Sprintf("host:%s", host)); ok {
			return val, true
		}
	}
	return "", false
}

func (m *AWGManager) setCachedContainerForClient(client ssh.SSHClient, name string) {
	if client == nil || !IsValidContainerName(name) {
		return
	}
	if id := client.GetServerID(); id != nil && *id != 0 {
		m.setCachedContainer(fmt.Sprintf("id:%d", *id), name)
	}
	if host := client.GetHost(); host != "" {
		m.setCachedContainer(fmt.Sprintf("host:%s:%d", host, client.GetPort()), name)
		m.setCachedContainer(fmt.Sprintf("host:%s", host), name)
	}
}

func (m *AWGManager) setCachedContainerForServer(server *models.Server, name string) {
	if server == nil || !IsValidContainerName(name) {
		return
	}
	if server.ID != 0 {
		m.setCachedContainer(fmt.Sprintf("id:%d", server.ID), name)
	}
	if server.Host != "" {
		port := server.SSHPort
		if port == 0 {
			port = 22
		}
		m.setCachedContainer(fmt.Sprintf("host:%s:%d", server.Host, port), name)
		m.setCachedContainer(fmt.Sprintf("host:%s", server.Host), name)
	}
}

func (m *AWGManager) invalidateContainerCache(server *models.Server) {
	if server == nil {
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.containerCache == nil {
		return
	}
	if server.ID != 0 {
		delete(m.containerCache, fmt.Sprintf("id:%d", server.ID))
	}
	if server.Host != "" {
		port := server.SSHPort
		if port == 0 {
			port = 22
		}
		delete(m.containerCache, fmt.Sprintf("host:%s:%d", server.Host, port))
		delete(m.containerCache, fmt.Sprintf("host:%s", server.Host))
	}
}

func (m *AWGManager) Protocol() string {
	return "awg"
}

func (m *AWGManager) getSSHClient(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if m.sshPool == nil {
		return nil, errors.New("ssh pool is not configured")
	}
	return m.sshPool.Get(ctx, server)
}

func (m *AWGManager) containerName() string {
	return "amnezia-awg2"
}

func (m *AWGManager) configPath() string {
	return "/opt/amnezia/awg/awg0.conf"
}

func (m *AWGManager) clientsTablePath() string {
	return "/opt/amnezia/awg/clientsTable"
}

func (m *AWGManager) interfaceName() string {
	return "awg0"
}

func (m *AWGManager) wgBinary() string {
	return "awg"
}

func ensureDockerInstalled(ctx context.Context, client ssh.SSHClient) error {
	out, _, code, _ := client.RunCommand(ctx, "docker --version")
	if code == 0 && strings.Contains(strings.ToLower(out), "docker") {
		return nil
	}
	dockerScript := `
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
else echo "Packet manager not found"; exit 1; fi;
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then $pm $check_pkgs && $pm $silent_inst $docker_pkg && systemctl enable --now docker; fi;
systemctl start docker; docker --version
`
	if _, errOut, dCode, err := client.RunSudoScript(ctx, dockerScript); err != nil || dCode != 0 {
		return fmt.Errorf("failed to install Docker (code %d): %s, %w", dCode, errOut, err)
	}
	return nil
}

func prepareHostAndContainers(ctx context.Context, client ssh.SSHClient) error {
	prepScript := `
mkdir -p /opt/amnezia/amnezia-awg2 /opt/amnezia/awg
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net || true
fi
`
	if _, _, _, err := client.RunSudoScript(ctx, prepScript); err != nil {
		return fmt.Errorf("failed to prepare host: %w", err)
	}

	for _, name := range AWGContainerNames {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
	}
	return nil
}

// awgBaseImage pins the AmneziaWG userspace base image used to build AWG
// backends. devopsigor/amneziawg:v3.1.20260828-1 is a versioned multiarch
// (amd64+arm64) tag from the amneziawg-docker repo, built from the
// AmneziaWG v3.1.20260828 source (devopsigor publishing). Multiarch is
// required because backends install on both amd64 and arm64 hosts — the
// upstream amneziavpn/amneziawg-go image publishes amd64 only, which broke
// ARM64 installs (Issue #225). The versioned tag is chosen over :latest
// because this image becomes a privileged VPN container on remote hosts:
// a mutable floating tag is a supply-chain and reproducibility hazard, so
// installs must pin an immutable, verifiable version. The explicit pull
// before build ensures the tag exists on the host instead of failing
// mid-build with a stale local cache.
const awgBaseImage = "devopsigor/amneziawg:v3.1.20260828-1"

func (m *AWGManager) buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	cName := m.containerName()
	if !IsValidContainerName(cName) {
		cName = "amnezia-awg2"
	}
	// Preflight: fail fast when the UDP port is already bound (host socket or
	// existing docker port binding) instead of discovering it at `docker run`
	// time after a slow pull+build cycle (Issue #225). Best-effort: a port
	// could still bind between check and run — `docker run` remains the final
	// authority.
	if err := checkUDPPortAvailable(ctx, client, port); err != nil {
		return err
	}
	dockerfile := fmt.Sprintf(`FROM %s
LABEL maintainer="AmneziaVPN"
RUN apk add --no-cache bash curl dumb-init iptables && apk --update upgrade --no-cache
RUN mkdir -p /opt/amnezia
RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && echo "tail -f /dev/null" >> /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh
ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
`, awgBaseImage)
	if err := client.UploadSudoFile(ctx, fmt.Sprintf("/opt/amnezia/%s/Dockerfile", cName), []byte(dockerfile), 0644); err != nil {
		return fmt.Errorf("failed to upload Dockerfile: %w", err)
	}

	if _, errOut, pCode, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker pull %s", ssh.EscapeShellArg(awgBaseImage))); err != nil || pCode != 0 {
		return fmt.Errorf("failed to pull AWG base image %s (code %d): %s, %w", awgBaseImage, pCode, errOut, err)
	}

	if _, errOut, bCode, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker build --no-cache -t %s /opt/amnezia/%s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cName))); err != nil || bCode != 0 {
		return fmt.Errorf("failed to build %s image (code %d): %s, %w", cName, bCode, errOut, err)
	}

	runCmd := fmt.Sprintf(`docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p %s:%s/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name %s \
%s`, ssh.EscapeShellArg(port), ssh.EscapeShellArg(port), ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cName))

	if _, errOut, rCode, err := client.RunSudoCommand(ctx, runCmd); err != nil || rCode != 0 {
		return fmt.Errorf("failed to run container (code %d): %s, %w", rCode, errOut, err)
	}

	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker network connect amnezia-dns-net %s 2>/dev/null || true", ssh.EscapeShellArg(cName)))
	return nil
}

func buildAndRunAWGContainer(ctx context.Context, client ssh.SSHClient, port string) error {
	return (&AWGManager{}).buildAndRunAWGContainer(ctx, client, port)
}

// legacyTcCleanupCommands returns the exact remote commands that clear tc
// data-plane state installed by the pre-74b34d9 speed-limit code inside the
// AWG container: the root qdisc on awg0 (plus its per-client HTB classes and
// filters), the root qdisc on ifb0, and finally the ifb0 redirect device.
// Every command carries `|| true` — the sweep is strictly best-effort.
func legacyTcCleanupCommands(containerName string) []string {
	cn := ssh.EscapeShellArg(containerName)
	return []string{
		fmt.Sprintf("docker exec -i %s tc qdisc del dev awg0 root 2>/dev/null || true", cn),
		fmt.Sprintf("docker exec -i %s tc qdisc del dev ifb0 root 2>/dev/null || true", cn),
		fmt.Sprintf("docker exec -i %s ip link del ifb0 2>/dev/null || true", cn),
	}
}

// CleanupLegacyTcRules removes leftover tc speed-limit state (HTB qdiscs,
// filters, the ifb0 redirect device) from an existing AWG container. The
// speed-limit removal (74b34d9) deleted the control plane without clearing
// remote data-plane state, so deployments installed by the old code kept
// enforcing invisible limits with no UI/API left to clear them (PR #231
// re-review, Fix 2). Idempotent by construction: every command is a delete
// guarded by `|| true`, so re-running on a clean container is a no-op.
// Errors are logged and never propagated — this must not disturb the caller.
func (m *AWGManager) CleanupLegacyTcRules(ctx context.Context, client ssh.SSHClient, containerName string) {
	if !IsValidContainerName(containerName) {
		slog.Warn("legacy tc cleanup: skipping invalid container name", "container", containerName)
		return
	}
	for _, cmd := range legacyTcCleanupCommands(containerName) {
		if _, errOut, code, err := client.RunSudoCommand(ctx, cmd); err != nil || code != 0 {
			slog.Warn("legacy tc cleanup: command failed (best-effort, continuing)",
				"command", cmd, "exit_code", code, "stderr", errOut, "error", err)
		}
	}
}

// checkUDPPortAvailable verifies that the requested UDP port is not already
// bound on the remote host before the AWG install pulls or builds anything.
// It checks two sources: host listening UDP sockets (`ss -lun`) and existing
// docker port bindings (`docker ps --format '{{.Ports}}'`), because a port
// published by another container does not appear in host `ss` output when the
// panel itself runs inside a container (Issue #225, Server 1). A failed
// probe command is not fatal — the install proceeds and any real conflict
// still surfaces from `docker run` as before.
func checkUDPPortAvailable(ctx context.Context, client ssh.SSHClient, port string) error {
	const conflictErr = "UDP port %s is already in use on the server — choose a different port for the AWG backend"

	ssOut, _, _, err := client.RunSudoCommand(ctx, "ss -lun 2>/dev/null || true")
	if err != nil {
		slog.Warn("preflight: failed to list listening UDP sockets", "error", err)
	} else if udpPortBound(ssOut, port) {
		return fmt.Errorf(conflictErr, port)
	}

	portsOut, _, _, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter publish=%s/udp --format '{{.Ports}}' 2>/dev/null || true", ssh.EscapeShellArg(port)))
	if err != nil {
		slog.Warn("preflight: failed to list docker port bindings", "error", err)
	} else if strings.TrimSpace(portsOut) != "" {
		// Non-empty output: some container already publishes this host
		// port (the publish filter matches the HOST side, regardless of
		// the container-side port, and covers ranges).
		return fmt.Errorf(conflictErr, port)
	}

	return nil
}

// udpPortBound reports whether ss(8) output shows a UDP socket whose local
// port equals port. Matching is token-based: strings.Fields yields the local
// endpoint as a single `addr:port` token (e.g. `0.0.0.0:51820` or `[::]:53`),
// and the suffix `:<port>` is matched against the whole token to avoid prefix
// false positives such as `:5182` matching a bound `:51820`.
func udpPortBound(ssOut, port string) bool {
	for _, line := range strings.Split(ssOut, "\n") {
		for _, field := range strings.Fields(line) {
			if strings.HasSuffix(field, ":"+port) {
				return true
			}
		}
	}
	return false
}

func (m *AWGManager) initializeServerKeysAndConfig(ctx context.Context, client ssh.SSHClient, port string, awgParams *AWGParams) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		cName = "amnezia-awg2"
	}

	serverPrivKey, serverPubKey, err := GenerateWGKeypair()
	if err != nil {
		return fmt.Errorf("failed to generate server keypair: %w", err)
	}
	serverPSK, err := GeneratePSK()
	if err != nil {
		return fmt.Errorf("failed to generate server psk: %w", err)
	}

	keygenScript := fmt.Sprintf(`
mkdir -p /opt/amnezia/awg
echo "%s" > /opt/amnezia/awg/wireguard_server_private_key.key
echo "%s" > /opt/amnezia/awg/wireguard_server_public_key.key
echo "%s" > /opt/amnezia/awg/wireguard_psk.key
`, serverPrivKey, serverPubKey, serverPSK)
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s bash -c %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(keygenScript)))

	serverConfig := RenderServerConfig(serverPrivKey, AWGDefaults["subnet_ip"], AWGDefaults["subnet_cidr"], port, awgParams.MTU, awgParams, nil)
	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_awg0.conf", []byte(serverConfig), 0600); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker cp '/tmp/_amnz_awg0.conf' %s:'/opt/amnezia/awg/awg0.conf'", ssh.EscapeShellArg(cName)))
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_awg0.conf")

	startScript := `#!/bin/bash
ip -4 rule del not fwmark 51820 table 51820 2>/dev/null || true
ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true
ip -4 route flush table 51820 2>/dev/null || true
awg-quick down /opt/amnezia/awg/awg0.conf 2>/dev/null || true
if [ -f /opt/amnezia/awg/awg0.conf ]; then awg-quick up /opt/amnezia/awg/awg0.conf; fi
ip -4 rule del not fwmark 51820 table 51820 2>/dev/null || true
ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true
ip -4 route flush table 51820 2>/dev/null || true
ip route replace 10.100.0.0/16 dev awg0 2>/dev/null || ip route add 10.100.0.0/16 dev awg0 2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=2 2>/dev/null || true
sysctl -w net.ipv4.conf.awg0.rp_filter=2 2>/dev/null || true
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT
iptables -C FORWARD -s 10.100.0.0/16 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.100.0.0/16 -j ACCEPT
iptables -C FORWARD -d 10.100.0.0/16 -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.100.0.0/16 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.100.0.0/16 -o eth1 -j MASQUERADE 2>/dev/null || true
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.100.0.0/16 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.100.0.0/16 -j MASQUERADE
tail -f /dev/null
`

	if err := client.UploadSudoFile(ctx, "/tmp/_amnz_start.sh", []byte(startScript), 0755); err != nil {
		return err
	}
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker cp '/tmp/_amnz_start.sh' %s:'/opt/amnezia/start.sh'", ssh.EscapeShellArg(cName)))
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker exec %s chmod +x /opt/amnezia/start.sh", ssh.EscapeShellArg(cName)))
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -f /tmp/_amnz_start.sh")
	_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker restart %s", ssh.EscapeShellArg(cName)))

	firewallScript := `
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
`
	_, _, _, _ = client.RunSudoScript(ctx, firewallScript)
	return nil
}

func initializeServerKeysAndConfig(ctx context.Context, client ssh.SSHClient, port string, awgParams *AWGParams) error {
	return (&AWGManager{}).initializeServerKeysAndConfig(ctx, client, port, awgParams)
}

// Install deploys Docker (if missing), builds the AWG container, configures parameters, and starts the service.
func (m *AWGManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	port := AWGDefaults["port"]
	if p, ok := params["port"]; ok && fmt.Sprint(p) != "" {
		port = fmt.Sprint(p)
	}

	profile := "standard"
	if p, ok := params["awg_profile"]; ok && fmt.Sprint(p) != "" {
		profile = fmt.Sprint(p)
	}

	// AWG 3.1 header protection defaults to ON: new installs get 3.x semantics
	// unless explicitly disabled (compat mode for 2.0 backends).
	hpOn := true
	if v, ok := parseBoolParam(params["awg_header_protection"]); ok {
		hpOn = v
	}
	awgParams, err := GenerateAWGParams(profile, hpOn)
	if err != nil {
		return fmt.Errorf("failed to generate AWG params: %w", err)
	}
	awgParams.Port = port

	if (profile == "standard" || profile == "pro") && params != nil {
		cpsProto := "quic"
		if cp, ok := params["awg_cps_protocol"]; ok && fmt.Sprint(cp) != "" {
			cpsProto = fmt.Sprint(cp)
		}
		if d, err := cps.SelectMimicryDomain(ctx, client, cpsProto); err == nil && d != "" {
			if cpsPackets, err := cps.GenerateCPSPackets(profile, d); err == nil {
				awgParams.I1 = cpsPackets["i1"]
				awgParams.I2 = cpsPackets["i2"]
				awgParams.I3 = cpsPackets["i3"]
				awgParams.I4 = cpsPackets["i4"]
				awgParams.I5 = cpsPackets["i5"]
			}
		}
	}

	if err := ensureDockerInstalled(ctx, client); err != nil {
		return err
	}
	if err := prepareHostAndContainers(ctx, client); err != nil {
		return err
	}
	if err := m.buildAndRunAWGContainer(ctx, client, port); err != nil {
		return err
	}
	return m.initializeServerKeysAndConfig(ctx, client, port, awgParams)
}

// Uninstall stops and removes all AWG containers and clean up directories.
func (m *AWGManager) Uninstall(ctx context.Context, server *models.Server) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.invalidateContainerCache(server)

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker stop %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rm -fv %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("docker rmi %s 2>/dev/null || true", ssh.EscapeShellArg(name)))
	}
	_, _, _, _ = client.RunSudoCommand(ctx, "rm -rf /opt/amnezia/amnezia-awg /opt/amnezia/amnezia-awg2 /opt/amnezia/awg")
	return nil
}

func runDockerCmdWithRetry(ctx context.Context, client ssh.SSHClient, cmd string) (string, int, error) {
	const maxRetries = 2
	var (
		out  string
		code int
		err  error
	)
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", code, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
		out, _, code, err = client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 {
			return out, code, nil
		}
	}
	return out, code, err
}

func (m *AWGManager) discoverContainerName(ctx context.Context, client ssh.SSHClient) (string, bool) {
	if client == nil {
		return "", false
	}
	if cached, ok := m.getCachedContainerForClient(client); ok && IsValidContainerName(cached) {
		return cached, true
	}

	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		out, code, err := runDockerCmdWithRetry(ctx, client, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(name)))
		if err == nil && code == 0 {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == name {
					m.setCachedContainerForClient(client, name)
					return name, true
				}
			}
		}
	}
	// Fallback to any running container with name starting with amnezia-awg
	out, code, err := runDockerCmdWithRetry(ctx, client, "docker ps --filter name=amnezia-awg --format '{{.Names}}'")
	if err == nil && code == 0 {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "amnezia-awg") && IsValidContainerName(trimmed) {
				m.setCachedContainerForClient(client, trimmed)
				return trimmed, true
			}
		}
	}
	return "", false
}

func (m *AWGManager) resolveContainerName(ctx context.Context, client ssh.SSHClient) string {
	if client != nil {
		if found, ok := m.discoverContainerName(ctx, client); ok {
			return found
		}
	}
	safeDefault := m.containerName()
	if !IsValidContainerName(safeDefault) {
		safeDefault = "amnezia-awg2"
	}
	return safeDefault
}

// ResolveContainerName returns the discovered or default container name for the given client.
func (m *AWGManager) ResolveContainerName(ctx context.Context, client ssh.SSHClient) string {
	return m.resolveContainerName(ctx, client)
}

// ensureBackendRoutingAndNAT installs the return route for the portal client subnet,
// interface-scoped and subnet-scoped NAT masquerade rules, FORWARD rules, and loose
// reverse path filtering inside the backend's AWG container. Portal data-plane traffic
// arrives on awg0 with source IPs from the portal IPAM subnet (e.g. 10.100.0.0/16);
// without the return route, reply traffic is routed out eth0 default gateway and Martian
// packet filtering on awg0 drops incoming traffic.
func (m *AWGManager) ensureBackendRoutingAndNAT(ctx context.Context, client ssh.SSHClient, subnet string) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		return fmt.Errorf("cannot ensure backend routing and NAT: invalid container name %q", cName)
	}

	subnet = strings.TrimSpace(subnet)
	if subnet == "" {
		subnet = "10.100.0.0/16"
	}
	if _, _, err := net.ParseCIDR(subnet); err != nil {
		return fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
	}

	rules := []string{
		"ip -4 rule del not fwmark 51820 table 51820 2>/dev/null || true",
		"ip -4 rule del table main suppress_prefixlength 0 2>/dev/null || true",
		"ip -4 route flush table 51820 2>/dev/null || true",
		fmt.Sprintf("ip route replace %s dev awg0 2>/dev/null || ip route add %s dev awg0 2>/dev/null || true", subnet, subnet),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s %s -o eth0 -j MASQUERADE", subnet, subnet),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s %s -o eth1 -j MASQUERADE 2>/dev/null || true", subnet, subnet),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s %s -j MASQUERADE", subnet, subnet),
		"iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
		"iptables -t nat -C POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || true",
		fmt.Sprintf("iptables -C FORWARD -s %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -s %s -j ACCEPT", subnet, subnet),
		fmt.Sprintf("iptables -C FORWARD -d %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -d %s -j ACCEPT", subnet, subnet),
		"iptables -C FORWARD -i awg0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -o eth0 -j ACCEPT",
		"iptables -C FORWARD -i awg0 -o eth1 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i awg0 -o eth1 -j ACCEPT 2>/dev/null || true",
		"iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		"(sysctl -w net.ipv4.conf.all.rp_filter=2 2>/dev/null || true) && (sysctl -w net.ipv4.conf.awg0.rp_filter=2 2>/dev/null || true)",
	}

	var groupedRules []string
	for _, rule := range rules {
		groupedRules = append(groupedRules, fmt.Sprintf("( %s )", rule))
	}
	compoundCmd := fmt.Sprintf("docker exec %s bash -c %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(strings.Join(groupedRules, " && ")))
	out, errOut, code, err := client.RunSudoCommand(ctx, compoundCmd)
	if err != nil {
		// #nosec G706 -- Internal log for container routing/NAT rule application failure
		log.Printf("[awg/nat] failed to apply backend routing/NAT rule in container %s: %v", cName, err)
		return fmt.Errorf("failed to apply backend routing/NAT rule in container %s: %w", cName, err)
	}
	if code != 0 {
		errMsg := strings.TrimSpace(errOut)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out)
		}
		// #nosec G706 -- Internal log for container routing/NAT rule application failure
		log.Printf("[awg/nat] failed to apply backend routing/NAT rule in container %s (code %d): %s", cName, code, errMsg)
		return fmt.Errorf("failed to apply backend routing/NAT rule in container %s (code %d): %s", cName, code, errMsg)
	}

	// Host-level defense-in-depth:
	bridgeDev := "amn0"
	if out, _, code, err := client.RunSudoCommand(ctx, "ip link show amn0 2>/dev/null || ip link show docker0 2>/dev/null || true"); err == nil && code == 0 {
		if strings.Contains(out, "docker0") && !strings.Contains(out, "amn0") {
			bridgeDev = "docker0"
		}
	}
	hostRule := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s ! -o %s -j MASQUERADE 2>/dev/null || true", ssh.EscapeShellArg(subnet), ssh.EscapeShellArg(bridgeDev), ssh.EscapeShellArg(subnet), ssh.EscapeShellArg(bridgeDev))
	_, errOut, code, err = client.RunSudoCommand(ctx, hostRule)
	if err != nil {
		return fmt.Errorf("failed to apply host-level NAT defense rule: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("failed to apply host-level NAT defense rule (code %d): %s", code, errOut)
	}

	hostMangleRule := "iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true"
	_, _, _, _ = client.RunSudoCommand(ctx, hostMangleRule)

	return nil
}

// EnsureBackendRoutingAndNAT resolves the server's SSH client and applies return routes,
// NAT masquerade, and reverse path filtering for the portal subnet inside the container.
func (m *AWGManager) EnsureBackendRoutingAndNAT(ctx context.Context, server *models.Server, subnet string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return fmt.Errorf("failed to get SSH client for server %d: %w", server.ID, err)
	}
	return m.ensureBackendRoutingAndNAT(ctx, client, subnet)
}

// ensureBackendNATRule is a backward-compatible wrapper calling ensureBackendRoutingAndNAT with default subnet.
func (m *AWGManager) ensureBackendNATRule(ctx context.Context, client ssh.SSHClient) error {
	return m.ensureBackendRoutingAndNAT(ctx, client, "")
}

func (m *AWGManager) getServerConfig(ctx context.Context, client ssh.SSHClient, containerNames ...string) (string, error) {
	names := containerNames
	if len(names) == 0 || (len(names) == 1 && names[0] == "") {
		resolved := m.resolveContainerName(ctx, client)
		if !IsValidContainerName(resolved) {
			resolved = m.containerName()
		}
		names = []string{resolved}
		for _, name := range AWGContainerNames {
			if name != resolved && IsValidContainerName(name) {
				names = append(names, name)
			}
		}
	}
	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat %s 2>/dev/null || docker exec -i %s cat '/etc/amnezia/amneziawg/awg0.conf' 2>/dev/null", ssh.EscapeShellArg(name), ssh.EscapeShellArg(m.configPath()), ssh.EscapeShellArg(name))
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return out, nil
		}
	}
	return "", fmt.Errorf("failed to get server config from containers: %v", names)
}

func (m *AWGManager) resolveContainerConfigPath(ctx context.Context, client ssh.SSHClient, containerName string) string {
	candidates := []string{m.configPath(), "/etc/amnezia/amneziawg/awg0.conf"}
	for _, p := range candidates {
		cmd := fmt.Sprintf("docker exec -i %s test -f %s", ssh.EscapeShellArg(containerName), ssh.EscapeShellArg(p))
		_, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 {
			return p
		}
	}
	cmd := fmt.Sprintf("docker exec -i %s test -d '/etc/amnezia/amneziawg'", ssh.EscapeShellArg(containerName))
	if _, _, code, err := client.RunSudoCommand(ctx, cmd); err == nil && code == 0 {
		return "/etc/amnezia/amneziawg/awg0.conf"
	}
	return m.configPath()
}

func (m *AWGManager) saveServerConfig(ctx context.Context, client ssh.SSHClient, content string) error {
	_, err := m.saveServerConfigTracked(ctx, client, content)
	return err
}

func (m *AWGManager) saveServerConfigTracked(ctx context.Context, client ssh.SSHClient, content string) (bool, error) {
	params, _, err := ParseServerConfig(content)
	if err != nil {
		return false, fmt.Errorf("invalid server config: %w", err)
	}
	if len(params) > 0 {
		if err := ValidateAWGParams(params); err != nil {
			return false, fmt.Errorf("invalid AWG parameters: %w", err)
		}
	}

	content = EnsureInterfaceTableOff(content)
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return false, errors.New("invalid container name")
	}
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	tmpPath := fmt.Sprintf("/tmp/_amnz_edit_config_%d_%x.conf", time.Now().UnixNano(), randBytes)
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(content), 0600); err != nil {
		return false, err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", ssh.EscapeShellArg(tmpPath)))
	}()

	cfgPath := m.resolveContainerConfigPath(ctx, client, cName)
	cpCmd := fmt.Sprintf("docker cp %s %s:%s", ssh.EscapeShellArg(tmpPath), ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cfgPath))
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return false, fmt.Errorf("failed to copy config into container (code %d): %s, %w", code, errOut, err)
	}

	// Disk write succeeded
	diskWritten := true

	if err := m.syncInterfaceConfig(ctx, client, cName, cfgPath); err != nil {
		return diskWritten, err
	}
	return diskWritten, nil
}

func (m *AWGManager) syncInterfaceConfig(ctx context.Context, client ssh.SSHClient, cName, cfgPath string) error {
	syncCmd := fmt.Sprintf("docker exec -i %s bash -c %s",
		ssh.EscapeShellArg(cName), ssh.EscapeShellArg(fmt.Sprintf("%s syncconf %s <(%s-quick strip %s)", m.wgBinary(), m.interfaceName(), m.wgBinary(), cfgPath)))
	out, errOut, code, err := client.RunSudoCommand(ctx, syncCmd)
	if err != nil || code != 0 {
		if restErr := m.restoreInterfaceIfDown(ctx, client, cName, cfgPath); restErr != nil {
			return restErr
		}
		out, errOut, code, err = client.RunSudoCommand(ctx, syncCmd)
	}
	if err != nil || code != 0 {
		errMsg := strings.TrimSpace(errOut)
		if errMsg == "" {
			errMsg = strings.TrimSpace(out)
		}
		if err != nil {
			return fmt.Errorf("failed to sync AmneziaWG config in container %s (exit code %d): %s: %w", cName, code, errMsg, err)
		}
		return fmt.Errorf("failed to sync AmneziaWG config in container %s (exit code %d): %s", cName, code, errMsg)
	}
	return nil
}

func (m *AWGManager) restoreInterfaceIfDown(ctx context.Context, client ssh.SSHClient, cName, cfgPath string) error {
	ipCmd := fmt.Sprintf("docker exec -i %s ip link show %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.interfaceName()))
	ipOut, _, ipCode, ipErr := client.RunSudoCommand(ctx, ipCmd)
	isUp := ipErr == nil && ipCode == 0 && (strings.Contains(ipOut, "<UP") || strings.Contains(ipOut, ",UP") || strings.Contains(ipOut, "state UP"))
	if isUp {
		return nil
	}

	upCmd := fmt.Sprintf("docker exec -i %s awg-quick up %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(cfgPath))
	upOut, upErrOut, upCode, upErr := client.RunSudoCommand(ctx, upCmd)
	if upErr != nil || upCode != 0 {
		upErrMsg := strings.TrimSpace(upErrOut)
		if upErrMsg == "" {
			upErrMsg = strings.TrimSpace(upOut)
		} else if strings.TrimSpace(upOut) != "" {
			upErrMsg = upErrMsg + ": " + strings.TrimSpace(upOut)
		}
		if upErr != nil {
			return fmt.Errorf("failed to bring up AmneziaWG interface %s with awg-quick up in container %s (exit code %d): %s: %w",
				m.interfaceName(), cName, upCode, upErrMsg, upErr)
		}
		return fmt.Errorf("failed to bring up AmneziaWG interface %s with awg-quick up in container %s (exit code %d): %s",
			m.interfaceName(), cName, upCode, upErrMsg)
	}
	return nil
}

func (m *AWGManager) getClientsTable(ctx context.Context, client ssh.SSHClient) ([]AWGClient, error) {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return []AWGClient{}, errors.New("invalid container name")
	}
	out, errOut, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s cat %s", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.clientsTablePath())))
	if err != nil {
		return []AWGClient{}, fmt.Errorf("failed to read clientsTable: %w", err)
	}
	if code != 0 {
		if strings.Contains(errOut, "No such file") || strings.Contains(out, "No such file") {
			return []AWGClient{}, nil
		}
		return []AWGClient{}, fmt.Errorf("failed to read clientsTable (exit code %d): %s", code, strings.TrimSpace(errOut))
	}
	if strings.TrimSpace(out) == "" {
		return []AWGClient{}, nil
	}
	return ParseClientsTable(out)
}

func (m *AWGManager) saveClientsTable(ctx context.Context, client ssh.SSHClient, clients []AWGClient) error {
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	if !IsValidContainerName(cName) {
		return errors.New("invalid container name")
	}
	jsonData, err := SerializeClientsTable(clients)
	if err != nil {
		return err
	}

	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	tmpPath := fmt.Sprintf("/tmp/_amnz_clients_%d_%x.json", time.Now().UnixNano(), randBytes)
	if err := client.UploadSudoFile(ctx, tmpPath, []byte(jsonData), 0600); err != nil {
		return err
	}
	defer func() {
		_, _, _, _ = client.RunSudoCommand(ctx, fmt.Sprintf("rm -f %s", ssh.EscapeShellArg(tmpPath)))
	}()

	cpCmd := fmt.Sprintf("docker cp %s %s:%s", ssh.EscapeShellArg(tmpPath), ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.clientsTablePath()))
	if _, errOut, code, err := client.RunSudoCommand(ctx, cpCmd); err != nil || code != 0 {
		return fmt.Errorf("failed to copy clientsTable into container (code %d): %s, %w", code, errOut, err)
	}
	return nil
}

// GetClients returns all registered clients from clientsTable enriched with live transfer data.
func (m *AWGManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}

	// Live transfer stats via awg show all
	cName := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	showOut, _, _, _ := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s %s show all 2>/dev/null", ssh.EscapeShellArg(cName), ssh.EscapeShellArg(m.wgBinary())))
	showStats := parseWGShow(showOut)

	var result []map[string]any
	knownIDs := make(map[string]bool)

	for _, c := range clients {
		knownIDs[c.ClientID] = true
		ud := c.UserData

		if stat, ok := showStats[c.ClientID]; ok {
			ud.LatestHandshake = stat.LatestHandshake
			ud.DataReceived = stat.DataReceived
			ud.DataSent = stat.DataSent
			ud.DataReceivedBytes = stat.DataReceivedBytes
			ud.DataSentBytes = stat.DataSentBytes
			if stat.AllowedIPs != "" {
				ud.AllowedIPs = stat.AllowedIPs
			}
		}

		udMap := map[string]any{
			"clientName":        ud.ClientName,
			"creationDate":      ud.CreationDate,
			"clientPrivateKey":  ud.ClientPrivateKey,
			"clientIp":          ud.ClientIP,
			"psk":               ud.PSK,
			"enabled":           ud.Enabled,
			"awg_mimicry":       ud.AWGMimicry,
			"latestHandshake":   ud.LatestHandshake,
			"dataReceived":      ud.DataReceived,
			"dataSent":          ud.DataSent,
			"dataReceivedBytes": ud.DataReceivedBytes,
			"dataSentBytes":     ud.DataSentBytes,
			"allowedIps":        ud.AllowedIPs,
			"externalClient":    ud.ExternalClient,
			"rotated_at":        ud.RotatedAt,
		}

		result = append(result, map[string]any{
			"clientId": c.ClientID,
			"userData": udMap,
		})
	}

	// Pick up external peers in awg0.conf not in clientsTable
	if confText, err := m.getServerConfig(ctx, client); err == nil {
		_, peers, _ := ParseServerConfig(confText)
		for _, p := range peers {
			if !knownIDs[p.PublicKey] {
				stat := showStats[p.PublicKey]
				result = append(result, map[string]any{
					"clientId": p.PublicKey,
					"userData": map[string]any{
						"clientName":        fmt.Sprintf("External (%s)", p.AllowedIPs),
						"clientPrivateKey":  "",
						"externalClient":    true,
						"allowedIps":        p.AllowedIPs,
						"latestHandshake":   stat.LatestHandshake,
						"dataReceived":      stat.DataReceived,
						"dataSent":          stat.DataSent,
						"dataReceivedBytes": stat.DataReceivedBytes,
						"dataSentBytes":     stat.DataSentBytes,
					},
				})
			}
		}
	}

	return result, nil
}

type wgShowPeerStat struct {
	LatestHandshake   string
	DataReceived      string
	DataSent          string
	DataReceivedBytes int64
	DataSentBytes     int64
	AllowedIPs        string
}

func parseWGShow(out string) map[string]wgShowPeerStat {
	stats := make(map[string]wgShowPeerStat)
	var currentPeer string
	var currentStat wgShowPeerStat

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "peer:") {
			if currentPeer != "" {
				stats[currentPeer] = currentStat
			}
			currentPeer = strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
			currentStat = wgShowPeerStat{}
		} else if currentPeer != "" && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			switch k {
			case "latest handshake":
				currentStat.LatestHandshake = v
			case "transfer":
				tfParts := strings.Split(v, ",")
				if len(tfParts) == 2 {
					rx := strings.TrimSpace(strings.TrimSuffix(tfParts[0], "received"))
					tx := strings.TrimSpace(strings.TrimSuffix(tfParts[1], "sent"))
					currentStat.DataReceived = rx
					currentStat.DataSent = tx
					currentStat.DataReceivedBytes = parseSizeHuman(rx)
					currentStat.DataSentBytes = parseSizeHuman(tx)
				}
			case "allowed ips":
				currentStat.AllowedIPs = v
			}
		}
	}
	if currentPeer != "" {
		stats[currentPeer] = currentStat
	}
	return stats
}

func parseSizeHuman(s string) int64 {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	mult := int64(1)
	switch strings.ToLower(parts[1]) {
	case "kib", "kb":
		mult = 1024
	case "mib", "mb":
		mult = 1024 * 1024
	case "gib", "gb":
		mult = 1024 * 1024 * 1024
	case "tib", "tb":
		mult = 1024 * 1024 * 1024 * 1024
	}
	return int64(val * float64(mult))
}

func resolveClientName(clientParams map[string]any) string {
	if n, ok := clientParams["name"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	if n, ok := clientParams["clientName"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	if n, ok := clientParams["client_name"]; ok && fmt.Sprint(n) != "" {
		return fmt.Sprint(n)
	}
	return "client"
}

// probePeerPubKey extracts a valid caller-supplied WireGuard public key from
// clientParams (checked keys: "public_key", then "client_public_key").
// A valid key is base64 that decodes to exactly 32 bytes. Returns "" when
// absent or invalid, in which case AddClient generates a keypair as usual.
func probePeerPubKey(clientParams map[string]any) string {
	for _, k := range []string{"public_key", "client_public_key"} {
		v, ok := clientParams[k]
		if !ok || v == nil {
			continue
		}
		s, isStr := v.(string)
		if !isStr || s == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(decoded) != 32 {
			continue
		}
		return s
	}
	return ""
}

// upsertPeerInConfig replaces the [Peer] section whose PublicKey matches
// peerSection's PublicKey, or appends the section when no such peer exists.
// [Peer] blocks whose PublicKey is listed in removePubKeys are dropped (stale
// identity that was re-keyed under the same client name). Duplicate blocks for
// the same PublicKey are collapsed. Non-peer content is preserved as-is.
func upsertPeerInConfig(confText, peerSection string, removePubKeys ...string) (string, error) {
	confText = EnsureInterfaceTableOff(confText)
	peerLines := strings.Split(strings.TrimSpace(peerSection), "\n")
	newPub := ""
	for _, line := range peerLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PublicKey = ") {
			newPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
			break
		}
	}
	if newPub == "" {
		return "", errors.New("peer section is missing a PublicKey line")
	}

	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var out []string
	replaced := false
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			out = append(out, lines[i])
			continue
		}
		// Collect the whole [Peer] block (up to the next section header).
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		blockPub := ""
		for _, bl := range block {
			trimmed := strings.TrimSpace(bl)
			if strings.HasPrefix(trimmed, "PublicKey = ") {
				blockPub = strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = "))
				break
			}
		}
		stale := false
		for _, rk := range removePubKeys {
			if rk != "" && rk != newPub && rk == blockPub {
				stale = true
				break
			}
		}
		switch {
		case stale:
			// Drop the stale block entirely.
		case blockPub == newPub:
			if !replaced {
				out = append(out, peerLines...)
				replaced = true
			}
			// Duplicate legacy block for the same key: drop it.
		default:
			out = append(out, block...)
		}
		i = j - 1
	}
	if !replaced {
		// Blank separator line before the appended peer, mirroring the
		// formatting awg-quick conf files get from the portal.
		withSep := append([]string{""}, peerLines...)
		out = append(out, withSep...)
	}
	return strings.Join(out, "\n") + "\n", nil
}

// findExistingClient locates an existing clientsTable entry matching the peer
// identity: by client ID (public key) first, then by client name. Returns the
// entry index and its current client ID.
func findExistingClient(clients []AWGClient, clientPubKey, clientName string) (int, string) {
	for i := range clients {
		if clients[i].ClientID == clientPubKey || clients[i].UserData.ClientName == clientName {
			return i, clients[i].ClientID
		}
	}
	return -1, ""
}

// peerSectionFor renders the [Peer] section to append to the server config.
// Probe peers carry no PresharedKey line: the prober probes with psk="", so
// both sides must derive IKpsk2 keys with a zero PSK.
func peerSectionFor(isProbePeer bool, clientPubKey, psk, clientIP, allowedIPs string) string {
	if isProbePeer {
		if allowedIPs == "" {
			allowedIPs = clientIP + "/32"
		}
		return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", clientPubKey, allowedIPs)
	}
	return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientPubKey, psk, clientIP)
}

// upsertClientEntry updates the clientsTable entry at existingIdx in place
// (keeping IP and identity fields), or appends a new entry when idx < 0.
func upsertClientEntry(clients []AWGClient, existingIdx int, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry string, contentPadding bool) []AWGClient {
	if existingIdx >= 0 {
		clients[existingIdx].ClientID = clientPubKey
		clients[existingIdx].UserData.ClientName = clientName
		clients[existingIdx].UserData.ClientPrivateKey = clientPrivKey
		clients[existingIdx].UserData.PSK = psk
		clients[existingIdx].UserData.Enabled = true
		clients[existingIdx].UserData.ClientIP = clientIP

		ud := &clients[existingIdx].UserData
		if ud.RekeyAfterTime == nil {
			ud.RekeyAfterTime = GenerateRekeyAfterTime()
		}
		if ud.RekeyTimeout == nil {
			ud.RekeyTimeout = GenerateRekeyTimeout()
		}
		if ud.RejectAfterTime == nil {
			ud.RejectAfterTime = GenerateRejectAfterTime()
		}
		if ud.KeepaliveTimeout == nil {
			ud.KeepaliveTimeout = GenerateKeepaliveTimeout()
		}
		if ud.MaxHandshakeAttempts == nil {
			ud.MaxHandshakeAttempts = GenerateMaxHandshakeAttempts()
		}
		if ud.PersistentKeepalive == nil {
			ud.PersistentKeepalive = GeneratePersistentKeepalive()
		}
		EnforceTimingOrdering(ud.RekeyTimeout, ud.RekeyAfterTime, ud.RejectAfterTime)

		if contentPadding && clients[existingIdx].UserData.ContentPaddingAddition == nil {
			val := "16-64"
			clients[existingIdx].UserData.ContentPaddingAddition = &val
		}

		return clients
	}

	rat, rt, rej, kt, mha, pk := GenerateClientTimingParams()
	var cpAdd *string
	if contentPadding {
		val := "16-64"
		cpAdd = &val
	}

	return append(clients, AWGClient{
		ClientID: clientPubKey,
		UserData: AWGClientUserData{
			ClientName:             clientName,
			ClientPrivateKey:       clientPrivKey,
			ClientIP:               clientIP,
			PSK:                    psk,
			Enabled:                true,
			AWGMimicry:             mimicry,
			RekeyAfterTime:         rat,
			RekeyTimeout:           rt,
			RejectAfterTime:        rej,
			KeepaliveTimeout:       kt,
			MaxHandshakeAttempts:   mha,
			PersistentKeepalive:    pk,
			ContentPaddingAddition: cpAdd,
		},
	})
}

// AddClient provisions a new client/peer in the AWG configuration.
//
// If clientParams carries a valid caller-supplied public key ("public_key" or
// "client_public_key"), that key is registered as the peer identity and no
// keypair is generated (probe peers: the prober signs with the key the portal
// already holds, so no client private key is stored or returned). Probe peers
// are registered WITHOUT a PresharedKey because the prober derives Noise keys
// with an empty PSK; a registered PSK would break the IKpsk2 key derivation.
// Registration is idempotent: an existing clientsTable entry for the same
// identity (by client ID or client name) is updated in place, keeping its IP,
// instead of appending a duplicate [Peer], which amneziawg rejects.
func (m *AWGManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (res map[string]any, err error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockRemote()

	clientName := resolveClientName(clientParams)

	// Name-based probe detection (R2): a legacy "Health Probe" entry may exist
	// with a server PSK from the old name-only registration path. Treat the
	// name as probe identity so the upsert drops the PresharedKey line and
	// forces psk="" — keeping the peer on the PSK-less identity both probers use.
	clientNameIsProbe := strings.EqualFold(strings.TrimSpace(clientName), "Health Probe")

	clientPubKey := probePeerPubKey(clientParams)
	isProbePeer := clientPubKey != "" || clientNameIsProbe
	clientPrivKey, clientPubKey, err := resolveClientKeys(clientParams)
	if err != nil {
		return nil, err
	}

	// Read server config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return nil, err
	}

	usedIPs := GetUsedIPsFromConfig(confText)
	serverParams, remotePeers, _ := ParseServerConfig(confText)
	serverPubKey, err := m.getServerPublicKeyRequired(ctx, server)
	if err != nil {
		return nil, err
	}

	initialConfText := confText

	// Idempotency: reuse the existing entry (and its IP) when this identity is
	// already registered instead of appending a duplicate peer.
	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}
	initialClients := append([]AWGClient(nil), clients...)
	existingIdx, existingPubKey := findExistingClient(clients, clientPubKey, clientName)

	effectiveClientID := resolveEffectiveClientID(clientParams, clientPubKey)

	clientIP, newlyAllocated, rekeyed, previousOwner, rekeyedIP, err := m.obtainClientIP(
		ctx, serverID, clientParams, clients, existingIdx, clientPubKey, usedIPs, serverParams, remotePeers,
	)
	if err != nil {
		return nil, err
	}

	diskWritten := false
	remoteCommitted := false
	defer func() {
		if err != nil {
			m.rollbackAddClient(ctx, client, serverID, effectiveClientID, clientPubKey, clientIP, previousOwner, rekeyedIP, initialConfText, initialClients, rekeyed, newlyAllocated, diskWritten, remoteCommitted)
		}
	}()

	// Normal clients get the server's PresharedKey (read fresh each call, as
	// before). Probe peers force psk="": the prober derives IKpsk2 keys with an
	// empty PSK, so the peer must be registered without one (R2).
	var psk string
	if !isProbePeer {
		psk, _ = m.GetServerPSK(ctx, server)
	}

	allowedIPs := resolveAllowedIPs(clientParams)
	peerSection := peerSectionFor(isProbePeer, clientPubKey, psk, clientIP, allowedIPs)

	if diskWritten, err = m.commitPeerConfigWithCAS(ctx, client, confText, peerSection, clientPubKey, clientName, existingPubKey); err != nil {
		return nil, err
	}
	remoteCommitted = true

	mimicry := resolveMimicry(clientParams)
	cpOn, _ := parseBoolParam(clientParams["awg_content_padding"])

	// Fresh read-and-upsert for clientsTable to avoid lost updates
	clients, err = m.getClientsTable(ctx, client)
	if err != nil {
		return nil, err
	}
	existingIdx, _ = findExistingClient(clients, clientPubKey, clientName)
	clients = upsertClientEntry(clients, existingIdx, clientPubKey, clientName, clientPrivKey, psk, clientIP, mimicry, cpOn)
	if err = m.saveClientsTable(ctx, client, clients); err != nil {
		return nil, fmt.Errorf("failed to save clients table: %w", err)
	}

	if isProbePeer {
		// Probe peers need no client config, connection kit, or TC limits:
		// nothing consumes a private key that does not exist. Probe peers only
		// terminate keepalive probes on awg0 and never route or masquerade
		// client traffic, so ensureBackendNATRule is skipped.
		return map[string]any{
			"client_id":   clientPubKey,
			"client_name": clientName,
			"client_ip":   clientIP,
		}, nil
	}

	// Live remediation (issues #27, #36): ensure the return route, NAT masquerade,
	// and FORWARD rules exist so portal data-plane traffic (non-local source
	// subnets like 10.100.0.0/16) is forwarded and masqueraded. This covers
	// backends provisioned with the old subnet-scoped start.sh without
	// restarting or re-creating the container. Fail loudly: without the rules,
	// all load-balanced client traffic is dropped upstream.
	if err = m.ensureBackendNATRule(ctx, client); err != nil {
		err = fmt.Errorf("failed to ensure backend NAT rules: %w", err)
		return nil, err
	}

	// Render client config
	clientConfig := m.buildClientConfig(ctx, client, server, serverParams, clientPrivKey, clientIP, serverPubKey, psk, mimicry, clientPubKey, clients)

	return map[string]any{
		"client_id":   clientPubKey,
		"client_name": clientName,
		"client_ip":   clientIP,
		"config":      clientConfig,
		"awg_mimicry": mimicry,
	}, nil
}

func (m *AWGManager) commitPeerConfigWithCAS(
	ctx context.Context,
	client ssh.SSHClient,
	initialConf, peerSection, clientPubKey, clientName, existingPubKey string,
) (bool, error) {
	confText := initialConf
	currExistingPubKey := existingPubKey

	for attempt := 0; attempt < 5; attempt++ {
		freshConf, err := m.getServerConfig(ctx, client)
		if err != nil {
			return false, fmt.Errorf("failed to fetch remote config for CAS check: %w", err)
		}
		if freshConf != confText {
			confText = freshConf
			clients, err := m.getClientsTable(ctx, client)
			if err != nil {
				return false, fmt.Errorf("failed to fetch clientsTable for CAS retry: %w", err)
			}
			_, currExistingPubKey = findExistingClient(clients, clientPubKey, clientName)
			continue
		}

		removePubKeys := peerRemovalKeys(currExistingPubKey, clientPubKey)
		newConfig, err := upsertPeerInConfig(confText, peerSection, removePubKeys...)
		if err != nil {
			return false, fmt.Errorf("failed to upsert peer in config: %w", err)
		}
		return m.saveServerConfigTracked(ctx, client, newConfig)
	}

	return false, errors.New("failed to commit remote config: CAS retry limit exceeded due to concurrent modifications")
}

func removePeerFromConfig(confText, pubKey, ip string) string {
	confText = EnsureInterfaceTableOff(confText)
	lines := strings.Split(strings.TrimRight(confText, "\n"), "\n")
	var out []string

	var targetIP net.IP
	if ip != "" {
		targetIP = net.ParseIP(strings.TrimSpace(ip))
	}

	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			out = append(out, lines[i])
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := lines[i:j]
		match := false

		if pubKey != "" {
			for _, bl := range block {
				trimmed := strings.TrimSpace(bl)
				if strings.HasPrefix(trimmed, "PublicKey = ") {
					if strings.TrimSpace(strings.TrimPrefix(trimmed, "PublicKey = ")) == pubKey {
						match = true
						break
					}
				}
			}
		} else if targetIP != nil {
			for _, bl := range block {
				trimmed := strings.TrimSpace(bl)
				if strings.HasPrefix(trimmed, "AllowedIPs = ") {
					rawIPs := strings.TrimSpace(strings.TrimPrefix(trimmed, "AllowedIPs = "))
					for _, part := range strings.Split(rawIPs, ",") {
						part = strings.TrimSpace(part)
						if part == "" {
							continue
						}
						parsedIP, _, err := net.ParseCIDR(part)
						if err != nil {
							parsedIP = net.ParseIP(part)
						}
						if parsedIP != nil && parsedIP.Equal(targetIP) {
							match = true
							break
						}
					}
					if match {
						break
					}
				}
			}
		}

		if !match {
			out = append(out, block...)
		}
		i = j - 1
	}
	return strings.Join(out, "\n") + "\n"
}

func (m *AWGManager) removePeerFromRemote(ctx context.Context, client ssh.SSHClient, pubKey, ip string) error {
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get server config for peer removal: %w", err)
	}

	newConfig := removePeerFromConfig(confText, pubKey, ip)
	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return fmt.Errorf("failed to save config during peer removal: %w", err)
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get clients table during peer removal: %w", err)
	}
	if len(clients) > 0 {
		var updated []AWGClient
		for _, c := range clients {
			if (pubKey != "" && c.ClientID == pubKey) || (ip != "" && c.UserData.ClientIP == ip) {
				continue
			}
			updated = append(updated, c)
		}
		if err := m.saveClientsTable(ctx, client, updated); err != nil {
			return fmt.Errorf("failed to save clients table during peer removal: %w", err)
		}
	}

	return nil
}

func (m *AWGManager) restorePreviousPeer(ctx context.Context, client ssh.SSHClient, initialConfText string, initialClients []AWGClient) (bool, error) {
	if err := m.saveServerConfig(ctx, client, initialConfText); err != nil {
		return false, fmt.Errorf("failed to restore initial server config: %w", err)
	}
	if err := m.saveClientsTable(ctx, client, initialClients); err != nil {
		return true, fmt.Errorf("failed to restore initial clients table: %w", err)
	}
	return true, nil
}

func (m *AWGManager) rollbackAddClient(
	ctx context.Context,
	client ssh.SSHClient,
	serverID int64,
	effectiveClientID, clientPubKey, clientIP, previousOwner, rekeyedIP, initialConfText string,
	initialClients []AWGClient,
	rekeyed, newlyAllocated, diskWritten, remoteCommitted bool,
) {
	if rekeyed && m.ipAllocator != nil {
		if !diskWritten {
			if transErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP); transErr != nil {
				slog.Error("failed to revert AWG client IP lease to previous owner during re-key rollback without disk write",
					"server_id", serverID,
					"previous_owner", previousOwner,
					"new_client_id", effectiveClientID,
					"ip", rekeyedIP,
					"error", transErr,
				)
			}
		} else {
			configRestored, restoreErr := m.restorePreviousPeer(ctx, client, initialConfText, initialClients)
			if !configRestored {
				slog.Error("failed to restore previous peer config on remote server during re-key rollback; retaining new key lease in DB to prevent zombie IP collision",
					"server_id", serverID,
					"previous_owner", previousOwner,
					"new_client_id", effectiveClientID,
					"ip", rekeyedIP,
					"error", restoreErr,
				)
			} else {
				if restoreErr != nil {
					slog.Warn("remote peer config restored to previous owner but clients table restore failed during re-key rollback",
						"server_id", serverID,
						"previous_owner", previousOwner,
						"new_client_id", effectiveClientID,
						"ip", rekeyedIP,
						"error", restoreErr,
					)
				}
				if relErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP); relErr != nil {
					slog.Error("failed to revert AWG client IP lease to previous owner after remote restore",
						"server_id", serverID,
						"previous_owner", previousOwner,
						"new_client_id", effectiveClientID,
						"ip", rekeyedIP,
						"error", relErr,
					)
				}
			}
		}
	}
	if newlyAllocated && !rekeyed {
		m.rollbackAllocatedPeer(ctx, client, serverID, effectiveClientID, clientPubKey, clientIP, diskWritten, remoteCommitted)
	}
}

func (m *AWGManager) rollbackAllocatedPeer(
	ctx context.Context,
	client ssh.SSHClient,
	serverID int64,
	effectiveClientID, clientPubKey, clientIP string,
	diskWritten, remoteCommitted bool,
) {
	if m.ipAllocator == nil {
		return
	}
	if !diskWritten && !remoteCommitted {
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, clientIP); relErr != nil {
			slog.Warn("failed to release AWG client IP", "server_id", serverID, "client_id", effectiveClientID, "ip", clientIP, "error", relErr)
		}
		return
	}

	// Either diskWritten or remoteCommitted is true:
	// A peer entry was written to remote disk (and possibly applied to the interface).
	// Rollback MUST attempt remote disk cleanup by removing the peer from the remote config on disk.
	if err := m.removePeerFromRemote(ctx, client, clientPubKey, clientIP); err != nil {
		slog.Error("failed to remove peer from remote server during rollback; retaining IP allocation to prevent zombie IP collision",
			"server_id", serverID,
			"client_id", effectiveClientID,
			"ip", clientIP,
			"error", err,
		)
		return
	}

	if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, clientIP); relErr != nil {
		slog.Warn("failed to release AWG client IP after remote removal", "server_id", serverID, "client_id", effectiveClientID, "ip", clientIP, "error", relErr)
	}
}

func parseServerSubnetParams(serverParams map[string]string) (string, int, string) {
	subnetAddr := AWGDefaults["subnet_address"]
	subnetCIDR, _ := strconv.Atoi(AWGDefaults["subnet_cidr"])
	gatewayIP := AWGDefaults["subnet_ip"]

	if serverParams == nil {
		return subnetAddr, subnetCIDR, gatewayIP
	}

	addrVal := ""
	if v, ok := serverParams["Address"]; ok && strings.TrimSpace(v) != "" {
		addrVal = strings.TrimSpace(v)
	} else if v, ok := serverParams["address"]; ok && strings.TrimSpace(v) != "" {
		addrVal = strings.TrimSpace(v)
	}

	if addrVal != "" {
		ip, ipNet, err := net.ParseCIDR(addrVal)
		if err == nil && ip != nil && ipNet != nil {
			if ip4 := ip.To4(); ip4 != nil {
				gatewayIP = ip4.String()
				subnetAddr = ipNet.IP.To4().String()
				ones, _ := ipNet.Mask.Size()
				subnetCIDR = ones
			}
		}
	}

	return subnetAddr, subnetCIDR, gatewayIP
}

func conflictingRemotePeer(remotePeers []AWGPeer, targetIPStr, allowedKey string) *AWGPeer {
	targetIP := net.ParseIP(strings.TrimSpace(targetIPStr))
	if targetIP == nil {
		return nil
	}
	for _, peer := range remotePeers {
		if peer.PublicKey != allowedKey && peerHasIP(peer, targetIP) {
			p := peer
			return &p
		}
	}
	return nil
}

func peerHasIP(peer AWGPeer, targetIP net.IP) bool {
	if targetIP == nil {
		return false
	}
	for _, part := range strings.Split(peer.AllowedIPs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		parsedIP, _, err := net.ParseCIDR(part)
		if err != nil {
			parsedIP = net.ParseIP(part)
		}
		if parsedIP != nil && parsedIP.Equal(targetIP) {
			return true
		}
	}
	return false
}

const maxConflictRetries = 10

func (m *AWGManager) allocateNonConflictingIP(
	ctx context.Context,
	serverID int64,
	effectiveClientID, clientPubKey string,
	usedIPs []string,
	subnetAddr string,
	subnetCIDR int,
	gatewayIP string,
	remotePeers []AWGPeer,
) (string, error) {
	for attempt := 0; attempt < maxConflictRetries; attempt++ {
		allocatedIP, err := m.ipAllocator.AllocateAWGClientIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
		if err != nil {
			return "", err
		}
		if conflictingRemotePeer(remotePeers, allocatedIP, clientPubKey) == nil {
			return allocatedIP, nil
		}
		slog.Warn("allocated IP conflicts with active remote peer; releasing stale lease and re-allocating",
			"server_id", serverID,
			"client_id", effectiveClientID,
			"ip", allocatedIP,
			"attempt", attempt+1,
		)
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, allocatedIP); relErr != nil {
			slog.Warn("failed to release conflicting allocated IP lease",
				"server_id", serverID,
				"client_id", effectiveClientID,
				"ip", allocatedIP,
				"error", relErr,
			)
			return "", fmt.Errorf("failed to release conflicting allocated IP lease for client %s (IP %s): %w", effectiveClientID, allocatedIP, relErr)
		}
		usedIPs = append(usedIPs, allocatedIP)
	}
	return "", fmt.Errorf("failed to allocate non-conflicting IP on server %d after %d attempts: all candidates conflict with remote peers", serverID, maxConflictRetries)
}

func (m *AWGManager) revertRekeyedLease(ctx context.Context, serverID int64, previousOwner, newClientID, ip, reason string) {
	if compErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, previousOwner, newClientID, ip); compErr != nil {
		slog.Error("failed to revert AWG client IP lease to previous owner during "+reason,
			"server_id", serverID,
			"previous_owner", previousOwner,
			"new_client_id", newClientID,
			"ip", ip,
			"error", compErr,
		)
	}
}

func (m *AWGManager) obtainExistingClientIPWithAllocator(
	ctx context.Context,
	serverID int64,
	effectiveClientID, clientPubKey string,
	existingClient AWGClient,
	usedIPs []string,
	subnetAddr string,
	subnetCIDR int,
	gatewayIP string,
	remotePeers []AWGPeer,
) (string, bool, bool, string, string, error) {
	existingIP := existingClient.UserData.ClientIP
	existingPubKey := existingClient.ClientID

	rekeyed := false
	previousOwner := ""
	rekeyedIP := ""
	transferSucceeded := false

	// Re-keying ownership transfer: if existing peer is replacing K1 with K2
	if existingPubKey != "" && clientPubKey != "" && existingPubKey != clientPubKey {
		rekeyed = true
		previousOwner = existingPubKey
		rekeyedIP = existingIP
		if transErr := m.ipAllocator.TransferAWGClientIPLease(ctx, serverID, effectiveClientID, existingPubKey, existingIP); transErr == nil {
			transferSucceeded = true
		} else {
			// Existing client had no lease row in DB, attempt to adopt existingIP for new key
			if conflictingRemotePeer(remotePeers, existingIP, existingPubKey) != nil {
				allocatedIP, allocErr := m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
				if allocErr != nil {
					return "", false, false, "", "", allocErr
				}
				return allocatedIP, true, false, "", "", nil
			}
			if _, adoptErr := m.ipAllocator.AdoptAWGClientIPLease(ctx, serverID, effectiveClientID, clientPubKey, existingIP); adoptErr != nil {
				return "", false, false, "", "", fmt.Errorf("failed to adopt AWG client IP lease during re-keying: %w", adoptErr)
			}
		}
	} else {
		// Existing client without lease row in DB: adopt existingIP if not claimed
		if conflictingRemotePeer(remotePeers, existingIP, clientPubKey) != nil {
			allocatedIP, allocErr := m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
			if allocErr != nil {
				return "", false, false, "", "", allocErr
			}
			return allocatedIP, true, false, "", "", nil
		}
		if _, adoptErr := m.ipAllocator.AdoptAWGClientIPLease(ctx, serverID, effectiveClientID, clientPubKey, existingIP); adoptErr != nil {
			return "", false, false, "", "", fmt.Errorf("failed to adopt AWG client IP lease: %w", adoptErr)
		}
	}

	allocatedIP, allocErr := m.ipAllocator.AllocateAWGClientIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
	if allocErr != nil {
		if transferSucceeded {
			m.revertRekeyedLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP, "allocation failure compensation")
		}
		return "", false, false, "", "", allocErr
	}

	allowedKey := clientPubKey
	if rekeyed && previousOwner != "" {
		allowedKey = previousOwner
	}
	if conflictingRemotePeer(remotePeers, allocatedIP, allowedKey) != nil {
		slog.Warn("allocated IP conflicts with active remote peer; releasing stale lease and re-allocating",
			"server_id", serverID,
			"client_id", effectiveClientID,
			"ip", allocatedIP,
		)
		if transferSucceeded {
			m.revertRekeyedLease(ctx, serverID, previousOwner, effectiveClientID, rekeyedIP, "conflicting allocation compensation")
		}
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, effectiveClientID, allocatedIP); relErr != nil {
			slog.Warn("failed to release conflicting allocated IP lease",
				"server_id", serverID,
				"client_id", effectiveClientID,
				"ip", allocatedIP,
				"error", relErr,
			)
			return "", false, false, "", "", fmt.Errorf("failed to release conflicting allocated IP lease for client %s (IP %s): %w", effectiveClientID, allocatedIP, relErr)
		}
		usedIPs = append(usedIPs, allocatedIP)
		allocatedIP, allocErr = m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
		if allocErr != nil {
			return "", false, false, "", "", allocErr
		}
	}
	return allocatedIP, allocatedIP != existingIP, rekeyed, previousOwner, rekeyedIP, nil
}

func (m *AWGManager) obtainClientIP(
	ctx context.Context,
	serverID int64,
	clientParams map[string]any,
	clients []AWGClient,
	existingIdx int,
	clientPubKey string,
	usedIPs []string,
	serverParams map[string]string,
	remotePeers []AWGPeer,
) (string, bool, bool, string, string, error) {
	subnetAddr, subnetCIDR, gatewayIP := parseServerSubnetParams(serverParams)
	effectiveClientID := resolveEffectiveClientID(clientParams, clientPubKey)

	if m.ipAllocator != nil {
		if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
			return m.obtainExistingClientIPWithAllocator(
				ctx, serverID, effectiveClientID, clientPubKey, clients[existingIdx],
				usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers,
			)
		}

		allocatedIP, allocErr := m.allocateNonConflictingIP(ctx, serverID, effectiveClientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP, remotePeers)
		if allocErr != nil {
			return "", false, false, "", "", allocErr
		}
		return allocatedIP, true, false, "", "", nil
	}

	if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
		return clients[existingIdx].UserData.ClientIP, false, false, "", "", nil
	}
	resolvedIP, resErr := resolveClientIP(clients, existingIdx, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
	if resErr != nil {
		return "", false, false, "", "", resErr
	}
	return resolvedIP, false, false, "", "", nil
}

func resolveEffectiveClientID(clientParams map[string]any, clientPubKey string) string {
	if cid, ok := clientParams["client_id"].(string); ok && strings.TrimSpace(cid) != "" {
		return strings.TrimSpace(cid)
	}
	return clientPubKey
}

func (m *AWGManager) getServerPublicKeyRequired(ctx context.Context, server *models.Server) (string, error) {
	serverPubKey, err := m.GetServerPublicKey(ctx, server)
	if err != nil {
		return "", fmt.Errorf("failed to get AmneziaWG server public key: %w", err)
	}
	if serverPubKey == "" {
		return "", errors.New("AmneziaWG server public key is empty")
	}
	return serverPubKey, nil
}

func resolveAllowedIPs(clientParams map[string]any) string {
	if aip, ok := clientParams["allowed_ips"]; ok && aip != nil {
		return fmt.Sprint(aip)
	}
	return ""
}

func resolveMimicry(clientParams map[string]any) string {
	if v, ok := clientParams["awg_mimicry"]; ok && fmt.Sprint(v) != "" {
		return fmt.Sprint(v)
	}
	return "auto"
}

func peerRemovalKeys(existingPubKey, clientPubKey string) []string {
	if existingPubKey != "" && existingPubKey != clientPubKey {
		return []string{existingPubKey}
	}
	return nil
}

func resolveClientKeys(clientParams map[string]any) (string, string, error) {
	clientPubKey := probePeerPubKey(clientParams)
	if clientPubKey != "" {
		return "", clientPubKey, nil
	}
	clientPrivKey, clientPubKey, err := GenerateWGKeypair()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate client keypair: %w", err)
	}
	return clientPrivKey, clientPubKey, nil
}

func resolveClientIP(clients []AWGClient, existingIdx int, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error) {
	if existingIdx >= 0 && clients[existingIdx].UserData.ClientIP != "" {
		return clients[existingIdx].UserData.ClientIP, nil
	}
	return GetNextIP(usedIPs, subnetAddr, subnetCIDR, gatewayIP)
}

func (m *AWGManager) buildClientConfig(ctx context.Context, client ssh.SSHClient, server *models.Server, serverParams map[string]string, clientPrivKey, clientIP, serverPubKey, psk, mimicry, clientPubKey string, clients []AWGClient) string {
	parsedParams := AWGParamsFromMap(convertStringMapToAny(serverParams))
	if mimicry != "" {
		if mp, err := cps.GenerateMimicryPackets(ctx, mimicry, "", client); err == nil {
			parsedParams.I1 = mp["i1"]
			parsedParams.I2 = mp["i2"]
			parsedParams.I3 = mp["i3"]
			parsedParams.I4 = mp["i4"]
			parsedParams.I5 = mp["i5"]
		}
	}

	port := serverParams["port"]
	if port == "" {
		port = AWGDefaults["port"]
	}
	endpoint := fmt.Sprintf("%s:%s", server.Host, port)
	var ud *AWGClientUserData
	for i := range clients {
		if clients[i].ClientID == clientPubKey {
			ud = &clients[i].UserData
			break
		}
	}
	clientConfig := RenderClientConfig(clientPrivKey, clientIP, serverPubKey, psk, endpoint, AWGDefaults["dns1"], AWGDefaults["dns2"], parsedParams.MTU, parsedParams, ud)
	return clientConfig
}

func convertStringMapToAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RemoveClient removes a client from the server WireGuard configuration and clientsTable.
func (m *AWGManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	// 1. Find peer IP for the client being removed
	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}
	var peerIP string
	for _, c := range clients {
		if c.ClientID == clientID && c.UserData.ClientIP != "" {
			peerIP = c.UserData.ClientIP
			break
		}
	}

	// 2. Remove [Peer] section from config
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}

	sections := strings.Split(confText, "[")
	var newSections []string
	for _, sec := range sections {
		if strings.TrimSpace(sec) == "" {
			continue
		}
		if strings.Contains(sec, clientID) {
			if peerIP == "" {
				ipRegex := regexp.MustCompile(`AllowedIPs\s*=\s*(\d+\.\d+\.\d+\.\d+)`)
				if matches := ipRegex.FindStringSubmatch(sec); len(matches) > 1 {
					peerIP = matches[1]
				}
			}
			continue
		}
		newSections = append(newSections, sec)
	}

	newConfig := "[" + strings.Join(newSections, "[")
	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return err
	}

	// 3. Update clientsTable
	var updatedClients []AWGClient
	for _, c := range clients {
		if c.ClientID != clientID {
			updatedClients = append(updatedClients, c)
		}
	}
	if err := m.saveClientsTable(ctx, client, updatedClients); err != nil {
		return err
	}

	// 4. Release allocated IP
	if m.ipAllocator != nil {
		if relErr := m.ipAllocator.ReleaseAWGClientIP(ctx, serverID, clientID, peerIP); relErr != nil {
			slog.Warn("failed to release AWG client IP on client removal", "server_id", serverID, "client_id", clientID, "ip", peerIP, "error", relErr)
		}
	}

	return nil
}

// GetClientConfig reconstructs the client config file for an existing client ID.
func (m *AWGManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return "", err
	}

	var targetClient *AWGClient
	for _, c := range clients {
		if c.ClientID == clientID {
			targetClient = &c
			break
		}
	}
	if targetClient == nil {
		return "", fmt.Errorf("client %s not found in clients table", clientID)
	}

	ud := targetClient.UserData
	if ud.ClientPrivateKey == "" {
		return "", errors.New("client private key not stored; config cannot be reconstructed")
	}

	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return "", err
	}

	serverParams, _, _ := ParseServerConfig(confText)
	serverPubKey, err := m.GetServerPublicKey(ctx, server)
	if err != nil || serverPubKey == "" {
		if err != nil {
			return "", fmt.Errorf("failed to get AmneziaWG server public key: %w", err)
		}
		return "", errors.New("AmneziaWG server public key is empty")
	}

	psk := ud.PSK
	if psk == "" {
		psk, _ = m.GetServerPSK(ctx, server)
	}

	parsedParams := AWGParamsFromMap(convertStringMapToAny(serverParams))
	if ud.AWGMimicry != "" {
		if mp, err := cps.GenerateMimicryPackets(ctx, ud.AWGMimicry, "", client); err == nil {
			parsedParams.I1 = mp["i1"]
			parsedParams.I2 = mp["i2"]
			parsedParams.I3 = mp["i3"]
			parsedParams.I4 = mp["i4"]
			parsedParams.I5 = mp["i5"]
		}
	}

	port := serverParams["port"]
	if port == "" {
		port = AWGDefaults["port"]
	}
	endpoint := fmt.Sprintf("%s:%s", server.Host, port)

	return RenderClientConfig(ud.ClientPrivateKey, ud.ClientIP, serverPubKey, psk, endpoint, AWGDefaults["dns1"], AWGDefaults["dns2"], parsedParams.MTU, parsedParams, &ud), nil
}

// ToggleClient enables or disables a client by adding or removing the [Peer] from the server config.
func (m *AWGManager) ToggleClient(ctx context.Context, server *models.Server, clientID string, enable bool) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			clients[i].UserData.Enabled = enable
			break
		}
	}
	if target == nil {
		return fmt.Errorf("client %s not found", clientID)
	}

	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}

	var newConfig string
	if enable {
		psk := target.UserData.PSK
		peerSec := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientID, psk, target.UserData.ClientIP)
		newConfig = strings.TrimRight(confText, "\n") + "\n" + peerSec
	} else {
		sections := strings.Split(confText, "[")
		var newSections []string
		for _, sec := range sections {
			if strings.TrimSpace(sec) == "" || strings.Contains(sec, clientID) {
				continue
			}
			newSections = append(newSections, sec)
		}
		newConfig = "[" + strings.Join(newSections, "[")
	}

	if err := m.saveServerConfig(ctx, client, newConfig); err != nil {
		return err
	}
	return m.saveClientsTable(ctx, client, clients)
}

// findExistingContainer checks known container names for existence.
func (m *AWGManager) findExistingContainer(ctx context.Context, client ssh.SSHClient) (string, bool, error) {
	for _, name := range AWGContainerNames {
		if !IsValidContainerName(name) {
			continue
		}
		outAll, errOutAll, codeAll, errAll := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps -a --filter name=^%s$ --format '{{.Names}}'", ssh.EscapeShellArg(name)))
		if errAll != nil || codeAll != 0 {
			return "", false, fmt.Errorf("docker ps -a failed checking %s (code %d): %s, %w", name, codeAll, errOutAll, errAll)
		}
		for _, line := range strings.Split(strings.TrimSpace(outAll), "\n") {
			if strings.TrimSpace(line) == name {
				return name, true, nil
			}
		}
	}
	return "", false, nil
}

// enrichRunningServerStatus populates configuration and credential details for a running container.
func (m *AWGManager) enrichRunningServerStatus(ctx context.Context, server *models.Server, client ssh.SSHClient, cName string, status map[string]any) {
	if conf, err := m.getServerConfig(ctx, client, cName); err == nil {
		params, peers, _ := ParseServerConfig(conf)
		status["port"] = params["port"]
		status["awg_params"] = params
		status["clients_count"] = len(peers)
		// Protocol generation is derived from the parsed backend config:
		// a non-empty HeaderProtectionKey means the backend speaks AWG 3.1.
		if params["header_protection_key"] != "" {
			status["protocol_generation"] = "3.1"
		} else {
			status["protocol_generation"] = "2.0"
		}
	}
	if !IsValidContainerName(cName) {
		cName = m.containerName()
	}
	// Best-effort AWG version lookup; empty string on any failure.
	if out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker exec -i %s 'awg' --version", ssh.EscapeShellArg(cName))); err == nil && code == 0 {
		if line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]); line != "" {
			status["awg_version"] = line
		}
	}
	// If port is missing or 0, fallback extraction from docker port or docker inspect
	if p, ok := status["port"]; !ok || p == nil || fmt.Sprint(p) == "" || fmt.Sprint(p) == "0" {
		if port := m.extractContainerPort(ctx, client, cName); port > 0 {
			status["port"] = port
		}
	}
	if pubKey, err := m.GetServerPublicKey(ctx, server); err == nil && pubKey != "" {
		status["public_key"] = pubKey
	}
	if psk, err := m.GetServerPSK(ctx, server); err == nil && psk != "" {
		status["psk"] = psk
	}
}

// GetServerStatus returns whether the container is running and configuration details across all valid container names.
func (m *AWGManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return nil, err
	}

	// One-shot legacy tc cleanup (PR #231 re-review Fix 2): containers
	// installed before the speed-limit removal (74b34d9) may still carry
	// HTB qdiscs/filters/ifb0 rules that outlive the deleted control plane.
	// The status path is the earliest reliable point where a resolved SSH
	// client and the real container name are both available, and it fires on
	// the natural first poll after a panel restart. The once-per-server map
	// keeps the cost at exactly three commands, once per server per process.
	if server != nil {
		m.mu.Lock()
		alreadyCleaned := m.tcCleaned[server.ID]
		if !alreadyCleaned {
			m.tcCleaned[server.ID] = true
		}
		m.mu.Unlock()
		if !alreadyCleaned {
			cName := m.resolveContainerName(ctx, client)
			m.CleanupLegacyTcRules(ctx, client, cName)
		}
	}

	foundName, exists, err := m.findExistingContainer(ctx, client)
	if err != nil {
		return nil, err
	}

	var running bool
	if exists && foundName != "" && IsValidContainerName(foundName) {
		m.setCachedContainerForServer(server, foundName)
		m.setCachedContainerForClient(client, foundName)

		outRun, errOutRun, codeRun, errRun := client.RunSudoCommand(ctx, fmt.Sprintf("docker ps --filter name=^%s$ --format '{{.Status}}'", ssh.EscapeShellArg(foundName)))
		if errRun != nil || codeRun != 0 {
			return nil, fmt.Errorf("docker ps failed checking %s (code %d): %s, %w", foundName, codeRun, errOutRun, errRun)
		}
		running = strings.Contains(outRun, "Up")
	}

	status := map[string]any{
		"protocol":          "awg",
		"container_exists":  exists,
		"container_running": running,
	}

	if running {
		cName := foundName
		if cName == "" {
			cName = m.resolveContainerName(ctx, client)
		}
		if !IsValidContainerName(cName) {
			cName = m.containerName()
		}
		m.enrichRunningServerStatus(ctx, server, client, cName, status)
	}

	return status, nil
}

// extractContainerPort attempts to discover the host UDP listening port of the container
// via docker port and docker inspect.
func (m *AWGManager) extractContainerPort(ctx context.Context, client ssh.SSHClient, containerName string) int {
	if containerName == "" {
		containerName = m.resolveContainerName(ctx, client)
	}
	if !IsValidContainerName(containerName) {
		containerName = m.containerName()
	}
	if !IsValidContainerName(containerName) {
		return 0
	}
	out, _, code, err := client.RunSudoCommand(ctx, fmt.Sprintf("docker port %s 2>/dev/null", ssh.EscapeShellArg(containerName)))
	if err == nil && code == 0 && strings.TrimSpace(out) != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if idx := strings.LastIndex(line, ":"); idx != -1 {
				portStr := strings.TrimSpace(line[idx+1:])
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					return p
				}
			}
		}
	}

	inspectCmd := fmt.Sprintf("docker inspect --format '{{range $p, $conf := .HostConfig.PortBindings}}{{(index $conf 0).HostPort}} {{end}}' %s 2>/dev/null", ssh.EscapeShellArg(containerName))
	outInspect, _, codeInspect, errInspect := client.RunSudoCommand(ctx, inspectCmd)
	if errInspect == nil && codeInspect == 0 && strings.TrimSpace(outInspect) != "" {
		for _, part := range strings.Fields(outInspect) {
			if p, err := strconv.Atoi(part); err == nil && p > 0 {
				return p
			}
		}
	}
	return 0
}

// GetServerPublicKey returns the public key for AmneziaWG server.
func (m *AWGManager) GetServerPublicKey(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat '/opt/amnezia/awg/wireguard_server_public_key.key' 2>/dev/null || docker exec -i %s %s show awg0 public-key 2>/dev/null || docker exec -i %s wg show awg0 public-key 2>/dev/null", ssh.EscapeShellArg(name), ssh.EscapeShellArg(name), ssh.EscapeShellArg(m.wgBinary()), ssh.EscapeShellArg(name))
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	}

	// Also check if public key can be derived from PrivateKey in awg0.conf
	if conf, err := m.getServerConfig(ctx, client, names...); err == nil && conf != "" {
		for _, line := range strings.Split(conf, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(trimmed), "privatekey") {
				parts := strings.SplitN(trimmed, "=", 2)
				if len(parts) == 2 {
					privKeyBase64 := strings.TrimSpace(parts[1])
					if privBytes, err := base64.StdEncoding.DecodeString(privKeyBase64); err == nil && len(privBytes) == 32 {
						if pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint); err == nil {
							return base64.StdEncoding.EncodeToString(pubBytes), nil
						}
					}
				}
			}
		}
	}

	return "", errors.New("failed to get AmneziaWG server public key")
}

// GetServerPSK returns the preshared key for AmneziaWG server.
func (m *AWGManager) GetServerPSK(ctx context.Context, server *models.Server) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	resolved := m.resolveContainerName(ctx, client)
	if !IsValidContainerName(resolved) {
		resolved = m.containerName()
	}
	names := []string{resolved}
	for _, name := range AWGContainerNames {
		if name != resolved && IsValidContainerName(name) {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if !IsValidContainerName(name) {
			continue
		}
		cmd := fmt.Sprintf("docker exec -i %s cat '/opt/amnezia/awg/wireguard_psk.key' 2>/dev/null || docker exec -i %s cat '/etc/amnezia/amneziawg/wireguard_psk.key' 2>/dev/null", ssh.EscapeShellArg(name), ssh.EscapeShellArg(name))
		out, _, code, err := client.RunSudoCommand(ctx, cmd)
		if err == nil && code == 0 && strings.TrimSpace(out) != "" {
			return strings.TrimSpace(out), nil
		}
	}
	return "", nil
}

func parseParamString(params map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := params[k]; ok && v != nil && fmt.Sprint(v) != "" {
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

func parseBoolParam(val any) (bool, bool) {
	if val == nil {
		return false, false
	}
	switch v := val.(type) {
	case bool:
		return v, true
	case string:
		return strings.ToLower(v) == "true" || v == "1", true
	case int:
		return v != 0, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0, true
	default:
		return false, false
	}
}

// EditClient modifies client metadata and enabling/disabling state.
func (m *AWGManager) EditClient(ctx context.Context, server *models.Server, clientID string, params map[string]any) error {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return lockErr
	}
	defer unlockRemote()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("client %s not found in clients table", clientID)
	}

	if name, ok := parseParamString(params, "name", "clientName", "client_name"); ok {
		target.UserData.ClientName = name
	}
	if mimicry, ok := parseParamString(params, "awg_mimicry", "mimicry"); ok {
		target.UserData.AWGMimicry = mimicry
	}

	if newEnabled, ok := parseBoolParam(params["enabled"]); ok && newEnabled != target.UserData.Enabled {
		if err := m.updateServerConfigPeer(ctx, client, clientID, target.UserData.ClientIP, target.UserData.PSK, newEnabled); err != nil {
			return fmt.Errorf("failed to update server peer config: %w", err)
		}
		target.UserData.Enabled = newEnabled
	}

	return m.saveClientsTable(ctx, client, clients)
}

func (m *AWGManager) updateServerConfigPeer(ctx context.Context, client ssh.SSHClient, clientID, clientIP, psk string, enable bool) error {
	confText, err := m.getServerConfig(ctx, client)
	if err != nil {
		return err
	}
	var newConfig string
	if enable {
		peerSec := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", clientID, psk, clientIP)
		newConfig = strings.TrimRight(confText, "\n") + "\n" + peerSec
	} else {
		sections := strings.Split(confText, "[")
		var newSections []string
		for _, sec := range sections {
			if strings.TrimSpace(sec) == "" || strings.Contains(sec, clientID) {
				continue
			}
			newSections = append(newSections, sec)
		}
		newConfig = "[" + strings.Join(newSections, "[")
	}
	return m.saveServerConfig(ctx, client, newConfig)
}

// RotateMimicry rotates a client's mimicry profile through the sequence:
// auto -> tls -> quic -> dns -> sip -> tls, regenerates I1-I5 packet headers, and updates clientsTable.
func (m *AWGManager) RotateMimicry(ctx context.Context, server *models.Server, clientID string) (string, error) {
	client, err := m.getSSHClient(ctx, server)
	if err != nil {
		return "", err
	}

	var serverID int64
	if server != nil {
		serverID = server.ID
	}
	sLock := m.getServerLock(serverID)
	sLock.Lock()
	defer sLock.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	unlockRemote, lockErr := m.acquireRemoteServerLock(ctx, client, serverID)
	if lockErr != nil {
		return "", lockErr
	}
	defer unlockRemote()

	clients, err := m.getClientsTable(ctx, client)
	if err != nil {
		return "", err
	}

	var target *AWGClient
	for i := range clients {
		if clients[i].ClientID == clientID {
			target = &clients[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("client %s not found in clients table", clientID)
	}

	curr := strings.ToLower(strings.TrimSpace(target.UserData.AWGMimicry))
	if curr == "" {
		curr = "auto"
	}

	var nextProfile string
	switch curr {
	case "auto":
		nextProfile = "tls"
	case "tls":
		nextProfile = "quic"
	case "quic":
		nextProfile = "dns"
	case "dns":
		nextProfile = "sip"
	case "sip":
		nextProfile = "tls"
	default:
		nextProfile = "tls"
	}

	// Regenerate I1-I5 signature packets
	if mp, err := cps.GenerateMimicryPackets(ctx, nextProfile, "", client); err == nil {
		target.UserData.I1 = mp["i1"]
		target.UserData.I2 = mp["i2"]
		target.UserData.I3 = mp["i3"]
		target.UserData.I4 = mp["i4"]
		target.UserData.I5 = mp["i5"]
	}

	target.UserData.AWGMimicry = nextProfile
	target.UserData.RotatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := m.saveClientsTable(ctx, client, clients); err != nil {
		return "", fmt.Errorf("failed to save clients table after mimicry rotation: %w", err)
	}

	return nextProfile, nil
}
