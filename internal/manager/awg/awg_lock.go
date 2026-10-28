package awg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

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

// GetLock retrieves or creates a per-server mutex.
func (r *ServerLockRegistry) GetLock(serverID int64) *sync.Mutex {
	if r == nil {
		return globalServerLocks.getLock(serverID)
	}
	return r.getLock(serverID)
}

// GlobalServerLocks returns the global per-server lock registry.
func GlobalServerLocks() *ServerLockRegistry {
	return globalServerLocks
}

func (m *AWGManager) getServerLock(serverID int64) *sync.Mutex {
	if m != nil && m.serverLocks != nil {
		return m.serverLocks.getLock(serverID)
	}
	return globalServerLocks.getLock(serverID)
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
		`cur_owner=$(cat %s/owner 2>/dev/null); if [ -n %s ] && { [ "$cur_owner" = %s ] || [ "${cur_owner%%%% *}" = %s ]; }; then rm -rf %s 2>/dev/null; fi`,
		ssh.EscapeShellArg(lockDir),
		escapedTok,
		escapedTok,
		escapedTok,
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

// AcquireRemoteServerLock acquires a remote shell lock for the given resource on the target host.
func AcquireRemoteServerLock(ctx context.Context, client ssh.SSHClient, resource any) (func(), error) {
	return AcquireRemoteServerLockWithHeartbeat(ctx, client, resource, defaultRemoteLockHeartbeatInterval, defaultRemoteLockHeartbeatTimeout)
}

// AcquireRemoteServerLockWithHeartbeat acquires a remote shell lock with custom heartbeat settings.
func AcquireRemoteServerLockWithHeartbeat(ctx context.Context, client ssh.SSHClient, resource any, interval, timeout time.Duration) (func(), error) {
	if client == nil {
		return func() {}, nil
	}
	token := generateLockToken()
	cmd := remoteLockAcquireCmd(resource, token)
	_, errOut, code, err := client.RunSudoCommand(ctx, cmd)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("failed to acquire remote server lock on resource %v (exit code %d): %s: %w", resource, code, strings.TrimSpace(errOut), err)
	}

	if interval <= 0 {
		interval = defaultRemoteLockHeartbeatInterval
	}
	if timeout <= 0 {
		timeout = defaultRemoteLockHeartbeatTimeout
	}
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
						slog.Debug("failed to refresh remote server lock heartbeat", "resource", resource, "code", code, "error", err, "stderr", strings.TrimSpace(errOut))
					}
				}
			}
		}
	}()

	var once sync.Once
	unlock := func() {
		once.Do(func() {
			cancelHeartbeat()
			done := make(chan struct{})
			go func() {
				heartbeatWg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				slog.Warn("remote server lock heartbeat worker did not exit promptly on cancel")
			}

			relCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			relCmd := remoteLockReleaseCmd(resource, token)
			_, errOut, code, err := client.RunSudoCommand(relCtx, relCmd)
			if err != nil || code != 0 {
				slog.Warn("failed to release remote server lock", "resource", resource, "code", code, "error", err, "stderr", strings.TrimSpace(errOut))
			}
		})
	}
	return unlock, nil
}

func (m *AWGManager) acquireRemoteServerLock(ctx context.Context, client ssh.SSHClient, serverID int64) (func(), error) {
	if client == nil || serverID <= 0 {
		return func() {}, nil
	}
	resource := m.resolveLockResource(ctx, client, serverID)
	interval, timeout := m.getLockHeartbeatConfig()
	return AcquireRemoteServerLockWithHeartbeat(ctx, client, resource, interval, timeout)
}
