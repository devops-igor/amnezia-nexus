package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/curve25519"
)

var (
	ErrTunnelNotFound    = errors.New("backend tunnel not found")
	ErrPoolClosed        = errors.New("tunnel pool is closed")
	ErrStaleStateVersion = errors.New("stale tunnel state version")
)

// Pool manages the in-process AWG tunnels connected to backend VPN servers.
type Pool struct {
	mu                    sync.RWMutex
	db                    *database.DB
	tunnelsByServerID     map[int64]*models.BackendTunnel
	tunnelsByID           map[int64]*models.BackendTunnel
	tunnelsByIfName       map[string]*models.BackendTunnel
	closed                bool
	setTunnelEndpointHook func(ctx context.Context, tunnelID int64, endpoint string) error
	generateKeypairFn     func() (string, string, error)
}

// DeriveClientPublicKey derives the Base64-encoded Curve25519 public key from a Base64-encoded private key.
func DeriveClientPublicKey(privKey string) (string, error) {
	return health.ComputePublicKeyFromPrivate(privKey)
}

// ClientPublicKey derives the prober client's public key from the BackendTunnel's
// dedicated probe key (issue #43). It is the identity the health prober presents
// to the backend and is intentionally distinct from the data device key derived
// from PrivateKey.
func ClientPublicKey(t *models.BackendTunnel) (string, error) {
	if t == nil {
		return "", errors.New("tunnel is nil")
	}
	if t.ProbePrivateKey != "" {
		return health.ComputePublicKeyFromPrivate(t.ProbePrivateKey)
	}
	// Legacy tunnels without a probe key fall back to the data key so callers
	// still get a usable identity; EnsureBackendProbeKeys upgrades them.
	return health.ComputePublicKeyFromPrivate(t.PrivateKey)
}

// DataDevicePublicKey derives the backend DATA device's public key from the
// tunnel's PrivateKey. This is the identity that must be registered on the
// backend server with AllowedIPs covering the portal client subnet so the
// backend accepts data traffic and routes replies back to the data device.
func DataDevicePublicKey(t *models.BackendTunnel) (string, error) {
	if t == nil {
		return "", errors.New("tunnel is nil")
	}
	return health.ComputePublicKeyFromPrivate(t.PrivateKey)
}

// NewPool initializes an in-process backend tunnel pool.
func NewPool(db *database.DB) *Pool {
	return &Pool{
		db:                db,
		tunnelsByServerID: make(map[int64]*models.BackendTunnel),
		tunnelsByID:       make(map[int64]*models.BackendTunnel),
		tunnelsByIfName:   make(map[string]*models.BackendTunnel),
	}
}

// GenerateCurve25519KeyPair generates a Base64-encoded WireGuard/AWG keypair.
func GenerateCurve25519KeyPair() (pubKey string, privKey string, err error) {
	privBytes := make([]byte, 32)
	if _, err := rand.Read(privBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random private key: %w", err)
	}

	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("failed to compute public key: %w", err)
	}

	pubKey = base64.StdEncoding.EncodeToString(pubBytes)
	privKey = base64.StdEncoding.EncodeToString(privBytes)
	return pubKey, privKey, nil
}

// PublicKeyFromPrivateKey computes the Base64-encoded Curve25519 public key from a Base64-encoded private key.
func PublicKeyFromPrivateKey(privKeyBase64 string) (string, error) {
	return DeriveClientPublicKey(privKeyBase64)
}

func (p *Pool) genKeyPair() (string, string, error) {
	if p.generateKeypairFn != nil {
		return p.generateKeypairFn()
	}
	return GenerateCurve25519KeyPair()
}

// SetGenerateKeyPairForTest overrides the keypair generation function for testing.
func (p *Pool) SetGenerateKeyPairForTest(fn func() (string, string, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.generateKeypairFn = fn
}

// SyncFromDB loads all backend tunnels from the database into the memory pool.
func (p *Pool) SyncFromDB(ctx context.Context) error {
	if p.db == nil {
		return nil
	}

	tunnels, err := p.db.GetBackendTunnels(ctx)
	if err != nil {
		return fmt.Errorf("failed to load backend tunnels from DB: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for i := range tunnels {
		t := tunnels[i]
		if t.StateVersion <= 0 {
			t.StateVersion = 1
		}
		if t.AdministrativelyEnabled() {
			reset, err := p.db.ResetBackendTunnelRuntimeHealth(ctx, t.ID)
			if err != nil {
				return fmt.Errorf("failed to reset backend tunnel %d runtime health on sync: %w", t.ID, err)
			}
			if reset {
				t.StateVersion++
			}
			t.HealthStatus = models.TunnelStatusConnecting
			t.Status = models.TunnelStatusConnecting
			t.DisableReason = models.DisableReasonNone
			t.LatencyMS = 0
			t.LastHealthCheck = nil
		}
		if t.ProbePrivateKey == "" {
			// Legacy row from before the dedicated probe key existed
			// (issue #43): backfill in memory; EnableBackend's peer
			// registration persists it and provisions the probe peer.
			if _, sk, err := GenerateCurve25519KeyPair(); err == nil {
				t.ProbePrivateKey = sk
				if p.db != nil {
					_ = p.db.UpdateBackendTunnel(ctx, t.ID, map[string]any{
						"probe_private_key": sk,
					})
				}
			}
		}
		p.tunnelsByServerID[t.ServerID] = &t
		p.tunnelsByID[t.ID] = &t
		p.tunnelsByIfName[t.InterfaceName] = &t
	}

	return nil
}

// AddTunnel establishes or registers an in-process AWG backend tunnel for a server.
func (p *Pool) AddTunnel(ctx context.Context, serverID int64, endpoint, serverPubKey string) (*models.BackendTunnel, error) {
	if serverID <= 0 {
		return nil, errors.New("server_id must be greater than 0")
	}
	if endpoint == "" {
		return nil, errors.New("endpoint cannot be empty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrPoolClosed
	}

	if existing, ok := p.tunnelsByServerID[serverID]; ok {
		candEndpoint := endpoint
		candPubKey := serverPubKey
		if candPubKey == "" {
			candPubKey = existing.PublicKey
		}
		candPrivKey := existing.PrivateKey
		candProbePrivKey := existing.ProbePrivateKey

		if candPrivKey == "" {
			_, sk, err := p.genKeyPair()
			if err != nil {
				return nil, fmt.Errorf("failed to generate backend private key: %w", err)
			}
			candPrivKey = sk
		}

		if candProbePrivKey == "" {
			// Dedicated health-probe identity (issue #43): must differ from
			// PrivateKey so the prober's socket cannot steal the data peer's
			// return endpoint on the backend.
			_, sk, err := p.genKeyPair()
			if err != nil {
				return nil, fmt.Errorf("failed to generate probe private key: %w", err)
			}
			candProbePrivKey = sk
		}

		if p.db != nil {
			updates := map[string]any{
				"endpoint":          candEndpoint,
				"public_key":        candPubKey,
				"private_key":       candPrivKey,
				"probe_private_key": candProbePrivKey,
			}
			if err := p.db.UpdateBackendTunnel(ctx, existing.ID, updates); err != nil {
				return nil, fmt.Errorf("failed to persist backend tunnel updates: %w", err)
			}
		}

		existing.Endpoint = candEndpoint
		existing.PublicKey = candPubKey
		existing.PrivateKey = candPrivKey
		existing.ProbePrivateKey = candProbePrivKey
		return existing, nil
	}

	pubKey := serverPubKey
	var privKey string
	if pubKey == "" {
		pk, sk, err := p.genKeyPair()
		if err != nil {
			return nil, err
		}
		pubKey = pk
		privKey = sk
	} else {
		_, sk, err := p.genKeyPair()
		if err != nil {
			return nil, err
		}
		privKey = sk
	}

	probePrivPub, probePrivKey, err := p.genKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate probe keypair: %w", err)
	}
	_ = probePrivPub // pub recomputed from priv via ClientPublicKey; kept for symmetry

	ifName := fmt.Sprintf("awg-be-%d", serverID)
	now := time.Now().UTC()

	tunnel := &models.BackendTunnel{
		ServerID:          serverID,
		InterfaceName:     ifName,
		PublicKey:         pubKey,
		PrivateKey:        privKey,
		ProbePrivateKey:   probePrivKey,
		Endpoint:          endpoint,
		HealthStatus:      models.TunnelStatusActive,
		AdminDisabled:     false,
		Status:            models.TunnelStatusActive,
		DisableReason:     models.DisableReasonNone,
		StateVersion:      1,
		LastHealthCheck:   nil,
		LatencyMS:         0,
		ActiveConnections: 0,
		CreatedAt:         now,
	}

	if p.db != nil {
		id, err := p.db.CreateBackendTunnel(ctx, tunnel)
		if err != nil {
			return nil, fmt.Errorf("failed to persist backend tunnel: %w", err)
		}
		tunnel.ID = id
	} else {
		tunnel.ID = serverID
	}

	p.tunnelsByServerID[serverID] = tunnel
	p.tunnelsByID[tunnel.ID] = tunnel
	p.tunnelsByIfName[ifName] = tunnel

	return tunnel, nil
}

// RemoveTunnel removes a backend tunnel by server ID.
func (p *Pool) RemoveTunnel(ctx context.Context, serverID int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok {
		return ErrTunnelNotFound
	}

	if p.db != nil {
		if err := p.db.DeleteBackendTunnel(ctx, tunnel.ID); err != nil {
			return fmt.Errorf("failed to delete backend tunnel from DB: %w", err)
		}
	}

	delete(p.tunnelsByServerID, serverID)
	delete(p.tunnelsByID, tunnel.ID)
	delete(p.tunnelsByIfName, tunnel.InterfaceName)

	return nil
}

// GetTunnel retrieves a tunnel by server ID.
func (p *Pool) GetTunnel(serverID int64) (*models.BackendTunnel, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok {
		return nil, ErrTunnelNotFound
	}
	copyTunnel := *tunnel
	return &copyTunnel, nil
}

// GetTunnelByID retrieves a tunnel by its tunnel ID.
func (p *Pool) GetTunnelByID(id int64) (*models.BackendTunnel, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tunnel, ok := p.tunnelsByID[id]
	if !ok {
		return nil, ErrTunnelNotFound
	}
	copyTunnel := *tunnel
	return &copyTunnel, nil
}

// GetTunnelByInterface retrieves a tunnel by its interface name (e.g. "awg-be-1").
func (p *Pool) GetTunnelByInterface(ifName string) (*models.BackendTunnel, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tunnel, ok := p.tunnelsByIfName[ifName]
	if !ok {
		return nil, ErrTunnelNotFound
	}
	copyTunnel := *tunnel
	return &copyTunnel, nil
}

// ListTunnels returns a copy of all tunnels in the pool.
func (p *Pool) ListTunnels() []*models.BackendTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []*models.BackendTunnel
	for _, t := range p.tunnelsByServerID {
		copyTunnel := *t
		result = append(result, &copyTunnel)
	}
	return result
}

// GetActiveTunnels returns administratively enabled tunnels whose runtime health is active.
func (p *Pool) GetActiveTunnels() []*models.BackendTunnel {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []*models.BackendTunnel
	for _, t := range p.tunnelsByServerID {
		if t.AdministrativelyEnabled() && strings.EqualFold(t.RuntimeHealth(), models.TunnelStatusActive) {
			copyTunnel := *t
			result = append(result, &copyTunnel)
		}
	}
	return result
}

// SetTunnelAdminDisabled updates only persisted administrative intent and does
// not modify runtime health (issue #90).
func (p *Pool) SetTunnelAdminDisabled(ctx context.Context, serverID int64, disabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok {
		return ErrTunnelNotFound
	}
	if tunnel.AdminDisabled == disabled &&
		((disabled && tunnel.DisableReason == models.DisableReasonAdmin) ||
			(!disabled && tunnel.DisableReason != models.DisableReasonAdmin)) {
		return nil
	}
	if p.db != nil {
		if err := p.db.UpdateBackendTunnelAdminDisabled(ctx, tunnel.ID, disabled); err != nil {
			return fmt.Errorf("failed to persist backend administrative state: %w", err)
		}
	}

	tunnel.AdminDisabled = disabled
	if disabled {
		tunnel.Status = models.TunnelStatusDisabled
		tunnel.DisableReason = models.DisableReasonAdmin
	} else {
		tunnel.Status = tunnel.RuntimeHealth()
		if tunnel.Status == "" {
			tunnel.Status = models.TunnelStatusConnecting
		}
		tunnel.DisableReason = models.DisableReasonNone
	}
	tunnel.StateVersion++
	return nil
}

// SetTunnelStatus updates the status and latency of a backend tunnel.
// When status becomes "active", DisableReason is cleared.
// DB errors are propagated immediately; in-memory state is only updated on DB success.
func (p *Pool) SetTunnelStatus(ctx context.Context, serverID int64, status string, latencyMS int64) error {
	return p.setTunnelStatus(ctx, serverID, 0, 0, status, latencyMS)
}

// SetTunnelStatusIfCurrent applies a probe result only to the tunnel generation
// that produced it. The identity check and DB/memory update share p.mu.
func (p *Pool) SetTunnelStatusIfCurrent(ctx context.Context, serverID, expectedTunnelID int64, status string, latencyMS int64) error {
	if expectedTunnelID == 0 {
		return ErrTunnelNotFound
	}
	return p.setTunnelStatus(ctx, serverID, expectedTunnelID, 0, status, latencyMS)
}

// SetTunnelStatusIfCurrentWithVersion applies a probe result only to the tunnel generation
// and state version that produced it.
func (p *Pool) SetTunnelStatusIfCurrentWithVersion(ctx context.Context, serverID, expectedTunnelID, expectedVersion int64, status string, latencyMS int64) error {
	if expectedTunnelID == 0 {
		return ErrTunnelNotFound
	}
	return p.setTunnelStatus(ctx, serverID, expectedTunnelID, expectedVersion, status, latencyMS)
}

func (p *Pool) setTunnelStatus(ctx context.Context, serverID, expectedTunnelID, expectedVersion int64, status string, latencyMS int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok || (expectedTunnelID != 0 && tunnel.ID != expectedTunnelID) {
		return ErrTunnelNotFound
	}

	if expectedVersion > 0 && tunnel.StateVersion != expectedVersion {
		return ErrStaleStateVersion
	}

	if !tunnel.AdministrativelyEnabled() {
		return nil
	}

	newReason := tunnel.DisableReason
	if status == "active" || status == models.TunnelStatusActive {
		newReason = models.DisableReasonNone
	}

	if p.db != nil {
		if expectedVersion > 0 {
			swapped, err := p.db.CompareAndSwapTunnelStatus(ctx, tunnel.ID, tunnel.Status, tunnel.DisableReason, expectedVersion, status, newReason, latencyMS)
			if err != nil {
				return fmt.Errorf("failed to execute CAS update on backend tunnel: %w", err)
			}
			if !swapped {
				return ErrStaleStateVersion
			}
		} else {
			var err error
			if newReason != tunnel.DisableReason {
				err = p.db.UpdateBackendTunnelStatusWithReason(ctx, tunnel.ID, status, newReason, latencyMS)
			} else {
				err = p.db.UpdateBackendTunnelStatus(ctx, tunnel.ID, status, latencyMS)
			}
			if err != nil {
				return fmt.Errorf("failed to persist backend tunnel status: %w", err)
			}
		}
	}

	tunnel.HealthStatus = status
	tunnel.Status = status
	tunnel.DisableReason = newReason
	tunnel.LatencyMS = latencyMS
	tunnel.StateVersion++
	now := time.Now().UTC()
	tunnel.LastHealthCheck = &now

	return nil
}

// SetTunnelStatusWithReason updates the status, disable reason, and latency of a backend tunnel.
// DB errors are propagated immediately; in-memory state is only updated on DB success.
func (p *Pool) SetTunnelStatusWithReason(ctx context.Context, serverID int64, status, disableReason string, latencyMS int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok {
		return ErrTunnelNotFound
	}

	if disableReason == models.DisableReasonHealth && !tunnel.AdministrativelyEnabled() {
		return nil
	}

	if p.db != nil {
		if err := p.db.UpdateBackendTunnelStatusWithReason(ctx, tunnel.ID, status, disableReason, latencyMS); err != nil {
			return fmt.Errorf("failed to persist backend tunnel status with reason: %w", err)
		}
	}

	if disableReason == models.DisableReasonAdmin {
		tunnel.AdminDisabled = true
		tunnel.Status = models.TunnelStatusDisabled
		tunnel.DisableReason = models.DisableReasonAdmin
	} else {
		tunnel.AdminDisabled = false
		tunnel.HealthStatus = status
		tunnel.Status = status
		tunnel.DisableReason = disableReason
	}
	tunnel.LatencyMS = latencyMS
	tunnel.StateVersion++
	now := time.Now().UTC()
	tunnel.LastHealthCheck = &now

	return nil
}

// CompareAndSwapTunnelStatus conditionally updates tunnel status if the current status,
// disable reason, and state version match expected values.
// Returns true if the state was updated, false if state did not match.
func (p *Pool) CompareAndSwapTunnelStatus(ctx context.Context, serverID int64, expectedStatus, expectedReason string, expectedVersion int64, newStatus, newReason string, latencyMS int64) (bool, error) {
	return p.compareAndSwapTunnelStatus(ctx, serverID, 0, expectedStatus, expectedReason, expectedVersion, newStatus, newReason, latencyMS)
}

// CompareAndSwapTunnelStatusForTunnel rejects a CAS from an older tunnel
// generation before it can mutate a replacement with the same server ID.
func (p *Pool) CompareAndSwapTunnelStatusForTunnel(ctx context.Context, serverID, expectedTunnelID int64, expectedStatus, expectedReason string, expectedVersion int64, newStatus, newReason string, latencyMS int64) (bool, error) {
	if expectedTunnelID == 0 {
		return false, ErrTunnelNotFound
	}
	return p.compareAndSwapTunnelStatus(ctx, serverID, expectedTunnelID, expectedStatus, expectedReason, expectedVersion, newStatus, newReason, latencyMS)
}

func (p *Pool) compareAndSwapTunnelStatus(ctx context.Context, serverID, expectedTunnelID int64, expectedStatus, expectedReason string, expectedVersion int64, newStatus, newReason string, latencyMS int64) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok || (expectedTunnelID != 0 && tunnel.ID != expectedTunnelID) {
		return false, ErrTunnelNotFound
	}

	if tunnel.Status != expectedStatus || tunnel.DisableReason != expectedReason || tunnel.StateVersion != expectedVersion {
		return false, nil
	}

	if p.db != nil {
		swapped, err := p.db.CompareAndSwapTunnelStatus(ctx, tunnel.ID, expectedStatus, expectedReason, expectedVersion, newStatus, newReason, latencyMS)
		if err != nil {
			return false, fmt.Errorf("failed to execute CAS update on backend tunnel: %w", err)
		}
		if !swapped {
			return false, nil
		}
	}

	if newReason == models.DisableReasonAdmin {
		tunnel.AdminDisabled = true
		tunnel.Status = models.TunnelStatusDisabled
		tunnel.DisableReason = models.DisableReasonAdmin
	} else {
		tunnel.AdminDisabled = false
		tunnel.HealthStatus = newStatus
		tunnel.Status = newStatus
		tunnel.DisableReason = newReason
	}
	tunnel.LatencyMS = latencyMS
	tunnel.StateVersion++
	now := time.Now().UTC()
	tunnel.LastHealthCheck = &now

	return true, nil
}

// IncrementConnections increments active connection count on a tunnel.
//
// Serialization contract (issue #86): the pool guarantees only atomic,
// internally consistent gauge updates (this method takes p.mu); it does NOT
// enforce MaxPeersPerBackend and it cannot. The check-then-allocate capacity
// decision (FilterHealthy reads t.ActiveConnections here, the caller
// increments afterwards) is only a safe pattern because every production
// mutator of ActiveConnections serializes under the VPN Service's single
// mutex s.mu (internal/vpn/vpn.go), with one documented exception below.
// Callers outside that regime (tests, future refactorings such as the
// planned vpn.go split) MUST either hold the same serializing lock or make
// select+increment atomic another way (e.g. a reservation counter);
// incrementing from two unserialized goroutines after two FilterHealthy
// reads can exceed MaxPeersPerBackend by 1.
//
// Production callers:
//   - HandleIncomingPeer — increment, under s.mu (the only select+increment
//     path).
//   - DisconnectSession / DisconnectUser / ReleaseClient and failover
//     backend moves — decrements/increments, under s.mu.
//   - Rekey ReplacementHook (SetReplacementHook in vpn.go) — decrement of
//     the old backend plus a conditional increment of the new one. The hook
//     fires from the tail of SessionManager.CreateSession while
//     SessionManager.mu is held (it must not re-enter the manager). Today's
//     ONLY production call site of CreateSession is HandleIncomingPeer,
//     which holds s.mu for the whole select → CreateSession → increment
//     sequence — so the hook in fact runs nested under BOTH locks
//     (s.mu → sm.mu, a fixed lock order; no path takes them in reverse).
//     If a second CreateSession call site outside s.mu is ever added, the
//     hook path would no longer be under s.mu; the contract for such a
//     caller is that its replacements must still be serialized per peer
//     (the SessionManager guarantees that under sm.mu) and must not be able
//     to push more increments than live sessions onto one backend.
//
// Persistence (issue #96): the in-memory gauge mutation is the ONLY thing
// that happens under p.mu — the DB write is issued AFTER the lock is
// released (copy-state-release-persist), so a slow or blocked persist can
// never stall the read-locked hot paths (GetTunnel/ListTunnels/
// GetActiveTunnels). Because the DB write happens outside p.mu, two
// persisters for the SAME tunnel could in principle write out of order;
// every production mutator holds the VPN Service's s.mu (see above), so
// same-tunnel updates are serialized upstream and the write order matches
// the gauge order. A caller outside that regime could leave the DB
// transiently behind the in-memory gauge (last write wins); the hourly
// gauge reconciler (issue #78) self-corrects any residual divergence.
// Persist errors are logged (not silently ignored) — the in-memory gauge is
// already updated and remains authoritative for balancing; divergence is
// bounded and reconcilable exactly as pinned by the #88 scenario-1
// fault-injection tests.
func (p *Pool) IncrementConnections(tunnelID int64) {
	p.mu.Lock()
	var (
		found     bool
		persistID int64
		count     int
	)
	if tunnel, ok := p.tunnelsByID[tunnelID]; ok {
		tunnel.ActiveConnections++
		found = true
		persistID = tunnel.ID
		count = tunnel.ActiveConnections
	}
	p.mu.Unlock()
	if found {
		p.persistConnectionCount(persistID, int64(count))
	}
}

// persistConnectionCount issues the DB write for the connection gauge AFTER
// p.mu has been released (issue #96). It reads only immutable pool fields
// (p.db is fixed at NewPool and never mutated), so it requires no lock. A
// persist failure is logged with the gauge value that failed to land — the
// in-memory counter stays correct and the divergence is reconciled by
// reconcileConnectionCounts (startup + hourly).
func (p *Pool) persistConnectionCount(tunnelID, count int64) {
	if p.db == nil {
		return
	}
	if err := p.db.UpdateBackendTunnel(context.Background(), tunnelID, map[string]any{
		"active_connections": count,
	}); err != nil {
		slog.Error("failed to persist active_connections",
			"tunnel_id", tunnelID,
			"active_connections", count,
			"error", err)
	}
}

// DecrementConnections decrements active connection count on a tunnel.
//
// Serialization contract (issue #86): mirror of IncrementConnections — the
// gauge update itself is atomic under p.mu, but callers must hold the VPN
// Service's s.mu so a concurrent select+increment cannot interleave with
// the decrement and overshoot MaxPeersPerBackend (the rekey ReplacementHook
// decrement satisfies this transitively: it fires under SessionManager.mu
// from CreateSession, whose only production call site is HandleIncomingPeer
// holding s.mu — see IncrementConnections). The floor at 0 keeps a
// mis-serialized caller from driving the gauge negative; the capacity
// invariant itself depends on the caller-side serialization, not on this
// method.
//
// Persistence (issue #96): copy-state-release-persist, exactly as
// IncrementConnections — the DB write happens after p.mu is released, with
// the same upstream-serialization and reconcile-backstop reasoning. Persist
// failures are logged, never silently dropped.
func (p *Pool) DecrementConnections(tunnelID int64) {
	p.mu.Lock()
	var (
		found     bool
		persistID int64
		count     int
	)
	if tunnel, ok := p.tunnelsByID[tunnelID]; ok {
		if tunnel.ActiveConnections > 0 {
			tunnel.ActiveConnections--
		}
		found = true
		persistID = tunnel.ID
		count = tunnel.ActiveConnections
	}
	p.mu.Unlock()
	if found {
		p.persistConnectionCount(persistID, int64(count))
	}
}

// TransferConnectionsIfActive atomically transfers an active connection count from fromTunnelID
// to toTunnelID under p.mu.Lock(). It verifies that toTunnelID exists and is active, and optionally
// validates that its StateVersion matches expectedTargetVersion (issue #289 rework).
//
// If the target tunnel is not active or its StateVersion has changed since inspection, the transfer
// is rejected without modifying either counter.
func (p *Pool) TransferConnectionsIfActive(fromTunnelID, toTunnelID int64, expectedTargetVersion ...int64) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return ErrPoolClosed
	}

	toTun, ok := p.tunnelsByID[toTunnelID]
	if !ok {
		p.mu.Unlock()
		return ErrTunnelNotFound
	}

	if !strings.EqualFold(toTun.Status, "active") {
		p.mu.Unlock()
		return fmt.Errorf("target backend tunnel %d is not active (status=%s)", toTunnelID, toTun.Status)
	}

	if len(expectedTargetVersion) > 0 && expectedTargetVersion[0] > 0 {
		if toTun.StateVersion != expectedTargetVersion[0] {
			p.mu.Unlock()
			return fmt.Errorf("target backend tunnel %d state version mismatch (expected %d, got %d)",
				toTunnelID, expectedTargetVersion[0], toTun.StateVersion)
		}
	}

	var (
		fromPersistID int64
		fromCount     int
	)
	if fromTun, ok := p.tunnelsByID[fromTunnelID]; ok {
		if fromTun.ActiveConnections > 0 {
			fromTun.ActiveConnections--
		}
		fromPersistID = fromTun.ID
		fromCount = fromTun.ActiveConnections
	}

	toTun.ActiveConnections++
	toPersistID := toTun.ID
	toCount := toTun.ActiveConnections

	p.mu.Unlock()

	if fromPersistID > 0 {
		p.persistConnectionCount(fromPersistID, int64(fromCount))
	}
	if toPersistID > 0 {
		p.persistConnectionCount(toPersistID, int64(toCount))
	}

	return nil
}

// SetConnectionCount sets a tunnel's active connections gauge to count and
// persists it. It exists for the startup reconciliation (issue #54), which
// recomputes the gauge from the authoritative vpn_sessions table; the normal
// runtime path must keep using IncrementConnections/DecrementConnections.
// On a DB persist failure the in-memory gauge is left updated while the DB
// keeps the old value — the same divergence-on-error behavior as
// IncrementConnections/DecrementConnections.
//
// Serialization contract (issue #86): the reconcile loop that calls this
// runs during startup, before Start accepts traffic, so no live
// IncrementConnections/DecrementConnections traffic can race it — the
// guarantee is ordering, not a shared lock (see the reconcile call site in
// vpn.go). If reconciliation is ever made re-entrant at runtime, the caller
// must hold the VPN Service's s.mu exactly like the runtime mutator
// callers; the gauge write itself is atomic under p.mu either way.
func (p *Pool) SetConnectionCount(ctx context.Context, tunnelID int64, count int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, ok := p.tunnelsByID[tunnelID]
	if !ok {
		return ErrTunnelNotFound
	}
	if count < 0 {
		count = 0
	}
	tunnel.ActiveConnections = count
	if p.db != nil {
		if err := p.db.UpdateBackendTunnel(ctx, tunnel.ID, map[string]any{
			"active_connections": tunnel.ActiveConnections,
		}); err != nil {
			return fmt.Errorf("failed to persist active_connections for tunnel %d: %w", tunnel.ID, err)
		}
	}
	return nil
}

// SetTunnelEndpoint updates the endpoint of a backend tunnel in memory and in the database,
// advancing StateVersion so in-flight health probes targeting the previous endpoint are fenced.
func (p *Pool) SetTunnelEndpoint(ctx context.Context, tunnelID int64, endpoint string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.setTunnelEndpointHook != nil {
		if err := p.setTunnelEndpointHook(ctx, tunnelID, endpoint); err != nil {
			return err
		}
	}

	if p.closed {
		return ErrPoolClosed
	}

	tunnel, ok := p.tunnelsByID[tunnelID]
	if !ok {
		return ErrTunnelNotFound
	}

	if p.db != nil {
		if err := p.db.UpdateBackendTunnelEndpoint(ctx, tunnel.ID, endpoint); err != nil {
			return fmt.Errorf("failed to persist backend tunnel endpoint: %w", err)
		}
	}

	tunnel.StateVersion++
	tunnel.Endpoint = endpoint
	return nil
}

// SetSetTunnelEndpointHookForTest sets a hook invoked at the start of SetTunnelEndpoint for testing.
func (p *Pool) SetSetTunnelEndpointHookForTest(fn func(ctx context.Context, tunnelID int64, endpoint string) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setTunnelEndpointHook = fn
}

// Close tears down all tunnels and cleans up resources.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}
