package database

import (
	"context"
	"errors"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// PeerChangeListener is called after a durable access change has committed.
// Implementations must read the database afresh; the notification is a hint,
// not a second peer registry.
//
// ReconcilePeers must never run synchronously on the notifying goroutine:
// production implementations enqueue serialized background work and return
// immediately (issue #391 round 4a, finding 2), so a database commit path can
// never block on runtime device I/O or re-enter runtime locks. Because the
// notification is only a hint, it reports no runtime error: a failed or
// dropped enqueue is observable on the implementation's own telemetry, and
// the periodic reconcile loop retries any drift. The commit itself is already
// durable when this method is called.
type PeerChangeListener interface {
	ReconcilePeers(context.Context) error
	ValidatePortalConfig(*models.VPNConfig) error
}

// ErrPeerRuntimeSync means the database commit succeeded but the live upstream
// device could not be confirmed synchronized. The construction-time initial
// reconciliation reports it (aborting construction); the periodic reconcile
// loop and the enqueue worker's failures surface it through peer sync status
// telemetry and retry it. The post-commit notification path no longer returns
// it: enforcement is asynchronous (issue #391 round 4a, finding 2).
var ErrPeerRuntimeSync = errors.New("durable change committed but AWG runtime synchronization failed")

// PeerRevokeKind classifies one committed durable access revocation for the
// immediate live-session teardown trigger (issue #391 round 4a, finding 3).
type PeerRevokeKind int

const (
	// PeerRevokeNone reports that the committed change revokes no access.
	PeerRevokeNone PeerRevokeKind = iota
	// PeerRevokeConnection marks a connection-level revocation: toggle to
	// disabled, delete by id, or delete by client id. clientID carries the
	// peer public key when known.
	PeerRevokeConnection
	// PeerRevokeUser marks a user-level revocation: user disable or user
	// delete. Every session of the user loses live access.
	PeerRevokeUser
)

// PeerRevokeEvent describes one committed durable access revocation. The
// database layer owns the classification because it is the only place that
// can see the connection row both before and after the commit that destroyed
// it.
type PeerRevokeEvent struct {
	// Kind classifies the revocation.
	Kind PeerRevokeKind
	// UserID is the revoked user, for a user-level revocation.
	UserID string
	// ClientID is the revoked connection's peer public key, when known.
	ClientID string
	// PortalScope reports that the revoked durable connection is a
	// PORTAL-scope connection (server_id 0, awg protocol), the ingress
	// engine's domain. It is authoritative for connection-level events: the
	// row is already gone by the time the recorder runs. For user-level
	// events the database cannot classify the user's individual sessions, so
	// it stays false and the recorder resolves scope per session.
	PortalScope bool
}

// PeerRevokeRecorder receives one event per committed durable access
// revocation, immediately after the commit and before reconciliation is
// requested. Implementations must be non-blocking: they run on database
// commit goroutines, which may hold runtime locks and must never wait on
// runtime device I/O (issue #391 round 4a, finding 2).
type PeerRevokeRecorder interface {
	RecordPeerRevoke(ctx context.Context, event PeerRevokeEvent)
}

// The revoke recorder lives beside the change listener and follows the same
// out-of-write-lock discipline.
type peerRevokeSlot struct {
	mu       sync.RWMutex
	recorder PeerRevokeRecorder
}

func (d *DB) peerRevokeSlot() *peerRevokeSlot {
	return &d.peerRevokeListener
}

// SubscribePeerRevokes installs the immediate live-teardown trigger for
// committed durable access revocations. The returned function detaches it.
// A nil database has no durable access changes to observe, so subscribing
// one is a no-op and the returned detach function is a no-op too:
// constructing a service without a database is a supported path.
func (d *DB) SubscribePeerRevokes(recorder PeerRevokeRecorder) func() {
	if d == nil {
		return func() {}
	}
	slot := d.peerRevokeSlot()
	slot.mu.Lock()
	defer slot.mu.Unlock()
	slot.recorder = recorder
	return func() {
		slot.mu.Lock()
		if slot.recorder == recorder {
			slot.recorder = nil
		}
		slot.mu.Unlock()
	}
}

// portalScopedConnection reports whether a durable connection belongs to the
// portal (server_id 0, awg), the ingress engine's domain. Sessions of
// regular server peers and legacy server tunnels are not portal-scope and are
// never torn down by the engine-aware revoke dispatcher.
func portalScopedConnection(c *models.UserConnection) bool {
	return c != nil && c.ServerID == 0 && models.NormalizeProtocol(c.Protocol) == "awg"
}

// recordPeerRevoke reports one committed access revocation to the recorder,
// if installed. It never blocks on the recorder and never fails: the commit
// is already durable when this runs, and missed immediate enforcement is
// retried by the reconciliation worker and loop.
func (d *DB) recordPeerRevoke(ctx context.Context, event PeerRevokeEvent) {
	if event.Kind == PeerRevokeNone || d == nil {
		return
	}
	slot := d.peerRevokeSlot()
	slot.mu.RLock()
	recorder := slot.recorder
	slot.mu.RUnlock()
	if recorder == nil {
		return
	}
	recorder.RecordPeerRevoke(ctx, event)
}

// The listener is kept outside DB's write lock so a reconciliation callback
// can read durable state without deadlocking on a database writer.
type peerListenerSlot struct {
	mu       sync.RWMutex
	listener PeerChangeListener
}

func (d *DB) peerListenerSlot() *peerListenerSlot {
	return &d.peerListener
}

// SubscribePeerChanges installs the one live portal peer synchronizer for a DB.
// The returned function waits for in-flight notifications before detaching it.
func (d *DB) SubscribePeerChanges(listener PeerChangeListener) (func(), error) {
	if listener == nil {
		return nil, errors.New("nil AWG peer change listener")
	}
	slot := d.peerListenerSlot()
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.listener != nil {
		return nil, errors.New("AWG peer change listener already installed")
	}
	slot.listener = listener
	return func() {
		slot.mu.Lock()
		if slot.listener == listener {
			slot.listener = nil
		}
		slot.mu.Unlock()
	}, nil
}

// notifyPeerChange requests post-commit enforcement of a durable access
// change. It NEVER runs the reconciliation inline: the listener enqueues
// serialized background work (issue #391 round 4a, finding 2), so database
// commit callers, including legacy admission running under Service.mu, never
// block on runtime device I/O or re-enter runtime locks. A dropped or failed
// enqueue is not silent: the listener implementation is required to expose it
// through its own telemetry, and the periodic reconcile loop retries the
// drift. The commit is already durable when this runs, so success here means
// "persisted"; runtime convergence is observed through peer sync status.
func (d *DB) notifyPeerChange(ctx context.Context) error {
	slot := d.peerListenerSlot()
	slot.mu.RLock()
	listener := slot.listener
	slot.mu.RUnlock()
	if listener == nil {
		return nil
	}
	// The notification target is required to be non-blocking and to report no
	// runtime error (it enqueues; enforcement is asynchronous), so its result
	// is deliberately not inspected here. A listener that does return an
	// error is a contract violation surfaced by the caller's own telemetry,
	// not by the durable commit path.
	_ = listener.ReconcilePeers(ctx)
	return nil
}

func (d *DB) validatePortalConfig(cfg *models.VPNConfig) error {
	slot := d.peerListenerSlot()
	slot.mu.RLock()
	defer slot.mu.RUnlock()
	if slot.listener != nil {
		return slot.listener.ValidatePortalConfig(cfg)
	}
	return nil
}

// CreateConnection persists a connection, then synchronizes portal peers.
func (d *DB) CreateConnection(ctx context.Context, c *models.UserConnection) (string, error) {
	id, err := d.createConnection(ctx, c)
	if err != nil || c.ServerID != 0 || models.NormalizeProtocol(c.Protocol) != "awg" {
		return id, err
	}
	return id, d.notifyPeerChange(ctx)
}

// UpdateConnection synchronizes access changes after the durable update.
func (d *DB) UpdateConnection(ctx context.Context, id string, updates map[string]any) (bool, error) {
	ok, err := d.updateConnection(ctx, id, updates)
	if err != nil || !ok || len(updates) == 0 {
		return ok, err
	}
	for _, field := range []string{"user_id", "server_id", "protocol", "client_id", "client_params"} {
		if _, changed := updates[field]; changed {
			return ok, d.notifyPeerChange(ctx)
		}
	}
	return ok, nil
}

// DeleteConnection removes the durable row, then revokes its runtime peer.
func (d *DB) DeleteConnection(ctx context.Context, id string) (bool, error) {
	conn, _ := d.GetConnection(ctx, id)
	ok, err := d.deleteConnection(ctx, id)
	if err != nil || !ok {
		return ok, err
	}
	if conn != nil {
		d.recordPeerRevoke(ctx, PeerRevokeEvent{
			Kind:        PeerRevokeConnection,
			UserID:      conn.UserID,
			ClientID:    conn.ClientID,
			PortalScope: portalScopedConnection(conn),
		})
	}
	return ok, d.notifyPeerChange(ctx)
}

// DeleteConnectionByClientID removes matching durable rows and portal access.
func (d *DB) DeleteConnectionByClientID(ctx context.Context, clientID string, serverID int64) (bool, error) {
	conn, _ := d.GetConnectionByClientID(ctx, clientID, serverID)
	ok, err := d.deleteConnectionByClientID(ctx, clientID, serverID)
	if err != nil || !ok {
		return ok, err
	}
	if conn != nil {
		d.recordPeerRevoke(ctx, PeerRevokeEvent{
			Kind:        PeerRevokeConnection,
			UserID:      conn.UserID,
			ClientID:    conn.ClientID,
			PortalScope: portalScopedConnection(conn),
		})
	}
	return ok, d.notifyPeerChange(ctx)
}

// DeleteConnectionsByUserID removes a user's rows and reconciles portal access.
func (d *DB) DeleteConnectionsByUserID(ctx context.Context, userID string) (int, error) {
	n, err := d.deleteConnectionsByUserID(ctx, userID)
	if err != nil || n == 0 {
		return n, err
	}
	return n, d.notifyPeerChange(ctx)
}

// DeleteConnectionsByServerID removes server rows and reconciles portal access.
func (d *DB) DeleteConnectionsByServerID(ctx context.Context, serverID int64) (int, error) {
	n, err := d.deleteConnectionsByServerID(ctx, serverID)
	if err != nil || n == 0 || serverID != 0 {
		return n, err
	}
	return n, d.notifyPeerChange(ctx)
}

// DeleteConnectionsByServerAndProtocol reconciles portal access after deletion.
func (d *DB) DeleteConnectionsByServerAndProtocol(ctx context.Context, serverID int64, proto string) (int, error) {
	n, err := d.deleteConnectionsByServerAndProtocol(ctx, serverID, proto)
	if err != nil || n == 0 || serverID != 0 || models.NormalizeProtocol(proto) != "awg" {
		return n, err
	}
	return n, d.notifyPeerChange(ctx)
}

// UpdateUser reconciles peers when a user access field changes. Disabling a
// user revokes access: the immediate live-session teardown runs after the
// commit (issue #391 round 4a, finding 3).
func (d *DB) UpdateUser(ctx context.Context, id string, updates map[string]any) (bool, error) {
	ok, err := d.updateUser(ctx, id, updates)
	if err != nil || !ok {
		return ok, err
	}
	for _, field := range []string{"enabled", "traffic_limit", "traffic_used", "expires_at", "expiration_date"} {
		if _, changed := updates[field]; changed {
			if field == "enabled" {
				if enabled, isBool := updates["enabled"].(bool); isBool && !enabled {
					d.recordPeerRevoke(ctx, PeerRevokeEvent{Kind: PeerRevokeUser, UserID: id})
				}
			}
			return ok, d.notifyPeerChange(ctx)
		}
	}
	return ok, nil
}

// UpdateUserAndBumpSession reconciles peers after an access change commits.
// Disabling a user revokes access: the immediate live-session teardown runs
// after the commit (issue #391 round 4a, finding 3).
func (d *DB) UpdateUserAndBumpSession(ctx context.Context, id string, updates map[string]any) (bool, int, error) {
	ok, version, err := d.updateUserAndBumpSession(ctx, id, updates)
	if err != nil || !ok {
		return ok, version, err
	}
	for _, field := range []string{"enabled", "traffic_limit", "traffic_used", "expires_at", "expiration_date"} {
		if _, changed := updates[field]; changed {
			if field == "enabled" {
				if enabled, isBool := updates["enabled"].(bool); isBool && !enabled {
					d.recordPeerRevoke(ctx, PeerRevokeEvent{Kind: PeerRevokeUser, UserID: id})
				}
			}
			return ok, version, d.notifyPeerChange(ctx)
		}
	}
	return ok, version, nil
}

// DeleteUser removes a user and reconciles any portal peer revocations.
func (d *DB) DeleteUser(ctx context.Context, id string) (bool, error) {
	ok, err := d.deleteUser(ctx, id)
	if err != nil || !ok {
		return ok, err
	}
	d.recordPeerRevoke(ctx, PeerRevokeEvent{Kind: PeerRevokeUser, UserID: id})
	return ok, d.notifyPeerChange(ctx)
}

// AddUserTraffic reconciles peers when usage crosses the access quota.
func (d *DB) AddUserTraffic(ctx context.Context, id string, rxDelta, txDelta int64) (UserTrafficTotals, error) {
	totals, err := d.addUserTraffic(ctx, id, rxDelta, txDelta)
	if err != nil || totals.Limit <= 0 {
		return totals, err
	}
	previous := totals.Used - rxDelta - txDelta
	if (previous >= totals.Limit) != (totals.Used >= totals.Limit) {
		return totals, d.notifyPeerChange(ctx)
	}
	return totals, nil
}

// ResetUserMonthlyTraffic reconciles access after a successful quota reset.
func (d *DB) ResetUserMonthlyTraffic(ctx context.Context, id string, expectedResetAt *string, snapshot UserTrafficTotals, resetAt string) (bool, error) {
	ok, err := d.resetUserMonthlyTraffic(ctx, id, expectedResetAt, snapshot, resetAt)
	if err != nil || !ok {
		return ok, err
	}
	return ok, d.notifyPeerChange(ctx)
}

// ResetUserPeriodTraffic reconciles access after a successful period reset.
func (d *DB) ResetUserPeriodTraffic(ctx context.Context, id string, expectedResetAt *string, expectedStrategy string, snapshotUsed int64, resetAt string) (bool, error) {
	ok, err := d.resetUserPeriodTraffic(ctx, id, expectedResetAt, expectedStrategy, snapshotUsed, resetAt)
	if err != nil || !ok {
		return ok, err
	}
	return ok, d.notifyPeerChange(ctx)
}

// SaveVPNConfig rejects live portal protocol changes until a controlled restart.
func (d *DB) SaveVPNConfig(ctx context.Context, cfg *models.VPNConfig) error {
	if err := d.validatePortalConfig(cfg); err != nil {
		return err
	}
	return d.saveVPNConfig(ctx, cfg)
}
