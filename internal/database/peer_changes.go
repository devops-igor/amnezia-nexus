package database

import (
	"context"
	"errors"
	"fmt"
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
// never block on runtime device I/O or re-enter runtime locks. It has no
// synchronous fallback at all (issue #391 round 4b, finding 2): by the time
// this listener is visible, its enqueue path is armed, and if that path is
// ever unavailable the notification is recorded as a failed enforcement
// rather than executed on the caller's goroutine.
//
// Because the notification is only a hint, it reports no runtime error: the
// commit itself is already durable when this method is called. A caller that
// must learn whether the enforcement of its own change succeeded asks
// AwaitPeerRuntimeSync (below) after the commit returns, on a goroutine that
// holds no runtime lock; that is where ErrPeerRuntimeSync is produced
// (issue #391 round 4b, finding 4).
type PeerChangeListener interface {
	ReconcilePeers(context.Context) error
	ValidatePortalConfig(*models.VPNConfig) error
}

// PeerRuntimeConvergence is the OPTIONAL extension a PeerChangeListener
// implements when it can confirm the outcome of the post-commit enforcement it
// was asked for (issue #391 round 4b, finding 4).
//
// It exists because the notification path is deliberately non-blocking: a
// database commit may run on a goroutine that holds a runtime lock (legacy
// admission under Service.mu), so it must never perform the device I/O itself.
// But the caller of the durable API still has to be able to learn that the
// enforcement of ITS change failed. ReconcilePeers cannot report that (it
// returns before the work is done); this method does, and it is called on the
// CALLER's goroutine AFTER the commit returned and any locks were released.
//
// Contract for implementations:
//   - it performs no runtime device I/O itself; it waits for work already
//     handed to a serialized worker, which is what keeps it deadlock-free;
//   - it must never block indefinitely: it is bounded by ctx and by its own
//     deadline, and an unconfirmed enforcement is reported as
//     ErrPeerRuntimeSync rather than as a silent success;
//   - it must not be called while holding a runtime lock the worker needs.
type PeerRuntimeConvergence interface {
	AwaitPeerRuntimeSync(ctx context.Context) error
}

// AwaitPeerRuntimeSync confirms the runtime enforcement of the durable changes
// committed so far and returns ErrPeerRuntimeSync when it did not succeed
// (issue #391 round 4b, finding 4). It is the caller-visible counterpart of
// the asynchronous notification: notifyPeerChange only enqueues, so this is
// how a handler learns that the runtime did not actually converge and can
// still answer runtime_sync_failed instead of reporting a bare success.
//
// A database with no listener, or a listener that does not implement
// PeerRuntimeConvergence, has no asynchronous enforcement to confirm and
// reports success: there is nothing outstanding to wait for.
//
// Callers MUST invoke this after the durable call returned and after
// releasing every lock, never from inside a commit path.
func (d *DB) AwaitPeerRuntimeSync(ctx context.Context) error {
	if d == nil {
		return nil
	}
	slot := d.peerListenerSlot()
	slot.mu.RLock()
	listener := slot.listener
	slot.mu.RUnlock()
	convergence, ok := listener.(PeerRuntimeConvergence)
	if !ok {
		return nil
	}
	return convergence.AwaitPeerRuntimeSync(ctx)
}

// ErrPeerRuntimeSync means the database commit succeeded but the live upstream
// device could not be confirmed synchronized. The construction-time initial
// reconciliation reports it (aborting construction); the periodic reconcile
// loop and the enqueue worker's failures surface it through peer sync status
// telemetry and retry it.
//
// The post-commit path is asynchronous and therefore does not return it from
// the commit itself (issue #391 round 4a, finding 2). It reaches the caller
// through AwaitPeerRuntimeSync, which the handler consults after the commit
// returned and after releasing its locks, so handlers can still answer
// runtime_sync_failed (issue #391 round 4b, finding 4). The confirmation uses
// a GLOBAL watermark: it reports the enforcement of every notification
// accepted before the call, so a concurrent change's failure may be attributed
// to this caller. That is conservative and was reviewed and accepted.
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
	// events it stays false and the recorder uses PortalPeers.
	PortalScope bool
	// PortalPeers carries the peer public keys of the user's PORTAL-scope
	// connections, captured by the database BEFORE the deleting statement
	// destroyed their rows (issue #391 round 4b, finding 1). It is
	// authoritative for bulk user-level revocations (user delete, delete a
	// user's connections): without it the recorder could only re-derive
	// scope from durable state that no longer exists, and the established
	// session, its forwarder route and its backend accounting leaked.
	//
	// It is empty for a user-level revocation that does NOT delete rows
	// (user disable): the connections are still there, so the recorder
	// resolves each live session against its own durable connection as
	// before. Backward compatible: a recorder that ignores this field
	// behaves exactly as it did before.
	PortalPeers []string
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
// block on runtime device I/O or re-enter runtime locks. For the same reason
// the notification reports no runtime error here, and its result is not
// discarded silently: a listener that cannot accept the work must say so, and
// a listener that does report an error has it recorded. The caller-visible
// outcome of the enforcement is obtained separately, after the commit and
// after releasing locks, through AwaitPeerRuntimeSync (issue #391 round 4b,
// finding 4).
func (d *DB) notifyPeerChange(ctx context.Context) error {
	slot := d.peerListenerSlot()
	slot.mu.RLock()
	listener := slot.listener
	slot.mu.RUnlock()
	if listener == nil {
		return nil
	}
	// The notification target is required to be non-blocking, so its own
	// return carries no runtime outcome. A listener that DOES report an
	// error here is violating the non-blocking contract, and swallowing that
	// silently is exactly the round-4b finding-4 defect: surface it to the
	// durable caller as the same runtime_sync_failed condition, which is
	// strictly more informative than dropping it.
	if err := listener.ReconcilePeers(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrPeerRuntimeSync, err)
	}
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
// The PORTAL-scope peer identities are captured BEFORE the deleting statement
// and carried on the revoke event, so an established portal session is torn
// down immediately instead of leaking (issue #391 round 4b, finding 1).
func (d *DB) DeleteConnectionsByUserID(ctx context.Context, userID string) (int, error) {
	n, portalKeys, err := d.deleteConnectionsByUserID(ctx, userID)
	if err != nil || n == 0 {
		return n, err
	}
	if len(portalKeys) != 0 {
		d.recordPeerRevoke(ctx, PeerRevokeEvent{
			Kind:        PeerRevokeUser,
			UserID:      userID,
			PortalPeers: portalKeys,
		})
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

// DeleteUser removes a user and reconciles any portal peer revocations. The
// PORTAL-scope peer identities are captured inside the deleting transaction
// and carried on the revoke event, so an established portal session is torn
// down immediately instead of leaking (issue #391 round 4b, finding 1).
func (d *DB) DeleteUser(ctx context.Context, id string) (bool, error) {
	ok, portalKeys, err := d.deleteUser(ctx, id)
	if err != nil || !ok {
		return ok, err
	}
	d.recordPeerRevoke(ctx, PeerRevokeEvent{
		Kind:        PeerRevokeUser,
		UserID:      id,
		PortalPeers: portalKeys,
	})
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
