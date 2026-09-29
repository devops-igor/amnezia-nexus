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
// not a second peer registry. A returned error reports that the commit has
// succeeded but its runtime enforcement has not.
type PeerChangeListener interface {
	ReconcilePeers(context.Context) error
	ValidatePortalConfig(*models.VPNConfig) error
}

// ErrPeerRuntimeSync means the database commit succeeded but the live upstream
// device could not be confirmed synchronized. A later reconciliation retries.
var ErrPeerRuntimeSync = errors.New("durable change committed but AWG runtime synchronization failed")

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

func (d *DB) notifyPeerChange(ctx context.Context) error {
	slot := d.peerListenerSlot()
	slot.mu.RLock()
	defer slot.mu.RUnlock()
	if slot.listener == nil {
		return nil
	}
	if err := slot.listener.ReconcilePeers(ctx); err != nil {
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
	ok, err := d.deleteConnection(ctx, id)
	if err != nil || !ok {
		return ok, err
	}
	return ok, d.notifyPeerChange(ctx)
}

// DeleteConnectionByClientID removes matching durable rows and portal access.
func (d *DB) DeleteConnectionByClientID(ctx context.Context, clientID string, serverID int64) (bool, error) {
	ok, err := d.deleteConnectionByClientID(ctx, clientID, serverID)
	if err != nil || !ok || serverID != 0 {
		return ok, err
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

// UpdateUser reconciles peers when a user access field changes.
func (d *DB) UpdateUser(ctx context.Context, id string, updates map[string]any) (bool, error) {
	ok, err := d.updateUser(ctx, id, updates)
	if err != nil || !ok {
		return ok, err
	}
	for _, field := range []string{"enabled", "traffic_limit", "traffic_used", "expires_at", "expiration_date"} {
		if _, changed := updates[field]; changed {
			return ok, d.notifyPeerChange(ctx)
		}
	}
	return ok, nil
}

// UpdateUserAndBumpSession reconciles peers after an access change commits.
func (d *DB) UpdateUserAndBumpSession(ctx context.Context, id string, updates map[string]any) (bool, int, error) {
	ok, version, err := d.updateUserAndBumpSession(ctx, id, updates)
	if err != nil || !ok {
		return ok, version, err
	}
	for _, field := range []string{"enabled", "traffic_limit", "traffic_used", "expires_at", "expiration_date"} {
		if _, changed := updates[field]; changed {
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
