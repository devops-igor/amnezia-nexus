package database

import (
	"context"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// RecordPeerLifecycle records or updates a peer lifecycle tracking entry in SQLite.
func (d *DB) RecordPeerLifecycle(ctx context.Context, serverID int64, protocol, clientID, name, userID, status string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	protocol = models.NormalizeProtocol(protocol)
	if status == "" {
		status = "active"
	}
	nowStr := formatTime(time.Now().UTC())

	query := `INSERT INTO peer_lifecycle (server_id, protocol, client_id, name, user_id, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(server_id, protocol, client_id) DO UPDATE SET
			name = excluded.name,
			user_id = excluded.user_id,
			status = excluded.status,
			updated_at = excluded.updated_at`

	_, err := d.sqlDB.ExecContext(ctx, query, serverID, protocol, clientID, name, userID, status, nowStr, nowStr)
	if err != nil {
		return fmt.Errorf("failed to record peer lifecycle: %w", err)
	}
	return nil
}

// SetPeerLifecycleStatus updates the lifecycle status of a managed peer.
func (d *DB) SetPeerLifecycleStatus(ctx context.Context, serverID int64, protocol, clientID, status string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	protocol = models.NormalizeProtocol(protocol)
	nowStr := formatTime(time.Now().UTC())

	query := `UPDATE peer_lifecycle SET status = ?, updated_at = ? WHERE server_id = ? AND protocol = ? AND client_id = ?`
	_, err := d.sqlDB.ExecContext(ctx, query, status, nowStr, serverID, protocol, clientID)
	if err != nil {
		return fmt.Errorf("failed to update peer lifecycle status: %w", err)
	}
	return nil
}

// GetActivePeerIDs returns a set of client IDs for peers whose lifecycle status is active or pending.
func (d *DB) GetActivePeerIDs(ctx context.Context, serverID int64, protocol string) (map[string]bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	protocol = models.NormalizeProtocol(protocol)
	query := `SELECT client_id FROM peer_lifecycle WHERE server_id = ? AND protocol = ? AND status IN ('active', 'pending')`
	rows, err := d.sqlDB.QueryContext(ctx, query, serverID, protocol)
	if err != nil {
		return nil, fmt.Errorf("failed to query active peer IDs: %w", err)
	}
	defer rows.Close()

	activeIDs := make(map[string]bool)
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		if cid != "" {
			activeIDs[cid] = true
		}
	}
	return activeIDs, rows.Err()
}

// DeletePeerLifecycle removes a peer lifecycle record.
func (d *DB) DeletePeerLifecycle(ctx context.Context, serverID int64, protocol, clientID string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	protocol = models.NormalizeProtocol(protocol)
	query := `DELETE FROM peer_lifecycle WHERE server_id = ? AND protocol = ? AND client_id = ?`
	_, err := d.sqlDB.ExecContext(ctx, query, serverID, protocol, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete peer lifecycle: %w", err)
	}
	return nil
}

// DeletePeerLifecycleByUserID removes all peer lifecycle records associated with a user ID.
func (d *DB) DeletePeerLifecycleByUserID(ctx context.Context, userID string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := `DELETE FROM peer_lifecycle WHERE user_id = ?`
	_, err := d.sqlDB.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete peer lifecycle by user id: %w", err)
	}
	return nil
}
