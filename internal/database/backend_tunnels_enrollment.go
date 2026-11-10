package database

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const pendingEnrollmentKeyPrefix = "backend_pending_enrollment:"

func pendingEnrollmentKey(serverID int64) string {
	return fmt.Sprintf("%s%d", pendingEnrollmentKeyPrefix, serverID)
}

// SetBackendPendingEnrollment records or clears durable enrollment quarantine for a server.
func (d *DB) SetBackendPendingEnrollment(ctx context.Context, serverID int64, pending bool) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	key := pendingEnrollmentKey(serverID)
	if pending {
		query := `INSERT INTO settings (key, value) VALUES (?, '1')
			ON CONFLICT(key) DO UPDATE SET value = '1'`
		if _, err := d.sqlDB.ExecContext(ctx, query, key); err != nil {
			return fmt.Errorf("failed to record pending enrollment for server %d: %w", serverID, err)
		}
	} else {
		if _, err := d.sqlDB.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", key); err != nil {
			return fmt.Errorf("failed to delete pending enrollment for server %d: %w", serverID, err)
		}
	}
	return nil
}

// GetBackendPendingEnrollments retrieves all server IDs currently under durable enrollment quarantine.
func (d *DB) GetBackendPendingEnrollments(ctx context.Context) (map[int64]bool, error) {
	if d == nil || d.sqlDB == nil {
		return make(map[int64]bool), nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.sqlDB.QueryContext(ctx, "SELECT key FROM settings WHERE key LIKE ?", pendingEnrollmentKeyPrefix+"%")
	if err != nil {
		return nil, fmt.Errorf("failed to query pending enrollments: %w", err)
	}
	defer rows.Close()

	pending := make(map[int64]bool)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		idStr := strings.TrimPrefix(key, pendingEnrollmentKeyPrefix)
		if sid, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			pending[sid] = true
		}
	}
	return pending, rows.Err()
}

// ResetBackendTunnelForEnrollment atomically refreshes identity and invalidates
// runtime health, including for disabled rows. It preserves administrative intent.
// The version predicate fences concurrent health/admin writers; a mismatch or
// missing row is not a successful enrollment. SQL provides serialization without
// adding a mutex around I/O. Generic updates must not gain access to health fields.
func (d *DB) ResetBackendTunnelForEnrollment(ctx context.Context, id, expectedVersion int64, updates map[string]any) (bool, error) {
	clauses := []string{"status = ?", "disable_reason = ?", "latency_ms = 0", "last_health_check = NULL", "state_version = state_version + 1"}
	values := []any{models.TunnelStatusConnecting, models.DisableReasonNone}
	for col, raw := range updates {
		switch col {
		case "endpoint", "public_key", "private_key", "probe_private_key", "protocol", "protocol_params":
		default:
			return false, fmt.Errorf("invalid enrollment identity column: %s", col)
		}
		value, err := d.prepareBackendTunnelUpdateValue(col, raw)
		if err != nil {
			return false, err
		}
		clauses = append(clauses, col+" = ?")
		values = append(values, value)
	}
	values = append(values, id, expectedVersion)
	// #nosec G201 -- Column names are restricted to the identity allowlist above.
	query := fmt.Sprintf("UPDATE backend_tunnels SET %s WHERE id = ? AND state_version = ?", strings.Join(clauses, ", "))
	result, err := d.sqlDB.ExecContext(ctx, query, values...)
	if err != nil {
		return false, fmt.Errorf("failed to reset backend tunnel enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to inspect backend tunnel enrollment: %w", err)
	}
	return rows == 1, nil
}
