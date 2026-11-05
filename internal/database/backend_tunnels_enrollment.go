package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

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
