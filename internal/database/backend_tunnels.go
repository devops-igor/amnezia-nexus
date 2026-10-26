package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// GetBackendTunnels retrieves all backend AWG tunnel definitions.
func (d *DB) GetBackendTunnels(ctx context.Context) ([]models.BackendTunnel, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, server_id, interface_name, public_key, private_key, probe_private_key, endpoint,
		enabled, status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at,
		protocol, protocol_params
		FROM backend_tunnels ORDER BY id`

	rows, err := d.sqlDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query backend tunnels: %w", err)
	}
	defer rows.Close()

	var tunnels []models.BackendTunnel
	for rows.Next() {
		t, err := d.scanBackendTunnel(rows)
		if err != nil {
			return nil, err
		}
		tunnels = append(tunnels, t)
	}

	return tunnels, rows.Err()
}

// GetAllBackendTunnels is an alias for GetBackendTunnels.
func (d *DB) GetAllBackendTunnels(ctx context.Context) ([]models.BackendTunnel, error) {
	return d.GetBackendTunnels(ctx)
}

// GetBackendTunnel retrieves a backend tunnel by ID. Returns nil, nil if not found.
func (d *DB) GetBackendTunnel(ctx context.Context, id int64) (*models.BackendTunnel, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, server_id, interface_name, public_key, private_key, probe_private_key, endpoint,
		enabled, status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at,
		protocol, protocol_params
		FROM backend_tunnels WHERE id = ?`

	row := d.sqlDB.QueryRowContext(ctx, query, id)
	t, err := d.scanBackendTunnelRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get backend tunnel %d: %w", id, err)
	}
	return &t, nil
}

// GetBackendTunnelByID is an alias for GetBackendTunnel.
func (d *DB) GetBackendTunnelByID(ctx context.Context, id int64) (*models.BackendTunnel, error) {
	return d.GetBackendTunnel(ctx, id)
}

// CreateBackendTunnel inserts a new backend tunnel, encrypting the private key at rest.
func (d *DB) CreateBackendTunnel(ctx context.Context, t *models.BackendTunnel) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	encPrivKey := t.PrivateKey
	if encPrivKey != "" && !security.LooksLikeFernetToken(encPrivKey) {
		ep, err := security.EncryptCredential(encPrivKey, d.secretKey)
		if err != nil {
			return 0, fmt.Errorf("failed to encrypt backend tunnel private key: %w", err)
		}
		encPrivKey = ep
	}

	encProbeKey := t.ProbePrivateKey
	if encProbeKey != "" && !security.LooksLikeFernetToken(encProbeKey) {
		ep, err := security.EncryptCredential(encProbeKey, d.secretKey)
		if err != nil {
			return 0, fmt.Errorf("failed to encrypt backend tunnel probe private key: %w", err)
		}
		encProbeKey = ep
	}

	if t.Protocol == "" {
		t.Protocol = models.ProtocolAWG
	}

	encProtoParams := string(t.ProtocolParams)
	if encProtoParams != "" && !security.LooksLikeFernetToken(encProtoParams) {
		ep, err := security.EncryptCredential(encProtoParams, d.secretKey)
		if err != nil {
			return 0, fmt.Errorf("failed to encrypt backend tunnel protocol params: %w", err)
		}
		encProtoParams = ep
	}

	if !t.Enabled && t.DisableReason != models.DisableReasonAdmin {
		// Callers written before issue #90 did not populate Enabled. Preserve
		// the historical default: a newly created backend is administratively enabled.
		t.Enabled = true
	}
	if t.Status == "" {
		t.Status = "connecting"
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	createdAtStr := formatTime(t.CreatedAt)
	healthCheckStr := formatTimePtr(t.LastHealthCheck)

	if t.StateVersion <= 0 {
		t.StateVersion = 1
	}

	query := `INSERT INTO backend_tunnels (
		server_id, interface_name, public_key, private_key, probe_private_key, endpoint,
		enabled, status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at,
		protocol, protocol_params
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := d.sqlDB.ExecContext(ctx, query,
		t.ServerID,
		t.InterfaceName,
		t.PublicKey,
		encPrivKey,
		encProbeKey,
		t.Endpoint,
		t.Enabled,
		t.Status,
		t.DisableReason,
		t.StateVersion,
		healthCheckStr,
		t.LatencyMS,
		t.ActiveConnections,
		createdAtStr,
		t.Protocol,
		encProtoParams,
	)

	if err != nil {
		return 0, fmt.Errorf("failed to insert backend tunnel: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	t.ID = id
	return id, nil
}

// prepareBackendTunnelUpdateValue transforms and encrypts column update values.
func (d *DB) prepareBackendTunnelUpdateValue(col string, val any) (any, error) {
	switch col {
	case "private_key", "probe_private_key":
		if s, ok := val.(string); ok && s != "" && !security.LooksLikeFernetToken(s) {
			enc, err := security.EncryptCredential(s, d.secretKey)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt %s: %w", col, err)
			}
			return enc, nil
		}
		return val, nil
	case "protocol_params":
		var rawStr string
		switch v := val.(type) {
		case string:
			rawStr = v
		case []byte:
			rawStr = string(v)
		case json.RawMessage:
			rawStr = string(v)
		default:
			if b, err := json.Marshal(v); err == nil {
				rawStr = string(b)
			}
		}
		if rawStr != "" && !security.LooksLikeFernetToken(rawStr) {
			enc, err := security.EncryptCredential(rawStr, d.secretKey)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt protocol params: %w", err)
			}
			return enc, nil
		}
		return rawStr, nil
	case "last_health_check":
		if t, ok := val.(*time.Time); ok && t != nil {
			return formatTime(*t), nil
		} else if t, ok := val.(time.Time); ok {
			return formatTime(t), nil
		}
		return val, nil
	default:
		return val, nil
	}
}

// UpdateBackendTunnel dynamically updates fields on a backend tunnel record.
func (d *DB) UpdateBackendTunnel(ctx context.Context, id int64, updates map[string]any) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	for k := range updates {
		if !allowedBackendTunnelColumns[k] {
			return fmt.Errorf("unknown backend tunnel column: %s", k)
		}
	}

	if len(updates) == 0 {
		return nil
	}

	var setClauses []string
	var values []any

	for col, rawVal := range updates {
		val, err := d.prepareBackendTunnelUpdateValue(col, rawVal)
		if err != nil {
			return err
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = ?", col))
		values = append(values, val)
	}

	values = append(values, id)
	// #nosec G201 -- Column names are validated against allowedBackendTunnelColumns allowlist
	query := fmt.Sprintf("UPDATE backend_tunnels SET %s WHERE id = ?", strings.Join(setClauses, ", "))

	res, err := d.sqlDB.ExecContext(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel %d: %w", id, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected for backend tunnel %d: %w", id, err)
	}
	if rows == 0 {
		return fmt.Errorf("backend tunnel %d not found", id)
	}

	return nil
}

// UpdateBackendTunnelStatus updates status, latency, and health check timestamp, bumping state_version.
// Protects administratively disabled tunnels from being overwritten.
func (d *DB) UpdateBackendTunnelStatus(ctx context.Context, id int64, status string, latencyMS int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	nowStr := time.Now().Format(time.RFC3339)
	query := `UPDATE backend_tunnels SET status = ?, latency_ms = ?, last_health_check = ?, state_version = state_version + 1 WHERE id = ? AND enabled = 1`

	_, err := d.sqlDB.ExecContext(ctx, query, status, latencyMS, nowStr, id)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel status: %w", err)
	}
	return nil
}

// UpdateBackendTunnelStatusWithReason updates status, disable reason, latency, and health check timestamp, bumping state_version.
func (d *DB) UpdateBackendTunnelStatusWithReason(ctx context.Context, id int64, status, disableReason string, latencyMS int64) error {
	if disableReason == models.DisableReasonAdmin {
		return errors.New("administrative backend state must be changed with UpdateBackendTunnelEnabled")
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	nowStr := time.Now().Format(time.RFC3339)
	query := `UPDATE backend_tunnels SET status = ?, disable_reason = ?, latency_ms = ?, last_health_check = ?, state_version = state_version + 1 WHERE id = ? AND enabled = 1`

	_, err := d.sqlDB.ExecContext(ctx, query, status, disableReason, latencyMS, nowStr, id)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel status with reason: %w", err)
	}
	return nil
}

// UpdateBackendTunnelEnabled updates administrative intent without changing runtime health.
// disableReason is retained as provenance metadata; status, latency, and last_health_check are untouched.
func (d *DB) UpdateBackendTunnelEnabled(ctx context.Context, id int64, enabled bool, disableReason string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := `UPDATE backend_tunnels SET enabled = ?, disable_reason = ?, state_version = state_version + 1 WHERE id = ?`
	_, err := d.sqlDB.ExecContext(ctx, query, enabled, disableReason, id)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel administrative state: %w", err)
	}
	// Match the existing backend update/delete contract: an already-missing
	// row is a successful no-op. This is required by DeleteBackend's drift
	// cleanup path, which may intentionally operate on an in-memory tunnel
	// whose DB row has already disappeared.
	return nil
}

// ResetEnabledBackendTunnelHealthForStartup clears persisted runtime-health
// claims for administratively enabled backends. Administrative intent is
// preserved, while health becomes unknown until the startup probe establishes
// a fresh result.
func (d *DB) ResetEnabledBackendTunnelHealthForStartup(ctx context.Context) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := `UPDATE backend_tunnels
		SET status = ?, disable_reason = ?, latency_ms = 0, last_health_check = NULL,
		    state_version = state_version + 1
		WHERE enabled = 1`
	if _, err := d.sqlDB.ExecContext(ctx, query, models.TunnelStatusConnecting, models.DisableReasonNone); err != nil {
		return fmt.Errorf("failed to reset enabled backend health for startup: %w", err)
	}
	return nil
}

// UpdateBackendTunnelEndpoint updates the endpoint of a backend tunnel and increments its state_version.
func (d *DB) UpdateBackendTunnelEndpoint(ctx context.Context, id int64, endpoint string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := `UPDATE backend_tunnels SET endpoint = ?, state_version = state_version + 1 WHERE id = ?`
	_, err := d.sqlDB.ExecContext(ctx, query, endpoint, id)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel endpoint: %w", err)
	}
	return nil
}

// CompareAndSwapTunnelStatus conditionally updates tunnel status if the current status,
// disable reason, and state version match expected values.
// Returns true if a row was updated, false if state had changed or was not matched.
func (d *DB) CompareAndSwapTunnelStatus(ctx context.Context, id int64, expectedStatus, expectedReason string, expectedVersion int64, newStatus, newReason string, latencyMS int64) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	nowStr := time.Now().Format(time.RFC3339)
	query := `UPDATE backend_tunnels SET status = ?, disable_reason = ?, latency_ms = ?, last_health_check = ?, state_version = state_version + 1
		WHERE id = ? AND enabled = 1 AND status = ? AND disable_reason = ? AND state_version = ?`

	res, err := d.sqlDB.ExecContext(ctx, query, newStatus, newReason, latencyMS, nowStr, id, expectedStatus, expectedReason, expectedVersion)
	if err != nil {
		return false, fmt.Errorf("failed to execute CAS update on backend tunnel %d: %w", id, err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to inspect rows affected on CAS update %d: %w", id, err)
	}
	return rowsAffected > 0, nil
}

// DeleteBackendTunnel removes a backend tunnel record.
func (d *DB) DeleteBackendTunnel(ctx context.Context, id int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	_, err := d.sqlDB.ExecContext(ctx, "DELETE FROM backend_tunnels WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete backend tunnel %d: %w", id, err)
	}
	return nil
}

// GetBackendTunnelByServerID retrieves a backend tunnel by its server_id. Returns nil, nil if not found.
func (d *DB) GetBackendTunnelByServerID(ctx context.Context, serverID int64) (*models.BackendTunnel, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, server_id, interface_name, public_key, private_key, probe_private_key, endpoint,
		enabled, status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at,
		protocol, protocol_params
		FROM backend_tunnels WHERE server_id = ?`

	row := d.sqlDB.QueryRowContext(ctx, query, serverID)
	t, err := d.scanBackendTunnelRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get backend tunnel for server %d: %w", serverID, err)
	}
	return &t, nil
}

// Helper scanners

func (d *DB) scanBackendTunnel(s scannable) (models.BackendTunnel, error) {
	var t models.BackendTunnel
	var privKey, probeKey, healthCheck, createdAt sql.NullString
	var disableReason sql.NullString
	var stateVersion sql.NullInt64
	var protocol, protocolParams sql.NullString

	err := s.Scan(
		&t.ID,
		&t.ServerID,
		&t.InterfaceName,
		&t.PublicKey,
		&privKey,
		&probeKey,
		&t.Endpoint,
		&t.Enabled,
		&t.Status,
		&disableReason,
		&stateVersion,
		&healthCheck,
		&t.LatencyMS,
		&t.ActiveConnections,
		&createdAt,
		&protocol,
		&protocolParams,
	)
	if err != nil {
		return t, err
	}

	if disableReason.Valid {
		t.DisableReason = disableReason.String
	}
	if stateVersion.Valid && stateVersion.Int64 > 0 {
		t.StateVersion = stateVersion.Int64
	} else {
		t.StateVersion = 1
	}

	if privKey.Valid && privKey.String != "" {
		t.PrivateKey = security.DecryptCredentialSafe(privKey.String, d.secretKey)
	}
	if probeKey.Valid && probeKey.String != "" {
		t.ProbePrivateKey = security.DecryptCredentialSafe(probeKey.String, d.secretKey)
	}
	if healthCheck.Valid && healthCheck.String != "" {
		ht := parseTime(healthCheck.String)
		if !ht.IsZero() {
			t.LastHealthCheck = &ht
		}
	}
	if createdAt.Valid && createdAt.String != "" {
		t.CreatedAt = parseTime(createdAt.String)
	}

	if protocol.Valid && protocol.String != "" {
		t.Protocol = protocol.String
	} else {
		t.Protocol = models.ProtocolAWG
	}
	if protocolParams.Valid && protocolParams.String != "" {
		if security.LooksLikeFernetToken(protocolParams.String) {
			dec := security.DecryptCredentialSafe(protocolParams.String, d.secretKey)
			if dec != "" {
				t.ProtocolParams = json.RawMessage(dec)
			}
		} else {
			t.ProtocolParams = json.RawMessage(protocolParams.String)
		}
	}

	return t, nil
}

func (d *DB) scanBackendTunnelRow(row *sql.Row) (models.BackendTunnel, error) {
	return d.scanBackendTunnel(row)
}
