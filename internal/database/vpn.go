package database

import (
	"context"
	"crypto/rand"
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
		status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at
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
		status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at
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
		status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	res, err := d.sqlDB.ExecContext(ctx, query,
		t.ServerID,
		t.InterfaceName,
		t.PublicKey,
		encPrivKey,
		encProbeKey,
		t.Endpoint,
		t.Status,
		t.DisableReason,
		t.StateVersion,
		healthCheckStr,
		t.LatencyMS,
		t.ActiveConnections,
		createdAtStr,
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

	for col, val := range updates {
		if col == "private_key" {
			if s, ok := val.(string); ok && s != "" && !security.LooksLikeFernetToken(s) {
				enc, err := security.EncryptCredential(s, d.secretKey)
				if err != nil {
					return fmt.Errorf("failed to encrypt private key: %w", err)
				}
				val = enc
			}
		}
		if col == "probe_private_key" {
			if s, ok := val.(string); ok && s != "" && !security.LooksLikeFernetToken(s) {
				enc, err := security.EncryptCredential(s, d.secretKey)
				if err != nil {
					return fmt.Errorf("failed to encrypt probe private key: %w", err)
				}
				val = enc
			}
		}
		if col == "last_health_check" {
			if t, ok := val.(*time.Time); ok && t != nil {
				val = formatTime(*t)
			} else if t, ok := val.(time.Time); ok {
				val = formatTime(t)
			}
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
	query := `UPDATE backend_tunnels SET status = ?, latency_ms = ?, last_health_check = ?, state_version = state_version + 1 WHERE id = ? AND disable_reason != ?`

	_, err := d.sqlDB.ExecContext(ctx, query, status, latencyMS, nowStr, id, models.DisableReasonAdmin)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel status: %w", err)
	}
	return nil
}

// UpdateBackendTunnelStatusWithReason updates status, disable reason, latency, and health check timestamp, bumping state_version.
func (d *DB) UpdateBackendTunnelStatusWithReason(ctx context.Context, id int64, status, disableReason string, latencyMS int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	nowStr := time.Now().Format(time.RFC3339)
	query := `UPDATE backend_tunnels SET status = ?, disable_reason = ?, latency_ms = ?, last_health_check = ?, state_version = state_version + 1 WHERE id = ?`

	_, err := d.sqlDB.ExecContext(ctx, query, status, disableReason, latencyMS, nowStr, id)
	if err != nil {
		return fmt.Errorf("failed to update backend tunnel status with reason: %w", err)
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
		WHERE id = ? AND status = ? AND disable_reason = ? AND state_version = ?`

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
		status, disable_reason, state_version, last_health_check, latency_ms, active_connections, created_at
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

// GetVPNSessionByPeerKey retrieves an active VPN session by peer public key.
func (d *DB) GetVPNSessionByPeerKey(ctx context.Context, key string) (*models.VPNSession, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, user_id, backend_tunnel_id, peer_public_key, assigned_ip,
		connected_at, last_seen, rx_bytes, tx_bytes, status, connection_name
		FROM vpn_sessions WHERE peer_public_key = ?`

	row := d.sqlDB.QueryRowContext(ctx, query, key)
	s, err := d.scanVPNSessionRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get vpn session by peer key: %w", err)
	}
	return &s, nil
}

// GetVPNSessionByID retrieves a VPN session by its UUID. Returns nil, nil if not found.
func (d *DB) GetVPNSessionByID(ctx context.Context, id string) (*models.VPNSession, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, user_id, backend_tunnel_id, peer_public_key, assigned_ip,
		connected_at, last_seen, rx_bytes, tx_bytes, status, connection_name
		FROM vpn_sessions WHERE id = ?`

	row := d.sqlDB.QueryRowContext(ctx, query, id)
	s, err := d.scanVPNSessionRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get vpn session %s: %w", id, err)
	}
	return &s, nil
}

// GetVPNSessionsByUserID retrieves all VPN sessions for a specific user.
func (d *DB) GetVPNSessionsByUserID(ctx context.Context, userID string) ([]models.VPNSession, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, user_id, backend_tunnel_id, peer_public_key, assigned_ip,
		connected_at, last_seen, rx_bytes, tx_bytes, status, connection_name
		FROM vpn_sessions WHERE user_id = ? ORDER BY connected_at DESC`

	rows, err := d.sqlDB.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user vpn sessions: %w", err)
	}
	defer rows.Close()

	var sessions []models.VPNSession
	for rows.Next() {
		s, err := d.scanVPNSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}

	return sessions, rows.Err()
}

// GetVPNConfig retrieves the load balancing and VPN configuration from settings.
func (d *DB) GetVPNConfig(ctx context.Context) (*models.VPNConfig, error) {
	val, found, err := d.GetSettingRaw(ctx, "vpn_config")
	if err != nil {
		return nil, err
	}

	var cfg models.VPNConfig
	if !found {
		fillVPNConfigDefaults(&cfg)
		return &cfg, nil
	}

	if !val.Valid {
		return nil, fmt.Errorf("persisted vpn_config setting is SQL NULL")
	}
	trimmed := strings.TrimSpace(val.String)
	if trimmed == "" {
		return nil, fmt.Errorf("persisted vpn_config setting is empty")
	}
	if trimmed == "null" {
		return nil, fmt.Errorf("persisted vpn_config setting is JSON null")
	}

	if err := json.Unmarshal([]byte(val.String), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vpn_config JSON: %w", err)
	}

	fillVPNConfigDefaults(&cfg)
	// Obfuscation-parameter migration (generating H/S when unset and
	// persisting them) intentionally does NOT happen here: the database
	// package must not own obfuscation-parameter derivation. NewVPNService
	// in internal/vpn owns the migration so a single component derives,
	// persists, and distributes the parameters to listener and clients.
	return &cfg, nil
}

func fillVPNConfigDefaults(cfg *models.VPNConfig) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = models.LBLeastConnections
	}
	if cfg.MinRebalanceSessions <= 0 {
		cfg.MinRebalanceSessions = 8
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = "10.100.0.0/16"
	}
	if cfg.HealthThresholdMS == 0 {
		cfg.HealthThresholdMS = 500
	}
	if cfg.MaxTotalPeers == 0 {
		cfg.MaxTotalPeers = 1000
	}
	if cfg.MaxPeersPerBackend == 0 {
		cfg.MaxPeersPerBackend = 250
	}
	if cfg.AffinityTTLMinutes <= 0 {
		cfg.AffinityTTLMinutes = 30
	}
	if cfg.Weights == nil {
		cfg.Weights = make(map[int64]int)
	}
}

// SaveVPNConfig persists the VPN configuration to the settings table.
func (d *DB) SaveVPNConfig(ctx context.Context, cfg *models.VPNConfig) error {
	if cfg == nil {
		return errors.New("vpn config is nil")
	}
	return d.SetSetting(ctx, "vpn_config", cfg)
}

// CreateVPNSession records an active VPN session.
func (d *DB) CreateVPNSession(ctx context.Context, s *models.VPNSession) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if s.ID == "" {
		uuidBytes := make([]byte, 16)
		_, _ = rand.Read(uuidBytes)
		uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
		uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
		s.ID = fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:16])
	}

	if s.Status == "" {
		s.Status = "connected"
	}
	if s.ConnectedAt.IsZero() {
		s.ConnectedAt = time.Now().UTC()
	}
	if s.LastSeen.IsZero() {
		s.LastSeen = time.Now().UTC()
	}
	connectedAtStr := formatTime(s.ConnectedAt)
	lastSeenStr := formatTime(s.LastSeen)

	if s.AssignedIP != "" {
		if _, err := d.sqlDB.ExecContext(ctx, `DELETE FROM vpn_sessions WHERE assigned_ip = ? AND peer_public_key != ?`, s.AssignedIP, s.PeerPublicKey); err != nil {
			return fmt.Errorf("failed to clear conflicting assigned_ip in vpn_sessions: %w", err)
		}
	}

	query := `INSERT INTO vpn_sessions (
		id, user_id, backend_tunnel_id, peer_public_key, assigned_ip,
		connected_at, last_seen, rx_bytes, tx_bytes, status, connection_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(peer_public_key) DO UPDATE SET
		id = excluded.id,
		user_id = excluded.user_id,
		backend_tunnel_id = excluded.backend_tunnel_id,
		assigned_ip = excluded.assigned_ip,
		connected_at = excluded.connected_at,
		last_seen = excluded.last_seen,
		rx_bytes = excluded.rx_bytes,
		tx_bytes = excluded.tx_bytes,
		status = excluded.status,
		connection_name = excluded.connection_name`

	_, err := d.sqlDB.ExecContext(ctx, query,
		s.ID,
		s.UserID,
		s.BackendTunnelID,
		s.PeerPublicKey,
		s.AssignedIP,
		connectedAtStr,
		lastSeenStr,
		s.RxBytes,
		s.TxBytes,
		s.Status,
		s.ConnectionName,
	)

	if err != nil {
		return fmt.Errorf("failed to insert/update vpn session: %w", err)
	}

	return nil
}

// UpdateVPNSessionTraffic adds the given rx/tx DELTAS to the session's
// stored counters and refreshes last_seen to now. Row values are therefore
// cumulative-since-connect: each call increments rx_bytes and tx_bytes by
// its arguments rather than overwriting them (review-2 P1, issue #205).
// The single production caller is TrafficAccountant.Flush, which passes
// per-window deltas drained from its buffers.
func (d *DB) UpdateVPNSessionTraffic(ctx context.Context, sessionID string, rx, tx int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	nowStr := time.Now().Format(time.RFC3339)
	query := `UPDATE vpn_sessions SET rx_bytes = rx_bytes + ?, tx_bytes = tx_bytes + ?, last_seen = ? WHERE id = ?`

	_, err := d.sqlDB.ExecContext(ctx, query, rx, tx, nowStr, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update vpn session traffic %s: %w", sessionID, err)
	}
	return nil
}

// UpdateVPNSessionBackendTunnel reassigns a connected session to another backend
// tunnel in place, marking it "draining" (issue #44 R5: rebalancing is DB-only by
// design — the forwarder's live route is not migrated, so the session must leave
// the connected set and cannot be ping-ponged by the next cycle). The WHERE
// clause pins the update to rows still in 'connected' status, so a session that
// disconnected mid-rebalance is never resurrected; the session ID, connected_at,
// and traffic counters are all preserved.
func (d *DB) UpdateVPNSessionBackendTunnel(ctx context.Context, sessionID string, backendTunnelID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := "UPDATE vpn_sessions SET backend_tunnel_id = ?, status = 'draining' WHERE id = ? AND status = 'connected'"
	res, err := d.sqlDB.ExecContext(ctx, query, backendTunnelID, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update vpn session %s backend tunnel: %w", sessionID, err)
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("vpn session %s not found or no longer connected", sessionID)
	}
	return nil
}

// MigrateVPNSessionBackend updates a session's backend_tunnel_id while keeping status 'connected' (issue #289).
func (d *DB) MigrateVPNSessionBackend(ctx context.Context, sessionID string, backendTunnelID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	query := "UPDATE vpn_sessions SET backend_tunnel_id = ? WHERE id = ? AND status = 'connected'"
	res, err := d.sqlDB.ExecContext(ctx, query, backendTunnelID, sessionID)
	if err != nil {
		return fmt.Errorf("failed to migrate vpn session %s backend tunnel: %w", sessionID, err)
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("vpn session %s not found or no longer connected", sessionID)
	}
	return nil
}

// MigrateVPNSessionToActiveTunnel moves an orchestrator session only while its
// source is unchanged and the destination is still eligible. The tunnel check
// and assignment share one SQL statement and serialize with admin disable writes.
func (d *DB) MigrateVPNSessionToActiveTunnel(ctx context.Context, sessionID string, sourceID, targetID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	query := `UPDATE vpn_sessions SET backend_tunnel_id = ?
		WHERE id = ? AND backend_tunnel_id = ? AND status = 'connected'
		AND EXISTS (SELECT 1 FROM backend_tunnels
			WHERE id = ? AND status = 'active' AND disable_reason != ?)`
	res, err := d.sqlDB.ExecContext(ctx, query, targetID, sessionID, sourceID, targetID, models.DisableReasonAdmin)
	if err != nil {
		return fmt.Errorf("failed to migrate vpn session %s to tunnel %d: %w", sessionID, targetID, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check migration of vpn session %s: %w", sessionID, err)
	}
	if rows == 0 {
		return fmt.Errorf("vpn session %s is no longer connected to tunnel %d or target tunnel %d is unavailable", sessionID, sourceID, targetID)
	}
	return nil
}

// GetActiveVPNSessions retrieves all currently connected sessions.
func (d *DB) GetActiveVPNSessions(ctx context.Context) ([]models.VPNSession, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT id, user_id, backend_tunnel_id, peer_public_key, assigned_ip,
		connected_at, last_seen, rx_bytes, tx_bytes, status, connection_name
		FROM vpn_sessions WHERE status = 'connected' ORDER BY connected_at DESC`

	rows, err := d.sqlDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active vpn sessions: %w", err)
	}
	defer rows.Close()

	var sessions []models.VPNSession
	for rows.Next() {
		s, err := d.scanVPNSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}

	return sessions, rows.Err()
}

// GetEnrichedActiveVPNSessions returns all currently connected sessions with
// identity joins resolved: username from users, server identity via
// backend_tunnels -> servers. Rows whose joins miss fall back to 'unknown'
// and 'Server #<id>'. Read-path only (issue #189).
func (d *DB) GetEnrichedActiveVPNSessions(ctx context.Context) ([]models.EnrichedVPNSession, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT s.id, s.user_id, COALESCE(u.username, 'unknown') AS username,
		s.backend_tunnel_id, COALESCE(t.server_id, 0) AS server_id,
		COALESCE(srv.name, 'Server #' || t.server_id, 'Server #' || s.backend_tunnel_id) AS server_name,
		s.peer_public_key, s.assigned_ip, s.connected_at, s.last_seen,
		s.rx_bytes, s.tx_bytes, s.status, s.connection_name
		FROM vpn_sessions s
		LEFT JOIN users u ON u.id = s.user_id
		LEFT JOIN backend_tunnels t ON t.id = s.backend_tunnel_id
		LEFT JOIN servers srv ON srv.id = t.server_id
		WHERE s.status = 'connected'
		ORDER BY s.connected_at DESC`

	rows, err := d.sqlDB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query enriched active vpn sessions: %w", err)
	}
	defer rows.Close()

	var sessions []models.EnrichedVPNSession
	for rows.Next() {
		var s models.EnrichedVPNSession
		var connectedAt, lastSeen sql.NullString
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.Username, &s.BackendTunnelID, &s.ServerID,
			&s.ServerName, &s.PeerPublicKey, &s.AssignedIP, &connectedAt, &lastSeen,
			&s.RxBytes, &s.TxBytes, &s.Status, &s.ConnectionName,
		); err != nil {
			return nil, fmt.Errorf("failed to scan enriched vpn session: %w", err)
		}
		if connectedAt.Valid && connectedAt.String != "" {
			s.ConnectedAt = parseTime(connectedAt.String)
		}
		if lastSeen.Valid && lastSeen.String != "" {
			s.LastSeen = parseTime(lastSeen.String)
		}
		sessions = append(sessions, s)
	}

	return sessions, rows.Err()
}

// DeleteVPNSession removes a VPN session record.
func (d *DB) DeleteVPNSession(ctx context.Context, sessionID string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	_, err := d.sqlDB.ExecContext(ctx, "DELETE FROM vpn_sessions WHERE id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete vpn session %s: %w", sessionID, err)
	}
	return nil
}

// CloseVPNSession removes a closed or timed-out VPN session from the database,
// releasing its assigned_ip to prevent SQLite UNIQUE constraint collisions on IP re-lease.
func (d *DB) CloseVPNSession(ctx context.Context, sessionID string) error {
	return d.DeleteVPNSession(ctx, sessionID)
}

// InvalidateVPNSessionsForRestart removes sessions whose endpoint keys and
// forwarder routes died with the previous process. Session rows are ephemeral
// (normal disconnect also deletes them); removing every row frees the unique
// peer/IP constraints for the next handshake. Reset the persisted pool gauges
// in the same transaction so a crash cannot leave stale load-balancer counts.
// The returned count includes only rows that had been reported as connected.
func (d *DB) InvalidateVPNSessionsForRestart(ctx context.Context) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin VPN restart reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var connected int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM vpn_sessions WHERE status = 'connected'").Scan(&connected); err != nil {
		return 0, fmt.Errorf("count persisted connected VPN sessions: %w", err)
	}
	assignments, err := readVPNClientIPAssignments(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("read VPN client IP assignments: %w", err)
	}
	for _, assignment := range assignments {
		if !assignment.NeedsMigration {
			continue
		}
		if req, ok := assignment.ClientParams["config_regeneration_required"].(bool); ok && req {
			continue
		}
		if q, ok := assignment.ClientParams["quarantined_ip_collision"]; ok && q != nil && q != "" {
			continue
		}
		params, err := json.Marshal(assignment.ClientParams)
		if err != nil {
			return 0, fmt.Errorf("encode client IP assignment for connection %s: %w", assignment.ConnectionID, err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE user_connections SET client_params = ? WHERE id = ?", string(params), assignment.ConnectionID); err != nil {
			return 0, fmt.Errorf("migrate client IP assignment for connection %s: %w", assignment.ConnectionID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM vpn_sessions"); err != nil {
		return 0, fmt.Errorf("invalidate persisted VPN sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE backend_tunnels SET active_connections = 0 WHERE active_connections != 0"); err != nil {
		return 0, fmt.Errorf("reset persisted VPN connection gauges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit VPN restart reconciliation: %w", err)
	}
	return connected, nil
}

// VPNClientIPAssignment describes a durable client lease, including legacy
// leases which still exist only in the session table before restart cleanup.
type VPNClientIPAssignment struct {
	ConnectionID   string
	UserID         string
	PeerKey        string
	AssignedIP     string
	ClientParams   map[string]any
	NeedsMigration bool
	CreatedAt      time.Time
}

type vpnAssignmentQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readVPNClientIPAssignments(ctx context.Context, q vpnAssignmentQuerier) ([]VPNClientIPAssignment, error) {
	rows, err := q.QueryContext(ctx, `SELECT c.id, c.user_id, c.protocol, c.client_id, c.client_params, s.assigned_ip, c.created_at
		FROM user_connections c LEFT JOIN vpn_sessions s
		ON s.peer_public_key = c.client_id AND s.user_id = c.user_id
		WHERE c.server_id = 0 AND c.client_id IS NOT NULL AND c.client_id != ''
		ORDER BY c.created_at, c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assignments []VPNClientIPAssignment
	for rows.Next() {
		var a VPNClientIPAssignment
		var protocol string
		var params, sessionIP, createdAt sql.NullString
		if err := rows.Scan(&a.ConnectionID, &a.UserID, &protocol, &a.PeerKey, &params, &sessionIP, &createdAt); err != nil {
			return nil, err
		}
		if protocol != "" && models.NormalizeProtocol(protocol) != "awg" {
			continue
		}
		if createdAt.Valid && createdAt.String != "" {
			a.CreatedAt = parseTime(createdAt.String)
		}
		a.ClientParams = make(map[string]any)
		if params.Valid && params.String != "" {
			if err := json.Unmarshal([]byte(params.String), &a.ClientParams); err != nil {
				return nil, fmt.Errorf("decode client_params for connection %s: %w", a.ConnectionID, err)
			}
		}
		if a.ClientParams == nil {
			a.ClientParams = make(map[string]any)
		}
		if ip, ok := a.ClientParams["assigned_ip"].(string); ok && ip != "" {
			a.AssignedIP = ip
			a.NeedsMigration = false
		} else if sessionIP.Valid && sessionIP.String != "" {
			a.AssignedIP = sessionIP.String
			a.ClientParams["assigned_ip"] = a.AssignedIP
			a.NeedsMigration = true
		}
		if a.AssignedIP != "" {
			assignments = append(assignments, a)
		}
	}
	return assignments, rows.Err()
}

// GetVPNClientIPAssignments reads both persisted client leases and session-only
// legacy leases before startup invalidates the old session rows.
func (d *DB) GetVPNClientIPAssignments(ctx context.Context) ([]VPNClientIPAssignment, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return readVPNClientIPAssignments(ctx, d.sqlDB)
}

// Helper scanners

func (d *DB) scanBackendTunnel(s scannable) (models.BackendTunnel, error) {
	var t models.BackendTunnel
	var privKey, probeKey, healthCheck, createdAt sql.NullString
	var disableReason sql.NullString
	var stateVersion sql.NullInt64

	err := s.Scan(
		&t.ID,
		&t.ServerID,
		&t.InterfaceName,
		&t.PublicKey,
		&privKey,
		&probeKey,
		&t.Endpoint,
		&t.Status,
		&disableReason,
		&stateVersion,
		&healthCheck,
		&t.LatencyMS,
		&t.ActiveConnections,
		&createdAt,
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

	return t, nil
}

func (d *DB) scanBackendTunnelRow(row *sql.Row) (models.BackendTunnel, error) {
	return d.scanBackendTunnel(row)
}

func (d *DB) scanVPNSession(s scannable) (models.VPNSession, error) {
	var v models.VPNSession
	var connectedAt, lastSeen sql.NullString

	err := s.Scan(
		&v.ID,
		&v.UserID,
		&v.BackendTunnelID,
		&v.PeerPublicKey,
		&v.AssignedIP,
		&connectedAt,
		&lastSeen,
		&v.RxBytes,
		&v.TxBytes,
		&v.Status,
		&v.ConnectionName,
	)
	if err != nil {
		return v, err
	}

	if connectedAt.Valid && connectedAt.String != "" {
		v.ConnectedAt = parseTime(connectedAt.String)
	}
	if lastSeen.Valid && lastSeen.String != "" {
		v.LastSeen = parseTime(lastSeen.String)
	}

	return v, nil
}

func (d *DB) scanVPNSessionRow(row *sql.Row) (models.VPNSession, error) {
	return d.scanVPNSession(row)
}
