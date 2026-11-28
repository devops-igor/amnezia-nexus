package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// GetAllServers retrieves all server records ordered by ID, decrypting credentials and deserializing protocols.
func (d *DB) GetAllServers(ctx context.Context) ([]models.Server, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.sqlDB.QueryContext(ctx, "SELECT id, name, host, ssh_user, ssh_port, ssh_pass, ssh_key, protocols, created_at, provider_absent_at, provider_absent_account_id, provider_account_id FROM servers ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("failed to query servers: %w", err)
	}
	defer rows.Close()

	var servers []models.Server
	for rows.Next() {
		s, err := d.scanServer(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}

	return servers, rows.Err()
}

// GetServer retrieves a server by ID, decrypting credentials. Returns nil, nil if not found.
func (d *DB) GetServer(ctx context.Context, id int64) (*models.Server, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.sqlDB.QueryRowContext(ctx, "SELECT id, name, host, ssh_user, ssh_port, ssh_pass, ssh_key, protocols, created_at, provider_absent_at, provider_absent_account_id, provider_account_id FROM servers WHERE id = ?", id)
	s, err := d.scanServerRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get server %d: %w", id, err)
	}
	return &s, nil
}

// GetServerByID is an alias for GetServer.
func (d *DB) GetServerByID(ctx context.Context, id int64) (*models.Server, error) {
	return d.GetServer(ctx, id)
}

// IsServerProviderAbsent reports whether the provider's own inventory has
// confirmed that a server no longer exists. A row that is not found reports
// false: nothing is known about it, and a caller must not read "missing" as
// "provider-confirmed absent".
func (d *DB) IsServerProviderAbsent(ctx context.Context, id int64) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var observed sql.NullString
	err := d.sqlDB.QueryRowContext(ctx,
		"SELECT provider_absent_at FROM servers WHERE id = ?", id).Scan(&observed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read provider absence for server %d: %w", id, err)
	}
	return observed.Valid && strings.TrimSpace(observed.String) != "", nil
}

// ListProviderAbsentServerIDs returns the ids of the servers the provider's own
// inventory has already contradicted.
//
// It is the narrow read a selection path needs: one indexed column, no credential
// decryption, no row materialization, and no interpretation. An empty result means
// "nothing is confirmed absent", which is also what a caller must assume when the read
// fails - absence is a positive observation, never a default.
func (d *DB) ListProviderAbsentServerIDs(ctx context.Context) ([]int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT id FROM servers WHERE provider_absent_at IS NOT NULL AND TRIM(provider_absent_at) <> '' ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("failed to list provider-absent servers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to read provider-absent server id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list provider-absent servers: %w", err)
	}
	return ids, nil
}

// GetServerCount returns the total number of configured servers.
func (d *DB) GetServerCount(ctx context.Context) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.sqlDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM servers").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count servers: %w", err)
	}
	return count, nil
}

// CountServers is an alias for GetServerCount.
func (d *DB) CountServers(ctx context.Context) (int, error) {
	return d.GetServerCount(ctx)
}

// CreateServer inserts a new server record, encrypting credentials and serializing protocols.
func (d *DB) CreateServer(ctx context.Context, s *models.Server) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.insertServer(ctx, d.sqlDB, s)
}

type serverInserter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (d *DB) insertServer(ctx context.Context, db serverInserter, s *models.Server) (int64, error) {
	encPass, encKey, err := d.encryptedCredentials(s.SSHPass, s.SSHKey)
	if err != nil {
		return 0, err
	}

	cleanedProtocols := security.StripSensitiveProtocolFields(s.Protocols)
	if cleanedProtocols == nil {
		cleanedProtocols = make(map[string]any)
	}
	protoBytes, err := json.Marshal(cleanedProtocols)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal protocols JSON: %w", err)
	}

	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	createdAtStr := formatTime(s.CreatedAt)

	var res sql.Result
	if s.ID > 0 {
		res, err = db.ExecContext(ctx,
			"INSERT INTO servers (id, name, host, ssh_user, ssh_port, ssh_pass, ssh_key, protocols, created_at, provider_account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			s.ID, s.Name, s.Host, s.SSHUser, s.SSHPort, encPass, encKey, string(protoBytes), createdAtStr, s.ProviderAccountID,
		)
	} else {
		res, err = db.ExecContext(ctx,
			"INSERT INTO servers (name, host, ssh_user, ssh_port, ssh_pass, ssh_key, protocols, created_at, provider_account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			s.Name, s.Host, s.SSHUser, s.SSHPort, encPass, encKey, string(protoBytes), createdAtStr, s.ProviderAccountID,
		)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to insert server: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	s.ID = id
	return id, nil
}

// encryptedCredentials encrypts the credentials a row is inserted with. A value
// that is empty or already carries a Fernet token is passed through unchanged, so
// a caller that decrypted a stored credential does not wrap it twice.
//
// It is separate from the insert so both credentials follow one rule and the
// insert statement itself stays readable.
func (d *DB) encryptedCredentials(pass, key string) (string, string, error) {
	encPass, err := d.encryptCredentialIfNeeded(pass, "ssh password")
	if err != nil {
		return "", "", err
	}
	encKey, err := d.encryptCredentialIfNeeded(key, "ssh key")
	if err != nil {
		return "", "", err
	}
	return encPass, encKey, nil
}

func (d *DB) encryptCredentialIfNeeded(value, what string) (string, error) {
	if value == "" || security.LooksLikeFernetToken(value) {
		return value, nil
	}
	encrypted, err := security.EncryptCredential(value, d.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt %s: %w", what, err)
	}
	return encrypted, nil
}

// UpdateServer dynamically updates fields on a server, validating against the column allowlist.
func (d *DB) UpdateServer(ctx context.Context, id int64, updates map[string]any) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	fieldMap := map[string]string{
		"name":        "name",
		"host":        "host",
		"username":    "ssh_user",
		"ssh_user":    "ssh_user",
		"ssh_port":    "ssh_port",
		"password":    "ssh_pass",
		"ssh_pass":    "ssh_pass",
		"private_key": "ssh_key",
		"ssh_key":     "ssh_key",
		"protocols":   "protocols",
	}

	mapped := make(map[string]any)
	for k, v := range updates {
		col, ok := fieldMap[k]
		if !ok {
			col = k
		}
		if !allowedServerColumns[col] {
			return fmt.Errorf("unknown server column: %s", col)
		}
		mapped[col] = v
	}

	if len(mapped) == 0 {
		return nil
	}

	var setClauses []string
	var values []any

	for col, val := range mapped {
		if col == "protocols" {
			if m, ok := val.(map[string]any); ok {
				cleaned := security.StripSensitiveProtocolFields(m)
				b, err := json.Marshal(cleaned)
				if err != nil {
					return fmt.Errorf("failed to marshal protocols: %w", err)
				}
				val = string(b)
			}
		}
		if col == "ssh_pass" || col == "ssh_key" {
			strVal, _ := val.(string)
			if strVal != "" && !security.LooksLikeFernetToken(strVal) {
				enc, err := security.EncryptCredential(strVal, d.secretKey)
				if err != nil {
					return fmt.Errorf("failed to encrypt %s: %w", col, err)
				}
				val = enc
			}
		}

		setClauses = append(setClauses, fmt.Sprintf("%s = ?", col))
		values = append(values, val)
	}

	values = append(values, id)
	// #nosec G201 -- Column names are validated against allowedServerColumns allowlist
	query := fmt.Sprintf("UPDATE servers SET %s WHERE id = ?", strings.Join(setClauses, ", "))

	_, err := d.sqlDB.ExecContext(ctx, query, values...)
	if err != nil {
		return fmt.Errorf("failed to update server %d: %w", id, err)
	}
	return nil
}

// UpdateServerStats updates runtime statistics or server status metadata.
func (d *DB) UpdateServerStats(ctx context.Context, id int64, stats map[string]any) error {
	return d.UpdateServer(ctx, id, map[string]any{"protocols": stats})
}

// UpdateServerReachability updates reachability probe state.
func (d *DB) UpdateServerReachability(ctx context.Context, id int64, status models.ReachabilityStatus) error {
	d.reachabilityMu.Lock()
	defer d.reachabilityMu.Unlock()
	d.reachabilityCache[id] = status
	return nil
}

// UpdateServerReachabilityExtended updates reachability probe state with extended probe details.
func (d *DB) UpdateServerReachabilityExtended(ctx context.Context, id int64, status models.ReachabilityStatus, details map[string]any) error {
	return d.UpdateServerReachability(ctx, id, status)
}

// UpdateServerProtocols updates the protocols JSON blob for a server.
func (d *DB) UpdateServerProtocols(ctx context.Context, id int64, protocols map[string]any) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	cleaned := security.StripSensitiveProtocolFields(protocols)
	if cleaned == nil {
		cleaned = make(map[string]any)
	}
	b, err := json.Marshal(cleaned)
	if err != nil {
		return fmt.Errorf("failed to marshal protocols JSON: %w", err)
	}

	_, err = d.sqlDB.ExecContext(ctx, "UPDATE servers SET protocols = ? WHERE id = ?", string(b), id)
	if err != nil {
		return fmt.Errorf("failed to update server protocols: %w", err)
	}
	return nil
}

// UpdateServerSSHStatus updates SSH status for a server.
func (d *DB) UpdateServerSSHStatus(ctx context.Context, id int64, status string) error {
	// Status tracking
	return nil
}

// SetServerProviderAbsence records the provider's current view of a
// provider-provisioned server. A non-zero observedAt records that the provider's
// inventory confirmed the server no longer exists; a zero observedAt clears that
// state, which is what a server the provider lists again must end up with.
//
// Only the observation columns are written, together: which account the listing was read
// from is part of the observation, so a later key change is visible rather than silent.
// The row's address, credentials, sessions and reachability state are left exactly as
// they were, because this is a statement about the provider's inventory rather than a
// deletion or a health verdict.
func (d *DB) SetServerProviderAbsence(ctx context.Context, id int64, observedAt time.Time, accountID string) error {
	value, account := "", ""
	if !observedAt.IsZero() {
		value = formatTime(observedAt.UTC())
		account = strings.TrimSpace(accountID)
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if _, err := d.sqlDB.ExecContext(ctx,
		"UPDATE servers SET provider_absent_at = ?, provider_absent_account_id = ? WHERE id = ?",
		value, account, id); err != nil {
		return fmt.Errorf("failed to record provider absence for server %d: %w", id, err)
	}
	return nil
}

// The ledger's own existence record.
//
// The two methods below are the ledger siblings of SetServerProviderAbsence and live
// beside it, because they are one writer family: the same observation about the same
// provider inventory, kept on the row that owns it. The server-row record covers a
// deployment that registered a panel server. An order the provider no longer lists that
// never became a server has no such row to mark, so its observation is kept on the ledger
// entry itself and that order can be retired rather than refreshed and offered for setup
// forever.
//
// This is the only writer of the ledger's absence columns. The single-writer rule the
// absence guard states is satisfied structurally: the columns are written in this file,
// which the guard names as the store, and the gated DECISION stays in one place - the
// inventory reconciliation decides, these methods only record - so the one entry point
// for "something concluded a server is gone" does not depend on where the statement lives.
//
// Both are addressed by the provider order id, which is the ledger's identity for an
// order, and both refuse an update that matched no row: an observation about an order the
// ledger does not hold is a caller defect, not a silent no-op.

// SetGigahostOrderProviderAccount records the provider account an order was
// observed under.
//
// The association is what makes absence decidable: one account's inventory answer
// says nothing about another account's orders, so an order whose account is
// unknown is never judged. It is written only from a provider answer that named
// this order or the server it registered, never inferred from whichever
// credential happens to be configured.
func (d *DB) SetGigahostOrderProviderAccount(ctx context.Context, orderID, accountID string) error {
	orderID = strings.TrimSpace(orderID)
	accountID = strings.TrimSpace(accountID)
	if d == nil || d.sqlDB == nil || orderID == "" || accountID == "" {
		return nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return err
	}
	q := `UPDATE gigahost_orders
	      SET provider_account_id = ?, updated_at = ?
	      WHERE order_id = ? AND provider_account_id != ?`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q, accountID, time.Now().UTC().Format(time.RFC3339), orderID, accountID)
	if err != nil {
		return fmt.Errorf("failed to record the provider account of order %q: %w", orderID, err)
	}
	if _, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to confirm the provider account write for order %q: %w", orderID, err)
	}
	return nil
}

// SetGigahostOrderAbsence records one order's existence observation: absentAt is
// the instant the successful listing that omitted the order was requested, and a
// zero time clears the observation.
//
// Clearing is written together with the observation, so a row can never carry an
// absence stamp that belongs to a different account than the one currently
// recorded.
func (d *DB) SetGigahostOrderAbsence(ctx context.Context, orderID string, absentAt time.Time, accountID string) error {
	orderID = strings.TrimSpace(orderID)
	if d == nil || d.sqlDB == nil || orderID == "" {
		return nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return err
	}
	stamp := ""
	if !absentAt.IsZero() {
		stamp = absentAt.UTC().Format(time.RFC3339)
	}
	if stamp == "" {
		accountID = ""
	}
	q := `UPDATE gigahost_orders
	      SET provider_absent_at = ?, provider_absent_account_id = ?, updated_at = ?
	      WHERE order_id = ?
	        AND (provider_absent_at != ? OR provider_absent_account_id != ?)`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		stamp, strings.TrimSpace(accountID), time.Now().UTC().Format(time.RFC3339),
		orderID, stamp, strings.TrimSpace(accountID),
	)
	if err != nil {
		return fmt.Errorf("failed to record the existence state of order %q: %w", orderID, err)
	}
	if _, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to confirm the existence state write for order %q: %w", orderID, err)
	}
	return nil
}

// UpdateServerCredentials updates and encrypts SSH password and private key.
func (d *DB) UpdateServerCredentials(ctx context.Context, id int64, sshPass, sshKey string) error {
	return d.UpdateServer(ctx, id, map[string]any{
		"ssh_pass": sshPass,
		"ssh_key":  sshKey,
	})
}

// GetServerStatus returns the ReachabilityStatus of a server.
func (d *DB) GetServerStatus(ctx context.Context, id int64) (models.ReachabilityStatus, error) {
	d.reachabilityMu.RLock()
	defer d.reachabilityMu.RUnlock()

	if status, ok := d.reachabilityCache[id]; ok {
		return status, nil
	}
	return models.ReachabilityUnknown, nil
}

// ServerExists checks whether a server with the specified ID exists.
func (d *DB) ServerExists(ctx context.Context, id int64) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var dummy int
	err := d.sqlDB.QueryRowContext(ctx, "SELECT 1 FROM servers WHERE id = ?", id).Scan(&dummy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// DeleteServer deletes a server and cascades to user connections, known hosts, and backend tunnels.
func (d *DB) DeleteServer(ctx context.Context, id int64) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin delete transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, "DELETE FROM user_connections WHERE server_id = ?", id); err != nil {
		slog.Warn("failed to delete user_connections for server", "server_id", id, "error", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM known_hosts WHERE server_id = ?", id); err != nil {
		slog.Warn("failed to delete known_hosts for server", "server_id", id, "error", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM backend_tunnels WHERE server_id = ?", id); err != nil {
		slog.Warn("failed to delete backend_tunnels for server", "server_id", id, "error", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", fmt.Sprintf("backend_pending_enrollment:%d", id)); err != nil {
		slog.Warn("failed to delete pending enrollment setting for server", "server_id", id, "error", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM awg_ip_allocations WHERE server_id = ?", id); err != nil {
		slog.Warn("failed to delete awg_ip_allocations for server", "server_id", id, "error", err)
	}

	res, err := tx.ExecContext(ctx, "DELETE FROM servers WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("failed to delete server %d: %w", id, err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit delete server: %w", err)
	}

	return rowsAffected > 0, nil
}

// Internal scan helpers

type scannable interface {
	Scan(dest ...any) error
}

func (d *DB) scanServer(s scannable) (models.Server, error) {
	var srv models.Server
	var sshPass, sshKey, protoJSON, createdAt, providerAbsentAt, providerAbsentAccountID, providerAccountID sql.NullString

	err := s.Scan(
		&srv.ID,
		&srv.Name,
		&srv.Host,
		&srv.SSHUser,
		&srv.SSHPort,
		&sshPass,
		&sshKey,
		&protoJSON,
		&createdAt,
		&providerAbsentAt,
		&providerAbsentAccountID,
		&providerAccountID,
	)
	if err != nil {
		return srv, err
	}

	d.decodeServerColumns(&srv, sshPass, sshKey, protoJSON, createdAt, providerAbsentAt, providerAbsentAccountID, providerAccountID)

	d.reachabilityMu.RLock()
	if st, ok := d.reachabilityCache[srv.ID]; ok {
		srv.Status = st
	} else {
		srv.Status = models.ReachabilityUnknown
	}
	d.reachabilityMu.RUnlock()

	return srv, nil
}

// decodeServerColumns fills the server fields whose stored shape is not a plain
// value: credentials are decrypted, the protocols blob is decoded and sanitized,
// and the optional timestamps are parsed only when present.
func (d *DB) decodeServerColumns(
	srv *models.Server, sshPass, sshKey, protoJSON, createdAt, providerAbsentAt, providerAbsentAccountID, providerAccountID sql.NullString,
) {
	assignOptionalText(&srv.ProviderAbsentAt, providerAbsentAt)
	assignOptionalText(&srv.ProviderAbsentAccountID, providerAbsentAccountID)
	assignOptionalText(&srv.ProviderAccountID, providerAccountID)

	if sshPass.Valid && sshPass.String != "" {
		srv.SSHPass = security.DecryptCredentialSafe(sshPass.String, d.secretKey)
	}
	if sshKey.Valid && sshKey.String != "" {
		srv.SSHKey = security.DecryptCredentialSafe(sshKey.String, d.secretKey)
	}

	srv.Protocols = decodeServerProtocols(protoJSON)

	if createdAt.Valid && createdAt.String != "" {
		srv.CreatedAt = parseTime(createdAt.String)
	}
}

// assignOptionalText stores a nullable text column on its target when the row carried
// it, trimmed. The three provider columns are all "empty means not recorded", so they
// share one rule instead of three copies of it.
func assignOptionalText(target *string, value sql.NullString) {
	if value.Valid {
		*target = strings.TrimSpace(value.String)
	}
}

// decodeServerProtocols decodes the stored protocols blob, always returning a
// non-nil map so a caller never has to nil-check it. A blob that is absent or not
// valid JSON yields no protocols rather than an error: nothing usable can be read
// from it, and one unreadable row must not fail the whole listing.
func decodeServerProtocols(protoJSON sql.NullString) map[string]any {
	protocols := make(map[string]any)
	if protoJSON.Valid && protoJSON.String != "" {
		_ = json.Unmarshal([]byte(protoJSON.String), &protocols)
		protocols = security.StripSensitiveProtocolFields(protocols)
	}
	return protocols
}

func (d *DB) scanServerRow(row *sql.Row) (models.Server, error) {
	return d.scanServer(row)
}
