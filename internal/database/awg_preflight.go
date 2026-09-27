package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/preflight"
)

// AuditAWGMigration reads an existing SQLite database without invoking Open,
// InitSchema, defaults, credential migration, or IP collision repair. mode=ro
// prevents database writes and creation; query_only is defense in depth. A single
// transaction includes both configuration and authorization/connection rows,
// including committed WAL contents. Do not use immutable=1 on a live database.
func AuditAWGMigration(ctx context.Context, path, secret string, now time.Time) (preflight.Report, error) {
	abs, err := filepath.Abs(path)
	if err != nil || path == "" {
		return preflight.Report{}, errors.New("an existing database file path is required")
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	query := url.Values{"mode": {"ro"}, "_pragma": {"query_only(ON)", "busy_timeout(5000)"}}
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return preflight.Report{}, fmt.Errorf("open read-only preflight database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return preflight.Report{}, fmt.Errorf("begin read-only preflight snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // Always release without committing.
	snapshot, err := readAWGSnapshot(ctx, tx)
	if err != nil {
		return preflight.Report{}, err
	}
	return preflight.Validate(snapshot, secret, now), nil
}

func readAWGSnapshot(ctx context.Context, tx *sql.Tx) (preflight.Snapshot, error) {
	var snapshot preflight.Snapshot
	var config sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&config)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return snapshot, errors.New("cannot read persisted vpn_config; preflight requires an existing compatible schema")
	}
	snapshot.Config = config.String
	// A LEFT JOIN exposes orphaned owners. Do not filter by eligibility or use
	// GetConnectionByClientID (LIMIT 1): every conflicting row must be reported.
	rows, err := tx.QueryContext(ctx, `SELECT c.id, c.user_id, c.server_id, c.protocol,
		COALESCE(c.client_id, ''), COALESCE(c.client_params, ''),
		u.id, COALESCE(u.enabled, 0), COALESCE(u.traffic_limit, 0), COALESCE(u.traffic_used, 0),
		COALESCE(u.expires_at, ''), COALESCE(u.expiration_date, '')
		FROM user_connections c LEFT JOIN users u ON u.id = c.user_id
		WHERE c.server_id = 0 ORDER BY c.id`)
	if err != nil {
		return snapshot, errors.New("cannot read portal connections and owners; preflight requires an existing compatible schema (including client_params)")
	}
	defer rows.Close()
	for rows.Next() {
		var c preflight.Connection
		var u preflight.User
		var userID sql.NullString
		if err := rows.Scan(&c.ID, &c.UserID, &c.ServerID, &c.Protocol, &c.PublicKey, &c.ClientParams,
			&userID, &u.Enabled, &u.TrafficLimit, &u.TrafficUsed, &u.ExpiresAt, &u.ExpirationDate); err != nil {
			return snapshot, errors.New("cannot decode persisted portal connection or owner; no changes made")
		}
		if userID.Valid {
			c.User = &u
		}
		snapshot.Connections = append(snapshot.Connections, c)
	}
	if err := rows.Err(); err != nil {
		return snapshot, errors.New("reading preflight snapshot failed; no changes made")
	}
	return snapshot, nil
}
