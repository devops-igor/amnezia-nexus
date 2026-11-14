package database

import (
	"context"
	"fmt"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// BindKnownHostFingerprint pins a deployment identity without replacing a pin
// established concurrently. SQL's conflict predicate makes first-writer wins
// atomic across DB handles/processes, not just this process's mutex.
func (d *DB) BindKnownHostFingerprint(ctx context.Context, serverID int64, fingerprint string) error {
	if fingerprint == "" {
		return fmt.Errorf("empty SSH host identity")
	}
	res, err := d.sqlDB.ExecContext(ctx, `INSERT INTO known_hosts (server_id, fingerprint) VALUES (?, ?)
 ON CONFLICT(server_id) DO UPDATE SET fingerprint = excluded.fingerprint
 WHERE known_hosts.fingerprint = excluded.fingerprint`, serverID, fingerprint)
	if err != nil {
		return fmt.Errorf("bind SSH host identity: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("SSH host identity changed concurrently for server %d", serverID)
	}
	return nil
}

// CreateServerWithFingerprint publishes the server and pin in one transaction.
// A deployment server must not be observable before its trust pin exists.
func (d *DB) CreateServerWithFingerprint(ctx context.Context, s *models.Server, fingerprint string) (int64, error) {
	if fingerprint == "" {
		return 0, fmt.Errorf("empty SSH host identity")
	}
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	candidate := *s
	id, err := d.insertServer(ctx, tx, &candidate)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO known_hosts (server_id, fingerprint) VALUES (?, ?)", id, fingerprint); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.ID = id
	s.CreatedAt = candidate.CreatedAt
	return id, nil
}
