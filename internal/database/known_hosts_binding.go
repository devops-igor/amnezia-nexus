package database

import (
	"context"
	"database/sql"
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
//
// It is the order-free form of CreateDeployedServer: same transaction, same pin, no
// ledger question. Callers that create a server on behalf of a gigahost order must use
// CreateDeployedServer, which additionally refuses when that order has ended.
func (d *DB) CreateServerWithFingerprint(ctx context.Context, s *models.Server, fingerprint string) (int64, error) {
	return d.createServerRow(ctx, s, fingerprint, "")
}

// createServerRow inserts the row and its pin in one transaction, refusing when orderID
// names an order the panel has recorded as over. An empty orderID asks no question, which
// is the pre-existing behavior for a server created outside the onboarding path.
func (d *DB) createServerRow(
	ctx context.Context, s *models.Server, fingerprint, orderID string,
) (int64, error) {
	if d == nil || d.sqlDB == nil {
		return 0, fmt.Errorf("database not available")
	}
	if fingerprint == "" {
		return 0, fmt.Errorf("empty SSH host identity")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

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
	// The ledger question is asked inside this transaction, after the row is prepared and
	// before anything commits, so a retirement committed at any point before this commit is
	// visible to it and a refusal leaves neither a server row nor a pin behind.
	if err := d.registrationRefusedLocked(ctx, tx, orderID); err != nil {
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

// registrationRefusedLocked asks, inside the registering transaction, whether the order this
// row is being created for has ended. The caller holds the database write mutex and owns tx.
//
// An empty order means no commitment was named - the calls outside the onboarding path - and
// those keep the pre-existing behavior. A read failure is returned rather than treated as
// consent, because the caller is about to make a deployment visible in the panel.
func (d *DB) registrationRefusedLocked(ctx context.Context, tx *sql.Tx, orderID string) error {
	if orderID == "" {
		return nil
	}
	ended, err := gigahostOrderEndedFrom(ctx, tx, orderID)
	if err != nil {
		return err
	}
	if ended {
		return fmt.Errorf("%w: order %s", ErrOrderEndedBeforeRegistration, orderID)
	}
	return nil
}
