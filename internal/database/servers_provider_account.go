package database

// The write-once provider account association.
//
// A server row that records no hosting account is unknown to every inventory read,
// so the provider's view of it is never recorded. This is the one write that states
// the association, for a row created before the column existed, and it is deliberately
// a single conditional statement: the condition is the protection, not a read that a
// concurrent writer could invalidate between two statements.

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// BindServerProviderAccount records which provider account a server row belongs
// to, and only for a row that records none.
//
// The association is a one-time statement about a row created before the column
// existed, so it is write-once by construction rather than by a read followed by a
// write: a row that already records an account is left exactly as it was, whichever
// account it names. A concurrent registration or a concurrent run of the same
// association therefore cannot be overwritten between a check and a write.
//
// It reports whether this call is the one that bound the row, so a repeated run can
// report "nothing further associated" instead of counting the same row again. An
// empty account is refused: that is the absence of an association, and "binding" a
// row to nothing must not be a way to clear one.
func (d *DB) BindServerProviderAccount(ctx context.Context, id int64, accountID string) (bool, error) {
	account := strings.TrimSpace(accountID)
	if account == "" {
		return false, errors.New("refusing to associate a server with an empty provider account")
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	res, err := d.sqlDB.ExecContext(ctx,
		"UPDATE servers SET provider_account_id = ? WHERE id = ? AND (provider_account_id IS NULL OR TRIM(provider_account_id) = '')",
		account, id)
	if err != nil {
		return false, fmt.Errorf("failed to associate server %d with a provider account: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read the association result for server %d: %w", id, err)
	}
	return affected > 0, nil
}
