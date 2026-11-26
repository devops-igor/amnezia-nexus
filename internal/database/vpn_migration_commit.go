package database

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CommitVPNSessionMigration keeps inventory commits outside the connected-row
// update and its fallible memory publication. The caller pins session and pool
// identity before entry. publish must not acquire either owner lock or perform
// database, logging or network I/O. A failure restores the previously held row
// without applying a forward-destination guard to compensation.
func (d *DB) CommitVPNSessionMigration(ctx context.Context, sessionID string, sourceID, targetID int64, publish func() error) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	absent, err := d.backendTunnelServerAbsent(ctx, targetID)
	if err != nil {
		return fmt.Errorf("read migration destination %d: %w", targetID, err)
	}
	if absent {
		return fmt.Errorf("%w: backend tunnel %d", ErrDestinationProviderAbsent, targetID)
	}
	if err := d.migrateVPNSessionBackend(ctx, sessionID, targetID); err != nil {
		return err
	}
	if err := publish(); err != nil {
		restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return errors.Join(err, d.migrateVPNSessionBackend(restoreCtx, sessionID, sourceID))
	}
	return nil
}
