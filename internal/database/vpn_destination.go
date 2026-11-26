package database

import (
	"context"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// CommitVPNSessionDestination serializes a forward placement with inventory
// writes. The durable row, when present, is written before publish; a refusal or
// write error never calls publish. A mark committed first therefore prevents
// both effects, and a later mark observes an already-held placement.
//
// publish must only change in-memory state: no database calls, network I/O or
// re-entry into this method. The caller owns topology serialization. This is an
// ordering guarantee, not a transaction across SQLite and process memory;
// restart invalidates all routing sessions before serving traffic.
func (d *DB) CommitVPNSessionDestination(ctx context.Context, targetID int64, row *models.VPNSession, publish func()) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	absent, err := d.backendTunnelServerAbsent(ctx, targetID)
	if err != nil {
		return fmt.Errorf("read destination backend %d: %w", targetID, err)
	}
	if absent {
		return fmt.Errorf("%w: backend tunnel %d", ErrDestinationProviderAbsent, targetID)
	}
	if row != nil {
		if row.BackendTunnelID != targetID {
			return fmt.Errorf("session destination does not match backend %d", targetID)
		}
		if err := d.createVPNSession(ctx, row); err != nil {
			return err
		}
	}
	publish()
	return nil
}
