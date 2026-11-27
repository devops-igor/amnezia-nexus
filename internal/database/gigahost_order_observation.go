package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrGigahostObservationRetired means a newer affirmative repair owns the row.
var ErrGigahostObservationRetired = errors.New("gigahost order observation retired")

// UpdateGigahostOrderObservation commits the status and its repair evidence together,
// only if no other reader repaired the order since this observation began.
func (d *DB) UpdateGigahostOrderObservation(ctx context.Context, order *models.GigahostOrder, observedRepair *time.Time) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	return d.updateGigahostOrder(ctx, order, observedRepair, true)
}

func gigahostRepairTimeValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseGigahostRepairTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil
	}
	return &parsed
}
