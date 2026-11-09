package database

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func seedReleaseSnapshot(t *testing.T, db *DB) models.GigahostOrder {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	o := models.GigahostOrder{OrderID: "10001", ServerID: 7, Status: "ready",
		PlanID: 202, RegionID: 2, HourlyPriceNOK: 0.057, PriceID: 666,
		MonthlyCapNOK: 41, Currency: "NOK", CreatedAt: now, UpdatedAt: now}
	if err := db.InsertGigahostOrder(context.Background(), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// Every field that can change the financial/lifecycle meaning is compared, not
// just the provider identifiers. Writes deliberately preserve updated_at so the
// timestamp alone cannot accidentally make these tests pass.
func TestGigahostReleaseSnapshotFields(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"order", `UPDATE gigahost_orders SET order_id = '10002' WHERE id = ?`},
		{"server", `UPDATE gigahost_orders SET server_id = 8 WHERE id = ?`},
		{"status", `UPDATE gigahost_orders SET status = 'active' WHERE id = ?`},
		{"plan", `UPDATE gigahost_orders SET plan_id = 203 WHERE id = ?`},
		{"region", `UPDATE gigahost_orders SET region_id = 3 WHERE id = ?`},
		{"hourly", `UPDATE gigahost_orders SET hourly_price_nok = 0.15 WHERE id = ?`},
		{"address", `UPDATE gigahost_orders SET assigned_ip = '192.0.2.1' WHERE id = ?`},
		{"created", `UPDATE gigahost_orders SET created_at = '2030-01-01T00:00:00Z' WHERE id = ?`},
		{"updated_subsecond", `UPDATE gigahost_orders SET updated_at = updated_at || '.changed' WHERE id = ?`},
		{"price", `UPDATE gigahost_orders SET price_id = 667 WHERE id = ?`},
		{"cap", `UPDATE gigahost_orders SET monthly_cap_nok = 59 WHERE id = ?`},
		{"currency", `UPDATE gigahost_orders SET currency = 'EUR' WHERE id = ?`},
		{"release_reason", `UPDATE gigahost_orders SET release_reason = 'changed' WHERE id = ?`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := setupTestDB(t)
			o := seedReleaseSnapshot(t, db)
			ctx := context.Background()
			if _, err := db.ExecContext(ctx, tc.query, o.ID); err != nil {
				t.Fatal(err)
			}
			if err := db.ReleaseGigahostOrderIfCurrent(ctx, o.ID, o, "provider_terminated", "old observation"); !errors.Is(err, ErrGigahostOrderChanged) {
				t.Fatalf("release = %v, want stale", err)
			}
			after, err := db.GetGigahostOrderByID(ctx, o.ID)
			if err != nil || after == nil || after.ReleasedAt != "" {
				t.Fatalf("row = %+v, %v", after, err)
			}
			audit, err := db.ListGigahostOrderAudit(ctx, o.ID)
			if err != nil || len(audit) != 0 {
				t.Fatalf("audit = %+v, %v", audit, err)
			}
		})
	}
}

func TestGigahostReleaseConcurrentAuditExactlyOnce(t *testing.T) {
	db, _ := setupTestDB(t)
	o := seedReleaseSnapshot(t, db)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			results <- db.ReleaseGigahostOrderIfCurrent(ctx, o.ID, o, "provider_terminated", "same observation")
		})
	}
	wg.Wait()
	close(results)
	var success, repeated int
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrGigahostOrderAlreadyReleased):
			repeated++
		default:
			t.Fatalf("release: %v", err)
		}
	}
	if success != 1 || repeated != 1 {
		t.Fatalf("success=%d repeated=%d", success, repeated)
	}
	audit, err := db.ListGigahostOrderAudit(ctx, o.ID)
	if err != nil || len(audit) != 1 || audit[0].Reason != "provider_terminated" {
		t.Fatalf("audit = %+v, %v", audit, err)
	}
}

func TestGigahostReleaseRequiresExplicitSnapshot(t *testing.T) {
	db, _ := setupTestDB(t)
	o := seedReleaseSnapshot(t, db)
	ctx := context.Background()
	if err := db.ReleaseGigahostOrderIfCurrent(ctx, o.ID, ReleaseExpectation{}, "provider_terminated", "empty observation"); !errors.Is(err, ErrGigahostOrderChanged) {
		t.Fatalf("empty snapshot = %v, want stale", err)
	}
	if err := db.ReleaseGigahostOrderIfCurrent(ctx, o.ID, o, "", "no reason"); err == nil {
		t.Fatal("empty reason accepted")
	}
	if err := db.ReleaseGigahostOrderIfCurrent(ctx, o.ID+1, o, "provider_terminated", "missing row"); err == nil {
		t.Fatal("missing row accepted")
	}
	var missing *DB
	if err := missing.ReleaseGigahostOrderIfCurrent(ctx, o.ID, o, "provider_terminated", "no handle"); err == nil {
		t.Fatal("nil handle accepted")
	}
}
