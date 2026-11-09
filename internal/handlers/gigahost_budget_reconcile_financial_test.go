package handlers

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// Mutate durable state during the provider lookup, after the handler's ledger
// read and before its release transaction. No timing or test-only production
// hook is needed to reproduce a concurrent worker's write.
func TestFinancialReleaseStaleSnapshotBlocksPurchase(t *testing.T) {
	for _, field := range []string{"status", "server_zero_to_known", "order_zero_to_known", "monthly_cap", "updated_at"} {
		t.Run(field, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := context.Background()
			if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
				t.Fatal(err)
			}
			order := GigahostOrderRecord{OrderID: "10001", ServerID: 7, Status: "ready",
				PlanID: 202, RegionID: 2, MonthlyCapNOK: 41, Currency: "NOK"}
			if field == "server_zero_to_known" {
				order.ServerID = 0
			}
			if field == "order_zero_to_known" {
				order.OrderID = ""
			}
			seedA1Order(t, h, order)
			rows, err := h.getGigahostOrders(ctx)
			if err != nil || len(rows) != 1 {
				t.Fatalf("seed rows: %+v, %v", rows, err)
			}
			id := rows[0].ID
			mutate := func() {
				var query string
				switch field {
				case "status":
					query = `UPDATE gigahost_orders SET status = 'active' WHERE id = ?`
				case "server_zero_to_known":
					query = `UPDATE gigahost_orders SET server_id = 7 WHERE id = ?`
				case "order_zero_to_known":
					query = `UPDATE gigahost_orders SET order_id = '10001' WHERE id = ?`
				case "monthly_cap":
					query = `UPDATE gigahost_orders SET monthly_cap_nok = 59 WHERE id = ?`
				case "updated_at":
					query = `UPDATE gigahost_orders SET updated_at = '2030-01-01T00:00:00Z' WHERE id = ?`
				}
				if _, err := db.ExecContext(ctx, query, id); err != nil {
					t.Fatal(err)
				}
			}
			var posts int32
			hourly := true
			h.SetGigahostClient(&mockGigahostClient{
				getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
					return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
				},
				getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return a1bCatalog(), nil },
				getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
					if field == "order_zero_to_known" {
						// Another observation performs the write after the ledger
						// snapshot even though the blank-order row is not queryable.
						return []gigahost.ServerInfo{{ID: 7, PID: 202, Status: "terminated", BwIsHourly: &hourly}}, nil
					}
					return []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "terminated", BwIsHourly: &hourly}}, nil
				},
				getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
					mutate()
					return nil, gigahost.ErrNotFound
				},
				orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
					atomic.AddInt32(&posts, 1)
					return &gigahost.OrderResponse{OrderID: "90001", Status: "pending"}, nil
				},
			})
			if field == "order_zero_to_known" {
				// This second row triggers a provider lookup after BOTH rows were
				// snapshotted; it is locally released and cannot consume the cap.
				seedA1Order(t, h, GigahostOrderRecord{OrderID: "20002", Status: "ready", PlanID: 202})
				all, err := h.getGigahostOrders(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.ReleaseGigahostOrder(ctx, all[0].ID, "fixture", "observation trigger"); err != nil {
					t.Fatal(err)
				}
			}
			w := postBudgetOrder(t, h)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "release_evidence_stale") {
				t.Errorf("response = %d %s; want 503 explicit stale release", w.Code, w.Body.String())
			}
			if got := atomic.LoadInt32(&posts); got != 0 {
				t.Errorf("provider purchases = %d, want 0", got)
			}
			after, err := db.GetGigahostOrderByID(ctx, id)
			if err != nil || after == nil || after.ReleasedAt != "" {
				t.Errorf("stale observation released row: %+v, %v", after, err)
			}
			audit, err := db.ListGigahostOrderAudit(ctx, id)
			if err != nil || len(audit) != 0 {
				t.Errorf("stale release audit = %+v, %v", audit, err)
			}
		})
	}
}

func TestFinancialReleaseCapPositiveControls(t *testing.T) {
	for _, tc := range []struct {
		name      string
		committed float64
		status    int
		posts     int32
	}{
		{"zero_plus_59", 0, http.StatusOK, 1},
		{"41_plus_59", 41, http.StatusOK, 1},
		{"59_plus_59", 59, http.StatusBadRequest, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			if err := db.SetSetting(context.Background(), "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
				t.Fatal(err)
			}
			if tc.committed > 0 {
				seedA1Order(t, h, GigahostOrderRecord{OrderID: "10001", Status: "ready", PlanID: 202,
					RegionID: 2, MonthlyCapNOK: tc.committed, Currency: "NOK"})
			}
			var posts int32
			a1bClient(h, "10001", "ready", &posts)
			w := postBudgetOrder(t, h)
			if w.Code != tc.status || atomic.LoadInt32(&posts) != tc.posts {
				t.Fatalf("response=%d %s, purchases=%d; want %d, %d", w.Code, w.Body.String(), posts, tc.status, tc.posts)
			}
		})
	}
}

// An adjacent release lifecycle: a concurrent successful releaser is not an
// error and must not produce a second audit entry or block valid headroom.
func TestFinancialReleaseConcurrentDurableRelease(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{OrderID: "10001", ServerID: 7, Status: "ready", PlanID: 202,
		RegionID: 2, MonthlyCapNOK: 41, Currency: "NOK"})
	rows, err := h.getGigahostOrders(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v %v", rows, err)
	}
	o := rows[0]
	var posts int32
	hourly := true
	budgetAClient(h, a1bCatalog(), []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "deleted", BwIsHourly: &hourly}},
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			if err := db.ReleaseGigahostOrderIfCurrent(ctx, o.ID, o, "provider_deleted", "concurrent observation"); err != nil {
				t.Fatal(err)
			}
			return nil, gigahost.ErrNotFound
		}, &posts)
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusOK || atomic.LoadInt32(&posts) != 1 {
		t.Fatalf("response=%d %s posts=%d", w.Code, w.Body.String(), posts)
	}
	audit, err := db.ListGigahostOrderAudit(ctx, o.ID)
	if err != nil || len(audit) != 1 || audit[0].Reason != "provider_deleted" {
		t.Fatalf("audit=%+v %v", audit, err)
	}
}

func TestFinancialReleaseWriteFailureBlocksPurchase(t *testing.T) {
	for _, table := range []string{"gigahost_orders", "gigahost_order_audit"} {
		t.Run(table, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := context.Background()
			if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
				t.Fatal(err)
			}
			seedA1Order(t, h, GigahostOrderRecord{OrderID: "10001", ServerID: 7, Status: "ready",
				PlanID: 202, RegionID: 2, MonthlyCapNOK: 41, Currency: "NOK"})
			query := `CREATE TRIGGER fail_release BEFORE UPDATE OF released_at ON gigahost_orders BEGIN SELECT RAISE(ABORT, 'injected release failure'); END`
			if table == "gigahost_order_audit" {
				query = `CREATE TRIGGER fail_release BEFORE INSERT ON gigahost_order_audit BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`
			}
			if _, err := db.ExecContext(ctx, query); err != nil {
				t.Fatal(err)
			}
			var posts int32
			hourly := true
			budgetAClient(h, a1bCatalog(), []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "terminated", BwIsHourly: &hourly}},
				func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
					return nil, gigahost.ErrNotFound
				}, &posts)
			w := postBudgetOrder(t, h)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "release_write_failed") {
				t.Errorf("response = %d %s; want 503 explicit failed release", w.Code, w.Body.String())
			}
			if got := atomic.LoadInt32(&posts); got != 0 {
				t.Errorf("purchases = %d, want 0", got)
			}
			rows, err := h.getGigahostOrders(ctx)
			if err != nil || len(rows) != 1 || rows[0].ReleasedAt != "" {
				t.Errorf("rollback ledger: %+v, %v", rows, err)
			}
			audit, err := db.ListGigahostOrderAudit(ctx, 0)
			if err != nil || len(audit) != 0 {
				t.Errorf("rollback audit: %+v, %v", audit, err)
			}
			// Restart does not turn a failed transition into a successful one.
			h2, _, _ := setupTestHandlers(t)
			h2.db = db
			budgetAClient(h2, a1bCatalog(), []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "terminated", BwIsHourly: &hourly}},
				func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
					return nil, gigahost.ErrNotFound
				}, &posts)
			if w2 := postBudgetOrder(t, h2); w2.Code != http.StatusServiceUnavailable {
				t.Errorf("restart = %d %s", w2.Code, w2.Body.String())
			}
			if got := atomic.LoadInt32(&posts); got != 0 {
				t.Errorf("restart purchases = %d", got)
			}
		})
	}
}
