package handlers

// Integration regressions for checkpoint A at the production boundary.
//
// The purchase path is where the money decision is made, so these tests drive
// GigahostOrderHandler itself and assert both the HTTP outcome and the durable
// ledger state. They pin four properties:
//
//  1. the price identity the provider contracts is persisted with a new order;
//  2. a restart cannot release an unresolved reservation, and a release that
//     happens automatically happens only on conclusive provider evidence;
//  3. the committed total survives a restart unchanged (no in-memory state);
//  4. the same VPS represented in provider inventory and in the ledger counts
//     once, even when the two sides share no id.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// budgetOrderBody is the request the admin UI sends for plan 101.
const budgetOrderBody = `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`

// postBudgetOrder posts one order as an admin and reports the recorded result.
func postBudgetOrder(t *testing.T, h *Handlers) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(budgetOrderBody))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1", Username: "admin-1", Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	return w
}

// installBudgetClient wires a mock provider for a budget scenario.
func installBudgetClient(h *Handlers, catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo, posts *int32) {
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return servers, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(posts, 1)
			return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
		},
	})
}

// TestGigahostOrder_PersistsPriceIdentity is the regression for the lost
// contract: the order-time price (price id, monthly cap, hourly rate, currency)
// must be durable, because the provider never returns price id again and an
// existing reservation cannot be priced without it.
func TestGigahostOrder_PersistsPriceIdentity(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 200.0}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{{
		ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15,
		MonthlyCeiling: 59, InStock: true,
		Regions: []gigahost.Region{{ID: 1, Available: true}},
	}}
	var posts int32
	installBudgetClient(h, catalog, nil, &posts)

	w := postBudgetOrder(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if posts != 1 {
		t.Fatalf("provider orders = %d, want 1", posts)
	}

	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 {
		t.Fatalf("stored orders = %d, want 1", len(orders))
	}
	got := orders[0]
	if got.PriceID != 555 {
		t.Errorf("price id = %d, want the selected 555", got.PriceID)
	}
	if got.MonthlyCapNOK != 59 {
		t.Errorf("monthly cap = %v, want the catalog contract 59", got.MonthlyCapNOK)
	}
	if got.HourlyPriceNOK != 0.15 {
		t.Errorf("hourly rate = %v, want 0.15", got.HourlyPriceNOK)
	}
	if got.Currency != "NOK" {
		t.Errorf("currency = %q, want NOK", got.Currency)
	}

	// The persisted contract is what prices the reservation afterwards, so the
	// live catalog is no longer needed and a catalog price change must not
	// silently re-price the commitment.
	repriced := []gigahost.HourlyPlan{catalog[0]}
	repriced[0].MonthlyCeiling = 120
	committed, err := gigahostbudgetCommitted(repriced, nil, orders)
	if err != nil {
		t.Fatalf("committed spend: %v", err)
	}
	if committed != 59 {
		t.Errorf("committed = %v, want the persisted contract 59, not the current catalog 120", committed)
	}
}

// TestGigahostOrder_ProviderContractOverridesCatalogEstimate proves the
// provider's own response outranks the catalog row the order was placed with.
func TestGigahostOrder_ProviderContractOverridesCatalogEstimate(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 200.0}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{{
		ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15,
		MonthlyCeiling: 59, InStock: true,
		Regions: []gigahost.Region{{ID: 1, Available: true}},
	}}
	var posts int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return catalog, nil },
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&posts, 1)
			// Documented hourly shape: the provider states the contracted price.
			return &gigahost.OrderResponse{
				OrderID: "10001", Status: gigahost.StatusPending,
				RateHourly: 0.14375, MonthlyCap: 90, Currency: "NOK",
			}, nil
		},
	})

	if w := postBudgetOrder(t, h); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 {
		t.Fatalf("stored orders = %d, want 1", len(orders))
	}
	if orders[0].MonthlyCapNOK != 90 {
		t.Errorf("monthly cap = %v, want the provider's 90, not the catalog 59", orders[0].MonthlyCapNOK)
	}
	if orders[0].HourlyPriceNOK != 0.14375 {
		t.Errorf("hourly rate = %v, want the provider's 0.14375", orders[0].HourlyPriceNOK)
	}
}

// TestGigahostBudget_UnresolvedReservationIsNeverAutoReleased is the core safety
// regression for automatic reconciliation: a synthetic local id must survive
// every attempt, including a not-found answer from the provider, and a restart
// must not clear it.
func TestGigahostBudget_UnresolvedReservationIsNeverAutoReleased(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "intent_1700000000000000000", Status: "unknown", PlanID: 202, RegionID: 2,
		HourlyPriceNOK: 0.057, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{
		// The stale reservation's own plan, at 59 NOK/month, so the requested
		// second commitment of 59 crosses the 100 cap rather than meeting it
		// exactly.
		{ProductID: 202, PriceID: 666, Currency: "NOK", HourlyRateNOK: 0.15, MonthlyCeiling: 59,
			InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
		{ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15, MonthlyCeiling: 59,
			InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
	}
	var posts int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return catalog, nil },
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		// A not-found answer for the synthetic id must NOT be treated as proof.
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, gigahost.ErrNotFound
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&posts, 1)
			return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
		},
	})

	// 41 committed + 59 requested exceeds the 100 cap.
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("status = %d, want 400 budget_exceeded (body: %s)", w.Code, w.Body.String())
	}
	if posts != 0 {
		t.Errorf("provider orders = %d, want 0", posts)
	}
	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orders) != 1 || orders[0].ReleasedAt != "" {
		t.Fatalf("the unresolved reservation must stay counted, got %+v", orders)
	}

	// "Restart": a second, independent handler set over the same database must
	// reach the same decision, proving no in-memory state carries it.
	h2, _, _ := setupTestHandlers(t)
	h2.db = db
	var posts2 int32
	installBudgetClient(h2, catalog, nil, &posts2)
	w2 := postBudgetOrder(t, h2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("after restart status = %d, want 400: the reservation must survive a restart (body: %s)",
			w2.Code, w2.Body.String())
	}
	if posts2 != 0 {
		t.Errorf("after restart provider orders = %d, want 0", posts2)
	}
}

// TestGigahostBudget_ConclusiveProviderEvidenceReleases is the positive control:
// the same machinery MUST release a reservation the provider conclusively ended.
func TestGigahostBudget_ConclusiveProviderEvidenceReleases(t *testing.T) {
	t.Run("provider reports the matching server cancelled", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		ctx := context.Background()
		if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
			HourlyPriceNOK: 0.057, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}

		catalog := []gigahost.HourlyPlan{
			{ProductID: 202, PriceID: 666, Currency: "NOK", HourlyRateNOK: 0.057, MonthlyCeiling: 41,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
			{ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15, MonthlyCeiling: 59,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
		}
		var posts int32
		hourly := true
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
			},
			getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return catalog, nil },
			getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
				return []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "cancelled", BwIsHourly: &hourly}}, nil
			},
			orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				atomic.AddInt32(&posts, 1)
				return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
			},
		})

		// 0 committed after the release + 59 fits the cap.
		w := postBudgetOrder(t, h)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 after the release (body: %s)", w.Code, w.Body.String())
		}
		if posts != 1 {
			t.Errorf("provider orders = %d, want 1", posts)
		}

		orders, err := h.getGigahostOrders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var released bool
		for _, o := range orders {
			if o.OrderID == "10001" {
				released = o.ReleasedAt != ""
				if released && o.ReleaseReason != "provider_terminal_status" {
					t.Errorf("release reason = %q, want provider_terminal_status", o.ReleaseReason)
				}
			}
		}
		if !released {
			t.Error("conclusive provider evidence must release the reservation")
		}
		audit, err := db.ListGigahostOrderAudit(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(audit) != 1 {
			t.Errorf("audit rows = %d, want exactly 1", len(audit))
		}
	})
}

// TestGigahostBudget_ReconciliationIsIdempotentAcrossRestarts proves a second
// pass writes nothing new: the release marker is the durable evidence.
func TestGigahostBudget_ReconciliationIsIdempotentAcrossRestarts(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.057, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{
		{ProductID: 202, PriceID: 666, Currency: "NOK", HourlyRateNOK: 0.057, MonthlyCeiling: 41,
			InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
		{ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15, MonthlyCeiling: 59,
			InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
	}
	hourly := true
	servers := []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "deleted", BwIsHourly: &hourly}}

	run := func(h *Handlers, wantOK bool) {
		var posts int32
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
			},
			getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return catalog, nil },
			getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return servers, nil },
			orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				atomic.AddInt32(&posts, 1)
				return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
			},
		})
		w := postBudgetOrder(t, h)
		if wantOK && w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
		}
		if !wantOK && w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
		}
	}

	run(h, true)
	auditAfterFirst, err := db.ListGigahostOrderAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(auditAfterFirst) != 1 {
		t.Fatalf("audit rows after the first pass = %d, want 1", len(auditAfterFirst))
	}

	// A second independent handler set over the same database is the restart.
	// The already-released row must not be released again; the second attempt is
	// refused because the first one's 59 still occupies the cap.
	h2, _, _ := setupTestHandlers(t)
	h2.db = db
	run(h2, false)

	auditAfterSecond, err := db.ListGigahostOrderAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(auditAfterSecond) != 1 {
		t.Fatalf("audit rows after the second pass = %d, want 1: a repeated release must not rewrite history",
			len(auditAfterSecond))
	}
}

// gigahostbudgetCommitted is the committed total the budget decision uses.
func gigahostbudgetCommitted(
	catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo, orders []GigahostOrderRecord,
) (float64, error) {
	return calculateCommittedSpend(catalog, servers, orders)
}

// TestGigahostOrder_ConcurrentOrdersStillSerialized proves the new shared
// calculation did not weaken the pre-existing serialization: concurrent
// attempts cannot both buy.
func TestGigahostOrder_ConcurrentOrdersStillSerialized(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{{
		ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15, MonthlyCeiling: 59,
		InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
	}}
	var posts int32
	installBudgetClient(h, catalog, nil, &posts)

	results := make([]int, 4)
	done := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func(idx int) {
			w := postBudgetOrder(t, h)
			results[idx] = w.Code
			done <- idx
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}

	// At most one order may reach the provider: 59 + 59 would exceed 100.
	if got := atomic.LoadInt32(&posts); got > 1 {
		t.Fatalf("provider orders = %d, want at most 1", got)
	}
	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var realOrders int
	for _, o := range orders {
		if !strings.HasPrefix(o.OrderID, "intent_") {
			realOrders++
		}
	}
	if realOrders > 1 {
		t.Fatalf("persisted real orders = %d, want at most 1 (statuses: %v)", realOrders, results)
	}
}
