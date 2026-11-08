package handlers

// A1b consumer regressions: the financial lifecycle of a held order.
//
// The counterexample this file reproduces is not a single status check. It is a
// sequence across durable state:
//
//  1. an order is placed and the provider reports it as a waitlist reservation
//     (held, unbilled so far, but it "deploys automatically once capacity frees
//     up");
//  2. A1 released it permanently on that observation;
//  3. the released marker then suppressed both the count and the duplicate guard;
//  4. after a restart the provider deployed the order by itself, with no new
//     budget check, and a second VPS had already been bought into the same cap.
//
// These tests drive the real purchase handler, the durable ledger and the
// provider purchase counter, and they include the restart step, because the
// defect is only reachable across a restart.

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// a1bCatalog is plan 202 at 41 NOK/month (the held order) and plan 101 at
// 59 NOK/month (the second request). 41 + 59 = 100, so the cap decides whether
// the held order was counted.
func a1bCatalog() []gigahost.HourlyPlan {
	return []gigahost.HourlyPlan{
		{ProductID: 202, PriceID: 666, Currency: "NOK", HourlyRateNOK: 0.057,
			MonthlyCeiling: 41, InStock: true,
			Regions: []gigahost.Region{{ID: 1, Available: true}}},
		{ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15,
			MonthlyCeiling: 59, InStock: true,
			Regions: []gigahost.Region{{ID: 1, Available: true}}},
	}
}

// a1bClient wires a provider whose order status is fixed by the caller.
func a1bClient(h *Handlers, orderID, orderStatus string, posts *int32) {
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return a1bCatalog(), nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			// The held order has no server yet: that is the whole point of a
			// waitlist reservation, and it is also why inventory cannot be relied
			// on to keep the commitment visible.
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(_ context.Context, id string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: id, Status: orderStatus}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(posts, 1)
			return &gigahost.OrderResponse{OrderID: "90001", Status: gigahost.StatusPending}, nil
		},
	})
}

// TestA1b_HeldOrderConsumesBudgetAcrossTheWholeLifetime is the primary consumer
// counterexample, including the restart step.
//
// Phase 1: the held (waitlist) order is the only commitment. A second 59 NOK
// order against a 90 NOK cap must be refused, because the held order can deploy
// by itself.
// Phase 2: a fresh handler set over the same database (the restart) must reach
// the same decision, proving no in-memory state was carrying it.
// Phase 3: the provider has now deployed it. It must still be counted exactly
// once, and the held order must never have received a release marker.
func TestA1b_HeldOrderConsumesBudgetAcrossTheWholeLifetime(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", Status: "pending", PlanID: 202, RegionID: 2,
		HourlyPriceNOK: 0.057,
	})

	var posts int32

	// Phase 1: held on the waitlist, unbilled so far.
	a1bClient(h, "10001", "waitlist", &posts)
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("phase 1: status = %d, want 400 budget_exceeded (body: %s)", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("phase 1: provider orders = %d, want 0", got)
	}
	if released := a1bReleased(t, h, "10001"); released != "" {
		t.Fatalf("phase 1: the held order was released (%s); a pending commitment must never be released", released)
	}

	// Phase 2: restart. A second, independent handler set over the same database.
	h2, _, _ := setupTestHandlers(t)
	h2.db = db
	a1bClient(h2, "10001", "waitlist", &posts)
	w2 := postBudgetOrder(t, h2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("phase 2: after restart status = %d, want 400: the held commitment must survive a restart (body: %s)",
			w2.Code, w2.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("phase 2: provider orders = %d, want 0", got)
	}

	// Phase 3: the provider deployed it by itself. Still exactly one commitment.
	h3, _, _ := setupTestHandlers(t)
	h3.db = db
	a1bClient(h3, "10001", "ready", &posts)
	w3 := postBudgetOrder(t, h3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("phase 3: status = %d, want 400: the automatically deployed order occupies the cap (body: %s)",
			w3.Code, w3.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("phase 3: provider orders = %d, want 0: no second VPS may be bought into a used cap", got)
	}
}

// TestA1b_AutomaticallyDeployedOrderCannotBeReleased proves the release path stays
// closed for the whole held lifetime: no provider statement about a waitlist order
// is release evidence.
func TestA1b_AutomaticallyDeployedOrderCannotBeReleased(t *testing.T) {
	for _, status := range []string{"waitlist", "deploying", "installing", "ready"} {
		t.Run(status, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := context.Background()
			if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
				t.Fatal(err)
			}
			seedA1Order(t, h, GigahostOrderRecord{
				OrderID: "10001", Status: "pending", PlanID: 202, RegionID: 2, HourlyPriceNOK: 0.057,
			})

			var posts int32
			a1bClient(h, "10001", status, &posts)
			w := postBudgetOrder(t, h)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
			if released := a1bReleased(t, h, "10001"); released != "" {
				t.Fatalf("provider status %q released a pending commitment (%s)", status, released)
			}
			if got := atomic.LoadInt32(&posts); got != 0 {
				t.Fatalf("provider orders = %d, want 0", got)
			}
		})
	}
}

// TestA1b_StaleReleaseMarkerCannotHideANewlyLiveOrder is the adjacent lifecycle
// defect: a marker written in error must not survive the obligation becoming live.
//
// The ledger row already carries a release marker (as A1 would have written). The
// provider now reports the order ready. The obligation must count again, and the
// purchase must be refused.
func TestA1b_StaleReleaseMarkerCannotHideANewlyLiveOrder(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", Status: "pending", PlanID: 202, RegionID: 2, HourlyPriceNOK: 0.057,
	})
	orders, err := h.getGigahostOrders(ctx)
	if err != nil || len(orders) != 1 {
		t.Fatalf("setup: %v %v", orders, err)
	}
	// Simulate the erroneous A1 release.
	if err := db.ReleaseGigahostOrder(ctx, orders[0].ID, "provider_waitlist_not_billed", "released while unbilled"); err != nil {
		t.Fatal(err)
	}

	var posts int32
	a1bClient(h, "10001", "ready", &posts)
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("status = %d, want 400 budget_exceeded: a stale release marker must not hide a live obligation (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("provider orders = %d, want 0", got)
	}
}

// TestA1b_TerminationStillReleasesAndRestartsCleanly is the required negative
// control: a genuinely finished obligation must still be released, once, and stay
// released across a restart.
func TestA1b_TerminationStillReleasesAndRestartsCleanly(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.057,
	})

	var posts int32
	hourly := true
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return a1bCatalog(), nil },
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "terminated", BwIsHourly: &hourly}}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&posts, 1)
			return &gigahost.OrderResponse{OrderID: "90001", Status: gigahost.StatusPending}, nil
		},
	})

	// 41 + 59 fits the 100 cap only after the terminated commitment is released.
	if w := postBudgetOrder(t, h); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after a termination (body: %s)", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("provider orders = %d, want 1", got)
	}
	if released := a1bReleased(t, h, "10001"); released != "provider_terminated" {
		t.Fatalf("release reason = %q, want provider_terminated", released)
	}
	audit, err := db.ListGigahostOrderAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(audit))
	}

	// Restart: the release is durable and the marker is not re-lit, because the
	// provider still reports the server terminated.
	h2, _, _ := setupTestHandlers(t)
	h2.db = db
	var posts2 int32
	h2.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return a1bCatalog(), nil },
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "terminated", BwIsHourly: &hourly}}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&posts2, 1)
			return &gigahost.OrderResponse{OrderID: "90002", Status: gigahost.StatusPending}, nil
		},
	})
	// The first replacement now occupies 59 of the 100 cap, so this one is denied;
	// what matters is that the terminated row was not resurrected and no second
	// release was recorded.
	_ = postBudgetOrder(t, h2)
	audit2, err := db.ListGigahostOrderAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit2) != 1 {
		t.Fatalf("audit rows after restart = %d, want 1: a repeated release must not rewrite history", len(audit2))
	}
}

// TestA1b_LocallyTerminalRowWithLiveProviderServerStaysCounted re-asserts the A1
// correction that A1b must not regress.
func TestA1b_LocallyTerminalRowWithLiveProviderServerStaysCounted(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusFailed, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.057,
	})

	var posts int32
	hourly := true
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return a1bCatalog(), nil },
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "ready", BwIsHourly: &hourly}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{Status: "ready"}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&posts, 1)
			return &gigahost.OrderResponse{OrderID: "90001", Status: gigahost.StatusPending}, nil
		},
	})

	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: a live server counts even when the local row says failed (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("provider orders = %d, want 0", got)
	}
}

// a1bReleased returns the release reason for an order id, or "" when unreleased.
func a1bReleased(t *testing.T, h *Handlers, orderID string) string {
	t.Helper()
	orders, err := h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range orders {
		if o.OrderID == orderID && o.ReleasedAt != "" {
			return o.ReleaseReason
		}
	}
	return ""
}
