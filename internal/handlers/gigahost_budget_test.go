package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

func TestGigahostOrderHandler_BudgetRetainsReadyOrderAbsentFromInventory(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:   "local_ready_1",
		Status:    gigahost.StatusReady,
		PlanID:    101,
		RegionID:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	posts := 0
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 100.0}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts++
			return &gigahost.OrderResponse{OrderID: "10005", Status: "pending"}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Monthly budget cap exceeded") {
		t.Errorf("expected budget cap exceeded error, got %s", w.Body.String())
	}
	if posts != 0 {
		t.Errorf("expected 0 orders dispatched, got %d", posts)
	}

	// When the same order ID is subsequently returned in client.GetServers(),
	// verify it is deduplicated and counted only once.
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 200.0}); err != nil {
		t.Fatal(err)
	}

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 100.0}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: 999, OrderID: "local_ready_1", Status: gigahost.StatusReady, PID: 101, RegionID: 1},
			}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts++
			return &gigahost.OrderResponse{OrderID: "10006", Status: "pending"}, nil
		},
	})

	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w2 := httptest.NewRecorder()
	h.GigahostOrderHandler(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when deduplicated, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	if posts != 1 {
		t.Errorf("expected 1 order dispatched, got %d", posts)
	}
}

func TestGigahostOrderHandler_BudgetRetainsActiveOrderAbsentFromInventory(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:   "local_active_1",
		Status:    "active",
		PlanID:    101,
		RegionID:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	posts := 0
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 100.0}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts++
			return &gigahost.OrderResponse{OrderID: "10006", Status: "pending"}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Monthly budget cap exceeded") {
		t.Errorf("expected budget cap exceeded error, got %s", w.Body.String())
	}
	if posts != 0 {
		t.Errorf("expected 0 orders dispatched, got %d", posts)
	}
}

func TestIsOrderActiveForBudget(t *testing.T) {
	activeStatuses := []string{
		gigahost.StatusWaiting,
		gigahost.StatusDeploying,
		gigahost.StatusInstalling,
		gigahost.StatusUnknown,
		"pending_order",
		gigahost.StatusPending,
		gigahost.StatusReady,
		"active",
		"READY",
		"Active",
	}

	for _, s := range activeStatuses {
		if !isOrderActiveForBudget(s) {
			t.Errorf("expected status %q to be active for budget", s)
		}
	}

	// A1 correction: only labels that end the order attempt stop counting.
	// "cancelled" is no longer inactive-quietly: the provider contract shows a
	// cancellation keeps billing until termination (contract E2), so it is
	// counted and reported unresolved rather than dropped. "stopped" and "" are
	// undocumented states and likewise keep their reservation.
	inactiveStatuses := []string{
		"failed",
		"terminated",
		"deleted",
	}

	for _, s := range inactiveStatuses {
		if isOrderActiveForBudget(s) {
			t.Errorf("expected status %q to be inactive for budget", s)
		}
	}
}

func TestIsTerminalStatus(t *testing.T) {
	terminalStatuses := []string{
		gigahost.StatusFailed,
		"deleted",
		"cancelled",
		"canceled",
		"terminated",
		"CANCELLED",
		"Deleted",
		"Terminated",
	}
	for _, s := range terminalStatuses {
		if !isTerminalStatus(s) {
			t.Errorf("expected status %q to be terminal", s)
		}
	}

	nonTerminalStatuses := []string{
		gigahost.StatusReady,
		"active",
		gigahost.StatusPending,
		gigahost.StatusDeploying,
		gigahost.StatusInstalling,
		gigahost.StatusWaiting,
		gigahost.StatusUnknown,
		"pending_order",
		"",
	}
	for _, s := range nonTerminalStatuses {
		if isTerminalStatus(s) {
			t.Errorf("expected status %q to be non-terminal", s)
		}
	}
}

// TestGigahostOrderHandler_BudgetReconcilesCancelledServer covers the
// reconciliation of a provider-cancelled server.
//
// A1 CORRECTION (intake finding 1). The pre-A1 version of this test asserted that
// a provider server reported as "cancelled" frees its budget, and that a
// deploy-status answer with an empty status frees it too. Both contradict the
// provider contract:
//
//	"By default the server keeps running until the end of the paid period and is
//	 terminated on termination_date ... Hourly-billed servers are always
//	 terminated right away and their final hours are billed on the next monthly
//	 invoice."  (contract E2)
//
//	"Each server includes ... any pending cancellation (cancelled, null when
//	 none)"  (contract E2)
//
//	"[deploy status] ... orders that have been cancelled or whose server has been
//	 deleted are left out of the list."  (contract E1)
//
// A "cancelled" server is still running and still billed, and an omission from
// GET /deploy/status is indistinguishable from "never existed", "cancelled" or
// "not yours". Releasing on either let a second VPS be bought against budget the
// first one was still consuming. The subtest that asserted the release is now
// "terminated-in-inventory-releases-and-allows-replacement", which keeps the
// legitimate contract-supported positive.
func TestGigahostOrderHandler_BudgetReconcilesCancelledServer(t *testing.T) {
	t.Run("cancelled-in-inventory-still-counts", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		ctx := context.Background()

		if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
			t.Fatal(err)
		}

		now := time.Now().UTC()
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID:   "local_cancelled_1",
			Status:    gigahost.StatusReady,
			PlanID:    101,
			RegionID:  1,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}

		posts := 0
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 100.0}, nil
			},
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{
					{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
				}, nil
			},
			getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
				return []gigahost.ServerInfo{
					{ID: 201, OrderID: "local_cancelled_1", Status: "cancelled", PID: 101, RegionID: 1},
				}, nil
			},
			orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				posts++
				return &gigahost.OrderResponse{OrderID: "order_replacement_1", Status: "pending"}, nil
			},
		})

		// Refresh orders via GET /api/admin/hosting/gigahost/orders
		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrdersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from orders handler, got %d", w.Code)
		}

		orders, err := h.getGigahostOrders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(orders) != 1 || orders[0].ReleasedAt != "" {
			t.Fatalf("a pending cancellation must not release the reservation, got %+v", orders)
		}

		// 90 committed + 90 requested exceeds the 100 cap: the replacement must
		// be refused, because the cancelled server is still billed until
		// termination.
		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
		orderReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		orderReq = orderReq.WithContext(middleware.WithSession(orderReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
		orderW := httptest.NewRecorder()
		h.GigahostOrderHandler(orderW, orderReq)

		if orderW.Code != http.StatusBadRequest || !strings.Contains(orderW.Body.String(), "budget_exceeded") {
			t.Fatalf("expected 400 budget_exceeded for a still-billed cancelled server, got %d (body: %s)",
				orderW.Code, orderW.Body.String())
		}
		if posts != 0 {
			t.Errorf("expected 0 replacement orders dispatched, got %d", posts)
		}
	})

	t.Run("deploy-status-empty-response-still-counts", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		ctx := context.Background()

		if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
			t.Fatal(err)
		}

		now := time.Now().UTC()
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID:   "local_removed_1",
			Status:    gigahost.StatusReady,
			PlanID:    101,
			RegionID:  1,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}

		posts := 0
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 100.0}, nil
			},
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{
					{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
				}, nil
			},
			getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
				return []gigahost.ServerInfo{}, nil
			},
			getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
				// Per documented Gigahost API: cancelled/deleted orders return empty servers list
				return &gigahost.DeployStatusResponse{OrderID: orderID, Status: ""}, nil
			},
			orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				posts++
				return &gigahost.OrderResponse{OrderID: "order_replacement_2", Status: "pending"}, nil
			},
		})

		// Refresh orders via GET /api/admin/hosting/gigahost/orders
		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrdersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from orders handler, got %d", w.Code)
		}

		orders, err := h.getGigahostOrders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(orders) != 1 || orders[0].ReleasedAt != "" {
			t.Fatalf("an ambiguous deploy-status answer must not release the reservation, got %+v", orders)
		}

		// An empty deploy-status answer is indistinguishable from "cancelled",
		// "deleted" or "not yours", so the commitment stays counted.
		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
		orderReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		orderReq = orderReq.WithContext(middleware.WithSession(orderReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
		orderW := httptest.NewRecorder()
		h.GigahostOrderHandler(orderW, orderReq)

		if orderW.Code != http.StatusBadRequest || !strings.Contains(orderW.Body.String(), "budget_exceeded") {
			t.Fatalf("expected 400 budget_exceeded: an ambiguous order answer is not proof of no charge, got %d (body: %s)",
				orderW.Code, orderW.Body.String())
		}
		if posts != 0 {
			t.Errorf("expected 0 replacement orders dispatched, got %d", posts)
		}
	})

	t.Run("terminated-in-inventory-releases-and-allows-replacement", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		ctx := context.Background()

		if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
			t.Fatal(err)
		}

		now := time.Now().UTC()
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID:   "local_direct_1",
			Status:    gigahost.StatusReady,
			PlanID:    101,
			RegionID:  1,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}

		posts := 0
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 100.0}, nil
			},
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{
					{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}}},
				}, nil
			},
			getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
				return []gigahost.ServerInfo{
					{ID: 201, OrderID: "local_direct_1", Status: "terminated", PID: 101, RegionID: 1},
				}, nil
			},
			orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				posts++
				return &gigahost.OrderResponse{OrderID: "order_replacement_3", Status: "pending"}, nil
			},
		})

		// A direct replacement order, with no prior explicit refresh: the budget
		// check itself must reconcile the terminated reservation, or a legitimate
		// replacement after a real termination would be refused forever.
		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
		orderReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		orderReq = orderReq.WithContext(middleware.WithSession(orderReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
		orderW := httptest.NewRecorder()
		h.GigahostOrderHandler(orderW, orderReq)

		if orderW.Code != http.StatusOK {
			t.Fatalf("expected replacement order 200 OK, got %d (body: %s)", orderW.Code, orderW.Body.String())
		}
		if posts != 1 {
			t.Errorf("expected 1 replacement order dispatched, got %d", posts)
		}

		// The original row keeps its own status and gains a release marker.
		orders, err := h.getGigahostOrders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, o := range orders {
			if o.OrderID == "local_direct_1" {
				found = true
				if o.ReleasedAt == "" {
					t.Error("expected local_direct_1 to carry a release marker")
				}
				if o.Status != gigahost.StatusReady {
					t.Errorf("a release must not rewrite the stored status, got %q", o.Status)
				}
			}
		}
		if !found {
			t.Error("expected to find local_direct_1 in DB orders")
		}
	})
}
