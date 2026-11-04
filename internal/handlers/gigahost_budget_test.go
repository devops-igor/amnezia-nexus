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

	inactiveStatuses := []string{
		"failed",
		"cancelled",
		"terminated",
		"deleted",
		"stopped",
		"",
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

func TestGigahostOrderHandler_BudgetReconcilesCancelledServer(t *testing.T) {
	t.Run("terminal-in-inventory", func(t *testing.T) {
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
		if len(orders) != 1 || orders[0].Status != "cancelled" {
			t.Fatalf("expected local order status 'cancelled', got %+v", orders)
		}

		// Subsequent 90 NOK replacement under 100 NOK cap succeeds
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
	})

	t.Run("removed-from-inventory", func(t *testing.T) {
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
		if len(orders) != 1 || orders[0].Status != "cancelled" {
			t.Fatalf("expected local order status 'cancelled', got %+v", orders)
		}

		// Subsequent 90 NOK replacement under 100 NOK cap succeeds
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
	})

	t.Run("direct-order-reconciles-cancelled-without-explicit-refresh", func(t *testing.T) {
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
				return []gigahost.ServerInfo{}, nil
			},
			getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
				return &gigahost.DeployStatusResponse{OrderID: orderID, Status: ""}, nil
			},
			orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				posts++
				return &gigahost.OrderResponse{OrderID: "order_replacement_3", Status: "pending"}, nil
			},
		})

		// Direct replacement order without prior refresh: checkMonthlyBudget should reconcile it
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

		// Verify order was persisted as cancelled in DB
		orders, err := h.getGigahostOrders(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, o := range orders {
			if o.OrderID == "local_direct_1" {
				found = true
				if o.Status != "cancelled" {
					t.Errorf("expected local_direct_1 status to be 'cancelled', got %s", o.Status)
				}
			}
		}
		if !found {
			t.Errorf("expected to find local_direct_1 in DB orders")
		}
	})
}
