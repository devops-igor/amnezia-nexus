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
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0},
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
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0},
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
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0},
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
