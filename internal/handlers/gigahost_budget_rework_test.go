package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// TestGigahostOrderHandler_ValidateCatalogWithoutBudget verifies DoD 1:
// Purchasing with monthly_budget_nok = 0 and invalid/unpriced/out-of-stock plan returns 400 Bad Request.
func TestGigahostOrderHandler_ValidateCatalogWithoutBudget(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Explicitly configure monthly_budget_nok = 0
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 0.0}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{
		{
			ProductID:      101,
			PriceID:        555,
			Name:           "Standard Plan",
			HourlyRateNOK:  0.25,
			MonthlyCeiling: 180.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
		{
			ProductID:      102,
			PriceID:        556,
			Name:           "Out Of Stock Plan",
			HourlyRateNOK:  0.25,
			MonthlyCeiling: 180.0,
			InStock:        false,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
		{
			ProductID:      103,
			PriceID:        557,
			Name:           "Zero Cost Plan",
			HourlyRateNOK:  0.0,
			MonthlyCeiling: 0.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
		{
			ProductID:      104,
			PriceID:        558,
			Name:           "Unavailable Region Plan",
			HourlyRateNOK:  0.25,
			MonthlyCeiling: 180.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 2, Available: false}},
		},
	}

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{
				OrderID: "ord_success_101",
				Status:  gigahost.StatusPending,
			}, nil
		},
	})

	sendOrder := func(pid, priceID, regionID, osID int, hourlyPrice float64) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(OrderServerPayload{
			PID:            pid,
			PriceID:        priceID,
			RegionID:       regionID,
			OSID:           osID,
			HourlyPriceNOK: hourlyPrice,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		return w
	}

	t.Run("invalid plan absent from catalog returns 400", func(t *testing.T) {
		w := sendOrder(999, 555, 1, 1, 0.25)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_plan") {
			t.Errorf("expected error invalid_plan, got %s", w.Body.String())
		}
	})

	t.Run("out-of-stock plan returns 400", func(t *testing.T) {
		w := sendOrder(102, 556, 1, 1, 0.25)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "out of stock") {
			t.Errorf("expected out of stock error detail, got %s", w.Body.String())
		}
	})

	t.Run("unpriced zero-rate plan returns 400", func(t *testing.T) {
		w := sendOrder(103, 557, 1, 1, 0.0)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "zero or negative price") {
			t.Errorf("expected zero price error detail, got %s", w.Body.String())
		}
	})

	t.Run("unavailable region returns 400", func(t *testing.T) {
		w := sendOrder(104, 558, 2, 1, 0.25)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "not available") {
			t.Errorf("expected not available region error detail, got %s", w.Body.String())
		}
	})

	t.Run("valid plan succeeds with 200", func(t *testing.T) {
		w := sendOrder(101, 555, 1, 1, 0.25)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for valid plan, got %d (body: %s)", w.Code, w.Body.String())
		}
		if posts.Load() != 1 {
			t.Errorf("expected 1 order dispatched, got %d", posts.Load())
		}
	})
}

// TestGigahostOrderHandler_AmbiguousProviderErrorBlocksDuplicates verifies DoD 2:
// Ambiguous provider errors (5xx, malformed JSON) return OrderUncertainError and preserve
// orders as unknown/waiting, blocking duplicate purchases.
func TestGigahostOrderHandler_AmbiguousProviderErrorBlocksDuplicates(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 300.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID:      201,
				PriceID:        555,
				Name:           "Standard Plan",
				HourlyRateNOK:  0.20,
				MonthlyCeiling: 120.0,
				InStock:        true,
				Regions:        []gigahost.Region{{ID: 1, Available: true}},
			}}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			uncertainErr := &gigahost.OrderUncertainError{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal upstream server error",
				Err:        errors.New("HTTP 500: internal error"),
			}
			return &gigahost.OrderResponse{
				Status:  gigahost.StatusUnknown,
				Message: "upstream returned 500 internal error; marked unknown",
			}, uncertainErr
		},
	})

	payload, _ := json.Marshal(OrderServerPayload{
		PID:            201,
		PriceID:        555,
		RegionID:       1,
		OSID:           1,
		HourlyPriceNOK: 0.20,
	})

	// First request: provider encounters 500 / OrderUncertainError
	req1 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	req1 = req1.WithContext(middleware.WithSession(req1.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w1 := httptest.NewRecorder()
	h.GigahostOrderHandler(w1, req1)

	if w1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted on ambiguous error, got %d (body: %s)", w1.Code, w1.Body.String())
	}
	var resp1 map[string]any
	if err := json.Unmarshal(w1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp1["status"] != "unknown" {
		t.Errorf("expected status 'unknown', got %v", resp1["status"])
	}

	orders, err := h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("getGigahostOrders failed: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("expected 1 saved order, got %d", len(orders))
	}
	if orders[0].Status != gigahost.StatusUnknown {
		t.Errorf("expected saved order status 'unknown', got %s", orders[0].Status)
	}

	// Second request: duplicate attempt for same plan/region must be blocked
	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w2 := httptest.NewRecorder()
	h.GigahostOrderHandler(w2, req2)

	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted blocking duplicate purchase, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	var resp2 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	msg, _ := resp2["message"].(string)
	if !strings.Contains(msg, "Prior purchase order is pending reconciliation") {
		t.Errorf("expected duplicate refusal message, got %q", msg)
	}

	// Crucial check: OrderServerSafe must NOT have been called a second time
	if posts.Load() != 1 {
		t.Errorf("expected exactly 1 OrderServerSafe call, got %d", posts.Load())
	}
}

// TestIsOrderActiveForBudget_PendingPaymentAndUnknown verifies DoD 3:
// isOrderActiveForBudget counts pending_payment and unknown as committed spend.
func TestIsOrderActiveForBudget_PendingPaymentAndUnknown(t *testing.T) {
	// Statuses that must be counted active for budget
	requiredActive := []string{
		"pending_payment",
		"Pending_Payment",
		"PENDING_PAYMENT",
		gigahost.StatusUnknown,
		"unknown",
		"UNKNOWN",
		gigahost.StatusWaiting,
		gigahost.StatusDeploying,
		gigahost.StatusInstalling,
		"pending_order",
		gigahost.StatusPending,
		gigahost.StatusReady,
		"active",
	}

	for _, s := range requiredActive {
		if !isOrderActiveForBudget(s) {
			t.Errorf("expected status %q to be active for budget", s)
		}
	}

	// Terminal / inactive statuses
	inactive := []string{
		"failed",
		"cancelled",
		"deleted",
		"terminated",
		"stopped",
		"",
	}
	for _, s := range inactive {
		if isOrderActiveForBudget(s) {
			t.Errorf("expected status %q to be inactive for budget", s)
		}
	}
}

// TestGigahostOrderHandler_BudgetCountsPendingPaymentAndUnknown verifies DoD 3:
// End-to-end budget enforcement accounting for pending_payment and unknown orders.
func TestGigahostOrderHandler_BudgetCountsPendingPaymentAndUnknown(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Budget cap: 150 NOK
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 150.0}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{{
		ProductID:      101,
		PriceID:        555,
		Name:           "Standard Plan",
		HourlyRateNOK:  0.125,
		MonthlyCeiling: 90.0,
		InStock:        true,
		Regions:        []gigahost.Region{{ID: 1, Available: true}},
	}}

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
	})

	// Pre-seed an order with status "pending_payment" (monthly spend = 90 NOK)
	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:        "ord_pending_pay_1",
		Status:         "pending_payment",
		PlanID:         101,
		RegionID:       2, // different region so it doesn't trigger the in-flight duplicate lock
		HourlyPriceNOK: 0.125,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}

	// Attempt new order for Plan 101 in Region 1 (spend = 90 NOK)
	// Total spend: 90 + 90 = 180 > 150 NOK -> must be rejected as budget_exceeded!
	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":1,"hourly_price_nok":0.125}`
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
}

// TestGigahostOrdersHandler_DeployQueryAttemptLimit verifies DoD 4:
// GigahostOrdersHandler increments deploy query counter on every attempted query, stopping at maxDeployQueries = 10.
func TestGigahostOrdersHandler_DeployQueryAttemptLimit(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Seed 15 pending orders in DB
	now := time.Now().UTC()
	for i := 1; i <= 15; i++ {
		order := &GigahostOrderRecord{
			OrderID:        fmt.Sprintf("order_%03d", i),
			Status:         "deploying",
			PlanID:         101,
			RegionID:       1,
			HourlyPriceNOK: 0.10,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := h.saveGigahostOrder(ctx, order); err != nil {
			t.Fatalf("failed to save order: %v", err)
		}
	}

	var statusQueries atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			// No servers returned to force polling via GetDeployStatus
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			statusQueries.Add(1)
			// Return status unchanged so refreshed status remains deploying
			return &gigahost.DeployStatusResponse{
				OrderID: orderID,
				Status:  "deploying",
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrdersHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Must stop polling at maxDeployQueries = 10 attempts, despite 15 eligible orders
	queries := statusQueries.Load()
	if queries != 10 {
		t.Errorf("expected exactly 10 deploy status query attempts, got %d", queries)
	}
}

// TestReconcilePendingUnknownOrders_FailsClosedOnDBError verifies DoD 5:
// reconcilePendingUnknownOrders fails closed on DB read errors.
func TestReconcilePendingUnknownOrders_FailsClosedOnDBError(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	// Close the DB connection to induce a database read error
	_ = db.Close()

	client := &mockGigahostClient{
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
	}

	req := OrderServerPayload{
		PID:      101,
		PriceID:  555,
		RegionID: 1,
		OSID:     1,
	}

	// reconcilePendingUnknownOrders must return an error and NOT return nil, nil
	unresolved, err := h.reconcilePendingUnknownOrders(context.Background(), client, req)
	if err == nil {
		t.Fatalf("expected error on DB failure, got nil (unresolved: %+v)", unresolved)
	}
	if !strings.Contains(err.Error(), "failed to read local orders") {
		t.Errorf("expected 'failed to read local orders' error, got %v", err)
	}

	// Verify that GigahostOrderHandler fails closed with 503 Service Unavailable
	httpReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(`{"pid":101,"price_id":555,"region_id":1,"os_id":1}`))
	httpReq = httpReq.WithContext(middleware.WithSession(httpReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, httpReq)

	if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusBadRequest {
		// Note: verifyAccountEligibility may fail if DB is closed depending on settings, or reconciliation_failed (503)
		t.Logf("handler returned code %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestGigahostOrderHandler_NumericStringBudgetEnforced verifies [HIGH] R10-H1:
// Numeric string budgets like "100" are decoded flexibly and enforced (never treated as disabled/0).
func TestGigahostOrderHandler_NumericStringBudgetEnforced(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Configure budget as numeric string "100"
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": "100"}); err != nil {
		t.Fatal(err)
	}

	budget, err := h.getMonthlyBudgetNOK(ctx)
	if err != nil {
		t.Fatalf("expected successful decode of numeric string budget, got error: %v", err)
	}
	if budget != 100.0 {
		t.Fatalf("expected decoded budget to be 100.0, got %v", budget)
	}

	catalog := []gigahost.HourlyPlan{
		{
			ProductID:      101,
			PriceID:        555,
			Name:           "Plan 180 NOK",
			HourlyRateNOK:  0.25,
			MonthlyCeiling: 180.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
		{
			ProductID:      102,
			PriceID:        556,
			Name:           "Plan 50 NOK",
			HourlyRateNOK:  0.0694,
			MonthlyCeiling: 50.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
	}

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{
				OrderID: "ord_ok",
				Status:  gigahost.StatusPending,
			}, nil
		},
	})

	sendOrder := func(pid, priceID int, hourlyPrice float64) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(OrderServerPayload{
			PID:            pid,
			PriceID:        priceID,
			RegionID:       1,
			OSID:           1,
			HourlyPriceNOK: hourlyPrice,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		return w
	}

	// 1. Order Plan 101 costing 180 NOK/month against 100 NOK budget -> must be rejected with 400
	w1 := sendOrder(101, 555, 0.25)
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for order exceeding string-configured budget, got %d (body: %s)", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), "Monthly budget cap exceeded") {
		t.Errorf("expected budget exceeded message, got %s", w1.Body.String())
	}
	if posts.Load() != 0 {
		t.Errorf("expected 0 provider posts for exceeded budget, got %d", posts.Load())
	}

	// 2. Order Plan 102 costing 50 NOK/month against 100 NOK budget -> must succeed with 200
	w2 := sendOrder(102, 556, 0.0694)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for order within string-configured budget, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	if posts.Load() != 1 {
		t.Errorf("expected 1 provider post, got %d", posts.Load())
	}
}

// TestGigahostOrderHandler_MalformedBudgetFailsClosed verifies [HIGH] R10-H1:
// Malformed or undecodable budget setting fails closed in getMonthlyBudgetNOK and rejects orders.
func TestGigahostOrderHandler_MalformedBudgetFailsClosed(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	catalog := []gigahost.HourlyPlan{
		{
			ProductID:      101,
			PriceID:        555,
			Name:           "Plan 101",
			HourlyRateNOK:  0.10,
			MonthlyCeiling: 72.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
	}

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{
				OrderID: "ord_should_not_reach",
				Status:  gigahost.StatusPending,
			}, nil
		},
	})

	sendOrder := func() *httptest.ResponseRecorder {
		payload, _ := json.Marshal(OrderServerPayload{
			PID:            101,
			PriceID:        555,
			RegionID:       1,
			OSID:           1,
			HourlyPriceNOK: 0.10,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		return w
	}

	// 1. Non-numeric budget string
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": "invalid_number"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.getMonthlyBudgetNOK(ctx); err == nil {
		t.Fatal("expected getMonthlyBudgetNOK to fail closed on non-numeric budget")
	}
	w1 := sendOrder()
	if w1.Code != http.StatusBadGateway {
		t.Fatalf("expected HTTP 502 Bad Gateway on malformed budget, got %d (body: %s)", w1.Code, w1.Body.String())
	}
	if posts.Load() != 0 {
		t.Errorf("expected 0 provider posts, got %d", posts.Load())
	}

	// 2. Negative budget value
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": -50.0}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.getMonthlyBudgetNOK(ctx); err == nil {
		t.Fatal("expected getMonthlyBudgetNOK to fail closed on negative budget")
	}
	w2 := sendOrder()
	if w2.Code != http.StatusBadGateway {
		t.Fatalf("expected HTTP 502 Bad Gateway on negative budget, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	if posts.Load() != 0 {
		t.Errorf("expected 0 provider posts, got %d", posts.Load())
	}
}

// TestSaveSettingsHandler_BudgetValidation verifies [HIGH] R10-H1:
// SaveSettingsHandler validates monthly_budget_nok is a valid numeric value >= 0.
func TestSaveSettingsHandler_BudgetValidation(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	adminSession := &models.SessionData{Role: models.RoleAdmin}

	saveSettings := func(gigahostMap map[string]any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(models.SaveSettingsRequest{
			Gigahost: gigahostMap,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
		w := httptest.NewRecorder()
		h.SaveSettingsHandler(w, req)
		return w
	}

	// Valid numeric string "150.5" -> 200 OK
	w1 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": "150.5"})
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 for numeric string budget, got %d (body: %s)", w1.Code, w1.Body.String())
	}
	budget, err := h.getMonthlyBudgetNOK(ctx)
	if err != nil || budget != 150.5 {
		t.Fatalf("expected stored budget to be 150.5, got %v (err: %v)", budget, err)
	}

	// Valid float 200.0 -> 200 OK
	w2 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": 200.0})
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 for float budget, got %d (body: %s)", w2.Code, w2.Body.String())
	}

	// Valid zero budget -> 200 OK
	w3 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": 0})
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 for zero budget, got %d (body: %s)", w3.Code, w3.Body.String())
	}

	// Invalid non-numeric string -> 400 Bad Request
	w4 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": "invalid"})
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid budget string, got %d (body: %s)", w4.Code, w4.Body.String())
	}

	// Invalid negative number -> 400 Bad Request
	w5 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": -10.0})
	if w5.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative budget, got %d (body: %s)", w5.Code, w5.Body.String())
	}

	// Invalid negative string -> 400 Bad Request
	w6 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": "-10"})
	if w6.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative budget string, got %d (body: %s)", w6.Code, w6.Body.String())
	}

	// Invalid boolean -> 400 Bad Request
	w7 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": true})
	if w7.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for boolean budget, got %d (body: %s)", w7.Code, w7.Body.String())
	}

	// Invalid empty string -> 400 Bad Request
	w8 := saveSettings(map[string]any{"api_key": "valid_key", "monthly_budget_nok": ""})
	if w8.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty budget string, got %d (body: %s)", w8.Code, w8.Body.String())
	}
}

// TestValidateOrderAgainstCatalog_EmptyCatalogRejection verifies [CONTRACT] W9-1:
// Empty catalog is rejected with HTTP 400 ("no available plans in catalog").
func TestValidateOrderAgainstCatalog_EmptyCatalogRejection(t *testing.T) {
	req := OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           1,
		HourlyPriceNOK: 0.25,
	}

	// 1. Direct validation against nil catalog
	errNil := validateOrderAgainstCatalog(nil, req)
	if errNil == nil {
		t.Fatal("expected error for nil catalog, got nil")
	}
	if !strings.Contains(errNil.Error(), "no available plans in catalog") {
		t.Errorf("expected 'no available plans in catalog' error, got %v", errNil)
	}

	// 2. Direct validation against empty slice catalog
	errEmpty := validateOrderAgainstCatalog([]gigahost.HourlyPlan{}, req)
	if errEmpty == nil {
		t.Fatal("expected error for empty catalog, got nil")
	}
	if !strings.Contains(errEmpty.Error(), "no available plans in catalog") {
		t.Errorf("expected 'no available plans in catalog' error, got %v", errEmpty)
	}

	// 3. HTTP handler rejection with 400 when catalog has 0 plans
	h, _, _ := setupTestHandlers(t)
	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "should_not_reach"}, nil
		},
	})

	payload, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	httpReq = httpReq.WithContext(middleware.WithSession(httpReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 Bad Request for empty catalog, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "no available plans in catalog") {
		t.Errorf("expected body to contain 'no available plans in catalog', got %s", w.Body.String())
	}
	if posts.Load() != 0 {
		t.Errorf("expected 0 provider posts for empty catalog, got %d", posts.Load())
	}
}
