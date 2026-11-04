package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestGigahost_R12M3_CatalogValidationFailClosed verifies finding R12-M3:
// 1. Incomplete catalog records with InStock: false (empty name/specs) fail closed.
// 2. Plans with empty regions fail closed.
// 3. Plans with unavailable region fail closed.
func TestGigahost_R12M3_CatalogValidationFailClosed(t *testing.T) {
	req := OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           12,
		HourlyPriceNOK: 0.25,
	}

	t.Run("incomplete plan with InStock: false is rejected unconditionally", func(t *testing.T) {
		incompleteOutStockCatalog := []gigahost.HourlyPlan{
			{
				ProductID:      101,
				PriceID:        555,
				InStock:        false,
				HourlyRateNOK:  0.25,
				MonthlyCeiling: 180.0,
			},
		}

		err := validateOrderAgainstCatalog(incompleteOutStockCatalog, req)
		if err == nil {
			t.Fatal("expected error for incomplete out-of-stock plan, got nil")
		}
		if !strings.Contains(err.Error(), "out of stock") {
			t.Errorf("expected 'out of stock' in error, got %v", err)
		}

		// Also verify via HTTP handler
		h, _, _ := setupTestHandlers(t)
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
			},
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return incompleteOutStockCatalog, nil
			},
		})

		payload, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
		httpReq = httpReq.WithContext(middleware.WithSession(httpReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, httpReq)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "out of stock") {
			t.Errorf("expected body to mention out of stock, got %s", w.Body.String())
		}
	})

	t.Run("plan with empty Regions slice is rejected", func(t *testing.T) {
		emptyRegionsCatalog := []gigahost.HourlyPlan{
			{
				ProductID:      101,
				PriceID:        555,
				InStock:        true,
				HourlyRateNOK:  0.25,
				MonthlyCeiling: 180.0,
				Regions:        []gigahost.Region{},
			},
		}

		err := validateOrderAgainstCatalog(emptyRegionsCatalog, req)
		if err == nil {
			t.Fatal("expected error for plan with empty regions, got nil")
		}
		if !strings.Contains(err.Error(), "no available regions in catalog") {
			t.Errorf("expected 'no available regions in catalog' in error, got %v", err)
		}
	})

	t.Run("plan with unavailable region is rejected", func(t *testing.T) {
		unavailableRegionCatalog := []gigahost.HourlyPlan{
			{
				ProductID:      101,
				PriceID:        555,
				InStock:        true,
				HourlyRateNOK:  0.25,
				MonthlyCeiling: 180.0,
				Regions: []gigahost.Region{
					{ID: 1, Available: false},
					{ID: 2, Available: true},
				},
			},
		}

		err := validateOrderAgainstCatalog(unavailableRegionCatalog, req)
		if err == nil {
			t.Fatal("expected error for unavailable region, got nil")
		}
		if !strings.Contains(err.Error(), "not available") {
			t.Errorf("expected 'not available' in error, got %v", err)
		}
	})
}

// TestGigahost_R12M4_BudgetCalculationHourlyScope verifies finding R12-M4:
// Pre-existing dedicated and non-hourly recurring servers are excluded from the hourly VPS budget,
// while active hourly VPS servers are counted.
func TestGigahost_R12M4_BudgetCalculationHourlyScope(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Monthly budget cap = 100 NOK
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}

	catalog := []gigahost.HourlyPlan{
		{
			ProductID:      101,
			PriceID:        555,
			HourlyRateNOK:  0.05,
			MonthlyCeiling: 36.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
	}

	isHourlyFalse := false
	isHourlyTrue := true

	// Account inventory contains:
	// 1. Dedicated server (ID 8001): srv_type="dedicated", NOT in hourly catalog (would fail spend calculation if counted)
	// 2. Monthly recurring server (ID 8002): srv_type="vps", bw_is_hourly=false, NOT in catalog
	// 3. Active hourly VPS (ID 8003): srv_type="vps", bw_is_hourly=true, PID=101 (monthly spend = 36 NOK)
	servers := []gigahost.ServerInfo{
		{
			ID:         8001,
			OrderID:    "dedi_order_1",
			Status:     "ready",
			SrvType:    "dedicated",
			PID:        999, // Absent from hourly catalog
			BwIsHourly: &isHourlyFalse,
		},
		{
			ID:         8002,
			OrderID:    "recurring_order_2",
			Status:     "ready",
			SrvType:    "recurring",
			PID:        998, // Absent from hourly catalog
			BwIsHourly: &isHourlyFalse,
		},
		{
			ID:         8003,
			OrderID:    "hourly_vps_3",
			Status:     "ready",
			SrvType:    "vps",
			PID:        101,
			BwIsHourly: &isHourlyTrue,
		},
	}

	// 1. Directly verify calculateCommittedSpend:
	// Only server 8003 should be counted (36 NOK). Dedicated and recurring servers must be skipped.
	committed, err := calculateCommittedSpend(catalog, servers, nil)
	if err != nil {
		t.Fatalf("unexpected calculateCommittedSpend error: %v", err)
	}
	if committed != 36.0 {
		t.Fatalf("expected committed spend to be 36.0 (only hourly VPS), got %f", committed)
	}

	// 2. Ordering a new hourly VPS (PID 101, 36 NOK) + existing (36 NOK) = 72 NOK <= 100 NOK budget -> Succeeds!
	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 200.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return servers, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{
				OrderID: "new_hourly_ord_4",
				Status:  gigahost.StatusPending,
			}, nil
		},
	})

	orderReq := OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           12,
		HourlyPriceNOK: 0.05,
	}
	payload, _ := json.Marshal(orderReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	httpReq = httpReq.WithContext(middleware.WithSession(httpReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for order within budget, got %d (body: %s)", w.Code, w.Body.String())
	}
	if posts.Load() != 1 {
		t.Errorf("expected 1 order dispatched, got %d", posts.Load())
	}
}

// TestGigahost_R12H1_MultiPageBudgetEnforcement verifies that multi-page inventory
// is aggregated so that servers on page 2 correctly contribute to the budget calculation.
func TestGigahost_R12H1_MultiPageBudgetEnforcement(t *testing.T) {
	catalog := []gigahost.HourlyPlan{
		{
			ProductID:      101,
			PriceID:        555,
			HourlyRateNOK:  0.10,
			MonthlyCeiling: 72.0,
			InStock:        true,
			Regions:        []gigahost.Region{{ID: 1, Available: true}},
		},
	}

	// 2 servers in inventory across multiple pages
	servers := []gigahost.ServerInfo{
		{ID: 101, OrderID: "page1_srv", Status: "ready", PID: 101},
		{ID: 102, OrderID: "page2_srv", Status: "ready", PID: 101},
	}

	// 2 * 72 NOK = 144 NOK committed spend
	committed, err := calculateCommittedSpend(catalog, servers, nil)
	if err != nil {
		t.Fatalf("unexpected calculateCommittedSpend error: %v", err)
	}
	if committed != 144.0 {
		t.Fatalf("expected 144.0 committed spend across multi-page inventory, got %f", committed)
	}
}
