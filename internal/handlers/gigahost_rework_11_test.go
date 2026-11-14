package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
