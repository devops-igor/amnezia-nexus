package handlers

// Real-consumer regression for eligibility source equivalence (finding E1):
// GET /deploy/servers already carries every eligibility invariant the provider
// documents, and HasEligibility is an OR with no deny branch, so GET /account
// can only ADD eligibility - never remove it. When the catalog already
// qualifies, the account call therefore cannot change the outcome, and skipping
// it removes a provider round-trip that has been observed to stall.
//
// The equivalence is asserted through the production purchase path
// (GigahostOrderHandler), not only on the helper:
//
//	catalog qualifies                 -> order proceeds, /account not called
//	catalog does NOT qualify          -> /account is still consulted, with the
//	                                     same account_check_failed /
//	                                     insufficient_credit outcomes as before
//
// Nothing here removes a credit guard: the /account fallback is the only path
// that can still permit an order when the catalog does not qualify, and a
// non-qualifying catalog with a stalling account must still fail closed with
// zero purchases.

import (
	"context"
	"errors"
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

// eligibilityPlan builds a catalog row with the given catalog-level eligibility.
func eligibilityPlan(pid, priceID int, qualifiesArrears bool, creditNOK float64) gigahost.HourlyPlan {
	return gigahost.HourlyPlan{
		ProductID: pid, PriceID: priceID, Currency: "NOK",
		HourlyRateNOK: 0.15, MonthlyCeiling: 59, InStock: true,
		Regions:     []gigahost.Region{{ID: 1, Available: true}},
		Eligibility: gigahost.CatalogEligibility{QualifiesArrears: qualifiesArrears, CreditNOK: creditNOK},
	}
}

// eligibilityOutcome records what one order attempt actually did.
type eligibilityOutcome struct {
	code         int
	body         string
	posts        int32
	accountCalls int32
	catalogCalls int32
}

// runEligibilityOrder attempts one 59 NOK order for plan 101 with the given
// catalog/account behaviour.
func runEligibilityOrder(
	t *testing.T,
	catalog []gigahost.HourlyPlan,
	catalogErr, accountErr error,
	account *gigahost.AccountInfo,
) eligibilityOutcome {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 0.0}); err != nil {
		t.Fatal(err)
	}

	var out eligibilityOutcome
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			atomic.AddInt32(&out.accountCalls, 1)
			return account, accountErr
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			atomic.AddInt32(&out.catalogCalls, 1)
			return catalog, catalogErr
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return nil, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady, AssignedIP: "192.0.2.10"}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&out.posts, 1)
			return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	out.code, out.body = w.Code, w.Body.String()
	return out
}

// accountStalled is the account-call failure the human incident produced.
var accountStalled = errors.New("Client.Timeout exceeded while awaiting headers")

// TestGigahostOrderHandler_EligibilityCatalogFirst covers the evaluation-order
// change: a qualifying catalog means the account call cannot change the
// decision, so it is skipped; every non-qualifying path keeps the existing
// account fallback and its exact denial/error semantics.
func TestGigahostOrderHandler_EligibilityCatalogFirst(t *testing.T) {
	positive := &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}
	zero := &gigahost.AccountInfo{}

	cases := []struct {
		name             string
		catalog          []gigahost.HourlyPlan
		catalogErr       error
		accountErr       error
		account          *gigahost.AccountInfo
		wantCode         int
		wantPosts        int32
		wantAccountCalls int32
		wantCatalogCalls int32
		wantBody         string
	}{
		{
			name:             "catalog qualifies (arrears) and account stalls: proceeds, account not called",
			catalog:          []gigahost.HourlyPlan{eligibilityPlan(101, 555, true, 0)},
			accountErr:       accountStalled,
			wantCode:         http.StatusOK,
			wantPosts:        1,
			wantAccountCalls: 0,
			wantCatalogCalls: 1,
		},
		{
			name:             "catalog qualifies (credit) and account would deny: proceeds, account not called",
			catalog:          []gigahost.HourlyPlan{eligibilityPlan(101, 555, false, 120)},
			account:          zero,
			wantCode:         http.StatusOK,
			wantPosts:        1,
			wantAccountCalls: 0,
			wantCatalogCalls: 1,
		},
		{
			name:             "catalog does NOT qualify and account stalls: fail closed, zero purchases",
			catalog:          []gigahost.HourlyPlan{eligibilityPlan(101, 555, false, 0)},
			accountErr:       accountStalled,
			wantCode:         http.StatusBadGateway,
			wantPosts:        0,
			wantAccountCalls: 1,
			wantCatalogCalls: 1,
			wantBody:         "account_check_failed",
		},
		{
			name:             "catalog does NOT qualify and account has credit: fallback preserved, proceeds",
			catalog:          []gigahost.HourlyPlan{eligibilityPlan(101, 555, false, 0)},
			account:          positive,
			wantCode:         http.StatusOK,
			wantPosts:        1,
			wantAccountCalls: 1,
			wantCatalogCalls: 1,
		},
		{
			name:             "catalog does NOT qualify and account has no credit: denied",
			catalog:          []gigahost.HourlyPlan{eligibilityPlan(101, 555, false, 0)},
			account:          zero,
			wantCode:         http.StatusPaymentRequired,
			wantPosts:        0,
			wantAccountCalls: 1,
			wantCatalogCalls: 1,
			wantBody:         "insufficient_credit",
		},
		{
			name:             "catalog fetch fails: stops before the account call",
			catalogErr:       errors.New("catalog unavailable"),
			account:          positive,
			wantCode:         http.StatusBadGateway,
			wantPosts:        0,
			wantAccountCalls: 0,
			wantCatalogCalls: 1,
			wantBody:         "catalog_check_failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runEligibilityOrder(t, tc.catalog, tc.catalogErr, tc.accountErr, tc.account)
			if out.code != tc.wantCode {
				t.Errorf("status = %d, want %d (body: %s)", out.code, tc.wantCode, out.body)
			}
			if out.posts != tc.wantPosts {
				t.Errorf("provider orders dispatched = %d, want %d", out.posts, tc.wantPosts)
			}
			if out.accountCalls != tc.wantAccountCalls {
				t.Errorf("GET /account calls = %d, want %d", out.accountCalls, tc.wantAccountCalls)
			}
			if out.catalogCalls != tc.wantCatalogCalls {
				t.Errorf("catalog calls = %d, want %d", out.catalogCalls, tc.wantCatalogCalls)
			}
			if tc.wantBody != "" && !strings.Contains(out.body, tc.wantBody) {
				t.Errorf("body must contain %q, got %s", tc.wantBody, out.body)
			}
		})
	}
}

// TestHasEligibility_AccountNeverReducesCatalogEligibility states the property
// the evaluation-order change relies on, directly on the consumer's own
// predicate: whenever the catalog alone qualifies, adding any account shape -
// including a nil account, which is what a skipped call yields - cannot change
// HasEligibility. This is the equivalence argument, not a substitute for the
// handler assertions above.
func TestHasEligibility_AccountNeverReducesCatalogEligibility(t *testing.T) {
	qualifyingCatalogs := []*gigahost.Catalog{
		{Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true}},
		{Eligibility: gigahost.CatalogEligibility{CreditNOK: 120}},
		{Plans: []gigahost.HourlyPlan{eligibilityPlan(101, 555, true, 0)}},
		{Plans: []gigahost.HourlyPlan{eligibilityPlan(101, 555, false, 120)}},
	}
	accountShapes := []*gigahost.AccountInfo{
		nil,
		{},
		{Balance: -100, Credit: -50, CreditNOK: -10},
		{QualifiesArrears: false},
		{Balance: 500},
		{QualifiesArrears: true},
	}

	for ci, catalog := range qualifyingCatalogs {
		for ai, account := range accountShapes {
			if !gigahost.HasEligibility(account, catalog) {
				t.Errorf("catalog #%d qualifies on its own, but account shape #%d made HasEligibility false", ci, ai)
			}
		}
	}
}

// TestGigahostOrderHandler_SkippedAccountKeepsEveryGuard is the control that the
// evaluation-order change did not become a purchase bypass: with a qualifying
// catalog, the budget cap, the unknown-purchase block and B2 accounting must
// still stop an order exactly as before.
func TestGigahostOrderHandler_SkippedAccountKeepsEveryGuard(t *testing.T) {
	t.Run("budget cap still rejects a qualifying catalog", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		ctx := context.Background()
		if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 90.0}); err != nil {
			t.Fatal(err)
		}
		catalog := []gigahost.HourlyPlan{
			eligibilityPlan(101, 555, true, 0),
			priceIdentityPlan(202, 666, 0.057, 41),
		}
		hourly := true
		var posts int32
		var accountCalls int32
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
				atomic.AddInt32(&accountCalls, 1)
				return &gigahost.AccountInfo{Balance: 500}, nil
			},
			getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) { return catalog, nil },
			getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
				// 60 NOK of existing commitment + the 59 request crosses the cap.
				return []gigahost.ServerInfo{{ID: 7, PID: 202, Status: gigahost.StatusReady, BwIsHourly: &hourly}}, nil
			},
			orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				atomic.AddInt32(&posts, 1)
				return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
			},
		})
		// Seed the 41 NOK commitment as a server-linked local order.
		now := time.Now().UTC()
		rec := GigahostOrderRecord{OrderID: "existing", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1, HourlyPriceNOK: 0.057, CreatedAt: now, UpdatedAt: now}
		if err := h.saveGigahostOrder(ctx, &rec); err != nil {
			t.Fatal(err)
		}

		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
			t.Errorf("status = %d, want 400 budget_exceeded (body: %s)", w.Code, w.Body.String())
		}
		if posts != 0 {
			t.Errorf("provider orders dispatched = %d, want 0", posts)
		}
		if accountCalls != 0 {
			t.Errorf("GET /account calls = %d, want 0", accountCalls)
		}
	})
}
