package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// postOrderAs places one order request as an admin with the given identity and
// returns the recorded response. Every retained purchase-path regression drives
// the real handler through this one helper.
func postOrderAs(t *testing.T, h *Handlers, adminID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: adminID, Username: adminID, Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	return w
}

// newHandlersOverDB builds a second handler over an existing database, which is
// what a process restart looks like to the purchase path: durable rows survive,
// every in-memory reservation does not.
func newHandlersOverDB(t *testing.T, db *database.DB) *Handlers {
	t.Helper()
	cfg := &config.Config{
		AppVersion:  config.AppVersion,
		AppCodename: config.AppCodename,
		Host:        "127.0.0.1",
		Port:        5000,
		SecretKey:   testSecretKey,
	}
	reg := manager.NewRegistry()
	reg.Register(&mockProtocolManager{protocol: "awg"})
	reg.Register(&mockProtocolManager{protocol: "telemt"})
	reg.Register(&mockProtocolManager{protocol: "dns"})
	vpnSvc, _ := vpn.NewVPNService(db, nil)
	sshPool := ssh.NewSSHClientPool(ssh.PoolConfig{IdleTimeout: time.Minute}, db)
	// This constructor creates its own pool and VPN service, so it owns their
	// workers exactly like setupTestHandlers does. The database belongs to the
	// caller, so only the pool and the service are registered here; the service
	// release needs the store open, which the caller's own cleanup guarantees.
	t.Cleanup(func() { releaseFixtureSSHPool(t, sshPool) })
	t.Cleanup(func() { releaseFixtureVPNService(t, vpnSvc) })
	return NewHandlers(Dependencies{
		Config:     cfg,
		DB:         db,
		Registry:   reg,
		SSHPool:    sshPool,
		VPNService: vpnSvc,
	})
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

// TestIsPendingOrInFlight pins the set of statuses that keep a purchase attempt
// open. It is the classification the duplicate-purchase guard relies on, so a
// change here silently changes whether a second order can be placed.
func TestIsPendingOrInFlight(t *testing.T) {
	inFlight := []string{
		"pending_order",
		gigahost.StatusUnknown,
		gigahost.StatusWaiting,
		"pending_payment",
		gigahost.StatusPending,
		gigahost.StatusDeploying,
		gigahost.StatusInstalling,
	}
	for _, s := range inFlight {
		if !isPendingOrInFlight(s) {
			t.Errorf("expected status %q to be pending or in flight", s)
		}
	}

	settled := []string{
		gigahost.StatusReady,
		gigahost.StatusFailed,
		"terminated",
		"deleted",
		"",
	}
	for _, s := range settled {
		if isPendingOrInFlight(s) {
			t.Errorf("expected status %q to be settled", s)
		}
	}
}

// TestGigahostOrderHandler_LegacyBudgetSettingDoesNotBlockOrder is the removal
// acceptance: a stored legacy monthly budget far below the product's monthly
// equivalent must not stop a valid hourly order. The order goes through the real
// handler, the real SQLite ledger and a fake provider, and it is placed once.
func TestGigahostOrderHandler_LegacyBudgetSettingDoesNotBlockOrder(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// A legacy 30 NOK cap, still present in the settings row.
	if err := db.SetSetting(ctx, "gigahost", map[string]any{
		"api_key":            "flux_live_legacy_cap_0123456789abcdef0123456789abcdef",
		"monthly_budget_nok": 30.0,
	}); err != nil {
		t.Fatal(err)
	}

	var posts int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			// Monthly equivalent 180 NOK, six times the legacy cap.
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, Name: "Standard Plan", Currency: "NOK",
				HourlyRateNOK: 0.25, MonthlyCeiling: 180.0, InStock: true,
				Regions:     []gigahost.Region{{ID: 1, Available: true}},
				Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true},
			}}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return nil, nil
		},
		orderServerSafeFn: func(_ context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts++
			if req.BillingPeriod != gigahost.BillingPeriodHourly || req.Quantity != 1 {
				t.Errorf("order request = %+v, want one hourly unit", req)
			}
			return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
		},
	})

	w := postOrderAs(t, h, "admin-1", `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`)
	if w.Code != http.StatusOK {
		t.Fatalf("order with a legacy 30 NOK cap = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if posts != 1 {
		t.Fatalf("provider purchase calls = %d, want exactly 1", posts)
	}
	if body := w.Body.String(); strings.Contains(body, "budget") {
		t.Errorf("response still mentions a budget decision: %s", body)
	}

	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("getGigahostOrders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("ledger rows = %d, want 1", len(orders))
	}
	if orders[0].OrderID != "70001" || orders[0].Status != gigahost.StatusPending {
		t.Errorf("ledger row = %+v, want the provider order id and status", orders[0])
	}
	if orders[0].PriceID != 555 || orders[0].HourlyPriceNOK != 0.25 || orders[0].MonthlyCapNOK != 180 {
		t.Errorf("recorded price identity = %+v, want the catalog contract", orders[0])
	}
}

// TestGigahostOrderHandler_ProviderRefusalMakesNoPurchase proves a provider
// refusal still spends one purchase call and reports a useful error, and that
// the refusal is not re-labelled as a financial rejection.
func TestGigahostOrderHandler_ProviderRefusalMakesNoPurchase(t *testing.T) {
	for _, tc := range []struct {
		name     string
		account  func(context.Context) (*gigahost.AccountInfo, error)
		catalog  func(context.Context) ([]gigahost.HourlyPlan, error)
		wantCode int
		wantBody string
	}{
		{
			name: "insufficient credit",
			account: func(context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{Balance: 0, Currency: "NOK"}, nil
			},
			wantCode: http.StatusPaymentRequired,
			wantBody: "insufficient_credit",
		},
		{
			name: "no stock",
			catalog: func(context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{{
					ProductID: 101, PriceID: 555, HourlyRateNOK: 0.25, MonthlyCeiling: 180,
					InStock: false, Regions: []gigahost.Region{{ID: 1, Available: true}},
				}}, nil
			},
			wantCode: http.StatusBadRequest,
			wantBody: "out of stock",
		},
		{
			name: "catalog read failure",
			catalog: func(context.Context) ([]gigahost.HourlyPlan, error) {
				return nil, errors.New("upstream unavailable")
			},
			wantCode: http.StatusBadGateway,
			wantBody: "catalog_check_failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			var posts atomic.Int32

			catalog := tc.catalog
			if catalog == nil {
				// A catalog that does not qualify on its own, so the credit
				// guard is consulted through GET /account.
				catalog = func(context.Context) ([]gigahost.HourlyPlan, error) {
					return []gigahost.HourlyPlan{{
						ProductID: 101, PriceID: 555, HourlyRateNOK: 0.25, MonthlyCeiling: 180,
						InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
					}}, nil
				}
			}
			account := tc.account
			if account == nil {
				account = func(context.Context) (*gigahost.AccountInfo, error) {
					return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
				}
			}
			h.SetGigahostClient(&mockGigahostClient{
				getAccountFn: account,
				getCatalogFn: catalog,
				orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
					posts.Add(1)
					return &gigahost.OrderResponse{OrderID: "should_not_happen", Status: gigahost.StatusPending}, nil
				},
			})

			w := postOrderAs(t, h, "admin-1", `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Errorf("body = %s, want it to name %q", w.Body.String(), tc.wantBody)
			}
			if got := posts.Load(); got != 0 {
				t.Errorf("provider purchase calls = %d, want 0", got)
			}
		})
	}
}

// TestGigahostOrderHandler_RestartKeepsUnknownPurchaseBlocked proves the durable
// unknown-purchase state, not an in-memory reservation, is what stops a retry
// after a restart: a fresh handler over the same database still refuses.
func TestGigahostOrderHandler_RestartKeepsUnknownPurchaseBlocked(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:   "unknown_70002",
		Status:    gigahost.StatusUnknown,
		PlanID:    101,
		RegionID:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// A "restarted" handler shares the database and nothing else.
	restarted := newHandlersOverDB(t, db)
	var posts atomic.Int32
	restarted.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, HourlyRateNOK: 0.25, MonthlyCeiling: 180,
				InStock: true, Regions: []gigahost.Region{{ID: 1, Available: true}},
				Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true},
			}}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			// The provider still cannot say what happened: the answer stays
			// unknown and the block must hold.
			return nil, errors.New("deploy status unavailable")
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "70003", Status: gigahost.StatusPending}, nil
		},
	})

	w := postOrderAs(t, restarted, "admin-1", `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 unknown (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unknown") {
		t.Errorf("body = %s, want an unknown-outcome status", w.Body.String())
	}
	if got := posts.Load(); got != 0 {
		t.Errorf("provider purchase calls after restart = %d, want 0", got)
	}
}

// TestSettingsHandlers_HideRetiredBudgetSetting proves the retired cap cannot
// come back through the read API or be re-saved, while the stored bytes are left
// untouched (an existing database is not rewritten).
func TestSettingsHandlers_HideRetiredBudgetSetting(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// A settings row written by an older panel still carries the retired field.
	if err := db.SetSetting(ctx, "gigahost", map[string]any{
		"api_key":            "flux_live_legacy_0123456789abcdef0123456789abcdef0123",
		"monthly_budget_nok": 30.0,
	}); err != nil {
		t.Fatal(err)
	}

	readGH := func() map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GetSettingsHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/settings = %d (body: %s)", w.Code, w.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode settings response: %v", err)
		}
		gh, _ := resp["gigahost"].(map[string]any)
		return gh
	}

	gh := readGH()
	if _, present := gh["monthly_budget_nok"]; present {
		t.Errorf("settings response exposes the retired budget field: %v", gh["monthly_budget_nok"])
	}
	if gh["api_key"] != "********" {
		t.Errorf("api_key = %v, want it masked", gh["api_key"])
	}

	// Saving a stale client payload cannot reintroduce it.
	body := `{"gigahost":{"monthly_budget_nok":9999}}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings/save", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.SaveSettingsHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/settings/save = %d (body: %s)", w.Code, w.Body.String())
	}
	if _, present := readGH()["monthly_budget_nok"]; present {
		t.Error("a stale save reintroduced the retired budget field")
	}

	// The stored bytes are preserved: this is inert storage, not a migration.
	var stored map[string]any
	if err := db.GetSetting(ctx, "gigahost", &stored); err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if _, kept := stored["monthly_budget_nok"]; !kept {
		t.Error("the stored legacy setting was destroyed; it should be left inert")
	}
}
