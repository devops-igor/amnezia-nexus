package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/go-chi/chi/v5"
)

// mockGigahostClient provides a configurable mock implementation of gigahost.Client.
type mockGigahostClient struct {
	getCatalogFn      func(ctx context.Context) ([]gigahost.HourlyPlan, error)
	getProductsFn     func(ctx context.Context) ([]gigahost.Product, error)
	getOSFn           func(ctx context.Context) ([]gigahost.OperatingSystem, error)
	getAccountFn      func(ctx context.Context) (*gigahost.AccountInfo, error)
	listSSHKeysFn     func(ctx context.Context) ([]gigahost.SSHKeyInfo, error)
	registerSSHKeyFn  func(ctx context.Context, name, publicKey string) error
	orderServerFn     func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error)
	orderServerSafeFn func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error)
	getDeployStatusFn func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error)
	getServersFn      func(ctx context.Context) ([]gigahost.ServerInfo, error)

	// registeredKeys is the account key list this fake provider maintains when a
	// test does not supply listSSHKeysFn: RegisterSSHKey appends to it (unless
	// registerSSHKeyFn overrides) and ListSSHKeys reads it. It makes the
	// documented "register then re-read the account" contract observable without
	// every test having to wire both halves by hand.
	registeredKeys []gigahost.SSHKeyInfo
}

func (m *mockGigahostClient) ListSSHKeys(ctx context.Context) ([]gigahost.SSHKeyInfo, error) {
	if m.listSSHKeysFn != nil {
		return m.listSSHKeysFn(ctx)
	}
	return append([]gigahost.SSHKeyInfo(nil), m.registeredKeys...), nil
}

func (m *mockGigahostClient) RegisterSSHKey(ctx context.Context, name, publicKey string) error {
	if m.registerSSHKeyFn != nil {
		return m.registerSSHKeyFn(ctx, name, publicKey)
	}
	m.registeredKeys = append(m.registeredKeys, gigahost.SSHKeyInfo{
		KeyID:    strconv.Itoa(len(m.registeredKeys) + 1),
		KeyName:  name,
		KeyData:  publicKey,
		KeyAdded: "1700000000",
	})
	return nil
}

func (m *mockGigahostClient) GetCatalog(ctx context.Context) ([]gigahost.HourlyPlan, error) {
	if m.getCatalogFn != nil {
		return m.getCatalogFn(ctx)
	}
	return nil, nil
}

func (m *mockGigahostClient) GetProducts(ctx context.Context) ([]gigahost.Product, error) {
	if m.getProductsFn != nil {
		return m.getProductsFn(ctx)
	}
	return nil, nil
}

// GetOperatingSystems returns the documented fixture image catalog unless the
// test overrides it. The fixture mirrors the documented /reinstall/distro shape:
// one general image plus one dedicated-only image, which is what makes the
// per-plan narrowing observable.
func (m *mockGigahostClient) GetOperatingSystems(ctx context.Context) ([]gigahost.OperatingSystem, error) {
	if m.getOSFn != nil {
		return m.getOSFn(ctx)
	}
	return fixtureOperatingSystems(), nil
}

// fixtureOperatingSystems is the shared image catalog for handler tests. It
// mirrors the documented GET /reinstall/distro shape (string-encoded numeric and
// boolean fields decoded by OperatingSystem.UnmarshalJSON) and deliberately
// contains one image per documented restriction so the per-plan narrowing is
// observable: a plain image, a dedicated-only image and a RAM-gated image.
func fixtureOperatingSystems() []gigahost.OperatingSystem {
	return []gigahost.OperatingSystem{
		{OSID: 12, DistID: 1, DistName: "Debian", Name: "Debian 12 Bookworm", Arch: "amd64"},
		{OSID: 72, DistID: 9, DistName: "Ubuntu", Name: "Ubuntu 24.04 LTS", Arch: "amd64"},
		{OSID: 90, DistID: 9, DistName: "Ubuntu", Name: "Ubuntu 24.04 LTS (dedicated)", Arch: "amd64", DedicatedOnly: true},
		{OSID: 93, DistID: 1, DistName: "Debian", Name: "Debian 12 (8 GB minimum)", Arch: "amd64", MinRAMGB: 8},
	}
}

// The provider os_id values the fixtures order with, so a test never spells a
// bare number and never relies on an image the fixture does not contain.
const (
	testOSDebian12 int = 12
	testOSUbuntu   int = 72
)

// fixtureHourlyPlan is one documented catalog row: product 101 / price 555 with
// a documented hourly rate, monthly ceiling, region 1 in stock and one in-stock
// datacenter. Tests that are not about catalog contents start from this row so
// their order has a real selection to validate.
func fixtureHourlyPlan() gigahost.HourlyPlan {
	inStock := true
	return gigahost.HourlyPlan{
		ProductID:      101,
		Name:           "Cloud 2",
		Type:           "vm",
		CPUCores:       2,
		RAMMB:          4096,
		DiskGB:         80,
		InStock:        true,
		PriceID:        555,
		Currency:       "NOK",
		HourlyRateNOK:  0.14375,
		MonthlyCeiling: 90,
		Regions:        []gigahost.Region{{ID: 1, Name: "Norway", Country: "NO", Available: true, InStock: &inStock}},
		Datacenters:    []gigahost.Datacenter{{ID: 1, Name: "DC1", RegionID: 1, Location: "Sandefjord", Country: "NO", InStock: &inStock}},
		Eligibility:    gigahost.CatalogEligibility{QualifiesArrears: true},
	}
}

// fixtureCatalogFn is the getCatalogFn a non-catalog test supplies so the order
// path has a real provider answer instead of an invented one.
func fixtureCatalogFn(context.Context) ([]gigahost.HourlyPlan, error) {
	return []gigahost.HourlyPlan{fixtureHourlyPlan()}, nil
}

func (m *mockGigahostClient) GetAccount(ctx context.Context) (*gigahost.AccountInfo, error) {
	if m.getAccountFn != nil {
		return m.getAccountFn(ctx)
	}
	return &gigahost.AccountInfo{Balance: 100.0, Currency: "NOK"}, nil
}

func (m *mockGigahostClient) OrderServer(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	if m.orderServerFn != nil {
		return m.orderServerFn(ctx, req)
	}
	return &gigahost.OrderResponse{OrderID: "ord_1", Status: gigahost.StatusPending}, nil
}

func (m *mockGigahostClient) OrderServerSafe(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	if m.orderServerSafeFn != nil {
		return m.orderServerSafeFn(ctx, req)
	}
	return &gigahost.OrderResponse{OrderID: "ord_1", Status: gigahost.StatusPending}, nil
}

func (m *mockGigahostClient) GetDeployStatus(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	if m.getDeployStatusFn != nil {
		return m.getDeployStatusFn(ctx, orderID)
	}
	return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady, AssignedIP: "192.0.2.1"}, nil
}

func (m *mockGigahostClient) GetServers(ctx context.Context) ([]gigahost.ServerInfo, error) {
	if m.getServersFn != nil {
		return m.getServersFn(ctx)
	}
	return nil, nil
}

func TestGigahostCatalogHandler_RBAC(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	mock := &mockGigahostClient{
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{
				{ProductID: 1, Name: "VPS-Hourly", HourlyRateNOK: 0.12, Currency: "NOK"},
			}, nil
		},
	}
	h.SetGigahostClient(mock)

	tests := []struct {
		name         string
		role         models.UserRole
		auth         bool
		expectedCode int
	}{
		{"Admin role allowed", models.RoleAdmin, true, http.StatusOK},
		{"Support role forbidden", models.RoleSupport, true, http.StatusForbidden},
		{"User role forbidden", models.RoleUser, true, http.StatusForbidden},
		{"Unauthenticated forbidden", "", false, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
			if tt.auth {
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID: "user_test",
					Role:   tt.role,
				}))
			}
			w := httptest.NewRecorder()
			h.GigahostCatalogHandler(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("expected code %d, got %d (body: %s)", tt.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestGigahostCatalogHandler_SuccessAndErrors(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	t.Run("success returns plans and count", func(t *testing.T) {
		h.SetGigahostClient(&mockGigahostClient{
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{
					{ProductID: 10, Name: "VPS Oslo", CPUCores: 2, RAMMB: 4096, DiskGB: 50, HourlyRateNOK: 0.25},
				}, nil
			},
		})

		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostCatalogHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp struct {
			Status string                `json:"status"`
			Count  int                   `json:"count"`
			Plans  []gigahost.HourlyPlan `json:"plans"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse json: %v", err)
		}
		if resp.Count != 1 || len(resp.Plans) != 1 || resp.Plans[0].ProductID != 10 {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("rate limited upstream", func(t *testing.T) {
		h.SetGigahostClient(&mockGigahostClient{
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return nil, gigahost.ErrRateLimited
			},
		})

		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostCatalogHandler(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", w.Code)
		}
	})

	t.Run("unauthorized upstream", func(t *testing.T) {
		h.SetGigahostClient(&mockGigahostClient{
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return nil, gigahost.ErrUnauthorized
			},
		})

		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostCatalogHandler(w, req)

		if w.Code != http.StatusBadGateway {
			t.Errorf("expected 502, got %d", w.Code)
		}
	})
}

func TestGigahostOrderHandler_RBAC(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	body, _ := json.Marshal(OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           testOSDebian12,
		HourlyPriceNOK: 0.14375,
	})

	tests := []struct {
		name         string
		role         models.UserRole
		auth         bool
		expectedCode int
	}{
		{"Admin role allowed", models.RoleAdmin, true, http.StatusOK},
		{"Support role forbidden", models.RoleSupport, true, http.StatusForbidden},
		{"User role forbidden", models.RoleUser, true, http.StatusForbidden},
		{"Unauthenticated forbidden", "", false, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h.SetGigahostClient(&mockGigahostClient{
				getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
					return &gigahost.AccountInfo{Balance: 50.0}, nil
				},
				getCatalogFn: fixtureCatalogFn,
				orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
					return &gigahost.OrderResponse{OrderID: "ord_rbac", Status: gigahost.StatusPending}, nil
				},
			})

			req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(body))
			if tt.auth {
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID: "user_test",
					Role:   tt.role,
				}))
			}
			w := httptest.NewRecorder()
			h.GigahostOrderHandler(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("expected %d, got %d (body: %s)", tt.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestGigahostOrderHandler_AccountCreditPreCheck(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	var orderCalled bool

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 0, Credit: 0}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			plan := fixtureHourlyPlan()
			plan.Eligibility = gigahost.CatalogEligibility{}
			return []gigahost.HourlyPlan{plan}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			orderCalled = true
			return &gigahost.OrderResponse{OrderID: "ord_should_not_call"}, nil
		},
	})

	payload, _ := json.Marshal(OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           testOSDebian12,
		HourlyPriceNOK: 0.14375,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 Payment Required, got %d", w.Code)
	}
	if orderCalled {
		t.Fatal("OrderServer must NOT be called when credit pre-check fails")
	}
}

func TestGigahostOrderHandler_SuccessAndPersistence(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	var sentReq gigahost.OrderRequest
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 120.0, Currency: "NOK"}, nil
		},
		getCatalogFn: fixtureCatalogFn,
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			sentReq = req
			return &gigahost.OrderResponse{
				OrderID:   "ord_persist_123",
				ServerID:  777,
				Status:    gigahost.StatusPending,
				Message:   "Deploying VPS",
				CreatedAt: "2026-11-03T12:00:00Z",
			}, nil
		},
	})

	payload, _ := json.Marshal(OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           testOSDebian12,
		HourlyPriceNOK: 0.14375,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
	}

	if sentReq.BillingPeriod != gigahost.BillingPeriodHourly {
		t.Errorf("expected billing_period hourly, got %s", sentReq.BillingPeriod)
	}
	if sentReq.Quantity != 1 {
		t.Errorf("expected quantity 1, got %d", sentReq.Quantity)
	}

	// Verify persistence in gigahost_orders database
	orders, err := h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("getGigahostOrders failed: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("expected 1 persistent order in database, got %d", len(orders))
	}
	o := orders[0]
	if o.OrderID != "ord_persist_123" || o.ServerID != 777 || o.Status != gigahost.StatusPending {
		t.Errorf("unexpected database record: %+v", o)
	}
	if o.HourlyPriceNOK != 0.14375 {
		t.Errorf("expected the catalog hourly price 0.14375, got %f", o.HourlyPriceNOK)
	}

	// Query DB directly via SQL to verify raw schema
	var count int
	err = db.SQLDB().QueryRowContext(context.Background(), "SELECT count(*) FROM gigahost_orders WHERE order_id = 'ord_persist_123'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("SQL verification failed: count=%d, err=%v", count, err)
	}
}

func TestGigahostOrderHandler_TimeoutRecovery(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 50.0}, nil
		},
		getCatalogFn: fixtureCatalogFn,
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			return &gigahost.OrderResponse{
				Status:  gigahost.StatusUnknown,
				Message: "order timed out; marked unknown",
			}, errors.New("timeout reached")
		},
	})

	payload, _ := json.Marshal(OrderServerPayload{
		PID:            101,
		PriceID:        555,
		RegionID:       1,
		OSID:           testOSDebian12,
		HourlyPriceNOK: 0.14375,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	// When marked unknown due to timeout, handler returns 202 Accepted
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d (body: %s)", w.Code, w.Body.String())
	}

	orders, err := h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("getGigahostOrders failed: %v", err)
	}
	if len(orders) == 0 || orders[0].Status != gigahost.StatusUnknown {
		t.Fatalf("expected order saved with status 'unknown', got %+v", orders)
	}
}

func TestGigahostOrdersHandler_ListAndRefresh(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	// Save an initial pending order
	record := &GigahostOrderRecord{
		OrderID:        "ord_poll_1",
		ServerID:       0,
		Status:         gigahost.StatusPending,
		PlanID:         100,
		RegionID:       1,
		HourlyPriceNOK: 0.15,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = h.saveGigahostOrder(context.Background(), record)

	// Client will report this order as ready with assigned IP
	h.SetGigahostClient(&mockGigahostClient{
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			if orderID == "ord_poll_1" {
				return &gigahost.DeployStatusResponse{
					OrderID:    orderID,
					ServerID:   888,
					Status:     gigahost.StatusReady,
					AssignedIP: "198.51.100.77",
				}, nil
			}
			return nil, errors.New("not found")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrdersHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp struct {
		Status string                `json:"status"`
		Count  int                   `json:"count"`
		Orders []GigahostOrderRecord `json:"orders"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Count != 1 || len(resp.Orders) != 1 {
		t.Fatalf("expected 1 order, got %d", resp.Count)
	}

	o := resp.Orders[0]
	if o.Status != gigahost.StatusReady {
		t.Errorf("expected status refreshed to 'ready', got %s", o.Status)
	}
	if o.AssignedIP != "198.51.100.77" {
		t.Errorf("expected assigned IP 198.51.100.77, got %s", o.AssignedIP)
	}
	if o.ServerID != 888 {
		t.Errorf("expected server_id 888, got %d", o.ServerID)
	}
}

func TestGigahostRouterEndpoints_Integration(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAdmin)
		r.Get("/api/admin/hosting/gigahost/catalog", h.GigahostCatalogHandler)
		r.Post("/api/admin/hosting/gigahost/order", h.GigahostOrderHandler)
		r.Get("/api/admin/hosting/gigahost/orders", h.GigahostOrdersHandler)
	})

	h.SetGigahostClient(&mockGigahostClient{
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{ProductID: 1, Name: "Test Plan"}}, nil
		},
	})

	// 1. Unauthenticated request to /api/admin/hosting/gigahost/catalog -> 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
	wUnauth := httptest.NewRecorder()
	r.ServeHTTP(wUnauth, unauthReq)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated router request, got %d", wUnauth.Code)
	}

	// 2. Authenticated Admin request -> 200
	adminReq := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
	adminReq = adminReq.WithContext(middleware.WithSession(adminReq.Context(), &models.SessionData{
		UserID: "admin_test",
		Role:   models.RoleAdmin,
	}))
	wAdmin := httptest.NewRecorder()
	r.ServeHTTP(wAdmin, adminReq)
	if wAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 for admin router request, got %d", wAdmin.Code)
	}
}

func TestGigahostOrderHandler_InvalidPayloads(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.SetGigahostClient(&mockGigahostClient{})

	t.Run("malformed json body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader([]byte("{invalid-json")))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", w.Code)
		}
	})

	t.Run("non-positive params", func(t *testing.T) {
		payload, _ := json.Marshal(OrderServerPayload{
			PID:      0,
			PriceID:  1,
			RegionID: 1,
			OSID:     1,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", bytes.NewReader(payload))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", w.Code)
		}
	})
}

func TestGigahost_ClientResolution(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	t.Run("unconfigured client returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostCatalogHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for unconfigured client, got %d", w.Code)
		}
	})

	t.Run("client resolved from request header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
		req.Header.Set("X-Gigahost-API-Key", "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		client, err := h.getGigahostClient(context.Background(), req)
		if err != nil {
			t.Fatalf("expected client to resolve from header, got err: %v", err)
		}
		if client == nil {
			t.Fatal("expected non-nil client")
		}
	})
}

func TestGigahost_SecurityAndDurabilityContracts(t *testing.T) {
	t.Run("backup redacts configured api key for support", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		key := "flux_live_" + strings.Repeat("e", 64)
		if err := db.SetSetting(context.Background(), "gigahost", map[string]any{"api_key": key}); err != nil {
			t.Fatal(err)
		}
		r := chi.NewRouter()
		r.With(middleware.RequireAdminOrSupport).Get("/api/settings/backup/download", h.DownloadBackupHandler)
		req := httptest.NewRequest(http.MethodGet, "/api/settings/backup/download", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "support-user", Role: models.RoleSupport}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if bytes.Contains(w.Body.Bytes(), []byte(key)) {
			t.Errorf("expected backup to redact bearer key, but key was found in export")
		}
	})

	t.Run("pre-dispatch persistence failure refuses purchase", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		if err := h.ensureGigahostOrdersTable(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SQLDB().Exec("PRAGMA query_only=ON"); err != nil {
			t.Fatal(err)
		}
		calls := 0
		h.SetGigahostClient(&mockGigahostClient{
			getCatalogFn: fixtureCatalogFn,
			orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				calls++
				return &gigahost.OrderResponse{OrderID: "paid_10001", Status: gigahost.StatusPending}, nil
			},
		})
		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 when DB is read-only, got %d", w.Code)
		}
		if calls != 0 {
			t.Errorf("expected 0 purchase calls when pre-dispatch fails, got %d", calls)
		}
	})

	t.Run("cancellation after provider success still preserves durable job", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h.SetGigahostClient(&mockGigahostClient{
			getCatalogFn: fixtureCatalogFn,
			orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				cancel() // Client disconnected right after order succeeded
				return &gigahost.OrderResponse{OrderID: "paid_10002", Status: gigahost.StatusPending}, nil
			},
		})
		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(ctx)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		var count int
		if err := db.SQLDB().QueryRow("SELECT count(*) FROM gigahost_orders WHERE order_id='paid_10002'").Scan(&count); err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 saved order with order_id paid_10002 despite client cancellation, got %d", count)
		}
	})

	t.Run("installing state continues polling on subsequent orders requests", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		now := time.Now().UTC()
		if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
			OrderID: "10003", Status: "deploying", PlanID: 101, RegionID: 1, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		checks := 0
		h.SetGigahostClient(&mockGigahostClient{
			getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
				checks++
				return &gigahost.DeployStatusResponse{Status: "installing"}, nil
			},
		})
		req1 := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
		req1 = req1.WithContext(middleware.WithSession(req1.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w1 := httptest.NewRecorder()
		h.GigahostOrdersHandler(w1, req1)

		req2 := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
		req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w2 := httptest.NewRecorder()
		h.GigahostOrdersHandler(w2, req2)

		if checks != 2 {
			t.Errorf("expected installing state to continue being polled, checks=%d (wanted 2)", checks)
		}
	})

	t.Run("gigahost settings save and get masked", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		saveBody := `{
			"gigahost": {
				"api_key": "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			}
		}`
		saveReq := httptest.NewRequest(http.MethodPost, "/api/settings/save", strings.NewReader(saveBody))
		saveReq = saveReq.WithContext(middleware.WithSession(saveReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
		saveW := httptest.NewRecorder()
		h.SaveSettingsHandler(saveW, saveReq)
		if saveW.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from SaveSettingsHandler, got %d", saveW.Code)
		}

		getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		getReq = getReq.WithContext(middleware.WithSession(getReq.Context(), &models.SessionData{Role: models.RoleAdmin}))
		getW := httptest.NewRecorder()
		h.GetSettingsHandler(getW, getReq)
		if getW.Code != http.StatusOK {
			t.Fatalf("expected 200 OK from GetSettingsHandler, got %d", getW.Code)
		}

		var resp map[string]any
		if err := json.Unmarshal(getW.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		gh, ok := resp["gigahost"].(map[string]any)
		if !ok {
			t.Fatalf("expected gigahost in settings response, got: %+v", resp)
		}
		if gh["api_key"] != "********" {
			t.Errorf("expected api_key to be masked, got %v", gh["api_key"])
		}
		if _, present := gh["monthly_budget_nok"]; present {
			t.Errorf("settings response still exposes a monthly budget: %v", gh["monthly_budget_nok"])
		}
	})
}

func TestGigahostOrderHandler_InventoryReadErrorWhileReconcilingFailsClosed(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:   "unknown_pending_1",
		Status:    gigahost.StatusUnknown,
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
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true,
					Regions: []gigahost.Region{{ID: 1, Available: true}}, Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true}},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return nil, errors.New("503 Service Unavailable")
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts++
			return &gigahost.OrderResponse{OrderID: "10003", Status: "pending"}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while an unknown purchase cannot be reconciled, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cannot verify provider inventory") {
		t.Errorf("expected an inventory verification error, got %s", w.Body.String())
	}
	if posts != 0 {
		t.Errorf("expected 0 orders dispatched when the unknown purchase cannot be resolved, got %d", posts)
	}
}

func TestGigahostOrderHandler_DuplicateInFlightOrderIsNotRepurchased(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:   "order_transitioned_1",
		Status:    gigahost.StatusDeploying,
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
				{ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true,
					Regions: []gigahost.Region{{ID: 1, Available: true}}, Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true}},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: 888, OrderID: "order_transitioned_1", Status: gigahost.StatusDeploying, PID: 101, RegionID: 1},
			}, nil
		},
		// The provider cannot report progress, and its inventory still shows the
		// order mid-flight: the duplicate must not be re-purchased on a guess.
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, errors.New("deploy status unavailable")
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts++
			return &gigahost.OrderResponse{OrderID: "10004", Status: "pending"}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	// The in-flight order for the same plan and region is an unresolved
	// duplicate: refused as "unknown", with no second purchase.
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "refusing duplicate purchase") {
		t.Fatalf("expected 202 duplicate refusal, got %d (body: %s)", w.Code, w.Body.String())
	}
	if posts != 0 {
		t.Errorf("expected 0 additional orders against an in-flight duplicate, got %d", posts)
	}
}
