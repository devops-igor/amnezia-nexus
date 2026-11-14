package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

func TestGigahostPurchaseSafety_HTTP402PreservesOrderIDAndBlocksDuplicate(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 200.0, Currency: "NOK"}, nil
		},
		getCatalogFn: fixtureCatalogFn,
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return nil, &gigahost.OrderPartialError{
				StatusCode: http.StatusPaymentRequired,
				Message:    "Payment required for deployment",
				OrderIDs:   []int64{99001},
				RawBody:    `{"error":"Payment required","order_ids":[99001]}`,
			}
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID,
				Status:  gigahost.StatusWaiting,
			}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.15}`

	// First request: returns 402 with OrderID 99001
	req1 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req1 = req1.WithContext(middleware.WithSession(req1.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w1 := httptest.NewRecorder()
	h.GigahostOrderHandler(w1, req1)

	if w1.Code != http.StatusPaymentRequired {
		t.Fatalf("expected HTTP 402 Payment Required, got %d (body: %s)", w1.Code, w1.Body.String())
	}
	if !strings.Contains(w1.Body.String(), "99001") {
		t.Errorf("expected response to contain order_id 99001, got %s", w1.Body.String())
	}
	if posts.Load() != 1 {
		t.Errorf("expected exactly 1 provider post, got %d", posts.Load())
	}

	// Verify order was persisted in local database with provider OrderID and waiting status
	orders, err := h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("failed to get orders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("expected 1 order record in DB, got %d", len(orders))
	}
	if orders[0].OrderID != "99001" {
		t.Errorf("expected stored OrderID 99001, got %q", orders[0].OrderID)
	}
	if orders[0].Status != gigahost.StatusWaiting {
		t.Errorf("expected stored status waiting, got %q", orders[0].Status)
	}

	// Second request (retry): should be rejected as duplicate unconfirmed order without calling provider OrderServer
	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w2 := httptest.NewRecorder()
	h.GigahostOrderHandler(w2, req2)

	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted refusal on retry, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "Prior purchase order is pending reconciliation") {
		t.Errorf("expected pending reconciliation message, got %s", w2.Body.String())
	}
	if posts.Load() != 1 {
		t.Errorf("expected no additional provider order posts on retry, posts was %d", posts.Load())
	}
}

func TestGigahostPurchaseSafety_ConcurrentOrdersSerialized(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: fixtureCatalogFn,
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			n := posts.Add(1)
			// Simulate order dispatch latency
			time.Sleep(30 * time.Millisecond)
			return &gigahost.OrderResponse{
				OrderID: fmt.Sprintf("ord_%d", n),
				Status:  gigahost.StatusPending,
				Message: "Deploying VPS",
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID,
				Status:  gigahost.StatusDeploying,
			}, nil
		},
	})

	const concurrentWorkers = 5
	var wg sync.WaitGroup
	codes := make([]int, concurrentWorkers)

	for i := 0; i < concurrentWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.15}`
			req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
			w := httptest.NewRecorder()
			h.GigahostOrderHandler(w, req)
			codes[idx] = w.Code
		}(i)
	}

	wg.Wait()

	// Exactly 1 request must have succeeded (200 OK) with 1 provider order dispatched.
	// All other concurrent requests for the exact same plan & region must have been rejected as duplicates (202 Accepted).
	successCount := 0
	duplicateCount := 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			successCount++
		case http.StatusAccepted:
			duplicateCount++
		default:
			t.Errorf("unexpected HTTP status code: %d", code)
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful order, got %d (all codes: %v)", successCount, codes)
	}
	if duplicateCount != concurrentWorkers-1 {
		t.Errorf("expected %d duplicate refusals, got %d", concurrentWorkers-1, duplicateCount)
	}
	if posts.Load() != 1 {
		t.Errorf("expected provider OrderServer to be called exactly 1 time, got %d", posts.Load())
	}
}

func TestGigahostPurchaseSafety_AuthoritativeCatalogValidation(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 300.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{
				{
					ProductID:      101,
					PriceID:        555,
					HourlyRateNOK:  0.25,
					MonthlyCeiling: 180.0, // authoritative price 180 NOK exceeds 100 NOK budget!
					InStock:        true,
					Regions:        []gigahost.Region{{ID: 1, Available: true}},
				},
				{
					ProductID:      102,
					PriceID:        666,
					HourlyRateNOK:  0.0,
					MonthlyCeiling: 0.0, // invalid zero rate
					InStock:        true,
					Regions:        []gigahost.Region{{ID: 1, Available: true}},
				},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{}, nil
		},
	})

	t.Run("client-supplied hourly price does not override the catalog", func(t *testing.T) {
		// A forged zero client rate must not become the recorded order price.
		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
		}
		orders, err := h.getGigahostOrders(context.Background())
		if err != nil || len(orders) != 1 {
			t.Fatalf("orders = %+v, err = %v", orders, err)
		}
		if orders[0].HourlyPriceNOK != 0.25 || orders[0].PriceID != 555 {
			t.Errorf("recorded price = %v/%v, want the catalog contract 0.25/555", orders[0].HourlyPriceNOK, orders[0].PriceID)
		}
	})

	t.Run("unknown plan rejected with 400", func(t *testing.T) {
		body := `{"pid":999,"price_id":111,"region_id":1,"os_id":12,"hourly_price_nok":0}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for unknown plan, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_plan") {
			t.Errorf("expected invalid_plan error code, got: %s", w.Body.String())
		}
	})

	t.Run("zero price plan in catalog rejected with 400", func(t *testing.T) {
		body := `{"pid":102,"price_id":666,"region_id":1,"os_id":12,"hourly_price_nok":0.05}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for zero-cost plan, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_plan") {
			t.Errorf("expected invalid_plan error code, got: %s", w.Body.String())
		}
	})

	t.Run("unavailable region rejected with 400", func(t *testing.T) {
		body := `{"pid":101,"price_id":555,"region_id":99,"os_id":12,"hourly_price_nok":0.25}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for unavailable region, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "invalid_plan") {
			t.Errorf("expected invalid_plan error code, got: %s", w.Body.String())
		}
	})
}

func TestGigahostPurchaseSafety_OrdersRefreshSingleInventoryFetch(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Seed 3 active orders in database
	now := time.Now().UTC()
	for i := 1; i <= 3; i++ {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID:   fmt.Sprintf("ord_active_%d", i),
			Status:    gigahost.StatusWaiting,
			PlanID:    100 + i,
			RegionID:  1,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var serversCalls atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			serversCalls.Add(1)
			return []gigahost.ServerInfo{
				{OrderID: "ord_active_1", Status: gigahost.StatusReady, ID: 501, IPv4: "198.51.100.1"},
				{OrderID: "ord_active_2", Status: gigahost.StatusDeploying, ID: 502},
			}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID,
				Status:  gigahost.StatusWaiting,
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

	// Must have fetched inventory via GetServers exactly ONCE, not N times
	if serversCalls.Load() != 1 {
		t.Errorf("expected exactly 1 GetServers call across 3 orders, got %d", serversCalls.Load())
	}

	var resp struct {
		Orders []GigahostOrderRecord `json:"orders"`
		Count  int                   `json:"count"`
	}
	if err := json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Count != 3 {
		t.Errorf("expected 3 orders returned, got %d", resp.Count)
	}
}

func TestGigahostPurchaseSafety_DocumentedEligibleAccountAllowsOrder(t *testing.T) {
	t.Run("eligible account via catalog qualifies_arrears places order", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		var posts atomic.Int32
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
				// Documented /account returns customer metadata without financial balance
				return &gigahost.AccountInfo{
					CustID:   "cust_1111",
					CustName: "Example AS",
					Balance:  0.0,
					Credit:   0.0,
				}, nil
			},
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{
					{
						ProductID:      101,
						PriceID:        555,
						HourlyRateNOK:  0.14375,
						MonthlyCeiling: 90.0,
						InStock:        true,
						Regions:        []gigahost.Region{{ID: 1, Available: true}},
						Eligibility: gigahost.CatalogEligibility{
							QualifiesArrears: true,
							CreditNOK:        1000.0,
						},
					},
				}, nil
			},
			orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				posts.Add(1)
				return &gigahost.OrderResponse{OrderID: "10001", Status: gigahost.StatusPending}, nil
			},
		})

		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK for documented eligible account, got %d (body: %s)", w.Code, w.Body.String())
		}
		if posts.Load() != 1 {
			t.Errorf("expected 1 order posted, got %d", posts.Load())
		}
	})

	t.Run("ineligible account with zero balance and zero catalog credit rejected with 402", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		var posts atomic.Int32
		h.SetGigahostClient(&mockGigahostClient{
			getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
				return &gigahost.AccountInfo{
					CustID:  "cust_2222",
					Balance: 0.0,
					Credit:  0.0,
				}, nil
			},
			getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
				return []gigahost.HourlyPlan{
					{
						ProductID:      101,
						PriceID:        555,
						HourlyRateNOK:  0.14375,
						MonthlyCeiling: 90.0,
						InStock:        true,
						Regions:        []gigahost.Region{{ID: 1, Available: true}},
						Eligibility: gigahost.CatalogEligibility{
							QualifiesArrears: false,
							CreditNOK:        0.0,
						},
					},
				}, nil
			},
			orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
				posts.Add(1)
				return &gigahost.OrderResponse{OrderID: "10002", Status: gigahost.StatusPending}, nil
			},
		})

		body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)

		if w.Code != http.StatusPaymentRequired {
			t.Fatalf("expected HTTP 402 Payment Required for ineligible account, got %d (body: %s)", w.Code, w.Body.String())
		}
		if posts.Load() != 0 {
			t.Errorf("expected 0 orders posted for ineligible account, got %d", posts.Load())
		}
	})
}

func TestGigahostPurchaseSafety_OutOfStockPlanDoesNotTouchExistingHistory(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Existing order: ready server with stored rate 0.14375 NOK/hr (~103.5 NOK/mo)
	now := time.Now().UTC()
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID:        "10001",
		Status:         gigahost.StatusReady,
		PlanID:         101,
		RegionID:       1,
		HourlyPriceNOK: 0.14375,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}

	var posts atomic.Int32
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			// Plan 101 is out of stock (filtered from catalog).
			// Only Plan 102 (90 NOK/mo) is orderable.
			return []gigahost.HourlyPlan{
				{
					ProductID:      102,
					PriceID:        556,
					HourlyRateNOK:  0.125,
					MonthlyCeiling: 90.0,
					InStock:        true,
					Regions:        []gigahost.Region{{ID: 1, Available: true}},
				},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			// Existing inventory server corresponds to order 10001 (plan 101)
			return []gigahost.ServerInfo{
				{
					ID:      3500,
					OrderID: "10001",
					PID:     101,
					Status:  gigahost.StatusReady,
				},
			}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "10002", Status: gigahost.StatusPending}, nil
		},
	})

	// Plan 101 is no longer orderable, but its history must survive: the order
	// is refused and the existing row is not rewritten or deleted.
	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_plan") {
		t.Fatalf("expected 400 invalid_plan, got %d (body: %s)", w.Code, w.Body.String())
	}
	if posts.Load() != 0 {
		t.Errorf("expected 0 provider posts for an unavailable plan, got %d", posts.Load())
	}
	orders, err := h.getGigahostOrders(ctx)
	if err != nil || len(orders) != 1 {
		t.Fatalf("orders = %+v, err = %v", orders, err)
	}
	if orders[0].OrderID != "10001" || orders[0].HourlyPriceNOK != 0.14375 || orders[0].Status != gigahost.StatusReady {
		t.Errorf("existing history changed: %+v", orders[0])
	}
}

func TestGigahostPurchaseSafety_InFlightInstallingOrderBlocksDuplicateRetry(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var posts atomic.Int32
	var statusCalls atomic.Int32
	deployStatus := gigahost.StatusInstalling

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 1000.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{
				{
					ProductID:      101,
					PriceID:        555,
					HourlyRateNOK:  0.14375,
					MonthlyCeiling: 90.0,
					InStock:        true,
					Regions:        []gigahost.Region{{ID: 1, Available: true}},
				},
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			if posts.Load() > 0 {
				// Provider inventory reports billing status "active", but server is still installing
				return []gigahost.ServerInfo{
					{
						ID:      3500,
						OrderID: "10001",
						PID:     101,
						Status:  "active",
					},
				}, nil
			}
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			statusCalls.Add(1)
			return &gigahost.DeployStatusResponse{
				OrderID: orderID,
				Status:  deployStatus,
			}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "10001", Status: gigahost.StatusPending}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`

	// Request 1: first purchase succeeds
	req1 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req1 = req1.WithContext(middleware.WithSession(req1.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w1 := httptest.NewRecorder()
	h.GigahostOrderHandler(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("expected request 1 HTTP 200, got %d (body: %s)", w1.Code, w1.Body.String())
	}
	if posts.Load() != 1 {
		t.Fatalf("expected 1 post after request 1, got %d", posts.Load())
	}

	// Request 2: duplicate retry while status is "installing" -> refused with 202 Accepted
	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w2 := httptest.NewRecorder()
	h.GigahostOrderHandler(w2, req2)

	if w2.Code != http.StatusAccepted {
		t.Fatalf("expected request 2 HTTP 202 Accepted duplicate refusal, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "Prior purchase order is pending reconciliation") {
		t.Errorf("expected pending reconciliation message, got: %s", w2.Body.String())
	}
	if posts.Load() != 1 {
		t.Errorf("expected no additional post on duplicate retry, got %d", posts.Load())
	}
	if statusCalls.Load() == 0 {
		t.Errorf("expected GetDeployStatus to be queried during reconciliation")
	}

	// Now simulate deployment completion: deployStatus becomes "ready"
	deployStatus = gigahost.StatusReady

	// Request 3: intentional subsequent purchase after first is ready -> succeeds
	req3 := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req3 = req3.WithContext(middleware.WithSession(req3.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w3 := httptest.NewRecorder()
	h.GigahostOrderHandler(w3, req3)

	if w3.Code != http.StatusOK {
		t.Fatalf("expected request 3 HTTP 200 OK after ready, got %d (body: %s)", w3.Code, w3.Body.String())
	}
	if posts.Load() != 2 {
		t.Errorf("expected 2 total posts after intentional second order, got %d", posts.Load())
	}
}

func TestGigahostPurchaseSafety_OrderListingPreservesInFlightAndBlocksDuplicateRetry(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var posts, statusCalls atomic.Int32
	deployStatus := gigahost.StatusInstalling

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 1000.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			return []gigahost.HourlyPlan{{
				ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 90.0, InStock: true,
				Regions: []gigahost.Region{{ID: 1, Available: true}},
			}}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			if posts.Load() > 0 {
				return []gigahost.ServerInfo{{ID: 3500, OrderID: "10001", PID: 101, Status: "active"}}, nil
			}
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			statusCalls.Add(1)
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: deployStatus}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "10001", Status: gigahost.StatusPending}, nil
		},
	})

	postOrder := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		return w
	}
	listOrders := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrdersHandler(w, req)
		return w
	}

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`

	// 1. Initial order placement
	w1 := postOrder(body)
	if w1.Code != http.StatusOK || posts.Load() != 1 {
		t.Fatalf("expected order 1 HTTP 200 with 1 post, got code %d, posts %d", w1.Code, posts.Load())
	}

	// 2. Normal order listing (GET /orders) refreshes against provider inventory where server status is "active".
	// R8-H1: refreshOrderFromServers MUST NOT overwrite in-flight "installing" status with "active".
	listW := listOrders()
	if listW.Code != http.StatusOK {
		t.Fatalf("expected GET /orders HTTP 200, got %d", listW.Code)
	}

	dbOrders, err := h.getGigahostOrders(context.Background())
	if err != nil || len(dbOrders) != 1 {
		t.Fatalf("failed to query orders: %v (len %d)", err, len(dbOrders))
	}
	if strings.ToLower(dbOrders[0].Status) == "active" || dbOrders[0].Status != gigahost.StatusInstalling {
		t.Fatalf("expected order status to remain in-flight installing, got %q", dbOrders[0].Status)
	}

	// 3. Duplicate order request while still installing must be refused with 202 Accepted.
	w2 := postOrder(body)
	if w2.Code != http.StatusAccepted || !strings.Contains(w2.Body.String(), "Prior purchase order is pending reconciliation") {
		t.Fatalf("expected 202 duplicate refusal, got %d (body: %s)", w2.Code, w2.Body.String())
	}
	if posts.Load() != 1 {
		t.Errorf("expected duplicate order not to post to provider, posts was %d", posts.Load())
	}

	// 4. Once deploy status transitions to ready, subsequent order succeeds.
	deployStatus = gigahost.StatusReady
	listOrders()
	w3 := postOrder(body)
	if w3.Code != http.StatusOK || posts.Load() != 2 {
		t.Fatalf("expected request 3 HTTP 200 after ready with 2 posts, got code %d, posts %d", w3.Code, posts.Load())
	}
}

func TestGigahostPurchaseSafety_OmittedClientRatePersistsCatalogPrice(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	var posts atomic.Int32
	catalogStockPlan101 := true

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(ctx context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(ctx context.Context) ([]gigahost.HourlyPlan, error) {
			plans := []gigahost.HourlyPlan{{
				ProductID: 102, PriceID: 556, HourlyRateNOK: 0.125, MonthlyCeiling: 90.0, InStock: true,
				Regions: []gigahost.Region{{ID: 1, Available: true}},
			}}
			if catalogStockPlan101 {
				plans = append(plans, gigahost.HourlyPlan{
					ProductID: 101, PriceID: 555, HourlyRateNOK: 0.14375, MonthlyCeiling: 103.5, InStock: true,
					Regions: []gigahost.Region{{ID: 1, Available: true}},
				})
			}
			return plans, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			if posts.Load() > 0 {
				return []gigahost.ServerInfo{{ID: 3500, OrderID: "10001", PID: 101, Status: gigahost.StatusReady}}, nil
			}
			return []gigahost.ServerInfo{}, nil
		},
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady}, nil
		},
		orderServerSafeFn: func(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			posts.Add(1)
			return &gigahost.OrderResponse{OrderID: "10001", Status: gigahost.StatusReady}, nil
		},
	})

	postOrder := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		h.GigahostOrderHandler(w, req)
		return w
	}

	// 1. Order Plan 101 with OMITTED hourly_price_nok
	w1 := postOrder(`{"pid":101,"price_id":555,"region_id":1,"os_id":12}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected order 1 HTTP 200, got %d (body: %s)", w1.Code, w1.Body.String())
	}

	// Verify the database record has the authoritative catalog rate (0.14375), NOT 0!
	orders, err := h.getGigahostOrders(ctx)
	if err != nil || len(orders) != 1 || orders[0].HourlyPriceNOK != 0.14375 {
		t.Fatalf("expected stored HourlyPriceNOK 0.14375 from catalog, got %v (err: %v)", orders, err)
	}

	// 2. Plan 101 leaves the catalog: the recorded order-time price must still
	//    be the one stored, not a re-derivation or a zero.
	catalogStockPlan101 = false

	orders, err = h.getGigahostOrders(ctx)
	if err != nil || len(orders) != 1 {
		t.Fatalf("orders = %+v, err = %v", orders, err)
	}
	if orders[0].PriceID != 555 || orders[0].MonthlyCapNOK != 103.5 {
		t.Errorf("price identity = %+v, want the catalog contract 555/103.5", orders[0])
	}
	if posts.Load() != 1 {
		t.Errorf("expected exactly 1 purchase, got %d", posts.Load())
	}
}
