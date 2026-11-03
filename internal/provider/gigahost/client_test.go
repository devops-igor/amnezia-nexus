package gigahost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const testAPIKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValidateAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "valid key",
			key:     testAPIKey,
			wantErr: false,
		},
		{
			name:    "valid key uppercase hex",
			key:     "flux_live_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			wantErr: false,
		},
		{
			name:    "missing prefix",
			key:     "bearer_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "too short",
			key:     "flux_live_0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "too long",
			key:     testAPIKey + "01",
			wantErr: true,
		},
		{
			name:    "non-hex characters",
			key:     "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789zzzzzz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAPIKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAPIKey() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalidAPIKey) {
				t.Errorf("expected ErrInvalidAPIKey, got %v", err)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	t.Run("invalid api key", func(t *testing.T) {
		_, err := NewClient(Config{
			APIKey: "invalid_key",
		})
		if err == nil {
			t.Fatal("expected error for invalid API key, got nil")
		}
	})

	t.Run("valid configuration defaults", func(t *testing.T) {
		c, err := NewClient(Config{
			APIKey: testAPIKey,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cl := c.(*client)
		if cl.baseURL != DefaultBaseURL {
			t.Errorf("expected baseURL %q, got %q", DefaultBaseURL, cl.baseURL)
		}
		if cl.httpClient.Timeout != 30*time.Second {
			t.Errorf("expected default timeout 30s, got %v", cl.httpClient.Timeout)
		}
	})

	t.Run("custom roundtripper", func(t *testing.T) {
		customRT := &testRoundTripper{}
		c, err := NewClient(Config{
			APIKey:    testAPIKey,
			Transport: customRT,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cl := c.(*client)
		if cl.httpClient.Transport != customRT {
			t.Errorf("expected custom transport to be set")
		}
	})
}

type testRoundTripper struct{}

func (rt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("mock transport")
}

func TestClient_GetCatalog_HourlyFilter(t *testing.T) {
	mockCatalog := []Product{
		{
			ID:       101,
			PID:      101,
			Name:     "Cloud VPS 1 (Hourly)",
			CPUCores: 2,
			RAMMB:    2048,
			DiskGB:   40,
			InStock:  true,
			Prices: []Price{
				{
					ID:             1,
					BillingPeriod:  BillingPeriodHourly,
					Currency:       "NOK",
					HourlyRate:     0.15,
					MonthlyCeiling: 108.0,
				},
				{
					ID:             2,
					BillingPeriod:  BillingPeriodMonthly,
					Currency:       "NOK",
					MonthlyCeiling: 108.0,
					Amount:         108.0,
				},
			},
			Regions: []Region{
				{ID: 1, Name: "Oslo (NO)", Country: "NO", Available: true},
			},
			OSList: []OS{
				{ID: 10, Name: "Ubuntu 24.04 LTS"},
			},
		},
		{
			ID:       102,
			PID:      102,
			Name:     "Cloud VPS Dedicated (Monthly Only)",
			CPUCores: 8,
			RAMMB:    16384,
			DiskGB:   320,
			InStock:  true,
			Prices: []Price{
				{
					ID:             3,
					BillingPeriod:  BillingPeriodMonthly,
					Currency:       "NOK",
					MonthlyCeiling: 950.0,
					Amount:         950.0,
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/deploy/servers" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testAPIKey {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockCatalog)
	}))
	defer server.Close()

	c, err := NewClient(Config{
		BaseURL: server.URL,
		APIKey:  testAPIKey,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	plans, err := c.GetCatalog(context.Background())
	if err != nil {
		t.Fatalf("GetCatalog failed: %v", err)
	}

	if len(plans) != 1 {
		t.Fatalf("expected 1 hourly plan, got %d", len(plans))
	}

	p := plans[0]
	if p.ProductID != 101 {
		t.Errorf("expected product_id 101, got %d", p.ProductID)
	}
	if p.HourlyRateNOK != 0.15 {
		t.Errorf("expected hourly_rate_nok 0.15, got %f", p.HourlyRateNOK)
	}
	if p.MonthlyCeiling != 108.0 {
		t.Errorf("expected monthly ceiling 108.0, got %f", p.MonthlyCeiling)
	}
	if p.Currency != "NOK" {
		t.Errorf("expected currency NOK, got %s", p.Currency)
	}
	if !p.InStock {
		t.Errorf("expected in_stock true")
	}
	if len(p.Regions) != 1 || p.Regions[0].Country != "NO" {
		t.Errorf("expected Norwegian region, got %+v", p.Regions)
	}
}

func TestClient_GetAccount(t *testing.T) {
	t.Run("sufficient credit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/account" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"balance":  250.50,
				"credit":   50.00,
				"currency": "NOK",
				"status":   "active",
			})
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
		if err != nil {
			t.Fatalf("NewClient err: %v", err)
		}

		acc, err := c.GetAccount(context.Background())
		if err != nil {
			t.Fatalf("GetAccount err: %v", err)
		}
		if acc.Balance != 250.50 {
			t.Errorf("expected balance 250.50, got %f", acc.Balance)
		}
		if !acc.HasCredit() {
			t.Errorf("expected HasCredit to be true")
		}
	})

	t.Run("zero credit and balance", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(AccountInfo{
				Balance: 0,
				Credit:  0,
			})
		}))
		defer server.Close()

		c, _ := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
		acc, err := c.GetAccount(context.Background())
		if err != nil {
			t.Fatalf("GetAccount err: %v", err)
		}
		if acc.HasCredit() {
			t.Errorf("expected HasCredit false for 0 balance/credit")
		}
	})
}

func TestClient_OrderServer_Validations(t *testing.T) {
	c, _ := NewClient(Config{BaseURL: "http://example.com", APIKey: testAPIKey})

	t.Run("monthly billing rejected", func(t *testing.T) {
		_, err := c.OrderServer(context.Background(), OrderRequest{
			PID:           101,
			PriceID:       1,
			RegionID:      1,
			OSID:          1,
			BillingPeriod: BillingPeriodMonthly,
			Quantity:      1,
		})
		if !errors.Is(err, ErrInvalidBillingPeriod) {
			t.Errorf("expected ErrInvalidBillingPeriod, got %v", err)
		}
	})

	t.Run("quantity > 1 rejected", func(t *testing.T) {
		_, err := c.OrderServer(context.Background(), OrderRequest{
			PID:           101,
			PriceID:       1,
			RegionID:      1,
			OSID:          1,
			BillingPeriod: BillingPeriodHourly,
			Quantity:      2,
		})
		if !errors.Is(err, ErrInvalidQuantity) {
			t.Errorf("expected ErrInvalidQuantity, got %v", err)
		}
	})

	t.Run("zero pid rejected", func(t *testing.T) {
		_, err := c.OrderServer(context.Background(), OrderRequest{
			PID:           0,
			PriceID:       1,
			RegionID:      1,
			OSID:          1,
			BillingPeriod: BillingPeriodHourly,
			Quantity:      1,
		})
		if !errors.Is(err, ErrInvalidOrderParam) {
			t.Errorf("expected ErrInvalidOrderParam, got %v", err)
		}
	})
}

func TestClient_OrderServer_Success(t *testing.T) {
	var receivedPayload OrderRequest
	var authHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/deploy/servers" {
			http.NotFound(w, r)
			return
		}
		authHeader = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"order_id":   "ord_gh_98765",
			"server_id":  1234,
			"status":     "pending",
			"message":    "Order placed successfully",
			"created_at": "2026-11-03T12:00:00Z",
		})
	}))
	defer server.Close()

	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}

	req := OrderRequest{
		PID:           101,
		PriceID:       1,
		RegionID:      2,
		OSID:          5,
		BillingPeriod: BillingPeriodHourly,
		Quantity:      1,
	}

	resp, err := c.OrderServer(context.Background(), req)
	if err != nil {
		t.Fatalf("OrderServer err: %v", err)
	}

	if authHeader != "Bearer "+testAPIKey {
		t.Errorf("expected Bearer token in auth header, got %q", authHeader)
	}
	if receivedPayload.PID != 101 || receivedPayload.BillingPeriod != "hourly" || receivedPayload.Quantity != 1 {
		t.Errorf("unexpected payload sent to provider: %+v", receivedPayload)
	}
	if resp.OrderID != "ord_gh_98765" {
		t.Errorf("expected order_id 'ord_gh_98765', got %q", resp.OrderID)
	}
	if resp.ServerID != 1234 {
		t.Errorf("expected server_id 1234, got %d", resp.ServerID)
	}
	if resp.Status != StatusPending {
		t.Errorf("expected status 'pending', got %q", resp.Status)
	}
}

func TestClient_GetDeployStatus_And_IP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/deploy/status" {
			http.NotFound(w, r)
			return
		}
		orderID := r.URL.Query().Get("order_id")
		if orderID != "ord_test_1" {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DeployStatusResponse{
			OrderID:    "ord_test_1",
			ServerID:   555,
			Status:     StatusReady,
			Progress:   100,
			AssignedIP: "192.0.2.42",
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})

	status, err := c.GetDeployStatus(context.Background(), "ord_test_1")
	if err != nil {
		t.Fatalf("GetDeployStatus err: %v", err)
	}

	if status.Status != StatusReady {
		t.Errorf("expected status ready, got %s", status.Status)
	}
	if status.GetIP() != "192.0.2.42" {
		t.Errorf("expected IP 192.0.2.42, got %s", status.GetIP())
	}
}

func TestClient_HTTPErrorStatuses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		checkErr   func(error) bool
	}{
		{
			name:       "401 unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       `{"error":"invalid bearer token"}`,
			checkErr:   func(err error) bool { return errors.Is(err, ErrUnauthorized) },
		},
		{
			name:       "403 forbidden",
			statusCode: http.StatusForbidden,
			body:       `{"error":"insufficient permissions for deploy:rw"}`,
			checkErr:   func(err error) bool { return errors.Is(err, ErrUnauthorized) },
		},
		{
			name:       "429 rate limited",
			statusCode: http.StatusTooManyRequests,
			body:       `{"error":"rate limit exceeded"}`,
			checkErr:   func(err error) bool { return errors.Is(err, ErrRateLimited) },
		},
		{
			name:       "404 not found",
			statusCode: http.StatusNotFound,
			body:       `{"error":"server not found"}`,
			checkErr:   func(err error) bool { return errors.Is(err, ErrNotFound) },
		},
		{
			name:       "500 internal error",
			statusCode: http.StatusInternalServerError,
			body:       `{"message":"internal datastore error"}`,
			checkErr: func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && apiErr.StatusCode == 500
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			c, _ := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
			_, err := c.GetAccount(context.Background())
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", tt.statusCode)
			}
			if !tt.checkErr(err) {
				t.Errorf("checkErr failed for err: %v", err)
			}
		})
	}
}

func TestClient_OrderServerSafe_TimeoutRecoveryAndIdempotency(t *testing.T) {
	var postOrderCalls int32
	var getServersCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/servers":
			atomic.AddInt32(&getServersCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			// If POST was called, server now exists in /servers
			if atomic.LoadInt32(&postOrderCalls) > 0 {
				_ = json.NewEncoder(w).Encode([]ServerInfo{
					{
						ID:        999,
						OrderID:   "ord_recovered_1",
						Name:      "vps-auto-recovered",
						Status:    StatusDeploying,
						PID:       101,
						RegionID:  1,
						IPv4:      "198.51.100.10",
						CreatedAt: time.Now().Format(time.RFC3339),
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode([]ServerInfo{})
			}

		case r.Method == http.MethodPost && r.URL.Path == "/deploy/servers":
			atomic.AddInt32(&postOrderCalls, 1)
			// Simulate server taking too long / connection dropping
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(OrderResponse{
				OrderID:  "ord_recovered_1",
				ServerID: 999,
				Status:   StatusPending,
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, err := NewClient(Config{
		BaseURL: server.URL,
		APIKey:  testAPIKey,
		Timeout: 20 * time.Millisecond, // Client timeout will trigger before 100ms
	})
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}

	req := OrderRequest{
		PID:           101,
		PriceID:       1,
		RegionID:      1,
		OSID:          1,
		BillingPeriod: BillingPeriodHourly,
		Quantity:      1,
	}

	// First call: order times out, but OrderServerSafe recovers the server via GetServers()
	resp, err := c.OrderServerSafe(context.Background(), req)
	if err != nil {
		t.Fatalf("expected OrderServerSafe to recover server from timeout, got error: %v", err)
	}

	if resp.ServerID != 999 {
		t.Errorf("expected recovered server_id 999, got %d", resp.ServerID)
	}
	if resp.Status != StatusDeploying {
		t.Errorf("expected status 'deploying', got %s", resp.Status)
	}

	// Second call with same order parameters:
	// Pre-inspection detects matching server and reuses without duplicate POST!
	initialPostCount := atomic.LoadInt32(&postOrderCalls)
	resp2, err := c.OrderServerSafe(context.Background(), req)
	if err != nil {
		t.Fatalf("second call err: %v", err)
	}
	if resp2.ServerID != 999 {
		t.Errorf("expected reused server_id 999, got %d", resp2.ServerID)
	}
	if atomic.LoadInt32(&postOrderCalls) != initialPostCount {
		t.Errorf("expected no additional POST requests, but count increased from %d to %d",
			initialPostCount, atomic.LoadInt32(&postOrderCalls))
	}
}

func TestClient_OrderServerSafe_TimeoutUnknown(t *testing.T) {
	// Server hangs and /servers returns empty
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/servers":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]ServerInfo{})
		case r.Method == http.MethodPost && r.URL.Path == "/deploy/servers":
			time.Sleep(100 * time.Millisecond)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, _ := NewClient(Config{
		BaseURL: server.URL,
		APIKey:  testAPIKey,
		Timeout: 20 * time.Millisecond,
	})

	req := OrderRequest{
		PID:           202,
		PriceID:       1,
		RegionID:      1,
		OSID:          1,
		BillingPeriod: BillingPeriodHourly,
		Quantity:      1,
	}

	resp, err := c.OrderServerSafe(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when timeout cannot be confirmed, got nil")
	}
	if resp == nil || resp.Status != StatusUnknown {
		t.Fatalf("expected response status 'unknown', got %+v", resp)
	}
}

func TestClient_EdgeCasesAndFallbacks(t *testing.T) {
	t.Run("empty order_id on GetDeployStatus", func(t *testing.T) {
		c, _ := NewClient(Config{APIKey: testAPIKey})
		_, err := c.GetDeployStatus(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty order_id, got nil")
		}
	})

	t.Run("wrapped responses and fallback path", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/deploy/servers":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"products": []Product{
						{ID: 10, PID: 10, Name: "P10", CPUCores: 1, RAMMB: 1024, DiskGB: 20, InStock: true,
							Prices: []Price{{ID: 1, BillingPeriod: BillingPeriodHourly, HourlyRate: 0.10, Currency: "NOK"}}},
					},
				})
			case "/servers":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"servers": []ServerInfo{
						{ID: 20, Name: "S20", Status: "running", IPAddress: "192.0.2.100"},
					},
				})
			case "/account":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"account": AccountInfo{Balance: 100, Credit: 0, Currency: "NOK"},
				})
			case "/deploy/status":
				// Return 404 so client tests path fallback /deploy/status/{id}
				http.NotFound(w, r)
			case "/deploy/status/ord_fallback":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status": DeployStatusResponse{OrderID: "ord_fallback", Status: StatusReady, PublicIP: "192.0.2.200"},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		c, _ := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})

		products, err := c.GetProducts(context.Background())
		if err != nil || len(products) != 1 {
			t.Fatalf("GetProducts wrapped failed: %v", err)
		}

		servers, err := c.GetServers(context.Background())
		if err != nil || len(servers) != 1 {
			t.Fatalf("GetServers wrapped failed: %v", err)
		}
		if servers[0].GetIP() != "192.0.2.100" {
			t.Errorf("expected IP 192.0.2.100, got %s", servers[0].GetIP())
		}

		acc, err := c.GetAccount(context.Background())
		if err != nil || acc.Balance != 100 {
			t.Fatalf("GetAccount wrapped failed: %v", err)
		}

		status, err := c.GetDeployStatus(context.Background(), "ord_fallback")
		if err != nil || status.GetIP() != "192.0.2.200" {
			t.Fatalf("GetDeployStatus fallback failed: %v, status: %+v", err, status)
		}
	})

	t.Run("helper methods and IP extraction", func(t *testing.T) {
		var nilStatus *DeployStatusResponse
		if nilStatus.GetIP() != "" {
			t.Errorf("expected empty IP for nil status")
		}

		var nilServer *ServerInfo
		if nilServer.GetIP() != "" {
			t.Errorf("expected empty IP for nil server")
		}

		s1 := &DeployStatusResponse{IPv4: "10.0.0.1"}
		if s1.GetIP() != "10.0.0.1" {
			t.Errorf("expected IPv4 10.0.0.1, got %s", s1.GetIP())
		}

		srv1 := &ServerInfo{IPv4: "10.0.0.2"}
		if srv1.GetIP() != "10.0.0.2" {
			t.Errorf("expected IPv4 10.0.0.2, got %s", srv1.GetIP())
		}

		var nilAccount *AccountInfo
		if nilAccount.HasCredit() {
			t.Errorf("expected HasCredit false for nil account")
		}

		p := Product{ID: 99, PID: 0}
		if p.GetID() != 99 {
			t.Errorf("expected GetID fallback to ID 99, got %d", p.GetID())
		}
	})
}
