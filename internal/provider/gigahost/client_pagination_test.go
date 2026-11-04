package gigahost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const paginationTestAPIKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestClient_GetServers_Pagination(t *testing.T) {
	t.Run("aggregates 105 servers across 2 pages", func(t *testing.T) {
		var page1Calls, page2Calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			if page == "1" || page == "" {
				page1Calls.Add(1)
				servers := make([]map[string]any, 100)
				for i := 0; i < 100; i++ {
					servers[i] = map[string]any{
						"id":         int64(1000 + i),
						"order_id":   fmt.Sprintf("ord_%d", 1000+i),
						"status":     "ready",
						"name":       fmt.Sprintf("srv-%d", 1000+i),
						"ip_address": fmt.Sprintf("192.0.2.%d", i+1),
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"meta": map[string]any{
						"page":        1,
						"total_pages": 2,
					},
					"data": servers,
				})
				return
			}

			if page == "2" {
				page2Calls.Add(1)
				servers := make([]map[string]any, 5)
				for i := 0; i < 5; i++ {
					servers[i] = map[string]any{
						"id":         int64(2000 + i),
						"order_id":   fmt.Sprintf("ord_%d", 2000+i),
						"status":     "ready",
						"name":       fmt.Sprintf("srv-%d", 2000+i),
						"ip_address": fmt.Sprintf("198.51.100.%d", i+1),
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"meta": map[string]any{
						"page":        2,
						"total_pages": 2,
					},
					"data": servers,
				})
				return
			}

			http.NotFound(w, r)
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		servers, err := c.GetServers(context.Background())
		if err != nil {
			t.Fatalf("unexpected error fetching paginated servers: %v", err)
		}

		if len(servers) != 105 {
			t.Fatalf("expected 105 servers aggregated across pages, got %d", len(servers))
		}
		if page1Calls.Load() != 1 || page2Calls.Load() != 1 {
			t.Errorf("expected 1 call each to page 1 and page 2, got p1=%d, p2=%d", page1Calls.Load(), page2Calls.Load())
		}
		if servers[0].ID != 1000 || servers[104].ID != 2004 {
			t.Errorf("unexpected boundary IDs: first=%d, last=%d", servers[0].ID, servers[104].ID)
		}
	})

	t.Run("fails closed when intermediate page fails with HTTP 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			w.Header().Set("Content-Type", "application/json")

			if page == "1" || page == "" {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"meta": map[string]any{
						"page":        1,
						"total_pages": 3,
					},
					"data": []map[string]any{
						{"id": 101, "status": "ready"},
					},
				})
				return
			}

			if page == "2" {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": "database connection lost",
				})
				return
			}

			http.NotFound(w, r)
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		servers, err := c.GetServers(context.Background())
		if err == nil {
			t.Fatalf("expected error on intermediate page failure, got nil error with %d servers", len(servers))
		}
	})

	t.Run("fails closed when intermediate page returns invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page := r.URL.Query().Get("page")
			if page == "1" || page == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"meta": map[string]any{
						"page":        1,
						"total_pages": 2,
					},
					"data": []map[string]any{{"id": 101}},
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.GetServers(context.Background())
		if err == nil {
			t.Fatal("expected error on invalid page JSON, got nil")
		}
	})

	t.Run("handles single unpaginated direct array response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 501, "name": "direct-srv", "status": "ready"},
			})
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		servers, err := c.GetServers(context.Background())
		if err != nil {
			t.Fatalf("unexpected error for direct array: %v", err)
		}
		if len(servers) != 1 || servers[0].ID != 501 {
			t.Fatalf("unexpected servers: %+v", servers)
		}
	})
}

func TestClient_OrderServer_OrderIDRequirement(t *testing.T) {
	req := OrderRequest{
		PID:           101,
		PriceID:       555,
		RegionID:      1,
		OSID:          12,
		BillingPeriod: BillingPeriodHourly,
		Quantity:      1,
	}

	t.Run("HTTP 200 with empty JSON returns OrderUncertainError", func(t *testing.T) {
		var posts atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/servers" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			posts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := c.OrderServerSafe(context.Background(), req)
		if err == nil {
			t.Fatal("expected OrderUncertainError on empty JSON response, got nil")
		}
		var uncertainErr *OrderUncertainError
		if !errors.As(err, &uncertainErr) {
			t.Fatalf("expected OrderUncertainError, got %T: %v", err, err)
		}
		if resp == nil || resp.Status != StatusUnknown {
			t.Fatalf("expected StatusUnknown, got %+v", resp)
		}

		// Subsequent retry must be blocked by durable unknown state
		respRetry, errRetry := c.OrderServerSafe(context.Background(), req)
		if errRetry == nil || respRetry.Status != StatusUnknown {
			t.Fatalf("expected duplicate order blocked with unknown status, got %+v %v", respRetry, errRetry)
		}
		if posts.Load() != 1 {
			t.Fatalf("expected exactly 1 POST to provider, got %d", posts.Load())
		}
	})

	t.Run("HTTP 200 with success false returns OrderUncertainError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/servers" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":false,"message":"Order processing rejected"}`))
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := c.OrderServerSafe(context.Background(), req)
		if err == nil {
			t.Fatal("expected error on success:false, got nil")
		}
		var uncertainErr *OrderUncertainError
		if !errors.As(err, &uncertainErr) {
			t.Fatalf("expected OrderUncertainError on success:false, got %T: %v", err, err)
		}
		if resp == nil || resp.Status != StatusUnknown {
			t.Fatalf("expected StatusUnknown, got %+v", resp)
		}
	})

	t.Run("HTTP 200 with missing order_id returns OrderUncertainError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/servers" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"success":true,"message":"queued","order_ids":[]}}`))
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := c.OrderServerSafe(context.Background(), req)
		if err == nil {
			t.Fatal("expected error on empty order_ids, got nil")
		}
		var uncertainErr *OrderUncertainError
		if !errors.As(err, &uncertainErr) {
			t.Fatalf("expected OrderUncertainError on missing order ID, got %T: %v", err, err)
		}
		if resp == nil || resp.Status != StatusUnknown {
			t.Fatalf("expected StatusUnknown, got %+v", resp)
		}
	})

	t.Run("HTTP 200 with valid order ID succeeds", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/servers" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"success":true,"order_ids":[998811]}}`))
		}))
		defer server.Close()

		c, err := NewClient(Config{BaseURL: server.URL, APIKey: paginationTestAPIKey})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := c.OrderServerSafe(context.Background(), req)
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		if resp == nil || resp.OrderID != "998811" || resp.Status != StatusPending {
			t.Fatalf("unexpected order response: %+v", resp)
		}
	})
}
