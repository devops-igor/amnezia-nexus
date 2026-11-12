package gigahost

// Ambiguous provider order responses (#739 acceptance: an ambiguous outcome must
// stay protected against duplicate orders).
//
// These are the two remaining ways a provider can accept a request without
// identifying what it ordered, and both are safety-critical for placement: an
// order that silently looked "placed" while its identity was lost is exactly how a
// duplicate gets bought. They are exercised through the real HTTP client against a
// fixture server, so the decode path is the production one.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// usageOrderServer answers POST /deploy/servers with body, and /servers with an
// empty page so the pre-order inventory read succeeds.
func usageOrderServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
		case r.URL.Path == "/deploy/servers":
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestOrderServer_UndecodableAcceptanceIsUncertain pins that a 2xx whose body
// cannot be decoded is reported as an uncertain outcome. It is NOT a plain
// failure: the provider may well have queued a server, so the caller must not
// retry.
func TestOrderServer_UndecodableAcceptanceIsUncertain(t *testing.T) {
	server := usageOrderServer(t, `not json at all`)
	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.OrderServer(context.Background(), OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	})
	if err == nil {
		t.Fatal("an undecodable acceptance must not look like success")
	}
	var uncertain *OrderUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("error = %v, want an OrderUncertainError", err)
	}
	if uncertain.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want the acceptance status %d", uncertain.StatusCode, http.StatusOK)
	}
	if !isUncertainOrderError(err) {
		t.Error("an undecodable acceptance must be classified uncertain so no retry follows")
	}
}

// TestOrderServer_AcceptedWithoutOrderIDIsUncertain pins the other ambiguous
// shape: a decodable 2xx that carries no order id. Without this, a pinned order
// with a lost identity could be retried and bought twice.
//
// Honest scope: OrderResponse.UnmarshalJSON itself rejects a body without an order
// id, so this case is caught there and reported as an undecodable acceptance. The
// redundant guard later in OrderServer is therefore unreachable by construction,
// which is also why that function cannot reach 100% statement coverage.
func TestOrderServer_AcceptedWithoutOrderIDIsUncertain(t *testing.T) {
	server := usageOrderServer(t, `{"meta":{"status":200},"data":{"status":"pending"}}`)
	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.OrderServer(context.Background(), OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	})
	if err == nil {
		t.Fatal("an acceptance without an order id must not look like success")
	}
	var uncertain *OrderUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("error = %v, want an OrderUncertainError", err)
	}
	if !strings.Contains(uncertain.Message, "no order id") {
		t.Errorf("message = %q, want it to name the missing order id", uncertain.Message)
	}
	if !isUncertainOrderError(err) {
		t.Error("an acceptance without an order id must be classified uncertain")
	}
}

// TestOrderServerSafe_AcceptedWithoutOrderIDBlocksTheRepeat pins the end-to-end
// consequence of both shapes above: the client records the selection as unknown
// and then refuses the identical order without a second POST.
func TestOrderServerSafe_AcceptedWithoutOrderIDBlocksTheRepeat(t *testing.T) {
	bodies := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
		case "/deploy/servers":
			bodies++
			_, _ = w.Write([]byte(`{"meta":{"status":200},"data":{"status":"pending"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req := OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	}
	if _, err := c.OrderServerSafe(context.Background(), req); err == nil {
		t.Fatal("expected the ambiguous acceptance to be reported")
	}
	if _, err := c.OrderServerSafe(context.Background(), req); err == nil {
		t.Fatal("the identical repeat must be refused while the outcome is unknown")
	}
	if bodies != 1 {
		t.Errorf("provider order POSTs = %d, want exactly 1 (no duplicate purchase)", bodies)
	}
}
