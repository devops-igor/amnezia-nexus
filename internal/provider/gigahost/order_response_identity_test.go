package gigahost

// Order acceptance with an identity inside the answer.
//
// A successful order is persisted with its provider order id and, when the provider sent one,
// the server id it provisioned. Both are durable identifiers, so the same exact-decimal rule
// applies to every shape the answer can take: the flat object and the `data` envelope. The
// envelope is the documented shape for a purchase acknowledgement, and a numeric identity
// inside it arriving as float64 used to be refused even when it was a small integer, which
// turned an accepted purchase into an uncertain one.
//
// Controls in the same file: the queued response that names no server, the string spelling,
// and a genuinely fractional identity that must still be refused.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// orderServerFixture serves one POST /deploy/servers answer and returns a client pointed at it.
func orderServerFixture(t *testing.T, body string) Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/deploy/servers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// validOrderRequest is the smallest request the client accepts.
func validOrderRequest() OrderRequest {
	return OrderRequest{Quantity: 1, PID: 10, PriceID: 20, OSID: 30, RegionID: 40,
		BillingPeriod: BillingPeriodHourly}
}

func TestOrderServer_ServerIDShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		// wantErr is nil when the answer must be accepted.
		wantErr        bool
		wantServerID   int64
		wantOrderID    string
		wantUncertain  bool
		failureContext string
	}{
		{
			name:         "wrapped numeric server id",
			body:         `{"data":{"order_id":"ORD-1","server_id":816,"status":"pending","success":true}}`,
			wantServerID: 816,
			wantOrderID:  "ORD-1",
		},
		{
			name:         "wrapped numeric order id",
			body:         `{"data":{"order_id":816,"server_id":816,"status":"pending","success":true}}`,
			wantServerID: 816,
			wantOrderID:  "816",
		},
		{
			name:         "wrapped string server id",
			body:         `{"data":{"order_id":"ORD-2","server_id":"816","status":"pending","success":true}}`,
			wantServerID: 816,
			wantOrderID:  "ORD-2",
		},
		{
			name:         "flat numeric server id",
			body:         `{"order_id":"ORD-3","server_id":816,"status":"pending"}`,
			wantServerID: 816,
			wantOrderID:  "ORD-3",
		},
		{
			name:        "queued acknowledgement without a server id",
			body:        `{"data":{"order_ids":["ORD-4"],"success":true}}`,
			wantOrderID: "ORD-4",
		},
		{
			name:           "wrapped fractional server id is refused",
			body:           `{"data":{"order_id":"ORD-5","server_id":816.5,"status":"pending","success":true}}`,
			wantErr:        true,
			wantUncertain:  true,
			failureContext: "a fractional server id must not be truncated into 816",
		},
		{
			name:           "wrapped server id outside int64 is refused",
			body:           `{"data":{"order_id":"ORD-6","server_id":92233720368547758080,"status":"pending","success":true}}`,
			wantErr:        true,
			wantUncertain:  true,
			failureContext: "an out-of-range server id must not be truncated",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := orderServerFixture(t, tc.body)
			resp, err := client.OrderServer(t.Context(), validOrderRequest())

			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted an unusable answer (%s): %+v", tc.failureContext, resp)
				}
				var uncertain *OrderUncertainError
				if tc.wantUncertain && !errors.As(err, &uncertain) {
					t.Fatalf("refusal is not classified as uncertain: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("a supported answer was refused: %v", err)
			}
			if resp == nil {
				t.Fatal("no response without an error")
			}
			if resp.OrderID != tc.wantOrderID {
				t.Fatalf("order id = %q, want %q", resp.OrderID, tc.wantOrderID)
			}
			if resp.ServerID != tc.wantServerID {
				t.Fatalf("server id = %d, want %d", resp.ServerID, tc.wantServerID)
			}
		})
	}
}

// The order id itself is an identity: a wrapped numeric id must be recorded exactly, not
// rounded and not dropped.
func TestOrderServer_WrappedNumericOrderIDIsExact(t *testing.T) {
	client := orderServerFixture(t, `{"data":{"order_id":9007199254740993,"success":true}}`)
	resp, err := client.OrderServer(t.Context(), validOrderRequest())
	if err != nil {
		t.Fatalf("a large exact order id was refused: %v", err)
	}
	if resp.OrderID != "9007199254740993" {
		t.Fatalf("order id = %q, want 9007199254740993", resp.OrderID)
	}
}
