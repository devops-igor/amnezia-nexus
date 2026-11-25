package gigahost_test

// The partial-order reader is an identity path, so it gets an identity regression.
//
// A 402 answer can carry order ids even though the purchase did not complete: those ids are
// what the operator's tracking and any later reconciliation have to work from. They are
// therefore decoded with the same exactness as every other durable identifier, and this test
// is what keeps that true: it combines an id beyond float64's exact range, a fractional id
// that must not become a neighboring order, and the ordinary small and absent-id controls,
// all through the real client against a local HTTP fixture.
//
// The fractional case is the one a coercing reader gets wrong silently: 816.5 becomes 816,
// which names a real but different order. The large case is the one a float64 round trip gets
// wrong: 9007199254740993 becomes 9007199254740992.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// partialOrderClient serves one POST /deploy/servers answer with the given status and body.
func partialOrderClient(t *testing.T, status int, body string) gigahost.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := gigahost.NewClient(gigahost.Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// orderServerForPartial calls the real purchase path and returns the partial-purchase error.
func orderServerForPartial(t *testing.T, client gigahost.Client) *gigahost.OrderPartialError {
	t.Helper()
	_, err := client.OrderServer(context.Background(), gigahost.OrderRequest{
		Quantity:      1,
		PID:           10,
		PriceID:       20,
		OSID:          30,
		RegionID:      40,
		BillingPeriod: gigahost.BillingPeriodHourly,
	})
	if err == nil {
		t.Fatal("a 402 answer was accepted as a completed purchase")
	}
	var partial *gigahost.OrderPartialError
	if !errors.As(err, &partial) {
		t.Fatalf("402 with ids was not classified as a partial purchase: %v", err)
	}
	return partial
}

func TestClient_HTTP402PreservesExactOrderIdentity(t *testing.T) {
	cases := []struct {
		name string
		body string
		// wantIDs is compared exactly: no truncation, no rounding, no dropped id.
		wantIDs []int64
	}{
		{
			name:    "small id control",
			body:    `{"meta":{"status":402},"data":{"message":"Invoice pending","order_ids":[20045]}}`,
			wantIDs: []int64{20045},
		},
		{
			name:    "id beyond float64 exactness survives digit for digit",
			body:    `{"meta":{"status":402},"data":{"message":"Invoice pending","order_ids":[9007199254740993]}}`,
			wantIDs: []int64{9007199254740993},
		},
		{
			name:    "large id in the nested single-field shape",
			body:    `{"meta":{"status":402},"data":{"order_id":9007199254740993,"message":"Requires manual review"}}`,
			wantIDs: []int64{9007199254740993},
		},
		{
			name:    "large id in a root-level list",
			body:    `{"error":"Payment required before deployment","order_ids":[9007199254740993]}`,
			wantIDs: []int64{9007199254740993},
		},
		{
			// 816.5 must NOT become 816: that names a different, real order. The unusable
			// entry is dropped and the usable one beside it still survives, so a bad value
			// cannot take a good one down with it.
			name:    "fractional id is dropped, not aliased",
			body:    `{"meta":{"status":402},"data":{"message":"Invoice pending","order_ids":[816.5,9007199254740993]}}`,
			wantIDs: []int64{9007199254740993},
		},
		{
			name:    "fractional id alone yields no invented order",
			body:    `{"meta":{"status":402},"data":{"message":"Invoice pending","order_ids":[816.5]}}`,
			wantIDs: nil,
		},
		{
			name:    "documented queued acknowledgement without any id",
			body:    `{"error":"Insufficient funds on account"}`,
			wantIDs: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := partialOrderClient(t, http.StatusPaymentRequired, tc.body)

			_, err := client.OrderServer(context.Background(), gigahost.OrderRequest{
				Quantity: 1, PID: 10, PriceID: 20, OSID: 30, RegionID: 40,
				BillingPeriod: gigahost.BillingPeriodHourly,
			})
			if err == nil {
				t.Fatal("a 402 answer was accepted as a completed purchase")
			}

			var partial *gigahost.OrderPartialError
			if !errors.As(err, &partial) {
				// An answer naming no usable id is an ordinary API error, which is the
				// correct outcome when nothing can be tracked.
				if tc.wantIDs != nil {
					t.Fatalf("expected a partial purchase carrying %v, got %v", tc.wantIDs, err)
				}
				return
			}

			if len(partial.OrderIDs) != len(tc.wantIDs) {
				t.Fatalf("order ids = %v, want %v", partial.OrderIDs, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if partial.OrderIDs[i] != tc.wantIDs[i] {
					t.Fatalf("order id[%d] = %d, want %d (exact identity, no rounding or truncation)",
						i, partial.OrderIDs[i], tc.wantIDs[i])
				}
			}
			if tc.wantIDs != nil && partial.FirstOrderID() != formatInt64(tc.wantIDs[0]) {
				t.Fatalf("first order id = %q, want %q", partial.FirstOrderID(), formatInt64(tc.wantIDs[0]))
			}
			// The message stays human-readable rather than becoming the raw body.
			if partial.Message == "" || partial.Message == tc.body {
				t.Fatalf("message = %q, want a readable provider message", partial.Message)
			}
		})
	}
}

// The exact previous reader is the failure this test exists for: a JSON number decoded into an
// untyped field is a float64, so 9007199254740993 rounds and 816.5 truncates to 816. The check
// above compares exact values, which is what makes restoring that reader fail here.
func TestClient_HTTP402FractionalIDDoesNotAliasASmallID(t *testing.T) {
	client := partialOrderClient(t, http.StatusPaymentRequired,
		`{"meta":{"status":402},"data":{"message":"Invoice pending","order_ids":[816.5]}}`)

	_, err := client.OrderServer(context.Background(), gigahost.OrderRequest{
		Quantity: 1, PID: 10, PriceID: 20, OSID: 30, RegionID: 40,
		BillingPeriod: gigahost.BillingPeriodHourly,
	})
	var partial *gigahost.OrderPartialError
	if errors.As(err, &partial) {
		for _, id := range partial.OrderIDs {
			if id == 816 {
				t.Fatal("the fractional id 816.5 was truncated into order 816, which names a different order")
			}
		}
		t.Fatalf("a fractional id produced order ids %v; it must produce none", partial.OrderIDs)
	}
}

// A 2xx acknowledgement whose order id is unusable must still be refused rather than recorded
// under a rounded id: the same rule, on the success path.
func TestClient_AcceptedOrderWithFractionalIDIsRefused(t *testing.T) {
	client := partialOrderClient(t, http.StatusOK,
		`{"data":{"order_id":"ORD-FRACTIONAL","server_id":816.5,"success":true}}`)

	_, err := client.OrderServer(context.Background(), gigahost.OrderRequest{
		Quantity: 1, PID: 10, PriceID: 20, OSID: 30, RegionID: 40,
		BillingPeriod: gigahost.BillingPeriodHourly,
	})
	if err == nil {
		t.Fatal("an accepted order naming a fractional server id was recorded")
	}
	// The refusal must name the value the provider actually sent. A reader that truncated
	// first would report "816", which is a different server; naming "816.5" proves the
	// fraction was preserved all the way to the validation.
	if !strings.Contains(err.Error(), "816.5") {
		t.Fatalf("the refusal does not name the exact value the provider sent: %v", err)
	}
	var uncertain *gigahost.OrderUncertainError
	if !errors.As(err, &uncertain) {
		t.Fatalf("a 2xx refusal is not classified as uncertain: %v", err)
	}
}

func formatInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		digits[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}
