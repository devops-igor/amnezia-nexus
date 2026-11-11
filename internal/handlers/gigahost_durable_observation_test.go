package handlers

// Durable-state regression for the optional detail read.
//
// The reported defect was not in the returned observation but in the row behind it: when the
// provider answered an optional deploy-status request with no usable status, a live ready order
// was written to the database as cancelled, and every later list read then skipped it as
// terminal. The first response still looked healthy, which is why a response-level assertion
// could not see it.
//
// These tests therefore use the real production decoder over an in-process transport (an empty
// HTTP body is decoded by the shipping client, not hand-built as a struct), then reload the
// database and read a second time. That is the only shape that distinguishes the two: the first
// read's observation, the persisted row and the second read's rendered stage must all agree.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// durableRoundTripper serves controlled bytes in process. No socket, no live provider.
type durableRoundTripper func(*http.Request) (*http.Response, error)

func (f durableRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// funcTestKey is a well-formed provider key shape for the client constructor. It is a
// fixture value of the documented format, not a credential.
const funcTestKey = "flux_live_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// durableProviderClient builds the shipping client with a controlled detail response for one
// order, and a positive inventory entry for it.
func durableProviderClient(t *testing.T, orderID, inventoryStatus, detailBody string, detailCode int) gigahost.Client {
	t.Helper()
	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: "https://provider.invalid",
		APIKey:  funcTestKey,
		Transport: durableRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				return nil, fmt.Errorf("unexpected side effect %s", r.Method)
			}
			var body string
			code := http.StatusOK
			switch {
			case strings.HasSuffix(r.URL.Path, "/servers"):
				// The provider's inventory confirms this order as live.
				body = fmt.Sprintf(`[{"id":775,"order_id":%q,"status":%q,"ipv4":"198.51.100.77"}]`, orderID, inventoryStatus)
			case strings.Contains(r.URL.Path, "deploy/status"):
				body = detailBody
				code = detailCode
			default:
				return nil, fmt.Errorf("unexpected request %s", r.URL.Path)
			}
			return &http.Response{
				StatusCode: code,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build provider client: %v", err)
	}
	return client
}

// TestGigahostOrderDurableReadySurvivesSilentDetail is the F4 regression.
//
// A ready row that matches a positive inventory must survive an optional detail answer that
// carries no usable status: after the first read, the database must still say ready, and after a
// second read the observation must still be the inventory confirmation and the shipped renderer
// must still show the ready stage. Both empty forms are exercised because the production decoder
// accepts both with a nil error.
func TestGigahostOrderDurableReadySurvivesSilentDetail(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"empty_object", `{}`},
		{"empty_deployment_envelope", `{"data":{"servers":[]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			ctx := context.Background()
			now := time.Now().UTC()
			const orderID = "durable-ready"

			if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
				OrderID: orderID, Status: "ready", ServerID: 775,
				AssignedIP: "198.51.100.77", CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatalf("seed ready order: %v", err)
			}

			client := durableProviderClient(t, orderID, "ready", tc.body, http.StatusOK)

			// The decoder really does accept this body with no error. If that ever stops being
			// true this fixture is no longer describing the reported scenario.
			decoded, decodeErr := client.GetDeployStatus(ctx, orderID)
			if decodeErr != nil {
				t.Fatalf("the fixture body must decode without error to model the report, got %v", decodeErr)
			}
			if decoded == nil || decoded.Status != "" {
				t.Fatalf("the fixture must decode to an empty status, got %+v", decoded)
			}

			h.SetGigahostClient(client)

			// Read one, then reload from SQLite, exactly as the reported sequence does.
			first := gigahostOrderStatusRead(t, h, orderID)
			rows, err := h.getGigahostOrders(ctx)
			if err != nil {
				t.Fatalf("reload orders: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("expected one order, got %d", len(rows))
			}
			if rows[0].Status != "ready" {
				t.Fatalf("a silent optional detail answer must not durably change a "+
					"ready order, got %q after body %s", rows[0].Status, tc.body)
			}
			firstObs := gigahostOrderStatusProviderObservation(t, first.Orders, orderID)
			if got := firstObs["outcome"]; got != gigahostObservationConfirmed {
				t.Fatalf("the inventory confirmation must be reported on read one, got %v", got)
			}

			// Read two: the row is still live, so the inventory is consulted again and the
			// confirmation has to survive a second time.
			second := gigahostOrderStatusRead(t, h, orderID)
			rows, err = h.getGigahostOrders(ctx)
			if err != nil {
				t.Fatalf("reload orders after read two: %v", err)
			}
			if rows[0].Status != "ready" {
				t.Fatalf("read two must not durably change a ready order, got %q", rows[0].Status)
			}
			secondObs := gigahostOrderStatusProviderObservation(t, second.Orders, orderID)
			if got := secondObs["outcome"]; got != gigahostObservationConfirmed {
				t.Fatalf("the live confirmed inventory must survive read two, got %v", got)
			}
			if got, _ := secondObs["status"].(string); got != "ready" {
				t.Fatalf("read two must report the inventory status, got %q", got)
			}

			// And the shipped renderer must agree with the row and the observation.
			rendered := runGigahostOrderStatusRendererLoads(t, second, orderID)
			if !strings.Contains(rendered, `"stage":"ready"`) {
				t.Fatalf("the rendered stage must stay ready, got %s", rendered)
			}
			if strings.Contains(rendered, `"stage":"cancelled"`) {
				t.Fatalf("a silent detail answer must never render a cancelled stage: %s", rendered)
			}
		})
	}
}

// TestGigahostOrderDurableSilentDetailKeepsActiveRow covers the provider's other ready spelling.
// "active" is treated as ready throughout this handler (`isGigahostReady`, the cancellation
// branch that used to live here), so it must not be cancelled by silence either.
func TestGigahostOrderDurableSilentDetailKeepsActiveRow(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "durable-active"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "active", ServerID: 775,
		// Same address as the inventory: a differing address would set "updated" and skip
		// the optional detail read, so the test would not reach the state it names.
		AssignedIP: "198.51.100.77", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed active order: %v", err)
	}
	h.SetGigahostClient(durableProviderClient(t, orderID, "active", `{}`, http.StatusOK))

	_ = gigahostOrderStatusRead(t, h, orderID)
	rows, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("reload orders: %v", err)
	}
	if rows[0].Status != "active" {
		t.Fatalf("a silent detail answer must not durably change an active order, got %q", rows[0].Status)
	}
}

// TestGigahostOrderDurableSilentDetailLeavesDeployingAlone is the adjacent non-terminal state:
// a deploying order must not be cancelled by silence, and must not be moved to ready either.
func TestGigahostOrderDurableSilentDetailLeavesDeployingAlone(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "durable-deploying"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "deploying", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed deploying order: %v", err)
	}
	h.SetGigahostClient(durableProviderClient(t, orderID, "deploying", `{}`, http.StatusOK))

	_ = gigahostOrderStatusRead(t, h, orderID)
	rows, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("reload orders: %v", err)
	}
	if rows[0].Status != "deploying" {
		t.Fatalf("a silent detail answer must leave a deploying order alone, got %q", rows[0].Status)
	}
}

// TestGigahostOrderAuthoritativeDetailStillWins is the control the finding requires keeping: a
// non-empty detail status is a real provider answer and must still replace the inventory answer
// and the stored row.
func TestGigahostOrderAuthoritativeDetailStillWins(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "durable-authoritative"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		// Same address the inventory reports: an inventory field change would set "updated"
		// and skip the detail read entirely, which would make this test prove nothing about
		// detail precedence.
		AssignedIP: "198.51.100.77", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed ready order: %v", err)
	}
	// The inventory says ready (agreeing with the row), and the authoritative detail says the
	// deployment failed. The detail is the more specific read, so it must be what changes the row;
	// with a disagreeing inventory this would instead prove inventory precedence and tell us
	// nothing about the detail path.
	h.SetGigahostClient(durableProviderClient(t, orderID, "ready",
		`{"status":"failed","error":"provider reported failure"}`, http.StatusOK))

	read := gigahostOrderStatusRead(t, h, orderID)
	rows, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("reload orders: %v", err)
	}
	if rows[0].Status != "failed" {
		t.Fatalf("an authoritative detail status must still update the row, got %q", rows[0].Status)
	}
	obs := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
	if got := obs["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("the authoritative detail answer must be confirmed, got %v", got)
	}
	if got, _ := obs["status"].(string); got != "failed" {
		t.Fatalf("the authoritative detail status must win over inventory, got %q", got)
	}
}

// TestGigahostOrderFailedDetailKeepsDurableReady is the other required control: a transport-level
// failure of the optional read already left the row alone before this correction, and must keep
// doing so.
func TestGigahostOrderFailedDetailKeepsDurableReady(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "durable-503"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		AssignedIP: "198.51.100.80", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed ready order: %v", err)
	}
	h.SetGigahostClient(durableProviderClient(t, orderID, "ready",
		`{"error":"temporarily unavailable"}`, http.StatusServiceUnavailable))

	read := gigahostOrderStatusRead(t, h, orderID)
	rows, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("reload orders: %v", err)
	}
	if rows[0].Status != "ready" {
		t.Fatalf("a failed optional detail read must not change the row, got %q", rows[0].Status)
	}
	// The inventory confirmation stands, because the detail read never answered.
	obs := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
	if got := obs["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("the inventory confirmation must survive a failed detail read, got %v", got)
	}
}
