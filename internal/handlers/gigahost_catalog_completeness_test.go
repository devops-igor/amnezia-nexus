package handlers

// Real-parser regressions for the catalog cache's completeness boundary.
//
// These drive the ACTUAL provider client over a controlled in-memory transport and
// the ACTUAL handler and cache. The point is deliberate: the earlier cache tests
// proved retention by injecting a Go error from the fake provider, which cannot
// show what happens when the provider answers HTTP 200 with a body that is valid
// JSON but not the documented envelope. That is the shape an ordinary upstream
// fault produces, and Go's decoder accepts it silently.
//
// Covered here:
//   - a malformed distribution list or image page must not replace a complete
//     cached catalog, must keep its fetched_at, and must be reported stale;
//   - the failure must take the bounded-retry path and recover after the backoff;
//   - an explicitly empty provider answer stays a legitimate fresh read;
//   - the purchase path stays authoritative and uncached.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

// catalogWireTransport serves the documented provider catalog bodies and can
// switch one path to a malformed-but-successful response on demand.
//
// It is an in-memory RoundTripper: no sockets, no live provider, and the real
// provider parser decides the outcome.
type catalogWireTransport struct {
	// malformed, when set, replaces the body of every request to path with body.
	path      string
	body      string
	malformed atomic.Bool
	calls     atomic.Int32
	// emptyDistro makes the distribution list an explicitly empty array, which is
	// a valid provider answer and must not be treated as a broken response.
	emptyDistro atomic.Bool
}

func (t *catalogWireTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	// The provider paths are matched by suffix: the client builds them under the
	// documented /api/v0 base, so the raw URL path carries that prefix.
	path := r.URL.Path
	var body string
	switch {
	case strings.HasSuffix(path, "/deploy/servers"):
		plan := fixtureHourlyPlan()
		product := gigahost.Product{
			ID:      plan.ProductID,
			PID:     plan.ProductID,
			Name:    plan.Name,
			Type:    plan.Type,
			RAMMB:   plan.RAMMB,
			InStock: true,
			Regions: plan.Regions,
			Prices: []gigahost.Price{{
				ID:             plan.PriceID,
				BillingPeriod:  "hourly",
				HourlyRate:     plan.HourlyRateNOK,
				MonthlyCeiling: plan.MonthlyCeiling,
				Currency:       "NOK",
			}},
		}
		raw, err := json.Marshal([]gigahost.Product{product})
		if err != nil {
			return nil, err
		}
		body = string(raw)
	case strings.HasSuffix(path, "/reinstall/distro"):
		if t.emptyDistro.Load() {
			body = `{"meta":{"status":200},"data":[]}`
			break
		}
		body = `{"meta":{"status":200},"data":[{"dist_id":"1","dist_name":"Debian","dist_active":"1"}]}`
	case strings.HasSuffix(path, "/reinstall/distro/1"):
		body = `{"meta":{"status":200},"data":[{"os_id":"12","dist_id":"1","os_name":"Debian 12"}]}`
	default:
		return nil, errors.New("unexpected provider operation in the catalog fixture")
	}
	if t.malformed.Load() && strings.HasSuffix(path, t.path) {
		body = t.body
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

// newWireBackedCatalogHandler builds the real handler over the real provider
// client with the controlled transport and a controllable cache clock.
func newWireBackedCatalogHandler(t *testing.T, transport *catalogWireTransport) (*Handlers, *fakeClock) {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	client, err := gigahost.NewClient(gigahost.Config{
		APIKey:    "flux_live_" + strings.Repeat("c", 64),
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("building the provider client: %v", err)
	}
	h.SetGigahostClient(client)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	h.catalogCache().now = clock.Now
	return h, clock
}

// TestCatalogCache_MalformedSuccessDoesNotReplaceSnapshot is the malformed-refresh
// regression: every malformed-but-200 provider body must leave the complete cached
// catalog intact, keep its timestamp, and be reported stale.
func TestCatalogCache_MalformedSuccessDoesNotReplaceSnapshot(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{"missing distribution data", "/reinstall/distro", `{"meta":{"status":200}}`},
		{"null distribution data", "/reinstall/distro", `{"meta":{"status":200},"data":null}`},
		{"null distribution body", "/reinstall/distro", `null`},
		{"missing image data", "/reinstall/distro/1", `{"meta":{"status":200}}`},
		{"null image data", "/reinstall/distro/1", `{"meta":{"status":200},"data":null}`},
		{"null image body", "/reinstall/distro/1", `null`},
		{"image without os_id", "/reinstall/distro/1", `{"meta":{"status":200},"data":[{"os_name":"Debian 12"}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport := &catalogWireTransport{path: tc.path, body: tc.body}
			h, clock := newWireBackedCatalogHandler(t, transport)

			// Cold control: the complete documented catalog must load first.
			w, cold := getCatalog(t, h, "")
			if w.Code != http.StatusOK {
				t.Fatalf("cold load status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}
			if cold.Count != 1 || cold.OSCount != 1 || len(cold.Plans[0].OSOptions) != 1 {
				t.Fatalf("cold control invalid: %d plans / %d images / %d plan images (want 1/1/1)",
					cold.Count, cold.OSCount, len(cold.Plans[0].OSOptions))
			}
			if cold.Stale || cold.State != "fresh" {
				t.Fatalf("cold state = %q stale=%v, want fresh", cold.State, cold.Stale)
			}

			// The provider now answers HTTP 200 with a malformed body for one path.
			transport.malformed.Store(true)
			clock.advance(gigahostCatalogTTL + time.Second)

			w, after := getCatalog(t, h, "")
			if w.Code != http.StatusOK {
				t.Fatalf("malformed refresh status = %d, want 200 serving the retained snapshot (body: %s)",
					w.Code, w.Body.String())
			}
			if !after.Stale || after.State != "stale" {
				t.Errorf("malformed refresh state = %q stale=%v, want stale/true: a broken response must not be advertised as fresh",
					after.State, after.Stale)
			}
			if after.FetchedAt != cold.FetchedAt {
				t.Errorf("fetched_at advanced from %q to %q; a failed refresh must not restamp the snapshot",
					cold.FetchedAt, after.FetchedAt)
			}
			if after.Count != cold.Count || len(after.Plans) != len(cold.Plans) {
				t.Errorf("retained plans = %d (plans %d), want the prior %d", after.Count, len(after.Plans), cold.Count)
			}
			if after.OSCount != cold.OSCount {
				t.Errorf("retained images = %d, want the prior %d: a malformed image read erased usable options",
					after.OSCount, cold.OSCount)
			}
			if len(after.Plans[0].OSOptions) != 1 {
				t.Errorf("retained plan image options = %d, want the prior 1: the operator would be left with nothing selectable",
					len(after.Plans[0].OSOptions))
			}

			// The failure is bounded: inside the backoff window no new provider read.
			readsAfterFailure := transport.calls.Load()
			_, warm := getCatalog(t, h, "")
			if !warm.Stale {
				t.Errorf("warm load after failure state = %q, want stale", warm.State)
			}
			if got := transport.calls.Load(); got != readsAfterFailure {
				t.Errorf("provider calls inside the failure backoff = %d, want %d (no new read)", got, readsAfterFailure)
			}

			// And it recovers: once the provider answers correctly again the
			// snapshot is refreshed and reported fresh.
			transport.malformed.Store(false)
			clock.advance(gigahostCatalogFailureBackoff + time.Second)
			_, recovered := getCatalog(t, h, "")
			if recovered.Stale || recovered.State != "fresh" {
				t.Errorf("recovered state = %q stale=%v, want fresh", recovered.State, recovered.Stale)
			}
			if recovered.FetchedAt == cold.FetchedAt {
				t.Error("recovered snapshot did not advance fetched_at; the retry did not actually refresh")
			}
		})
	}
}

// TestCatalogCache_ExplicitEmptyProviderAnswerIsFresh is the positive control that
// keeps the fix honest: rejecting malformed envelopes must not turn a legitimate
// "this account has no distributions/images" answer into an error.
func TestCatalogCache_ExplicitEmptyProviderAnswerIsFresh(t *testing.T) {
	transport := &catalogWireTransport{}
	transport.emptyDistro.Store(true)
	h, _ := newWireBackedCatalogHandler(t, transport)

	w, body := getCatalog(t, h, "")
	if w.Code != http.StatusOK {
		t.Fatalf("explicit empty distribution list status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	if body.Stale || body.State != "fresh" {
		t.Errorf("explicit empty answer state = %q stale=%v, want fresh: an empty list is a valid provider answer",
			body.State, body.Stale)
	}
	if body.OSCount != 0 {
		t.Errorf("images = %d, want 0 for an explicitly empty distribution list", body.OSCount)
	}
	// The plan is still published; only its image options are empty, which the
	// portal renders as "no operating system installable".
	if body.Count != 1 {
		t.Errorf("plans = %d, want the provider's 1", body.Count)
	}
}

// TestCatalogCache_MalformedRefreshPreservesPurchaseAuthority re-proves the core
// boundary with the real parser in play: a warm display snapshot plus a live
// catalog that no longer sells the plan must still yield zero purchases.
func TestCatalogCache_MalformedRefreshPreservesPurchaseAuthority(t *testing.T) {
	transport := &catalogWireTransport{path: "/reinstall/distro", body: `{"meta":{"status":200}}`}
	h, clock := newWireBackedCatalogHandler(t, transport)

	// Warm a complete, selectable display snapshot.
	if w, cold := getCatalog(t, h, ""); w.Code != http.StatusOK || cold.Count != 1 {
		t.Fatalf("cold control failed: %d %+v", w.Code, cold)
	}
	// The image path now returns a malformed success, and the snapshot expires.
	transport.malformed.Store(true)
	clock.advance(gigahostCatalogTTL + time.Second)
	if _, after := getCatalog(t, h, ""); !after.Stale {
		t.Fatalf("expected the malformed refresh to serve stale, got %q", after.State)
	}

	// The order path never consults that snapshot. Its own live read now returns a
	// catalog whose plan is out of stock, so the order must be refused with no
	// purchase. The transport keeps serving the malformed image body, so a purchase
	// path that had reused the cache would also fail differently - either way zero
	// purchases is the assertion that matters.
	var purchases atomic.Int32
	h.SetGigahostClient(&purchaseCountingClient{
		Client:    mustProviderClient(t, transport),
		purchases: &purchases,
	})

	w := postAdminOrder(t, h, "admin-malformed-authority", `{"pid":101,"price_id":555,"region_id":1,"os_id":12}`)
	if w.Code == http.StatusOK {
		t.Fatalf("order succeeded against a stale snapshot; body: %s", w.Body.String())
	}
	if got := purchases.Load(); got != 0 {
		t.Errorf("provider purchases = %d, want 0", got)
	}
}

// purchaseCountingClient forwards every provider call to the real client and
// counts only the paid request, so "zero purchases" is a measurement of the real
// client path rather than of a stub that never reaches it.
type purchaseCountingClient struct {
	gigahost.Client
	purchases *atomic.Int32
}

func (c *purchaseCountingClient) OrderServerSafe(ctx context.Context, req gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	c.purchases.Add(1)
	return c.Client.OrderServerSafe(ctx, req)
}

// mustProviderClient builds the real provider client over the fixture transport.
func mustProviderClient(t *testing.T, transport *catalogWireTransport) gigahost.Client {
	t.Helper()
	c, err := gigahost.NewClient(gigahost.Config{
		APIKey:    "flux_live_" + strings.Repeat("d", 64),
		Transport: transport,
	})
	if err != nil {
		t.Fatalf("building the provider client: %v", err)
	}
	return c
}

// postAdminOrder submits one order as an admin through the real handler.
func postAdminOrder(t *testing.T, h *Handlers, admin, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: admin,
		Role:   models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	return w
}
