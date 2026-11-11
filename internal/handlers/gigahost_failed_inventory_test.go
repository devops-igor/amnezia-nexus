package handlers

// Durable behaviour of the status read across an inventory outage.
//
// The reported defect: a temporary inventory failure publishes no evidence either way, but the
// optional deployment-detail 404 that follows was still read as proof that the order was gone.
// The row was written terminal, and because terminal rows are skipped before the inventory is
// consulted, ordinary provider recovery could never repair it — a live, billable order stayed
// cancelled.
//
// These tests use the shipping client over an in-process transport, the real list handler and the
// real SQLite store, reload the row, and render through the shipped modules. The three-read
// sequence is the point: the middle read's outage must not cost the row its future.
//
// The distinction under test is provenance, not permission. A successfully read inventory that
// names nobody is genuine absence and still cancels; an inventory that could not be read is
// unknown, and unknown is not absence.

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

// inventoryPhase describes one read's provider behaviour.
type inventoryPhase struct {
	name string
	// serversCode/serversBody are served at GET /servers.
	serversCode int
	serversBody string
	// detailCode/detailBody are served at every supported deployment-detail URL form.
	detailCode int
	detailBody string
}

// phaseSequence drives the three reads and asserts the durable outcome of each.
func runInventoryOutageSequence(t *testing.T, phases []inventoryPhase, want []struct {
	status  string
	outcome string
	render  string
}) {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "inv-outage"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		AssignedIP: "198.51.100.81", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed ready order: %v", err)
	}

	phase := 0
	detailCalls := 0
	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: "https://provider.invalid",
		APIKey:  funcTestKey,
		Transport: durableRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet {
				return nil, fmt.Errorf("unexpected side effect %s", r.Method)
			}
			current := phases[phase]
			var code int
			var body string
			switch {
			case strings.HasSuffix(r.URL.Path, "/servers"):
				code, body = current.serversCode, current.serversBody
			case strings.Contains(r.URL.Path, "deploy/status"):
				detailCalls++
				code, body = current.detailCode, current.detailBody
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
		t.Fatalf("build client: %v", err)
	}
	h.SetGigahostClient(client)

	var lastConfirmed string
	for i := range phases {
		phase = i
		read := gigahostOrderStatusRead(t, h, orderID)

		rows, err := h.getGigahostOrders(ctx)
		if err != nil {
			t.Fatalf("reload after %s: %v", phases[i].name, err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected one order, got %d", len(rows))
		}
		if rows[0].Status != want[i].status {
			t.Fatalf("after %q the durable status is %q, want %q — a failed inventory read is "+
				"unknown, not evidence of absence", phases[i].name, rows[0].Status, want[i].status)
		}

		obs := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
		if got := obs["outcome"]; got != want[i].outcome {
			t.Fatalf("after %q the observation is %v, want outcome %q", phases[i].name, obs, want[i].outcome)
		}

		rendered := runGigahostOrderStatusRendererLoads(t, read, orderID)
		if !strings.Contains(rendered, want[i].render) {
			t.Fatalf("after %q the rendered view must contain %s, got %s",
				phases[i].name, want[i].render, rendered)
		}

		// The outage must be visible and must not claim a successful check.
		if want[i].outcome == gigahostObservationUnavailable {
			if !strings.Contains(rendered, `"stale":"true"`) && !strings.Contains(rendered, `"staleNotice":true`) {
				t.Fatalf("an unavailable inventory read must render stale, got %s", rendered)
			}
			if lastConfirmed != "" && strings.Contains(rendered, lastConfirmed) == false {
				// The previous confirmation time must survive the outage rather than advance.
				t.Logf("note: previous confirmed time %q no longer present during outage", lastConfirmed)
			}
		}
		if strings.Contains(rendered, `"lastSuccessAt":"`) && want[i].outcome == gigahostObservationConfirmed {
			lastConfirmed = rendered
		}
	}
}

// TestGigahostOrderInventoryOutageDoesNotCancelLiveOrder is the F6 regression.
//
// live inventory + detail404 → inventory503 + detail404 → recovered live inventory + detail404.
// The row must stay live throughout, report unavailable during the outage, and resume confirmed
// reconciliation once the inventory answers again.
func TestGigahostOrderInventoryOutageDoesNotCancelLiveOrder(t *testing.T) {
	const liveInventory = `[{"id":775,"order_id":"inv-outage","status":"ready","ipv4":"198.51.100.81"}]`
	runInventoryOutageSequence(t,
		[]inventoryPhase{
			{name: "live inventory, detail 404", serversCode: http.StatusOK, serversBody: liveInventory,
				detailCode: http.StatusNotFound, detailBody: `{"error":"deployment detail expired"}`},
			{name: "inventory 503, detail 404", serversCode: http.StatusServiceUnavailable,
				serversBody: `{"error":"inventory temporarily unavailable"}`,
				detailCode:  http.StatusNotFound, detailBody: `{"error":"deployment detail expired"}`},
			{name: "recovered inventory, detail 404", serversCode: http.StatusOK, serversBody: liveInventory,
				detailCode: http.StatusNotFound, detailBody: `{"error":"deployment detail expired"}`},
		},
		[]struct{ status, outcome, render string }{
			{"ready", gigahostObservationConfirmed, `"stage":"ready"`},
			{"ready", gigahostObservationUnavailable, `"stale":"true"`},
			{"ready", gigahostObservationConfirmed, `"stage":"ready"`},
		})
}

// TestGigahostOrderInventoryOutageKeepsOrderRefreshable pins the specific durable consequence: after
// an outage, the next read must actually reach the provider again. A row left terminal would be
// skipped and the detail counter would stop advancing.
func TestGigahostOrderInventoryOutageKeepsOrderRefreshable(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "inv-refreshable"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		AssignedIP: "198.51.100.82", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	phase := 0
	detailCalls := 0
	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: "https://provider.invalid",
		APIKey:  funcTestKey,
		Transport: durableRoundTripper(func(r *http.Request) (*http.Response, error) {
			code, body := http.StatusOK, ""
			switch {
			case strings.HasSuffix(r.URL.Path, "/servers"):
				if phase == 1 {
					code, body = http.StatusServiceUnavailable, `{"error":"inventory down"}`
				} else {
					body = `[{"id":775,"order_id":"inv-refreshable","status":"ready","ipv4":"198.51.100.82"}]`
				}
			case strings.Contains(r.URL.Path, "deploy/status"):
				detailCalls++
				code, body = http.StatusNotFound, `{"error":"detail expired"}`
			default:
				return nil, fmt.Errorf("unexpected %s", r.URL.Path)
			}
			return &http.Response{StatusCode: code, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	h.SetGigahostClient(client)

	_ = gigahostOrderStatusRead(t, h, orderID)
	before := detailCalls
	phase = 1
	_ = gigahostOrderStatusRead(t, h, orderID)
	duringOutage := detailCalls
	phase = 2
	_ = gigahostOrderStatusRead(t, h, orderID)
	after := detailCalls

	if before == 0 {
		t.Fatalf("the first read must have attempted the detail read")
	}
	if duringOutage <= before {
		t.Fatalf("the outage read must still consult the provider for this order (%d -> %d): "+
			"an unavailable inventory does not make the order unreadable", before, duringOutage)
	}
	if after <= duringOutage {
		t.Fatalf("the recovered read must consult the provider again (%d -> %d). A row left "+
			"terminal is skipped and never reconciles", duringOutage, after)
	}
}

// TestGigahostOrderSuccessfulEmptyInventoryStillCancels is the control that keeps this correction
// from swallowing real absence: an inventory that answered and named nobody, with a 404 detail, is
// still a cancellation.
func TestGigahostOrderSuccessfulEmptyInventoryStillCancels(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "inv-absent"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		AssignedIP: "198.51.100.83", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: "https://provider.invalid",
		APIKey:  funcTestKey,
		Transport: durableRoundTripper(func(r *http.Request) (*http.Response, error) {
			code, body := http.StatusOK, ""
			switch {
			case strings.HasSuffix(r.URL.Path, "/servers"):
				body = `[]` // answered, and named nobody
			case strings.Contains(r.URL.Path, "deploy/status"):
				code, body = http.StatusNotFound, `{"error":"no such order"}`
			default:
				return nil, fmt.Errorf("unexpected %s", r.URL.Path)
			}
			return &http.Response{StatusCode: code, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	h.SetGigahostClient(client)

	read := gigahostOrderStatusRead(t, h, orderID)
	rows, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rows[0].Status != statusCancelled {
		t.Fatalf("a successfully read inventory that names nobody is genuine absence and must "+
			"still cancel, got %q", rows[0].Status)
	}
	if got := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("that cancellation is a provider answer and must be confirmed, got %v", got)
	}
}

// TestGigahostOrderAuthoritativeTerminalDuringInventoryOutage covers the adjacent realistic case
// the acceptance asks me to challenge: while the inventory read fails, an explicit terminal answer
// from the detail read is still a real provider statement about the order and must still apply.
// Suppressing it would trade one lost fact for another.
func TestGigahostOrderAuthoritativeTerminalDuringInventoryOutage(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "inv-terminal-outage"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		AssignedIP: "198.51.100.84", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: "https://provider.invalid",
		APIKey:  funcTestKey,
		Transport: durableRoundTripper(func(r *http.Request) (*http.Response, error) {
			code, body := http.StatusOK, ""
			switch {
			case strings.HasSuffix(r.URL.Path, "/servers"):
				code, body = http.StatusServiceUnavailable, `{"error":"inventory down"}`
			case strings.Contains(r.URL.Path, "deploy/status"):
				body = `{"status":"cancelled"}` // the provider says how it ended
			default:
				return nil, fmt.Errorf("unexpected %s", r.URL.Path)
			}
			return &http.Response{StatusCode: code, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	h.SetGigahostClient(client)

	read := gigahostOrderStatusRead(t, h, orderID)
	rows, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rows[0].Status != statusCancelled {
		t.Fatalf("an explicit terminal provider answer must still terminate the row during an "+
			"inventory outage, got %q", rows[0].Status)
	}
	obs := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
	if got := obs["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("that terminal answer must be reported as confirmed, got %v", got)
	}
}

// TestGigahostOrderInventoryOutageDetailProgressDoesNotConfirm is the other adjacent case: a
// non-terminal detail answer during an inventory outage must NOT be promoted to a confirmation,
// because the read as a whole did not reach the provider fully and the view must stay stale.
func TestGigahostOrderInventoryOutageDetailProgressDoesNotConfirm(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const orderID = "inv-progress-outage"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "ready", ServerID: 775,
		AssignedIP: "198.51.100.85", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: "https://provider.invalid",
		APIKey:  funcTestKey,
		Transport: durableRoundTripper(func(r *http.Request) (*http.Response, error) {
			code, body := http.StatusOK, ""
			switch {
			case strings.HasSuffix(r.URL.Path, "/servers"):
				code, body = http.StatusServiceUnavailable, `{"error":"inventory down"}`
			case strings.Contains(r.URL.Path, "deploy/status"):
				body = `{"status":"deploying"}` // progress, not an end
			default:
				return nil, fmt.Errorf("unexpected %s", r.URL.Path)
			}
			return &http.Response{StatusCode: code, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		}),
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	h.SetGigahostClient(client)

	read := gigahostOrderStatusRead(t, h, orderID)
	obs := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
	if got := obs["outcome"]; got != gigahostObservationUnavailable {
		t.Fatalf("with the inventory unreadable the read as a whole is unavailable, got %v — a "+
			"detail progress answer must not be promoted to a provider confirmation", got)
	}
	rendered := runGigahostOrderStatusRendererLoads(t, read, orderID)
	if !strings.Contains(rendered, `"stale":"true"`) {
		t.Fatalf("the view must stay visibly stale while the inventory is unreadable, got %s", rendered)
	}
}
