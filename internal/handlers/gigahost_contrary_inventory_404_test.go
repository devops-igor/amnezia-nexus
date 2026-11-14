package handlers

// Contrary-inventory 404 correction: the positive/negative matrix, on the real
// handler, SQLite and provider client.
//
// The defect: a deployment-detail 404 durably cancelled a live order even while the
// inventory read for the same request listed that order's server as live. The row
// then became terminal, and terminal rows are skipped on later reads, so continued
// positive inventory could never repair it.
//
// The correction must NOT be "ignore 404". These cases pin both sides:
//
//	live inventory + 404 detail      -> row keeps its live state, stays refreshable
//	no inventory + 404 detail        -> genuine absence, still cancels
//	inventory listing it terminal    -> not contrary evidence, still cancels
//	explicit authoritative status    -> keeps today's precedence, both directions
//
// Every case uses the shipping client against a controlled local provider fixture,
// the real order handler, and the real SQLite store, then reloads the row from the
// database so the assertion is about durable state rather than a response body.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

func TestGigahostOrders_ContraryInventoryNotFound(t *testing.T) {
	const orderID = "ord_contrary"

	// inventory is the exact /servers body the fixture serves; detail is the exact
	// /deploy/status answer. Each case models one coherent provider state.
	cases := []struct {
		name string
		// inventory is served verbatim at GET /servers.
		inventory string
		// detailStatus and detailBody are served at GET /deploy/status.
		detailStatus int
		detailBody   string
		// wantStatus is the durable row state after the read.
		wantStatus string
		// wantOutcome is the observation the panel reports for the order.
		wantOutcome string
		// wantRefreshable says whether a second GET must still attempt the detail read.
		wantRefreshable bool
	}{
		{
			name:            "live inventory plus 404 detail keeps the live row",
			inventory:       `{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":776,"order_id":"ord_contrary","status":"ready","ipv4":"198.51.100.76"}]}`,
			detailStatus:    http.StatusNotFound,
			detailBody:      `{"error":"order detail expired"}`,
			wantStatus:      gigahost.StatusReady,
			wantOutcome:     gigahostObservationConfirmed,
			wantRefreshable: true,
		},
		{
			name:            "genuine absence still cancels",
			inventory:       `{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`,
			detailStatus:    http.StatusNotFound,
			detailBody:      `{"error":"no such order"}`,
			wantStatus:      statusCancelled,
			wantOutcome:     gigahostObservationConfirmed,
			wantRefreshable: false,
		},
		{
			// The inventory carries a terminal status the panel accepts from it
			// (refreshOrderFromServers writes it), so the row is already terminal here
			// and the detail read is skipped. What matters for this correction is that
			// a terminal inventory status is NOT treated as contrary evidence guarding a
			// cancellation: the word the provider used is preserved rather than
			// rewritten to "cancelled".
			name:            "terminal inventory status is preserved, not contrary evidence",
			inventory:       `{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":776,"order_id":"ord_contrary","status":"deleted","ipv4":"198.51.100.76"}]}`,
			detailStatus:    http.StatusNotFound,
			detailBody:      `{"error":"no such order"}`,
			wantStatus:      "deleted",
			wantOutcome:     gigahostObservationConfirmed,
			wantRefreshable: false,
		},
		{
			name:            "authoritative cancelled detail still terminates a live row",
			inventory:       `{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":776,"order_id":"ord_contrary","status":"ready","ipv4":"198.51.100.76"}]}`,
			detailStatus:    http.StatusOK,
			detailBody:      `{"data":{"servers":[{"order_id":"ord_contrary","status":"cancelled","srv_id":776}]}}`,
			wantStatus:      statusCancelled,
			wantOutcome:     gigahostObservationConfirmed,
			wantRefreshable: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			now := time.Now().UTC()
			if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
				OrderID:    orderID,
				Status:     gigahost.StatusReady,
				ServerID:   776,
				AssignedIP: "198.51.100.76",
				CreatedAt:  now,
				UpdatedAt:  now,
			}); err != nil {
				t.Fatalf("seeding the order: %v", err)
			}

			detailCalls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/servers":
					_, _ = w.Write([]byte(tc.inventory))
				case strings.HasPrefix(r.URL.Path, "/deploy/status"):
					detailCalls++
					w.WriteHeader(tc.detailStatus)
					_, _ = w.Write([]byte(tc.detailBody))
				default:
					t.Errorf("unexpected provider path %q", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			client, err := gigahost.NewClient(gigahost.Config{BaseURL: srv.URL, APIKey: testGigahostAPIKey})
			if err != nil {
				t.Fatalf("building the client: %v", err)
			}
			h.SetGigahostClient(client)

			readOrders := func() string {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
				req = req.WithContext(middleware.WithSession(req.Context(),
					&models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
				rec := httptest.NewRecorder()
				h.GigahostOrdersHandler(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("orders read = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
				}
				return rec.Body.String()
			}

			first := readOrders()

			stored, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
			if err != nil || !found {
				t.Fatalf("reloading the order: found=%v err=%v", found, err)
			}
			if stored.Status != tc.wantStatus {
				t.Errorf("durable status after the read = %q, want %q", stored.Status, tc.wantStatus)
			}
			if !strings.Contains(first, `"outcome":"`+tc.wantOutcome+`"`) {
				t.Errorf("observation = %s, want outcome %q", first, tc.wantOutcome)
			}

			// The second read is what proves the row was not left terminal by mistake:
			// a terminal row is skipped and never consults the provider again.
			callsBefore := detailCalls
			second := readOrders()
			refreshed := detailCalls > callsBefore
			if refreshed != tc.wantRefreshable {
				t.Errorf("second read refreshed = %v, want %v (detail calls %d -> %d)",
					refreshed, tc.wantRefreshable, callsBefore, detailCalls)
			}
			_ = second

			storedAgain, foundAgain, errAgain := h.db.GetGigahostOrder(context.Background(), orderID)
			if errAgain != nil || !foundAgain {
				t.Fatalf("reloading after the second read: found=%v err=%v", foundAgain, errAgain)
			}
			if storedAgain.Status != tc.wantStatus {
				t.Errorf("durable status after the second read = %q, want %q (not repaired, not re-broken)",
					storedAgain.Status, tc.wantStatus)
			}
		})
	}
}

// TestGigahostOrders_ContraryInventoryNotFoundSurvivesReload pins the specific durable
// consequence the review described: the row must still be live, and still be the same
// live row, after a fresh database read - not merely in the response the first request
// happened to build.
func TestGigahostOrders_ContraryInventoryNotFoundSurvivesReload(t *testing.T) {
	const orderID = "ord_durable"
	h, _, _ := setupTestHandlers(t)
	now := time.Now().UTC()
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID: orderID, Status: gigahost.StatusReady, ServerID: 776,
		AssignedIP: "198.51.100.76", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":776,"order_id":"ord_durable","status":"ready","ipv4":"198.51.100.76"}]}`))
		case strings.HasPrefix(r.URL.Path, "/deploy/status"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"detail not found"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := gigahost.NewClient(gigahost.Config{BaseURL: srv.URL, APIKey: testGigahostAPIKey})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	h.SetGigahostClient(client)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	rec := httptest.NewRecorder()
	h.GigahostOrdersHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("read = %d (body %s)", rec.Code, rec.Body.String())
	}

	// A completely separate read of the store, as a later page load would do.
	orders, err := h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("listing from the store: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("orders in the store = %d, want 1", len(orders))
	}
	if orders[0].Status != gigahost.StatusReady {
		t.Errorf("durable status = %q, want %q: a missing detail record must not cancel a live order",
			orders[0].Status, gigahost.StatusReady)
	}
	if isTerminalStatus(orders[0].Status) {
		t.Error("the row must not be terminal, or later polling can never repair it")
	}
}
