package handlers

// One authority for "the provider no longer holds this order".
//
// The order ledger records absence from a successful, complete inventory read attributed
// to the order's own account (gigahost_order_reconcile.go). A second, weaker writer used
// to exist: a deployment-detail 404 was read as a cancellation. That branch carried none
// of the reconciliation's evidence - a 404 says the same thing whether the order was
// cancelled, belongs to another account, or was simply not found by a partial read - so a
// foreign account, an unidentifiable inventory entry and a refused account read all
// durably retired a live order, and cancellation is not repaired by inventory either.
//
// These regressions drive the real list handler, the real SQLite store and the shipped
// provider client against a controlled fixture, then reload the row so every assertion is
// about durable state. The control cases are the ones that must keep working: a genuine
// omission still retires, and an explicit provider terminal status still applies.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestDetail404CannotRetireAnOrderTheInventoryDidNotJudge is the F1007-01 regression.
//
// Every case reaches the detail-404 branch with evidence the reconciliation refuses to
// treat as absence: a foreign account, an incomplete inventory, and a refused account
// read. None of them may change the order, because none of them is an answer about it.
//
// The three cases are asserted as a set on purpose. The defect was not one missing check;
// it was a second writer with no checks at all, so a regression that only covers the
// foreign-account case would leave the other two reachable.
func TestDetail404CannotRetireAnOrderTheInventoryDidNotJudge(t *testing.T) {
	const orderID = "ord_f1007_01"

	cases := []struct {
		name string
		// prepare runs before the read, so a case can record the order's account.
		prepare func(t *testing.T, h *Handlers)
		// inventory is served at GET /servers; account at GET /account.
		inventory    string
		accountReply func(w http.ResponseWriter)
	}{
		{
			name: "another account's complete inventory omits the order",
			prepare: func(t *testing.T, h *Handlers) {
				if err := h.db.SetGigahostOrderProviderAccount(context.Background(), orderID, existenceOtherAccount); err != nil {
					t.Fatalf("record the order's account: %v", err)
				}
			},
			inventory: `{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`,
		},
		{
			name: "the inventory contains an entry no server id can be read from",
			prepare: func(t *testing.T, h *Handlers) {
				// A panel purchase with no provider-named account: the reconciliation would
				// otherwise adopt the answering account and retire the order, so the
				// completeness refusal is the only thing standing between this answer and a
				// recorded absence.
			},
			inventory: `{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":0,"order_id":"some_other","status":"ready"}]}`,
		},
		{
			name: "the account that answered cannot be identified",
			prepare: func(t *testing.T, h *Handlers) {
			},
			inventory: `{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`,
			accountReply: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			seedExistenceOrder(t, h, orderID, 7201, models.PurchaseOriginPanelPurchase)
			if tc.prepare != nil {
				tc.prepare(t, h)
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/servers":
					_, _ = w.Write([]byte(tc.inventory))
				case r.URL.Path == "/account":
					if tc.accountReply != nil {
						tc.accountReply(w)
						return
					}
					_, _ = w.Write([]byte(`{"data":{"cust_id":1111,"cust_name":"Fixture"}}`))
				default:
					// The deployment detail has no record of this order, which is the
					// branch under test.
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"error":"no such order"}`))
				}
			}))
			defer srv.Close()

			client, err := gigahost.NewClient(gigahost.Config{BaseURL: srv.URL, APIKey: funcTestKey})
			if err != nil {
				t.Fatalf("build the provider client: %v", err)
			}
			h.SetGigahostClient(client)

			read := gigahostOrderStatusRead(t, h, "")

			stored := storedOrder(t, h, orderID)
			if stored.ProviderAbsent() {
				t.Errorf("a read the reconciliation refused recorded absence: %+v", stored)
			}
			if stored.Status != gigahost.StatusReady {
				t.Errorf("durable status = %q, want %q: a detail 404 is not evidence about the order",
					stored.Status, gigahost.StatusReady)
			}
			// The row must still be listed as the live deployment it is, and it must not
			// have been presented as the deletion a cancellation becomes.
			if absenceMark(t, read.Orders, orderID) {
				t.Errorf("the list response marked an order nobody observed absent: %s", read.Orders)
			}
			if got := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)["outcome"]; got == gigahostObservationConfirmed {
				t.Errorf("a detail 404 was reported as a provider confirmation: %v", got)
			}

			// A second read must reach the provider again: a row left terminal is skipped
			// and could never be reconciled by a later, usable inventory answer.
			second := gigahostOrderStatusRead(t, h, "")
			if storedAgain := storedOrder(t, h, orderID); storedAgain.Status != gigahost.StatusReady {
				t.Errorf("durable status after the second read = %q, want %q",
					storedAgain.Status, gigahost.StatusReady)
			}
			_ = second
		})
	}
}

// TestGenuineInventoryOmissionStillRetiresWithADetail404 is the paired control for the
// regression above: the correction must not turn every 404 into inaction. A complete
// inventory answer attributed to the order's own account that omits the order IS the
// panel's existence observation, and the same read's detail 404 must not change what the
// reconciliation already decided.
func TestGenuineInventoryOmissionStillRetiresWithADetail404(t *testing.T) {
	const orderID = "ord_f1007_01_control"

	h, _, _ := setupTestHandlers(t)
	seedExistenceOrder(t, h, orderID, 7202, models.PurchaseOriginPanelPurchase)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
		case r.URL.Path == "/account":
			_, _ = w.Write([]byte(`{"data":{"cust_id":1111,"cust_name":"Fixture"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no such order"}`))
		}
	}))
	defer srv.Close()

	client, err := gigahost.NewClient(gigahost.Config{BaseURL: srv.URL, APIKey: funcTestKey})
	if err != nil {
		t.Fatalf("build the provider client: %v", err)
	}
	h.SetGigahostClient(client)

	read := gigahostOrderStatusRead(t, h, "")

	stored := storedOrder(t, h, orderID)
	if !stored.ProviderAbsent() {
		t.Fatalf("a complete omission attributed to the order's own account must retire it: %+v", stored)
	}
	if stored.ProviderAbsentAccountID != existenceAccount {
		t.Errorf("the observation must name the account that answered, got %q", stored.ProviderAbsentAccountID)
	}
	if !absenceMark(t, read.Orders, orderID) {
		t.Errorf("the list response must carry the recorded absence: %s", read.Orders)
	}
	// A recorded absence is the panel's own answer, so the rendered row is DELETED with no
	// action - the same presentation an invented cancellation used to produce, now reached
	// by evidence that actually supports it.
	rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID))
	if len(rendered.Rows) != 1 || rendered.Rows[0].Stage != "deleted" || len(rendered.Rows[0].Actions) != 0 {
		t.Fatalf("a genuinely retired order must render as deleted with no action: %+v", rendered.Rows)
	}
}

// TestExplicitProviderCancellationStillTerminatesTheRow is the other control: the
// authoritative provider statement the correction must not swallow. A successful detail
// answer that says the order was cancelled is the provider's own word about this order,
// so it is recorded whatever the inventory said.
func TestExplicitProviderCancellationStillTerminatesTheRow(t *testing.T) {
	const orderID = "ord_f1007_01_cancel"

	h, _, _ := setupTestHandlers(t)
	seedExistenceOrder(t, h, orderID, 7203, models.PurchaseOriginPanelPurchase)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":1},"data":[{"srv_id":7203,"order_id":"ord_f1007_01_cancel","status":"ready","ipv4":"198.51.100.31"}]}`))
		case r.URL.Path == "/account":
			_, _ = w.Write([]byte(`{"data":{"cust_id":1111,"cust_name":"Fixture"}}`))
		default:
			_, _ = w.Write([]byte(`{"data":{"servers":[{"order_id":"ord_f1007_01_cancel","status":"cancelled","srv_id":7203}]}}`))
		}
	}))
	defer srv.Close()

	client, err := gigahost.NewClient(gigahost.Config{BaseURL: srv.URL, APIKey: funcTestKey})
	if err != nil {
		t.Fatalf("build the provider client: %v", err)
	}
	h.SetGigahostClient(client)

	read := gigahostOrderStatusRead(t, h, "")

	stored := storedOrder(t, h, orderID)
	if stored.Status != statusCancelled {
		t.Fatalf("an explicit provider cancellation must still terminate the row, got %q", stored.Status)
	}
	if got := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)["outcome"]; got != gigahostObservationConfirmed {
		t.Errorf("the provider's own cancellation is a confirmation, got %v", got)
	}
}

// TestOrderListPublishesTheRetirementDecisionPerOrder pins the wire contract the browser
// half reads: the absence map is the panel's own decision, so a consumer can present an
// ending without re-deriving it from status strings, and an order nobody judged absent is
// simply not in the map.
func TestOrderListPublishesTheRetirementDecisionPerOrder(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedExistenceOrder(t, h, "ord_f1007_01_live", 7204, models.PurchaseOriginPanelPurchase)
	seedExistenceOrder(t, h, "ord_f1007_01_gone", 7205, models.PurchaseOriginPanelPurchase)
	ctx := context.Background()
	if err := h.db.SetGigahostOrderAbsence(ctx, "ord_f1007_01_gone", time.Now().UTC(), existenceAccount); err != nil {
		t.Fatalf("record the absence: %v", err)
	}

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{CustID: existenceAccount}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{ID: 7204, OrderID: "ord_f1007_01_live", Status: gigahost.StatusReady}}, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady}, nil
		},
	})

	read := gigahostOrderStatusRead(t, h, "")

	var envelope struct {
		Absent map[string]bool `json:"provider_absent_orders"`
	}
	if err := json.Unmarshal([]byte(read.Orders), &envelope); err != nil {
		t.Fatalf("the list response is not the documented shape: %v", err)
	}
	if !envelope.Absent["ord_f1007_01_gone"] {
		t.Errorf("a recorded absence must be published: %v", envelope.Absent)
	}
	if envelope.Absent["ord_f1007_01_live"] {
		t.Errorf("an order the inventory lists was published as absent: %v", envelope.Absent)
	}
}
