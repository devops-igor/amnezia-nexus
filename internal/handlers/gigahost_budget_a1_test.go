package handlers

// A1 consumer regressions: the corrected classification and identity rules seen
// through the real purchase handler.
//
// Every case asserts the money decision (allowed/denied), the provider purchase
// call count, and the durable ledger state. A classifier that agrees with itself
// in a unit test but still lets the handler buy a second VPS on budget the first
// one is consuming would be worthless, so the assertions are at the HTTP
// boundary.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// budgetAClient wires a provider whose inventory and deploy status are fixed.
func budgetAClient(
	h *Handlers, catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo,
	deployFn func(context.Context, string) (*gigahost.DeployStatusResponse, error), posts *int32,
) {
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500, Currency: "NOK"}, nil
		},
		getCatalogFn:      func(context.Context) ([]gigahost.HourlyPlan, error) { return catalog, nil },
		getServersFn:      func(context.Context) ([]gigahost.ServerInfo, error) { return servers, nil },
		getDeployStatusFn: deployFn,
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(posts, 1)
			return &gigahost.OrderResponse{OrderID: "90001", Status: gigahost.StatusPending}, nil
		},
	})
}

// a1Catalog is plan 202 at 59 NOK/month (the existing commitment) and plan 101 at
// 59 NOK/month (the new request). 59 + 59 exceeds a 100 NOK cap.
func a1Catalog() []gigahost.HourlyPlan {
	rows := []gigahost.HourlyPlan{}
	for _, row := range []struct{ pid, priceID int }{{202, 666}, {101, 555}} {
		rows = append(rows, gigahost.HourlyPlan{
			ProductID: row.pid, PriceID: row.priceID, Currency: "NOK", HourlyRateNOK: 0.15,
			MonthlyCeiling: 59, InStock: true,
			Regions: []gigahost.Region{{ID: 1, Available: true}},
		})
	}
	return rows
}

// seedA1Order stores one pre-existing reservation.
func seedA1Order(t *testing.T, h *Handlers, rec GigahostOrderRecord) {
	t.Helper()
	now := time.Now().UTC()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt, rec.UpdatedAt = now, now
	}
	if err := h.saveGigahostOrder(context.Background(), &rec); err != nil {
		t.Fatal(err)
	}
}

// TestA1_PendingCancellationStillConsumesBudget is the primary intake
// counterexample at the consumer boundary.
//
// The provider reports the existing server as `cancelled`, which the contract
// defines as a PENDING cancellation that keeps running and billing until
// termination_date. Before A1 this released the 59 NOK commitment, and the
// handler then sold a second 59 NOK VPS against a 100 NOK cap that was already
// fully committed.
func TestA1_PendingCancellationStillConsumesBudget(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	var posts int32
	hourly := true
	budgetAClient(h, a1Catalog(),
		[]gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "cancelled", BwIsHourly: &hourly}},
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{Status: "ready"}, nil
		}, &posts)

	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("status = %d, want 400 budget_exceeded: a pending cancellation must keep consuming budget (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("provider orders = %d, want 0", got)
	}

	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range orders {
		if o.OrderID == "10001" && o.ReleasedAt != "" {
			t.Fatalf("the pending-cancellation reservation was released: %s", o.ReleaseReason)
		}
	}
}

// TestA1_DeployStatusOmissionKeepsBudget is the second intake counterexample:
// GET /deploy/status omits cancelled orders by contract, so its omission must
// not release the commitment.
func TestA1_DeployStatusOmissionKeepsBudget(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	var posts int32
	// No inventory row, and the deploy-status endpoint answers "not found".
	// Contract E1: that answer also covers cancelled orders and orders whose
	// server was deleted, so it proves nothing.
	budgetAClient(h, a1Catalog(), nil,
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, gigahost.ErrNotFound
		}, &posts)

	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("status = %d, want 400 budget_exceeded: a deploy-status omission is not proof of no charge (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("provider orders = %d, want 0", got)
	}
}

// TestA1_TerminatedServerReleasesBudget is the required positive control: the
// contract-supported release must still work through the consumer, or A1 would
// have "fixed" the defect by refusing every release.
func TestA1_TerminatedServerReleasesBudget(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	var posts int32
	hourly := true
	budgetAClient(h, a1Catalog(),
		[]gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "terminated", BwIsHourly: &hourly}},
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, gigahost.ErrNotFound
		}, &posts)

	// 59 + 59 > 100 unless the terminated commitment is released.
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after a terminated server released its commitment (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("provider orders = %d, want 1", got)
	}

	orders, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var released bool
	for _, o := range orders {
		if o.OrderID == "10001" {
			released = o.ReleasedAt != ""
			if released && o.ReleaseReason != "provider_terminated" {
				t.Errorf("release reason = %q, want provider_terminated", o.ReleaseReason)
			}
		}
	}
	if !released {
		t.Error("a contract-supported termination must release the reservation")
	}
}

// TestA1_LocalFailedLabelCannotHideALiveProviderServer is the stale-local-label
// counterexample: a locally failed attempt whose server is demonstrably running.
func TestA1_LocalFailedLabelCannotHideALiveProviderServer(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusFailed, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	var posts int32
	hourly := true
	budgetAClient(h, a1Catalog(),
		[]gigahost.ServerInfo{{ID: 7, OrderID: "10001", PID: 202, Status: "ready", BwIsHourly: &hourly}},
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{Status: "ready"}, nil
		}, &posts)

	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("status = %d, want 400: a live server must count even when the local row says failed (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("provider orders = %d, want 0", got)
	}
}

// TestA1_ConflictingIdentitiesAreTwoCommitments is the identity counterexample at
// the consumer boundary.
//
// A ledger row carries provider order id 10001 and server id 7; the provider
// inventory row carries server id 7 but order id 20002. These are contradictory
// identities. Before A1 the matching server id silently merged them into one
// commitment, halving the committed total.
func TestA1_ConflictingIdentitiesAreTwoCommitments(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	var posts int32
	hourly := true
	budgetAClient(h, a1Catalog(),
		[]gigahost.ServerInfo{{ID: 7, OrderID: "20002", PID: 202, Status: "ready", BwIsHourly: &hourly}},
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{Status: "ready"}, nil
		}, &posts)

	// Two contradictory identities are two possible commitments: 59 + 59 > 100.
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "budget_exceeded") {
		t.Fatalf("status = %d, want 400: contradictory identities must not be merged into one commitment (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("provider orders = %d, want 0", got)
	}
}

// TestA1_ServerIDOnlyMatchStillDeduplicates is the required identity positive
// control: a provider record with no order id, linked only by its server id, must
// still count exactly once. Losing this would double-count a real reservation.
func TestA1_ServerIDOnlyMatchStillDeduplicates(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	// A 150 cap discriminates: counted once, 59 + 59 = 118 fits. Double-counted,
	// 118 + 59 = 177 does not.
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 150.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	var posts int32
	hourly := true
	// Provider record has no order id at all; only the server id links them.
	budgetAClient(h, a1Catalog(),
		[]gigahost.ServerInfo{{ID: 7, PID: 202, Status: "ready", BwIsHourly: &hourly}},
		func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{Status: "ready"}, nil
		}, &posts)

	// One commitment of 59 against a 100 cap: the request fits.
	w := postBudgetOrder(t, h)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a server-id-only link must count the VPS once, not twice (body: %s)",
			w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("provider orders = %d, want 1", got)
	}
}

// TestA1_StaleObservationCannotReleaseAChangedRecord proves the freshness guard:
// evidence gathered against one identity must not release a row that has since
// been updated to a different commitment.
//
// The guard is enforced inside the release transaction, because a check made
// outside it can be invalidated between the check and the write.
func TestA1_StaleObservationCannotReleaseAChangedRecord(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": 100.0}); err != nil {
		t.Fatal(err)
	}
	seedA1Order(t, h, GigahostOrderRecord{
		OrderID: "10001", ServerID: 7, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: 0.15,
	})

	orders, err := h.getGigahostOrders(ctx)
	if err != nil || len(orders) != 1 {
		t.Fatalf("setup: %v %v", orders, err)
	}
	recordID := orders[0].ID

	// The record is updated underneath a previously gathered observation: it now
	// describes a different provider order.
	changed := &GigahostOrderRecord{ID: recordID, OrderID: "10099", ServerID: 7, Status: gigahost.StatusReady}
	if err := h.updateGigahostOrder(ctx, changed); err != nil {
		t.Fatal(err)
	}

	// A stale observation (order 10001) must be refused by the transaction.
	stale := database.ReleaseExpectation{OrderID: "10001", ServerID: 7}
	err = db.ReleaseGigahostOrderIfCurrent(ctx, recordID, stale, "provider_terminated", "stale observation")
	if !errors.Is(err, database.ErrGigahostOrderChanged) {
		t.Fatalf("stale release error = %v, want %v", err, database.ErrGigahostOrderChanged)
	}

	after, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].ReleasedAt != "" {
		t.Fatalf("the stale observation released the record: %+v", after)
	}

	// The matching identity is accepted and records exactly one audit row, so the
	// guard is not simply "always refuse".
	fresh := database.ReleaseExpectation{OrderID: "10099", ServerID: 7}
	if err := db.ReleaseGigahostOrderIfCurrent(ctx, recordID, fresh, "provider_terminated", "current observation"); err != nil {
		t.Fatalf("the freshness guard rejected an unchanged identity: %v", err)
	}
	audit, err := db.ListGigahostOrderAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(audit))
	}

	// Repeating the same release is a no-op, not a second audit row.
	err = db.ReleaseGigahostOrderIfCurrent(ctx, recordID, fresh, "provider_terminated", "repeat")
	if !errors.Is(err, database.ErrGigahostOrderAlreadyReleased) {
		t.Fatalf("repeat release error = %v, want %v", err, database.ErrGigahostOrderAlreadyReleased)
	}
	audit, err = db.ListGigahostOrderAudit(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 {
		t.Fatalf("audit rows after a repeat = %d, want 1", len(audit))
	}
}
