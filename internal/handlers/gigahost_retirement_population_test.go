package handlers

// The retirement population, pinned as a decision rather than inferred from a fixture.
//
// The design verdict left one criterion open: whether the two stale production orders stop
// being polled. That cannot be answered offline, because it needs one successful inventory
// read from the account those orders were bought under. What CAN be answered offline is the
// narrower question the answer depends on: for a row in each of the states those two orders
// are recorded in, does the reconciliation judge it at all, and does a complete successful
// listing that omits it retire it?
//
// This file pins exactly that, for the recorded states 38840 (`ready`) and 38876 (`failed`)
// are reported to carry, and states plainly which branch is which. It does not claim the
// production rows hold any particular columns: it proves what happens if they hold the ones
// the mechanism requires, and what happens if they do not.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestRetirementPopulationCoversEachRecordedStateTheStaleOrdersCarry drives the production
// reconciliation over one row per recorded state, with and without a provider server id,
// and asserts the exact population rule: a row is judged when it carries a provider server
// id or is recorded ready.
//
// The four cases are the whole rule, and each one is a different answer:
//
//	ready  + server id   judged, so a successful omission retires it
//	ready  + no id       judged (ready is itself the population), retired the same way
//	failed + server id   judged, so a failed deployment that once existed is retired
//	failed + no id       not judged: nothing was ever deployed to be absent
//
// The last case is the stated limit of the mechanism, not a defect: an order with neither
// a ready status nor a provider server id was never a deployment, so there is no omission
// to record. Which case the production rows fall in is not knowable here.
func TestRetirementPopulationCoversEachRecordedStateTheStaleOrdersCarry(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		status     string
		serverID   int64
		wantJudged bool
		why        string
	}{
		{
			name: "recorded-ready-with-server-id", status: gigahost.StatusReady, serverID: 38840,
			wantJudged: true,
			why:        "a ready order is one the listing is expected to contain",
		},
		{
			name: "recorded-ready-without-server-id", status: gigahost.StatusReady, serverID: 0,
			wantJudged: true,
			why:        "the ready status alone names a deployment that exists",
		},
		{
			name: "recorded-failed-with-server-id", status: gigahost.StatusFailed, serverID: 38876,
			wantJudged: true,
			why:        "a failed deployment that ever existed carries a provider server id",
		},
		{
			name: "recorded-failed-without-server-id", status: gigahost.StatusFailed, serverID: 0,
			wantJudged: false,
			why:        "a purchase the provider never acknowledged has no deployment to be absent",
		},
		{
			name: "recorded-deploying", status: gigahost.StatusDeploying, serverID: 9001,
			wantJudged: false,
			why:        "an order still in flight is not absent from a listing, it is not finished",
		},
		{
			name: "pending-purchase", status: "pending_order", serverID: 0,
			wantJudged: false,
			why:        "a purchase still being placed has no deployment",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			order := &GigahostOrderRecord{
				OrderID:   "ord_population_" + tc.name,
				Status:    tc.status,
				ServerID:  tc.serverID,
				CreatedAt: now,
				UpdatedAt: now,
			}
			got := gigahostOrderNeedsExistenceCheck(order)
			if got != tc.wantJudged {
				t.Fatalf("%s: judged = %v, want %v (%s)", tc.name, got, tc.wantJudged, tc.why)
			}
		})
	}
}

// TestAReadyOrFailedDeploymentIsRetiredByACompleteOmission runs each judged case through the
// whole path, so the population rule above is shown to reach the durable record rather than
// stopping at a predicate.
//
// The provider is the offline fixture from the wire scenario: a successful inventory that
// enumerates nothing. Every judged row must end up with a recorded absence and must stop
// being asked about; the not-judged row must be untouched.
func TestAReadyOrFailedDeploymentIsRetiredByACompleteOmission(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 28, 10, 30, 0, 0, time.UTC)

	type row struct {
		orderID  string
		status   string
		serverID int64
		judged   bool
	}
	rows := []row{
		{"ord_retire_ready_with_id", gigahost.StatusReady, 8101, true},
		{"ord_retire_ready_no_id", gigahost.StatusReady, 0, true},
		{"ord_retire_failed_with_id", gigahost.StatusFailed, 8103, true},
		{"ord_retire_failed_no_id", gigahost.StatusFailed, 0, false},
	}
	for _, r := range rows {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID:        r.orderID,
			Status:         r.status,
			ServerID:       r.serverID,
			AssignedIP:     "198.51.100.80",
			PurchaseOrigin: models.PurchaseOriginPanelPurchase,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			t.Fatalf("seed %q: %v", r.orderID, err)
		}
	}

	provider := newWireProvider(t, nil)
	h.SetGigahostClient(wireClient(t, provider))
	read := gigahostOrderStatusRead(t, h, "")

	for _, r := range rows {
		stored := storedOrder(t, h, r.orderID)
		if stored.ProviderAbsent() != r.judged {
			t.Errorf("%s (%s, server id %d): recorded absence = %v, want %v",
				r.orderID, r.status, r.serverID, stored.ProviderAbsent(), r.judged)
		}
		if mark := absenceMark(t, read.Orders, r.orderID); mark != r.judged {
			t.Errorf("%s: the list reported absence = %v, want %v", r.orderID, mark, r.judged)
		}
		if !r.judged && stored.ProviderAbsentAccountID != "" {
			t.Errorf("%s: an account was stamped on an order that was never judged, got %q",
				r.orderID, stored.ProviderAbsentAccountID)
		}
		// The retired rows are not asked about again by the same read that retired them.
		if r.judged && provider.statusReads[r.orderID] != 0 {
			t.Errorf("%s: a retired order was asked about %d time(s)",
				r.orderID, provider.statusReads[r.orderID])
		}
	}
}
