package handlers

// Deterministic regressions for the list response's provider-observation accounting.
//
// Two accounting faults were reported against the observation boundary, and both are
// exercised here through the real list handler against a disposable SQLite database and a
// controlled provider, because both faults live in the producer and cannot be seen from a
// hand-written response:
//
//	Case A  client resolution fails            → every non-terminal order must report
//	                                             unavailable, not not_checked
//	Case B  inventory confirms, detail fails   → the confirmation must survive
//
// A successful authoritative detail answer must still win, which is the precedence the
// finding requires retaining. Nothing here contacts a provider or touches a purchase or
// setup path.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// observationFor pulls one order's observation out of a real list response.
func observationFor(t *testing.T, ordersResponse, orderID string) map[string]any {
	t.Helper()
	return gigahostOrderStatusProviderObservation(t, ordersResponse, orderID)
}

// TestGigahostOrderObservationsClientResolutionFailureIsUnavailable is Case A.
//
// When the provider client cannot be resolved, the list handler used to leave every order at
// not_checked, which the view treats as "deliberately not re-read" and therefore neither a
// confirmation nor a failure. A non-terminal order whose provider could not be reached is a
// failure, and must say so; a terminal order genuinely is not re-read, and must keep
// not_checked.
func TestGigahostOrderObservationsClientResolutionFailureIsUnavailable(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)

	// One live order and one terminal order, so the distinction is exercised side by side.
	for _, seed := range []struct{ id, status string }{
		{"live-9", "deploying"},
		{"done-9", "failed"},
	} {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: seed.id, Status: seed.status, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", seed.id, err)
		}
	}

	// No injected client and no configured key: exactly the unconfigured-panel case that
	// ResolveGigahostSetupProvider already treats as "could not ask".
	h.SetGigahostClient(nil)
	t.Setenv("GIGAHOST_API_KEY", "")

	responses := gigahostOrderStatusRead(t, h, "")

	live := observationFor(t, responses.Orders, "live-9")
	if got := live["outcome"]; got != gigahostObservationUnavailable {
		t.Fatalf("a non-terminal order whose provider client could not be resolved must report "+
			"unavailable, got %v in %s", got, responses.Orders)
	}
	if reason, _ := live["error"].(string); reason == "" {
		t.Fatalf("the unavailable observation must carry a diagnostic, got %s", responses.Orders)
	}
	// The diagnostic must not leak configured material. The resolution error can quote the
	// offending character of a rejected key, so a fixed message is used instead.
	const wantReason = "gigahost provider client unavailable"
	if reason, _ := live["error"].(string); reason != wantReason {
		t.Fatalf("the client-resolution diagnostic must be the fixed message %q, got %q",
			wantReason, reason)
	}

	done := observationFor(t, responses.Orders, "done-9")
	if got := done["outcome"]; got != gigahostObservationNotChecked {
		t.Fatalf("a terminal order is deliberately not re-read and must stay not_checked, got %v", got)
	}

	// The rows themselves are untouched: this is a read-only accounting correction.
	var body struct {
		Orders []map[string]any `json:"orders"`
	}
	if err := json.Unmarshal([]byte(responses.Orders), &body); err != nil {
		t.Fatalf("list response is not JSON: %v", err)
	}
	if len(body.Orders) != 2 {
		t.Fatalf("both orders must still be listed, got %d", len(body.Orders))
	}
	for _, row := range body.Orders {
		if row["status"] == "" {
			t.Fatalf("the ledger status must be preserved, got %v", row)
		}
	}
}

// TestGigahostOrderObservationsInventoryConfirmationSurvivesDetailFailure is Case B.
//
// A successful inventory read can confirm an order's status without changing the stored row.
// The handler then still asks for deployment details, and if that second call fails its
// unavailable observation used to replace the inventory confirmation — marking the order
// stale and refusing to advance its confirmed check time even though the provider had already
// answered. The confirmation must survive; a no-usable-status detail answer must not displace
// it either.
func TestGigahostOrderObservationsInventoryConfirmationSurvivesDetailFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		detail     func(context.Context, string) (*gigahost.DeployStatusResponse, error)
		wantStatus string
	}{
		{
			name: "detail read fails",
			detail: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
				return nil, fmt.Errorf("controlled detail read failure")
			},
			wantStatus: gigahost.StatusReady,
		},
		{
			name: "detail returns no usable status",
			detail: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
				return &gigahost.DeployStatusResponse{OrderID: "inv-9"}, nil
			},
			wantStatus: gigahost.StatusReady,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			ctx := context.Background()
			now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
			const orderID = "inv-9"

			// A live order, so the handler will reach for the detail read as well.
			if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
				OrderID: orderID, Status: "deploying", CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				t.Fatalf("seed order: %v", err)
			}

			var detailReads int
			h.SetGigahostClient(&mockGigahostClient{
				getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
					// The inventory names this order's status. It does not touch the row:
					// refreshOrderFromServers keeps an in-flight status, so `updated` stays
					// false and the handler proceeds to the detail read.
					return []gigahost.ServerInfo{
						{OrderID: orderID, Status: gigahost.StatusReady, ID: 775},
					}, nil
				},
				getDeployStatusFn: func(ctx context.Context, id string) (*gigahost.DeployStatusResponse, error) {
					detailReads++
					return tc.detail(ctx, id)
				},
			})

			responses := gigahostOrderStatusRead(t, h, orderID)
			if detailReads == 0 {
				t.Fatalf("the fixture must have attempted the detail read, otherwise it does not " +
					"exercise the precedence this test exists for")
			}

			obs := observationFor(t, responses.Orders, orderID)
			if got := obs["outcome"]; got != gigahostObservationConfirmed {
				t.Fatalf("a confirmed inventory answer must survive a failed or silent detail read, "+
					"got %v in %s", got, responses.Orders)
			}
			if got, _ := obs["status"].(string); got != tc.wantStatus {
				t.Fatalf("the surviving observation must keep the inventory status %q, got %q",
					tc.wantStatus, got)
			}
		})
	}
}

// TestGigahostOrderObservationsConfirmedDetailStillWins pins the precedence that must be
// retained: the order detail is the more specific read, so a confirmed answer from it
// replaces an inventory answer for the same order.
func TestGigahostOrderObservationsConfirmedDetailStillWins(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	const orderID = "prec-9"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "deploying", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}

	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{OrderID: orderID, Status: gigahost.StatusDeploying, ID: 775},
			}, nil
		},
		getDeployStatusFn: func(_ context.Context, id string) (*gigahost.DeployStatusResponse, error) {
			// The detail is authoritative and disagrees with the inventory.
			return &gigahost.DeployStatusResponse{OrderID: id, Status: gigahost.StatusFailed}, nil
		},
	})

	responses := gigahostOrderStatusRead(t, h, orderID)
	obs := observationFor(t, responses.Orders, orderID)
	if got := obs["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("a confirmed detail answer must be reported as confirmed, got %v", got)
	}
	if got, _ := obs["status"].(string); got != gigahost.StatusFailed {
		t.Fatalf("the confirmed detail answer must win over the inventory answer, got %q want %q",
			got, gigahost.StatusFailed)
	}
}

// TestGigahostOrderObservationsHaveNoPurchaseOrSetupEffect pins that this accounting
// correction stays read-only: listing orders must not create a setup intent, mutate a
// purchase marker, or otherwise write beyond the row refresh the handler already did.
func TestGigahostOrderObservationsHaveNoPurchaseOrSetupEffect(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	const orderID = "effect-9"

	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: "deploying", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}

	before, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("read orders before: %v", err)
	}
	beforeByID := map[string]GigahostOrderRecord{}
	for _, o := range before {
		beforeByID[o.OrderID] = o
	}

	intentsBefore, err := h.ListGigahostSetupIntents(ctx)
	if err != nil {
		t.Fatalf("read intents before: %v", err)
	}

	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{OrderID: orderID, Status: gigahost.StatusReady, ID: 775}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, fmt.Errorf("controlled detail read failure")
		},
	})

	_ = gigahostOrderStatusRead(t, h, orderID)

	intentsAfter, err := h.ListGigahostSetupIntents(ctx)
	if err != nil {
		t.Fatalf("read intents after: %v", err)
	}
	if len(intentsAfter) != len(intentsBefore) {
		t.Fatalf("listing orders must not create a setup intent: %d before, %d after",
			len(intentsBefore), len(intentsAfter))
	}

	after, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("read orders after: %v", err)
	}
	for _, o := range after {
		prev, ok := beforeByID[o.OrderID]
		if !ok {
			t.Fatalf("listing orders invented a row %q", o.OrderID)
		}
		// The purchase marker is main's provenance contract; this branch must not touch it.
		if o.PurchaseOrigin != prev.PurchaseOrigin {
			t.Fatalf("listing orders must not change the purchase origin: %q -> %q",
				prev.PurchaseOrigin, o.PurchaseOrigin)
		}
	}
}
