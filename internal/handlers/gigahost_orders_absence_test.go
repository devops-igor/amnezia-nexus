package handlers

// The order list carries the panel's durable existence record.
//
// The deleted presentation used to depend on the per-order deploy read, so a failing
// detail request returned the row to its ordinary treatment and an older deletion fell
// out of the list's five-row window. These tests drive the real handlers: the absence
// is written through the same column the inventory pass writes, the list response is
// read for the mark, and the shipped renderer is executed with every per-order detail
// request genuinely failing (phase 1) and then succeeding (phase 2). The second phase
// is the control: the treatment of the same rows must be the one it always had.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestGigahostOrdersListCarriesRecordedAbsence is the response half: the mark is on the
// list, it names exactly the recorded order, and it is there before any detail request.
func TestGigahostOrdersListCarriesRecordedAbsence(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)

	const goneOrderID = "ord_986_gone"
	const liveOrderID = "ord_986_live"
	goneServerID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-" + goneOrderID,
		Host:      "198.51.100.61",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 6104},
	})
	liveServerID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-" + liveOrderID,
		Host:      "198.51.100.62",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 6105},
	})
	for _, id := range []string{goneOrderID, liveOrderID} {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: id, Status: DeployStatusFailed, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed order %s: %v", id, err)
		}
	}
	// The onboarding journal is what mirrors the panel server id onto the ledger, which
	// is the identity an existence question is asked about.
	if err := h.updateDeployOrderStatus(ctx, goneOrderID, DeployStatusFailed, DeployStatusInstallingProtocol,
		"controlled install failure", 6104, goneServerID, "198.51.100.61"); err != nil {
		t.Fatalf("journal the gone deployment: %v", err)
	}
	if err := h.updateDeployOrderStatus(ctx, liveOrderID, DeployStatusFailed, DeployStatusInstallingProtocol,
		"controlled install failure", 6105, liveServerID, "198.51.100.62"); err != nil {
		t.Fatalf("journal the live deployment: %v", err)
	}
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
	})

	responses := gigahostOrderStatusRead(t, h, "")

	var body struct {
		Orders  []map[string]any `json:"orders"`
		Absent  map[string]bool  `json:"provider_absent_orders"`
		Observe map[string]any   `json:"provider_observations"`
	}
	if err := json.Unmarshal([]byte(responses.Orders), &body); err != nil {
		t.Fatalf("list response is not JSON: %v %s", err, responses.Orders)
	}
	if body.Absent == nil {
		t.Fatalf("the list response carries no absence record at all: %s", responses.Orders)
	}
	if len(body.Orders) != 2 {
		t.Fatalf("the fixture must return both orders, got %s", responses.Orders)
	}
	// Before the observation nothing is recorded, so the mark is empty rather than
	// guessed from a status the panel does not own.
	if len(body.Absent) != 0 {
		t.Fatalf("an order nobody recorded absent must not be marked: %s", responses.Orders)
	}

	// The inventory pass records the deletion; the list is read afterwards.
	markServerProviderAbsent(t, h, goneServerID)

	observed := gigahostOrderStatusRead(t, h, "")
	var observedBody struct {
		Orders []map[string]any `json:"orders"`
		Absent map[string]bool  `json:"provider_absent_orders"`
	}
	if err := json.Unmarshal([]byte(observed.Orders), &observedBody); err != nil {
		t.Fatalf("list response is not JSON: %v %s", err, observed.Orders)
	}
	if len(observedBody.Absent) != 1 || !observedBody.Absent[goneOrderID] {
		t.Fatalf("the list must mark exactly the recorded order absent, got %v", observedBody.Absent)
	}
	if observedBody.Absent[liveOrderID] {
		t.Fatalf("the list marked a registered, listed order absent: %v", observedBody.Absent)
	}
	// The two channels agree: the detail read still carries the same durable fact.
	if detail := readGigahostOrderStatusDetail(t, h, goneOrderID); detail == "" {
		t.Fatalf("the detail read answered nothing for %s", goneOrderID)
	}
}

// TestRecentDeploymentsKeepsARecordedDeletionWhenTheDetailReadFails is the rendering
// half: with every per-order status request failing, the recorded deletion is still
// DELETED, still offers no contact action, and is still listed though it is older than
// the five most recent deployments.
func TestRecentDeploymentsKeepsARecordedDeletionWhenTheDetailReadFails(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

	const goneOrderID = "ord_986_older_deletion"
	serverID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-" + goneOrderID,
		Host:      "198.51.100.71",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 7104},
	})
	// The recorded deletion is the oldest row, so it sits beyond the five the list shows
	// by default - the window that used to drop it when its stage stopped reading as
	// deleted.
	orderIDs := []string{goneOrderID, "ord_986_r1", "ord_986_r2", "ord_986_r3", "ord_986_r4", "ord_986_r5"}
	for _, id := range orderIDs {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: id, Status: DeployStatusFailed, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed order %s: %v", id, err)
		}
	}
	// Every row is a journaled install failure, which is the state that offers a Retry
	// control - so the deleted row's missing control is a change this state caused, not a
	// control this view never draws.
	if err := h.updateDeployOrderStatus(ctx, goneOrderID, DeployStatusFailed, DeployStatusInstallingProtocol,
		"controlled install failure", 7104, serverID, "198.51.100.71"); err != nil {
		t.Fatalf("journal the deleted deployment: %v", err)
	}
	for _, id := range orderIDs[1:] {
		if err := h.updateDeployOrderStatus(ctx, id, DeployStatusFailed, DeployStatusInstallingProtocol,
			"controlled install failure", 0, 0, ""); err != nil {
			t.Fatalf("journal %s: %v", id, err)
		}
	}
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
	})
	markServerProviderAbsent(t, h, serverID)

	// An empty order id leaves every per-order detail body unset in the harness, so each
	// row's status request fails and the renderer sees no deploy read at all.
	failingReads := gigahostOrderStatusRead(t, h, "")
	if failingReads.Detail != "" || len(failingReads.Details) != 0 {
		t.Fatalf("the failed-read fixture is meant to supply no detail body: %+v", failingReads)
	}

	rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, failingReads, ""))
	if len(rendered.Rows) != len(orderIDs) {
		t.Fatalf("a recorded deletion older than the five shown must still be listed while the detail read fails, got %d rows: %+v",
			len(rendered.Rows), rendered.Rows)
	}
	gone := rendered.Rows[len(rendered.Rows)-1]
	if gone.OrderID != goneOrderID {
		t.Fatalf("the oldest row must be the recorded deletion, got %+v", rendered.Rows)
	}
	if gone.Stage != "deleted" {
		t.Fatalf("a failing detail read must not undo the recorded deletion, got stage %q", gone.Stage)
	}
	if len(gone.Actions) != 0 {
		t.Fatalf("a deleted deployment must offer no contact action while the detail read fails, got %v", gone.Actions)
	}
	// The negative direction: the rows nobody recorded absent keep the ordinary treatment.
	for _, row := range rendered.Rows[:len(rendered.Rows)-1] {
		if row.Stage != "failed" {
			t.Fatalf("an unrecorded order must not borrow the deleted stage: %+v", row)
		}
	}
	if len(rendered.Rows[0].Actions) == 0 {
		t.Fatalf("an unrecorded failure must keep its control, got %+v", rendered.Rows[0])
	}

	// Phase 2 - the control: the same rows with every detail read succeeding.
	succeeding := failingReads
	succeeding.Details = make(map[string]string, len(orderIDs))
	for _, id := range orderIDs {
		succeeding.Details[id] = readGigahostOrderStatusDetail(t, h, id)
	}
	controlled := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, succeeding, ""))
	if len(controlled.Rows) != len(orderIDs) {
		t.Fatalf("the recorded deletion must be listed when the detail read succeeds too, got %+v", controlled.Rows)
	}
	controlledGone := controlled.Rows[len(controlled.Rows)-1]
	if controlledGone.OrderID != goneOrderID || controlledGone.Stage != "deleted" || len(controlledGone.Actions) != 0 {
		t.Fatalf("the succeeding read must present the same deletion, got %+v", controlledGone)
	}
}
