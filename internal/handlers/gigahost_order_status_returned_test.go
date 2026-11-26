package handlers

// A provider order-detail answer that says `deleted` is an ending in its own right,
// and it is not the same fact as the panel's durable inventory mark. Two things went
// wrong when the view treated the mark as the only source of "deleted": a literal
// provider answer rendered DELETED while the row still offered Setup Backend and
// Approve, and a row that had recorded such an ending was skipped on every later
// refresh, so it kept showing DELETED after the provider listed the server again
// and its card had returned.
//
// These fixtures replay the real handlers' responses into the shipped renderer: the
// provider is a fake implementing the same interface, and the sequence is the same
// order throughout, so "restored" is measured against that order's own earlier state
// rather than against an empty screen.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// deletedProviderStatus is the provider's own word for a deployment it no longer has.
// Production compares this spelling directly (`isTerminalStatus`, `confirmedOrderAccepted`),
// so the fixture speaks the same vocabulary rather than a constant of its own.
const deletedProviderStatus = "deleted"

// seedUnonboardedOrder records an order the panel placed and whose address the
// provider assigned, but which the onboarding journal never finished. It is the state
// the audit fixture used: the row still offers the two setup actions, which is what
// makes their disappearance observable.
func seedUnonboardedOrder(t *testing.T, h *Handlers, orderID, ip string) {
	t.Helper()
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID: orderID, Status: DeployStatusReady, AssignedIP: ip, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order %s: %v", orderID, err)
	}
}

// TestProviderDeletedResponseSuppressesActionsAndIsCorrectedByInventory is F995-02.
func TestProviderDeletedResponseSuppressesActionsAndIsCorrectedByInventory(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_995_returns"
	const providerServerID = int64(6196)

	seedUnonboardedOrder(t, h, orderID, "198.51.100.196")

	// One provider whose answers move through the three states this test needs: a
	// literal deleted answer, an inventory read that fails, and the same order listed
	// again. The client is replaced nowhere, so every phase is the same provider.
	const (
		providerSaysDeleted  = "deleted"
		providerUnreachable  = "unreachable"
		providerListsItAgain = "returned"
	)
	providerMode := providerSaysDeleted
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			switch providerMode {
			case providerUnreachable:
				return nil, fmt.Errorf("controlled inventory read failure")
			case providerListsItAgain:
				return []gigahost.ServerInfo{{
					ID: providerServerID, OrderID: orderID,
					IPv4: "198.51.100.196", Status: gigahost.StatusReady,
				}}, nil
			}
			return nil, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			switch providerMode {
			case providerUnreachable:
				// A row that has already ended is never asked about again through the
				// detail read; asking here would be the re-read this correction avoids.
				t.Fatalf("a terminal row must not be re-read from the provider detail")
			}
			if providerMode == providerSaysDeleted {
				return &gigahost.DeployStatusResponse{OrderID: orderID, Status: deletedProviderStatus}, nil
			}
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, Status: gigahost.StatusReady,
				ServerID: providerServerID, AssignedIP: "198.51.100.196",
			}, nil
		},
	})

	// Phase 1 - the provider's literal answer.
	deletedRead := gigahostOrderStatusRead(t, h, orderID)
	deletedRead.Details = map[string]string{orderID: deletedRead.Detail}
	obs := gigahostOrderStatusProviderObservation(t, deletedRead.Orders, orderID)
	if got := obs["status"]; got != deletedProviderStatus {
		t.Fatalf("the fixture must carry the provider's own deleted answer, got %v in %s", got, deletedRead.Orders)
	}
	deletedRow := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, deletedRead, orderID))
	if deletedRow.Stage != "deleted" {
		t.Fatalf("a provider-deleted deployment must render deleted, got %q", deletedRow.Stage)
	}
	// The defect: the stage said deleted while the row still offered two actions that
	// end in a connection to that deployment.
	if len(deletedRow.Actions) != 0 {
		t.Fatalf("a deployment the provider says is deleted must offer no contact action, got %v", deletedRow.Actions)
	}
	if !strings.Contains(deletedRow.Identity, "#"+orderID) {
		t.Fatalf("the deleted deployment lost its order identity: %q", deletedRow.Identity)
	}
	// The details still carry the provider's own word and the deleted-stage advice.
	if !strings.Contains(deletedRow.Panel, "gigahost_status_stage_deleted") {
		t.Fatalf("the deleted deployment's details must state the deleted stage: %q", deletedRow.Panel)
	}
	if !strings.Contains(deletedRow.Panel, "gigahost_status_next_action_none") {
		t.Fatalf("a deleted deployment must advise no next action: %q", deletedRow.Panel)
	}

	// Phase 1b - an inventory read that fails changes nothing: the row keeps exactly
	// what it recorded, and the observation may not claim a confirmation.
	providerMode = providerUnreachable
	unknownRead := gigahostOrderStatusRead(t, h, orderID)
	unknownRead.Details = map[string]string{orderID: unknownRead.Detail}
	var unknownOrders struct {
		Orders []map[string]any `json:"orders"`
	}
	if err := json.Unmarshal([]byte(unknownRead.Orders), &unknownOrders); err != nil || len(unknownOrders.Orders) != 1 {
		t.Fatalf("the failed-inventory response must still carry the row: %v %s", err, unknownRead.Orders)
	}
	if got := unknownOrders.Orders[0]["status"]; got != deletedProviderStatus {
		t.Fatalf("a failed inventory must not change the recorded ending, got %v", got)
	}
	unknownObs := gigahostOrderStatusProviderObservation(t, unknownRead.Orders, orderID)
	if got := unknownObs["outcome"]; got == gigahostObservationConfirmed {
		t.Fatalf("a failed inventory must not be reported as a confirmation: %v", unknownObs)
	}
	stillDeleted := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, unknownRead, orderID))
	if stillDeleted.Stage != "deleted" {
		t.Fatalf("a failed inventory must not alter what the row records, got stage %q", stillDeleted.Stage)
	}

	// Phase 2 - the same order's server is listed again, ready.
	providerMode = providerListsItAgain
	returnedRead := gigahostOrderStatusRead(t, h, orderID)
	returnedRead.Details = map[string]string{orderID: returnedRead.Detail}
	var returnedOrders struct {
		Orders []map[string]any `json:"orders"`
	}
	if err := json.Unmarshal([]byte(returnedRead.Orders), &returnedOrders); err != nil || len(returnedOrders.Orders) != 1 {
		t.Fatalf("the return response is not the documented shape: %v %s", err, returnedRead.Orders)
	}
	if got := returnedOrders.Orders[0]["status"]; got != gigahost.StatusReady {
		t.Fatalf("an affirmative inventory listing must correct the stale terminal row, got %v in %s", got, returnedRead.Orders)
	}
	returnedObs := gigahostOrderStatusProviderObservation(t, returnedRead.Orders, orderID)
	if got := returnedObs["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("the return must be reported as a provider confirmation, got %v", returnedObs)
	}
	if got := returnedObs["status"]; got != gigahost.StatusReady {
		t.Fatalf("the confirmation must carry the provider's own status, got %v", got)
	}
	returnedRow := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, returnedRead, orderID))
	if returnedRow.Stage == "deleted" {
		t.Fatalf("a deployment the provider lists again is still rendered deleted: %+v", returnedRow)
	}
	if !slices.Contains(returnedRow.Actions, "deploy_setup_btn") {
		t.Fatalf("a corrected deployment must get its ordinary actions back, got %v", returnedRow.Actions)
	}
	if !strings.Contains(returnedRead.Detail, `"status":"`+gigahost.StatusReady+`"`) {
		t.Fatalf("the corrected deploy read must carry the recovered status: %s", returnedRead.Detail)
	}
}

// TestGenuineCancellationSurvivesAnInventoryThatDoesNotListIt is the negative control
// for the correction above: a row the provider terminated is not repaired by an
// inventory read that simply does not mention it. Only an affirmative live listing
// for the same order overrides a recorded ending.
func TestGenuineCancellationSurvivesAnInventoryThatDoesNotListIt(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_995_cancelled"

	seedUnonboardedOrder(t, h, orderID, "198.51.100.197")
	// A cancellation the provider recorded: no onboarding step is written with it, so the
	// row's status is the provider's own word rather than journal evidence.
	if err := h.updateDeployOrderStatus(context.Background(), orderID, statusCancelled,
		"", "", 0, 0, ""); err != nil {
		t.Fatalf("record the cancellation: %v", err)
	}

	h.SetGigahostClient(&mockGigahostClient{
		// The inventory still lists the server: a cancelled order's VPS may well still be
		// running. That listing must not turn the order back into a live deployment.
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{{
				ID: 6197, OrderID: orderID, IPv4: "198.51.100.197", Status: gigahost.StatusReady,
			}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			t.Fatalf("a terminal row must not be re-read from the provider detail")
			return nil, nil
		},
	})

	read := gigahostOrderStatusRead(t, h, orderID)
	read.Details = map[string]string{orderID: read.Detail}
	var body struct {
		Orders []map[string]any `json:"orders"`
	}
	if err := json.Unmarshal([]byte(read.Orders), &body); err != nil || len(body.Orders) != 1 {
		t.Fatalf("cancellation response is not the documented shape: %v %s", err, read.Orders)
	}
	if got := body.Orders[0]["status"]; got != statusCancelled {
		t.Fatalf("a cancellation the inventory does not contradict must survive, got %v", got)
	}
	row := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID))
	if row.Stage != "cancelled" {
		t.Fatalf("a cancelled deployment must render cancelled, got %q", row.Stage)
	}
	// A cancelled order is not a deleted one: cancellation stops the order while its VPS
	// may still be running, so its actions are deliberately untouched by this change.
	if slices.Contains(row.Actions, "deploy_retry_btn") {
		t.Fatalf("a cancelled order is not retried through the deleted rule, got %v", row.Actions)
	}
	if !strings.Contains(row.Identity, "#"+orderID) {
		t.Fatalf("the cancelled deployment lost its order identity: %q", row.Identity)
	}
}
