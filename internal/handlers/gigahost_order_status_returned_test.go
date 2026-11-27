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

// returnedOrderProviderModes are the inventories this regression moves the provider
// through, in the order the sequences below run.
const (
	returnedOrderDeletion   = "deletion"
	returnedOrderLive       = "live"
	returnedOrderOutage     = "outage"
	returnedOrderOtherOrder = "other-order"
	returnedOrderTerminal   = "terminal"
)

// TestAffirmativeReturnStaysRecordedWhileTheProviderKeepsListingTheServer is F995-02's
// durable half.
//
// The correction above proves one read: a deletion was recorded, an affirmative listing
// repaired it, and that response rendered correctly. It cannot see whether the repair was
// *persisted* or whether it survives the next read, and those are the two failures reported
// afterwards. A row repaired with the provider's `active` spelling was never written at all,
// so the ledger kept `deleted` and the next outage rendered the deletion again. A row
// repaired with `ready` held until the next identical inventory read, which changed no row
// and therefore asked the order detail again: that detail still answered `deleted`, and the
// stale ending was committed a second time.
//
// Each phase below therefore reloads the ledger row from the database and renders the same
// order's row, so "the return held" is asserted against durable state and against what the
// operator is shown - not against the response that produced it.
func TestAffirmativeReturnStaysRecordedWhileTheProviderKeepsListingTheServer(t *testing.T) {
	// Both spellings the provider uses for a live server. `active` is the one the inventory
	// decoder passes through and the view renders as ready, and it was the spelling the
	// ledger refused to store.
	for _, liveSpelling := range []string{gigahost.StatusReady, "active"} {
		t.Run(liveSpelling, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			const orderID = "ord_995_durable"
			const providerServerID = int64(6198)
			const address = "198.51.100.198"
			seedUnonboardedOrder(t, h, orderID, address)

			mode := returnedOrderDeletion
			detailReads := 0
			// One provider for the whole sequence, so every phase is the same provider
			// answering differently rather than a different provider each time.
			h.SetGigahostClient(&mockGigahostClient{
				getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
					switch mode {
					case returnedOrderOutage:
						return nil, fmt.Errorf("controlled inventory read failure")
					case returnedOrderLive:
						return []gigahost.ServerInfo{{
							ID: providerServerID, OrderID: orderID, IPv4: address, Status: liveSpelling,
						}}, nil
					case returnedOrderTerminal:
						return []gigahost.ServerInfo{{
							ID: providerServerID, OrderID: orderID, IPv4: address, Status: deletedProviderStatus,
						}}, nil
					case returnedOrderOtherOrder:
						// A different deployment at the same address: the listing names
						// neither this order nor this order's provider server id, so it
						// answers nothing about whether this deployment exists.
						return []gigahost.ServerInfo{{
							ID: providerServerID + 1, OrderID: "ord_995_neighbour", IPv4: address, Status: "active",
						}}, nil
					default:
						return nil, nil
					}
				},
				getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
					detailReads++
					// The detail keeps answering the exact ending already contradicted by
					// inventory, including when later inventory names only other orders.
					return &gigahost.DeployStatusResponse{
						OrderID: orderID, Status: deletedProviderStatus,
						ServerID: providerServerID, AssignedIP: address,
					}, nil
				},
			})

			snapshot := func(label string) (string, deletedDeploymentRender, int, string) {
				t.Helper()
				read := gigahostOrderStatusRead(t, h, orderID)
				read.Details = map[string]string{orderID: read.Detail}
				order, _, _, _, err := h.getDeployOrderByID(context.Background(), orderID)
				if err != nil || order == nil {
					t.Fatalf("%s: reload the ledger row: %v", label, err)
				}
				observation := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
				observed, _ := observation["status"].(string)
				return order.Status, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID)), detailReads, observed
			}

			// Phase 1 - the provider's literal deletion, while the panel does not yet know
			// which provider server this order is.
			status, row, _, _ := snapshot("literal deletion")
			if status != deletedProviderStatus {
				t.Fatalf("the literal deletion must reach the ledger, got %q", status)
			}
			if row.Stage != "deleted" || len(row.Actions) != 0 {
				t.Fatalf("a deleted deployment must render deleted with no action, got %+v", row)
			}

			// Phase 2 - the same server is listed again. The ledger has to record it: the
			// view reading it correctly is not the same fact as the panel remembering it,
			// and the value it remembers is the panel's own word for a running server. The
			// provider's spelling stays in the observation, which is where it belongs.
			mode = returnedOrderLive
			status, row, _, observed := snapshot("live return (" + liveSpelling + ")")
			if status != gigahost.StatusReady {
				t.Fatalf("an affirmative live listing must be persisted as the panel's status, "+
					"got ledger status %q, want %q", status, gigahost.StatusReady)
			}
			if observed != liveSpelling {
				t.Fatalf("the observation must keep the provider's own spelling, got %q want %q",
					observed, liveSpelling)
			}
			if row.Stage == "deleted" {
				t.Fatalf("a deployment the provider lists again still renders deleted: %+v", row)
			}
			if !slices.Contains(row.Actions, "deploy_setup_btn") {
				t.Fatalf("a returned deployment must get its ordinary actions back, got %v", row.Actions)
			}

			// Phase 3 - an identical inventory read with an unchanged detail answer. This is
			// the read that used to re-delete the row, because the inventory changed nothing
			// and the detail was therefore asked again.
			beforeDetail := detailReads
			status, row, afterDetail, _ := snapshot("identical inventory read")
			if afterDetail == beforeDetail {
				t.Fatalf("the fixture must still ask the order detail, otherwise this phase " +
					"does not exercise the stale answer it exists for")
			}
			if status != gigahost.StatusReady {
				t.Fatalf("an unchanged terminal detail answer re-deleted the row: ledger status %q, want %q",
					status, gigahost.StatusReady)
			}
			if row.Stage == "deleted" {
				t.Fatalf("an unchanged terminal detail answer re-deleted the rendered row: %+v", row)
			}

			// Phase 4 - the inventory read fails. An inventory the panel could not read is not
			// evidence that the server is gone, so the same stale detail answer must not bring
			// the deletion back.
			mode = returnedOrderOutage
			status, row, _, _ = snapshot("inventory outage")
			if status != gigahost.StatusReady {
				t.Fatalf("an inventory outage exposed the deletion again: ledger status %q, want %q",
					status, gigahost.StatusReady)
			}
			if row.Stage == "deleted" {
				t.Fatalf("an inventory outage re-deleted the rendered row: %+v", row)
			}

			// Phase 5 - the inventory answers with a different deployment at the same
			// address. It names neither this order nor its provider server id, so it says
			// nothing about this deployment and must change nothing. The detail still repeats
			// the same contradicted deletion; omission cannot make it new evidence.
			mode = returnedOrderOtherOrder
			status, row, _, _ = snapshot("non-matching inventory")
			if status != gigahost.StatusReady {
				t.Fatalf("a non-matching inventory changed the ledger row: status %q, want %q",
					status, gigahost.StatusReady)
			}
			if row.Stage == "deleted" {
				t.Fatalf("a non-matching inventory re-deleted the rendered row: %+v", row)
			}

			// Phase 6 - the ending is still reachable. When the provider's own inventory names
			// this order's server with a terminal status, that answer is recorded, so the rule
			// above suppresses a stale detail answer rather than making an ending unreachable.
			mode = returnedOrderTerminal
			status, row, _, _ = snapshot("provider's terminal listing")
			if status != deletedProviderStatus {
				t.Fatalf("the provider's own terminal status for this server must still be recorded, got %q", status)
			}
			if row.Stage != "deleted" || len(row.Actions) != 0 {
				t.Fatalf("a deployment the provider reports as deleted must render deleted with no action, got %+v", row)
			}
		})
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
