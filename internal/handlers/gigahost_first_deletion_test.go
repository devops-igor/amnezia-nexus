package handlers

// A first, uncontradicted deletion has to be recorded even when the panel already knows
// the order's numeric provider server id.
//
// The provider id is what the inventory answers with; it is not a registration. An order
// that was viewed once while the provider listed it therefore carries that id while
// nothing else about it has changed, and a rule that read the id as "this deletion was
// already repaired" made the first genuine deletion invisible forever: the inventory
// omitted the order, the order detail said `deleted`, and the row stayed Ready with Setup
// Backend and Approve still offered, on every read.
//
// The deferral that this replaces is still needed for one case - a deployment this panel
// registered, whose existence the account-scoped inventory pass records on the server row
// itself. That row is the durable existence observation for the deployment, so the pass's
// mark is what presents it as deleted; the order detail is not asked to decide it. The
// control below is that case, and it also shows the ending is still reachable through the
// mark.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// deletionPhases drives one fake provider through the two provider answers this sequence
// needs: the order listed and live, then removed from the account's inventory with its
// detail naming the deletion.
type deletionPhases struct {
	listed bool
}

func (p *deletionPhases) servers(orderID, address string, providerServerID int64) func(context.Context) ([]gigahost.ServerInfo, error) {
	return func(context.Context) ([]gigahost.ServerInfo, error) {
		if !p.listed {
			// The provider removed the VPS, so its inventory no longer names the order.
			// The read succeeded and answered: an omission from a successful listing.
			return nil, nil
		}
		return []gigahost.ServerInfo{{
			ID: providerServerID, OrderID: orderID, IPv4: address, Status: gigahost.StatusReady,
		}}, nil
	}
}

func (p *deletionPhases) detail(orderID, address string, providerServerID int64) func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
	return func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		if !p.listed {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: deletedProviderStatus}, nil
		}
		return &gigahost.DeployStatusResponse{
			OrderID: orderID, Status: gigahost.StatusReady,
			ServerID: providerServerID, AssignedIP: address,
		}, nil
	}
}

// TestFirstGenuineDeletionIsRecordedForAnOrderWhoseProviderIDIsKnown is F995-05.
func TestFirstGenuineDeletionIsRecordedForAnOrderWhoseProviderIDIsKnown(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID          = "ord_995_first_deletion"
		providerServerID = int64(6211)
		address          = "198.51.100.211"
	)
	seedUnonboardedOrder(t, h, orderID, address)

	phases := &deletionPhases{listed: true}
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn:      phases.servers(orderID, address, providerServerID),
		getDeployStatusFn: phases.detail(orderID, address, providerServerID),
	})

	// Phase 1 - the operator views the order while the provider still lists it. The ledger
	// learns the provider's numeric server id and nothing else: no registration, no step.
	first := readOrderStatusList(t, h, orderID)
	learned, nexusServerID, _, step, err := h.getDeployOrderByID(context.Background(), orderID)
	if err != nil || learned == nil {
		t.Fatalf("reload the ledger row after the listed read: %v", err)
	}
	if learned.ServerID != providerServerID {
		t.Fatalf("fixture premise: the ledger must learn the provider id %d, got %d",
			providerServerID, learned.ServerID)
	}
	if nexusServerID != 0 || step != "" {
		t.Fatalf("fixture premise: the order must not be onboarded, got panel server %d step %q",
			nexusServerID, step)
	}
	if got := gigahostOrderStatusProviderObservation(t, first.Orders, orderID)["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("the listed read must be a provider confirmation, got %v", got)
	}

	// Phase 2 - the provider removes the VPS. Repeated reads of the same provider state
	// must each record and present the ending; a single read is not the claim.
	phases.listed = false
	for attempt := 1; attempt <= 3; attempt++ {
		read := readOrderStatusList(t, h, orderID)
		recorded, _, _, _, reloadErr := h.getDeployOrderByID(context.Background(), orderID)
		if reloadErr != nil || recorded == nil {
			t.Fatalf("attempt %d: reload the ledger row: %v", attempt, reloadErr)
		}
		if recorded.Status != deletedProviderStatus {
			t.Fatalf("attempt %d: the first genuine deletion was not recorded, ledger status %q in %s",
				attempt, recorded.Status, read.Orders)
		}
		var body struct {
			Orders []map[string]any `json:"orders"`
		}
		if err := json.Unmarshal([]byte(read.Orders), &body); err != nil || len(body.Orders) != 1 {
			t.Fatalf("attempt %d: the orders response is not the documented shape: %v %s",
				attempt, err, read.Orders)
		}
		if got := body.Orders[0]["status"]; got != deletedProviderStatus {
			t.Fatalf("attempt %d: the list still presents %v for a deleted deployment", attempt, got)
		}
		if !strings.Contains(read.Details[orderID], `"status":"`+deletedProviderStatus+`"`) {
			t.Fatalf("attempt %d: the deploy read does not carry the provider's ending: %s",
				attempt, read.Details[orderID])
		}
		rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID))
		row := renderedRowFor(t, rendered, orderID)
		if row.Stage != deletedProviderStatus {
			t.Fatalf("attempt %d: a deployment the provider removed must render deleted, got %q",
				attempt, row.Stage)
		}
		if len(row.Actions) != 0 {
			t.Fatalf("attempt %d: a deleted deployment must offer no contact action, got %v",
				attempt, row.Actions)
		}
	}
}

// TestRegisteredDeploymentLetsTheInventoryPassRecordTheAbsence is F995-05's control.
//
// For a deployment this panel registered, the account-scoped inventory pass records
// existence on the server row, and the view presents that mark as deleted. The order
// detail's ending is therefore not the surface that decides it - which is the case the
// deferral exists for - and the mark below shows the ending still arrives.
func TestRegisteredDeploymentLetsTheInventoryPassRecordTheAbsence(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID          = "ord_995_registered_absent"
		providerServerID = int64(6212)
		address          = "198.51.100.212"
	)
	serverID := completeOnboarding(t, h, orderID, address, providerServerID)

	// The provider lists it live once, so both surfaces hold an ordinary row, then it
	// removes the VPS: the inventory omits it and the order detail says deleted, which is
	// exactly the pair the first-deletion regression is about.
	phases := &deletionPhases{listed: true}
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn:      phases.servers(orderID, address, providerServerID),
		getDeployStatusFn: phases.detail(orderID, address, providerServerID),
	})
	live := readOrderStatusList(t, h, orderID)
	liveRow := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, live, orderID)), orderID)
	if liveRow.Stage != "ready" {
		t.Fatalf("the fixture must start from a live registered deployment, got stage %q", liveRow.Stage)
	}
	if slices.Contains(liveRow.Actions, "deploy_setup_btn") {
		t.Fatalf("a registered, onboarded deployment must not offer Setup, got %v", liveRow.Actions)
	}

	phases.listed = false
	absent := readOrderStatusList(t, h, orderID)
	recorded, _, _, _, err := h.getDeployOrderByID(context.Background(), orderID)
	if err != nil || recorded == nil {
		t.Fatalf("reload the ledger row: %v", err)
	}
	if recorded.Status != gigahost.StatusReady {
		t.Fatalf("the registered deployment's journal was overwritten by the order detail, got %q",
			recorded.Status)
	}
	// The order detail is not what decides this deployment's existence, so its ending is
	// not presented either: the registered server row is, and it carries no mark yet.
	deferredRow := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, absent, orderID)), orderID)
	if deferredRow.Stage == deletedProviderStatus {
		t.Fatalf("the order detail presented a registered deployment as deleted before the inventory pass: %+v",
			deferredRow)
	}

	// The inventory pass records the absence on the server row it registered, and that
	// mark is what presents the deployment as deleted.
	markServerProviderAbsent(t, h, serverID)
	marked := readOrderStatusList(t, h, orderID)
	markedRow := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, marked, orderID)), orderID)
	if markedRow.Stage != deletedProviderStatus {
		t.Fatalf("the inventory pass's mark must present the deployment as deleted, got stage %q",
			markedRow.Stage)
	}
	if len(markedRow.Actions) != 0 {
		t.Fatalf("a marked deployment must offer no contact action, got %v", markedRow.Actions)
	}
}
