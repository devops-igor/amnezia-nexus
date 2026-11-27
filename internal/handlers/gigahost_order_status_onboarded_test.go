package handlers

// A backend that finished onboarding must stay finished, whatever word the provider uses
// for a running VPS.
//
// The order ledger's status column is the panel's own journal, and the view reads literal
// `ready` there as "this order is installed". A provider that names the same running
// server `active` on one read and `ready` on the next therefore used to rewrite the shared
// column on identical reads: the row alternated between the two words, Setup Backend and
// Approve reappeared on a backend that was already installed, and an administrator who
// followed the offered action could reinstall a live server.
//
// Both halves of the correction are asserted here: the ledger keeps the panel's word for
// the state, and the view recognises a completed onboarding from the journal's own durable
// evidence - the panel server it registered and the completed step - rather than from a
// provider spelling. The un-onboarded row is the control: it must keep offering the two
// setup actions under exactly the same inventory.

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// completeOnboarding records a deployment whose onboarding journal completed: the ledger
// carries the completed step and the mirror of the panel server the install registered,
// and the panel holds that server row. It is the state an immediate Setup Backend leaves
// behind, written through the same updater the deploy path uses.
func completeOnboarding(t *testing.T, h *Handlers, orderID, address string, providerServerID int64) int64 {
	t.Helper()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID: orderID, Status: DeployStatusReady, AssignedIP: address, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order %s: %v", orderID, err)
	}
	serverID := createPresentationServer(t, h, models.Server{
		Name: "Gigahost-" + orderID,
		Host: address,
		Protocols: map[string]any{
			"provider":           "gigahost",
			"provider_server_id": providerServerID,
		},
	})
	if err := h.updateDeployOrderStatus(context.Background(), orderID,
		DeployStatusReady, DeployStatusReady, "", providerServerID, serverID, address); err != nil {
		t.Fatalf("record the completed onboarding for %s: %v", orderID, err)
	}
	return serverID
}

// readOrderStatusList reads the order list once through the production handler and then
// each named order's deploy detail, so one rendering carries every row this sequence is
// about. Every body is the handler's own output.
func readOrderStatusList(t *testing.T, h *Handlers, orderIDs ...string) gigahostOrderStatusResponses {
	t.Helper()
	read := gigahostOrderStatusRead(t, h, "")
	read.Details = make(map[string]string, len(orderIDs))
	for _, id := range orderIDs {
		read.Details[id] = readGigahostOrderStatusDetail(t, h, id)
	}
	return read
}

// TestOnboardedBackendKeepsItsJournalUnderRepeatedActiveInventory is F995-06.
func TestOnboardedBackendKeepsItsJournalUnderRepeatedActiveInventory(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		onboardedOrder      = "ord_995_onboarded"
		unonboardedOrder    = "ord_995_unonboarded"
		onboardedProviderID = int64(6201)
		removedProviderID   = int64(6202)
		onboardedAddress    = "198.51.100.201"
		unonboardedAddress  = "198.51.100.202"
	)
	nexusServerID := completeOnboarding(t, h, onboardedOrder, onboardedAddress, onboardedProviderID)
	seedUnonboardedOrder(t, h, unonboardedOrder, unonboardedAddress)

	// The provider answers the same way on every read: its inventory spells a running
	// server `active`, and its order detail spells the same state `ready`. Nothing in the
	// fixture moves, so a row that changes did so because the panel rewrote it.
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: onboardedProviderID, OrderID: onboardedOrder, IPv4: onboardedAddress, Status: "active"},
				{ID: removedProviderID, OrderID: unonboardedOrder, IPv4: unonboardedAddress, Status: "active"},
			}, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			switch orderID {
			case onboardedOrder:
				return &gigahost.DeployStatusResponse{
					OrderID: orderID, Status: gigahost.StatusReady,
					ServerID: onboardedProviderID, AssignedIP: onboardedAddress,
				}, nil
			case unonboardedOrder:
				return &gigahost.DeployStatusResponse{
					OrderID: orderID, Status: gigahost.StatusReady,
					ServerID: removedProviderID, AssignedIP: unonboardedAddress,
				}, nil
			}
			return nil, fmt.Errorf("unexpected deploy detail read for %q", orderID)
		},
	})

	for attempt := 1; attempt <= 3; attempt++ {
		read := readOrderStatusList(t, h, onboardedOrder, unonboardedOrder)
		rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, onboardedOrder))
		row := renderedRowFor(t, rendered, onboardedOrder)
		control := renderedRowFor(t, rendered, unonboardedOrder)

		// The shared ledger keeps the panel's word for a running VPS on every read, so a
		// consumer that reads `ready` as "onboarded" cannot be un-taught by an inventory
		// listing. Before the correction this alternated active -> ready -> active.
		recorded, mirroredServerID, _, step, err := h.getDeployOrderByID(context.Background(), onboardedOrder)
		if err != nil || recorded == nil {
			t.Fatalf("attempt %d: reload the onboarded ledger row: %v", attempt, err)
		}
		if recorded.Status != gigahost.StatusReady {
			t.Fatalf("attempt %d: an inventory read rewrote the onboarded row's recorded status to %q: "+
				"the shared ledger must keep the panel's own word for the state",
				attempt, recorded.Status)
		}
		if step != DeployStatusReady {
			t.Fatalf("attempt %d: the completed step was lost from the journal, got %q", attempt, step)
		}
		if mirroredServerID != nexusServerID {
			t.Fatalf("attempt %d: the registered panel server is no longer recorded, got %d want %d",
				attempt, mirroredServerID, nexusServerID)
		}

		// The deploy read the view consumes says the same thing, and it is what decides
		// onboarding: a `server_id` and the completed step, not a provider spelling.
		var detail struct {
			Deploy struct {
				Status   string `json:"status"`
				Step     string `json:"step"`
				ServerID int64  `json:"server_id"`
			} `json:"deploy"`
		}
		if err := json.Unmarshal([]byte(read.Details[onboardedOrder]), &detail); err != nil {
			t.Fatalf("attempt %d: the deploy read is not the documented shape: %v %s",
				attempt, err, read.Details[onboardedOrder])
		}
		if detail.Deploy.Status != gigahost.StatusReady {
			t.Fatalf("attempt %d: the deploy read presents %q as the order's status: %s",
				attempt, detail.Deploy.Status, read.Details[onboardedOrder])
		}
		if detail.Deploy.Step != DeployStatusReady || detail.Deploy.ServerID != nexusServerID {
			t.Fatalf("attempt %d: the onboarded row lost its journal evidence: step %q server %d",
				attempt, detail.Deploy.Step, detail.Deploy.ServerID)
		}

		// The defect: an installed backend offering to run its own setup again.
		for _, action := range []string{"deploy_setup_btn", "setup_intents_approve"} {
			if slices.Contains(row.Actions, action) {
				t.Fatalf("attempt %d: an already onboarded backend offers %q again: %v",
					attempt, action, row.Actions)
			}
		}
		if row.Stage != "ready" {
			t.Fatalf("attempt %d: an onboarded backend must render ready, got %q", attempt, row.Stage)
		}

		// The control: nothing was onboarded for this order, so the same inventory must
		// keep offering both setup actions. Without it, a view that never offers an action
		// would pass the assertions above for the wrong reason.
		for _, action := range []string{"deploy_setup_btn", "setup_intents_approve"} {
			if !slices.Contains(control.Actions, action) {
				t.Fatalf("attempt %d: the un-onboarded control must still offer %q, got %v",
					attempt, action, control.Actions)
			}
		}
	}
}

// renderedRowFor returns one order's rendered row, failing when the list does not show it.
func renderedRowFor(t *testing.T, rendered deletedDeploymentRender, orderID string) deletedDeploymentRow {
	t.Helper()
	for _, row := range rendered.Rows {
		if row.OrderID == orderID {
			return row
		}
	}
	t.Fatalf("the list does not render order %q; rows: %+v", orderID, rendered.Rows)
	return deletedDeploymentRow{}
}

// TestRendererRecognisesOnboardingWithoutTheProviderSpelling is F995-06's renderer half.
//
// The backend now records the panel's own word for a running server, so no new row can carry
// the provider's `active` spelling in its status column. A row persisted by the previous
// build still can, and the question this test asks is the one that mattered: does the view
// decide "this backend is installed" from the provider's word or from the panel's own
// journal? The bodies below are therefore authored - they are the state the previous build
// left in the ledger, which this build's handlers can no longer produce.
func TestRendererRecognisesOnboardingWithoutTheProviderSpelling(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID          = "ord_995_legacy_active"
		providerServerID = int64(6204)
		address          = "198.51.100.204"
	)
	nexusServerID := completeOnboarding(t, h, orderID, address, providerServerID)

	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: providerServerID, OrderID: orderID, IPv4: address, Status: "active"},
			}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, Status: gigahost.StatusReady,
				ServerID: providerServerID, AssignedIP: address,
			}, nil
		},
	})
	read := readOrderStatusList(t, h, orderID)

	// The completed journal, presented the way the previous build left it: the provider's
	// spelling in the status column, the panel's registered server and completed step beside
	// it.
	body := func(step string) string {
		encoded, err := json.Marshal(map[string]any{"deploy": map[string]any{
			"order_id":    orderID,
			"status":      "active",
			"step":        step,
			"server_id":   nexusServerID,
			"assigned_ip": address,
		}})
		if err != nil {
			t.Fatalf("build the legacy deploy body: %v", err)
		}
		return string(encoded)
	}

	legacy := read
	legacy.Details = map[string]string{orderID: body(DeployStatusReady)}
	row := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, legacy, orderID)), orderID)
	if row.Stage != "ready" {
		t.Fatalf("a running backend must render ready whatever the provider calls it, got %q", row.Stage)
	}
	for _, action := range []string{"deploy_setup_btn", "setup_intents_approve"} {
		if slices.Contains(row.Actions, action) {
			t.Fatalf("the renderer still decides onboarding from the provider's word: it offers %q, "+
				"got %v", action, row.Actions)
		}
	}

	// The control: the same provider word and the same registered server, but no completed
	// step in the journal. That is an install the panel never finished, so it must keep
	// offering both setup actions.
	paused := read
	paused.Details = map[string]string{orderID: body("")}
	control := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, paused, orderID)), orderID)
	for _, action := range []string{"deploy_setup_btn", "setup_intents_approve"} {
		if !slices.Contains(control.Actions, action) {
			t.Fatalf("an install with no completed step must still offer %q, got %v",
				action, control.Actions)
		}
	}
}

// TestProviderActiveSpellingIsRecordedAsThePanelStatus pins the vocabulary rule the
// correction above rests on: the provider's own spelling stays in the observation, and the
// shared ledger records the panel's word for the same state.
func TestProviderActiveSpellingIsRecordedAsThePanelStatus(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const (
		orderID          = "ord_995_vocabulary"
		providerServerID = int64(6203)
		address          = "198.51.100.203"
	)
	seedUnonboardedOrder(t, h, orderID, address)

	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: providerServerID, OrderID: orderID, IPv4: address, Status: "active"},
			}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			t.Fatalf("a row the inventory already answers for must not be asked about again in this read")
			return nil, nil
		},
	})

	// A row whose recorded state the inventory corrects: `deleted` is an ending, so the
	// live listing repairs it, and the repaired value must be the panel's word.
	if err := h.updateDeployOrderStatus(context.Background(), orderID, deletedProviderStatus, "", "", 0, 0, ""); err != nil {
		t.Fatalf("record the deletion: %v", err)
	}
	read := readOrderStatusList(t, h, orderID)

	recorded, _, _, _, err := h.getDeployOrderByID(context.Background(), orderID)
	if err != nil || recorded == nil {
		t.Fatalf("reload the repaired row: %v", err)
	}
	if recorded.Status != gigahost.StatusReady {
		t.Fatalf("the repaired ledger row reads %q, want the panel's %q", recorded.Status, gigahost.StatusReady)
	}
	obs := gigahostOrderStatusProviderObservation(t, read.Orders, orderID)
	if got := obs["status"]; got != "active" {
		t.Fatalf("the observation must keep the provider's own spelling, got %v in %s", got, read.Orders)
	}
	if !strings.Contains(read.Details[orderID], `"status":"`+gigahost.StatusReady+`"`) {
		t.Fatalf("the deploy read must present the panel's status: %s", read.Details[orderID])
	}
}
