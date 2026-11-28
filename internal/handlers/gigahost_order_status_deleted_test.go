package handlers

// What Recent Deployments says about a deployment the provider has deleted.
//
// The absence state itself is recorded by the inventory pass; these tests are only about
// what an operator sees. They drive the real handlers, replay the response bodies those
// handlers actually produced into the shipped view module, and assert three things: the
// row reads DELETED, it keeps its order identity and its other values, and it offers no
// control whose only effect would be to contact a server the panel holds evidence is
// gone. Each fixture is rendered three times - before the observation, with it, and after
// it is corrected - so every claim is measured against that same row's normal treatment
// rather than against an empty screen.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// deletedDeploymentRender is the part of the shipped renderer's summary these tests read.
type deletedDeploymentRender struct {
	Stage    string   `json:"stage"`
	Identity string   `json:"identity"`
	Actions  []string `json:"actions"`
	Panel    string   `json:"panel"`
	// Label is the status control's accessible name, which is where a screen reader
	// hears any claim the row makes about a step being in flight.
	Label string `json:"label"`
	// Rows is every rendered row in order, so a test can assert what the list shows
	// rather than only inspecting its first cell.
	Rows []deletedDeploymentRow `json:"rows"`
}

// deletedDeploymentRow is one rendered row of the recent-deployments list.
type deletedDeploymentRow struct {
	OrderID  string   `json:"orderId"`
	Stage    string   `json:"stage"`
	Identity string   `json:"identity"`
	Label    string   `json:"label"`
	Actions  []string `json:"actions"`
}

// renderDeletedDeployment parses one renderer summary.
func renderDeletedDeployment(t *testing.T, summary string) deletedDeploymentRender {
	t.Helper()
	var rendered deletedDeploymentRender
	if err := json.Unmarshal([]byte(summary), &rendered); err != nil {
		t.Fatalf("the renderer summary is not JSON: %v %s", err, summary)
	}
	return rendered
}

// TestRecentDeploymentsShowsADeletedDeploymentWithoutContactActions is criterion 4's
// Recent Deployments half, with criterion 6 as its third phase.
func TestRecentDeploymentsShowsADeletedDeploymentWithoutContactActions(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	const orderID = "ord_986_recent"

	serverID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-" + orderID,
		Host:      "198.51.100.146",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 5104},
	})
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: orderID, Status: DeployStatusReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the order: %v", err)
	}
	// The onboarding journal: the server was registered and the install then failed. That
	// is the state that offers a Retry control, and the control is exactly what the
	// absence mark has to remove, so the fixture is chosen to make its disappearance
	// observable rather than trivially absent.
	//
	// The step is what makes this a recoverable failure: the order row records that an
	// install was attempted, so the failure is execution this panel ran rather than a
	// provider that ended provisioning. Without it the row is provider-final, which this
	// view already presents as an ending and offers nothing for - and then this test could
	// not distinguish the absence mark's effect from the state's.
	if err := h.updateDeployOrderStatus(ctx, orderID, DeployStatusFailed, DeployStatusInstallingProtocol,
		"controlled install failure", 5104, serverID, "198.51.100.146"); err != nil {
		t.Fatalf("write the onboarding journal: %v", err)
	}
	// The provider answers about the order throughout, so nothing here is explained by a
	// provider outage.
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, Status: gigahost.StatusReady, ServerID: 5104,
				AssignedIP: "198.51.100.146",
			}, nil
		},
	})

	// Phase 1 - control: the row's ordinary treatment before any absence is recorded.
	before := gigahostOrderStatusRead(t, h, orderID)
	if strings.Contains(before.Detail, "provider_absent") {
		t.Fatalf("the deploy read reported absence before any observation was recorded: %s", before.Detail)
	}
	normal := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, before, orderID))
	if normal.Stage == "deleted" {
		t.Fatalf("an order the panel has no absence record for rendered as deleted: %+v", normal)
	}
	if !slices.Contains(normal.Actions, "deploy_retry_btn") {
		t.Fatalf("the fixture must offer a contact action before the observation, got %v", normal.Actions)
	}

	// Phase 2 - the provider's inventory has confirmed the server no longer exists.
	markServerProviderAbsent(t, h, serverID)

	deletedRead := gigahostOrderStatusRead(t, h, orderID)
	if !strings.Contains(deletedRead.Detail, `"provider_absent":true`) {
		t.Fatalf("the deploy response must carry the recorded absence: %s", deletedRead.Detail)
	}
	deleted := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, deletedRead, orderID))
	if deleted.Stage != "deleted" {
		t.Fatalf("a deployment the provider has deleted must render as deleted, got stage %q", deleted.Stage)
	}
	// The visible word comes from the same stage vocabulary every other state uses.
	if !strings.Contains(deleted.Panel, "gigahost_status_stage_deleted") {
		t.Fatalf("the deleted deployment's details must state the deleted stage: %s", deleted.Panel)
	}
	// The address is kept, and so is the warning that it is no longer this panel's.
	if !strings.Contains(deleted.Panel, "gigahost_status_ip_deleted") {
		t.Fatalf("the deleted deployment must say its recorded address is no longer reserved for the panel: %s", deleted.Panel)
	}
	if strings.Contains(deleted.Panel, "gigahost_status_ip_while_provisioning") {
		t.Fatalf("a deleted deployment must not claim the provider is still provisioning it: %s", deleted.Panel)
	}
	// The stage's own next action: the panel advises nothing, because nothing it could
	// advise is available for a server the provider does not have.
	if !strings.Contains(deleted.Panel, "gigahost_status_next_action_none") {
		t.Fatalf("a deleted deployment must advise no next action: %s", deleted.Panel)
	}
	// The order identity, and the rest of the row, survive the state.
	if !strings.Contains(deleted.Identity, "#"+orderID) {
		t.Fatalf("the deleted deployment lost its order identity: %q", deleted.Identity)
	}
	if !strings.Contains(deleted.Identity, "198.51.100.146") {
		t.Fatalf("the deleted deployment lost its recorded address: %q", deleted.Identity)
	}
	// No control is offered, because every one of them would contact the server.
	if len(deleted.Actions) != 0 {
		t.Fatalf("a deleted deployment must offer no contact action, got %v", deleted.Actions)
	}
	// R5-01: the recorded step stays visible, and nothing on this row calls it current.
	// The attempt is over, so "Current step: installing_protocol" beside "Nothing to do"
	// reads as progress that is not happening.
	if !strings.Contains(deleted.Panel, DeployStatusInstallingProtocol) {
		t.Fatalf("the deleted deployment lost the recorded step it saved: %s", deleted.Panel)
	}
	if strings.Contains(deleted.Panel, "gigahost_status_step") {
		t.Fatalf("a finished attempt must not label its recorded step as the current one: %s", deleted.Panel)
	}
	if !strings.Contains(deleted.Panel, "gigahost_status_recorded_step") {
		t.Fatalf("the recorded step must still be shown, labelled as historical: %s", deleted.Panel)
	}
	if strings.Contains(deleted.Label, "gigahost_status_current_step") {
		t.Fatalf("the deleted row's accessible name must not claim a step is current: %q", deleted.Label)
	}

	// Phase 3 - criterion 6: the provider lists the server again.
	clearServerProviderAbsence(t, h, serverID)

	restoredRead := gigahostOrderStatusRead(t, h, orderID)
	if strings.Contains(restoredRead.Detail, "provider_absent") {
		t.Fatalf("a corrected row still reports provider absence: %s", restoredRead.Detail)
	}
	restored := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, restoredRead, orderID))
	if restored.Stage == "deleted" {
		t.Fatalf("a deployment the provider lists again is still rendered deleted: %+v", restored)
	}
	if !slices.Contains(restored.Actions, "deploy_retry_btn") {
		t.Fatalf("a corrected deployment must get its ordinary actions back, got %v", restored.Actions)
	}
	if !strings.Contains(restored.Identity, "#"+orderID) {
		t.Fatalf("the corrected deployment lost its order identity: %q", restored.Identity)
	}
}
