package handlers

// A provider ending the panel recorded durably survives the historical setup journal.
//
// The immediate "Setup Backend" path can run while the provider is still deploying: it
// journals `deploying` and returns without waiting, and no panel server is registered. If
// the provider then removes the deployment, the next order read accepts the complete
// inventory omission plus the provider's explicit ending and persists it on the ledger.
//
// The first read presents that ending correctly. The next read skips a terminal row at the
// provider, so the only evidence left beside the ledger is the old journal step - and a
// journal step must not outrank the panel's own record of how the deployment ended, or an
// ordinary refresh undoes the ending and re-offers provisioning for a server the panel has
// already recorded as gone.
//
// The controls are the directions the correction must not take: an affirmative inventory
// repair still wins over a recorded deletion, and a journal-only failure or cancellation is
// never promoted into a deletion.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// deployDetailOf decodes the deploy half of one real status response.
func deployDetailOf(t *testing.T, body string) map[string]any {
	t.Helper()
	var parsed struct {
		Deploy map[string]any `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("the deploy response is not JSON: %v %s", err, body)
	}
	if parsed.Deploy == nil {
		t.Fatalf("the deploy response carries no deploy record: %s", body)
	}
	return parsed.Deploy
}

// TestDurablyRecordedDeletionSurvivesAHistoricalJournalStep is the two-read sequence for
// each spelling the backend treats as a deletion: the read that records it, and the next
// refresh whose status request still reports the onboarding step.
func TestDurablyRecordedDeletionSurvivesAHistoricalJournalStep(t *testing.T) {
	for _, spelling := range []string{"terminated", "deleted"} {
		t.Run(spelling, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			ctx := context.Background()
			const orderID = "ord_986_ending"

			providerRemoved := false
			providerRestored := false
			h.SetGigahostClient(&mockGigahostClient{
				getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
					if providerRestored {
						return []gigahost.ServerInfo{{
							ID: 9809, OrderID: orderID, IPv4: "198.51.100.41", Status: gigahost.StatusReady,
						}}, nil
					}
					return nil, nil
				},
				getDeployStatusFn: func(_ context.Context, id string) (*gigahost.DeployStatusResponse, error) {
					if providerRestored {
						return &gigahost.DeployStatusResponse{
							OrderID: id, Status: gigahost.StatusReady, ServerID: 9809, AssignedIP: "198.51.100.41",
						}, nil
					}
					if providerRemoved {
						return &gigahost.DeployStatusResponse{OrderID: id, Status: spelling}, nil
					}
					return &gigahost.DeployStatusResponse{OrderID: id, Status: gigahost.StatusDeploying}, nil
				},
			})

			// The real non-waiting setup route: the provider is still deploying, so the
			// request journals the step and answers without waiting.
			started, err := h.DeployGigahostOrder(ctx, GigahostDeployRequest{
				OrderID: orderID, SSHPassword: "fixture-only",
			})
			if err != nil {
				t.Fatalf("non-waiting setup failed: %v", err)
			}
			if started.Status != DeployStatusDeploying {
				t.Fatalf("the fixture must leave the order deploying, got %q", started.Status)
			}
			order, nexusServerID, _, step, err := h.getDeployOrderByID(ctx, orderID)
			if err != nil || order == nil {
				t.Fatalf("read the journal back: order=%v err=%v", order, err)
			}
			if step != DeployStatusDeploying || order.Status != DeployStatusDeploying {
				t.Fatalf("the fixture must journal the deploying step, got status %q step %q", order.Status, step)
			}
			if nexusServerID != 0 {
				t.Fatalf("the fixture must register no panel server, got %d", nexusServerID)
			}

			// The provider removes the deployment. The first read records the ending it
			// reports and must present it.
			providerRemoved = true
			first := gigahostOrderStatusRead(t, h, orderID)
			firstRender := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, first, orderID))
			if firstRender.Stage != "deleted" {
				t.Fatalf("the read that records the provider's %s must present it, got stage %q: %+v",
					spelling, firstRender.Stage, firstRender)
			}
			recorded, _, _, _, err := h.getDeployOrderByID(ctx, orderID)
			if err != nil || recorded == nil {
				t.Fatalf("read the recorded ending back: order=%v err=%v", recorded, err)
			}
			if recorded.Status != spelling {
				t.Fatalf("the %s ending must be persisted on the ledger, got %q", spelling, recorded.Status)
			}

			// The next refresh: the row is terminal, so the provider is not asked about it
			// again, while the status request still reports the old onboarding step.
			second := gigahostOrderStatusRead(t, h, orderID)
			detail := deployDetailOf(t, second.Detail)
			if detail["status"] != spelling {
				t.Fatalf("the second status read must still report the recorded ending, got %v in %s",
					detail["status"], second.Detail)
			}
			if detail["step"] != DeployStatusDeploying {
				t.Fatalf("the second status read must still carry the historical journal step, got %v in %s",
					detail["step"], second.Detail)
			}
			secondRender := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, second, orderID))
			if secondRender.Stage != "deleted" {
				t.Fatalf("a historical journal step must not undo a durably recorded %s, got stage %q: %+v",
					spelling, secondRender.Stage, secondRender)
			}
			if len(secondRender.Actions) != 0 {
				t.Fatalf("a durably recorded %s must offer no contact action on the second read, got %v",
					spelling, secondRender.Actions)
			}

			// Control: an affirmative inventory listing of the same order is a correction
			// of the recorded ending, so it stays authoritative over it.
			providerRestored = true
			repaired := gigahostOrderStatusRead(t, h, orderID)
			repairedRender := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, repaired, orderID))
			if repairedRender.Stage == "deleted" {
				t.Fatalf("an inventory that lists the deployment again must repair the %s ending, got %+v",
					spelling, repairedRender)
			}
			if len(repairedRender.Actions) == 0 {
				t.Fatalf("a repaired deployment must get its ordinary controls back, got %+v", repairedRender)
			}
		})
	}
}

// TestJournalOnlyFailureAndCancellationAreNotDeletions is the other direction: a status the
// onboarding journal writes is an install outcome, not a provider deletion, so the ending
// correction must not reach it. Both rows keep the treatment they had, and both are states
// in which a deletion would have removed the controls, so "an action is still offered"
// distinguishes the outcome from the deletion rather than from an empty screen.
func TestJournalOnlyFailureAndCancellationAreNotDeletions(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()

	rows := []struct {
		orderID string
		status  string
	}{
		{"ord_986_journal_failed", DeployStatusFailed},
		{"ord_986_journal_cancelled", statusCancelled},
	}
	for _, row := range rows {
		if err := h.updateDeployOrderStatus(ctx, row.orderID, row.status, DeployStatusInstallingProtocol,
			"controlled install failure", 0, 0, "198.51.100.31"); err != nil {
			t.Fatalf("journal %s: %v", row.orderID, err)
		}
	}
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
	})

	responses := gigahostOrderStatusRead(t, h, "")
	responses.Details = make(map[string]string, len(rows))
	for _, row := range rows {
		responses.Details[row.orderID] = readGigahostOrderStatusDetail(t, h, row.orderID)
		if step, _ := deployDetailOf(t, responses.Details[row.orderID])["step"].(string); step != DeployStatusInstallingProtocol {
			t.Fatalf("the fixture must carry the journal step for %s: %s", row.orderID, responses.Details[row.orderID])
		}
	}

	rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, responses, ""))
	if len(rendered.Rows) != len(rows) {
		t.Fatalf("both journal-only outcomes must still be listed, got %+v", rendered.Rows)
	}
	expected := map[string]string{rows[0].orderID: rows[0].status, rows[1].orderID: rows[1].status}
	for _, row := range rendered.Rows {
		status, ok := expected[row.OrderID]
		if !ok {
			t.Fatalf("the list returned a row this fixture did not seed: %+v", row)
		}
		if row.Stage == "deleted" {
			t.Fatalf("a journal-only %s must not be promoted to a deletion: %+v", status, row)
		}
		if len(row.Actions) == 0 {
			t.Fatalf("a journal-only %s keeps the controls a deletion would remove, got %+v", status, row)
		}
	}
}
