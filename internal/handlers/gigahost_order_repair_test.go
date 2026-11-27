package handlers

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// Each follow-up repeats the exact detail that the live inventory contradicted.
// Checking the ledger separately from the rendered row catches durable false endings.
func TestRepairedOrderRejectsRepeatedDeletionEvidence(t *testing.T) {
	for _, spelling := range []string{"ready", "active"} {
		for _, followup := range []string{"identical", "failure", "numeric_id_only", "unrelated_orders"} {
			for _, onboarded := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/onboarded_%t", spelling, followup, onboarded), func(t *testing.T) {
					h, _, _ := setupTestHandlers(t)
					const orderID = "ord_repair_evidence"
					const address = "198.51.100.213"
					const serverID = int64(6213)
					if onboarded {
						completeOnboarding(t, h, orderID, address, serverID)
					} else {
						seedUnonboardedOrder(t, h, orderID, address)
					}
					// A recorded deletion is the common starting point, including for a completed journal.
					if err := h.updateDeployOrderStatus(context.Background(), orderID, "deleted", "", "", serverID, 0, address); err != nil {
						t.Fatal(err)
					}
					if onboarded {
						// Keep the completed step: deletion concerns existence, not completion of setup.
						if err := h.updateDeployOrderStatus(context.Background(), orderID, "deleted", "ready", "", serverID, 0, address); err != nil {
							t.Fatal(err)
						}
					}
					mode := "live"
					detailReads := 0
					h.SetGigahostClient(&mockGigahostClient{
						getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
							switch mode {
							case "failure":
								return nil, fmt.Errorf("controlled inventory failure")
							case "unrelated_orders":
								return []gigahost.ServerInfo{{ID: serverID + 1, OrderID: "ord_neighbour", IPv4: address, Status: spelling}}, nil
							case "numeric_id_only":
								return []gigahost.ServerInfo{{ID: serverID, IPv4: address, Status: spelling}}, nil
							default:
								return []gigahost.ServerInfo{{ID: serverID, OrderID: orderID, IPv4: address, Status: spelling}}, nil
							}
						},
						getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
							detailReads++
							return &gigahost.DeployStatusResponse{OrderID: orderID, ServerID: serverID, Status: "deleted", UpdatedAt: "2020-01-01T00:00:00Z"}, nil
						},
					})
					readOrderStatusList(t, h, orderID) // affirmative repair
					repaired, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
					if err != nil || !found || repaired.LiveRepairedAt == nil {
						t.Fatalf("affirmative repair has no durable evidence: %+v %v", repaired, err)
					}
					mode = followup
					for attempt := 1; attempt <= 2; attempt++ {
						before := detailReads
						read := readOrderStatusList(t, h, orderID)
						if detailReads == before {
							t.Errorf("follow-up did not consume the unchanged detail")
						}
						order, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
						if err != nil || !found {
							t.Fatalf("reload repaired order: found=%t err=%v", found, err)
						}
						if order.LiveRepairedAt == nil || !order.LiveRepairedAt.Equal(*repaired.LiveRepairedAt) {
							t.Errorf("follow-up lost or invented repair evidence: %+v", order)
						}
						if order.Status != "ready" {
							t.Errorf("attempt %d: repeated stale detail re-deleted the ledger: %q", attempt, order.Status)
						}
						row := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, orderID)), orderID)
						if row.Stage == "deleted" {
							t.Errorf("attempt %d: repaired row rendered Deleted", attempt)
						}
						for _, action := range []string{"deploy_setup_btn", "setup_intents_approve"} {
							if slices.Contains(row.Actions, action) == onboarded {
								t.Errorf("attempt %d: action %s inconsistent with completed onboarding=%t: %v", attempt, action, onboarded, row.Actions)
							}
						}
					}
				})
			}
		}
	}
}

func TestRepairedOrderRequiresNewIdentifiedDetail(t *testing.T) {
	for _, test := range []struct {
		name, timestamp, identity, status string
		want                              string
	}{
		{"old", "2020-01-01T00:00:00Z", "ord_evidence", "deleted", "ready"},
		{"missing_time", "", "ord_evidence", "deleted", "ready"},
		{"unreadable_time", "not-a-time", "ord_evidence", "deleted", "ready"},
		{"new_deletion", "new", "ord_evidence", "deleted", "deleted"},
		{"wrong_order", "new", "another_order", "deleted", "ready"},
		{"missing_order", "new", "", "deleted", "ready"},
		{"cancellation", "", "ord_evidence", "cancelled", "cancelled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			seedUnonboardedOrder(t, h, "ord_evidence", "198.51.100.214")
			order, _, err := h.db.GetGigahostOrder(context.Background(), "ord_evidence")
			if err != nil {
				t.Fatal(err)
			}
			repaired := time.Now().UTC().Add(-time.Hour)
			order.LiveRepairedAt = &repaired
			order.Status = "ready"
			if err := h.db.UpdateGigahostOrderObservation(context.Background(), order, nil); err != nil {
				t.Fatal(err)
			}
			timestamp := test.timestamp
			if timestamp == "new" {
				timestamp = repaired.Add(time.Minute).Format(time.RFC3339Nano)
			}
			h.SetGigahostClient(&mockGigahostClient{
				getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
				getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
					return &gigahost.DeployStatusResponse{OrderID: test.identity, Status: test.status, UpdatedAt: timestamp}, nil
				},
			})
			read := readOrderStatusList(t, h, "ord_evidence")
			stored, _, err := h.db.GetGigahostOrder(context.Background(), "ord_evidence")
			if err != nil || stored.Status != test.want {
				t.Fatalf("detail wrote %q, want %q: %v", stored.Status, test.want, err)
			}
			row := renderedRowFor(t, renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, read, "ord_evidence")), "ord_evidence")
			if row.Stage != test.want {
				t.Fatalf("rendered %q, want %q", row.Stage, test.want)
			}
		})
	}
}

func TestDeletedOrderRepairRequiresAffirmativeIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		server gigahost.ServerInfo
		known  bool
		want   bool
	}{
		{"order_identity", gigahost.ServerInfo{ID: 77, OrderID: "ord_identity", Status: "active"}, true, true},
		{"recorded_numeric_identity", gigahost.ServerInfo{ID: 77, Status: "ready"}, true, true},
		{"same_address_only", gigahost.ServerInfo{ID: 78, OrderID: "other", IPv4: "198.51.100.215", Status: "active"}, true, false},
		{"conflicting_order", gigahost.ServerInfo{ID: 77, OrderID: "other", Status: "active"}, true, false},
		{"unreadable_inventory", gigahost.ServerInfo{ID: 77, OrderID: "ord_identity", Status: "active"}, false, false},
		{"no_status", gigahost.ServerInfo{ID: 77, OrderID: "ord_identity"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			seedUnonboardedOrder(t, h, "ord_identity", "198.51.100.215")
			order, _, err := h.db.GetGigahostOrder(context.Background(), "ord_identity")
			if err != nil {
				t.Fatal(err)
			}
			order.Status = "deleted"
			order.ServerID = 77
			if err := h.db.UpdateGigahostOrder(context.Background(), order); err != nil {
				t.Fatal(err)
			}
			_, spoke := h.repairDeletedOrderFromInventory(context.Background(), []gigahost.ServerInfo{test.server}, test.known, order, time.Now().UTC())
			if spoke != test.want {
				t.Fatalf("repair=%t want %t", spoke, test.want)
			}
			stored, _, err := h.db.GetGigahostOrder(context.Background(), "ord_identity")
			if err != nil {
				t.Fatal(err)
			}
			if (stored.LiveRepairedAt != nil) != test.want {
				t.Fatalf("unexpected durable repair: %+v", stored)
			}
			if !test.want && stored.Status != "deleted" {
				t.Fatalf("unreliable evidence repaired deletion: %+v", stored)
			}
		})
	}
}
