package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

func TestNewerDetailContradictedByLiveInventoryIsRemembered(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_newer_contradiction"
	seedUnonboardedOrder(t, h, orderID, "198.51.100.216")
	order, _, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil {
		t.Fatal(err)
	}
	previous := time.Now().UTC().Add(-2 * time.Hour)
	order.Status = "ready"
	order.LiveRepairedAt = &previous
	if err := h.db.UpdateGigahostOrderObservation(context.Background(), order, nil); err != nil {
		t.Fatal(err)
	}
	listed := true
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			if !listed {
				return nil, nil
			}
			return []gigahost.ServerInfo{{ID: 79, OrderID: orderID, Status: "active"}}, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: "deleted", UpdatedAt: previous.Add(time.Hour).Format(time.RFC3339Nano)}, nil
		},
	})
	readOrderStatusList(t, h, orderID) // learns the ID; detail may not be needed yet
	readOrderStatusList(t, h, orderID) // unchanged live inventory, newer contradictory detail
	updated, _, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || updated.LiveRepairedAt == nil || !updated.LiveRepairedAt.After(previous) {
		t.Fatalf("new contradiction not recorded: %+v %v", updated, err)
	}
	listed = false
	readOrderStatusList(t, h, orderID)
	stored, _, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || stored.Status != "ready" {
		t.Fatalf("previously contradicted newer detail re-deleted order: %+v %v", stored, err)
	}
}

func TestMissingDetailAfterRepairDoesNotInventCancellation(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_repaired_missing"
	seedUnonboardedOrder(t, h, orderID, "198.51.100.217")
	order, _, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil {
		t.Fatal(err)
	}
	repaired := time.Now().UTC()
	order.Status = "ready"
	order.LiveRepairedAt = &repaired
	if err := h.db.UpdateGigahostOrderObservation(context.Background(), order, nil); err != nil {
		t.Fatal(err)
	}
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, gigahost.ErrNotFound
		},
	})
	readOrderStatusList(t, h, orderID)
	stored, _, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || stored.Status != "ready" {
		t.Fatalf("failed read invented cancellation: %+v %v", stored, err)
	}
}
