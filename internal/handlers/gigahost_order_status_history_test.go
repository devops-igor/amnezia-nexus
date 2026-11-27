package handlers

// Recent Deployments renders the five newest orders. A deployment the provider has
// deleted is hidden from the Servers grid by design, so when it is also outside those
// five the operator has no surface that names it: the ledger and the API still hold
// the record, but nobody can read the order id or see that it was removed.
//
// The default five stay exactly as they were - only a row the view itself classifies
// as deleted is rendered beyond it, which is the one class of row the grid refuses.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestMarkedDeploymentBeyondTheRecentFiveStaysIdentifiable is F995-03.
func TestMarkedDeploymentBeyondTheRecentFiveStaysIdentifiable(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	const markedOrderID = "ord_995_history"
	const markedProviderServerID = int64(6198)
	const markedIP = "198.51.100.198"

	// The marked deployment is the OLDEST row, so five newer orders are enough to push
	// it out of the default view.
	historyServerID := createPresentationServer(t, h, models.Server{
		Name:      "Gigahost-" + markedOrderID,
		Host:      markedIP,
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": markedProviderServerID},
	})
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: markedOrderID, Status: DeployStatusReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the marked order: %v", err)
	}
	// A failed journal, so the row would offer Retry if it were not marked: that makes
	// "no contact control" a statement about the mark rather than about an empty row.
	if err := h.updateDeployOrderStatus(ctx, markedOrderID, DeployStatusFailed, DeployStatusInstallingProtocol,
		"controlled install failure", markedProviderServerID, historyServerID, markedIP); err != nil {
		t.Fatalf("write the onboarding journal: %v", err)
	}

	newer := make([]string, 0, 5)
	for i := 1; i <= 5; i++ {
		orderID := fmt.Sprintf("ord_995_newer_%d", i)
		newer = append(newer, orderID)
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: orderID, Status: DeployStatusDeploying,
			AssignedIP: fmt.Sprintf("198.51.100.2%02d", i), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", orderID, err)
		}
	}

	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			servers := make([]gigahost.ServerInfo, 0, len(newer))
			for i, orderID := range newer {
				servers = append(servers, gigahost.ServerInfo{
					ID: int64(6200 + i), OrderID: orderID,
					IPv4: fmt.Sprintf("198.51.100.2%02d", i+1), Status: gigahost.StatusDeploying,
				})
			}
			return servers, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusDeploying}, nil
		},
	})

	readAll := func() gigahostOrderStatusResponses {
		t.Helper()
		read := gigahostOrderStatusRead(t, h, markedOrderID)
		read.Details = map[string]string{markedOrderID: read.Detail}
		for _, orderID := range newer {
			read.Details[orderID] = readGigahostOrderStatusDetail(t, h, orderID)
		}
		return read
	}

	// Control: while nothing is recorded against the server, the default five render and
	// the older order is outside them - the cap the change must not remove.
	before := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, readAll(), markedOrderID))
	if len(before.Rows) != 5 {
		t.Fatalf("the default recent list must render five rows, got %d: %+v", len(before.Rows), before.Rows)
	}
	for _, row := range before.Rows {
		if row.OrderID == markedOrderID {
			t.Fatalf("the control must have the older order outside the default five, got %+v", before.Rows)
		}
	}

	// The provider's own inventory confirms the older deployment's server is gone.
	markServerProviderAbsent(t, h, historyServerID)

	rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, readAll(), markedOrderID))
	if len(rendered.Rows) != 6 {
		t.Fatalf("the marked deployment must be reachable in addition to the default five, got %d rows: %+v",
			len(rendered.Rows), rendered.Rows)
	}

	// The existing five-row default still renders, newest first.
	for i, orderID := range newer {
		position := len(newer) - 1 - i // the list is ordered by insert id, newest first
		if rendered.Rows[position].OrderID != orderID {
			t.Fatalf("the default five changed: row %d is %q, want %q", position, rendered.Rows[position].OrderID, orderID)
		}
	}

	var marked *deletedDeploymentRow
	for i := range rendered.Rows {
		if rendered.Rows[i].OrderID == markedOrderID {
			marked = &rendered.Rows[i]
		}
	}
	if marked == nil {
		t.Fatalf("a deployment the Servers grid hides and Recent Deployments drops is invisible: %+v", rendered.Rows)
	}
	if marked.Stage != "deleted" {
		t.Fatalf("the marked deployment must render deleted, got %q", marked.Stage)
	}
	if !strings.Contains(marked.Identity, "#"+markedOrderID) {
		t.Fatalf("the marked deployment must stay identifiable by its order id: %q", marked.Identity)
	}
	if !strings.Contains(marked.Identity, markedIP) {
		t.Fatalf("the marked deployment must keep its recorded address: %q", marked.Identity)
	}
	if len(marked.Actions) != 0 {
		t.Fatalf("the marked deployment must offer no contact action, got %v", marked.Actions)
	}
}
