package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestListGigahostDeploymentsReadsWithoutCreatingTheTable pins the single decision this
// reader makes differently from ListGigahostOrders: a page render must not run schema
// DDL, so a panel that has never ordered anything answers "no deployments" and is left
// without a ledger table.
func TestListGigahostDeploymentsReadsWithoutCreatingTheTable(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.SQLDB().ExecContext(ctx, `DROP TABLE gigahost_orders`); err != nil {
		t.Fatalf("drop the ledger table: %v", err)
	}

	got, err := db.ListGigahostDeployments(ctx)
	if err != nil {
		t.Fatalf("a missing ledger must read as no deployments, got error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no deployments from a missing ledger, got %d", len(got))
	}

	// The read must not have created the table it could not find.
	var name string
	if err := db.SQLDB().QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='gigahost_orders'`).Scan(&name); err == nil {
		t.Fatalf("the display reader created the ledger table (%q); it must only read", name)
	}
}

// TestListGigahostDeploymentsReturnsTheRecordedRows pins that the reader answers with the
// recorded state a page displays, not a derived one.
func TestListGigahostDeploymentsReturnsTheRecordedRows(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	order := &models.GigahostOrder{
		OrderID:        "ord_page_read",
		Status:         "deploying",
		PlanID:         7,
		RegionID:       2,
		HourlyPriceNOK: 0.5,
		PriceID:        70,
		AssignedIP:     "198.51.100.30",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := db.InsertGigahostOrder(ctx, order); err != nil {
		t.Fatalf("insert the ledger row: %v", err)
	}

	got, err := db.ListGigahostDeployments(ctx)
	if err != nil {
		t.Fatalf("read the ledger: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one deployment, got %d", len(got))
	}
	if got[0].OrderID != "ord_page_read" || got[0].Status != "deploying" {
		t.Fatalf("expected the recorded row back, got %+v", got[0])
	}
	if got[0].AssignedIP != "198.51.100.30" {
		t.Fatalf("expected the recorded address back, got %q", got[0].AssignedIP)
	}
}
