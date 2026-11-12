package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// seedLedgerRow inserts one complete order row through the real API.
func seedLedgerRow(t *testing.T, db *DB) models.GigahostOrder {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	o := models.GigahostOrder{OrderID: "10001", ServerID: 7, Status: "ready",
		PlanID: 202, RegionID: 2, HourlyPriceNOK: 0.057, PriceID: 666,
		MonthlyCapNOK: 41, Currency: "NOK", CreatedAt: now, UpdatedAt: now}
	if err := db.InsertGigahostOrder(context.Background(), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// TestGigahostOrderLedgerRoundTrip pins the retained order-history contract:
// every recorded field, including the provider price identity, survives a write
// and a read, and nothing in the read path invents a value for an absent field.
func TestGigahostOrderLedgerRoundTrip(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seed := seedLedgerRow(t, db)

	orders, err := db.ListGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("ListGigahostOrders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("rows = %d, want 1", len(orders))
	}
	got := orders[0]
	if got.ID != seed.ID || got.OrderID != seed.OrderID || got.ServerID != seed.ServerID {
		t.Fatalf("identity = %+v, want %+v", got, seed)
	}
	if got.Status != "ready" || got.PlanID != 202 || got.RegionID != 2 {
		t.Fatalf("lifecycle = %+v", got)
	}
	if got.HourlyPriceNOK != 0.057 || got.MonthlyCapNOK != 41 ||
		got.PriceID != 666 || got.Currency != "NOK" {
		t.Fatalf("price identity = %+v", got)
	}
	if got.AssignedIP != "" {
		t.Fatalf("assigned_ip = %q, want the stored empty default", got.AssignedIP)
	}

	// An update records the provider answer without rewriting the order-time
	// price identity, so history stays readable after the order has progressed.
	got.Status = "active"
	got.AssignedIP = "192.0.2.10"
	got.ServerID = 8
	got.MonthlyCapNOK = 0
	got.Currency = ""
	if err := db.UpdateGigahostOrder(ctx, &got); err != nil {
		t.Fatalf("UpdateGigahostOrder: %v", err)
	}

	after, err := db.ListGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("ListGigahostOrders after update: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("rows = %d, want 1", len(after))
	}
	if after[0].Status != "active" || after[0].AssignedIP != "192.0.2.10" || after[0].ServerID != 8 {
		t.Fatalf("lifecycle after update = %+v", after[0])
	}
	if after[0].PriceID != 666 || after[0].HourlyPriceNOK != 0.057 {
		t.Fatalf("price identity rewritten by update: %+v", after[0])
	}
	if after[0].MonthlyCapNOK != 41 || after[0].Currency != "NOK" {
		t.Fatalf("an empty update value overwrote recorded price data: %+v", after[0])
	}
}
