package database

// The ledger association statement, proved at the store.
//
// The handler tests exercise this through the tracker, which is the path that matters for
// behaviour, but they only ever reach the happy shapes: a fresh purchase, a repeat and one
// conflict through the automatic path. These tests cover the statement's own contract
// directly - provenance refusal, each conflict shape, repeats, and the argument guards -
// because that contract is what stops a background pass from manufacturing ownership or
// re-pointing a row.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// seedLedgerOrder records one ledger row with the supplied provenance and identity.
func seedLedgerOrder(
	t *testing.T, db *DB, orderID string, origin string, serverID int64, address string,
) {
	t.Helper()
	now := time.Now().UTC()
	order := &models.GigahostOrder{
		OrderID: orderID, Status: "pending_order", PlanID: 7, RegionID: 3,
		ServerID: serverID, AssignedIP: address,
		PurchaseOrigin: origin, CreatedAt: now, UpdatedAt: now,
	}
	if origin != "" {
		order.PurchaseRecordedAt = now
	}
	if err := db.InsertGigahostOrder(context.Background(), order); err != nil {
		t.Fatalf("seed ledger order %s: %v", orderID, err)
	}
}

// readLedgerOrder returns the stored row.
func readLedgerOrder(t *testing.T, db *DB, orderID string) *models.GigahostOrder {
	t.Helper()
	order, found, err := db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("read ledger order %s: found=%v err=%v", orderID, found, err)
	}
	return order
}

// TestRecordProviderAssociationRequiresProvenance proves the statement cannot touch a row
// this panel did not purchase, and therefore cannot create the stamp that proves it.
func TestRecordProviderAssociationRequiresProvenance(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedLedgerOrder(t, db, "ord_unstamped", models.PurchaseOriginNone, 0, "")

	changed, err := db.RecordGigahostSetupProviderAssociation(ctx, "ord_unstamped", 7001, "198.51.100.5")
	if err != nil {
		t.Fatalf("associate an unstamped row: %v", err)
	}
	if changed {
		t.Fatal("the statement updated a row that is not the panel's purchase")
	}
	stored := readLedgerOrder(t, db, "ord_unstamped")
	if stored.PurchaseOrigin != models.PurchaseOriginNone {
		t.Fatalf("the statement manufactured provenance: %q", stored.PurchaseOrigin)
	}
	if stored.ServerID != 0 || stored.AssignedIP != "" {
		t.Fatalf("the statement wrote identity onto an unowned row: server=%d address=%q",
			stored.ServerID, stored.AssignedIP)
	}
}

// TestRecordProviderAssociationRepeatsAndConflicts covers the three no-op shapes:
// a plain repeat, a server-id conflict and an address conflict.
//
// Each is a distinct answer to the caller. A repeat is "already recorded", which is not an
// error; a conflict is a refusal that must name which fact disagreed, because that is the
// one an operator has to reconcile.
func TestRecordProviderAssociationRepeatsAndConflicts(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	const orderID = "ord_repeat"

	cases := []struct {
		name string
		// seedServer is the identity the row already carries.
		seedServer  int64
		seedAddress string
		// recordServer/recordAddress are the facts being recorded.
		recordServer  int64
		recordAddress string
		wantChanged   bool
		wantConflict  bool
	}{
		{
			name:         "a fresh row is filled in",
			recordServer: 7002, recordAddress: "198.51.100.6",
			wantChanged: true,
		},
		{
			name:         "an exact repeat changes nothing",
			seedServer:   7002,
			seedAddress:  "198.51.100.6",
			recordServer: 7002, recordAddress: "198.51.100.6",
			wantChanged: false,
		},
		{
			name:        "a different server id is a conflict",
			seedServer:  7002,
			seedAddress: "198.51.100.6",
			// Only the server disagrees; the address matches.
			recordServer: 7003, recordAddress: "198.51.100.6",
			wantConflict: true,
		},
		{
			name:        "a different address is a conflict",
			seedServer:  7002,
			seedAddress: "198.51.100.6",
			// Only the address disagrees; the server matches.
			recordServer: 7002, recordAddress: "198.51.100.7",
			wantConflict: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seedLedgerOrder(t, db, orderID, models.PurchaseOriginPanelPurchase,
				tc.seedServer, tc.seedAddress)

			changed, err := db.RecordGigahostSetupProviderAssociation(
				ctx, orderID, tc.recordServer, tc.recordAddress)
			if tc.wantConflict {
				if !errors.Is(err, ErrProviderAssociationConflict) {
					t.Fatalf("conflict was not reported: changed=%v err=%v", changed, err)
				}
				if changed {
					t.Fatal("a conflict reported a change")
				}
			} else if err != nil {
				t.Fatalf("associate: %v", err)
			} else if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tc.wantChanged)
			}

			stored := readLedgerOrder(t, db, orderID)
			// A conflict must leave the ORIGINAL identity in place - that is the whole
			// point of refusing rather than overwriting - so the expected identity is
			// what was requested only when the write was allowed to apply.
			wantServer, wantAddress := tc.recordServer, tc.recordAddress
			if tc.wantConflict {
				wantServer, wantAddress = tc.seedServer, tc.seedAddress
			}
			if stored.ServerID != wantServer || stored.AssignedIP != wantAddress {
				t.Fatalf("recorded identity = (%d, %q), want (%d, %q)",
					stored.ServerID, stored.AssignedIP, wantServer, wantAddress)
			}
			if stored.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
				t.Fatalf("the statement changed provenance to %q", stored.PurchaseOrigin)
			}
		})
	}
}

// TestRecordProviderAssociationGuardsItsArguments covers the shapes that are not an
// association at all. None may write, and none is an error: a partial answer is simply not
// evidence of anything.
func TestRecordProviderAssociationGuardsItsArguments(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	const orderID = "ord_guard"
	seedLedgerOrder(t, db, orderID, models.PurchaseOriginPanelPurchase, 0, "")

	cases := []struct {
		name     string
		orderID  string
		serverID int64
		address  string
	}{
		{name: "no order id", orderID: "  ", serverID: 7004, address: "198.51.100.8"},
		{name: "no server id", orderID: orderID, serverID: 0, address: "198.51.100.8"},
		{name: "negative server id", orderID: orderID, serverID: -1, address: "198.51.100.8"},
		{name: "no address", orderID: orderID, serverID: 7004, address: "   "},
		{name: "unknown order", orderID: "ord_missing", serverID: 7004, address: "198.51.100.8"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := db.RecordGigahostSetupProviderAssociation(
				ctx, tc.orderID, tc.serverID, tc.address)
			if err != nil {
				t.Fatalf("a non-association was reported as an error: %v", err)
			}
			if changed {
				t.Fatal("a non-association reported a change")
			}
			stored := readLedgerOrder(t, db, orderID)
			if stored.ServerID != 0 || stored.AssignedIP != "" {
				t.Fatalf("a non-association wrote identity: server=%d address=%q",
					stored.ServerID, stored.AssignedIP)
			}
		})
	}
}

// TestRecordProviderAssociationNilStoreIsNotAnError keeps the shared store convention: a
// package-level nil receiver is a no-op, not a panic, so a caller that wired no database
// gets a refusal rather than a crash.
func TestRecordProviderAssociationNilStoreIsNotAnError(t *testing.T) {
	var db *DB
	changed, err := db.RecordGigahostSetupProviderAssociation(
		context.Background(), "ord_anything", 7005, "198.51.100.9")
	if err != nil || changed {
		t.Fatalf("nil store: changed=%v err=%v", changed, err)
	}
}
