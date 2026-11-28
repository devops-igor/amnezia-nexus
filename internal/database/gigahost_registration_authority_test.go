package database

// Registration authority at the store's own boundary.
//
// The handler-level regression (internal/handlers) proves the fence through the production
// deploy path. This file pins the decision where it is made, so the three answers that path
// depends on are covered directly: a retired order is refused, a live order registers, and a
// call that names no order - the pre-existing behavior for every non-onboarding caller - is
// unaffected.
//
// The refusal is also asserted to be atomic: a refused registration leaves neither the server
// row nor its host-identity pin, which is the durable state a later reader would otherwise see
// as a deployment that exists.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// retirementTestFingerprint is a syntactically valid canonical SHA256 fingerprint. It is a
// fixture value, not a real host identity.
const retirementTestFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// seedRetirementOrder records one ledger row with the supplied status, so the retirement
// decision is exercised through the same models.GigahostOrder predicate every surface uses.
func seedRetirementOrder(t *testing.T, db *DB, orderID, status string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: 9001, Status: status,
		AssignedIP: "198.51.100.71", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order %q: %v", orderID, err)
	}
}

// countServerRows reports how many server rows exist, so a refusal can be shown to have
// committed nothing rather than merely returned an error.
func countServerRows(t *testing.T, db *DB) int {
	t.Helper()
	servers, err := db.GetAllServers(context.Background())
	if err != nil {
		t.Fatalf("list servers: %v", err)
	}
	return len(servers)
}

// countKnownHosts reports how many host-identity pins exist.
func countKnownHosts(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.SQLDB().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM known_hosts").Scan(&n); err != nil {
		t.Fatalf("count known_hosts: %v", err)
	}
	return n
}

// TestDeployedServerRegistrationRefusesAnEndedOrder is the store-level regression.
func TestDeployedServerRegistrationRefusesAnEndedOrder(t *testing.T) {
	cases := []struct {
		name        string
		status      string
		wantRefused bool
		// noOrderID exercises the unprefixed call: it names no order at all.
		noOrderID bool
	}{
		{name: "live-order-registers", status: "ready"},
		{name: "canceled-order-is-refused", status: "canceled", wantRefused: true},
		{name: "deleted-order-is-refused", status: "deleted", wantRefused: true},
		{name: "terminated-order-is-refused", status: "terminated", wantRefused: true},
		// A failure with no onboarding journal is provider-final, which the one predicate
		// treats as an ended order. The refusal must follow that decision, not re-derive it.
		{name: "provider-final-failure-is-refused", status: "failed", wantRefused: true},
		{name: "unnamed-order-is-unaffected", status: "canceled", noOrderID: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := setupTestDB(t)
			ctx := context.Background()
			const orderID = "ord_registration_authority"
			seedRetirementOrder(t, db, orderID, tc.status)

			serversBefore := countServerRows(t, db)
			pinsBefore := countKnownHosts(t, db)

			target := orderID
			if tc.noOrderID {
				target = ""
			}
			candidate := &models.Server{
				Name: "registration-fixture", Host: "198.51.100.72", SSHPort: 22, SSHUser: "root",
				Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 9001},
			}
			_, err := db.CreateDeployedServer(ctx, candidate, retirementTestFingerprint, target)

			if !tc.wantRefused {
				if err != nil {
					t.Fatalf("registration was refused: %v", err)
				}
				if got := countServerRows(t, db); got != serversBefore+1 {
					t.Errorf("server rows = %d, want %d", got, serversBefore+1)
				}
				if got := countKnownHosts(t, db); got != pinsBefore+1 {
					t.Errorf("host-identity pins = %d, want %d", got, pinsBefore+1)
				}
				return
			}

			if !errors.Is(err, ErrOrderEndedBeforeRegistration) {
				t.Fatalf("error = %v, want ErrOrderEndedBeforeRegistration", err)
			}
			// The refusal is a refusal: nothing was written.
			if got := countServerRows(t, db); got != serversBefore {
				t.Errorf("a refused registration left a server row: %d -> %d", serversBefore, got)
			}
			if got := countKnownHosts(t, db); got != pinsBefore {
				t.Errorf("a refused registration left a host pin: %d -> %d", pinsBefore, got)
			}
		})
	}
}

// TestCreateServerWithFingerprintStillPublishesRowAndPin is the control for the shared
// implementation: the order-free form the rest of the panel uses is unchanged, so extracting
// the common body did not quietly fence the ordinary server paths.
func TestCreateServerWithFingerprintStillPublishesRowAndPin(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	pinsBefore := countKnownHosts(t, db)

	id, err := db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "plain-fixture", Host: "198.51.100.73", SSHPort: 22, SSHUser: "root",
	}, retirementTestFingerprint)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if id <= 0 {
		t.Fatalf("created id = %d, want a row id", id)
	}
	if got := countKnownHosts(t, db); got != pinsBefore+1 {
		t.Errorf("host-identity pins = %d, want %d", got, pinsBefore+1)
	}
	bound, err := db.GetKnownHostFingerprint(ctx, id)
	if err != nil {
		t.Fatalf("read the bound identity: %v", err)
	}
	if bound != retirementTestFingerprint {
		t.Errorf("bound identity = %q, want %q", bound, retirementTestFingerprint)
	}
}

// TestOrderEndedFromReadsTheOnePredicate pins the shared read the fences share: any caller -
// the pool or a transaction - answers from the same ledger predicate, and an order the ledger
// never recorded answers "not ended".
//
// The two forms are exercised in separate critical sections on purpose. The store is opened
// with a single connection, so a transaction held open while the pool is queried would wait on
// itself; the property being proved is that both paths reach the same answer, not that they can
// run concurrently against one connection.
func TestOrderEndedFromReadsTheOnePredicate(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seedRetirementOrder(t, db, "ord_live", "ready")
	seedRetirementOrder(t, db, "ord_gone", "canceled")

	cases := []struct {
		orderID string
		want    bool
	}{
		{orderID: "ord_live"},
		{orderID: "ord_gone", want: true},
		{orderID: "ord_never_recorded"},
	}

	for _, tc := range cases {
		fromPool, err := gigahostOrderEndedFrom(ctx, db.SQLDB(), tc.orderID)
		if err != nil {
			t.Fatalf("pool read %q: %v", tc.orderID, err)
		}
		if fromPool != tc.want {
			t.Errorf("%q through the pool = %v, want %v", tc.orderID, fromPool, tc.want)
		}
	}

	for _, tc := range cases {
		fromTx, err := orderEndedThroughTransaction(t, ctx, db, tc.orderID)
		if err != nil {
			t.Fatalf("transaction read %q: %v", tc.orderID, err)
		}
		if fromTx != tc.want {
			t.Errorf("%q through a transaction = %v, want %v", tc.orderID, fromTx, tc.want)
		}
	}
}

// orderEndedThroughTransaction asks the question from inside a transaction and closes it before
// returning, so the single pooled connection is released for the next case.
func orderEndedThroughTransaction(
	t *testing.T, ctx context.Context, db *DB, orderID string,
) (bool, error) {
	t.Helper()
	tx, err := db.SQLDB().BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	ended, err := gigahostOrderEndedFrom(ctx, tx, orderID)
	if rollbackErr := tx.Rollback(); rollbackErr != nil {
		t.Fatalf("rollback: %v", rollbackErr)
	}
	return ended, err
}
