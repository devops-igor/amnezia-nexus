package handlers

// The order-level existence record, driven through the production handlers.
//
// The provider's inventory is the evidence, so each case here changes only what the
// provider answered and asserts what the ledger did with it. The fail-safe direction is
// the subject: a failed, partial or unattributable answer must leave every row exactly
// as it was, and only a complete answer attributed to the order's own account may record
// that the order is gone.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

const (
	existenceAccount      = "1111"
	existenceOtherAccount = "2222"
)

// seedExistenceOrder writes one ledger row in the state a deployment reaches after the
// provider accepted it: a provider server id and a running status.
func seedExistenceOrder(t *testing.T, h *Handlers, orderID string, serverID int64, origin string) {
	t.Helper()
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID:        orderID,
		Status:         gigahost.StatusReady,
		ServerID:       serverID,
		AssignedIP:     "198.51.100.31",
		PurchaseOrigin: origin,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("seed the ledger row %q: %v", orderID, err)
	}
}

// existenceProvider is the provider fixture: the account identity, the inventory answer
// and the number of per-order deploy reads the list performed.
func existenceProvider(t *testing.T, inventory []gigahost.ServerInfo, inventoryErr error, deployReads *int) *mockGigahostClient {
	t.Helper()
	return &mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{CustID: existenceAccount}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return inventory, inventoryErr
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			if deployReads != nil {
				*deployReads++
			}
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady}, nil
		},
	}
}

// storedOrder reloads one ledger row so the assertion is about durable state.
func storedOrder(t *testing.T, h *Handlers, orderID string) *GigahostOrderRecord {
	t.Helper()
	order, found, err := h.db.GetGigahostOrder(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("reload order %q: found=%v err=%v", orderID, found, err)
	}
	return order
}

// absenceMark reads the list response's durable absence marks.
func absenceMark(t *testing.T, body, orderID string) bool {
	t.Helper()
	var envelope struct {
		Absent map[string]bool `json:"provider_absent_orders"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("the list response is not the documented shape: %v", err)
	}
	return envelope.Absent[orderID]
}

// TestOrderAbsenceIsRecordedFromASuccessfulInventoryReadThatOmitsIt is the positive case:
// a complete listing attributed to the order's account does not name it, so the ledger
// records that the order is gone, the response says so, the row renders DELETED with no
// action, and the list stops asking the provider about the order.
func TestOrderAbsenceIsRecordedFromASuccessfulInventoryReadThatOmitsIt(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_gone"
	seedExistenceOrder(t, h, orderID, 7101, models.PurchaseOriginPanelPurchase)

	deployReads := 0
	h.SetGigahostClient(existenceProvider(t, nil, nil, &deployReads))

	read := gigahostOrderStatusRead(t, h, "")

	stored := storedOrder(t, h, orderID)
	if !stored.ProviderAbsent() {
		t.Fatalf("a successful listing that omits the order must record its absence: %+v", stored)
	}
	if stored.ProviderAbsentAccountID != existenceAccount {
		t.Fatalf("the observation must name the account that answered, got %q", stored.ProviderAbsentAccountID)
	}
	if !absenceMark(t, read.Orders, orderID) {
		t.Fatalf("the list response must carry the recorded absence: %s", read.Orders)
	}
	// A recorded absence is the panel's own answer, so the order is not asked about
	// again: the read that produced the record is the last one.
	if deployReads != 0 {
		t.Fatalf("the list asked the provider about a retired order %d time(s)", deployReads)
	}

	// The rendered row: DELETED, with no control that would contact the deployment.
	h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	statusRead := gigahostOrderStatusRead(t, h, orderID)
	statusRead.Details = map[string]string{orderID: statusRead.Detail}
	rendered := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, statusRead, orderID))
	if len(rendered.Rows) != 1 || rendered.Rows[0].Stage != "deleted" {
		t.Fatalf("a retired order must render as deleted, got %+v", rendered.Rows)
	}
	if len(rendered.Rows[0].Actions) != 0 {
		t.Fatalf("a retired order offers no action, got %v", rendered.Rows[0].Actions)
	}
}

// TestFailedInventoryReadRecordsNoOrderAbsence is the safety case: an unanswered read is
// not evidence about any order, so the row keeps the state it had and stays refreshable.
func TestFailedInventoryReadRecordsNoOrderAbsence(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_outage"
	seedExistenceOrder(t, h, orderID, 7102, models.PurchaseOriginPanelPurchase)

	deployReads := 0
	h.SetGigahostClient(existenceProvider(t, nil, errors.New("provider timed out"), &deployReads))

	read := gigahostOrderStatusRead(t, h, "")

	if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
		t.Fatalf("a failed inventory read recorded absence: %+v", stored)
	}
	if absenceMark(t, read.Orders, orderID) {
		t.Fatalf("a failed inventory read produced an absence mark: %s", read.Orders)
	}
	if deployReads == 0 {
		t.Fatalf("an order with no absence record must stay refreshable, but no detail read was made")
	}
}

// TestPartialInventoryReadRecordsNoOrderAbsence pins the completeness gate: a listing
// that carries an entry no server id can be read from says nothing about the account, so
// nothing may be concluded from it.
func TestPartialInventoryReadRecordsNoOrderAbsence(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_partial"
	seedExistenceOrder(t, h, orderID, 7103, models.PurchaseOriginPanelPurchase)

	deployReads := 0
	partial := []gigahost.ServerInfo{{ID: 0, OrderID: "another_order", Status: gigahost.StatusReady}}
	h.SetGigahostClient(existenceProvider(t, partial, nil, &deployReads))

	read := gigahostOrderStatusRead(t, h, "")

	if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
		t.Fatalf("a partial inventory answer recorded absence: %+v", stored)
	}
	if absenceMark(t, read.Orders, orderID) {
		t.Fatalf("a partial inventory answer produced an absence mark")
	}
}

// TestUnattributableInventoryReadRecordsNoOrderAbsence pins the account gate: an answer
// that cannot be attributed to an account proves nothing about any order.
func TestUnattributableInventoryReadRecordsNoOrderAbsence(t *testing.T) {
	for _, test := range []struct {
		name    string
		account func(context.Context) (*gigahost.AccountInfo, error)
	}{
		{"account read failed", func(context.Context) (*gigahost.AccountInfo, error) {
			return nil, errors.New("provider unavailable")
		}},
		{"account identity missing", func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{}, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			const orderID = "ord_existence_unattributed"
			seedExistenceOrder(t, h, orderID, 7104, models.PurchaseOriginPanelPurchase)

			client := existenceProvider(t, nil, nil, nil)
			client.getAccountFn = test.account
			h.SetGigahostClient(client)

			read := gigahostOrderStatusRead(t, h, "")

			if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
				t.Fatalf("an unattributable answer recorded absence: %+v", stored)
			}
			if absenceMark(t, read.Orders, orderID) {
				t.Fatalf("an unattributable answer produced an absence mark")
			}
		})
	}
}

// TestAnotherAccountsListingRecordsNoOrderAbsence pins the association gate: one account's
// listing is not evidence about another account's orders.
func TestAnotherAccountsListingRecordsNoOrderAbsence(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_other_account"
	seedExistenceOrder(t, h, orderID, 7105, models.PurchaseOriginPanelPurchase)
	order := storedOrder(t, h, orderID)
	order.ProviderAccountID = existenceOtherAccount
	if err := h.db.SetGigahostOrderProviderAccount(context.Background(), orderID, existenceOtherAccount); err != nil {
		t.Fatalf("record the other account: %v", err)
	}

	h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	read := gigahostOrderStatusRead(t, h, "")

	if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
		t.Fatalf("another account's listing recorded absence on this account's order: %+v", stored)
	}
	if absenceMark(t, read.Orders, orderID) {
		t.Fatalf("another account's listing produced an absence mark")
	}
}

// TestAListingThatNamesTheOrderClearsItsRecord is the recovery direction: the provider
// lists the order again, so the record is cleared and the association is recorded from
// the answer that named it.
func TestAListingThatNamesTheOrderClearsItsRecord(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_relisted"
	seedExistenceOrder(t, h, orderID, 7106, "")
	if err := h.db.SetGigahostOrderAbsence(context.Background(), orderID, time.Now().UTC(), existenceAccount); err != nil {
		t.Fatalf("record a prior absence: %v", err)
	}

	listed := []gigahost.ServerInfo{{ID: 7106, OrderID: orderID, Status: gigahost.StatusReady}}
	h.SetGigahostClient(existenceProvider(t, listed, nil, nil))

	read := gigahostOrderStatusRead(t, h, "")

	stored := storedOrder(t, h, orderID)
	if stored.ProviderAbsent() {
		t.Fatalf("a listed order kept its absence record: %+v", stored)
	}
	if stored.ProviderAccountID != existenceAccount {
		t.Fatalf("the listing that named the order must record its account, got %q", stored.ProviderAccountID)
	}
	if absenceMark(t, read.Orders, orderID) {
		t.Fatalf("a listed order still reports absence: %s", read.Orders)
	}
}

// TestPanelPurchaseWithoutAProviderNamedAccountIsRetired pins the case the record exists
// for: an order this panel bought, whose deployment the provider no longer lists and
// which never registered a panel server, so no provider answer can name its account any
// more. The purchase is the association the panel holds, and it is recorded once.
func TestPanelPurchaseWithoutAProviderNamedAccountIsRetired(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_legacy_purchase"
	seedExistenceOrder(t, h, orderID, 7107, models.PurchaseOriginPanelPurchase)

	h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	read := gigahostOrderStatusRead(t, h, "")

	stored := storedOrder(t, h, orderID)
	if !stored.ProviderAbsent() {
		t.Fatalf("a panel purchase the provider no longer lists must be retireable: %+v", stored)
	}
	if stored.ProviderAccountID != existenceAccount {
		t.Fatalf("the association must be recorded with the observation, got %q", stored.ProviderAccountID)
	}
	if !absenceMark(t, read.Orders, orderID) {
		t.Fatalf("the list response must carry the recorded absence")
	}
}

// TestOrderThatNeverDeployedIsNotRecordedAbsent is the negative control for the
// population rule: an order still being placed is not absent from a listing, it is not
// deployed yet, and a purchase the provider never acknowledged has no deployment at all.
func TestOrderThatNeverDeployedIsNotRecordedAbsent(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for orderID, status := range map[string]string{
		"ord_existence_pending": "pending",
		"intent_existence":      "pending_order",
	} {
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: orderID, Status: status, PurchaseOrigin: models.PurchaseOriginPanelPurchase,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %q: %v", orderID, err)
		}
	}

	h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	read := gigahostOrderStatusRead(t, h, "")

	for _, orderID := range []string{"ord_existence_pending", "intent_existence"} {
		if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
			t.Fatalf("%q was recorded absent before it ever deployed: %+v", orderID, stored)
		}
		if absenceMark(t, read.Orders, orderID) {
			t.Fatalf("%q produced an absence mark before it ever deployed", orderID)
		}
	}
}

// TestOrderAbsenceNeedsTheConfiguredReadToSucceedAlsoDurably pins the write boundary from
// the database side: a cleared observation removes the account stamp with it, so a row
// never carries an absence that belongs to a different answering account.
func TestOrderAbsenceObservationCarriesItsAccount(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_existence_stamp"
	seedExistenceOrder(t, h, orderID, 7108, models.PurchaseOriginPanelPurchase)

	ctx := context.Background()
	stamp := time.Date(2026, 11, 27, 13, 0, 0, 0, time.UTC)
	if err := h.db.SetGigahostOrderAbsence(ctx, orderID, stamp, existenceAccount); err != nil {
		t.Fatalf("record absence: %v", err)
	}
	if stored := storedOrder(t, h, orderID); stored.ProviderAbsentAt != stamp.Format(time.RFC3339) {
		t.Fatalf("the observation was not stored as its own instant: %q", stored.ProviderAbsentAt)
	}
	if err := h.db.SetGigahostOrderAbsence(ctx, orderID, time.Time{}, existenceAccount); err != nil {
		t.Fatalf("clear absence: %v", err)
	}
	stored := storedOrder(t, h, orderID)
	if stored.ProviderAbsent() || stored.ProviderAbsentAccountID != "" {
		t.Fatalf("clearing must remove the stamp and its account together: %+v", stored)
	}
	if strings.TrimSpace(stored.ProviderAccountID) != "" {
		t.Fatalf("clearing an observation must not invent an association: %q", stored.ProviderAccountID)
	}
}
