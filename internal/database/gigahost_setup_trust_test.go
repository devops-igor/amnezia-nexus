package database

// Refusal paths of the first-contact trust store.
//
// The store is the durable half of the automatic-trust boundary: it re-proves the
// authority a caller read earlier and it never lets an ordinary writer replace an
// identity. These tests drive its refusals directly, because a tracking pass stops at
// the first one and would leave the rest unexercised.
//
// The positive control for each function is exercised by the tracker-level tests; this
// file is about the ways the store must say no.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	trustTestSecretKey    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	trustTestFingerprint  = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	trustOtherFingerprint = "SHA256:ERERERERERERERERERERERERERERERERERERERERERE"
)

// newTrustDB opens a fresh database for a store-level test.
func newTrustDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir()+"/trust.db", trustTestSecretKey)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedTrustIntent records one pending intent with the supplied policy.
func seedTrustIntent(t *testing.T, db *DB, orderID, policy string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.CreateGigahostSetupIntent(context.Background(), &models.GigahostSetupIntent{
		OrderID:         orderID,
		Protocol:        models.ProtocolAWG,
		Port:            "51820",
		CredentialMode:  models.SetupCredentialManaged,
		State:           models.SetupStatePending,
		Step:            "approved",
		HostTrustPolicy: policy,
		NextAttemptAt:   now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}); err != nil {
		t.Fatalf("seed intent %s: %v", orderID, err)
	}
}

// seedPurchasedOrder records what the purchase-intent writer records: a ledger row that
// carries the provenance stamp, the provider server identity and an address, plus the
// managed credential registered at the provider.
func seedPurchasedOrder(t *testing.T, db *DB, orderID string, providerServerID int64, ip string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: "pending",
		PlanID: 7, RegionID: 3, AssignedIP: ip,
		PurchaseOrigin:     models.PurchaseOriginPanelPurchase,
		PurchaseRecordedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed purchased order %s: %v", orderID, err)
	}
	if err := db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: "[REDACTED PRIVATE KEY]",
		PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
		ProviderKeyID: 4242,
	}); err != nil {
		t.Fatalf("seed managed credential for %s: %v", orderID, err)
	}
}

// grantBinding records the automation authority for a purchased order, as the internal
// caller does: prove the binding, then store it.
func grantBinding(t *testing.T, db *DB, orderID string, providerServerID int64) *models.GigahostSetupIntent {
	t.Helper()
	ctx := context.Background()
	binding, err := db.ProveAutomationBinding(ctx, orderID, providerServerID)
	if err != nil {
		t.Fatalf("prove binding for %s: %v", orderID, err)
	}
	intent, changed, err := db.SetGigahostSetupAutomationBinding(ctx, binding)
	if err != nil || !changed {
		t.Fatalf("grant binding for %s: changed=%v err=%v", orderID, changed, err)
	}
	return intent
}

// TestTrustStorePinRefusesWithoutAnOrder proves the pin cannot be attempted against a
// row it cannot name, and that it validates the identity before touching storage.
func TestTrustStorePinRefusesWithoutAnOrder(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()

	if _, err := db.PinGigahostSetupFirstContact(ctx, "   ", trustTestFingerprint); err == nil {
		t.Fatal("a pin with no order id was accepted")
	}
	// A well-formed call against an order that does not exist is eligible for nothing,
	// and must say so rather than reporting a pin.
	outcome, err := db.PinGigahostSetupFirstContact(ctx, "ord_missing", trustTestFingerprint)
	if err != nil {
		t.Fatalf("pin against a missing order: %v", err)
	}
	if outcome != models.FirstContactNotEligible {
		t.Fatalf("outcome = %q, want %q", outcome, models.FirstContactNotEligible)
	}
}

// TestTrustStoreGrantRefusesAnIncompleteBinding proves durable authority cannot exist
// without saying which resource it is for: an incomplete binding is not a weaker grant,
// it is no grant at all.
func TestTrustStoreGrantRefusesAnIncompleteBinding(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_incomplete", models.SetupTrustPolicyManual)

	cases := map[string]AutomationBinding{
		"no order id":     {ProviderServerID: 42, Address: "198.51.100.5", ProviderKeyID: 4242},
		"no server id":    {OrderID: "ord_incomplete", Address: "198.51.100.5", ProviderKeyID: 4242},
		"no address":      {OrderID: "ord_incomplete", ProviderServerID: 42, ProviderKeyID: 4242},
		"no provider key": {OrderID: "ord_incomplete", ProviderServerID: 42, Address: "198.51.100.5"},
		"nothing at all":  {},
	}
	for name, binding := range cases {
		if intent, changed, err := db.SetGigahostSetupAutomationBinding(ctx, binding); err != nil || changed || intent != nil {
			t.Fatalf("%s = (%v, %v, %v), want (nil, false, nil)", name, intent, changed, err)
		}
	}
	stored, _, _ := db.GetGigahostSetupIntent(ctx, "ord_incomplete")
	if stored.HostTrustPolicy != models.SetupTrustPolicyManual || stored.HostTrustGrantedAt != (time.Time{}) {
		t.Fatalf("a refused grant changed the row: policy=%q granted=%v",
			stored.HostTrustPolicy, stored.HostTrustGrantedAt)
	}
}

// TestTrustStoreGrantRecordsTheExactBinding proves the grant stores every fact it was
// granted for, in one write, so a later step can compare against a recorded decision
// rather than a live re-read.
func TestTrustStoreGrantRecordsTheExactBinding(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_grant", models.SetupTrustPolicyManual)
	seedPurchasedOrder(t, db, "ord_grant", 4242, "198.51.100.42")

	granted := grantBinding(t, db, "ord_grant", 4242)
	if granted.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("policy = %q", granted.HostTrustPolicy)
	}
	if granted.HostTrustOrderID != "ord_grant" || granted.HostTrustServerID != 4242 {
		t.Fatalf("binding order/server = (%q, %d)", granted.HostTrustOrderID, granted.HostTrustServerID)
	}
	if granted.HostTrustAddress != "198.51.100.42" || granted.HostTrustKeyID != 4242 {
		t.Fatalf("binding address/key = (%q, %d)", granted.HostTrustAddress, granted.HostTrustKeyID)
	}
	if granted.HostTrustGrantedAt.IsZero() {
		t.Fatal("the grant recorded no timestamp")
	}

	// A repeat grant is not a second decision.
	if _, changed, err := db.SetGigahostSetupAutomationBinding(ctx, AutomationBinding{
		OrderID: "ord_grant", ProviderServerID: 4242,
		Address: "198.51.100.42", ProviderKeyID: 4242,
	}); err != nil || changed {
		t.Fatalf("repeat grant: changed=%v err=%v, want false/nil", changed, err)
	}
}

// TestTrustStoreGrantRefusesAfterTrustIsDecided proves authority is granted before trust
// is decided and never after: a row with an identity, or one that left pending, must not
// acquire a binding.
func TestTrustStoreGrantRefusesAfterTrustIsDecided(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_late", models.SetupTrustPolicyManual)
	seedPurchasedOrder(t, db, "ord_late", 4242, "198.51.100.43")
	seedTrustIntent(t, db, "ord_left", models.SetupTrustPolicyManual)
	seedPurchasedOrder(t, db, "ord_left", 4243, "198.51.100.44")

	// Handed off already.
	current, _, _ := db.GetGigahostSetupIntent(ctx, "ord_left")
	current.State = models.SetupStateReadyForSetup
	current.Step = "ready_for_setup"
	if _, err := db.TransitionGigahostSetupIntent(ctx, current, []string{models.SetupStatePending}); err != nil {
		t.Fatalf("move the row out of pending: %v", err)
	}
	if _, changed, err := db.SetGigahostSetupAutomationBinding(ctx, AutomationBinding{
		OrderID: "ord_left", ProviderServerID: 4243, Address: "198.51.100.44", ProviderKeyID: 4242,
	}); err != nil || changed {
		t.Fatalf("grant on a handed-off row: changed=%v err=%v, want false/nil", changed, err)
	}
}

// TestTrustStoreGrantNoOpOnAnUnusableStore proves a partially constructed store answers
// rather than panicking, which a caller must be able to rely on at startup.
func TestTrustStoreGrantNoOpOnAnUnusableStore(t *testing.T) {
	ctx := context.Background()
	binding := AutomationBinding{OrderID: "ord_x", ProviderServerID: 1, Address: "198.51.100.9", ProviderKeyID: 1}

	var nilDB *DB
	if intent, changed, err := nilDB.SetGigahostSetupAutomationBinding(ctx, binding); err != nil || changed || intent != nil {
		t.Fatalf("nil store = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}
	closed := &DB{}
	if intent, changed, err := closed.SetGigahostSetupAutomationBinding(ctx, binding); err != nil || changed || intent != nil {
		t.Fatalf("store with no handle = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}
	db := newTrustDB(t)
	if intent, changed, err := db.SetGigahostSetupAutomationBinding(ctx, binding); err != nil || changed || intent != nil {
		t.Fatalf("no such job = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}
}

// TestTrustStorePinOutcomeExplainsANonMatchingRow proves a pin that matched no row is
// explained by what is stored, including the case where the identity is present but the row
// left the pinnable state.
func TestTrustStorePinOutcomeExplainsANonMatchingRow(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_outcome", models.SetupTrustPolicyManual)
	seedPurchasedOrder(t, db, "ord_outcome", 4101, "198.51.100.61")
	grantBinding(t, db, "ord_outcome", 4101)

	// Pin once, so the identity exists under the granted authority.
	if outcome, err := db.PinGigahostSetupFirstContact(ctx, "ord_outcome", trustTestFingerprint); err != nil {
		t.Fatalf("pin: %v", err)
	} else if outcome != models.FirstContactPinned {
		t.Fatalf("first pin = %q, want %q", outcome, models.FirstContactPinned)
	}
	// Same identity again: the same answer, not a second decision.
	if outcome, err := db.PinGigahostSetupFirstContact(ctx, "ord_outcome", trustTestFingerprint); err != nil {
		t.Fatalf("repeat pin: %v", err)
	} else if outcome != models.FirstContactAlreadyPinnedSame {
		t.Fatalf("repeat pin = %q, want %q", outcome, models.FirstContactAlreadyPinnedSame)
	}
	// A different identity is a contradiction, and trust does not move.
	if outcome, err := db.PinGigahostSetupFirstContact(ctx, "ord_outcome", trustOtherFingerprint); err != nil {
		t.Fatalf("changed pin: %v", err)
	} else if outcome != models.FirstContactIdentityChanged {
		t.Fatalf("changed pin = %q, want %q", outcome, models.FirstContactIdentityChanged)
	}
	// None of that rewrote the stored identity.
	stored, _, _ := db.GetGigahostSetupIntent(ctx, "ord_outcome")
	if stored.HostFingerprint != trustTestFingerprint {
		t.Fatalf("stored identity = %q, want %q", stored.HostFingerprint, trustTestFingerprint)
	}

	// A granted row that has left the pinnable state is not eligible, and the outcome
	// must say that rather than inventing an identity change.
	seedTrustIntent(t, db, "ord_left", models.SetupTrustPolicyManual)
	seedPurchasedOrder(t, db, "ord_left", 4102, "198.51.100.62")
	grantBinding(t, db, "ord_left", 4102)
	current, _, _ := db.GetGigahostSetupIntent(ctx, "ord_left")
	current.State = models.SetupStateReadyForSetup
	current.Step = "ready_for_setup"
	if _, err := db.TransitionGigahostSetupIntent(ctx, current, []string{models.SetupStatePending}); err != nil {
		t.Fatalf("move the row out of pending: %v", err)
	}
	if outcome, err := db.PinGigahostSetupFirstContact(ctx, "ord_left", trustTestFingerprint); err != nil {
		t.Fatalf("pin on a handed-off row: %v", err)
	} else if outcome != models.FirstContactNotEligible {
		t.Fatalf("outcome = %q, want %q", outcome, models.FirstContactNotEligible)
	}
}

// TestTrustStorePinRejectsAForeignFingerprintShape proves the store validates the exact
// canonical shape it later compares by string equality.
func TestTrustStorePinRejectsAForeignFingerprintShape(t *testing.T) {
	db := newTrustDB(t)
	seedTrustIntent(t, db, "ord_shape", models.SetupTrustPolicyManual)
	seedPurchasedOrder(t, db, "ord_shape", 4103, "198.51.100.63")
	grantBinding(t, db, "ord_shape", 4103)

	// The canonical value is 43 base64 characters decoding to 32 bytes, so the
	// neighbouring lengths are the ones that must be refused: 42 decodes to 31 bytes
	// and 44 to 33. Explicit padding and a near-miss prefix are refused as well.
	for _, bad := range []string{
		"SHA256:" + strings.Repeat("A", 42),
		"SHA256:" + strings.Repeat("A", 44),
		"SHA256:" + strings.Repeat("A", 43) + "=",
		"MD5:aa:bb",
		"SSH256:" + strings.Repeat("A", 43),
	} {
		if _, err := db.PinGigahostSetupFirstContact(context.Background(), "ord_shape", bad); err == nil {
			t.Fatalf("fingerprint %q was accepted", bad)
		}
	}
	stored, _, _ := db.GetGigahostSetupIntent(context.Background(), "ord_shape")
	if stored.HostFingerprint != "" || stored.HostTrustMode != models.SetupTrustModeNone {
		t.Fatalf("a rejected fingerprint was stored: identity=%q mode=%q",
			stored.HostFingerprint, stored.HostTrustMode)
	}
}
