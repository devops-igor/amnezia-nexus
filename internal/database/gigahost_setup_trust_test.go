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

// TestTrustStorePolicyWriteRefusesAnUnsupportedPolicy proves durable authority cannot be
// invented: a value nothing enforces would read as permission in the database and be one
// in no code path.
func TestTrustStorePolicyWriteRefusesAnUnsupportedPolicy(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_policy", models.SetupTrustPolicyManual)

	for _, bad := range []string{"always_trust", "first-contact", "FIRST_CONTACT", "automation"} {
		if _, _, err := db.SetGigahostSetupHostTrustPolicy(ctx, "ord_policy", bad); err == nil {
			t.Fatalf("unsupported policy %q was accepted", bad)
		}
	}
	stored, found, err := db.GetGigahostSetupIntent(ctx, "ord_policy")
	if err != nil || !found {
		t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	if stored.HostTrustPolicy != models.SetupTrustPolicyManual {
		t.Fatalf("a refused policy write changed the row to %q", stored.HostTrustPolicy)
	}
}

// TestTrustStorePolicyWriteIsIdempotentAndThenRefusesOtherValues proves the two answers a
// policy write must give after the first one: the same value again is not a change, and a
// different value is refused because authority is granted once, before trust is decided.
func TestTrustStorePolicyWriteRefusesAfterTrustIsDecided(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_policy_once", models.SetupTrustPolicyManual)

	granted, changed, err := db.SetGigahostSetupHostTrustPolicy(
		ctx, "ord_policy_once", models.SetupTrustPolicyFirstContact)
	if err != nil || !changed {
		t.Fatalf("grant: changed=%v err=%v", changed, err)
	}
	if granted.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("granted policy = %q", granted.HostTrustPolicy)
	}

	// The same request twice is not a second change.
	if _, changed, err := db.SetGigahostSetupHostTrustPolicy(
		ctx, "ord_policy_once", models.SetupTrustPolicyFirstContact); err != nil || changed {
		t.Fatalf("repeat grant: changed=%v err=%v, want false/nil", changed, err)
	}

	// Once trust is decided, the authority behind it is history and cannot be edited.
	if _, changed, err := db.SetGigahostSetupHostTrustPolicy(
		ctx, "ord_policy_once", models.SetupTrustPolicyFirstContact); err != nil || changed {
		t.Fatalf("post-trust grant: changed=%v err=%v, want false/nil", changed, err)
	}
	if _, _, err := db.SetGigahostSetupHostTrustPolicy(ctx, "  ", models.SetupTrustPolicyFirstContact); err != nil {
		t.Fatalf("empty order id returned an error instead of a no-op: %v", err)
	}
}

// TestTrustStorePinOutcomeExplainsANonMatchingRow proves a pin that matched no row is
// explained by what is stored, including the case where the identity is present but the row
// left the pinnable state.
func TestTrustStorePinOutcomeExplainsANonMatchingRow(t *testing.T) {
	db := newTrustDB(t)
	ctx := context.Background()
	seedTrustIntent(t, db, "ord_outcome", models.SetupTrustPolicyFirstContact)

	// Pin once, so the identity exists under attended trust.
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

	// A row with a policy but no identity that has left the pinnable state is not
	// eligible, and the outcome must say that rather than inventing an identity change.
	seedTrustIntent(t, db, "ord_left", models.SetupTrustPolicyFirstContact)
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

// TestTrustStorePolicyWriteOnAnUnusableStoreIsANoOp proves the guard that a partially
// constructed store answers rather than panicking, which is what a caller has to be able to
// rely on when the panel starts before its database is ready.
func TestTrustStorePolicyWriteOnAnUnusableStoreIsANoOp(t *testing.T) {
	ctx := context.Background()

	var nilDB *DB
	if intent, changed, err := nilDB.SetGigahostSetupHostTrustPolicy(ctx, "ord_x", models.SetupTrustPolicyManual); err != nil || changed || intent != nil {
		t.Fatalf("nil store = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}
	closed := &DB{}
	if intent, changed, err := closed.SetGigahostSetupHostTrustPolicy(ctx, "ord_x", models.SetupTrustPolicyManual); err != nil || changed || intent != nil {
		t.Fatalf("store with no handle = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}

	// A policy write against an order that has no intent row is a no-op with no error:
	// "no such job" is an answer, not a fault.
	db := newTrustDB(t)
	if intent, changed, err := db.SetGigahostSetupHostTrustPolicy(
		ctx, "ord_no_such_job", models.SetupTrustPolicyFirstContact); err != nil || changed || intent != nil {
		t.Fatalf("missing order = (%v, %v, %v), want (nil, false, nil)", intent, changed, err)
	}
}

// TestTrustStorePinRejectsAForeignFingerprintShape proves the store validates the exact
// canonical shape it later compares by string equality.
func TestTrustStorePinRejectsAForeignFingerprintShape(t *testing.T) {
	db := newTrustDB(t)
	seedTrustIntent(t, db, "ord_shape", models.SetupTrustPolicyFirstContact)

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
