package database

// The surrender that closes a saved setup job when its order ends.
//
// The installer and the tracker both reach an order ledger they do not own, so the durable
// transition those findings need lives here, beside the table it writes. What these tests
// pin is that the surrender is the SAME decision a revocation makes - it uses the
// revocation's own expected-state list, so a completed install is preserved and a repeated
// call is idempotent - and that the in-flight journal writer asks it inside its own critical
// section, so a retirement is visible to the write it must refuse.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// seedEndedOrder records an order the panel's own records say has ended.
func seedEndedOrder(t *testing.T, db *DB, orderID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: orderID, Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	if err := db.SetGigahostOrderAbsence(ctx, orderID, now, "1111"); err != nil {
		t.Fatalf("record the absence: %v", err)
	}
}

// TestSurrenderClosesAnInFlightAttemptAtItsOwnWriter is the store-level half of the
// in-flight finding.
//
// The attempt holds a valid generation and a live installing row. Once the order ends, its
// own journal write - the authorization for every effect-bearing phase - must be refused,
// and the row must be closed rather than left installing. A journal write that a state
// change alone could refuse would not prove this: the generation still matches, so the only
// fence that can stop it is the order's own ending.
func TestSurrenderClosesAnInFlightAttemptAtItsOwnWriter(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name   string
		retire bool
	}{
		{name: "live-control", retire: false},
		{name: "ended-order", retire: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openSetupIntentTestDB(t)
			const orderID = "ord_surrender_inflight"
			seedEndedOrder(t, db, orderID)
			if !tc.retire {
				// The live control starts from the same row with the observation cleared,
				// so the only difference between the cases is whether the order has ended.
				if err := db.SetGigahostOrderAbsence(ctx, orderID, time.Time{}, ""); err != nil {
					t.Fatalf("clear the absence: %v", err)
				}
			}
			if retired, err := db.IsGigahostOrderRetired(ctx, orderID); err != nil || retired != tc.retire {
				t.Fatalf("fixture retirement = %v (err %v), want %v", retired, err, tc.retire)
			}

			intent := newPendingIntent(orderID)
			intent.State = models.SetupStateReadyForSetup
			if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
				t.Fatalf("seed approval: %v", err)
			}
			claimed, ok, err := db.ClaimGigahostSetupInstall(ctx, orderID)
			if err != nil || !ok {
				t.Fatalf("claim: ok=%v err=%v", ok, err)
			}

			// The first effect-bearing phase is authorized by this write.
			claimed.InstallPhase = models.SetupPhaseRegistered
			claimed.Step = "server_registration"
			changed, err := db.UpdateGigahostSetupInstall(ctx, claimed, claimed.InstallGeneration)
			if err != nil {
				t.Fatalf("journal write: %v", err)
			}

			stored, found, err := db.GetGigahostSetupIntent(ctx, orderID)
			if err != nil || !found {
				t.Fatalf("reload: found=%v err=%v", found, err)
			}
			if !tc.retire {
				// The control: a live order's attempt keeps writing and stays installing.
				if !changed {
					t.Fatal("a live order's attempt was refused its journal write")
				}
				if stored.State != models.SetupStateInstalling {
					t.Fatalf("state = %q, want %q", stored.State, models.SetupStateInstalling)
				}
				if stored.InstallPhase != models.SetupPhaseRegistered {
					t.Errorf("phase = %q, want %q", stored.InstallPhase, models.SetupPhaseRegistered)
				}
				return
			}

			// The ended order's write is refused, and the refusal is not an error: it is the
			// same "this attempt no longer owns the row" answer the runner already handles.
			if changed {
				t.Fatal("an ended order's attempt was allowed to journal a phase")
			}
			if stored.State != models.SetupStateCanceled {
				t.Fatalf("state = %q, want %q: the row must be closed, not left installing",
					stored.State, models.SetupStateCanceled)
			}
			if stored.Step != SetupStepOrderEnded {
				t.Errorf("step = %q, want %q so the surrender is diagnosable", stored.Step, SetupStepOrderEnded)
			}
			if stored.LastError == "" {
				t.Error("the closed row records no reason")
			}
			// The phase the attempt had proven before the ending is preserved: the rule is
			// "no further effect", not "rewrite the history".
			if stored.InstallPhaseDone != "" {
				t.Errorf("the surrender invented a proven phase: %q", stored.InstallPhaseDone)
			}
			if stored.InstallPhase != "" {
				t.Errorf("the surrender left a phase in flight: %q", stored.InstallPhase)
			}
			if !stored.NextAttemptAt.IsZero() {
				t.Errorf("the closed row kept a schedule: %v", stored.NextAttemptAt)
			}
		})
	}
}

// TestSurrenderIsIdempotentAndPreservesACompletedInstall pins the two states the surrender
// must not rewrite.
func TestSurrenderIsIdempotentAndPreservesACompletedInstall(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	// A completed install: the surrender reports the ending but leaves the row alone.
	const doneID = "ord_surrender_done"
	seedEndedOrder(t, db, doneID)
	done := newPendingIntent(doneID)
	done.State = models.SetupStateReady
	done.InstallPhaseDone = models.SetupPhaseEnabled
	done.NexusServerID = 42
	if err := db.CreateGigahostSetupIntent(ctx, done); err != nil {
		t.Fatalf("seed completed approval: %v", err)
	}
	ended, err := db.SurrenderGigahostSetupForEndedOrder(ctx, doneID)
	if err != nil || !ended {
		t.Fatalf("surrender a completed install: ended=%v err=%v", ended, err)
	}
	after, _, err := db.GetGigahostSetupIntent(ctx, doneID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.State != models.SetupStateReady || after.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Errorf("a completed install was rewritten: %+v", after)
	}

	// A pending job: the first call closes it, the second reports the same ending without a
	// second effect.
	const pendingID = "ord_surrender_twice"
	seedEndedOrder(t, db, pendingID)
	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent(pendingID)); err != nil {
		t.Fatalf("seed pending approval: %v", err)
	}
	first, err := db.SurrenderGigahostSetupForEndedOrder(ctx, pendingID)
	if err != nil || !first {
		t.Fatalf("first surrender: ended=%v err=%v", first, err)
	}
	closed, _, err := db.GetGigahostSetupIntent(ctx, pendingID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	second, err := db.SurrenderGigahostSetupForEndedOrder(ctx, pendingID)
	if err != nil || !second {
		t.Fatalf("repeated surrender: ended=%v err=%v", second, err)
	}
	again, _, err := db.GetGigahostSetupIntent(ctx, pendingID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	// A revocation that already closed the row is idempotent, so the repeat must not move the
	// row's own timestamps either.
	if !again.UpdatedAt.Equal(closed.UpdatedAt) {
		t.Errorf("the repeated surrender rewrote the row: %v -> %v", closed.UpdatedAt, again.UpdatedAt)
	}
}

// TestSurrenderAnswersNotEndedForAnOrderWithNoRecord is the negative control for the read.
//
// A deployment the ledger does not hold, and a live order, are both "not ended": absence of
// a record is not an observation, and a first-time deployment may legitimately have none.
func TestSurrenderAnswersNotEndedForAnOrderWithNoRecord(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	for _, orderID := range []string{"ord_surrender_unknown", "ord_surrender_live"} {
		ended, err := db.SurrenderGigahostSetupForEndedOrder(ctx, orderID)
		if err != nil {
			t.Fatalf("%s: surrender: %v", orderID, err)
		}
		if ended {
			t.Errorf("%s: an order with no recorded ending was reported as ended", orderID)
		}
	}

	// A live order with a valid approval is left untouched as well.
	const liveID = "ord_surrender_live_job"
	now := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: liveID, Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent(liveID)); err != nil {
		t.Fatalf("seed approval: %v", err)
	}
	ended, err := db.SurrenderGigahostSetupForEndedOrder(ctx, liveID)
	if err != nil {
		t.Fatalf("surrender: %v", err)
	}
	if ended {
		t.Fatal("a live order was reported as ended")
	}
	stored, _, err := db.GetGigahostSetupIntent(ctx, liveID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.State != models.SetupStatePending || stored.Step != "approved" {
		t.Errorf("a live order's approval was changed: %+v", stored)
	}
}

// TestUpdateInstallFailsClosedWhenTheOrderCannotBeRead proves the fence does not treat an
// unreadable ledger as consent. The write is refused and the error is reported, so a caller
// cannot mistake "could not ask" for "the order is live".
func TestUpdateInstallFailsClosedWhenTheOrderCannotBeRead(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	const orderID = "ord_surrender_unreadable"
	seedEndedOrder(t, db, orderID)

	intent := newPendingIntent(orderID)
	intent.State = models.SetupStateReadyForSetup
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("seed approval: %v", err)
	}
	claimed, ok, err := db.ClaimGigahostSetupInstall(ctx, orderID)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	// A cancelled context makes the ledger read fail rather than answer.
	deadCtx, cancel := context.WithCancel(ctx)
	cancel()
	claimed.InstallPhase = models.SetupPhaseRegistered
	changed, err := db.UpdateGigahostSetupInstall(deadCtx, claimed, claimed.InstallGeneration)
	if changed {
		t.Fatal("an unreadable ledger was treated as a live order")
	}
	if err == nil {
		t.Fatal("an unreadable ledger answered without an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to carry the cancelled context", err)
	}
	// The refused write did not land.
	stored, _, err := db.GetGigahostSetupIntent(ctx, orderID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.InstallPhase != "" {
		t.Errorf("a refused write still recorded a phase: %q", stored.InstallPhase)
	}
	if stored.State != models.SetupStateInstalling {
		t.Errorf("state = %q, want the claim's %q untouched", stored.State, models.SetupStateInstalling)
	}
}
