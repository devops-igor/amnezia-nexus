package database

import (
	"context"
	"testing"
)

// funcBackedRecorder is a PeerRevokeRecorder whose DYNAMIC TYPE IS A FUNC.
// It is a perfectly valid recorder — the interface contract only requires a
// method — and comparing two of these interface values panics at runtime with
// "comparing uncomparable type". It is the shape production and test code
// actually uses to adapt a plain function to the recorder interface.
type funcBackedRecorder func(ctx context.Context, event PeerRevokeEvent)

func (f funcBackedRecorder) RecordPeerRevoke(ctx context.Context, event PeerRevokeEvent) {
	f(ctx, event)
}

// sliceHoldingRecorder is the other uncomparable shape: a struct that carries
// a slice (or map, or func) field. The interface comparison panics for the
// same reason as for funcBackedRecorder.
type sliceHoldingRecorder struct {
	seen []PeerRevokeEvent
	tag  string
}

func (r *sliceHoldingRecorder) RecordPeerRevoke(_ context.Context, event PeerRevokeEvent) {
	r.seen = append(r.seen, event)
}

// TestSubscribePeerRevokesUnsubscribeUncomparableRecorder pins the detach
// path against uncomparable recorder types (issue #391 round 4b, finding 2).
//
// The detach closure used to decide whether it was detaching ITS OWN
// subscription by comparing two interface values. For any recorder whose
// dynamic type is uncomparable — a func adapter, or a struct holding a slice,
// map or func — that comparison PANICS. A production service (or a test
// dispatcher) that subscribes such a recorder therefore crashed on unsubscribe.
// Subscription identity must be a monotonic token, not the recorder value.
func TestSubscribePeerRevokesUnsubscribeUncomparableRecorder(t *testing.T) {
	t.Run("func-backed recorder", func(t *testing.T) {
		db, _ := setupTestDB(t)
		unsubscribe := db.SubscribePeerRevokes(funcBackedRecorder(func(context.Context, PeerRevokeEvent) {}))
		// Must not panic: this is the assertion. A panic here fails the test
		// with "comparing uncomparable type ...funcBackedRecorder".
		unsubscribe()
	})

	t.Run("struct recorder holding a slice", func(t *testing.T) {
		db, _ := setupTestDB(t)
		unsubscribe := db.SubscribePeerRevokes(&sliceHoldingRecorder{tag: "slicer"})
		unsubscribe()
	})

	t.Run("unsubscribe is idempotent", func(t *testing.T) {
		db, _ := setupTestDB(t)
		unsubscribe := db.SubscribePeerRevokes(funcBackedRecorder(func(context.Context, PeerRevokeEvent) {}))
		unsubscribe()
		unsubscribe()
	})

	t.Run("nil database stays a no-op", func(t *testing.T) {
		var db *DB
		unsubscribe := db.SubscribePeerRevokes(funcBackedRecorder(func(context.Context, PeerRevokeEvent) {}))
		unsubscribe()
	})
}

// TestSubscribePeerRevokesDetachSemantics pins the documented "detach only if
// this subscription is still current" contract, which the token-based
// implementation must preserve exactly:
//
//   - a current detach removes the recorder;
//   - a STALE detach (its subscription already superseded) leaves the newer
//     recorder installed — it must not steal the slot;
//   - the last recorder installed is the one that receives events.
func TestSubscribePeerRevokesDetachSemantics(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	var stale, current int
	detachStale := db.SubscribePeerRevokes(funcBackedRecorder(func(context.Context, PeerRevokeEvent) {
		stale++
	}))
	detachCurrent := db.SubscribePeerRevokes(funcBackedRecorder(func(context.Context, PeerRevokeEvent) {
		current++
	}))

	// The stale detach must not remove the recorder installed after it.
	detachStale()
	db.recordPeerRevoke(ctx, PeerRevokeEvent{Kind: PeerRevokeUser, UserID: "user-1"})
	if stale != 0 || current != 1 {
		t.Fatalf("after a stale detach: stale recorder calls = %d, current recorder calls = %d, want 0 and 1", stale, current)
	}

	// The current detach does remove it.
	detachCurrent()
	db.recordPeerRevoke(ctx, PeerRevokeEvent{Kind: PeerRevokeUser, UserID: "user-2"})
	if current != 1 {
		t.Fatalf("current recorder received %d events, want 1 (detached recorder must be silent)", current)
	}
}
