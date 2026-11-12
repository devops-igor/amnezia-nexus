package tunnel

// Lock-order contract for the enrollment release path (issue #794 group B).
//
// The package's documented order is hp.mu -> pool.mu: acceptCanaryObservation and
// canaryObservationCurrent hold hp.mu and then take pool.mu.RLock. The removal
// path runs in the opposite direction, so it must not invoke the runtime-owner
// release while holding pool.mu, or a prober holding hp.mu and waiting for
// pool.mu would deadlock against it.
//
// These tests assert the property directly rather than relying on a timing race.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestEnrollmentReleaseRunsWithoutPoolLock asserts the release callback is invoked
// with pool.mu NOT held. TryLock is the honest probe: if it succeeds, nobody held
// the mutex at that instant, and the lock is handed straight back.
func TestEnrollmentReleaseRunsWithoutPoolLock(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)
	f.markEnrolled(t)

	var poolLockHeldDuringRelease atomic.Bool
	var called atomic.Bool
	f.pool.SetEnrollmentReleaseHook(func(_ context.Context, serverID int64) {
		called.Store(true)
		if !f.pool.mu.TryLock() {
			poolLockHeldDuringRelease.Store(true)
			return
		}
		f.pool.mu.Unlock()
		// The runtime owner must actually be released by this path.
		f.prober.releaseRuntimeEnrollment(serverID)
	})

	if err := f.pool.RemoveTunnel(context.Background(), f.server); err != nil {
		t.Fatalf("remove tunnel: %v", err)
	}
	if !called.Load() {
		t.Fatal("the runtime-owner release callback was never invoked")
	}
	if poolLockHeldDuringRelease.Load() {
		t.Fatal("the runtime-owner release ran while pool.mu was held: lock-order inversion against the documented hp.mu -> pool.mu order")
	}
}

// TestConcurrentRemovalAndMarkingIsRaceFree exercises concurrent delete and
// enrollment marking, which is the interleaving that can let a release and a mark
// race on the same server, and asserts the
// owners cannot end up disagreeing about a backend that still exists.
func TestConcurrentRemovalAndMarkingIsRaceFree(t *testing.T) {
	f := newEnrollmentLifecycleFixture(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = f.pool.RemoveTunnel(context.Background(), f.server)
		}()
		go func() {
			defer wg.Done()
			f.prober.SetPendingEnrollment(f.server, true)
		}()
	}
	wg.Wait()

	cur, err := f.pool.GetTunnel(f.server)
	if err == nil && cur != nil {
		runtime := f.prober.IsPendingEnrollment(f.server)
		durable := f.durablePending(t)
		if runtime != durable {
			t.Fatalf("owners diverged after concurrent removal/marking: runtime=%v durable=%v", runtime, durable)
		}
	}
	_ = models.TunnelStatusConnecting
}
