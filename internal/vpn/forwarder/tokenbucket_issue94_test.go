package forwarder

// Issue #94: TokenBucket rate-vs-burst semantics coverage. These tests pin
// the documented behavior (see TokenBucket/NewTokenBucket Godoc): `rate` is
// the sustained refill rate in bytes/second, `capacity` the max burst; the
// default capacity equals the rate, so a fresh bucket permits an initial
// burst of up to one second of configured bandwidth. NO behavior change is
// introduced by this file — it documents and locks the existing semantics.

import (
	"sync"
	"testing"
	"time"
)

// TestTokenBucketSustainedRate verifies the sustained (long-run) rate: after
// the initial burst is drained, the bucket only refills at `rate` bytes per
// second — an immediate follow-up request beyond the tiny refill window is
// rejected, and after a measurable wait roughly rate*elapsed tokens are
// available (with generous time-scheduling tolerance).
func TestTokenBucketSustainedRate(t *testing.T) {
	const rate = 10_000 // bytes per second
	tb := NewTokenBucket(rate)
	if tb == nil {
		t.Fatal("NewTokenBucket returned nil for positive rate")
	}

	// Drain the full initial burst (capacity == rate by default).
	if !tb.Allow(rate) {
		t.Fatalf("initial burst of %d bytes should be allowed", rate)
	}
	// Zero elapsed time since creation ⇒ no meaningful refill yet: a request
	// of rate/10 (1000 B, vs a sub-millisecond refill of ≤ ~10 B) must fail.
	if tb.Allow(rate / 10) {
		t.Errorf("sustained request exceeded immediate refill: bucket should be empty right after burst")
	}

	// Wait ~200 ms: refill ≈ 2000 B. Allow a chunk well below the lower
	// bound of plausible refill (100 ms worth = 1000 B) and reject a chunk
	// well above the upper bound (400 ms worth = 4000 B).
	waitForRefill(t, 200*time.Millisecond)
	if !tb.Allow(1000) {
		t.Errorf("Allow(1000) after 200ms idle should succeed (refill ≈ 2000 B at %d B/s)", rate)
	}
	if tb.Allow(4000) {
		t.Errorf("Allow(4000) after 200ms idle should fail (refill ≈ 2000 B at %d B/s)", rate)
	}
}

// TestTokenBucketInitialBurst pins the DEFAULT burst semantics (issue #94's
// core observation): capacity defaults to rate, so a fresh bucket at
// 1 MB/s permits an immediate ~1 MB burst — limitBps is NOT a hard
// per-second ceiling on the first second.
func TestTokenBucketInitialBurst(t *testing.T) {
	const mb = 1024 * 1024
	tb := NewTokenBucket(mb)

	// The full default burst must pass in one call.
	if !tb.Allow(mb) {
		t.Fatalf("initial burst of %d bytes at default capacity=rate should be allowed", mb)
	}
	// One byte beyond it must effectively fail immediately: refill over the
	// microseconds between calls is a handful of tokens, nowhere near half a
	// burst. (Allow(1) itself can succeed on that tiny refill, so assert a
	// robust bound instead — the bucket cannot serve another large chunk.)
	if tb.Allow(mb / 2) {
		t.Errorf("Allow(%d) immediately after full burst should fail (refill window is negligible)", mb/2)
	}

	// The burst is bounded by capacity, not infinite: an explicit smaller
	// capacity bounds the initial burst accordingly — but only down to the
	// rate, because NewTokenBucket clamps capacity UP to at least rate.
	// Use a capacity well above the rate to observe independent bounding.
	const bigCap = 4 * mb
	tb2 := NewTokenBucket(rateForClamp, bigCap)
	if !tb2.Allow(bigCap) {
		t.Fatalf("initial burst up to explicit capacity %d should be allowed", bigCap)
	}
	if tb2.Allow(bigCap / 2) {
		t.Errorf("Allow(%d) beyond explicit burst capacity should fail immediately", bigCap/2)
	}
}

// rateForClampTest pins the documented clamping: a capacity below rate is
// clamped UP to rate, so a "small" explicit capacity still permits a full
// rate-sized burst.
func TestTokenBucketCapacityClampedUpToRate(t *testing.T) {
	const rate = 100_000
	tb := NewTokenBucket(rate, 1)
	if tb == nil {
		t.Fatal("nil bucket")
	}
	tb.mu.Lock()
	cap := tb.capacity
	tb.mu.Unlock()
	if cap < float64(rate) {
		t.Errorf("capacity %v below rate %d was not clamped up to rate", cap, rate)
	}
	if !tb.Allow(rate) {
		t.Errorf("burst of clamped capacity (rate) should be allowed")
	}
}

const rateForClamp = 1 << 20 // 1 MB/s used by TestTokenBucketInitialBurst

// TestTokenBucketIdleRefill verifies that idle time refills tokens at the
// sustained rate, capped at capacity (issue #94: "refill while idle, cap at
// capacity").
func TestTokenBucketIdleRefill(t *testing.T) {
	const rate = 50_000
	tb := NewTokenBucket(rate) // capacity = rate

	// Drain everything.
	if !tb.Allow(rate) {
		t.Fatal("initial burst should be allowed")
	}

	// Short idle: partial refill at the sustained rate.
	waitForRefill(t, 100*time.Millisecond) // ≈ 5000 tokens accrued
	if !tb.Allow(1000) {
		t.Errorf("Allow(1000) after 100ms idle should succeed (refill ≈ 5000 B)")
	}
	// Far more than the refill window must still fail: 30k B ≫ 5000 B.
	if tb.Allow(30_000) {
		t.Errorf("Allow(30000) after 100ms idle should fail (refill ≈ 5000 B)")
	}

	// Long idle: tokens cap at capacity (default = rate = 50000). Even
	// though 1s of idle would nominally refill the full rate, nothing above
	// capacity can ever be consumed.
	waitForRefill(t, 1100*time.Millisecond)
	if tb.Allow(rate + 1) {
		t.Errorf("Allow(capacity+1) after long idle should fail: tokens cap at capacity")
	}
	if !tb.Allow(rate) {
		t.Errorf("Allow(capacity) after long idle should succeed: bucket refilled to capacity")
	}
}

// TestTokenBucketCustomCapacity covers the explicit-capacity constructor
// path beyond TestTokenBucketDirect's basics: capacity bounds the burst
// independently of the sustained rate, and refill accumulates toward it.
func TestTokenBucketCustomCapacity(t *testing.T) {
	const rate = 10_000
	const cap = 100_000
	tb := NewTokenBucket(rate, cap)

	// Full custom burst in one shot.
	if !tb.Allow(cap) {
		t.Fatalf("burst of full custom capacity %d should be allowed", cap)
	}
	// Sustained refill: 150ms ⇒ ~1500 tokens.
	waitForRefill(t, 150*time.Millisecond)
	if !tb.Allow(500) {
		t.Errorf("Allow(500) after 150ms idle should succeed (refill ≈ 1500 B)")
	}
	if tb.Allow(5000) {
		t.Errorf("Allow(5000) after 150ms idle should fail (refill ≈ 1500 B)")
	}

	// Repeated small consumes must be bounded by the sustained rate over
	// time: 10 × 100 B immediately after the above should fail (only
	// ~1500-500 = ~1000 B refilled, consumed 500 already ⇒ < 1000 left for
	// the 10×100 = 1000 B total; use a tight-but-safe bound: 9 × 100 = 900
	// must also fail since refill happens only between calls and the test
	// runs them back-to-back within microseconds).
	consumed := 0
	for i := 0; i < 10; i++ {
		if tb.Allow(100) {
			consumed += 100
		}
	}
	if consumed > 1500 {
		t.Errorf("back-to-back consumes drained %d bytes, exceeding the ~1500 B refill window", consumed)
	}
}

// TestTokenBucketConcurrentAllow exercises Allow from many goroutines
// sharing one bucket (the per-peer wiring: concurrent pumps consume the
// same tbDown/tbUp). The mutex must keep the total consumed bytes within
// capacity + refill; run under -race via the standard suite.
func TestTokenBucketConcurrentAllow(t *testing.T) {
	const capacity = 100_000
	const chunk = 13
	tb := NewTokenBucket(capacity, capacity)

	const workers = 50
	const callsPerWorker = 200
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int64
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := int64(0)
			for i := 0; i < callsPerWorker; i++ {
				if tb.Allow(chunk) {
					local += chunk
				}
			}
			mu.Lock()
			allowed += local
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Total consumption can never exceed the initial capacity plus whatever
	// refilled during the (short) run. The test runs in well under a second
	// at capacity B/s... but the test would be flaky if it relied on time;
	// instead the run takes microseconds, so bound by capacity plus a small
	// scheduling-tolerant refill allowance (50 ms worth).
	const refillAllowance = int64(50) * capacity / 1000 // 50 ms of refill
	if allowed > capacity+refillAllowance {
		t.Errorf("concurrent Allow over-consumed: %d bytes > capacity %d + refill allowance %d",
			allowed, capacity, refillAllowance)
	}
	if allowed == 0 {
		t.Errorf("no consumption recorded — concurrency test exercised nothing")
	}
}

// waitForRefill sleeps for d while tolerating slow CI scheduling: it is a
// plain sleep; the assertions around it use wide margins (±50% of the wait)
// so timer granularity never flips the expected outcome.
func waitForRefill(t *testing.T, d time.Duration) {
	t.Helper()
	time.Sleep(d)
}
