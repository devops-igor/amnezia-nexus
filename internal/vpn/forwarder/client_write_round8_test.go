package forwarder

import (
	"testing"
	"time"
)

// Issue #424 round 8, finding 4: the latency reservoir stored bare durations
// with no timestamps, so a burst of slow writes kept p95 above the threshold
// until 1024 NEW writes displaced them. On a low-volume or idle server that is
// arbitrarily long, and the health evaluator turned P95MS >= 100 straight into
// DEGRADED.
func TestLatencyReservoir_HealthP95AgesOutWhileDescriptiveP95KeepsHistory(t *testing.T) {
	var r latencyReservoir
	now := time.Now()

	// 20 slow writes, all completed now.
	for i := 0; i < 20; i++ {
		r.recordAt(200*time.Millisecond, now)
	}

	// Fresh: every sample is inside the window, so health sees the slowness.
	p95, n := r.healthP95(now)
	if n != 20 {
		t.Fatalf("expected 20 fresh samples, got %d", n)
	}
	if p95 < 100*time.Millisecond {
		t.Fatalf("fresh slow writes must be visible to health, got p95=%v", p95)
	}

	// Descriptive telemetry keeps the history regardless of age.
	_, descP95, _ := r.percentiles()
	if descP95 < 100*time.Millisecond {
		t.Fatalf("descriptive p95 must still report the historical value, got %v", descP95)
	}

	// The samples age out of the health window. Nothing was written since, so
	// health must report UNKNOWN (zero samples), not BAD.
	aged := now.Add(latencyHealthWindow + time.Second)
	p95, n = r.healthP95(aged)
	if n != 0 {
		t.Fatalf("expected zero fresh samples once the burst aged out, got %d", n)
	}
	if p95 != 0 {
		t.Fatalf("an empty health window must report zero p95, got %v", p95)
	}

	// Descriptive p95 is untouched by age: operators still see the history.
	_, descP95, _ = r.percentiles()
	if descP95 < 100*time.Millisecond {
		t.Fatalf("descriptive p95 must survive ageing, got %v", descP95)
	}
}

// Only the stale samples age out: a server that recovered and is writing fast
// again must recover on the health view while the reservoir still holds history.
func TestLatencyReservoir_RecentFastWritesRecoverHealthDespiteHistory(t *testing.T) {
	var r latencyReservoir
	now := time.Now()

	// 20 slow writes just outside the window.
	for i := 0; i < 20; i++ {
		r.recordAt(300*time.Millisecond, now.Add(-2*latencyHealthWindow))
	}
	// 20 fast writes inside the window.
	for i := 0; i < 20; i++ {
		r.recordAt(2*time.Millisecond, now)
	}

	p95, n := r.healthP95(now)
	if n != 20 {
		t.Fatalf("expected only the 20 fresh samples in the health window, got %d", n)
	}
	if p95 >= 100*time.Millisecond {
		t.Fatalf("health must recover on recent fast writes, got p95=%v", p95)
	}

	// The descriptive percentiles still describe the whole reservoir, which is
	// what an operator expects from a no-expiry reservoir.
	_, descP95, _ := r.percentiles()
	if descP95 < 100*time.Millisecond {
		t.Fatalf("descriptive p95 should still reflect the historical burst, got %v", descP95)
	}
}

func TestLatencyReservoir_EmptyReservoirReportsUnknown(t *testing.T) {
	var r latencyReservoir
	p95, n := r.healthP95(time.Now())
	if n != 0 || p95 != 0 {
		t.Fatalf("an empty reservoir must report zero samples and zero p95, got n=%d p95=%v", n, p95)
	}
}

func TestLatencyReservoir_RecordStampsWithCurrentTime(t *testing.T) {
	var r latencyReservoir
	before := time.Now()
	r.record(5 * time.Millisecond)
	after := time.Now()

	stamp := r.stamps[0]
	if stamp.Before(before) || stamp.After(after) {
		t.Fatalf("record() must stamp the sample with the current time, got %v (want between %v and %v)",
			stamp, before, after)
	}
}
