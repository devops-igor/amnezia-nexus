package gigahostsetup

// Coverage for the tracker's smaller decisions and its provider-narrowing wrapper.
//
// These are separated from tracker_test.go because they test the pieces the
// scheduling tests only pass through: identity merging, provider vocabulary,
// server-id matching, the non-blocking nudge, and the store-side failure paths.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestMergedIdentityKeepsStrongestKnownValue proves a later provider read that
// omits a field cannot erase what an earlier answer established.
func TestMergedIdentityKeepsStrongestKnownValue(t *testing.T) {
	cases := []struct {
		name       string
		status     *gigahost.DeployStatusResponse
		ip         string
		serverID   int64
		wantIP     string
		wantServer int64
	}{
		{"nil status changes nothing", nil, "198.51.100.1", 7, "198.51.100.1", 7},
		{"status fills an empty ip and id", &gigahost.DeployStatusResponse{
			AssignedIP: "198.51.100.2", ServerID: 8}, "", 0, "198.51.100.2", 8},
		{"status does not erase a known id", &gigahost.DeployStatusResponse{
			AssignedIP: "198.51.100.3"}, "198.51.100.1", 7, "198.51.100.3", 7},
		{"empty status fields keep prior values", &gigahost.DeployStatusResponse{},
			"198.51.100.1", 7, "198.51.100.1", 7},
	}
	for _, tc := range cases {
		ip, serverID := mergedIdentity(tc.status, tc.ip, tc.serverID)
		if ip != tc.wantIP || serverID != tc.wantServer {
			t.Fatalf("%s: got (%q, %d), want (%q, %d)", tc.name, ip, serverID, tc.wantIP, tc.wantServer)
		}
	}
}

// TestProviderVocabularyClassification pins the tracker's reading of provider
// status words, including the spellings the API mixes.
func TestProviderVocabularyClassification(t *testing.T) {
	for _, s := range []string{"ready", "READY", " active ", "Active"} {
		if !isProviderReady(s) {
			t.Fatalf("%q should read as ready", s)
		}
	}
	for _, s := range []string{"pending", "deploying", "waiting", "installing", "", "unknown"} {
		if isProviderReady(s) {
			t.Fatalf("%q should not read as ready", s)
		}
	}
	for _, s := range []string{"failed", "FAILED", "error", "cancelled", "canceled", "deleted"} {
		if !isProviderFailed(s) {
			t.Fatalf("%q should read as failed", s)
		}
	}
	for _, s := range []string{"ready", "pending", "deploying", ""} {
		if isProviderFailed(s) {
			t.Fatalf("%q should not read as failed", s)
		}
	}
}

// TestMatchesProviderServerIDAcceptsStoredNumericShapes proves the comparison
// survives the several numeric shapes a protocols map can hold after a JSON
// round trip, and rejects everything else.
func TestMatchesProviderServerIDAcceptsStoredNumericShapes(t *testing.T) {
	for _, stored := range []any{int64(42), 42, float64(42), "42", " 42 "} {
		if !matchesProviderServerID(stored, 42) {
			t.Fatalf("%T(%v) should match 42", stored, stored)
		}
	}
	for _, stored := range []any{int64(43), 43, float64(43), "43", "forty-two", "", nil, true, []int{42}} {
		if matchesProviderServerID(stored, 42) {
			t.Fatalf("%T(%v) should not match 42", stored, stored)
		}
	}
}

// TestProviderFailureDetailAndReadFailureSummary proves provider text is passed
// through as provider text, while a local read failure is labelled as ours.
func TestProviderFailureDetailAndReadFailureSummary(t *testing.T) {
	if got := providerFailureDetail(nil); got != "" {
		t.Fatalf("nil status detail = %q, want empty", got)
	}
	if got := providerFailureDetail(&gigahost.DeployStatusResponse{Error: " no capacity "}); got != "no capacity" {
		t.Fatalf("detail = %q", got)
	}
	if got := summarizeReadFailure(nil); got != "" {
		t.Fatalf("nil error summary = %q, want empty", got)
	}
	summary := summarizeReadFailure(errors.New("dial  tcp:\nconnection refused"))
	if summary != "could not read provider status: dial tcp: connection refused" {
		t.Fatalf("summary = %q", summary)
	}
	// A very long message is bounded rather than stored whole.
	long := summarizeReadFailure(errors.New(string(make([]byte, 0)) + repeat("x", 500)))
	if len(long) > 280 || long[len(long)-3:] != "..." {
		t.Fatalf("long summary not bounded: len=%d", len(long))
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// TestNudgeIsNonBlockingAndIdempotent proves the approval hint cannot stall a
// request: a second nudge with one already pending is dropped, not queued.
func TestNudgeIsNonBlockingAndIdempotent(t *testing.T) {
	tracker := New(nil, Options{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			tracker.Nudge()
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Nudge blocked")
	}
	// Exactly one hint is buffered; the rest were dropped as duplicates.
	if len(tracker.nudgeCh) != 1 {
		t.Fatalf("buffered nudges = %d, want 1", len(tracker.nudgeCh))
	}
}

// TestBackoffGrowsAndIsCapped proves a persistent outage is retried with growing
// delays that never exceed the configured maximum.
func TestBackoffGrowsAndIsCapped(t *testing.T) {
	tracker := New(nil, Options{
		FailureBack: time.Minute,
		MaxBackoff:  10 * time.Minute,
	})
	want := []time.Duration{
		1 * time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		10 * time.Minute, 10 * time.Minute, 10 * time.Minute,
	}
	for i, expected := range want {
		if got := tracker.backoffFor(i + 1); got != expected {
			t.Fatalf("backoff for %d failures = %v, want %v", i+1, got, expected)
		}
	}
}

// TestNewAppliesDefaultsAndRejectsDoubleStart proves the constructor's defaults
// and that a second Start on a running tracker is refused rather than spawning a
// second loop over the same rows.
func TestNewAppliesDefaultsAndRejectsDoubleStart(t *testing.T) {
	tracker := New(nil, Options{})
	if tracker.interval != DefaultInterval || tracker.failureBack != DefaultFailureBackoff ||
		tracker.maxBackoff != DefaultMaxBackoff || tracker.batch != DefaultBatch {
		t.Fatalf("defaults not applied: %+v", tracker)
	}
	if tracker.Name() != "gigahost-setup-tracker" {
		t.Fatalf("Name() = %q", tracker.Name())
	}

	// A second Start while one is running is refused rather than spawning a
	// second loop over the same rows.
	h := newHarness(t)
	running := h.tracker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = running.Start(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !running.running.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	if !running.running.Load() {
		t.Fatal("tracker did not start")
	}
	if err := running.Start(ctx); err == nil {
		t.Fatal("second Start on a running tracker returned nil")
	}

	// A store-less tracker reports the misconfiguration on every pass, so it does
	// not silently idle. The pass is bounded by the caller's context, which is
	// what the loop supplies in production.
	if err := tracker.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce with no store returned nil")
	}
}

// TestRegisteredServerIDFindsOnlyThisProvider proves the lookup ignores other
// providers and other ids, which is what stops a Gigahost order adopting an
// unrelated server.
func TestRegisteredServerIDFindsOnlyThisProvider(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A different provider with the same numeric id must not match.
	if _, err := h.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "other", Host: "203.0.113.1", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "other", "provider_server_id": 42},
		CreatedAt: h.clock.Now(),
	}, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatalf("seed other provider: %v", err)
	}
	// A Gigahost server with a different id must not match either.
	if _, err := h.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "gh-other", Host: "203.0.113.2", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 43},
		CreatedAt: h.clock.Now(),
	}, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatalf("seed mismatched id: %v", err)
	}

	tracker := h.tracker()
	id, err := tracker.registeredServerID(ctx, 42)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if id != 0 {
		t.Fatalf("matched server %d, want no match", id)
	}

	// The genuine Gigahost server with the right id does match.
	wantID, err := h.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "gh-right", Host: "203.0.113.3", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 42},
		CreatedAt: h.clock.Now(),
	}, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatalf("seed correct server: %v", err)
	}
	id, err = tracker.registeredServerID(ctx, 42)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if id != wantID {
		t.Fatalf("matched server %d, want %d", id, wantID)
	}

	// A non-positive provider id never matches anything.
	if id, err := tracker.registeredServerID(ctx, 0); err != nil || id != 0 {
		t.Fatalf("zero provider id matched: id=%d err=%v", id, err)
	}
}

// TestRunOnceWithNoStoreIsAnError proves a misconfigured tracker reports the
// problem instead of silently doing nothing forever.
func TestRunOnceWithNoStoreIsAnError(t *testing.T) {
	tracker := New(nil, Options{})
	if err := tracker.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce with no store returned nil")
	}
}

// TestResolveReaderFailureIsProviderUnavailable proves an unresolvable provider is
// reported as unavailable rather than as a nil reader that would panic.
func TestResolveReaderFailureIsProviderUnavailable(t *testing.T) {
	tracker := New(nil, Options{})
	if _, err := tracker.resolveReader(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("resolveReader error = %v, want ErrProviderUnavailable", err)
	}
	tracker = New(nil, Options{Resolve: func(context.Context) (ProviderReader, error) {
		return nil, ErrProviderUnavailable
	}})
	if _, err := tracker.resolveReader(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("resolveReader error = %v, want ErrProviderUnavailable", err)
	}
}
