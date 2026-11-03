package updater

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckEngine_ColdFailure_FullLifecycle(t *testing.T) {
	var requestCount int64
	var statusCode int = http.StatusTooManyRequests
	var retryAfterVal string = "300"
	var respBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		if retryAfterVal != "" {
			w.Header().Set("Retry-After", retryAfterVal)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if len(respBody) > 0 {
			_, _ = w.Write(respBody)
		}
	}))
	defer server.Close()

	var timeMu sync.Mutex
	simTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	getTime := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return simTime
	}
	advanceTime := func(d time.Duration) {
		timeMu.Lock()
		defer timeMu.Unlock()
		simTime = simTime.Add(d)
	}

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(12*time.Hour),
		WithTimeFunc(getTime),
	)
	ctx := context.Background()

	// 1. Initial cold failure: HTTP 429
	status1, err1 := checker.CheckEngine(ctx, EngineXray, "v1.8.0")
	if err1 == nil {
		t.Fatal("expected error on initial cold 429, got nil")
	}
	if !status1.CheckedAt.IsZero() {
		t.Errorf("expected zero CheckedAt on cold failure, got %v", status1.CheckedAt)
	}
	if status1.LatestVersion != "" {
		t.Errorf("expected empty LatestVersion on cold failure, got %q", status1.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected 1 request, got %d", atomic.LoadInt64(&requestCount))
	}
	if _, ok := checker.GetCachedRelease(EngineXray); ok {
		t.Error("expected GetCachedRelease to return ok=false after cold failure")
	}
	expectedRetry1 := getTime().Add(300 * time.Second)
	if nextRetry := checker.NextRetryAt(EngineXray); !nextRetry.Equal(expectedRetry1) {
		t.Errorf("expected NextRetryAt %v, got %v", expectedRetry1, nextRetry)
	}

	// 2. Call during active backoff (100 seconds later, < 300s): must error without HTTP request
	advanceTime(100 * time.Second)
	status2, err2 := checker.CheckEngine(ctx, EngineXray, "v1.8.0")
	if err2 == nil {
		t.Fatal("expected error during active backoff on cold cache, got nil")
	}
	if !status2.CheckedAt.IsZero() {
		t.Errorf("expected zero CheckedAt during cold backoff, got %v", status2.CheckedAt)
	}
	if status2.LatestVersion != "" {
		t.Errorf("expected empty LatestVersion during cold backoff, got %q", status2.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected request count to remain 1 during active backoff, got %d", atomic.LoadInt64(&requestCount))
	}

	// 3. Expire backoff and retry: upstream fails again with HTTP 500.
	// HIGH R2-H1 regression: Must NOT return cached zero release with err == nil or fabricated CheckedAt!
	advanceTime(250 * time.Second) // total 350s > 300s
	statusCode = http.StatusInternalServerError
	retryAfterVal = ""

	status3, err3 := checker.CheckEngine(ctx, EngineXray, "v1.8.0")
	if err3 == nil {
		t.Fatal("expected error on repeated cold failure after backoff expiry, got nil (R2-H1 regression!)")
	}
	if !status3.CheckedAt.IsZero() {
		t.Errorf("expected zero CheckedAt on repeated cold failure, got fabricated %v", status3.CheckedAt)
	}
	if status3.LatestVersion != "" {
		t.Errorf("expected empty LatestVersion on repeated cold failure, got %q", status3.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected request count 2 after backoff expiry, got %d", atomic.LoadInt64(&requestCount))
	}
	if _, ok := checker.GetCachedRelease(EngineXray); ok {
		t.Error("expected GetCachedRelease to remain ok=false after repeated cold failure")
	}

	// 4. Call during second backoff (60 seconds later, < 5m minBackoff)
	advanceTime(60 * time.Second)
	status4, err4 := checker.CheckEngine(ctx, EngineXray, "v1.8.0")
	if err4 == nil {
		t.Fatal("expected error during second backoff, got nil")
	}
	if !status4.CheckedAt.IsZero() {
		t.Errorf("expected zero CheckedAt during second cold backoff, got %v", status4.CheckedAt)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected request count to remain 2 during second backoff, got %d", atomic.LoadInt64(&requestCount))
	}

	// 5. Expire second backoff and recover: upstream returns HTTP 200 with valid release
	advanceTime(5 * time.Minute)
	statusCode = http.StatusOK
	resp := githubReleaseResponse{
		TagName:     "v1.8.24",
		HTMLURL:     "https://github.com/XTLS/Xray-core/releases/tag/v1.8.24",
		PublishedAt: getTime(),
	}
	respBody, _ = json.Marshal(resp)

	status5, err5 := checker.CheckEngine(ctx, EngineXray, "v1.8.0", WithProfile("legacy"))
	if err5 != nil {
		t.Fatalf("expected success after backoff elapsed and upstream recovered, got error: %v", err5)
	}
	if status5.LatestVersion != "v1.8.24" {
		t.Errorf("expected LatestVersion 'v1.8.24', got %q", status5.LatestVersion)
	}
	if !status5.UpdateAvailable {
		t.Error("expected UpdateAvailable = true")
	}
	if status5.IsStale {
		t.Error("expected fresh status (IsStale = false) on recovery")
	}
	successfulCheckedAt := getTime()
	if !status5.CheckedAt.Equal(successfulCheckedAt) {
		t.Errorf("expected CheckedAt %v, got %v", successfulCheckedAt, status5.CheckedAt)
	}
	if !status5.RequestedAt.Equal(successfulCheckedAt) {
		t.Errorf("expected RequestedAt %v, got %v", successfulCheckedAt, status5.RequestedAt)
	}
	if atomic.LoadInt64(&requestCount) != 3 {
		t.Fatalf("expected request count 3 after recovery, got %d", atomic.LoadInt64(&requestCount))
	}
	cached, ok := checker.GetCachedRelease(EngineXray)
	if !ok || cached.Version != "v1.8.24" {
		t.Fatalf("expected GetCachedRelease to return v1.8.24, got %+v, ok=%v", cached, ok)
	}

	// 6. Verify subsequent warm cache fallback: expire TTL, upstream 502 -> returns cached release
	advanceTime(13 * time.Hour) // past 12h TTL
	statusCode = http.StatusBadGateway
	respBody = nil

	status6, err6 := checker.CheckEngine(ctx, EngineXray, "v1.8.0", WithProfile("legacy"))
	if err6 != nil {
		t.Fatalf("expected fallback to cached release on warm failure, got error: %v", err6)
	}
	if status6.LatestVersion != "v1.8.24" {
		t.Errorf("expected fallback LatestVersion 'v1.8.24', got %q", status6.LatestVersion)
	}
	if !status6.IsStale {
		t.Error("expected IsStale = true on fallback to cached release")
	}
	if !status6.CheckedAt.Equal(successfulCheckedAt) {
		t.Errorf("expected CheckedAt to retain initial contact time %v, got %v", successfulCheckedAt, status6.CheckedAt)
	}
	if !status6.RequestedAt.Equal(getTime()) {
		t.Errorf("expected RequestedAt %v, got %v", getTime(), status6.RequestedAt)
	}
	if atomic.LoadInt64(&requestCount) != 4 {
		t.Fatalf("expected request count 4 on warm fallback, got %d", atomic.LoadInt64(&requestCount))
	}
}

func TestCheckEngine_ColdFailure_NetworkError_RepeatedFailure(t *testing.T) {
	var requestCount int64
	mockClient := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				atomic.AddInt64(&requestCount, 1)
				return nil, errors.New("network dial tcp refused")
			},
		},
	}

	var timeMu sync.Mutex
	simTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	getTime := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return simTime
	}
	advanceTime := func(d time.Duration) {
		timeMu.Lock()
		defer timeMu.Unlock()
		simTime = simTime.Add(d)
	}

	checker := NewReleaseChecker(
		WithHTTPClient(mockClient),
		WithTimeFunc(getTime),
	)
	ctx := context.Background()

	// Initial network failure
	_, err := checker.CheckEngine(ctx, EngineNaive, "v1.0.0")
	if err == nil {
		t.Fatal("expected error on initial network failure, got nil")
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected 1 request, got %d", atomic.LoadInt64(&requestCount))
	}

	// Active backoff
	advanceTime(1 * time.Minute)
	_, err = checker.CheckEngine(ctx, EngineNaive, "v1.0.0")
	if err == nil {
		t.Fatal("expected error during active backoff, got nil")
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected request count to remain 1, got %d", atomic.LoadInt64(&requestCount))
	}

	// Expire backoff -> repeated network failure
	advanceTime(5 * time.Minute)
	status, err := checker.CheckEngine(ctx, EngineNaive, "v1.0.0")
	if err == nil {
		t.Fatal("expected error on repeated cold network failure, got nil")
	}
	if !status.CheckedAt.IsZero() {
		t.Errorf("expected zero CheckedAt on repeated failure, got %v", status.CheckedAt)
	}
	if status.LatestVersion != "" {
		t.Errorf("expected empty LatestVersion, got %q", status.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected request count 2 after retry, got %d", atomic.LoadInt64(&requestCount))
	}
	if _, ok := checker.GetCachedRelease(EngineNaive); ok {
		t.Error("expected GetCachedRelease to return ok=false after cold failures")
	}
}

func TestCheckEngine_ColdFailure_InvalidJSON_RepeatedFailure(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tag_name": ""`)) // malformed JSON
	}))
	defer server.Close()

	var timeMu sync.Mutex
	simTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	getTime := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return simTime
	}
	advanceTime := func(d time.Duration) {
		timeMu.Lock()
		defer timeMu.Unlock()
		simTime = simTime.Add(d)
	}

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTimeFunc(getTime),
	)
	ctx := context.Background()

	// Initial decode failure
	_, err := checker.CheckEngine(ctx, EngineSingBox, "v1.9.0")
	if err == nil {
		t.Fatal("expected error on decode failure, got nil")
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected 1 request, got %d", atomic.LoadInt64(&requestCount))
	}

	// Expire backoff -> repeated decode failure
	advanceTime(6 * time.Minute)
	status, err := checker.CheckEngine(ctx, EngineSingBox, "v1.9.0")
	if err == nil {
		t.Fatal("expected error on repeated cold decode failure, got nil")
	}
	if !status.CheckedAt.IsZero() {
		t.Errorf("expected zero CheckedAt, got %v", status.CheckedAt)
	}
	if status.LatestVersion != "" {
		t.Errorf("expected empty LatestVersion, got %q", status.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected request count 2 after retry, got %d", atomic.LoadInt64(&requestCount))
	}
}

func TestGetLatestRelease_ColdRetry_NoFabricatedRelease(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	var timeMu sync.Mutex
	simTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	getTime := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return simTime
	}
	advanceTime := func(d time.Duration) {
		timeMu.Lock()
		defer timeMu.Unlock()
		simTime = simTime.Add(d)
	}

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTimeFunc(getTime),
	)
	ctx := context.Background()

	// 1. Initial 403
	_, err := checker.GetLatestRelease(ctx, EngineCaddy)
	if err == nil {
		t.Fatal("expected error on initial cold 403, got nil")
	}

	// 2. Active backoff call
	advanceTime(1 * time.Minute)
	_, err = checker.GetLatestRelease(ctx, EngineCaddy)
	if err == nil {
		t.Fatal("expected error during active backoff, got nil")
	}

	// 3. Expire backoff -> retry still 403
	advanceTime(5 * time.Minute)
	info, err := checker.GetLatestRelease(ctx, EngineCaddy)
	if err == nil {
		t.Fatalf("expected error on repeated cold 403, got nil with info: %+v", info)
	}
	if info.Version != "" {
		t.Errorf("expected empty Version, got %q", info.Version)
	}
}
