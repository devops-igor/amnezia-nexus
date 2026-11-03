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

// mockRoundTripper allows mocking HTTP responses and errors directly.
type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestCheckEngine_Success(t *testing.T) {
	pubTime := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name             string
		engine           EngineType
		installed        string
		upstreamTag      string
		expectedProtocol string
		wantUpdate       bool
	}{
		{
			name:             "xray update available",
			engine:           EngineXray,
			installed:        "v26.10.28",
			upstreamTag:      "v26.10.29",
			expectedProtocol: "vless",
			wantUpdate:       true,
		},
		{
			name:             "xray already latest",
			engine:           EngineXray,
			installed:        "v26.10.29",
			upstreamTag:      "v26.10.29",
			expectedProtocol: "vless",
			wantUpdate:       false,
		},
		{
			name:             "naive update available",
			engine:           EngineNaive,
			installed:        "v154.0.8037.49-1",
			upstreamTag:      "v154.0.8037.49-5",
			expectedProtocol: "naive",
			wantUpdate:       true,
		},
		{
			name:             "caddy already latest",
			engine:           EngineCaddy,
			installed:        "v2.8.4",
			upstreamTag:      "v2.8.4",
			expectedProtocol: "caddy",
			wantUpdate:       false,
		},
		{
			name:             "sing-box rc to release update available",
			engine:           EngineSingBox,
			installed:        "v1.12.0-rc1",
			upstreamTag:      "v1.12.0",
			expectedProtocol: "sing-box",
			wantUpdate:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("ETag", `"etag-test"`)
				resp := githubReleaseResponse{
					TagName:     tt.upstreamTag,
					HTMLURL:     "https://github.com/test/" + string(tt.engine) + "/releases/tag/" + tt.upstreamTag,
					PublishedAt: pubTime,
					Prerelease:  false,
				}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()

			checker := NewReleaseChecker(
				WithBaseURL(server.URL),
				WithHTTPClient(server.Client()),
				WithTTL(1*time.Hour),
			)

			status, err := checker.CheckEngine(context.Background(), tt.engine, tt.installed)
			if err != nil {
				t.Fatalf("CheckEngine returned unexpected error: %v", err)
			}

			if status.Protocol != tt.expectedProtocol {
				t.Errorf("expected Protocol %q, got %q", tt.expectedProtocol, status.Protocol)
			}
			if status.InstalledVersion != tt.installed {
				t.Errorf("expected InstalledVersion %q, got %q", tt.installed, status.InstalledVersion)
			}
			if status.LatestVersion != tt.upstreamTag {
				t.Errorf("expected LatestVersion %q, got %q", tt.upstreamTag, status.LatestVersion)
			}
			if status.UpdateAvailable != tt.wantUpdate {
				t.Errorf("expected UpdateAvailable %v, got %v", tt.wantUpdate, status.UpdateAvailable)
			}
			expectedURL := "https://github.com/test/" + string(tt.engine) + "/releases/tag/" + tt.upstreamTag
			if status.ReleaseURL != expectedURL {
				t.Errorf("expected ReleaseURL %q, got %q", expectedURL, status.ReleaseURL)
			}
			if status.CheckedAt.IsZero() {
				t.Error("expected CheckedAt to be non-zero")
			}
		})
	}
}

func TestCheckEngine_CacheHit(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		resp := githubReleaseResponse{
			TagName:     "v1.8.24",
			HTMLURL:     "https://github.com/XTLS/Xray-core/releases/tag/v1.8.24",
			PublishedAt: time.Now(),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(12*time.Hour),
	)

	ctx := context.Background()

	// First call hits upstream server
	status1, err := checker.CheckEngine(ctx, EngineXray, "v1.8.20")
	if err != nil {
		t.Fatalf("first CheckEngine failed: %v", err)
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected 1 request, got %d", atomic.LoadInt64(&requestCount))
	}

	// Second call within TTL should be served from cache
	status2, err := checker.CheckEngine(ctx, EngineXray, "v1.8.20")
	if err != nil {
		t.Fatalf("second CheckEngine failed: %v", err)
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected requestCount to remain 1, got %d", atomic.LoadInt64(&requestCount))
	}

	if status1.LatestVersion != status2.LatestVersion {
		t.Errorf("cached LatestVersion mismatch: %q vs %q", status1.LatestVersion, status2.LatestVersion)
	}
}

func TestCheckEngine_ETag304(t *testing.T) {
	var requestCount int64
	const expectedETag = `"etag-abc123"`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		if r.Header.Get("If-None-Match") == expectedETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", expectedETag)
		w.Header().Set("Content-Type", "application/json")
		resp := githubReleaseResponse{
			TagName:     "v26.10.29",
			HTMLURL:     "https://github.com/XTLS/Xray-core/releases/tag/v26.10.29",
			PublishedAt: time.Now(),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	curTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	timeMu := sync.Mutex{}
	getTime := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return curTime
	}
	setTime := func(t time.Time) {
		timeMu.Lock()
		defer timeMu.Unlock()
		curTime = t
	}

	ttl := 1 * time.Hour
	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(ttl),
		WithTimeFunc(getTime),
	)

	ctx := context.Background()

	// 1. Initial fetch -> 200 OK with ETag
	status, err := checker.CheckEngine(ctx, EngineXray, "v26.10.20")
	if err != nil {
		t.Fatalf("initial check failed: %v", err)
	}
	if status.LatestVersion != "v26.10.29" {
		t.Fatalf("expected latest version v26.10.29, got %q", status.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected 1 request, got %d", atomic.LoadInt64(&requestCount))
	}

	// 2. Advance time past TTL -> triggers upstream check with If-None-Match
	setTime(getTime().Add(2 * time.Hour))

	status304, err := checker.CheckEngine(ctx, EngineXray, "v26.10.20")
	if err != nil {
		t.Fatalf("second check after expiry failed: %v", err)
	}
	if status304.LatestVersion != "v26.10.29" {
		t.Fatalf("expected latest version v26.10.29 from 304, got %q", status304.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected 2 requests, got %d", atomic.LoadInt64(&requestCount))
	}

	// 3. Check again within new refreshed TTL -> cache hit, no network request
	setTime(getTime().Add(30 * time.Minute))
	statusCached, err := checker.CheckEngine(ctx, EngineXray, "v26.10.20")
	if err != nil {
		t.Fatalf("check within refreshed TTL failed: %v", err)
	}
	if statusCached.LatestVersion != "v26.10.29" {
		t.Fatalf("expected latest version v26.10.29, got %q", statusCached.LatestVersion)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected requestCount to remain 2, got %d", atomic.LoadInt64(&requestCount))
	}
}

func TestCheckEngine_RateLimit_403_Fallback(t *testing.T) {
	statusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := githubReleaseResponse{
			TagName: "v2.8.4",
			HTMLURL: "https://github.com/caddyserver/caddy/releases/tag/v2.8.4",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	curTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(1*time.Hour),
		WithTimeFunc(func() time.Time { return curTime }),
	)

	ctx := context.Background()

	// Initial fetch
	status, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
	if err != nil {
		t.Fatalf("initial check failed: %v", err)
	}
	if status.LatestVersion != "v2.8.4" {
		t.Fatalf("expected latest version v2.8.4, got %q", status.LatestVersion)
	}

	// Simulate rate limit 403 on expired cache
	curTime = curTime.Add(2 * time.Hour)
	statusCode = http.StatusForbidden

	fallbackStatus, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
	if err != nil {
		t.Fatalf("expected fallback to succeed on 403, got error: %v", err)
	}
	if fallbackStatus.LatestVersion != "v2.8.4" {
		t.Errorf("expected fallback to return cached version v2.8.4, got %q", fallbackStatus.LatestVersion)
	}
}

func TestCheckEngine_RateLimit_429_Fallback(t *testing.T) {
	statusCode := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := githubReleaseResponse{
			TagName: "v1.12.0",
			HTMLURL: "https://github.com/SagerNet/sing-box/releases/tag/v1.12.0",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	curTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(1*time.Hour),
		WithTimeFunc(func() time.Time { return curTime }),
	)

	ctx := context.Background()

	// Initial fetch
	status, err := checker.CheckEngine(ctx, EngineSingBox, "v1.11.0")
	if err != nil {
		t.Fatalf("initial check failed: %v", err)
	}
	if status.LatestVersion != "v1.12.0" {
		t.Fatalf("expected latest version v1.12.0, got %q", status.LatestVersion)
	}

	// Simulate rate limit 429 on expired cache
	curTime = curTime.Add(2 * time.Hour)
	statusCode = http.StatusTooManyRequests

	fallbackStatus, err := checker.CheckEngine(ctx, EngineSingBox, "v1.11.0")
	if err != nil {
		t.Fatalf("expected fallback to succeed on 429, got error: %v", err)
	}
	if fallbackStatus.LatestVersion != "v1.12.0" {
		t.Errorf("expected fallback to return cached version v1.12.0, got %q", fallbackStatus.LatestVersion)
	}
}

func TestCheckEngine_NetworkError_Fallback(t *testing.T) {
	failNetwork := false
	mockClient := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if failNetwork {
					return nil, errors.New("network connection timeout/refused")
				}
				rec := httptest.NewRecorder()
				rec.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(rec).Encode(githubReleaseResponse{
					TagName: "v154.0.8037.49-5",
					HTMLURL: "https://github.com/klzgrad/naiveproxy/releases/tag/v154.0.8037.49-5",
				})
				return rec.Result(), nil
			},
		},
	}

	curTime := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	checker := NewReleaseChecker(
		WithHTTPClient(mockClient),
		WithTTL(1*time.Hour),
		WithTimeFunc(func() time.Time { return curTime }),
	)

	ctx := context.Background()

	// Initial fetch
	status, err := checker.CheckEngine(ctx, EngineNaive, "v154.0.8037.49-1")
	if err != nil {
		t.Fatalf("initial check failed: %v", err)
	}
	if status.LatestVersion != "v154.0.8037.49-5" {
		t.Fatalf("expected v154.0.8037.49-5, got %q", status.LatestVersion)
	}

	// Simulate network failure after TTL expiry
	curTime = curTime.Add(2 * time.Hour)
	failNetwork = true

	fallbackStatus, err := checker.CheckEngine(ctx, EngineNaive, "v154.0.8037.49-1")
	if err != nil {
		t.Fatalf("expected fallback to succeed on network failure, got error: %v", err)
	}
	if fallbackStatus.LatestVersion != "v154.0.8037.49-5" {
		t.Errorf("expected cached version v154.0.8037.49-5, got %q", fallbackStatus.LatestVersion)
	}
}

func TestCheckEngine_NoCache_Errors(t *testing.T) {
	t.Run("rate limit 403 without cache returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()

		checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
		_, err := checker.CheckEngine(context.Background(), EngineXray, "v1.8.0")
		if err == nil {
			t.Fatal("expected error on 403 without cache, got nil")
		}
	})

	t.Run("network error without cache returns error", func(t *testing.T) {
		mockClient := &http.Client{
			Transport: &mockRoundTripper{
				roundTripFunc: func(req *http.Request) (*http.Response, error) {
					return nil, errors.New("network dial tcp refused")
				},
			},
		}

		checker := NewReleaseChecker(WithHTTPClient(mockClient))
		_, err := checker.CheckEngine(context.Background(), EngineXray, "v1.8.0")
		if err == nil {
			t.Fatal("expected error on network failure without cache, got nil")
		}
	})

	t.Run("unsupported engine returns error", func(t *testing.T) {
		checker := NewReleaseChecker()
		_, err := checker.CheckEngine(context.Background(), EngineType("invalid-engine"), "v1.0.0")
		if err == nil {
			t.Fatal("expected error for unsupported engine, got nil")
		}
	})
}

func TestReleaseChecker_CacheOperations(t *testing.T) {
	checker := NewReleaseChecker()

	// Initial state: not cached
	if _, ok := checker.GetCachedRelease(EngineXray); ok {
		t.Error("expected Xray to not be in cache initially")
	}

	info := ReleaseInfo{
		Engine:     EngineXray,
		Version:    "v26.10.29",
		ReleaseURL: "https://example.com/xray",
	}
	checker.SetCachedRelease(EngineXray, info, "etag-123")

	got, ok := checker.GetCachedRelease(EngineXray)
	if !ok || got.Version != "v26.10.29" {
		t.Fatalf("GetCachedRelease failed: got %+v, ok %v", got, ok)
	}

	checker.ClearCache()
	if _, ok := checker.GetCachedRelease(EngineXray); ok {
		t.Error("expected cache to be empty after ClearCache")
	}
}

func TestReleaseChecker_SingleflightDeduplication(t *testing.T) {
	var requestCount int64
	blockCh := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		<-blockCh // Hold request to allow concurrent callers to arrive
		w.Header().Set("Content-Type", "application/json")
		resp := githubReleaseResponse{
			TagName: "v26.10.29",
			HTMLURL: "https://github.com/XTLS/Xray-core/releases/tag/v26.10.29",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(1*time.Hour),
	)

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := checker.GetLatestRelease(context.Background(), EngineXray)
			if err != nil {
				t.Errorf("GetLatestRelease concurrent call failed: %v", err)
			}
		}()
	}

	// Give goroutines time to block in singleflight
	time.Sleep(50 * time.Millisecond)
	close(blockCh)
	wg.Wait()

	if atomic.LoadInt64(&requestCount) != 1 {
		t.Errorf("expected exactly 1 upstream request due to singleflight, got %d", atomic.LoadInt64(&requestCount))
	}
}

func TestReleaseChecker_Concurrency_Race(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := githubReleaseResponse{
			TagName: "v1.8.24",
			HTMLURL: "https://github.com/XTLS/Xray-core/releases/tag/v1.8.24",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(50*time.Millisecond),
	)

	engines := SupportedEngines()
	var wg sync.WaitGroup
	const iterations = 30

	for _, eng := range engines {
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(engine EngineType) {
				defer wg.Done()
				for j := 0; j < iterations; j++ {
					_, _ = checker.CheckEngine(context.Background(), engine, "v1.8.0")
					_, _ = checker.GetCachedRelease(engine)
					if j%10 == 0 {
						checker.SetCachedRelease(engine, ReleaseInfo{
							Engine:  engine,
							Version: "v1.8.24",
						}, "etag")
					}
				}
			}(eng)
		}
	}

	wg.Wait()
}

func TestReleaseChecker_AdditionalOptionsAndErrors(t *testing.T) {
	t.Run("custom repo map and option", func(t *testing.T) {
		customRepos := map[EngineType]string{
			EngineXray: "custom/xray",
		}
		checker := NewReleaseChecker(WithRepoMap(customRepos))
		if _, ok := checker.repos[EngineXray]; !ok || checker.repos[EngineXray] != "custom/xray" {
			t.Errorf("expected custom repo mapping, got %v", checker.repos)
		}
	})

	t.Run("upstream 500 without cache", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
		_, err := checker.CheckEngine(context.Background(), EngineXray, "v1.0.0")
		if err == nil {
			t.Fatal("expected error on 500 without cache, got nil")
		}
	})

	t.Run("upstream 500 with cached fallback", func(t *testing.T) {
		statusCode := http.StatusOK
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if statusCode != http.StatusOK {
				w.WriteHeader(statusCode)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(githubReleaseResponse{
				TagName: "v1.8.24",
				HTMLURL: "https://example.com",
			})
		}))
		defer server.Close()

		checker := NewReleaseChecker(
			WithBaseURL(server.URL),
			WithHTTPClient(server.Client()),
			WithTTL(1*time.Millisecond),
		)

		// Seed initial release
		_, err := checker.CheckEngine(context.Background(), EngineXray, "v1.8.0")
		if err != nil {
			t.Fatalf("unexpected error on seed: %v", err)
		}

		time.Sleep(5 * time.Millisecond) // expire cache
		statusCode = http.StatusInternalServerError

		status, err := checker.CheckEngine(context.Background(), EngineXray, "v1.8.0")
		if err != nil {
			t.Fatalf("expected fallback on 500 with cache, got error: %v", err)
		}
		if status.LatestVersion != "v1.8.24" {
			t.Errorf("expected cached version v1.8.24, got %q", status.LatestVersion)
		}
	})

	t.Run("invalid json response without cache", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{invalid-json"))
		}))
		defer server.Close()

		checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
		_, err := checker.CheckEngine(context.Background(), EngineXray, "v1.0.0")
		if err == nil {
			t.Fatal("expected error on invalid json, got nil")
		}
	})

	t.Run("empty tag_name without cache", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(githubReleaseResponse{
				TagName: "",
			})
		}))
		defer server.Close()

		checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
		_, err := checker.CheckEngine(context.Background(), EngineXray, "v1.0.0")
		if err == nil {
			t.Fatal("expected error on empty tag_name, got nil")
		}
	})
}
