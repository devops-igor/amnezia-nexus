package updater

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		profile          string
		expectedProtocol string
		wantUpdate       bool
	}{
		{name: "xray update available", engine: EngineXray, installed: "v26.10.28", upstreamTag: "v26.10.29", profile: "modern_pq", expectedProtocol: "vless", wantUpdate: true},
		{name: "xray already latest", engine: EngineXray, installed: "v26.10.29", upstreamTag: "v26.10.29", profile: "modern_pq", expectedProtocol: "vless", wantUpdate: false},
		{name: "naive update available", engine: EngineNaive, installed: "v154.0.8037.49-1", upstreamTag: "v154.0.8037.49-5", expectedProtocol: "naive", wantUpdate: true},
		{name: "caddy already latest", engine: EngineCaddy, installed: "v2.8.4", upstreamTag: "v2.8.4", expectedProtocol: "caddy", wantUpdate: false},
		{name: "sing-box rc to release update available", engine: EngineSingBox, installed: "v1.12.0-rc1", upstreamTag: "v1.12.0", expectedProtocol: "sing-box", wantUpdate: true},
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

			var opts []CheckOption
			if tt.profile != "" {
				opts = append(opts, WithProfile(tt.profile))
			}
			status, err := checker.CheckEngine(context.Background(), tt.engine, tt.installed, opts...)
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

func TestCheckEngine_RateLimit_Fallback(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			statusCode := http.StatusOK
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if statusCode != http.StatusOK {
					w.WriteHeader(statusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(githubReleaseResponse{
					TagName: "v2.8.4",
					HTMLURL: "https://github.com/caddyserver/caddy/releases/tag/v2.8.4",
				})
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
			status, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
			if err != nil || status.LatestVersion != "v2.8.4" {
				t.Fatalf("initial check failed: %v", err)
			}

			curTime = curTime.Add(2 * time.Hour)
			statusCode = code
			fallbackStatus, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
			if err != nil {
				t.Fatalf("expected fallback to succeed on %d, got: %v", code, err)
			}
			if fallbackStatus.LatestVersion != "v2.8.4" {
				t.Errorf("expected cached version v2.8.4, got %q", fallbackStatus.LatestVersion)
			}
		})
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

func TestCheckEngine_ProfileAwareness(t *testing.T) {
	tests := []struct {
		name              string
		engine            EngineType
		installed         string
		upstreamTag       string
		profile           string
		wantUpstreamNewer bool
		wantCompatible    bool
		wantUpdate        bool
	}{
		{name: "xray legacy with 26.10 breaking", engine: EngineXray, installed: "v1.8.24", upstreamTag: "v26.10.31", profile: "legacy", wantUpstreamNewer: true, wantCompatible: false, wantUpdate: false},
		{name: "xray legacy with 1.8 compatible", engine: EngineXray, installed: "v1.8.24", upstreamTag: "v1.8.25", profile: "legacy", wantUpstreamNewer: true, wantCompatible: true, wantUpdate: true},
		{name: "xray modern_pq with 26.10 newer", engine: EngineXray, installed: "v26.10.29", upstreamTag: "v26.10.31", profile: "modern_pq", wantUpstreamNewer: true, wantCompatible: true, wantUpdate: true},
		{name: "xray modern pq alias with 26.10 newer", engine: EngineXray, installed: "v26.10.29", upstreamTag: "v26.10.31", profile: "modern pq", wantUpstreamNewer: true, wantCompatible: true, wantUpdate: true},
		{name: "xray post_quantum alias with 26.10 newer", engine: EngineXray, installed: "v26.10.29", upstreamTag: "v26.10.31", profile: "post_quantum", wantUpstreamNewer: true, wantCompatible: true, wantUpdate: true},
		{name: "xray post-quantum alias with 26.10 newer", engine: EngineXray, installed: "v26.10.29", upstreamTag: "v26.10.31", profile: "post-quantum", wantUpstreamNewer: true, wantCompatible: true, wantUpdate: true},
		{name: "xray post_quantum alias with 1.8 incompatible", engine: EngineXray, installed: "v1.8.20", upstreamTag: "v1.8.25", profile: "post_quantum", wantUpstreamNewer: true, wantCompatible: false, wantUpdate: false},
		{name: "xray legacy compatibility baseline alias with 1.8 compatible", engine: EngineXray, installed: "v1.8.24", upstreamTag: "v1.8.25", profile: "legacy compatibility baseline", wantUpstreamNewer: true, wantCompatible: true, wantUpdate: true},
		{name: "xray legacy compatibility baseline alias with 26.10 breaking", engine: EngineXray, installed: "v1.8.24", upstreamTag: "v26.10.31", profile: "legacy compatibility baseline", wantUpstreamNewer: true, wantCompatible: false, wantUpdate: false},
		{name: "xray modern_pq with legacy downgrade", engine: EngineXray, installed: "v26.10.29", upstreamTag: "v1.8.24", profile: "modern_pq", wantUpstreamNewer: false, wantCompatible: true, wantUpdate: false},
		{name: "xray unprofiled defaults incompatible", engine: EngineXray, installed: "v1.8.24", upstreamTag: "v26.10.31", profile: "", wantUpstreamNewer: true, wantCompatible: false, wantUpdate: false},
		{name: "xray unrecognized profile defaults incompatible", engine: EngineXray, installed: "v1.8.24", upstreamTag: "v26.10.31", profile: "custom_unknown", wantUpstreamNewer: true, wantCompatible: false, wantUpdate: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(githubReleaseResponse{
					TagName: tt.upstreamTag,
					HTMLURL: "https://example.com/tag/" + tt.upstreamTag,
				})
			}))
			defer server.Close()

			checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

			status, err := checker.CheckEngineWithProfile(context.Background(), tt.engine, tt.installed, tt.profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status.UpstreamNewer != tt.wantUpstreamNewer {
				t.Errorf("UpstreamNewer = %v, want %v", status.UpstreamNewer, tt.wantUpstreamNewer)
			}
			if status.UpgradeCompatible != tt.wantCompatible {
				t.Errorf("UpgradeCompatible = %v, want %v", status.UpgradeCompatible, tt.wantCompatible)
			}
			if status.UpdateAvailable != tt.wantUpdate {
				t.Errorf("UpdateAvailable = %v, want %v", status.UpdateAvailable, tt.wantUpdate)
			}
			if status.Channel != tt.profile {
				t.Errorf("Channel = %q, want %q", status.Channel, tt.profile)
			}
		})
	}
}

func TestCheckEngine_ComponentSeparation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/klzgrad/naiveproxy/releases/latest":
			_ = json.NewEncoder(w).Encode(githubReleaseResponse{TagName: "v154.0.8037.49-5"})
		case "/repos/caddyserver/caddy/releases/latest":
			_ = json.NewEncoder(w).Encode(githubReleaseResponse{TagName: "v2.8.4"})
		case "/repos/klzgrad/forwardproxy/releases/latest":
			_ = json.NewEncoder(w).Encode(githubReleaseResponse{TagName: "v2.11.7-naive2"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	ctx := context.Background()

	// 1. Naive Client
	sClient, err := checker.CheckEngine(ctx, EngineNaiveClient, "v154.0.8037.49-1")
	if err != nil || sClient.LatestVersion != "v154.0.8037.49-5" || sClient.Protocol != "naive" {
		t.Fatalf("EngineNaiveClient failed: %+v, err: %v", sClient, err)
	}

	// 2. Caddy Core
	sCaddy, err := checker.CheckEngine(ctx, EngineCaddyCore, "v2.8.0")
	if err != nil || sCaddy.LatestVersion != "v2.8.4" || sCaddy.Protocol != "caddy" {
		t.Fatalf("EngineCaddyCore failed: %+v, err: %v", sCaddy, err)
	}

	// 3. Naive ForwardProxy Plugin
	sPlugin, err := checker.CheckEngine(ctx, EngineNaiveForwardProxy, "v2.11.7-naive1")
	if err != nil || sPlugin.LatestVersion != "v2.11.7-naive2" || sPlugin.Protocol != "naive" {
		t.Fatalf("EngineNaiveForwardProxy failed: %+v, err: %v", sPlugin, err)
	}
}

func TestCheckEngine_RateLimitBackoffSchedule(t *testing.T) {
	var requestCount int64
	statusCode := http.StatusOK
	retryAfterVal := ""
	resetVal := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		if statusCode != http.StatusOK {
			if retryAfterVal != "" {
				w.Header().Set("Retry-After", retryAfterVal)
			}
			if resetVal != "" {
				w.Header().Set("X-RateLimit-Reset", resetVal)
			}
			w.WriteHeader(statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubReleaseResponse{
			TagName: "v2.8.4",
			HTMLURL: "https://example.com/caddy",
		})
	}))
	defer server.Close()

	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	var timeMu sync.Mutex
	getTime := func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return now
	}
	advanceTime := func(d time.Duration) {
		timeMu.Lock()
		defer timeMu.Unlock()
		now = now.Add(d)
	}

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(1*time.Hour),
		WithTimeFunc(getTime),
	)
	ctx := context.Background()

	// 1. Initial successful fetch
	initialStatus, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
	if err != nil || initialStatus.LatestVersion != "v2.8.4" {
		t.Fatalf("initial fetch failed: %+v, err: %v", initialStatus, err)
	}
	if initialStatus.IsStale {
		t.Error("expected fresh status initially")
	}
	firstCheckedAt := initialStatus.CheckedAt
	if atomic.LoadInt64(&requestCount) != 1 {
		t.Fatalf("expected 1 request, got %d", atomic.LoadInt64(&requestCount))
	}

	// 2. Expire cache and encounter 429 with Retry-After: 600 (10 minutes)
	advanceTime(2 * time.Hour)
	statusCode = http.StatusTooManyRequests
	retryAfterVal = "600"

	fallbackStatus, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
	if err != nil {
		t.Fatalf("expected fallback on 429, got error: %v", err)
	}
	if !fallbackStatus.IsStale {
		t.Error("expected IsStale = true on rate limit fallback")
	}
	if fallbackStatus.CheckedAt != firstCheckedAt {
		t.Errorf("CheckedAt should retain initial contact time %v, got %v", firstCheckedAt, fallbackStatus.CheckedAt)
	}
	if fallbackStatus.RequestedAt != getTime() {
		t.Errorf("RequestedAt should be current call time %v, got %v", getTime(), fallbackStatus.RequestedAt)
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("expected 2 requests, got %d", atomic.LoadInt64(&requestCount))
	}

	expectedNextRetry := getTime().Add(600 * time.Second)
	if nextRetry := checker.NextRetryAt(EngineCaddy); !nextRetry.Equal(expectedNextRetry) {
		t.Errorf("NextRetryAt = %v, want %v", nextRetry, expectedNextRetry)
	}

	// Verify explicit upstream retry deadline is respected without capping at 1 hour for large Retry-After
	if retryDeadline := calculateNextRetry(&http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Retry-After": []string{"86400"}},
	}, getTime()); !retryDeadline.Equal(getTime().Add(86400 * time.Second)) {
		t.Errorf("expected backoff to respect 24h Retry-After without capping at 1h, got %v", retryDeadline)
	}

	// Verify explicit X-RateLimit-Reset deadline is respected without capping at 1 hour
	resetTimestamp := getTime().Add(2 * time.Hour).Unix()
	resetHdr := make(http.Header)
	resetHdr.Set("X-RateLimit-Reset", strconv.FormatInt(resetTimestamp, 10))
	if retryDeadline := calculateNextRetry(&http.Response{
		StatusCode: http.StatusForbidden,
		Header:     resetHdr,
	}, getTime()); !retryDeadline.Equal(time.Unix(resetTimestamp, 0)) {
		t.Errorf("expected backoff to respect X-RateLimit-Reset without capping at 1h, got %v", retryDeadline)
	}

	// Verify fallback to maxBackoff when no explicit upstream deadline is provided on rate limit
	if retryDeadline := calculateNextRetry(&http.Response{
		StatusCode: http.StatusTooManyRequests,
	}, getTime()); !retryDeadline.Equal(getTime().Add(maxBackoff)) {
		t.Errorf("expected fallback to maxBackoff (1h) on rate limit with no headers, got %v", retryDeadline)
	}

	// 3. Repeated call during backoff (e.g. 3 minutes later) MUST NOT hit GitHub
	advanceTime(3 * time.Minute)
	backoffStatus, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
	if err != nil {
		t.Fatalf("expected cached release during backoff, got error: %v", err)
	}
	if !backoffStatus.IsStale {
		t.Error("expected IsStale = true during backoff")
	}
	if atomic.LoadInt64(&requestCount) != 2 {
		t.Fatalf("request count should NOT increment during active backoff, got %d", atomic.LoadInt64(&requestCount))
	}

	// 4. Advance time past backoff schedule (8 minutes later, total 11 minutes > 10m backoff)
	// Server recovers with 200 OK
	advanceTime(8 * time.Minute)
	statusCode = http.StatusOK
	recoveredStatus, err := checker.CheckEngine(ctx, EngineCaddy, "v2.8.0")
	if err != nil {
		t.Fatalf("expected success after backoff elapsed, got error: %v", err)
	}
	if recoveredStatus.IsStale {
		t.Error("expected fresh status after recovery")
	}
	if atomic.LoadInt64(&requestCount) != 3 {
		t.Fatalf("expected request count 3 after backoff recovery, got %d", atomic.LoadInt64(&requestCount))
	}
	if !checker.NextRetryAt(EngineCaddy).IsZero() {
		t.Errorf("NextRetryAt should be reset after successful contact, got %v", checker.NextRetryAt(EngineCaddy))
	}
}

func TestReleaseChecker_SingleflightCancellationDecoupled(t *testing.T) {
	inFlight := make(chan struct{})
	releaseBlock := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-inFlight:
		default:
			close(inFlight)
		}
		<-releaseBlock
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubReleaseResponse{
			TagName: "v26.10.31",
			HTMLURL: "https://example.com/xray",
		})
	}))
	defer server.Close()

	checker := NewReleaseChecker(
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTTL(1*time.Hour),
	)

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	var wg sync.WaitGroup
	var errA, errB error
	var resB ReleaseInfo

	// Caller A starts request
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, errA = checker.GetLatestRelease(ctxA, EngineXray)
	}()

	<-inFlight

	// Caller B joins singleflight for the same engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		resB, errB = checker.GetLatestRelease(ctxB, EngineXray)
	}()

	// Cancel Caller A while in-flight
	time.Sleep(20 * time.Millisecond)
	cancelA()

	// Unblock server response
	close(releaseBlock)
	wg.Wait()

	if !errors.Is(errA, context.Canceled) {
		t.Errorf("expected caller A to receive context.Canceled, got: %v", errA)
	}
	if errB != nil {
		t.Errorf("expected caller B to succeed despite caller A cancellation, got: %v", errB)
	}
	if resB.Version != "v26.10.31" {
		t.Errorf("expected caller B to receive v26.10.31, got: %q", resB.Version)
	}
}

func TestCheckEngine_UnknownInstalledVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubReleaseResponse{
			TagName: "v1.8.25",
			HTMLURL: "https://example.com/xray",
		})
	}))
	defer server.Close()

	checker := NewReleaseChecker(WithBaseURL(server.URL), WithHTTPClient(server.Client()))

	for _, invalid := range []string{"", "   ", "unknown", "invalid.version.tag"} {
		status, err := checker.CheckEngine(context.Background(), EngineXray, invalid)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", invalid, err)
		}
		if status.Status != UpdateUnknown {
			t.Errorf("for %q: Status = %q, want %q", invalid, status.Status, UpdateUnknown)
		}
		if status.UpdateAvailable {
			t.Errorf("for %q: UpdateAvailable should be false", invalid)
		}
		if status.UpstreamNewer {
			t.Errorf("for %q: UpstreamNewer should be false", invalid)
		}
	}
}
