package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		// Exact matches
		{"v3.1.20260828", "v3.1.20260828", 0},
		{"3.1.20260828", "v3.1.20260828", 0},
		{"v1.0.0", "v1.0.0", 0},
		{"", "", 0},

		// SemVer 2.0.0 build metadata (+...) stripped before precedence comparison
		{"1.0.0+1", "1.0.0+2", 0},
		{"1.0.0+2", "1.0.0+1", 0},
		{"1.0.0+build.1", "1.0.0+build.2", 0},
		{"1.0.0+build", "1.0.0", 0},
		{"1.0.0", "1.0.0+build", 0},
		{"1.0.0-alpha+001", "1.0.0-alpha+002", 0},

		// SemVer 2.0.0 rule 11.4.2/11.4.3: numeric prereleases have lower precedence than non-numeric
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0-1", "1.0.0-rc1", -1},
		{"1.0.0-rc1", "1.0.0-1", 1},
		{"1.0.0-1", "1.0.0-2", -1},
		{"1.0.0-2", "1.0.0-1", 1},

		// Release vs prerelease precedence: 1.0.0-alpha < 1.0.0
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0", "1.0.0-foo", 1},
		{"1.0.0-foo", "1.0.0", -1},
		{"1.0.0", "1.0.0-0", 1},
		{"1.0.0-0", "1.0.0", -1},
		{"1.0.0-alpha.0", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-alpha.0", -1},
		{"v1.0.0-rc1", "v1.0.0", -1},
		{"v1.0.0", "v1.0.0-rc1", 1},
		{"v1.0.0-rc2", "v1.0.0-rc1", 1},
		{"v1.0.0-rc10", "v1.0.0-rc2", 1},
		{"v1.0.0-beta", "v1.0.0-alpha", 1},

		// Calendar versions (CalVer)
		{"v3.1.20260828", "v3.1.20260901", -1},
		{"v3.1.20260901", "v3.1.20260828", 1},
		{"v3.1.20260828", "v3.1.20260814", 1},
		{"v3.1.20260814", "v3.1.20260828", -1},
		{"v3.1.20260812", "v3.0.20260805", 1},
		{"v3.0.20260805", "v3.1.20260812", -1},

		// Docker image revision comparison (v3.1.20260828-1 < v3.1.20260828-2)
		{"v3.1.20260828-1", "v3.1.20260828-2", -1},
		{"v3.1.20260828-2", "v3.1.20260828-1", 1},
		{"devopsigor/amneziawg:v3.1.20260828-1", "devopsigor/amneziawg:v3.1.20260828-2", -1},
		{"devopsigor/amneziawg:v3.1.20260828-2", "devopsigor/amneziawg:v3.1.20260828-1", 1},
		{"devopsigor/amneziawg:v3.1.20260828-1", "devopsigor/amneziawg:v3.1.20260828-1", 0},

		// Standard semver
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.4", "v1.2.3", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.9.9", "v2.0.0", -1},

		// Trailing zeros / equivalence
		{"v1.0.0", "v1.0", 0},
		{"v1.0", "v1.0.0", 0},
		{"v1.0.1", "v1.0", 1},
		{"v1.0", "v1.0.1", -1},

		// Packaging revisions (hyphen + number on calver)
		{"v1.0.20260618-2", "v1.0.20260618", 1},
		{"v1.0.20260618", "v1.0.20260618-2", -1},
		{"v1.0.20260618-2", "v1.0.20260618-1", 1},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("%s_vs_%s", tc.v1, tc.v2)
		t.Run(name, func(t *testing.T) {
			got := CompareVersions(tc.v1, tc.v2)
			if got != tc.expected {
				t.Errorf("CompareVersions(%q, %q) = %d; want %d", tc.v1, tc.v2, got, tc.expected)
			}
		})
	}
}

func setupMockServers(t *testing.T) (*httptest.Server, *httptest.Server, *http.ServeMux, *http.ServeMux) {
	t.Helper()
	ghMux := http.NewServeMux()
	dhMux := http.NewServeMux()

	ghSrv := httptest.NewServer(ghMux)
	dhSrv := httptest.NewServer(dhMux)

	return ghSrv, dhSrv, ghMux, dhMux
}

func TestServiceCheck_Success(t *testing.T) {
	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	// amneziawg-go tags
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260828"},
			{Name: "v3.1.20260814"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	// amneziawg-tools tags
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260812"},
			{Name: "v3.0.20260805"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	// amneziawg-tools releases
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/releases", func(w http.ResponseWriter, r *http.Request) {
		releases := []gitHubRelease{
			{
				TagName:     "v3.1.20260812",
				HTMLURL:     "https://github.com/amnezia-vpn/amneziawg-tools/releases/tag/v3.1.20260812",
				PublishedAt: time.Date(2026, 8, 12, 22, 40, 46, 0, time.UTC),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(releases)
	})

	// amneziawg-go releases (returns 404)
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/releases", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	// Docker Hub tags for devopsigor/amneziawg
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		resp := dockerHubResponse{
			Count: 2,
			Results: []dockerHubTag{
				{Name: "latest", LastUpdated: time.Now()},
				{Name: "v3.1.20260828-1", LastUpdated: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
		WithToken("test-token"),
	)

	ctx := context.Background()
	status, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status == nil {
		t.Fatal("expected non-nil UpstreamStatus")
	}

	if status.Status != "up_to_date" {
		t.Errorf("expected Status='up_to_date', got %q", status.Status)
	}
	if status.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=false, got true")
	}

	if len(status.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(status.Components))
	}

	goComp := status.Components[0]
	if goComp.Name != "amneziawg-go" || goComp.LatestVersion != "v3.1.20260828" || goComp.UpdateAvailable {
		t.Errorf("unexpected amneziawg-go status: %+v", goComp)
	}
	if goComp.Error != "" {
		t.Errorf("unexpected error on amneziawg-go: %s", goComp.Error)
	}

	toolsComp := status.Components[1]
	if toolsComp.Name != "amneziawg-tools" || toolsComp.LatestVersion != "v3.1.20260812" || toolsComp.UpdateAvailable {
		t.Errorf("unexpected amneziawg-tools status: %+v", toolsComp)
	}
	if toolsComp.PublishedAt.IsZero() {
		t.Errorf("expected non-zero PublishedAt for amneziawg-tools")
	}
	if toolsComp.Error != "" {
		t.Errorf("unexpected error on amneziawg-tools: %s", toolsComp.Error)
	}

	dockerComp := status.Components[2]
	if dockerComp.Name != "docker-base-image" || dockerComp.LatestVersion != "v3.1.20260828-1" || dockerComp.UpdateAvailable {
		t.Errorf("unexpected docker-base-image status: %+v", dockerComp)
	}
	if dockerComp.PublishedAt.IsZero() {
		t.Errorf("expected non-zero PublishedAt for docker-base-image")
	}
	if dockerComp.Error != "" {
		t.Errorf("unexpected error on docker-base-image: %s", dockerComp.Error)
	}

	if status.BaseImage != PinnedAWGBaseImage {
		t.Errorf("expected BaseImage %q, got %q", PinnedAWGBaseImage, status.BaseImage)
	}
}

func TestServiceCheck_UpdateAvailable(t *testing.T) {
	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	// amneziawg-go has a newer tag: v3.1.20260930
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260930"},
			{Name: "v3.1.20260828"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260812"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	// Docker Hub has a newer tag: v3.1.20260828-2
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		resp := dockerHubResponse{
			Count: 2,
			Results: []dockerHubTag{
				{Name: "latest", LastUpdated: time.Now()},
				{Name: "v3.1.20260828-2", LastUpdated: time.Now()},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
	)

	status, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Status != "update_available" {
		t.Errorf("expected overall Status='update_available', got %q", status.Status)
	}
	if !status.UpdateAvailable {
		t.Errorf("expected overall UpdateAvailable=true")
	}

	// amneziawg-go has update
	if !status.Components[0].UpdateAvailable {
		t.Errorf("expected amneziawg-go UpdateAvailable=true")
	}
	if status.Components[0].LatestVersion != "v3.1.20260930" {
		t.Errorf("expected latest version v3.1.20260930, got %s", status.Components[0].LatestVersion)
	}

	// amneziawg-tools is up to date
	if status.Components[1].UpdateAvailable {
		t.Errorf("expected amneziawg-tools UpdateAvailable=false")
	}

	// docker-base-image has update
	if !status.Components[2].UpdateAvailable {
		t.Errorf("expected docker-base-image UpdateAvailable=true")
	}
	if status.Components[2].LatestVersion != "v3.1.20260828-2" {
		t.Errorf("expected latest version v3.1.20260828-2, got %s", status.Components[2].LatestVersion)
	}
}

func TestServiceCheck_DegradedAndNoCachePoisoning(t *testing.T) {
	var toolsRequestCount int32
	var goRequestCount int32

	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&goRequestCount, 1)
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260828"}})
	})

	// amneziawg-tools fails with rate limit
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&toolsRequestCount, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message": "rate limit"}`))
	})

	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(dockerHubResponse{
			Count: 1,
			Results: []dockerHubTag{
				{Name: "v3.1.20260828-1", LastUpdated: time.Now()},
			},
		})
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
		WithCacheTTL(1*time.Hour),
	)

	ctx := context.Background()

	// Initial check results in degraded status
	status1, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}

	if status1.Status != "degraded" {
		t.Errorf("expected Status='degraded', got %q", status1.Status)
	}
	if status1.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=false in degraded check")
	}
	if status1.Components[1].Error == "" {
		t.Errorf("expected tools component to record rate limit error")
	}

	// CRITICAL TEST: Degraded state MUST NOT be cached as valid fresh state for 1 hour.
	// Calling Check again without forceRefresh must still make new queries because cache was not set.
	prevToolsRequests := atomic.LoadInt32(&toolsRequestCount)
	status2, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("second Check returned error: %v", err)
	}
	if status2.Status != "degraded" {
		t.Errorf("expected second status to be degraded, got %q", status2.Status)
	}
	if atomic.LoadInt32(&toolsRequestCount) <= prevToolsRequests {
		t.Errorf("expected retry without cache lockout for degraded component, but no new requests were made")
	}
}

func TestServiceCheck_AllErrors(t *testing.T) {
	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
	)

	status, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check returned unexpected error: %v", err)
	}

	if status.Status != "error" {
		t.Errorf("expected Status='error', got %q", status.Status)
	}
	if status.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=false on error")
	}

	for _, comp := range status.Components {
		if comp.Error == "" {
			t.Errorf("expected component %s to record error", comp.Name)
		}
	}
}

func TestServiceCheck_LastKnownGoodFallback(t *testing.T) {
	var goShouldFail int32

	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&goShouldFail) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260901"}})
	})
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260812"}})
	})
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(dockerHubResponse{
			Count: 1,
			Results: []dockerHubTag{
				{Name: "v3.1.20260828-1", LastUpdated: time.Now()},
			},
		})
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
		WithCacheTTL(10*time.Millisecond),
	)

	ctx := context.Background()

	// Step 1: Initial successful check populates last-known-good
	status1, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("initial check failed: %v", err)
	}
	if status1.Status != "update_available" {
		t.Errorf("expected update_available, got %q", status1.Status)
	}
	if status1.Components[0].LatestVersion != "v3.1.20260901" {
		t.Fatalf("expected v3.1.20260901, got %s", status1.Components[0].LatestVersion)
	}

	// Step 2: Expire cache and trigger failure on amneziawg-go
	time.Sleep(20 * time.Millisecond)
	atomic.StoreInt32(&goShouldFail, 1)

	// Step 3: Check should retain error indicator while falling back to last-known-good values
	status2, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("second check failed: %v", err)
	}

	if status2.Status != "degraded" {
		t.Errorf("expected degraded from fallback with partial error, got %q", status2.Status)
	}
	if !status2.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=true from fallback even when degraded")
	}
	goComp := status2.Components[0]
	if goComp.Error == "" {
		t.Errorf("expected error indicator to be retained on failed component")
	}
	if goComp.LatestVersion != "v3.1.20260901" {
		t.Errorf("expected last-known-good LatestVersion 'v3.1.20260901', got %q", goComp.LatestVersion)
	}
	if !goComp.UpdateAvailable {
		t.Errorf("expected fallback UpdateAvailable to remain true")
	}
}

func TestServiceCheck_DegradedWhenAnyFailsEvenWithUpdate(t *testing.T) {
	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	// amneziawg-go has update available
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260901"}})
	})
	// amneziawg-tools fails with error
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	// docker is up to date
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(dockerHubResponse{
			Count: 1,
			Results: []dockerHubTag{
				{Name: "v3.1.20260828-1", LastUpdated: time.Now()},
			},
		})
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
	)

	status, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}

	if status.Status != "degraded" {
		t.Errorf("expected Status='degraded', got %q", status.Status)
	}
	if !status.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=true, got false")
	}
	if !status.Components[0].UpdateAvailable {
		t.Errorf("expected amneziawg-go UpdateAvailable=true")
	}
	if status.Components[1].Error == "" {
		t.Errorf("expected amneziawg-tools to have error")
	}
}

func TestServiceCheck_Caching(t *testing.T) {
	var requestCount int32

	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260828"}})
	})
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260812"}})
	})
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_ = json.NewEncoder(w).Encode(dockerHubResponse{
			Count: 1,
			Results: []dockerHubTag{
				{Name: "v3.1.20260828-1", LastUpdated: time.Now()},
			},
		})
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
		WithCacheTTL(1*time.Hour),
	)

	ctx := context.Background()

	// Initial fetch
	status1, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("first check error: %v", err)
	}
	initialRequests := atomic.LoadInt32(&requestCount)
	if initialRequests < 3 {
		t.Fatalf("expected at least 3 requests, got %d", initialRequests)
	}

	// Cache hit (forceRefresh = false)
	status2, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("second check error: %v", err)
	}
	if atomic.LoadInt32(&requestCount) != initialRequests {
		t.Errorf("expected cache hit to make no new requests, count was %d", atomic.LoadInt32(&requestCount))
	}
	if status1.CheckedAt != status2.CheckedAt {
		t.Errorf("expected identical CheckedAt timestamps for cached result")
	}

	// Force refresh (forceRefresh = true)
	status3, err := svc.Check(ctx, true)
	if err != nil {
		t.Fatalf("force refresh check error: %v", err)
	}
	if atomic.LoadInt32(&requestCount) <= initialRequests {
		t.Errorf("expected new requests on force refresh")
	}
	if status3 == nil {
		t.Fatal("expected non-nil status on force refresh")
	}
}

func TestServiceCheck_ConcurrencyAndRace(t *testing.T) {
	ghSrv, dhSrv, ghMux, dhMux := setupMockServers(t)
	defer ghSrv.Close()
	defer dhSrv.Close()

	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260828"}})
	})
	ghMux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260812"}})
	})
	dhMux.HandleFunc("/repositories/devopsigor/amneziawg/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(dockerHubResponse{
			Count: 1,
			Results: []dockerHubTag{
				{Name: "v3.1.20260828-1", LastUpdated: time.Now()},
			},
		})
	})

	svc := NewService(
		WithBaseURL(ghSrv.URL),
		WithDockerBaseURL(dhSrv.URL),
	)

	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			force := idx%2 == 0
			status, err := svc.Check(ctx, force)
			if err != nil {
				t.Errorf("goroutine %d failed: %v", idx, err)
			}
			if status == nil {
				t.Errorf("goroutine %d got nil status", idx)
			}
		}(i)
	}

	wg.Wait()
}
