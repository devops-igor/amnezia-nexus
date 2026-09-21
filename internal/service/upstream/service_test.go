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

		// Calendar versions
		{"v3.1.20260828", "v3.1.20260814", 1},
		{"v3.1.20260814", "v3.1.20260828", -1},
		{"v3.1.20260812", "v3.0.20260805", 1},
		{"v3.0.20260805", "v3.1.20260812", -1},

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

		// Packaging revisions (hyphen + number)
		{"v1.0.20260618-2", "v1.0.20260618", 1},
		{"v1.0.20260618", "v1.0.20260618-2", -1},
		{"v1.0.20260618-2", "v1.0.20260618-1", 1},

		// Prereleases (lower precedence than release)
		{"v1.0.0-rc1", "v1.0.0", -1},
		{"v1.0.0", "v1.0.0-rc1", 1},
		{"v1.0.0-rc2", "v1.0.0-rc1", 1},
		{"v1.0.0-rc10", "v1.0.0-rc2", 1},
		{"v1.0.0-beta", "v1.0.0-alpha", 1},

		// Full image tag comparisons
		{"devopsigor/amneziawg:v3.1.20260828-2", "devopsigor/amneziawg:v3.1.20260828-1", 1},
		{"devopsigor/amneziawg:v3.1.20260828-1", "devopsigor/amneziawg:v3.1.20260828-1", 0},
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

func TestServiceCheck_Success(t *testing.T) {
	mux := http.NewServeMux()

	// amneziawg-go tags
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260828"},
			{Name: "v3.1.20260814"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	// amneziawg-tools tags
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260812"},
			{Name: "v3.0.20260805"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	// amneziawg-tools releases
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/releases", func(w http.ResponseWriter, r *http.Request) {
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

	// amneziawg-go releases (returns 404 like production)
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/releases", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(
		WithBaseURL(srv.URL),
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

	if status.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=false, got true")
	}

	if len(status.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(status.Components))
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

	if status.BaseImage != PinnedAWGBaseImage {
		t.Errorf("expected BaseImage %q, got %q", PinnedAWGBaseImage, status.BaseImage)
	}
}

func TestServiceCheck_UpdateAvailable(t *testing.T) {
	mux := http.NewServeMux()

	// amneziawg-go has a newer tag: v3.1.20260930
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260930"},
			{Name: "v3.1.20260828"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		tags := []gitHubTag{
			{Name: "v3.1.20260812"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tags)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(WithBaseURL(srv.URL))

	status, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !status.UpdateAvailable {
		t.Errorf("expected overall UpdateAvailable=true")
	}

	if !status.Components[0].UpdateAvailable {
		t.Errorf("expected amneziawg-go UpdateAvailable=true")
	}

	if status.Components[0].LatestVersion != "v3.1.20260930" {
		t.Errorf("expected latest version v3.1.20260930, got %s", status.Components[0].LatestVersion)
	}

	if status.Components[1].UpdateAvailable {
		t.Errorf("expected amneziawg-tools UpdateAvailable=false")
	}
}

func TestServiceCheck_Caching(t *testing.T) {
	var requestCount int32

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260828"}})
	})
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260812"}})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(
		WithBaseURL(srv.URL),
		WithCacheTTL(1*time.Hour),
	)

	ctx := context.Background()

	// Initial fetch
	status1, err := svc.Check(ctx, false)
	if err != nil {
		t.Fatalf("first check error: %v", err)
	}
	initialRequests := atomic.LoadInt32(&requestCount)
	if initialRequests < 2 {
		t.Fatalf("expected at least 2 requests, got %d", initialRequests)
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

func TestServiceCheck_RateLimitAndErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message": "API rate limit exceeded"}`))
	})
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message": "Too many requests"}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(WithBaseURL(srv.URL))

	status, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("Check should not return fatal error on upstream rate limit: %v", err)
	}

	if status == nil {
		t.Fatal("expected non-nil status")
	}

	if status.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=false when errors occur")
	}

	for _, comp := range status.Components {
		if comp.Error == "" {
			t.Errorf("expected component %s to record rate-limit error", comp.Name)
		}
		if comp.LatestVersion != comp.PinnedVersion {
			t.Errorf("expected component %s to retain pinned version on error", comp.Name)
		}
	}
}

func TestServiceCheck_StaleCacheFallback(t *testing.T) {
	var shouldFail int32

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&shouldFail) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260828"}})
	})
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&shouldFail) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260812"}})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(
		WithBaseURL(srv.URL),
		WithCacheTTL(10*time.Millisecond),
	)

	// Step 1: Successful initial population
	initial, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("initial check failed: %v", err)
	}

	// Step 2: Expire cache and simulate server failure
	time.Sleep(20 * time.Millisecond)
	atomic.StoreInt32(&shouldFail, 1)

	// Step 3: Check should fallback to stale cache
	fallback, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("fallback check returned error: %v", err)
	}

	if fallback.CheckedAt != initial.CheckedAt {
		t.Errorf("expected fallback to return stale cache with original CheckedAt")
	}
}

func TestServiceCheck_MalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json}`))
	})
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(WithBaseURL(srv.URL))

	status, err := svc.Check(context.Background(), false)
	if err != nil {
		t.Fatalf("unexpected error on malformed JSON: %v", err)
	}

	if status.Components[0].Error == "" {
		t.Errorf("expected error recorded on malformed JSON")
	}
}

func TestServiceCheck_ConcurrencyAndRace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-go/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260828"}})
	})
	mux.HandleFunc("/repos/amnezia-vpn/amneziawg-tools/tags", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]gitHubTag{{Name: "v3.1.20260812"}})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewService(WithBaseURL(srv.URL))

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
