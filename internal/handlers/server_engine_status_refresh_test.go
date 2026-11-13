package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/naive"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/manager/updater"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestResolveServerEngineStatusCached_ExpiredCacheTriggersBackgroundWarm verifies that
// when an expired cache entry is encountered during cached status resolution:
// 1. It returns immediately (non-blocking) with IsStale: true and preserving the original CheckedAt timestamp.
// 2. It triggers background singleflight warming that refreshes the cache from upstream.
// 3. Subsequent calls return the fresh release with IsStale: false.
func TestResolveServerEngineStatusCached_ExpiredCacheTriggersBackgroundWarm(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	upstreamSrv := newMockUpstreamEngineServer(t)
	defer upstreamSrv.Close()

	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	// Seed cache with an expired release (fetched 24 hours ago, past 12h TTL)
	expiredFetchedAt := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	oldRelease := updater.ReleaseInfo{
		Engine:      updater.EngineXray,
		Version:     "v1.8.20",
		ReleaseURL:  "https://github.com/XTLS/Xray-core/releases/tag/v1.8.20",
		PublishedAt: expiredFetchedAt,
	}
	checker.SetCachedReleaseWithTime(updater.EngineXray, oldRelease, "etag-old-xray", expiredFetchedAt, false)

	if !checker.IsCacheExpired(updater.EngineXray) {
		t.Fatalf("expected checker.IsCacheExpired to be true for 24h old cache entry")
	}

	server := &models.Server{
		ID:   1001,
		Name: "Test Server Expired Cache",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"engine_profile": "legacy",
				"engine_version": "1.8.20",
			},
		},
	}

	// 1. Initial cached resolution: must return stale cached release immediately
	start := time.Now()
	statusMap := h.resolveServerEngineStatusCached(server)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("resolveServerEngineStatusCached took %v, expected non-blocking execution (<100ms)", elapsed)
	}
	if statusMap == nil {
		t.Fatalf("expected non-nil statusMap from cached resolution")
	}

	vlessStatus, ok := statusMap[models.ProtocolVLESS].(updater.EngineStatus)
	if !ok {
		t.Fatalf("expected EngineStatus for vless, got %T: %+v", statusMap[models.ProtocolVLESS], statusMap[models.ProtocolVLESS])
	}
	if !vlessStatus.IsStale {
		t.Errorf("expected IsStale = true for expired cache entry, got false")
	}
	if !vlessStatus.CheckedAt.Equal(expiredFetchedAt) {
		t.Errorf("expected CheckedAt = %v (true cached fetchedAt), got %v", expiredFetchedAt, vlessStatus.CheckedAt)
	}
	if vlessStatus.LatestVersion != "v1.8.20" {
		t.Errorf("expected LatestVersion = 'v1.8.20', got %q", vlessStatus.LatestVersion)
	}

	// 2. Wait for background singleflight warming to refresh cache from upstream
	refreshed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if !checker.IsCacheExpired(updater.EngineXray) {
			rel, ok := checker.GetCachedRelease(updater.EngineXray)
			if ok && rel.Version == "v26.10.31" {
				refreshed = true
				break
			}
		}
	}
	if !refreshed {
		t.Fatalf("background warming did not refresh the cache within timeout")
	}

	// 3. Subsequent cached resolution returns fresh status with IsStale: false
	freshMap := h.resolveServerEngineStatusCached(server)
	if freshMap == nil {
		t.Fatalf("expected non-nil statusMap after cache refresh")
	}
	freshVless, ok := freshMap[models.ProtocolVLESS].(updater.EngineStatus)
	if !ok {
		t.Fatalf("expected EngineStatus for vless, got %T", freshMap[models.ProtocolVLESS])
	}
	if freshVless.IsStale {
		t.Errorf("expected IsStale = false after cache refresh, got true")
	}
	if freshVless.LatestVersion != "v26.10.31" {
		t.Errorf("expected LatestVersion = 'v26.10.31', got %q", freshVless.LatestVersion)
	}
	if freshVless.CheckedAt.Before(start) {
		t.Errorf("expected refreshed CheckedAt to be after start %v, got %v", start, freshVless.CheckedAt)
	}
}

// TestNaiveMetadata_V2_11_7_Naive_ExposesUpdateAvailable verifies finding H2:
// NaiveProxy forwardproxy pinned commit c096d6a accurately maps to v2.11.7-naive,
// and comparing against upstream v2.11.7-naive2 reports UpdateAvailable = true.
func TestNaiveMetadata_V2_11_7_Naive_ExposesUpdateAvailable(t *testing.T) {
	cases := []struct {
		name          string
		meta          map[string]any
		expectedTag   string
		upstreamTag   string
		wantAvailable bool
	}{
		{
			name: "pinned commit c096d6a maps to v2.11.7-naive and reveals v2.11.7-naive2 upgrade",
			meta: map[string]any{
				"installed":      true,
				"caddy_version":  "2.8.4",
				"plugin_version": "c096d6a00cb28e019cc1995b04bdc6a9311d8024",
			},
			expectedTag:   "v2.11.7-naive",
			upstreamTag:   "v2.11.7-naive2",
			wantAvailable: true,
		},
		{
			name: "installed tag v2.11.7-naive reveals v2.11.7-naive2 upgrade",
			meta: map[string]any{
				"installed":      true,
				"caddy_version":  "2.8.4",
				"plugin_version": "v2.11.7-naive",
			},
			expectedTag:   "v2.11.7-naive",
			upstreamTag:   "v2.11.7-naive2",
			wantAvailable: true,
		},
		{
			name: "already updated to v2.11.7-naive2 reports up-to-date",
			meta: map[string]any{
				"installed":      true,
				"caddy_version":  "2.8.4",
				"plugin_version": "v2.11.7-naive2",
			},
			expectedTag:   "v2.11.7-naive2",
			upstreamTag:   "v2.11.7-naive2",
			wantAvailable: false,
		},
		{
			name: "nested params plugin_version with commit prefix c096d6a",
			meta: map[string]any{
				"installed": true,
				"params": map[string]any{
					"plugin_version": "c096d6a",
				},
			},
			expectedTag:   "v2.11.7-naive",
			upstreamTag:   "v2.11.7-naive2",
			wantAvailable: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extracted := extractNaivePluginVersion(tc.meta)
			if extracted != tc.expectedTag {
				t.Fatalf("extractNaivePluginVersion = %q, want %q", extracted, tc.expectedTag)
			}

			// Verify CheckUpdateStatus
			st := updater.CheckUpdateStatus(extracted, tc.upstreamTag)
			if tc.wantAvailable && st != updater.UpdateAvailable {
				t.Errorf("CheckUpdateStatus(%q, %q) = %q, want %q", extracted, tc.upstreamTag, st, updater.UpdateAvailable)
			}
			if !tc.wantAvailable && st != updater.UpdateUpToDate {
				t.Errorf("CheckUpdateStatus(%q, %q) = %q, want %q", extracted, tc.upstreamTag, st, updater.UpdateUpToDate)
			}
		})
	}
}

// TestNaiveMetadata_IntegrationWithHandlers verifies that both synchronous and cached resolution
// evaluate v2.11.7-naive installed version against upstream v2.11.7-naive2 with UpdateAvailable = true.
func TestNaiveMetadata_IntegrationWithHandlers(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	upstreamSrv := newMockUpstreamEngineServer(t)
	defer upstreamSrv.Close()

	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	server := &models.Server{
		ID:   2001,
		Name: "Test Naive Server",
		Protocols: map[string]any{
			models.ProtocolNaive: map[string]any{
				"installed":      true,
				"caddy_version":  "2.8.4",
				"plugin_version": "c096d6a00cb28e019cc1995b04bdc6a9311d8024",
			},
		},
	}

	// 1. Synchronous resolution
	syncMap := h.resolveServerEngineStatus(context.Background(), server)
	if syncMap == nil {
		t.Fatalf("expected non-nil syncMap")
	}
	naiveSync, ok := syncMap[models.ProtocolNaive].(updater.EngineStatus)
	if !ok {
		t.Fatalf("expected EngineStatus for naive")
	}
	if naiveSync.InstalledVersion != "v2.11.7-naive" {
		t.Errorf("expected InstalledVersion = 'v2.11.7-naive', got %q", naiveSync.InstalledVersion)
	}
	if naiveSync.LatestVersion != "v2.11.7-naive2" {
		t.Errorf("expected LatestVersion = 'v2.11.7-naive2', got %q", naiveSync.LatestVersion)
	}
	if !naiveSync.UpdateAvailable {
		t.Errorf("expected UpdateAvailable = true for naive plugin upgrade")
	}
	if !naiveSync.UpstreamNewer {
		t.Errorf("expected UpstreamNewer = true")
	}
	if !naiveSync.UpgradeCompatible {
		t.Errorf("expected UpgradeCompatible = true")
	}

	// 2. Cached resolution (cache was populated by synchronous call)
	cachedMap := h.resolveServerEngineStatusCached(server)
	if cachedMap == nil {
		t.Fatalf("expected non-nil cachedMap")
	}
	naiveCached, ok := cachedMap[models.ProtocolNaive].(updater.EngineStatus)
	if !ok {
		t.Fatalf("expected EngineStatus for naive in cachedMap")
	}
	if naiveCached.InstalledVersion != "v2.11.7-naive" {
		t.Errorf("expected InstalledVersion = 'v2.11.7-naive', got %q", naiveCached.InstalledVersion)
	}
	if naiveCached.LatestVersion != "v2.11.7-naive2" {
		t.Errorf("expected LatestVersion = 'v2.11.7-naive2', got %q", naiveCached.LatestVersion)
	}
	if !naiveCached.UpdateAvailable {
		t.Errorf("expected UpdateAvailable = true in cached resolution")
	}
	if naiveCached.IsStale {
		t.Errorf("expected IsStale = false for freshly cached entry")
	}
}

// TestReleaseChecker_IsCacheExpired tests cache freshness calculation directly.
func TestReleaseChecker_IsCacheExpired(t *testing.T) {
	checker := updater.NewReleaseChecker(updater.WithTTL(1 * time.Hour))

	// 1. Cold cache
	if !checker.IsCacheExpired(updater.EngineXray) {
		t.Errorf("expected cold cache to report expired = true")
	}

	// 2. Fresh entry (within TTL)
	now := time.Now()
	checker.SetCachedReleaseWithTime(
		updater.EngineXray,
		updater.ReleaseInfo{Engine: updater.EngineXray, Version: "v26.10.29"},
		"etag-fresh",
		now.Add(-10*time.Minute),
		false,
	)
	if checker.IsCacheExpired(updater.EngineXray) {
		t.Errorf("expected 10-minute-old cache with 1h TTL to report expired = false")
	}

	info, fetchedAt, isStale, ok := checker.GetCachedReleaseState(updater.EngineXray)
	if !ok || isStale || info.Version != "v26.10.29" {
		t.Errorf("unexpected GetCachedReleaseState: ok=%v, isStale=%v, info=%+v", ok, isStale, info)
	}
	if fetchedAt.IsZero() {
		t.Errorf("expected non-zero fetchedAt")
	}

	// 3. Expired entry (past TTL)
	checker.SetCachedReleaseWithTime(
		updater.EngineXray,
		updater.ReleaseInfo{Engine: updater.EngineXray, Version: "v26.10.29"},
		"etag-expired",
		now.Add(-2*time.Hour),
		false,
	)
	if !checker.IsCacheExpired(updater.EngineXray) {
		t.Errorf("expected 2-hour-old cache with 1h TTL to report expired = true")
	}
	_, _, isStale, ok = checker.GetCachedReleaseState(updater.EngineXray)
	if !ok || !isStale {
		t.Errorf("expected ok=true and isStale=true for expired entry, got ok=%v, isStale=%v", ok, isStale)
	}

	// 4. Stale-flagged entry even within TTL
	checker.SetCachedReleaseWithTime(
		updater.EngineXray,
		updater.ReleaseInfo{Engine: updater.EngineXray, Version: "v26.10.29"},
		"etag-stale",
		now.Add(-5*time.Minute),
		true,
	)
	if !checker.IsCacheExpired(updater.EngineXray) {
		t.Errorf("expected stale-flagged cache to report expired = true")
	}
}

// TestExtractXrayProfile_Conservative verifies Finding 5:
// extractXrayProfile returns "" (unknown) instead of "legacy" when profile cannot be established.
func TestExtractXrayProfile_Conservative(t *testing.T) {
	// 1. nil or empty metadata returns ""
	if p := extractXrayProfile(nil); p != "" {
		t.Errorf("expected empty profile for nil meta, got %q", p)
	}
	if p := extractXrayProfile(map[string]any{}); p != "" {
		t.Errorf("expected empty profile for empty meta, got %q", p)
	}

	// 2. Unestablished metadata without profile or modern prefix must return "" (no legacy assumption)
	cases := []map[string]any{
		{"installed": true},
		{"installed": true, "engine_version": "1.8.24"},
		{"installed": true, "running_engine_version": "1.8.24"},
		{"installed": true, "version": "v1.8.23"},
	}
	for i, c := range cases {
		if p := extractXrayProfile(c); p != "" {
			t.Errorf("case %d: expected empty profile, got %q", i, p)
		}
	}

	// 3. Explicit profile is preserved
	if p := extractXrayProfile(map[string]any{"engine_profile": "legacy"}); p != "legacy" {
		t.Errorf("expected legacy profile, got %q", p)
	}
	if p := extractXrayProfile(map[string]any{"engine_profile": "modern_pq"}); p != "modern_pq" {
		t.Errorf("expected modern_pq profile, got %q", p)
	}
	if p := extractXrayProfile(map[string]any{"params": map[string]any{"engine_profile": "custom"}}); p != "custom" {
		t.Errorf("expected custom profile from params, got %q", p)
	}

	// 4. Modern version prefixes (25.x, 26.x) map to modern_pq
	if p := extractXrayProfile(map[string]any{"running_engine_version": "26.10.29"}); p != "modern_pq" {
		t.Errorf("expected modern_pq for 26.x, got %q", p)
	}
	if p := extractXrayProfile(map[string]any{"running_engine_version": "v25.1.0"}); p != "modern_pq" {
		t.Errorf("expected modern_pq for v25.x, got %q", p)
	}
}

// TestTriggerBackgroundReleaseWarm_InFlightDeduplication verifies Finding 3:
// Concurrent calls to triggerBackgroundReleaseWarm for the same engine do not spawn
// redundant waiting goroutines and deduplicate in-flight operations.
func TestTriggerBackgroundReleaseWarm_InFlightDeduplication(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	fetchBlock := make(chan struct{})
	fetchCount := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetchCount++
		mu.Unlock()
		<-fetchBlock
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name":     "v26.10.29",
			"html_url":     "https://github.com/XTLS/Xray-core/releases/tag/v26.10.29",
			"published_at": time.Now().Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(srv.URL),
		updater.WithHTTPClient(srv.Client()),
	)

	// First trigger: spawns goroutine, marks in-flight
	h.triggerBackgroundReleaseWarm(checker, updater.EngineXray)

	// Wait for in-flight flag to be set
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		bgReleaseWarmMu.Lock()
		inFlight := bgReleaseWarmInFlight[updater.EngineXray]
		bgReleaseWarmMu.Unlock()
		if inFlight {
			break
		}
	}

	// Trigger multiple times while in-flight: all must be dropped as duplicates
	for i := 0; i < 5; i++ {
		h.triggerBackgroundReleaseWarm(checker, updater.EngineXray)
	}

	// Unblock upstream response
	close(fetchBlock)

	// Wait for in-flight to clear
	for deadline := time.Now().Add(1 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		bgReleaseWarmMu.Lock()
		inFlight := bgReleaseWarmInFlight[updater.EngineXray]
		bgReleaseWarmMu.Unlock()
		if !inFlight {
			break
		}
	}

	mu.Lock()
	totalFetches := fetchCount
	mu.Unlock()
	if totalFetches != 1 {
		t.Errorf("expected exactly 1 upstream fetch due to in-flight deduplication, got %d", totalFetches)
	}
}

// TestTriggerBackgroundReleaseWarm_RespectsBackoff verifies Finding 3:
// triggerBackgroundReleaseWarm respects NextRetryAt and does not spawn goroutines
// during active rate limit or failure backoff.
func TestTriggerBackgroundReleaseWarm_RespectsBackoff(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	var requestCount int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(srv.URL),
		updater.WithHTTPClient(srv.Client()),
	)

	// 1. Trigger initial failure so checker enters backoff
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = checker.GetLatestRelease(ctx, updater.EngineXray)

	nextRetry := checker.NextRetryAt(updater.EngineXray)
	if nextRetry.IsZero() || !time.Now().Before(nextRetry) {
		t.Fatalf("expected NextRetryAt to be scheduled in the future, got %v", nextRetry)
	}

	mu.Lock()
	initialRequests := requestCount
	mu.Unlock()

	// 2. Call triggerBackgroundReleaseWarm during backoff
	h.triggerBackgroundReleaseWarm(checker, updater.EngineXray)

	// Sleep briefly to confirm no background goroutine executes network call
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	afterRequests := requestCount
	mu.Unlock()

	if afterRequests != initialRequests {
		t.Errorf("expected no additional requests during backoff, got %d (was %d)", afterRequests, initialRequests)
	}

	bgReleaseWarmMu.Lock()
	inFlight := bgReleaseWarmInFlight[updater.EngineXray]
	bgReleaseWarmMu.Unlock()
	if inFlight {
		t.Errorf("expected in-flight to remain false during active backoff")
	}
}

type testGenericSSHPool struct {
	client ssh.SSHClient
}

func (p *testGenericSSHPool) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

type testCustomSSHClient struct {
	*testMockSSHClient
	fileExistsFn func(ctx context.Context, path string) (bool, error)
}

func (c *testCustomSSHClient) FileExists(ctx context.Context, path string) (bool, error) {
	if c.fileExistsFn != nil {
		return c.fileExistsFn(ctx, path)
	}
	return c.testMockSSHClient.FileExists(ctx, path)
}

// TestRuntimeVersionDetection_FailedDetectionLeavesVersionEmpty verifies Findings 1 & 2:
// 1. Failed runtime version detection returns "" and avoids saving guessed versions (2.8.4 / profile.Version).
// 2. Pinned forwardproxy version is strictly derived from build and rejects parameter overrides.
func TestRuntimeVersionDetection_FailedDetectionLeavesVersionEmpty(t *testing.T) {
	ctx := context.Background()

	// --- 1. Naive Manager ---
	t.Run("naive failed caddy detection leaves caddy_version unverified and locks plugin_version", func(t *testing.T) {
		mockSSH := &testMockSSHClient{
			cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
				if strings.Contains(cmd, "docker --version") {
					return "Docker version 24.0.5", "", 0, nil
				}
				if strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, ".State.Running") {
					return "true false 123\n", "", 0, nil
				}
				if strings.Contains(cmd, "caddy version") {
					// Simulate failed runtime version command
					return "", "command not found", 127, nil
				}
				if strings.Contains(cmd, "cat") && strings.Contains(cmd, "Caddyfile") {
					return naive.RenderCaddyfile(443, "127.0.0.1", nil), "", 0, nil
				}
				return "ok", "", 0, nil
			},
		}

		pool := &testGenericSSHPool{client: mockSSH}
		mgr := naive.NewNaiveManager(pool)
		server := &models.Server{
			ID:   3001,
			Host: "127.0.0.1",
		}

		err := mgr.Install(ctx, server, map[string]any{
			"port":           443,
			"caddy_version":  "9.9.9",            // Must NOT be accepted as fallback
			"plugin_version": "v99.0.0-override", // Must NOT override build source of truth
		})
		if err != nil {
			t.Fatalf("Install failed: %v", err)
		}

		naiveProto, ok := server.Protocols[models.ProtocolNaive].(map[string]any)
		if !ok {
			t.Fatalf("expected ProtocolNaive in server.Protocols")
		}

		// caddy_version must be absent or empty (NEVER 2.8.4 or 9.9.9)
		if cv, exists := naiveProto["caddy_version"]; exists && cv != "" {
			t.Errorf("expected caddy_version to be absent/empty on failed runtime detection, got %v", cv)
		}

		// plugin_version must be strictly v2.11.7-naive
		if pv, _ := naiveProto["plugin_version"].(string); pv != "v2.11.7-naive" {
			t.Errorf("expected plugin_version to be 'v2.11.7-naive', got %q", pv)
		}
	})

	// --- 2. Xray Manager ---
	t.Run("xray failed detection does not save running_engine_version fallback", func(t *testing.T) {
		baseMock := &testMockSSHClient{
			cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
				if strings.Contains(cmd, "docker --version") {
					return "Docker version 25.0.3", "", 0, nil
				}
				if strings.Contains(cmd, "xray version") {
					// Simulate failed runtime version detection
					return "", "exec failed", 1, nil
				}
				if strings.Contains(cmd, "docker inspect") {
					if strings.Contains(cmd, "{{.State.Restarting}}") {
						return "true false 123\n", "", 0, nil
					}
					// Pre-flight check: container does not exist
					return "", "Error: No such container: amnezia-xray", 1, nil
				}
				return "ok", "", 0, nil
			},
		}
		customSSH := &testCustomSSHClient{
			testMockSSHClient: baseMock,
			fileExistsFn: func(ctx context.Context, path string) (bool, error) {
				if strings.Contains(path, "config.json") {
					return false, nil // Fresh install: no pre-existing config
				}
				return true, nil
			},
		}

		pool := &testGenericSSHPool{client: customSSH}
		mgr := xray.NewXrayManager(pool)
		mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
			return 0, nil
		})
		server := &models.Server{
			ID:   3002,
			Host: "192.0.2.1",
		}

		err := mgr.Install(ctx, server, map[string]any{
			"port":           443,
			"engine_profile": "legacy",
		})
		if err != nil {
			t.Fatalf("Install failed: %v", err)
		}

		vlessProto, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
		if !ok {
			t.Fatalf("expected ProtocolVLESS in server.Protocols")
		}

		// running_engine_version must NOT be saved on failed runtime detection
		if rv, exists := vlessProto["running_engine_version"]; exists && rv != "" {
			t.Errorf("expected running_engine_version to NOT be set on failed detection, got %v", rv)
		}
	})
}

// TestNaiveManager_Install_E2E_PersistenceToAdminAPI verifies Finding 4:
// End-to-end integration executing NaiveManager.Install() with mocked SSH (mocking caddy version),
// persisting metadata to SQLite database, and calling the admin API handler to verify serialization.
func TestNaiveManager_Install_E2E_PersistenceToAdminAPI(t *testing.T) {
	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "docker --version") {
				return "Docker version 24.0.5", "", 0, nil
			}
			if strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, ".State.Running") {
				return "true false 123\n", "", 0, nil
			}
			if strings.Contains(cmd, "caddy version") {
				return "v2.8.4 (amnezia-caddy)\n", "", 0, nil
			}
			if strings.Contains(cmd, "cat") && strings.Contains(cmd, "Caddyfile") {
				return naive.RenderCaddyfile(443, "127.0.0.1", nil), "", 0, nil
			}
			return "ok", "", 0, nil
		},
	}

	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)

	// Upstream engine mock for updater
	upstreamSrv := newMockUpstreamEngineServer(t)
	defer upstreamSrv.Close()
	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	ctx := context.Background()

	// 1. Create server in SQLite database
	srv := &models.Server{
		Name:    "Naive-E2E-Integration-Server",
		Host:    "127.0.0.1",
		SSHPort: 22,
		SSHUser: "root",
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	srv.ID = serverID

	// 2. Execute NaiveManager.Install()
	naiveMgr := naive.NewNaiveManager(h.sshPool)
	installParams := map[string]any{
		"port":           443,
		"domain":         "127.0.0.1",
		"plugin_version": "should-be-ignored",
	}
	if err := naiveMgr.Install(ctx, srv, installParams); err != nil {
		t.Fatalf("naiveMgr.Install failed: %v", err)
	}

	// Verify in-memory server metadata
	meta, ok := srv.Protocols[models.ProtocolNaive].(map[string]any)
	if !ok {
		t.Fatalf("expected ProtocolNaive in server.Protocols after install")
	}
	if meta["caddy_version"] != "2.8.4" {
		t.Errorf("expected caddy_version = '2.8.4', got %v", meta["caddy_version"])
	}
	if meta["plugin_version"] != naive.NaiveForwardProxyVersion {
		t.Errorf("expected plugin_version = %q, got %v", naive.NaiveForwardProxyVersion, meta["plugin_version"])
	}

	// 3. Persist protocol metadata to real SQLite database
	if err := db.UpdateServerProtocols(ctx, srv.ID, srv.Protocols); err != nil {
		t.Fatalf("UpdateServerProtocols failed: %v", err)
	}

	// 4. Initial call: cold cache returns non-blocking and triggers background warm
	req1 := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	req1 = req1.WithContext(middleware.WithSession(req1.Context(), &models.SessionData{
		UserID: "admin-1",
		Role:   models.RoleAdmin,
	}))
	w1 := httptest.NewRecorder()
	h.ListServersHandler(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("ListServersHandler returned %d: %s", w1.Code, w1.Body.String())
	}

	// 5. Wait for background warm to populate cache from mock upstream
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if !checker.IsCacheExpired(updater.EngineNaiveForwardProxy) && !checker.IsCacheExpired(updater.EngineCaddyCore) {
			break
		}
	}

	// 6. Second call: cached release is now available
	req2 := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{
		UserID: "admin-1",
		Role:   models.RoleAdmin,
	}))
	w2 := httptest.NewRecorder()
	h.ListServersHandler(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("ListServersHandler (warmed) returned %d: %s", w2.Code, w2.Body.String())
	}

	// 7. Decode response and verify EngineStatus
	var servers []models.ServerItemResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &servers); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	var found *models.ServerItemResponse
	for i := range servers {
		if servers[i].ID == srv.ID {
			found = &servers[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("server %d not found in ListServersHandler response", srv.ID)
	}

	if found.EngineStatus == nil {
		t.Fatalf("expected EngineStatus to be populated for admin, got nil")
	}

	caddyStatus, ok := found.EngineStatus["caddy"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'caddy' in EngineStatus, got %+v", found.EngineStatus)
	}
	if caddyStatus["installed_version"] != "2.8.4" {
		t.Errorf("expected caddy installed_version = '2.8.4', got %v", caddyStatus["installed_version"])
	}

	naiveStatus, ok := found.EngineStatus[models.ProtocolNaive].(map[string]any)
	if !ok {
		t.Fatalf("expected %q in EngineStatus, got %+v", models.ProtocolNaive, found.EngineStatus)
	}
	if naiveStatus["installed_version"] != naive.NaiveForwardProxyVersion {
		t.Errorf("expected naive installed_version = %q, got %v", naive.NaiveForwardProxyVersion, naiveStatus["installed_version"])
	}
	if naiveStatus["latest_version"] != "v2.11.7-naive2" {
		t.Errorf("expected naive latest_version = 'v2.11.7-naive2', got %v", naiveStatus["latest_version"])
	}
	// A fresh install must not advertise an upgrade against the release it was
	// built from: that was the reported bug when plugin_version lagged the image.
	if upd, _ := naiveStatus["update_available"].(bool); upd {
		t.Errorf("expected naive update_available = false for a current install, got %v", upd)
	}
}

// TestXrayManager_Reinstall_FailedDetection_InvalidatesRunningVersion verifies Finding R5-H1:
// When reinstalling/switching Xray on a server with an existing running_engine_version,
// if runtime version detection fails on the replaced container, the old running_engine_version
// is invalidated (removed from metadata and nested params). When persisted to SQLite and retrieved
// by the admin API, the new profile's static engine version is reported without false update_available.
func TestXrayManager_Reinstall_FailedDetection_InvalidatesRunningVersion(t *testing.T) {
	ctx := context.Background()

	priv, _, err := xray.GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair failed: %v", err)
	}
	renderedCfg, err := xray.RenderXrayConfig(443, 54321, "example.com", "example.com:443", priv, []string{"0123456789abcdef"}, nil)
	if err != nil {
		t.Fatalf("RenderXrayConfig failed: %v", err)
	}

	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			switch {
			case strings.Contains(cmd, "docker --version"):
				return "Docker version 25.0.3", "", 0, nil
			case strings.Contains(cmd, "xray version"):
				// Simulate failed runtime version detection on the new container
				return "", "exec failed", 1, nil
			case strings.Contains(cmd, "cat") && strings.Contains(cmd, "config.json"):
				return string(renderedCfg), "", 0, nil
			case strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, "{{.State.Restarting}}"):
				// Readiness check: running and not restarting
				return "true false 123\n", "", 0, nil
			case strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, "{{.State.Running}}"):
				// Container exists and is running
				return "true\n", "", 0, nil
			default:
				return "ok", "", 0, nil
			}
		},
		downloadFn: func(ctx context.Context, path string) ([]byte, error) {
			if strings.Contains(path, "config.json") {
				return renderedCfg, nil
			}
			return []byte("ok"), nil
		},
	}

	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)

	upstreamSrv := newMockUpstreamEngineServer(t)
	defer upstreamSrv.Close()
	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	// 1. Create server in SQLite database with existing legacy Xray and running_engine_version
	srv := &models.Server{
		Name:    "Xray-Replacement-Server",
		Host:    "127.0.0.1",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":              true,
				"port":                   443,
				"server_name":            "example.com",
				"engine_profile":         "legacy",
				"engine_version":         "1.8.24",
				"running_engine_version": "1.8.24",
				"params": map[string]any{
					"port":                   443,
					"server_name":            "example.com",
					"engine_profile":         "legacy",
					"running_engine_version": "1.8.24",
				},
			},
		},
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	srv.ID = serverID

	// 2. Execute XrayManager.Install() switching profile to Modern PQ, where runtime version detection fails
	xrayMgr := xray.NewXrayManager(h.sshPool)
	xrayMgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		return 0, nil
	})

	switchParams := map[string]any{
		"engine_profile": "modern_pq",
	}
	if err := xrayMgr.Install(ctx, srv, switchParams); err != nil {
		t.Fatalf("xrayMgr.Install failed: %v", err)
	}

	// 3. Verify in-memory server metadata: old running_engine_version must be invalidated
	meta, ok := srv.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected ProtocolVLESS in server.Protocols after install")
	}
	if rv, exists := meta["running_engine_version"]; exists && rv != "" {
		t.Errorf("expected running_engine_version to be deleted from protoMeta, got %v", rv)
	}
	if pMap, ok := meta["params"].(map[string]any); ok {
		if rv, exists := pMap["running_engine_version"]; exists && rv != "" {
			t.Errorf("expected running_engine_version to be deleted from params, got %v", rv)
		}
	}
	if meta["engine_profile"] != "modern_pq" {
		t.Errorf("expected engine_profile = 'modern_pq', got %v", meta["engine_profile"])
	}
	if meta["engine_version"] != xray.XrayModernPQVersion {
		t.Errorf("expected engine_version = %q, got %v", xray.XrayModernPQVersion, meta["engine_version"])
	}

	// 4. Persist protocol metadata to real SQLite database
	if err := db.UpdateServerProtocols(ctx, srv.ID, srv.Protocols); err != nil {
		t.Fatalf("UpdateServerProtocols failed: %v", err)
	}

	// 5. Initial call: cold cache returns non-blocking and triggers background warm
	req1 := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	req1 = req1.WithContext(middleware.WithSession(req1.Context(), &models.SessionData{
		UserID: "admin-1",
		Role:   models.RoleAdmin,
	}))
	w1 := httptest.NewRecorder()
	h.ListServersHandler(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("ListServersHandler returned %d: %s", w1.Code, w1.Body.String())
	}

	// 6. Wait for background warm to populate cache from mock upstream
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if !checker.IsCacheExpired(updater.EngineXray) {
			break
		}
	}

	// 7. Second call: cached release is now available
	req2 := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	req2 = req2.WithContext(middleware.WithSession(req2.Context(), &models.SessionData{
		UserID: "admin-1",
		Role:   models.RoleAdmin,
	}))
	w2 := httptest.NewRecorder()
	h.ListServersHandler(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("ListServersHandler (warmed) returned %d: %s", w2.Code, w2.Body.String())
	}

	// 8. Decode response and verify EngineStatus
	var servers []models.ServerItemResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &servers); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	var found *models.ServerItemResponse
	for i := range servers {
		if servers[i].ID == srv.ID {
			found = &servers[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("server %d not found in ListServersHandler response", srv.ID)
	}
	if found.EngineStatus == nil {
		t.Fatalf("expected EngineStatus to be populated for admin, got nil")
	}

	vlessStatus, ok := found.EngineStatus[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected %q in EngineStatus, got %+v", models.ProtocolVLESS, found.EngineStatus)
	}
	// Must report new profile version (the current modern pin), NOT retired "1.8.24"
	if vlessStatus["installed_version"] != xray.XrayModernPQVersion {
		t.Errorf("expected vless installed_version = %q, got %v", xray.XrayModernPQVersion, vlessStatus["installed_version"])
	}
	if vlessStatus["latest_version"] != "v26.10.31" {
		t.Errorf("expected vless latest_version = 'v26.10.31', got %v", vlessStatus["latest_version"])
	}
	// Must NOT report false update_available!
	if upd, _ := vlessStatus["update_available"].(bool); upd {
		t.Errorf("expected vless update_available = false, got %v (old running_engine_version leaked!)", upd)
	}
}
