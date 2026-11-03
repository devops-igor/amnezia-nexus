package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/updater"
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
			if ok && rel.Version == "v26.10.29" {
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
	if freshVless.LatestVersion != "v26.10.29" {
		t.Errorf("expected LatestVersion = 'v26.10.29', got %q", freshVless.LatestVersion)
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
