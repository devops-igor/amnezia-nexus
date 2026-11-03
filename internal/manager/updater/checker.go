package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultCacheTTL is the default cache duration for upstream release info (12 hours).
const DefaultCacheTTL = 12 * time.Hour

// DefaultBaseURL is the default GitHub API base URL.
const DefaultBaseURL = "https://api.github.com"

// minBackoff is the minimum backoff delay after rate limits or transient errors (5 minutes).
const minBackoff = 5 * time.Minute

// maxBackoff is the maximum backoff delay for rate limit schedules (1 hour).
const maxBackoff = 1 * time.Hour

// EngineType represents a supported proxy or engine backend.
type EngineType string

const (
	EngineXray              EngineType = "xray"
	EngineNaive             EngineType = "naive"
	EngineNaiveClient       EngineType = "naive-client"
	EngineCaddy             EngineType = "caddy"
	EngineCaddyCore         EngineType = "caddy"
	EngineNaiveForwardProxy EngineType = "naive-forwardproxy"
	EngineSingBox           EngineType = "sing-box"
)

// ReleaseInfo contains release metadata retrieved from an upstream repository.
type ReleaseInfo struct {
	Engine      EngineType `json:"engine"`
	Version     string     `json:"version"` // e.g. "v26.10.29" or "v1.8.24"
	ReleaseURL  string     `json:"release_url"`
	PublishedAt time.Time  `json:"published_at"`
	Prerelease  bool       `json:"prerelease"`
}

// EngineStatus describes the current installed and upstream version state for a proxy engine.
type EngineStatus struct {
	Protocol          string       `json:"protocol"` // e.g. "vless", "naive"
	InstalledVersion  string       `json:"installed_version"`
	LatestVersion     string       `json:"latest_version"`
	UpdateAvailable   bool         `json:"update_available"`
	UpstreamNewer     bool         `json:"upstream_newer"`
	UpgradeCompatible bool         `json:"upgrade_compatible"`
	Status            UpdateStatus `json:"status,omitempty"`
	Channel           string       `json:"channel,omitempty"`
	ReleaseURL        string       `json:"release_url"`
	CheckedAt         time.Time    `json:"checked_at"`
	RequestedAt       time.Time    `json:"requested_at"`
	IsStale           bool         `json:"is_stale"`
}

// DefaultRepoMap maps supported engines to their official upstream GitHub repositories.
var DefaultRepoMap = map[EngineType]string{
	EngineXray:              "XTLS/Xray-core",
	EngineNaive:             "klzgrad/naiveproxy",
	EngineNaiveClient:       "klzgrad/naiveproxy",
	EngineCaddy:             "caddyserver/caddy",
	EngineNaiveForwardProxy: "klzgrad/forwardproxy",
	EngineSingBox:           "SagerNet/sing-box",
}

// HTTPClient defines the minimum interface required to execute HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// cacheEntry holds cached release details along with ETag, timestamp, and backoff state.
type cacheEntry struct {
	release     ReleaseInfo
	etag        string
	fetchedAt   time.Time
	nextRetryAt time.Time
	isStale     bool
}

// githubReleaseResponse represents GitHub's release endpoint JSON payload.
type githubReleaseResponse struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
}

// ReleaseChecker queries and caches upstream release versions for proxy engines.
type ReleaseChecker struct {
	mu      sync.RWMutex
	cache   map[EngineType]cacheEntry
	ttl     time.Duration
	client  HTTPClient
	baseURL string
	repos   map[EngineType]string
	sfGroup singleflight.Group
	nowFunc func() time.Time
}

// Option configures a ReleaseChecker instance.
type Option func(*ReleaseChecker)

// WithHTTPClient sets a custom HTTP client (useful for mock testing).
func WithHTTPClient(client HTTPClient) Option {
	return func(r *ReleaseChecker) {
		if client != nil {
			r.client = client
		}
	}
}

// WithTTL sets a custom cache time-to-live duration.
func WithTTL(ttl time.Duration) Option {
	return func(r *ReleaseChecker) {
		if ttl > 0 {
			r.ttl = ttl
		}
	}
}

// WithBaseURL overrides the GitHub API base URL.
func WithBaseURL(baseURL string) Option {
	return func(r *ReleaseChecker) {
		if baseURL != "" {
			r.baseURL = baseURL
		}
	}
}

// WithRepoMap overrides the engine-to-repository mapping.
func WithRepoMap(repoMap map[EngineType]string) Option {
	return func(r *ReleaseChecker) {
		if repoMap != nil {
			r.repos = make(map[EngineType]string, len(repoMap))
			for k, v := range repoMap {
				r.repos[k] = v
			}
		}
	}
}

// WithTimeFunc overrides the time source function for deterministic testing.
func WithTimeFunc(fn func() time.Time) Option {
	return func(r *ReleaseChecker) {
		if fn != nil {
			r.nowFunc = fn
		}
	}
}

// NewReleaseChecker creates a new ReleaseChecker with the provided options.
func NewReleaseChecker(opts ...Option) *ReleaseChecker {
	checker := &ReleaseChecker{
		cache:   make(map[EngineType]cacheEntry),
		ttl:     DefaultCacheTTL,
		client:  &http.Client{Timeout: 15 * time.Second},
		baseURL: DefaultBaseURL,
		repos:   make(map[EngineType]string, len(DefaultRepoMap)),
		nowFunc: time.Now,
	}

	for k, v := range DefaultRepoMap {
		checker.repos[k] = v
	}

	for _, opt := range opts {
		opt(checker)
	}

	return checker
}

func (r *ReleaseChecker) now() time.Time {
	if r.nowFunc != nil {
		return r.nowFunc()
	}
	return time.Now()
}

// ProtocolForEngine returns the canonical protocol name associated with the engine.
func ProtocolForEngine(engine EngineType) string {
	switch engine {
	case EngineXray:
		return "vless"
	case EngineNaive, EngineNaiveClient, EngineNaiveForwardProxy:
		return "naive"
	case EngineCaddy: // also covers EngineCaddyCore
		return "caddy"
	case EngineSingBox:
		return "sing-box"
	default:
		return string(engine)
	}
}

// SupportedEngines returns a list of supported EngineType constants.
func SupportedEngines() []EngineType {
	return []EngineType{
		EngineXray,
		EngineNaive,
		EngineNaiveClient,
		EngineCaddy,
		EngineNaiveForwardProxy,
		EngineSingBox,
	}
}

// GetCachedRelease returns the cached release info for an engine if present.
func (r *ReleaseChecker) GetCachedRelease(engine EngineType) (ReleaseInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.cache[engine]
	if !ok {
		return ReleaseInfo{}, false
	}
	return entry.release, true
}

// NextRetryAt returns the scheduled backoff retry time for an engine, or a zero time if not in backoff.
func (r *ReleaseChecker) NextRetryAt(engine EngineType) time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cache[engine].nextRetryAt
}

// SetCachedRelease manually sets a cache entry (useful for tests or seeding).
func (r *ReleaseChecker) SetCachedRelease(engine EngineType, info ReleaseInfo, etag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[engine] = cacheEntry{
		release:     info,
		etag:        etag,
		fetchedAt:   r.now(),
		nextRetryAt: time.Time{},
		isStale:     false,
	}
}

// ClearCache evicts all cached release entries.
func (r *ReleaseChecker) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[EngineType]cacheEntry)
}

// CheckOption configures behavior for an engine check call.
type CheckOption func(*checkOptions)

type checkOptions struct {
	profile string
}

// WithProfile specifies an engine compatibility profile (e.g. "legacy", "modern_pq").
func WithProfile(profile string) CheckOption {
	return func(o *checkOptions) {
		o.profile = profile
	}
}

// WithCheckProfile is an alias for WithProfile.
func WithCheckProfile(profile string) CheckOption {
	return WithProfile(profile)
}

// CheckEngineWithProfile checks engine update status with an explicit profile channel.
func (r *ReleaseChecker) CheckEngineWithProfile(ctx context.Context, engine EngineType, installedVersion, profile string) (EngineStatus, error) {
	return r.CheckEngine(ctx, engine, installedVersion, WithProfile(profile))
}

// CheckEngine checks if an update is available for the given engine and installed version.
// It leverages caching, ETag validation, and falls back to last-known-good cached data
// when encountering rate limits or network issues.
func (r *ReleaseChecker) CheckEngine(ctx context.Context, engine EngineType, installedVersion string, opts ...CheckOption) (EngineStatus, error) {
	var co checkOptions
	for _, opt := range opts {
		opt(&co)
	}

	requestedAt := r.now()
	info, err := r.GetLatestRelease(ctx, engine)
	if err != nil {
		return EngineStatus{}, err
	}

	r.mu.RLock()
	entry := r.cache[engine]
	r.mu.RUnlock()

	checkedAt := entry.fetchedAt
	if checkedAt.IsZero() {
		checkedAt = requestedAt
	}

	isStale := entry.isStale
	if requestedAt.Sub(entry.fetchedAt) >= r.ttl {
		isStale = true
	}

	status := CheckUpdateStatus(installedVersion, info.Version)

	var upstreamNewer bool
	var upgradeCompatible bool
	var updateAvailable bool

	switch status {
	case UpdateUnknown:
		upstreamNewer = false
		upgradeCompatible = false
		updateAvailable = false
	case UpdateAvailable:
		upstreamNewer = true
		upgradeCompatible = isProfileCompatible(engine, co.profile, info.Version)
		updateAvailable = upstreamNewer && upgradeCompatible
	case UpdateUpToDate:
		upstreamNewer = false
		upgradeCompatible = true
		updateAvailable = false
	}

	return EngineStatus{
		Protocol:          ProtocolForEngine(engine),
		InstalledVersion:  installedVersion,
		LatestVersion:     info.Version,
		UpdateAvailable:   updateAvailable,
		UpstreamNewer:     upstreamNewer,
		UpgradeCompatible: upgradeCompatible,
		Status:            status,
		Channel:           co.profile,
		ReleaseURL:        info.ReleaseURL,
		CheckedAt:         checkedAt,
		RequestedAt:       requestedAt,
		IsStale:           isStale,
	}, nil
}

func isProfileCompatible(engine EngineType, profile, upstreamTag string) bool {
	if engine != EngineXray {
		return true
	}
	norm := strings.ToLower(strings.TrimSpace(profile))
	if norm == "" {
		return true
	}

	vLat, err := ParseVersion(upstreamTag)
	if err != nil {
		return true
	}

	switch {
	case norm == "legacy" || norm == "legacy_baseline" || norm == "baseline" || norm == "1.8.24" || norm == "v1.8.24":
		return vLat.Major() < 20
	case norm == "modern_pq" || norm == "modern" || norm == "pq" || strings.HasPrefix(norm, "26.10.") || strings.HasPrefix(norm, "v26.10."):
		return vLat.Major() >= 20
	default:
		return true
	}
}

// GetLatestRelease retrieves the latest release info for the specified engine,
// using cache when valid, singleflight with decoupled context to coalesce concurrent requests, and
// falling back to last-known-good cache on upstream errors.
func (r *ReleaseChecker) GetLatestRelease(ctx context.Context, engine EngineType) (ReleaseInfo, error) {
	repo, ok := r.repos[engine]
	if !ok {
		return ReleaseInfo{}, fmt.Errorf("unsupported engine type: %q", engine)
	}

	if err := ctx.Err(); err != nil {
		return ReleaseInfo{}, err
	}

	now := r.now()

	// 1. Fast path: check if cache is valid under read lock.
	r.mu.RLock()
	entry, exists := r.cache[engine]
	r.mu.RUnlock()

	if exists {
		if now.Sub(entry.fetchedAt) < r.ttl {
			return entry.release, nil
		}
		if !entry.nextRetryAt.IsZero() && now.Before(entry.nextRetryAt) {
			if entry.release.Version != "" {
				return entry.release, nil
			}
			return ReleaseInfo{}, fmt.Errorf("upstream rate limit backoff active for %s until %s", engine, entry.nextRetryAt)
		}
	}

	// 2. Slow path: singleflight coalesce with decoupled context to prevent aborting sibling callers.
	key := string(engine)
	ch := r.sfGroup.DoChan(key, func() (any, error) {
		// Re-check cache inside singleflight in case another caller already refreshed it.
		r.mu.RLock()
		innerEntry, innerExists := r.cache[engine]
		r.mu.RUnlock()

		innerNow := r.now()
		if innerExists {
			if innerNow.Sub(innerEntry.fetchedAt) < r.ttl {
				return innerEntry.release, nil
			}
			if !innerEntry.nextRetryAt.IsZero() && innerNow.Before(innerEntry.nextRetryAt) {
				if innerEntry.release.Version != "" {
					return innerEntry.release, nil
				}
				return ReleaseInfo{}, fmt.Errorf("upstream rate limit backoff active for %s until %s", engine, innerEntry.nextRetryAt)
			}
		}

		fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer fetchCancel()

		return r.fetchRelease(fetchCtx, engine, repo, innerEntry.etag, innerExists, innerEntry.release)
	})

	select {
	case <-ctx.Done():
		return ReleaseInfo{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return ReleaseInfo{}, res.Err
		}
		return res.Val.(ReleaseInfo), nil
	}
}

// fetchRelease performs the HTTP request to GitHub releases API with ETag and fallback support.
func (r *ReleaseChecker) fetchRelease(
	ctx context.Context,
	engine EngineType,
	repo string,
	cachedEtag string,
	hasCached bool,
	cachedRelease ReleaseInfo,
) (ReleaseInfo, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/releases/latest", r.baseURL, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		if hasCached {
			return cachedRelease, nil
		}
		return ReleaseInfo{}, fmt.Errorf("failed to create release request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "amnezia-nexus-updater")
	if cachedEtag != "" {
		req.Header.Set("If-None-Match", cachedEtag)
	}

	// Mutex is deliberately NOT held during network I/O.
	resp, err := r.client.Do(req)
	now := r.now()
	if err != nil {
		nextRetry := calculateNextRetry(nil, now)
		r.mu.Lock()
		entry := r.cache[engine]
		entry.nextRetryAt = nextRetry
		entry.isStale = true
		r.cache[engine] = entry
		r.mu.Unlock()

		if hasCached {
			return cachedRelease, nil
		}
		return ReleaseInfo{}, fmt.Errorf("failed to fetch release for %s from upstream: %w", engine, err)
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified: refresh cache TTL without re-parsing body.
	if resp.StatusCode == http.StatusNotModified {
		r.mu.Lock()
		entry := r.cache[engine]
		entry.fetchedAt = now
		entry.nextRetryAt = time.Time{}
		entry.isStale = false
		if newETag := resp.Header.Get("ETag"); newETag != "" {
			entry.etag = newETag
		}
		r.cache[engine] = entry
		cachedRelease = entry.release
		r.mu.Unlock()
		return cachedRelease, nil
	}

	// Handle rate limits (403 Forbidden or 429 Too Many Requests).
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		nextRetry := calculateNextRetry(resp, now)
		r.mu.Lock()
		entry := r.cache[engine]
		entry.nextRetryAt = nextRetry
		entry.isStale = true
		r.cache[engine] = entry
		r.mu.Unlock()

		if hasCached {
			return cachedRelease, nil
		}
		return ReleaseInfo{}, fmt.Errorf("upstream rate limit exceeded for %s (status %d)", engine, resp.StatusCode)
	}

	// Handle successful release response (200 OK).
	if resp.StatusCode == http.StatusOK {
		var ghResp githubReleaseResponse
		if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
			nextRetry := calculateNextRetry(resp, now)
			r.mu.Lock()
			entry := r.cache[engine]
			entry.nextRetryAt = nextRetry
			entry.isStale = true
			r.cache[engine] = entry
			r.mu.Unlock()

			if hasCached {
				return cachedRelease, nil
			}
			return ReleaseInfo{}, fmt.Errorf("failed to decode release response for %s: %w", engine, err)
		}

		if ghResp.TagName == "" {
			nextRetry := calculateNextRetry(resp, now)
			r.mu.Lock()
			entry := r.cache[engine]
			entry.nextRetryAt = nextRetry
			entry.isStale = true
			r.cache[engine] = entry
			r.mu.Unlock()

			if hasCached {
				return cachedRelease, nil
			}
			return ReleaseInfo{}, errors.New("empty tag_name in release response")
		}

		releaseURL := ghResp.HTMLURL
		if releaseURL == "" {
			releaseURL = fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, ghResp.TagName)
		}

		newRelease := ReleaseInfo{
			Engine:      engine,
			Version:     ghResp.TagName,
			ReleaseURL:  releaseURL,
			PublishedAt: ghResp.PublishedAt,
			Prerelease:  ghResp.Prerelease,
		}

		r.mu.Lock()
		r.cache[engine] = cacheEntry{
			release:     newRelease,
			etag:        resp.Header.Get("ETag"),
			fetchedAt:   now,
			nextRetryAt: time.Time{},
			isStale:     false,
		}
		r.mu.Unlock()

		return newRelease, nil
	}

	// Any other upstream error code: backoff and fallback if cached, else fail.
	nextRetry := calculateNextRetry(resp, now)
	r.mu.Lock()
	entry := r.cache[engine]
	entry.nextRetryAt = nextRetry
	entry.isStale = true
	r.cache[engine] = entry
	r.mu.Unlock()

	if hasCached {
		return cachedRelease, nil
	}
	return ReleaseInfo{}, fmt.Errorf("upstream release query failed for %s with status %d", engine, resp.StatusCode)
}

func parseRetryAfter(header string, now time.Time) (time.Time, bool) {
	s := strings.TrimSpace(header)
	if s == "" {
		return time.Time{}, false
	}
	if secs, err := strconv.Atoi(s); err == nil && secs >= 0 {
		return now.Add(time.Duration(secs) * time.Second), true
	}
	if t, err := http.ParseTime(s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func parseRateLimitReset(header string) (time.Time, bool) {
	s := strings.TrimSpace(header)
	if s == "" {
		return time.Time{}, false
	}
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil && ts > 0 {
		return time.Unix(ts, 0), true
	}
	return time.Time{}, false
}

func calculateNextRetry(resp *http.Response, now time.Time) time.Time {
	maxTime := now.Add(maxBackoff)
	if resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden) {
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if t, ok := parseRetryAfter(retryAfter, now); ok && t.After(now) {
				if t.After(maxTime) {
					return maxTime
				}
				return t
			}
		}
		if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
			if t, ok := parseRateLimitReset(reset); ok && t.After(now) {
				if t.After(maxTime) {
					return maxTime
				}
				return t
			}
		}
	}
	return now.Add(minBackoff)
}
