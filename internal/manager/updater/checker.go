package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultCacheTTL is the default cache duration for upstream release info (12 hours).
const DefaultCacheTTL = 12 * time.Hour

// DefaultBaseURL is the default GitHub API base URL.
const DefaultBaseURL = "https://api.github.com"

// EngineType represents a supported proxy or engine backend.
type EngineType string

const (
	EngineXray    EngineType = "xray"
	EngineNaive   EngineType = "naive"
	EngineCaddy   EngineType = "caddy"
	EngineSingBox EngineType = "sing-box"
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
	Protocol         string    `json:"protocol"` // e.g. "vless", "naive"
	InstalledVersion string    `json:"installed_version"`
	LatestVersion    string    `json:"latest_version"`
	UpdateAvailable  bool      `json:"update_available"`
	ReleaseURL       string    `json:"release_url"`
	CheckedAt        time.Time `json:"checked_at"`
}

// DefaultRepoMap maps supported engines to their official upstream GitHub repositories.
var DefaultRepoMap = map[EngineType]string{
	EngineXray:    "XTLS/Xray-core",
	EngineNaive:   "klzgrad/naiveproxy",
	EngineCaddy:   "caddyserver/caddy",
	EngineSingBox: "SagerNet/sing-box",
}

// HTTPClient defines the minimum interface required to execute HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// cacheEntry holds cached release details along with ETag and timestamp.
type cacheEntry struct {
	release   ReleaseInfo
	etag      string
	fetchedAt time.Time
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
	case EngineNaive:
		return "naive"
	case EngineCaddy:
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
		EngineCaddy,
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

// SetCachedRelease manually sets a cache entry (useful for tests or seeding).
func (r *ReleaseChecker) SetCachedRelease(engine EngineType, info ReleaseInfo, etag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[engine] = cacheEntry{
		release:   info,
		etag:      etag,
		fetchedAt: r.now(),
	}
}

// ClearCache evicts all cached release entries.
func (r *ReleaseChecker) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[EngineType]cacheEntry)
}

// CheckEngine checks if an update is available for the given engine and installed version.
// It leverages caching, ETag validation, and falls back to last-known-good cached data
// when encountering rate limits or network issues.
func (r *ReleaseChecker) CheckEngine(ctx context.Context, engine EngineType, installedVersion string) (EngineStatus, error) {
	info, err := r.GetLatestRelease(ctx, engine)
	if err != nil {
		return EngineStatus{}, err
	}

	return EngineStatus{
		Protocol:         ProtocolForEngine(engine),
		InstalledVersion: installedVersion,
		LatestVersion:    info.Version,
		UpdateAvailable:  IsUpdateAvailable(installedVersion, info.Version),
		ReleaseURL:       info.ReleaseURL,
		CheckedAt:        r.now(),
	}, nil
}

// GetLatestRelease retrieves the latest release info for the specified engine,
// using cache when valid, singleflight to coalesce concurrent requests, and
// falling back to last-known-good cache on upstream errors.
func (r *ReleaseChecker) GetLatestRelease(ctx context.Context, engine EngineType) (ReleaseInfo, error) {
	repo, ok := r.repos[engine]
	if !ok {
		return ReleaseInfo{}, fmt.Errorf("unsupported engine type: %q", engine)
	}

	// 1. Fast path: check if cache is valid under read lock.
	r.mu.RLock()
	entry, exists := r.cache[engine]
	r.mu.RUnlock()

	now := r.now()
	if exists && now.Sub(entry.fetchedAt) < r.ttl {
		return entry.release, nil
	}

	// 2. Slow path: singleflight coalesce to prevent cache stampedes.
	key := string(engine)
	res, err, _ := r.sfGroup.Do(key, func() (any, error) {
		// Re-check cache inside singleflight in case another caller already refreshed it.
		r.mu.RLock()
		innerEntry, innerExists := r.cache[engine]
		r.mu.RUnlock()

		innerNow := r.now()
		if innerExists && innerNow.Sub(innerEntry.fetchedAt) < r.ttl {
			return innerEntry.release, nil
		}

		return r.fetchRelease(ctx, engine, repo, innerEntry.etag, innerExists, innerEntry.release)
	})
	if err != nil {
		return ReleaseInfo{}, err
	}

	return res.(ReleaseInfo), nil
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
	if err != nil {
		if hasCached {
			return cachedRelease, nil
		}
		return ReleaseInfo{}, fmt.Errorf("failed to fetch release for %s from upstream: %w", engine, err)
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified: refresh cache TTL without re-parsing body.
	if resp.StatusCode == http.StatusNotModified {
		r.mu.Lock()
		if entry, ok := r.cache[engine]; ok {
			entry.fetchedAt = r.now()
			if newETag := resp.Header.Get("ETag"); newETag != "" {
				entry.etag = newETag
			}
			r.cache[engine] = entry
			cachedRelease = entry.release
		}
		r.mu.Unlock()
		return cachedRelease, nil
	}

	// Handle rate limits (403 Forbidden or 429 Too Many Requests).
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if hasCached {
			return cachedRelease, nil
		}
		return ReleaseInfo{}, fmt.Errorf("upstream rate limit exceeded for %s (status %d)", engine, resp.StatusCode)
	}

	// Handle successful release response (200 OK).
	if resp.StatusCode == http.StatusOK {
		var ghResp githubReleaseResponse
		if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
			if hasCached {
				return cachedRelease, nil
			}
			return ReleaseInfo{}, fmt.Errorf("failed to decode release response for %s: %w", engine, err)
		}

		if ghResp.TagName == "" {
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
			release:   newRelease,
			etag:      resp.Header.Get("ETag"),
			fetchedAt: r.now(),
		}
		r.mu.Unlock()

		return newRelease, nil
	}

	// Any other upstream error code: fallback if cached, else fail.
	if hasCached {
		return cachedRelease, nil
	}
	return ReleaseInfo{}, fmt.Errorf("upstream release query failed for %s with status %d", engine, resp.StatusCode)
}
