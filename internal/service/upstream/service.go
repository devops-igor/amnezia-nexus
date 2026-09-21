package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pinned upstream component versions and container base image.
const (
	PinnedAWGGoVersion    = "v3.1.20260828"
	PinnedAWGToolsVersion = "v3.1.20260812"
	PinnedAWGBaseImage    = "devopsigor/amneziawg:v3.1.20260828-1"

	DefaultCacheTTL = 1 * time.Hour
	DefaultTimeout  = 10 * time.Second
	UserAgent       = "amnezia-nexus/1.2.1"
)

// ComponentStatus represents the upstream status of a single AmneziaWG component.
type ComponentStatus struct {
	Name            string    `json:"name"`
	Repo            string    `json:"repo"`
	PinnedVersion   string    `json:"pinned_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url"`
	PublishedAt     time.Time `json:"published_at,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// UpstreamStatus encapsulates the aggregated status of all upstream components.
//
//nolint:revive // Stutter is permitted to strictly adhere to task specification
type UpstreamStatus struct {
	CheckedAt       time.Time         `json:"checked_at"`
	UpdateAvailable bool              `json:"update_available"`
	Components      []ComponentStatus `json:"components"`
	BaseImage       string            `json:"base_image"`
}

// Service queries and caches upstream release metadata.
type Service struct {
	mu         sync.RWMutex
	cached     *UpstreamStatus
	cachedAt   time.Time
	cacheTTL   time.Duration
	httpClient *http.Client
	baseURL    string
	token      string
}

// Option configures a Service instance.
type Option func(*Service)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Service) {
		if client != nil {
			s.httpClient = client
		}
	}
}

// WithBaseURL overrides the GitHub API base URL (useful for testing).
func WithBaseURL(url string) Option {
	return func(s *Service) {
		s.baseURL = strings.TrimRight(url, "/")
	}
}

// WithCacheTTL overrides the default cache TTL.
func WithCacheTTL(ttl time.Duration) Option {
	return func(s *Service) {
		s.cacheTTL = ttl
	}
}

// WithToken sets an explicit GitHub token for authentication.
func WithToken(token string) Option {
	return func(s *Service) {
		s.token = token
	}
}

// NewService creates a new upstream Service instance.
func NewService(opts ...Option) *Service {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	s := &Service{
		cacheTTL: DefaultCacheTTL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: "https://api.github.com",
		token:   token,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// CompareVersions compares two version strings v1 and v2.
// Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
// It handles semantic versions (e.g. "v1.2.3") and calendar-version strings (e.g. "v3.1.20260828").
func CompareVersions(v1, v2 string) int {
	norm1 := normalizeVersion(v1)
	norm2 := normalizeVersion(v2)

	if norm1 == norm2 {
		return 0
	}

	segs1 := splitSegments(v1)
	segs2 := splitSegments(v2)

	minLen := len(segs1)
	if len(segs2) < minLen {
		minLen = len(segs2)
	}

	for i := 0; i < minLen; i++ {
		s1 := segs1[i]
		s2 := segs2[i]

		cmp := compareSegment(s1, s2)
		if cmp != 0 {
			return cmp
		}
	}

	if len(segs1) > len(segs2) {
		for i := minLen; i < len(segs1); i++ {
			if isPrerelease(segs1[i]) {
				return -1
			}
			if isNonZero(segs1[i]) {
				return 1
			}
		}
		return 0
	}

	if len(segs2) > len(segs1) {
		for i := minLen; i < len(segs2); i++ {
			if isPrerelease(segs2[i]) {
				return 1
			}
			if isNonZero(segs2[i]) {
				return -1
			}
		}
		return 0
	}

	return 0
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if idx := strings.LastIndex(v, ":"); idx != -1 {
		v = v[idx+1:]
	}
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return v
}

func splitSegments(v string) []string {
	norm := normalizeVersion(v)
	if norm == "" {
		return nil
	}
	return strings.FieldsFunc(norm, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == '+'
	})
}

func compareSegment(s1, s2 string) int {
	if s1 == s2 {
		return 0
	}

	n1, err1 := strconv.ParseUint(s1, 10, 64)
	n2, err2 := strconv.ParseUint(s2, 10, 64)

	if err1 == nil && err2 == nil {
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
		return 0
	}

	prefix1, num1, ok1 := splitPrefixAndNumber(s1)
	prefix2, num2, ok2 := splitPrefixAndNumber(s2)
	if ok1 && ok2 && prefix1 == prefix2 {
		if num1 < num2 {
			return -1
		}
		if num1 > num2 {
			return 1
		}
		return 0
	}

	if err1 == nil && isPrerelease(s2) {
		return 1
	}
	if err2 == nil && isPrerelease(s1) {
		return -1
	}

	if s1 < s2 {
		return -1
	}
	if s1 > s2 {
		return 1
	}
	return 0
}

func splitPrefixAndNumber(s string) (string, uint64, bool) {
	nonDigits := strings.TrimRight(s, "0123456789")
	if nonDigits == s || nonDigits == "" {
		return "", 0, false
	}
	numStr := strings.TrimPrefix(s, nonDigits)
	num, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return strings.ToLower(nonDigits), num, true
}

func isPrerelease(seg string) bool {
	lower := strings.ToLower(seg)
	for _, p := range []string{"alpha", "beta", "rc", "dev", "pre", "preview"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func isNonZero(seg string) bool {
	n, err := strconv.ParseUint(seg, 10, 64)
	if err == nil {
		return n > 0
	}
	return true
}

type gitHubTag struct {
	Name string `json:"name"`
}

type gitHubRelease struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
}

func (s *Service) newRequest(ctx context.Context, endpoint string) (*http.Request, error) {
	url := fmt.Sprintf("%s/%s", s.baseURL, strings.TrimPrefix(endpoint, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	return req, nil
}

func (s *Service) queryGitHubTags(ctx context.Context, repo string) ([]string, error) {
	endpoint := fmt.Sprintf("repos/%s/tags?per_page=10", repo)
	req, err := s.newRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error querying tags for %s: %w", repo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GitHub API rate limit exceeded (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API tags returned HTTP %d for %s", resp.StatusCode, repo)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var tags []gitHubTag
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("decoding tags JSON: %w", err)
	}

	result := make([]string, 0, len(tags))
	for _, t := range tags {
		name := strings.TrimSpace(t.Name)
		if name != "" {
			result = append(result, name)
		}
	}

	return result, nil
}

func (s *Service) queryGitHubReleases(ctx context.Context, repo string) ([]gitHubRelease, error) {
	endpoint := fmt.Sprintf("repos/%s/releases?per_page=5", repo)
	req, err := s.newRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("releases HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var releases []gitHubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, err
	}

	return releases, nil
}

func (s *Service) queryComponent(ctx context.Context, repo string) (string, time.Time, string, error) {
	tags, err := s.queryGitHubTags(ctx, repo)
	if err != nil {
		return "", time.Time{}, "", err
	}

	var maxTag string
	for _, tag := range tags {
		norm := normalizeVersion(tag)
		if norm == "" || (norm[0] < '0' || norm[0] > '9') {
			continue
		}
		if maxTag == "" || CompareVersions(tag, maxTag) > 0 {
			maxTag = tag
		}
	}

	if maxTag == "" {
		if len(tags) > 0 {
			maxTag = tags[0]
		} else {
			return "", time.Time{}, "", fmt.Errorf("no tags found for %s", repo)
		}
	}

	releaseURL := fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, maxTag)
	var publishedAt time.Time

	// Attempt to get published_at from releases if available
	releases, relErr := s.queryGitHubReleases(ctx, repo)
	if relErr == nil {
		for _, r := range releases {
			if strings.EqualFold(normalizeVersion(r.TagName), normalizeVersion(maxTag)) {
				if !r.PublishedAt.IsZero() {
					publishedAt = r.PublishedAt
				}
				if r.HTMLURL != "" {
					releaseURL = r.HTMLURL
				}
				break
			}
		}
	}

	return maxTag, publishedAt, releaseURL, nil
}

func (s *Service) fetchComponent(ctx context.Context, name, repo, pinnedVersion string) ComponentStatus {
	status := ComponentStatus{
		Name:          name,
		Repo:          repo,
		PinnedVersion: pinnedVersion,
		LatestVersion: pinnedVersion,
		ReleaseURL:    fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, pinnedVersion),
	}

	latestTag, publishedAt, releaseURL, err := s.queryComponent(ctx, repo)
	if err != nil {
		status.Error = err.Error()
		return status
	}

	status.LatestVersion = latestTag
	if releaseURL != "" {
		status.ReleaseURL = releaseURL
	}
	if !publishedAt.IsZero() {
		status.PublishedAt = publishedAt
	}

	status.UpdateAvailable = CompareVersions(latestTag, pinnedVersion) > 0
	return status
}

// Check queries upstream component statuses, respecting the 1-hour cache unless forceRefresh is true.
func (s *Service) Check(ctx context.Context, forceRefresh bool) (*UpstreamStatus, error) {
	s.mu.RLock()
	if !forceRefresh && s.cached != nil && time.Since(s.cachedAt) < s.cacheTTL {
		cachedCopy := s.cloneStatus(s.cached)
		s.mu.RUnlock()
		return cachedCopy, nil
	}
	stale := s.cached
	s.mu.RUnlock()

	goStatus := s.fetchComponent(ctx, "amneziawg-go", "amnezia-vpn/amneziawg-go", PinnedAWGGoVersion)
	toolsStatus := s.fetchComponent(ctx, "amneziawg-tools", "amnezia-vpn/amneziawg-tools", PinnedAWGToolsVersion)

	// If both components returned an error and a stale cache is available, return stale cache
	if goStatus.Error != "" && toolsStatus.Error != "" && stale != nil {
		return s.cloneStatus(stale), nil
	}

	newStatus := &UpstreamStatus{
		CheckedAt:       time.Now().UTC(),
		UpdateAvailable: goStatus.UpdateAvailable || toolsStatus.UpdateAvailable,
		Components:      []ComponentStatus{goStatus, toolsStatus},
		BaseImage:       PinnedAWGBaseImage,
	}

	// Cache if at least one component succeeded without error
	if goStatus.Error == "" || toolsStatus.Error == "" {
		s.mu.Lock()
		s.cached = newStatus
		s.cachedAt = time.Now()
		s.mu.Unlock()
	}

	return s.cloneStatus(newStatus), nil
}

func (s *Service) cloneStatus(src *UpstreamStatus) *UpstreamStatus {
	if src == nil {
		return nil
	}
	dst := *src
	if src.Components != nil {
		dst.Components = make([]ComponentStatus, len(src.Components))
		copy(dst.Components, src.Components)
	}
	return &dst
}
