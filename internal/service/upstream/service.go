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

	DefaultDockerRepo    = "devopsigor/amneziawg"
	DefaultDockerBaseURL = "https://hub.docker.com/v2"

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
	Status          string            `json:"status"`
	UpdateAvailable bool              `json:"update_available"`
	Components      []ComponentStatus `json:"components"`
	BaseImage       string            `json:"base_image"`
}

// Service queries and caches upstream release metadata.
type Service struct {
	mu            sync.RWMutex
	cached        *UpstreamStatus
	cachedAt      time.Time
	cacheTTL      time.Duration
	lastKnownGood map[string]ComponentStatus
	httpClient    *http.Client
	baseURL       string
	dockerBaseURL string
	token         string
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

// WithDockerBaseURL overrides the Docker Hub API base URL (useful for testing).
func WithDockerBaseURL(url string) Option {
	return func(s *Service) {
		s.dockerBaseURL = strings.TrimRight(url, "/")
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
		cacheTTL:      DefaultCacheTTL,
		lastKnownGood: make(map[string]ComponentStatus),
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL:       "https://api.github.com",
		dockerBaseURL: DefaultDockerBaseURL,
		token:         token,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// CompareVersions compares two version strings v1 and v2 according to SemVer 2.0.0
// and CalVer conventions.
// Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	v1 = stripBuildMetadata(v1)
	v2 = stripBuildMetadata(v2)

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
		cmp := compareSegment(segs1[i], segs2[i])
		if cmp != 0 {
			return cmp
		}
	}

	if len(segs1) > len(segs2) {
		return compareExtraSegments(segs1[minLen:], 1)
	}

	if len(segs2) > len(segs1) {
		return compareExtraSegments(segs2[minLen:], -1)
	}

	return 0
}

func compareExtraSegments(extra []string, sign int) int {
	for _, s := range extra {
		if isPrerelease(s) {
			return -1 * sign
		}
		if isNonZero(s) {
			return 1 * sign
		}
	}
	return 0
}

func stripBuildMetadata(v string) string {
	if idx := strings.Index(v, "+"); idx != -1 {
		return v[:idx]
	}
	return v
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
		return r == '.' || r == '-' || r == '_'
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

	// SemVer 2.0.0 Rule 11.4.2/11.4.3: Numeric identifiers always have lower
	// precedence than non-numeric identifiers.
	if err1 == nil && err2 != nil {
		return -1
	}
	if err1 != nil && err2 == nil {
		return 1
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

type dockerHubTag struct {
	Name        string    `json:"name"`
	LastUpdated time.Time `json:"last_updated"`
}

type dockerHubResponse struct {
	Count   int            `json:"count"`
	Results []dockerHubTag `json:"results"`
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

func (s *Service) queryDockerHubTags(ctx context.Context, repo string) ([]dockerHubTag, error) {
	url := fmt.Sprintf("%s/repositories/%s/tags?page_size=10", s.dockerBaseURL, strings.TrimPrefix(repo, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error querying docker tags for %s: %w", repo, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("Docker Hub rate limit exceeded (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Docker Hub tags returned HTTP %d for %s", resp.StatusCode, repo)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var res dockerHubResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("decoding docker tags JSON: %w", err)
	}

	return res.Results, nil
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

func (s *Service) queryDockerComponent(ctx context.Context, repo string) (string, time.Time, string, error) {
	tags, err := s.queryDockerHubTags(ctx, repo)
	if err != nil {
		return "", time.Time{}, "", err
	}

	var maxTag string
	var publishedAt time.Time

	for _, t := range tags {
		name := strings.TrimSpace(t.Name)
		if name == "" || name == "latest" {
			continue
		}
		norm := normalizeVersion(name)
		if norm == "" || (norm[0] < '0' || norm[0] > '9') {
			continue
		}
		if maxTag == "" || CompareVersions(name, maxTag) > 0 {
			maxTag = name
			publishedAt = t.LastUpdated
		}
	}

	if maxTag == "" {
		for _, t := range tags {
			if t.Name != "" && t.Name != "latest" {
				maxTag = t.Name
				publishedAt = t.LastUpdated
				break
			}
		}
		if maxTag == "" {
			return "", time.Time{}, "", fmt.Errorf("no valid tags found for docker repo %s", repo)
		}
	}

	releaseURL := fmt.Sprintf("https://hub.docker.com/r/%s/tags", repo)
	return maxTag, publishedAt, releaseURL, nil
}

func (s *Service) getLastKnownGood(name string) (ComponentStatus, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prev, ok := s.lastKnownGood[name]
	return prev, ok
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
		if prev, ok := s.getLastKnownGood(name); ok {
			status.LatestVersion = prev.LatestVersion
			status.ReleaseURL = prev.ReleaseURL
			status.PublishedAt = prev.PublishedAt
			status.UpdateAvailable = CompareVersions(status.LatestVersion, status.PinnedVersion) > 0
		}
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

func parseDockerTag(image string) string {
	if idx := strings.LastIndex(image, ":"); idx != -1 {
		return image[idx+1:]
	}
	return image
}

func (s *Service) fetchDockerComponent(ctx context.Context, name, repo, pinnedImage string) ComponentStatus {
	pinnedTag := parseDockerTag(pinnedImage)
	status := ComponentStatus{
		Name:          name,
		Repo:          repo,
		PinnedVersion: pinnedTag,
		LatestVersion: pinnedTag,
		ReleaseURL:    fmt.Sprintf("https://hub.docker.com/r/%s/tags", repo),
	}

	latestTag, publishedAt, releaseURL, err := s.queryDockerComponent(ctx, repo)
	if err != nil {
		status.Error = err.Error()
		if prev, ok := s.getLastKnownGood(name); ok {
			status.LatestVersion = prev.LatestVersion
			status.ReleaseURL = prev.ReleaseURL
			status.PublishedAt = prev.PublishedAt
			status.UpdateAvailable = CompareVersions(status.LatestVersion, status.PinnedVersion) > 0
		}
		return status
	}

	status.LatestVersion = latestTag
	if releaseURL != "" {
		status.ReleaseURL = releaseURL
	}
	if !publishedAt.IsZero() {
		status.PublishedAt = publishedAt
	}

	status.UpdateAvailable = CompareVersions(latestTag, pinnedTag) > 0
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
	s.mu.RUnlock()

	goStatus := s.fetchComponent(ctx, "amneziawg-go", "amnezia-vpn/amneziawg-go", PinnedAWGGoVersion)
	toolsStatus := s.fetchComponent(ctx, "amneziawg-tools", "amnezia-vpn/amneziawg-tools", PinnedAWGToolsVersion)
	dockerStatus := s.fetchDockerComponent(ctx, "docker-base-image", DefaultDockerRepo, PinnedAWGBaseImage)

	components := []ComponentStatus{goStatus, toolsStatus, dockerStatus}

	errCount := 0
	updateCount := 0
	for _, c := range components {
		if c.Error != "" {
			errCount++
		}
		if c.UpdateAvailable {
			updateCount++
		}
	}

	var status string
	switch {
	case errCount == len(components):
		status = "error"
	case updateCount > 0:
		status = "update_available"
	case errCount > 0:
		status = "degraded"
	default:
		status = "up_to_date"
	}

	newStatus := &UpstreamStatus{
		CheckedAt:       time.Now().UTC(),
		Status:          status,
		UpdateAvailable: updateCount > 0,
		Components:      components,
		BaseImage:       PinnedAWGBaseImage,
	}

	s.mu.Lock()
	for _, comp := range components {
		if comp.Error == "" {
			s.lastKnownGood[comp.Name] = comp
		}
	}
	// Only cache the combined snapshot if ALL components succeeded without error
	if errCount == 0 {
		s.cached = newStatus
		s.cachedAt = time.Now()
	}
	s.mu.Unlock()

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
