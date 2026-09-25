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
	UserAgent       = "amnezia-nexus/1.4.0"
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
	clean1 := cleanVersion(v1)
	clean2 := cleanVersion(v2)

	if clean1 == clean2 {
		return 0
	}
	if clean1 == "" {
		return -1
	}
	if clean2 == "" {
		return 1
	}

	core1, hasPre1, preStr1 := parseVersion(clean1)
	core2, hasPre2, preStr2 := parseVersion(clean2)

	if cmp := compareCoreVersions(core1, core2); cmp != 0 {
		return cmp
	}

	if cmp, ok := compareCalVerRevisions(core1, core2, hasPre1, hasPre2, preStr1, preStr2); ok {
		return cmp
	}

	return comparePrerelease(hasPre1, hasPre2, preStr1, preStr2)
}

func compareCoreVersions(core1, core2 []string) int {
	minCore := len(core1)
	if len(core2) < minCore {
		minCore = len(core2)
	}

	for i := 0; i < minCore; i++ {
		if cmp := compareSegment(core1[i], core2[i]); cmp != 0 {
			return cmp
		}
	}

	if len(core1) > len(core2) {
		for _, s := range core1[minCore:] {
			if isNonZero(s) {
				return 1
			}
		}
	} else if len(core2) > len(core1) {
		for _, s := range core2[minCore:] {
			if isNonZero(s) {
				return -1
			}
		}
	}

	return 0
}

func compareCalVerRevisions(core1, core2 []string, hasPre1, hasPre2 bool, preStr1, preStr2 string) (int, bool) {
	calVer1 := getCalVerPatch(core1)
	calVer2 := getCalVerPatch(core2)

	if calVer1 == "" || calVer2 == "" {
		return 0, false
	}

	isPkg1 := !hasPre1 || isNumeric(preStr1)
	isPkg2 := !hasPre2 || isNumeric(preStr2)
	if !isPkg1 || !isPkg2 {
		return 0, false
	}

	var rev1, rev2 uint64
	if hasPre1 && isNumeric(preStr1) {
		rev1, _ = strconv.ParseUint(preStr1, 10, 64)
	}
	if hasPre2 && isNumeric(preStr2) {
		rev2, _ = strconv.ParseUint(preStr2, 10, 64)
	}
	if rev1 < rev2 {
		return -1, true
	}
	if rev1 > rev2 {
		return 1, true
	}
	return 0, true
}

func comparePrerelease(hasPre1, hasPre2 bool, preStr1, preStr2 string) int {
	// SemVer 2.0.0 Precedence:
	// A version without a prerelease has HIGHER precedence than a version with ANY prerelease.
	if !hasPre1 && hasPre2 {
		return 1
	}
	if hasPre1 && !hasPre2 {
		return -1
	}
	if !hasPre1 && !hasPre2 {
		return 0
	}

	// If both have prereleases, compare dot-separated identifiers from left to right:
	ids1 := strings.Split(preStr1, ".")
	ids2 := strings.Split(preStr2, ".")
	minPre := len(ids1)
	if len(ids2) < minPre {
		minPre = len(ids2)
	}

	for i := 0; i < minPre; i++ {
		if cmp := comparePrereleaseIdentifier(ids1[i], ids2[i]); cmp != 0 {
			return cmp
		}
	}

	// Larger set of prerelease identifiers has higher precedence if preceding are equal.
	if len(ids1) > len(ids2) {
		return 1
	}
	if len(ids2) > len(ids1) {
		return -1
	}

	return 0
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if idx := strings.LastIndex(v, ":"); idx != -1 {
		v = v[idx+1:]
	}
	if idx := strings.Index(v, "+"); idx != -1 {
		v = v[:idx]
	}
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return strings.TrimSpace(v)
}

func normalizeVersion(v string) string {
	return cleanVersion(v)
}

func parseVersion(v string) ([]string, bool, string) {
	if idx := strings.Index(v, "-"); idx != -1 {
		corePart := v[:idx]
		prePart := v[idx+1:]
		return splitCoreSegments(corePart), true, prePart
	}
	return splitCoreSegments(v), false, ""
}

func splitCoreSegments(v string) []string {
	parts := strings.Split(v, ".")
	var res []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func getCalVerPatch(core []string) string {
	if len(core) >= 3 {
		p := core[2]
		if len(p) >= 8 && isNumeric(p) {
			return p
		}
	}
	return ""
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func comparePrereleaseIdentifier(id1, id2 string) int {
	if id1 == id2 {
		return 0
	}

	num1 := isNumeric(id1)
	num2 := isNumeric(id2)

	if num1 && num2 {
		n1, _ := strconv.ParseUint(id1, 10, 64)
		n2, _ := strconv.ParseUint(id2, 10, 64)
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
		return 0
	}

	// SemVer 2.0.0 Rule 11.4.3: Numeric identifiers always have lower
	// precedence than non-numeric identifiers.
	if num1 && !num2 {
		return -1
	}
	if !num1 && num2 {
		return 1
	}

	// Both non-numeric identifiers
	prefix1, n1, ok1 := splitPrefixAndNumber(id1)
	prefix2, n2, ok2 := splitPrefixAndNumber(id2)
	if ok1 && ok2 && prefix1 == prefix2 {
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
		return 0
	}

	if id1 < id2 {
		return -1
	}
	if id1 > id2 {
		return 1
	}
	return 0
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

func isNonZero(seg string) bool {
	n, err := strconv.ParseUint(seg, 10, 64)
	if err == nil {
		return n > 0
	}
	return seg != ""
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
	case errCount > 0:
		status = "degraded"
	case updateCount > 0:
		status = "update_available"
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
