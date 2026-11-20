package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrSyncInProgress indicates an update is already being executed.
	ErrSyncInProgress = errors.New("policy sync already in progress")
	// ErrSyncerClosed indicates the syncer has been shut down.
	ErrSyncerClosed = errors.New("policy syncer is closed")
)

// Default intervals.
const (
	DefaultRefreshInterval = 6 * time.Hour
	MinRefreshInterval     = 30 * time.Minute
)

// SyncConfig defines parameters for scheduled and manual policy synchronization.
type SyncConfig struct {
	Sources    []Source    `json:"sources"`
	LocalRules ParsedRules `json:"-"`
	// ExcludedDomains is the parsed operator never-proxy list (built-in patterns
	// are added separately). It is deliberately not part of the config hash: a
	// no-op exclusion must not mint a new generation (equivalence.go), and
	// baseline adoption revalidates stored rules against the current list.
	ExcludedDomains []string      `json:"-"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	FetchLimits     FetchLimits   `json:"fetch_limits"`
	ParseLimits     ParseLimits   `json:"parse_limits"`
	ForceShrink     bool          `json:"force_shrink"`
}

// SourceSyncStats records the execution metrics for an individual source during a sync cycle.
type SourceSyncStats struct {
	ID          string `json:"id"`
	StatusCode  int    `json:"status_code"`
	NotModified bool   `json:"not_modified"`
	Accepted    int    `json:"accepted"`
	Rejected    int    `json:"rejected"`
	Excluded    int    `json:"excluded"`
	Duplicates  int    `json:"duplicates"`
	CheckedAt   string `json:"checked_at,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SyncResult returns the result of an executed synchronization cycle.
type SyncResult struct {
	Version      uint64                     `json:"version"`
	GenerationID string                     `json:"generation_id"`
	SourceStats  map[string]SourceSyncStats `json:"source_stats"`
	Published    bool                       `json:"published"`
	Duration     time.Duration              `json:"duration"`
}

// Status represents a read-only snapshot of syncer health and active policy metrics.
type Status struct {
	Ready        bool                       `json:"ready"`
	Version      uint64                     `json:"version"`
	GenerationID string                     `json:"generation_id"`
	LastSyncTime time.Time                  `json:"last_sync_time"`
	LastSuccess  time.Time                  `json:"last_success"`
	LastError    string                     `json:"last_error,omitempty"`
	DomainCount  int                        `json:"domain_count"`
	CIDRCount    int                        `json:"cidr_count"`
	SourceStats  map[string]SourceSyncStats `json:"source_stats"`
}

type syncRequest struct {
	ctx      context.Context
	respChan chan syncResponse
}

type syncResponse struct {
	res SyncResult
	err error
}

// localSourceID is the per-source identifier for operator-supplied local rules.
// It never reaches the fetcher; it exists so the local rules participate in the
// composed snapshot, provenance and attribution digest like any other source.
const localSourceID = "local"

type cachedSourceData struct {
	meta  SourceMeta
	rules ParsedRules
	// report and excluded are the parse outcome for rules. A conditional 304
	// refresh reuses the filtered rules, so it must reuse their accounting too;
	// otherwise a normal scheduled refresh reports zero accepted and zero
	// excluded rules for a component that still contributes thousands.
	report   ParseReport
	excluded int
}

// Syncer orchestrates single-owner policy updates, LKG durability, and atomic publication.
type Syncer struct {
	matcher *Matcher
	fetcher *Fetcher
	store   Store
	cfg     SyncConfig
	// guardPatterns is the built-in never-proxy set plus the operator
	// exclusions, fixed at construction so every source and the composed
	// candidate are filtered by the same closed set.
	guardPatterns []string

	// owner/ticket bind this syncer to its service's write-ownership boundary
	// (see sync_ownership.go). Both are set once, before the syncer runs, and
	// never mutated afterwards.
	owner  *WriteOwner
	ticket uint64

	statusMu sync.RWMutex
	status   Status

	cachedGen     *Generation
	cachedSources map[string]cachedSourceData

	syncReqCh chan syncRequest
	active    atomic.Bool
	closed    atomic.Bool
	stopCh    chan struct{}
}

// NewSyncer creates a new Syncer.
func NewSyncer(m *Matcher, fetcher *Fetcher, store Store, cfg SyncConfig) (*Syncer, error) {
	if m == nil {
		return nil, errors.New("matcher cannot be nil")
	}
	if store == nil {
		return nil, errors.New("store cannot be nil")
	}
	if len(cfg.Sources) == 0 {
		return nil, errors.New("at least one source must be configured")
	}
	if len(cfg.Sources) > MaxSyncSources {
		return nil, fmt.Errorf("maximum %d sources may be configured", MaxSyncSources)
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	} else if cfg.RefreshInterval < MinRefreshInterval {
		return nil, fmt.Errorf("refresh interval cannot be shorter than %v", MinRefreshInterval)
	}

	if fetcher == nil {
		fetcher = NewFetcher(cfg.FetchLimits)
	}

	normalizedExclusions, err := ParseExcludedDomains(cfg.ExcludedDomains)
	if err != nil {
		return nil, fmt.Errorf("excluded domains: %w", err)
	}
	cfg.ExcludedDomains = normalizedExclusions

	return &Syncer{
		matcher:       m,
		fetcher:       fetcher,
		store:         store,
		cfg:           cfg,
		guardPatterns: mergeGuardPatterns(cfg.ExcludedDomains),
		cachedSources: make(map[string]cachedSourceData),
		syncReqCh:     make(chan syncRequest, 1),
		stopCh:        make(chan struct{}),
	}, nil
}

// BaselineStatus, BaselineAbsent, BaselinePrimed, BaselineForeign and
// PrimeBaseline live in baseline.go: the last-known-good baseline a syncer
// establishes before evaluating its first candidate replacement.

// AttachOwnership binds this syncer to its service's write-ownership boundary and
// issues its ticket. It must be called before the syncer performs any update: the
// ticket is what makes a superseded runtime's commit and publication refusable
// (see sync_ownership.go).
//
// An unattached syncer keeps working with no boundary, which is what unit tests
// and store-only helpers rely on.
func (s *Syncer) AttachOwnership(owner *WriteOwner) {
	if s == nil || owner == nil {
		return
	}
	s.owner = owner
	s.ticket = owner.Ticket()
}

// ConfigHash returns the source-configuration hash this syncer commits and
// compares against durable generations. Callers that must decide whether a stored
// generation belongs to *this* configuration read it here instead of restating the
// hash format.
func (s *Syncer) ConfigHash() string {
	if s == nil {
		return ""
	}
	return s.computeConfigHash()
}

// Run executes the single-owner update and scheduling loop until ctx is canceled.
func (s *Syncer) Run(ctx context.Context) error {
	// Recover the last-known-good baseline before the initial update, so a
	// shortened first response is evaluated against it instead of being accepted
	// as the first-ever snapshot. A failure is deliberately not fatal here: the
	// loop's own update reports content problems through its status, and refusing
	// to run would leave a previously working policy unpublished.
	_, _ = s.PrimeBaseline(ctx)

	// Trigger initial sync to fetch current rules
	_, _ = s.executeUpdate(ctx)

	ticker := time.NewTicker(s.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.closed.Store(true)
			return ctx.Err()
		case <-s.stopCh:
			s.closed.Store(true)
			return nil
		case req := <-s.syncReqCh:
			res, err := s.executeUpdate(req.ctx)
			req.respChan <- syncResponse{res: res, err: err}
		case <-ticker.C:
			_, _ = s.executeUpdate(ctx)
		}
	}
}

// Sync requests an on-demand update cycle. If an update is already running,
// ErrSyncInProgress is returned immediately.
func (s *Syncer) Sync(ctx context.Context) (SyncResult, error) {
	if s.closed.Load() {
		return SyncResult{}, ErrSyncerClosed
	}

	// Non-blocking reservation check to prevent unbounded request queueing
	if !s.active.CompareAndSwap(false, true) {
		return SyncResult{}, ErrSyncInProgress
	}
	// Swap back so executeUpdate will manage the active flag
	s.active.Store(false)

	respCh := make(chan syncResponse, 1)
	req := syncRequest{
		ctx:      ctx,
		respChan: respCh,
	}

	select {
	case s.syncReqCh <- req:
	case <-ctx.Done():
		return SyncResult{}, ctx.Err()
	}

	select {
	case resp := <-respCh:
		return resp.res, resp.err
	case <-ctx.Done():
		return SyncResult{}, ctx.Err()
	}
}

// Status returns a deep copy of the syncer's status.
func (s *Syncer) Status() Status {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()

	out := s.status
	if s.status.SourceStats != nil {
		out.SourceStats = make(map[string]SourceSyncStats, len(s.status.SourceStats))
		for k, v := range s.status.SourceStats {
			out.SourceStats[k] = v
		}
	}
	return out
}

func (s *Syncer) getConditionalValidators(src Source) (string, string) {
	if cached, exists := s.cachedSources[src.ID]; exists && cached.meta.URL == src.URL {
		return cached.meta.ETag, cached.meta.LastModified
	}
	if s.cachedGen != nil {
		if meta, ok := s.cachedGen.SourcesMeta[src.ID]; ok && meta.URL == src.URL {
			return meta.ETag, meta.LastModified
		}
	}
	return "", ""
}

func (s *Syncer) syncSingleSource(ctx context.Context, src Source, startTime time.Time) (cachedSourceData, SourceSyncStats, SourceParsedRules, error) {
	stat := SourceSyncStats{ID: src.ID, CheckedAt: startTime.UTC().Format(time.RFC3339)}
	ifNoneMatch, ifModifiedSince := s.getConditionalValidators(src)

	fetchRes, err := s.fetcher.Fetch(ctx, src.URL, ifNoneMatch, ifModifiedSince)
	if err != nil {
		stat.Error = err.Error()
		return cachedSourceData{}, stat, SourceParsedRules{}, fmt.Errorf("source %s fetch failed: %w", src.ID, err)
	}

	stat.StatusCode = fetchRes.StatusCode
	stat.NotModified = fetchRes.NotModified

	var rules ParsedRules
	var report ParseReport
	var excluded int

	if fetchRes.NotModified {
		cached, exists := s.cachedSources[src.ID]
		if !exists {
			fetchRes, err = s.fetcher.Fetch(ctx, src.URL, "", "")
			if err != nil {
				stat.Error = err.Error()
				return cachedSourceData{}, stat, SourceParsedRules{}, fmt.Errorf("source %s conditional refresh fallback failed: %w", src.ID, err)
			}
			rules, report, err = Parse(ctx, bytes.NewReader(fetchRes.Body), src, s.cfg.ParseLimits)
			if err != nil {
				stat.Error = err.Error()
				return cachedSourceData{}, stat, SourceParsedRules{}, fmt.Errorf("source %s parse failed: %w", src.ID, err)
			}
			rules, excluded = filterNeverProxyDomains(rules, s.guardPatterns)
		} else {
			rules = cached.rules
			report = cached.report
			excluded = cached.excluded
		}
	} else {
		rules, report, err = Parse(ctx, bytes.NewReader(fetchRes.Body), src, s.cfg.ParseLimits)
		if err != nil {
			stat.Error = err.Error()
			return cachedSourceData{}, stat, SourceParsedRules{}, fmt.Errorf("source %s parse failed: %w", src.ID, err)
		}
		rules, excluded = filterNeverProxyDomains(rules, s.guardPatterns)
	}

	stat.Accepted = report.Accepted
	stat.Rejected = report.Rejected
	stat.Excluded = excluded
	stat.Duplicates = report.Duplicates
	stat.LastSuccess = startTime.UTC().Format(time.RFC3339)

	etag, lastMod := retainedValidators(fetchRes, ifNoneMatch, ifModifiedSince)

	meta := SourceMeta{
		ID:           src.ID,
		URL:          src.URL,
		ETag:         etag,
		LastModified: lastMod,
		CheckedAt:    startTime,
		RuleCount:    len(rules.Domains) + len(rules.CIDRs),
	}

	cached := cachedSourceData{meta: meta, rules: rules, report: report, excluded: excluded}
	parsed := SourceParsedRules{SourceID: src.ID, Rules: rules}
	return cached, stat, parsed, nil
}

// retainedValidators returns the HTTP validators to persist for this fetch. A
// 304 may omit them even though the cached copy is still current; dropping a
// still-valid validator would force a full download on the next cycle.
func retainedValidators(fetchRes *FetchResult, ifNoneMatch, ifModifiedSince string) (string, string) {
	etag := fetchRes.ETag
	lastMod := fetchRes.LastModified
	if !fetchRes.NotModified {
		return etag, lastMod
	}
	if etag == "" {
		etag = ifNoneMatch
	}
	if lastMod == "" {
		lastMod = ifModifiedSince
	}
	return etag, lastMod
}

func aggregateCandidateRules(sourceParsedList []SourceParsedRules) (map[string]uint32, []string, int) {
	candidateDomains := make(map[string]uint32)
	var candidateCIDRs []string
	seenCIDRs := make(map[netip.Prefix]struct{})

	for _, item := range sourceParsedList {
		for base, flags := range item.Rules.Domains {
			candidateDomains[base] |= uint32(flags)
		}
		for _, prefix := range item.Rules.CIDRs {
			canon := prefix.Masked()
			if _, exists := seenCIDRs[canon]; !exists {
				seenCIDRs[canon] = struct{}{}
				candidateCIDRs = append(candidateCIDRs, canon.String())
			}
		}
	}
	return candidateDomains, candidateCIDRs, len(candidateDomains) + len(candidateCIDRs)
}

func (s *Syncer) guardCandidateDomains(domains map[string]uint32, cidrs []string, total int) (map[string]uint32, int) {
	guarded, excluded := filterNeverProxyFlags(domains, s.guardPatterns)
	if excluded == 0 {
		return domains, total
	}
	return guarded, len(guarded) + len(cidrs)
}

func (s *Syncer) validateCandidateRules(totalCandidateRules int) error {
	if totalCandidateRules == 0 {
		return errors.New("cannot publish policy snapshot with zero rules")
	}
	return s.checkShrink(totalCandidateRules)
}

func (s *Syncer) checkShrink(totalCandidateRules int) error {
	currentSnap := s.matcher.Current()
	if currentSnap != nil {
		prevRules := currentSnap.DomainCount() + currentSnap.CIDRCount()
		if prevRules > 0 && !s.cfg.ForceShrink && totalCandidateRules < prevRules/2 {
			return fmt.Errorf("shrink guard: new rules count (%d) is less than 50%% of previous count (%d)", totalCandidateRules, prevRules)
		}
	}
	return nil
}

func (s *Syncer) nextVersion() uint64 {
	if s.cachedGen != nil {
		return s.cachedGen.Version + 1
	}
	if currentSnap := s.matcher.Current(); currentSnap != nil {
		return currentSnap.Version() + 1
	}
	return 1
}

func (s *Syncer) fetchSources(ctx context.Context, startTime time.Time) ([]SourceParsedRules, map[string]SourceSyncStats, map[string]cachedSourceData, error) {
	statsMap := make(map[string]SourceSyncStats)
	newCachedSources := make(map[string]cachedSourceData)
	var sourceParsedList []SourceParsedRules
	for _, src := range s.cfg.Sources {
		cached, stat, parsed, err := s.syncSingleSource(ctx, src, startTime)
		statsMap[src.ID] = stat
		if err != nil {
			return sourceParsedList, statsMap, newCachedSources, err
		}
		newCachedSources[src.ID] = cached
		sourceParsedList = append(sourceParsedList, parsed)
	}
	return sourceParsedList, statsMap, newCachedSources, nil
}

func (s *Syncer) appendLocalRules(sourceParsedList []SourceParsedRules, statsMap map[string]SourceSyncStats) ([]SourceParsedRules, error) {
	if len(s.cfg.LocalRules.Domains) == 0 && len(s.cfg.LocalRules.CIDRs) == 0 {
		return sourceParsedList, nil
	}
	localRules, excluded := filterNeverProxyDomains(s.cfg.LocalRules, s.guardPatterns)
	if excluded > 0 {
		return sourceParsedList, fmt.Errorf("local rules contain %d never-proxy entries", excluded)
	}
	statsMap[localSourceID] = SourceSyncStats{ID: localSourceID, Accepted: len(localRules.Domains) + len(localRules.CIDRs)}
	return append(sourceParsedList, SourceParsedRules{SourceID: localSourceID, Rules: localRules}), nil
}

func (s *Syncer) executeUpdate(ctx context.Context) (SyncResult, error) {
	if !s.active.CompareAndSwap(false, true) {
		return SyncResult{}, ErrSyncInProgress
	}
	defer s.active.Store(false)

	startTime := time.Now().UTC()
	sourceParsedList, statsMap, newCachedSources, err := s.fetchSources(ctx, startTime)
	if err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}
	sourceParsedList, err = s.appendLocalRules(sourceParsedList, statsMap)
	if err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}

	candidateDomains, candidateCIDRs, totalRules := aggregateCandidateRules(sourceParsedList)
	candidateDomains, totalRules = s.guardCandidateDomains(candidateDomains, candidateCIDRs, totalRules)
	if err := s.validateCandidateRules(totalRules); err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}

	// A content-equivalent refresh keeps the published generation (equivalence.go):
	// advancing it for rules the client already had would stamp a new attribution
	// on the flows that run the same policy. The retained generation still goes
	// through the same durable commit and atomic publication below, which is what
	// refreshes its source fetch/health metadata.
	newVersion, genID, createdAt := s.candidateIdentity(startTime, candidateDomains, candidateCIDRs, sourceParsedList)
	sourcesMeta := make(map[string]SourceMeta, len(newCachedSources))
	for id, item := range newCachedSources {
		sourcesMeta[id] = item.meta
	}

	// The attribution digest is what a later cycle compares when this syncer is
	// gone (provenance.go). It is recorded on the retained and the published path
	// alike: a retained cycle then also writes the digest a generation committed
	// before the field existed was missing, so the one-cycle legacy gap closes
	// with the first successful refresh.
	attributionHash, _ := attributionDigest(sourceParsedList)

	candidateGen := &Generation{
		SchemaVersion:   SchemaVersion,
		GenerationID:    genID,
		Version:         newVersion,
		CreatedAt:       createdAt,
		ConfigHash:      s.computeConfigHash(),
		AttributionHash: attributionHash,
		SourcesMeta:     sourcesMeta,
		Domains:         candidateDomains,
		CIDRs:           candidateCIDRs,
		DomainCount:     len(candidateDomains),
		CIDRCount:       len(candidateCIDRs),
	}

	// Compile before entering the ownership boundary: a compile failure is not a
	// write, so it must not be able to retire the incumbent writer.
	candidateSnap, err := CompileSnapshot(newVersion, genID, sourceParsedList)
	if err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)},
			fmt.Errorf("failed compiling policy snapshot: %w", err)
	}

	// Durable commit and live publication are one ownership-bound section
	// (#678 F678-04). A sync that is still in flight when a replacement has
	// already been accepted must not commit its old generation or publish it into
	// the shared matcher: that would leave settings and status naming the new
	// source while both the durable and the live policy were the old one. The
	// boundary is evaluated here, at the write, not before the fetch.
	write := func() error {
		// Commit candidate generation to durable store before publication
		if err := s.store.Commit(ctx, candidateGen); err != nil {
			return fmt.Errorf("durable commit of policy generation failed: %w", err)
		}

		// Atomically publish new snapshot
		s.matcher.Publish(candidateSnap)

		s.cachedGen = candidateGen
		s.cachedSources = newCachedSources

		s.statusMu.Lock()
		s.status = Status{
			Ready:        true,
			Version:      newVersion,
			GenerationID: genID,
			LastSyncTime: startTime,
			LastSuccess:  startTime,
			LastError:    "",
			DomainCount:  candidateSnap.DomainCount(),
			CIDRCount:    candidateSnap.CIDRCount(),
			SourceStats:  statsMap,
		}
		s.statusMu.Unlock()
		return nil
	}
	if err := s.owner.Write(s.ticket, write); err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}

	return SyncResult{
		Version:      newVersion,
		GenerationID: genID,
		SourceStats:  statsMap,
		Published:    true,
		Duration:     time.Since(startTime),
	}, nil
}

func (s *Syncer) recordFailure(err error, stats map[string]SourceSyncStats, syncTime time.Time) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	s.status.LastSyncTime = syncTime
	s.status.LastError = err.Error()
	if stats != nil {
		s.status.SourceStats = stats
	}
}

func (s *Syncer) computeConfigHash() string {
	h := sha256.New()
	for _, src := range s.cfg.Sources {
		_, _ = fmt.Fprintf(h, "%s:%s:%d:%d:%v\n", src.ID, src.URL, src.Format, src.BareDomainMode, src.IsPreset)
	}
	return hex.EncodeToString(h.Sum(nil))
}
