package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	Sources         []Source      `json:"sources"`
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
	Duplicates  int    `json:"duplicates"`
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

type cachedSourceData struct {
	meta  SourceMeta
	rules ParsedRules
}

// Syncer orchestrates single-owner policy updates, LKG durability, and atomic publication.
type Syncer struct {
	matcher *Matcher
	fetcher *Fetcher
	store   Store
	cfg     SyncConfig

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
	if len(cfg.Sources) > 4 {
		return nil, errors.New("maximum 4 sources may be configured")
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	} else if cfg.RefreshInterval < MinRefreshInterval {
		return nil, fmt.Errorf("refresh interval cannot be shorter than %v", MinRefreshInterval)
	}

	if fetcher == nil {
		fetcher = NewFetcher(cfg.FetchLimits)
	}

	return &Syncer{
		matcher:       m,
		fetcher:       fetcher,
		store:         store,
		cfg:           cfg,
		cachedSources: make(map[string]cachedSourceData),
		syncReqCh:     make(chan syncRequest, 1),
		stopCh:        make(chan struct{}),
	}, nil
}

// Run executes the single-owner update and scheduling loop until ctx is canceled.
func (s *Syncer) Run(ctx context.Context) error {
	// Attempt initial recovery from last-known-good cache on startup
	if s.store != nil {
		if gen, err := s.store.Load(ctx); err == nil && gen != nil {
			if snap, snapErr := GenerationToSnapshot(gen); snapErr == nil && (snap.DomainCount() > 0 || snap.CIDRCount() > 0) {
				s.matcher.Publish(snap)
				s.cachedGen = gen
				s.statusMu.Lock()
				s.status.Ready = true
				s.status.Version = gen.Version
				s.status.GenerationID = gen.GenerationID
				s.status.LastSuccess = gen.CreatedAt
				s.status.DomainCount = snap.DomainCount()
				s.status.CIDRCount = snap.CIDRCount()
				s.statusMu.Unlock()
			}
		}
	}

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
	stat := SourceSyncStats{ID: src.ID}
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
		} else {
			rules = cached.rules
		}
	} else {
		rules, report, err = Parse(ctx, bytes.NewReader(fetchRes.Body), src, s.cfg.ParseLimits)
		if err != nil {
			stat.Error = err.Error()
			return cachedSourceData{}, stat, SourceParsedRules{}, fmt.Errorf("source %s parse failed: %w", src.ID, err)
		}
	}

	stat.Accepted = report.Accepted
	stat.Rejected = report.Rejected
	stat.Duplicates = report.Duplicates

	meta := SourceMeta{
		ID:           src.ID,
		URL:          src.URL,
		ETag:         fetchRes.ETag,
		LastModified: fetchRes.LastModified,
		CheckedAt:    startTime,
		RuleCount:    len(rules.Domains) + len(rules.CIDRs),
	}

	cached := cachedSourceData{meta: meta, rules: rules}
	parsed := SourceParsedRules{SourceID: src.ID, Rules: rules}
	return cached, stat, parsed, nil
}

func aggregateCandidateRules(sourceParsedList []SourceParsedRules) (map[string]uint8, []string, int) {
	candidateDomains := make(map[string]uint8)
	var candidateCIDRs []string

	for _, item := range sourceParsedList {
		for base, flags := range item.Rules.Domains {
			candidateDomains[base] |= uint8(flags)
		}
		for _, prefix := range item.Rules.CIDRs {
			candidateCIDRs = append(candidateCIDRs, prefix.String())
		}
	}
	return candidateDomains, candidateCIDRs, len(candidateDomains) + len(candidateCIDRs)
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

func (s *Syncer) executeUpdate(ctx context.Context) (SyncResult, error) {
	if !s.active.CompareAndSwap(false, true) {
		return SyncResult{}, ErrSyncInProgress
	}
	defer s.active.Store(false)

	startTime := time.Now().UTC()
	statsMap := make(map[string]SourceSyncStats)
	newCachedSources := make(map[string]cachedSourceData)
	var sourceParsedList []SourceParsedRules

	for _, src := range s.cfg.Sources {
		cached, stat, parsed, err := s.syncSingleSource(ctx, src, startTime)
		statsMap[src.ID] = stat
		if err != nil {
			s.recordFailure(err, statsMap, startTime)
			return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
		}
		newCachedSources[src.ID] = cached
		sourceParsedList = append(sourceParsedList, parsed)
	}

	candidateDomains, candidateCIDRs, totalRules := aggregateCandidateRules(sourceParsedList)
	if totalRules == 0 {
		err := errors.New("cannot publish policy snapshot with zero rules")
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}
	if err := s.checkShrink(totalRules); err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}

	newVersion := s.nextVersion()
	genID := fmt.Sprintf("gen-%d-%d", newVersion, startTime.UnixNano())
	sourcesMeta := make(map[string]SourceMeta, len(newCachedSources))
	for id, item := range newCachedSources {
		sourcesMeta[id] = item.meta
	}

	candidateGen := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  genID,
		Version:       newVersion,
		CreatedAt:     startTime,
		ConfigHash:    s.computeConfigHash(),
		SourcesMeta:   sourcesMeta,
		Domains:       candidateDomains,
		CIDRs:         candidateCIDRs,
		DomainCount:   len(candidateDomains),
		CIDRCount:     len(candidateCIDRs),
	}

	// Commit candidate generation to durable store before publication
	if err := s.store.Commit(ctx, candidateGen); err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)},
			fmt.Errorf("durable commit of policy generation failed: %w", err)
	}

	candidateSnap, err := CompileSnapshot(newVersion, genID, sourceParsedList)
	if err != nil {
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)},
			fmt.Errorf("failed compiling policy snapshot: %w", err)
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
