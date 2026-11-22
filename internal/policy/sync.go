package policy

import (
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

// SyncConfig defines parameters for a policy cycle's rule content.
//
// It carries no network input by design: the routing authority is the destination
// classifier, and the operator's contribution is the local IPv4 exception list.
//
// There is no truncation/reduction knob. That guard belonged to a downloaded feed
// whose list could arrive truncated; with every rule operator-supplied and
// validated before it is stored, a shorter candidate list is a deliberate edit.
// The cycle's remaining refusal is the zero-rule one.
type SyncConfig struct {
	LocalRules      ParsedRules   `json:"-"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	ParseLimits     ParseLimits   `json:"parse_limits"`
}

// SourceSyncStats records the execution metrics for an individual rule source
// during a cycle. With no fetched sources, the only entry is the local exception
// list.
type SourceSyncStats struct {
	ID          string `json:"id"`
	Accepted    int    `json:"accepted"`
	Duplicates  int    `json:"duplicates"`
	CheckedAt   string `json:"checked_at,omitempty"`
	LastSuccess string `json:"last_success,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SyncResult returns the result of an executed policy cycle.
type SyncResult struct {
	Version      uint64                     `json:"version"`
	GenerationID string                     `json:"generation_id"`
	SourceStats  map[string]SourceSyncStats `json:"source_stats"`
	Published    bool                       `json:"published"`
	Duration     time.Duration              `json:"duration"`
}

// Status represents a read-only snapshot of policy health and active metrics.
type Status struct {
	Ready        bool                       `json:"ready"`
	Version      uint64                     `json:"version"`
	GenerationID string                     `json:"generation_id"`
	LastSyncTime time.Time                  `json:"last_sync_time"`
	LastSuccess  time.Time                  `json:"last_success"`
	LastError    string                     `json:"last_error,omitempty"`
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
// It exists so the exception list participates in the composed snapshot and its
// provenance like any other source.
const localSourceID = "local"

// Syncer orchestrates single-owner policy updates, last-known-good durability
// and atomic publication.
type Syncer struct {
	matcher *Matcher
	store   Store
	cfg     SyncConfig

	// owner/ticket bind this syncer to its service's write-ownership boundary
	// (see sync_ownership.go). Both are set once, before the syncer runs, and
	// never mutated afterwards.
	owner  *WriteOwner
	ticket uint64

	statusMu sync.RWMutex
	status   Status

	cachedGen *Generation

	syncReqCh chan syncRequest
	active    atomic.Bool
	closed    atomic.Bool
	stopCh    chan struct{}
}

// NewSyncer creates a new Syncer.
//
// A configuration that currently holds no rules is accepted: the record is valid
// and the cycle that runs it reports the empty-policy refusal, which is the
// operator-facing reason the VPN layer surfaces. Rejecting it here would replace
// that reason with a constructor error and change where the refusal is owned.
func NewSyncer(m *Matcher, store Store, cfg SyncConfig) (*Syncer, error) {
	if m == nil {
		return nil, errors.New("matcher cannot be nil")
	}
	if store == nil {
		return nil, errors.New("store cannot be nil")
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	} else if cfg.RefreshInterval < MinRefreshInterval {
		return nil, fmt.Errorf("refresh interval cannot be shorter than %v", MinRefreshInterval)
	}

	return &Syncer{
		matcher:   m,
		store:     store,
		cfg:       cfg,
		syncReqCh: make(chan syncRequest, 1),
		stopCh:    make(chan struct{}),
	}, nil
}

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

// ConfigHash returns the rule-configuration hash this syncer commits and
// compares against durable generations.
//
// With no fetched sources the hash covers the local rule set, so two records that
// differ only in their exception prefixes remain distinguishable.
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
	// as the first-ever snapshot.
	_, _ = s.PrimeBaseline(ctx)

	// Trigger initial sync to publish the current rules
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

// nextVersion returns the version a newly published generation takes: one past
// the newest one this syncer can see.
func (s *Syncer) nextVersion() uint64 {
	if s.cachedGen != nil {
		return s.cachedGen.Version + 1
	}
	if currentSnap := s.matcher.Current(); currentSnap != nil {
		return currentSnap.Version() + 1
	}
	return 1
}

// localSourceRules returns the operator's exception list as the cycle's single
// rule source, and whether it holds anything at all.
func (s *Syncer) localSourceRules() (SourceParsedRules, bool) {
	if len(s.cfg.LocalRules.CIDRs) == 0 {
		return SourceParsedRules{}, false
	}
	return SourceParsedRules{SourceID: localSourceID, Rules: s.cfg.LocalRules}, true
}

func (s *Syncer) executeUpdate(ctx context.Context) (SyncResult, error) {
	if !s.active.CompareAndSwap(false, true) {
		return SyncResult{}, ErrSyncInProgress
	}
	defer s.active.Store(false)

	startTime := time.Now().UTC()
	statsMap := make(map[string]SourceSyncStats)

	local, hasLocal := s.localSourceRules()
	if !hasLocal {
		err := errors.New("cannot publish policy snapshot with zero rules")
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}
	statsMap[localSourceID] = SourceSyncStats{
		ID:          localSourceID,
		Accepted:    len(local.Rules.CIDRs),
		CheckedAt:   startTime.UTC().Format(time.RFC3339),
		LastSuccess: startTime.UTC().Format(time.RFC3339),
	}
	sourceParsedList := []SourceParsedRules{local}

	totalRules := len(local.Rules.CIDRs)
	if totalRules == 0 {
		err := errors.New("cannot publish policy snapshot with zero rules")
		s.recordFailure(err, statsMap, startTime)
		return SyncResult{SourceStats: statsMap, Duration: time.Since(startTime)}, err
	}

	candidateCIDRs := canonicalPrefixStrings(local.Rules.CIDRs)
	newVersion, genID, createdAt := s.candidateIdentity(startTime, candidateCIDRs, sourceParsedList)

	// The attribution digest is what a later cycle compares when this syncer is
	// gone (provenance.go).
	attributionHash, _ := attributionDigest(sourceParsedList)

	candidateGen := &Generation{
		SchemaVersion:   SchemaVersion,
		GenerationID:    genID,
		Version:         newVersion,
		CreatedAt:       createdAt,
		ConfigHash:      s.computeConfigHash(),
		AttributionHash: attributionHash,
		CIDRs:           candidateCIDRs,
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
	// the shared matcher.
	write := func() error {
		// Commit candidate generation to durable store before publication
		if err := s.store.Commit(ctx, candidateGen); err != nil {
			return fmt.Errorf("durable commit of policy generation failed: %w", err)
		}

		// Atomically publish new snapshot
		s.matcher.Publish(candidateSnap)

		s.cachedGen = candidateGen

		s.statusMu.Lock()
		s.status = Status{
			Ready:        true,
			Version:      newVersion,
			GenerationID: genID,
			LastSyncTime: startTime,
			LastSuccess:  startTime,
			LastError:    "",
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

// computeConfigHash covers the effective rule content and the schedule. With no
// fetched source, the exception prefixes are the configuration that decides
// whether a durable generation still describes this record.
func (s *Syncer) computeConfigHash() string {
	h := sha256.New()
	for _, prefix := range canonicalPrefixStrings(s.cfg.LocalRules.CIDRs) {
		_, _ = fmt.Fprintf(h, "L:%s\n", prefix)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalPrefixStrings returns the distinct masked prefixes in string form.
// Declaration order and duplicate lines are not changes to the rule set.
func canonicalPrefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		canon := prefix.Masked()
		if _, exists := seen[canon]; exists {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon.String())
	}
	return out
}
