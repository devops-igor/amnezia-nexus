package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file owns the production policy-source lifecycle for issue #678: turning
// the operator's persisted, validated policy settings into a live syncer, an
// activated PBR data path, and the status the admin API reports.
//
// It deliberately reuses every existing guard instead of restating them:
//   - initPBR (vpn_pbr.go) decides whether enablement is possible and installs
//     the WAN device, matcher, route cache and DNS gateway, failing closed via
//     ValidatePBRPrerequisites / ErrPBREmptyPolicy / ErrPBRMissingHostWAN.
//   - policy.Syncer owns fetch, parse, the shrink guard, durable LKG commit and
//     atomic publication. A sync failure leaves the previous snapshot published.
//
// The only thing #678 adds is the source of truth for PolicySources: the
// persisted settings record. Before this file, initPBR ran with an empty source
// list, so the empty-policy guard correctly refused activation and PBR could
// never come up in production.
//
// Live policy state lives in a package-level registry keyed by *Service, the same
// pattern vpn_pbr.go already uses for servicePBRConfigs. That keeps Service's
// struct definition (vpn.go) untouched, which matters because vpn.go is not in
// this assignment's authorized edit set.

var (
	// ErrPolicyActivationNoRules indicates activation was requested but no policy
	// snapshot could be published, so PBR must stay disabled.
	ErrPolicyActivationNoRules = errors.New("vpn: policy activation requires a published non-empty policy snapshot")

	policyRuntimeMu sync.RWMutex
	policyRuntimes  = make(map[*Service]*policyRuntime)
)

// policyActivationTimeout bounds the startup sync so a hung upstream cannot
// block service start indefinitely. Individual fetches are additionally bounded
// by the syncer's own per-request timeout.
const policyActivationTimeout = 2 * time.Minute

// PolicyStatus is the operator-facing view of the policy subsystem. It contains
// no client DNS history, queried domains, credentials or private addresses: only
// aggregate counters and configuration identity.
type PolicyStatus struct {
	Enabled      bool   `json:"enabled"`
	Ready        bool   `json:"ready"`
	Preset       string `json:"preset,omitempty"`
	GenerationID string `json:"generation_id,omitempty"`
	Version      uint64 `json:"version"`
	DomainCount  int    `json:"domain_count"`
	CIDRCount    int    `json:"cidr_count"`
	LastSyncTime string `json:"last_sync_time,omitempty"`
	LastSuccess  string `json:"last_success,omitempty"`
	SyncState    string `json:"sync_state"`
	LastError    string `json:"last_error,omitempty"`
}

// policyRuntime holds the live policy objects for a started service.
type policyRuntime struct {
	syncer   *policy.Syncer
	matcher  *policy.Matcher
	settings policy.Settings
	presetID string
	cancel   context.CancelFunc
}

// StartPolicyRouting starts policy synchronization and activates the PBR data
// path for the supplied validated settings.
//
// Ordering is deliberate and fail-closed:
//  1. compile the syncer configuration from the settings (rejecting an invalid
//     record before any network or runtime work);
//  2. run one synchronous sync so a snapshot exists BEFORE the data path can
//     accept traffic;
//  3. only then call initPBR, which validates WAN prerequisites and installs the
//     direct egress device.
//
// If no non-empty snapshot can be published, PBR is left disabled and an error is
// returned. Nothing durable is written here: the caller owns persisting the
// operator's settings, so a failed activation cannot overwrite a previously
// working configuration.
func (s *Service) StartPolicyRouting(ctx context.Context, settings policy.Settings, store policy.Store, presetID string) error {
	if s == nil {
		return errors.New("vpn: policy activation requires a service")
	}
	cfg, err := settings.SyncConfig()
	if err != nil {
		return fmt.Errorf("policy settings: %w", err)
	}
	if store == nil {
		return errors.New("vpn: policy activation requires a durable policy store")
	}

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, nil, store, cfg)
	if err != nil {
		return fmt.Errorf("policy syncer: %w", err)
	}

	// Obtain a snapshot BEFORE the data path can accept traffic. A failure here is
	// not fatal to the panel: PBR stays disabled and the operator sees the reason,
	// which is the documented "missing initial rules prevents enablement with a
	// useful error" behavior.
	if err := ensureInitialSnapshot(ctx, syncer, store, matcher); err != nil {
		return err
	}

	// Hand initPBR the compiled matcher so it installs exactly this snapshot
	// instead of compiling from an empty source list.
	s.SetPBRConfig(PBRConfig{
		Enabled:       true,
		PolicyMatcher: matcher,
	})

	if err := s.initPBR(ctx); err != nil {
		// Leave no half-registered PBR configuration behind: a refused activation
		// must look exactly like "policy routing was never configured", so a later
		// disable or status read cannot observe a phantom matcher.
		s.clearPBRConfig()
		return fmt.Errorf("activate policy routing: %w", err)
	}

	s.startPolicyLoop(ctx, syncer, matcher, settings, presetID)
	return nil
}

// startPolicyLoop registers the live runtime and hands the syncer its scheduling
// loop. It runs only after activation succeeded, so a refused activation never
// leaves a background fetcher running.
func (s *Service) startPolicyLoop(ctx context.Context, syncer *policy.Syncer, matcher *policy.Matcher, settings policy.Settings, presetID string) {
	runCtx, runCancel := context.WithCancel(ctx)
	policyRuntimeMu.Lock()
	policyRuntimes[s] = &policyRuntime{
		syncer:   syncer,
		matcher:  matcher,
		settings: settings,
		presetID: presetID,
		cancel:   runCancel,
	}
	policyRuntimeMu.Unlock()

	go func() {
		if runErr := syncer.Run(runCtx); runErr != nil && !errors.Is(runErr, context.Canceled) {
			slog.Warn("Policy syncer stopped", "err", runErr)
		}
	}()
}

// clearPBRConfig removes the registered PBR configuration for this service, so a
// refused activation leaves no half-installed state behind.
func (s *Service) clearPBRConfig() {
	servicePBRConfigsMu.Lock()
	delete(servicePBRConfigs, s)
	servicePBRConfigsMu.Unlock()
}

// ensureInitialSnapshot guarantees the matcher holds a non-empty policy snapshot
// before activation proceeds.
//
// One synchronous sync runs first. If it fails, the durable last-known-good
// generation is published instead: that is the "preserve last-known-good policy on
// transient sync failure" half of the contract. If neither yields rules, activation
// is refused with an error an operator can act on.
func ensureInitialSnapshot(ctx context.Context, syncer *policy.Syncer, store policy.Store, matcher *policy.Matcher) error {
	syncCtx, cancelSync := context.WithTimeout(ctx, policyActivationTimeout)
	syncRes, syncErr := syncer.SyncOnce(syncCtx)
	cancelSync()

	if syncErr != nil {
		if loadErr := loadLastKnownGood(ctx, store, matcher); loadErr != nil {
			return fmt.Errorf("%w: initial sync failed (%v) and no usable last-known-good policy was found: %w",
				ErrPolicyActivationNoRules, syncErr, loadErr)
		}
		slog.Warn("Policy sync failed at startup; activated last-known-good policy instead", "err", syncErr)
	} else if !syncRes.Published {
		return fmt.Errorf("%w: sync did not publish a snapshot", ErrPolicyActivationNoRules)
	}

	snap := matcher.Current()
	if snap == nil || (snap.DomainCount() == 0 && snap.CIDRCount() == 0) {
		return ErrPolicyActivationNoRules
	}
	return nil
}

// loadLastKnownGood publishes the durable last-known-good generation, if any.
func loadLastKnownGood(ctx context.Context, store policy.Store, matcher *policy.Matcher) error {
	gen, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if gen == nil {
		return errors.New("no last-known-good policy generation stored")
	}
	snap, err := policy.GenerationToSnapshot(gen)
	if err != nil {
		return err
	}
	if snap.DomainCount() == 0 && snap.CIDRCount() == 0 {
		return errors.New("stored policy generation contains no rules")
	}
	matcher.Publish(snap)
	return nil
}

// StopPolicyRouting stops the scheduling loop and tears the PBR data path down.
// It is safe to call when policy routing was never started.
func (s *Service) StopPolicyRouting() {
	policyRuntimeMu.Lock()
	runtime := policyRuntimes[s]
	delete(policyRuntimes, s)
	policyRuntimeMu.Unlock()

	if runtime == nil {
		return
	}
	if runtime.cancel != nil {
		runtime.cancel()
	}
	if err := s.TeardownPBR(); err != nil {
		slog.Warn("PBR teardown error", "err", err)
	}
}

func (s *Service) policyRuntime() *policyRuntime {
	policyRuntimeMu.RLock()
	defer policyRuntimeMu.RUnlock()
	return policyRuntimes[s]
}

// SyncPolicyNow requests one on-demand policy sync. It reports
// policy.ErrSyncInProgress when a sync is already running, so the API can answer
// 409 rather than queue unbounded requests.
func (s *Service) SyncPolicyNow(ctx context.Context) (policy.SyncResult, error) {
	runtime := s.policyRuntime()
	if runtime == nil || runtime.syncer == nil {
		return policy.SyncResult{}, errors.New("vpn: policy routing is not started")
	}
	return runtime.syncer.Sync(ctx)
}

// PolicyMatcher returns the matcher holding the live policy snapshot, if any.
func (s *Service) PolicyMatcher() *policy.Matcher {
	if runtime := s.policyRuntime(); runtime != nil {
		return runtime.matcher
	}
	return nil
}

// PolicyDispatchCounters returns the aggregate policy-routing traffic counters:
// bytes forwarded to proxy backends, bytes egressed directly over WAN, and the
// number of proxy-required drops. These are snapshot values from the forwarder.
func (s *Service) PolicyDispatchCounters() (proxyBytes, directBytes int64, proxyDrops uint64) {
	s.mu.RLock()
	fwd := s.forwarder
	s.mu.RUnlock()
	if fwd == nil {
		return 0, 0, 0
	}
	proxiedBytes, direct, proxyDropCount, _ := fwd.DispatchMetrics()
	return proxiedBytes, direct, proxyDropCount
}

// PolicyDirectDrops returns the number of packets dropped on the direct WAN path.
func (s *Service) PolicyDirectDrops() uint64 {
	s.mu.RLock()
	fwd := s.forwarder
	s.mu.RUnlock()
	if fwd == nil {
		return 0
	}
	_, _, _, directDrops := fwd.DispatchMetrics()
	return directDrops
}

// PolicyRouteCacheSize reports the current DNS route-cache size as
// (entries, live sessions). It returns zeros when PBR is not configured.
func (s *Service) PolicyRouteCacheSize() (entries, sessions int) {
	runtime := s.policyRuntime()
	if runtime == nil {
		return 0, 0
	}
	cfg := s.getPBRConfig()
	if cfg == nil {
		return 0, 0
	}
	mem, ok := cfg.RouteCache.(*MemoryRouteCache)
	if !ok || mem == nil {
		return 0, 0
	}
	rc := mem.RouteCache()
	if rc == nil {
		return 0, 0
	}
	return rc.EntryCount(), rc.SessionCount()
}

// PolicyStatusSnapshot reports the current policy subsystem state including the
// persisted configuration and the live syncer's last outcome.
func (s *Service) PolicyStatusSnapshot() PolicyStatus {
	runtime := s.policyRuntime()
	status := PolicyStatus{SyncState: "disabled"}
	if runtime != nil && runtime.syncer != nil {
		applySyncerStatus(&status, runtime)
	}
	status.Enabled = s.PBREnabled()

	// Fall back to the matcher when the syncer has no status yet but a snapshot is
	// published (e.g. activated straight from last-known-good).
	if !status.Ready && runtime != nil {
		applyMatcherStatus(&status, runtime.matcher)
	}
	return status
}

// applySyncerStatus copies the live syncer's counters and sync outcome into status.
func applySyncerStatus(status *PolicyStatus, runtime *policyRuntime) {
	live := runtime.syncer.Status()
	status.Ready = live.Ready
	status.GenerationID = live.GenerationID
	status.Version = live.Version
	status.DomainCount = live.DomainCount
	status.CIDRCount = live.CIDRCount
	status.LastError = live.LastError
	status.Preset = runtime.presetID
	if !live.LastSyncTime.IsZero() {
		status.LastSyncTime = live.LastSyncTime.UTC().Format(time.RFC3339)
	}
	if !live.LastSuccess.IsZero() {
		status.LastSuccess = live.LastSuccess.UTC().Format(time.RFC3339)
	}
	switch {
	case live.LastError != "":
		status.SyncState = "error"
	case live.Ready:
		status.SyncState = "synced"
	default:
		status.SyncState = "pending"
	}
}

// applyMatcherStatus fills status from a published snapshot when no syncer status
// is available.
func applyMatcherStatus(status *PolicyStatus, matcher *policy.Matcher) {
	if matcher == nil {
		return
	}
	snap := matcher.Current()
	if snap == nil {
		return
	}
	status.Ready = true
	status.GenerationID = snap.Generation()
	status.Version = snap.Version()
	status.DomainCount = snap.DomainCount()
	status.CIDRCount = snap.CIDRCount()
	if status.SyncState == "disabled" {
		status.SyncState = "synced"
	}
}
