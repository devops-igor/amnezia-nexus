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

	// policyActivationMu serializes activation against disable for the same
	// process. A repeated enabled update must observe a stable runtime (reuse the
	// live data path or create the first one), and a concurrent disable must not
	// interleave with either. It is a lifecycle mutex only: no network, device or
	// database I/O is performed while holding it on the disable side, and the
	// bounded activation work it guards is the same work that already ran
	// unsynchronized.
	policyActivationMu sync.Mutex
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

	policyActivationMu.Lock()
	defer policyActivationMu.Unlock()

	// A repeated enabled update arrives whenever an operator saves settings while
	// policy routing is already on: the admin PUT path only calls
	// StopPolicyRouting when disabling, so it re-enters activation with the data
	// path still live.
	//
	// That must not rebuild the data path. The WAN device name is a single-owner
	// kernel resource, so constructing a second device fails EBUSY while the first
	// is open; and tearing the healthy one down would drop every live flow for a
	// settings change that does not alter the device at all. Reuse the installed
	// matcher and data path instead and let the sync publish the new rules into it
	// atomically, so the change takes effect without interrupting traffic.
	if live := s.policyRuntime(); live != nil && live.matcher != nil {
		return s.updateLivePolicyRouting(ctx, live.matcher, store, cfg, settings, presetID)
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
	//
	// Every other PBRConfig field is left at its zero value deliberately, including
	// HostWANIP and GatewayDNSIP. A non-nil PBRConfig suppresses initPBR's
	// derivation of those values, so supplying our own zero-valued struct would
	// leave HostWANIP unset and make ValidatePBRPrerequisites fail with
	// ErrPBRMissingHostWAN on every activation. initPBR must therefore be allowed
	// to derive the WAN address and gateway itself; only the matcher is ours.
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

// updateLivePolicyRouting applies new settings to an already-active data path.
//
// It deliberately does not rebuild the WAN device, route cache or DNS gateway:
// those do not depend on the operator's source/interval choice, and rebuilding
// them would fail on the single-owner device name and drop live flows. What does
// change is the policy content and the sync schedule, so this:
//
//  1. syncs once into the live matcher, which publishes atomically — a sync
//     failure keeps the previous snapshot (the syncer's own contract) and is
//     reported rather than silently ignored;
//  2. replaces the scheduling loop so the new interval/preset takes effect, and
//     only after the sync succeeded, so a failed update leaves the old loop
//     running on the old rules.
//
// A refused update therefore leaves the previous working configuration intact and
// in effect, which is what the admin PUT's rollback expects.
func (s *Service) updateLivePolicyRouting(ctx context.Context, matcher *policy.Matcher, store policy.Store, cfg policy.SyncConfig, settings policy.Settings, presetID string) error {
	syncer, err := policy.NewSyncer(matcher, nil, store, cfg)
	if err != nil {
		return fmt.Errorf("policy syncer: %w", err)
	}
	syncCtx, cancelSync := context.WithTimeout(ctx, policyActivationTimeout)
	syncRes, syncErr := syncer.SyncOnce(syncCtx)
	cancelSync()
	if syncErr != nil {
		// The live matcher keeps its previous snapshot. Report the failure so the
		// caller can answer 422 and roll the record back, instead of pretending the
		// new settings are in effect.
		return fmt.Errorf("%w: policy update sync failed: %v", ErrPolicyActivationNoRules, syncErr)
	}
	if !syncRes.Published {
		return fmt.Errorf("%w: policy update sync did not publish a snapshot", ErrPolicyActivationNoRules)
	}
	// Only after the content is published does the schedule change, so a refused
	// update leaves the previous loop running on the previous rules.
	s.startPolicyLoop(ctx, syncer, matcher, settings, presetID)
	return nil
}

// startPolicyLoop registers the live runtime and hands the syncer its scheduling
// loop. It runs only after activation succeeded, so a refused activation never
// leaves a background fetcher running.
//
// It replaces any previously registered runtime and cancels that runtime's loop
// first: on a repeated enabled update the old syncer must stop rather than keep
// polling on a superseded schedule, or every save would leak a fetcher.
//
// Lifetime (fix F678-01): the loop must outlive the call that started it. An
// admin PUT reaches this through the HTTP request context, and that context is
// canceled the moment the handler returns — by the shipped
// middleware.OperationTimeout and by net/http's own request lifetime. Deriving
// it from the request made a *successful* save permanently close the syncer: PBR
// stayed enabled with stale rules, the periodic refresh stopped and
// SyncPolicyNow answered ErrSyncerClosed until the process restarted.
//
// So the loop is deliberately detached from the caller's cancellation
// (context.WithoutCancel) and owned by this service instead. Only the
// synchronous work that produced the snapshot stays bounded by the caller's
// context; the long-running fetch schedule is stopped by explicit disable or
// replacement (StopPolicyRouting / a later startPolicyLoop) and by service
// shutdown (Service.Stop and rollbackStartup call StopPolicyRouting).
func (s *Service) startPolicyLoop(ctx context.Context, syncer *policy.Syncer, matcher *policy.Matcher, settings policy.Settings, presetID string) {
	runCtx, runCancel := context.WithCancel(context.WithoutCancel(ctx))
	policyRuntimeMu.Lock()
	old := policyRuntimes[s]
	policyRuntimes[s] = &policyRuntime{
		syncer:   syncer,
		matcher:  matcher,
		settings: settings,
		presetID: presetID,
		cancel:   runCancel,
	}
	policyRuntimeMu.Unlock()

	if old != nil && old.cancel != nil {
		old.cancel()
	}

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

// ensureInitialSnapshot, settleInitialSync and loadLastKnownGood live in
// vpn_pbr_policy_snapshot.go: the activation handshake and the ordering that
// keeps the first sync honest (#678 F678-03).

// StopPolicyRouting stops the scheduling loop and tears the PBR data path down.
// It is safe to call when policy routing was never started.
func (s *Service) StopPolicyRouting() {
	// Serialize against activation so a disable cannot interleave with a
	// re-activation that is publishing new rules into the same data path.
	policyActivationMu.Lock()
	defer policyActivationMu.Unlock()

	runtime := s.stopPolicyLoop()
	if runtime == nil {
		return
	}
	if err := s.TeardownPBR(); err != nil {
		slog.Warn("PBR teardown error", "err", err)
	}
}

// stopPolicyLoop unregisters and cancels the service's policy scheduling loop,
// returning the runtime it removed.
//
// The loop is detached from any request lifetime (see startPolicyLoop), so this
// is the only thing that stops it. It is called from StopPolicyRouting (explicit
// disable and replacement) and from service shutdown, which is what keeps the
// detached lifetime from becoming a process-lifetime goroutine leak.
func (s *Service) stopPolicyLoop() *policyRuntime {
	policyRuntimeMu.Lock()
	runtime := policyRuntimes[s]
	delete(policyRuntimes, s)
	policyRuntimeMu.Unlock()

	if runtime != nil && runtime.cancel != nil {
		runtime.cancel()
	}
	return runtime
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
