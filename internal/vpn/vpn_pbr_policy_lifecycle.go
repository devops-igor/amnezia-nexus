package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
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
	// ErrPolicyActivationNoRules indicates activation was requested but the policy
	// data path could not be brought up: no routing authority is installed, the
	// stored last-known-good generation cannot be used, or no snapshot could be
	// published. It is NOT a rule-count check — zero operator exceptions is a valid
	// policy — so each wrap site names its own cause and the text is deliberately
	// cause-neutral. The name is historical.
	ErrPolicyActivationNoRules = errors.New("vpn: policy routing could not be activated")

	policyRuntimeMu sync.RWMutex
	policyRuntimes  = make(map[*Service]*policyRuntime)

	// policyWriteOwners holds each service's write-ownership boundary (#678
	// F678-04). It is keyed by service rather than stored in policyRuntime because
	// it must outlive a single runtime: a replacement syncer is created *before*
	// it is registered, and it has to take ownership from the runtime it replaces.
	// Retiring deletes the entry, so a later activation starts from a fresh
	// boundary while every retired syncer keeps its already-refused old one.
	policyWriteOwners = make(map[*Service]*policy.WriteOwner)

	// policyActivationFailures records why policy routing is not active for a
	// service whose activation was refused before a runtime existed (startup). It
	// is reported through PolicyStatusSnapshot so an operator can see the reason
	// instead of a panel that simply never turned policy routing on (#678 P2-B).
	// It is cleared as soon as activation succeeds or policy routing is disabled.
	policyActivationFailures = make(map[*Service]string)

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
	GenerationID string `json:"generation_id,omitempty"`
	Version      uint64 `json:"version"`
	CIDRCount    int    `json:"cidr_count"`
	LastSyncTime string `json:"last_sync_time,omitempty"`
	LastSuccess  string `json:"last_success,omitempty"`
	SyncState    string `json:"sync_state"`
	LastError    string `json:"last_error,omitempty"`
	// SourceStats carries the per-component aggregate-list outcome: accepted,
	// excluded by the never-proxy guard, duplicates, conditional status and any
	// failure. It is aggregate metadata, never a client observation.
	SourceStats map[string]policy.SourceSyncStats `json:"source_stats,omitempty"`

	// Inventory is the committed Russian address inventory (issue #919): the
	// source and retrieval date recorded beside the data, its age against the
	// staleness threshold, and whether an operator override is in force.
	//
	// It is reported whether or not policy routing is currently enabled,
	// because the artifact ships with the build and its age is a fact about
	// the binary rather than about the sync. It carries no client addresses.
	Inventory *policy.InventoryStatus `json:"inventory,omitempty"`

	// CDN is the CDN exclusion set the classifier consults (issue #934): the
	// networks whose addresses are proxied even when they fall inside the Russian
	// allocation. It is reported whether or not policy routing is enabled,
	// because the set ships with the build and decides every direct decision
	// that is made.
	//
	// Without it the second classifier input was only visible one flow at a time,
	// so an operator could not answer why a Russian-allocation destination was
	// proxied without reading code.
	CDN *CDNExclusionStatus `json:"cdn,omitempty"`
}

// CDNExclusionStatus is the operator-facing view of the CDN exclusion set: the
// entries in force, where they come from, and — when they cannot be described —
// the reason instead of an empty list.
//
// Entries carries no client addresses and no destinations: it is the static set,
// not a record of what was classified.
type CDNExclusionStatus struct {
	// Source names where the set comes from. It is a built-in table, so this is
	// the identity of that table rather than a feed location.
	Source string `json:"source"`
	// Entries is the exclusion set in ASN order. It is empty when the classifier
	// excludes nothing, which is a fact the surface reports as such.
	Entries []geodb.CDNExclusion `json:"entries"`
	// Error reports entries that could not be described. The set is then not
	// empty — it is unknown — and must not be read as "nothing is excluded".
	Error string `json:"error,omitempty"`
}

// policyRuntime holds the live policy objects for a started service.
type policyRuntime struct {
	syncer   *policy.Syncer
	matcher  *policy.Matcher
	settings policy.Settings
	cancel   context.CancelFunc
}

// policyActivationInput compiles the two things activation needs from an operator
// record: the syncer configuration, and the parsed inventory override the address
// classifier is built from.
//
// Both belong to one derivation because they share the same contract. SyncConfig
// validates the whole record — the address override included — so an override that
// reaches the classifier is one the same validation accepted. Parsing it here
// keeps that pairing in one place instead of leaving activation to remember it,
// and the error is returned rather than swallowed so an unusable body can never
// activate as a shipped-set-only classifier that looks applied.
func policyActivationInput(settings policy.Settings) (policy.SyncConfig, *policy.InventoryOverride, error) {
	cfg, err := settings.SyncConfig()
	if err != nil {
		return policy.SyncConfig{}, nil, fmt.Errorf("policy settings: %w", err)
	}
	override, err := settings.ParsedInventoryOverride()
	if err != nil {
		return policy.SyncConfig{}, nil, fmt.Errorf("policy settings: inventory override: %w", err)
	}
	return cfg, override, nil
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
func (s *Service) StartPolicyRouting(ctx context.Context, settings policy.Settings, store policy.Store) error {
	if s == nil {
		return errors.New("vpn: policy activation requires a service")
	}
	cfg, override, err := policyActivationInput(settings)
	if err != nil {
		return err
	}
	if store == nil {
		return errors.New("vpn: policy activation requires a durable policy store")
	}
	if hook := policyActivationHookForTest; hook != nil {
		// Test seam: runs inside the caller's settings mutation, before any activation
		// work, so a test can hold one mutation while another is attempted.
		hook()
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
		return s.updateLivePolicyRouting(ctx, live.matcher, store, cfg, settings)
	}
	return s.activateFreshPolicyPath(ctx, store, cfg, settings, override)
}

// activateFreshPolicyPath brings up a policy data path for a service that has
// none installed, and is the cold-start half of activation.
//
// It is one function because it is one contract: nothing may accept traffic until
// a snapshot is published AND the routing authority is installed, and the
// prerequisite that decides whether traffic can be classified is read before
// anything is enabled. Splitting it would let a caller reach enablement with the
// matcher published and no classifier, which is exactly the state the guards
// refuse.
//
// The caller holds policyActivationMu, so activation and disable cannot interleave
// inside it.
func (s *Service) activateFreshPolicyPath(ctx context.Context, store policy.Store, cfg policy.SyncConfig, settings policy.Settings, override *policy.InventoryOverride) error {
	matcher := policy.NewMatcher()
	syncer, err := newPolicySyncer(matcher, store, cfg)
	if err != nil {
		return fmt.Errorf("policy syncer: %w", err)
	}
	syncer.AttachOwnership(s.policyWriteOwner())

	// The address classifier is the routing authority: it answers every
	// destination the operator's exception list does not override. Building it can
	// fail when a committed artifact is unusable, and newDestinationClassifier
	// reports that failure and returns nil rather than a partially capable
	// classifier — so this is the one place "the authority is installed" is
	// decided, and the handshake below refuses activation without it.
	classifier := newDestinationClassifier(override)

	// Obtain a snapshot BEFORE the data path can accept traffic. A failure here is
	// not fatal to the panel: PBR stays disabled and the operator sees the reason.
	// The classifier is the routing authority, so it is what this handshake
	// requires; a zero-rule snapshot is a valid override-free policy rather than a
	// reason to refuse.
	if err := ensureInitialSnapshot(ctx, syncer, store, matcher, classifier); err != nil {
		return err
	}

	// Hand initPBR the compiled matcher so it installs exactly this snapshot
	// instead of compiling from an empty source list.
	//
	// The host WAN address is derived here rather than left to initPBR: that
	// function only derives it when no configuration is registered, and this path
	// must register one to hand over the matcher. Deriving explicitly keeps the
	// production derivation (no hardcoded or test address) and fails closed with
	// the same classified error when this host has no usable uplink.
	hostWAN, err := DeriveHostWANIP()
	if err != nil {
		return fmt.Errorf("activate policy routing: %w", err)
	}
	s.SetPBRConfig(PBRConfig{
		Enabled:               true,
		HostWANIP:             hostWAN,
		PolicyMatcher:         matcher,
		InventoryOverride:     override,
		DestinationClassifier: classifier,
	})

	if err := s.initPBR(ctx); err != nil {
		// Leave no half-registered PBR configuration behind: a refused activation
		// must look exactly like "policy routing was never configured", so a later
		// disable or status read cannot observe a phantom matcher.
		s.clearPBRConfig()
		return fmt.Errorf("activate policy routing: %w", err)
	}

	s.startPolicyLoop(ctx, syncer, matcher, settings)
	s.clearPolicyActivationFailure()
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
//  2. replaces the scheduling loop so the new interval takes effect, and
//     only after the sync succeeded, so a failed update leaves the old loop
//     running on the old rules.
//
// A refused update therefore leaves the previous working configuration intact and
// in effect, which is what the admin PUT's rollback expects.
func (s *Service) updateLivePolicyRouting(ctx context.Context, matcher *policy.Matcher, store policy.Store, cfg policy.SyncConfig, settings policy.Settings) error {
	// The routing authority is the destination classifier, and this path replaces
	// it from the new record. Build the replacement BEFORE anything is published:
	// an unusable committed artifact would otherwise install a nil classifier over
	// a live data path, where every destination answers "uncovered", nothing can
	// route DIRECT, and the operator's policy would silently become proxy-everything.
	//
	// A refused update therefore leaves the incumbent classifier, like the
	// incumbent rules, still installed and still deciding.
	override, err := settings.ParsedInventoryOverride()
	if err != nil {
		return fmt.Errorf("inventory override: %w", err)
	}
	classifier := newDestinationClassifier(override)
	if classifier == nil {
		return fmt.Errorf("%w: policy update cannot install the destination classifier", ErrPolicyActivationNoRules)
	}

	syncer, err := newPolicySyncer(matcher, store, cfg)
	if err != nil {
		return fmt.Errorf("policy syncer: %w", err)
	}
	// The replacement takes write ownership by publishing its own generation (see
	// policy.WriteOwner): until that succeeds this runtime keeps the boundary, so a
	// refused update leaves the incumbent writing and serving unchanged. After it
	// succeeds, the incumbent's still-running syncs are refused at their commit.
	syncer.AttachOwnership(s.policyWriteOwner())
	// A save usually changes settings the policy snapshot does not carry — the
	// refresh interval, the inventory override — so its effective rules are
	// unchanged and the cycle must keep the published generation, which is what the
	// forwarder's route caches key client DNS evidence on (#864). Adopting the
	// durable generation is a read: it publishes nothing and commits nothing, so the
	// boundary above is untouched and a save whose fetch is refused below leaves the
	// incumbent runtime still owning its writes. A different source configuration is
	// reported as BaselineForeign and adopted not at all, and the cycle then
	// publishes the fetched content.
	if _, adoptErr := syncer.AdoptBaseline(ctx); adoptErr != nil {
		// An unreadable durable generation must not block a settings change: the cycle
		// below either publishes freshly fetched content or reports its own failure,
		// and the incumbent runtime keeps serving in the meantime.
		slog.Warn("Policy update could not adopt the stored generation as its baseline", "err", adoptErr)
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
	// The inventory override is not part of the compiled snapshot: it is applied
	// to the installed classifier, which is replaced rather than rebuilt. It is
	// applied only after the sync succeeded: a refused update must leave the
	// previous configuration, override included, in effect.
	s.SetInventoryOverride(override)
	// Only after the content is published does the schedule change, so a refused
	// update leaves the previous loop running on the previous rules.
	s.startPolicyLoop(ctx, syncer, matcher, settings)
	return nil
}

// newPolicySyncer builds the syncer one activation/replacement uses.
//
// It fetches nothing: the routing authority is the destination classifier and the
// operator's contribution is the local exception list, so a cycle only compiles
// and publishes the rules the record already holds.
func newPolicySyncer(matcher *policy.Matcher, store policy.Store, cfg policy.SyncConfig) (*policy.Syncer, error) {
	return policy.NewSyncer(matcher, store, cfg)
}

// policyWriteOwner returns this service's write-ownership boundary, creating it
// on first use.
func (s *Service) policyWriteOwner() *policy.WriteOwner {
	policyRuntimeMu.Lock()
	defer policyRuntimeMu.Unlock()
	owner := policyWriteOwners[s]
	if owner == nil {
		owner = policy.NewWriteOwner()
		policyWriteOwners[s] = owner
	}
	return owner
}

// retirePolicyWriteOwner permanently refuses writes from every syncer bound to
// this service's current boundary, and drops the entry so the next activation
// starts from a fresh one.
//
// A retired syncer keeps its own (now refusing) boundary, which is what makes a
// manual sync that outlives an explicit disable unable to commit afterwards.
func (s *Service) retirePolicyWriteOwner() {
	policyRuntimeMu.Lock()
	owner := policyWriteOwners[s]
	delete(policyWriteOwners, s)
	policyRuntimeMu.Unlock()
	if owner != nil {
		// Blocks until any in-flight commit-and-publish section finishes, so once
		// this returns no further write can land for the retired runtime.
		owner.Retire()
	}
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
func (s *Service) startPolicyLoop(ctx context.Context, syncer *policy.Syncer, matcher *policy.Matcher, settings policy.Settings) {
	runCtx, runCancel := context.WithCancel(context.WithoutCancel(ctx))
	policyRuntimeMu.Lock()
	old := policyRuntimes[s]
	policyRuntimes[s] = &policyRuntime{
		syncer:   syncer,
		matcher:  matcher,
		settings: settings,
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
	// Refuse further writes from the runtime being torn down before the data path
	// disappears (#678 F678-04): a manual sync that is still in flight when the
	// admin disables policy routing must not commit or publish afterwards. This is
	// unconditional because a syncer from a failed or already-replaced activation
	// may still be able to write even though no runtime is registered.
	s.retirePolicyWriteOwner()
	// An explicit disable is the operator's decision, not a failure to report.
	s.clearPolicyActivationFailure()
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

// ReportPolicyActivationFailure records why policy routing could not be activated
// so the status surface can explain it. It is used when activation was refused
// before a runtime existed, where the syncer's own status cannot carry the reason.
//
// It never changes the persisted settings: the operator's stored intent is what
// they must be able to repair through the API.
func (s *Service) ReportPolicyActivationFailure(err error) {
	if s == nil || err == nil {
		return
	}
	policyRuntimeMu.Lock()
	policyActivationFailures[s] = err.Error()
	policyRuntimeMu.Unlock()
	slog.Error("Policy routing is not active", "err", err)
}

// clearPolicyActivationFailure drops a recorded activation failure.
func (s *Service) clearPolicyActivationFailure() {
	policyRuntimeMu.Lock()
	delete(policyActivationFailures, s)
	policyRuntimeMu.Unlock()
}

// policyActivationFailure returns the recorded activation failure, if any.
func (s *Service) policyActivationFailure() string {
	policyRuntimeMu.RLock()
	defer policyRuntimeMu.RUnlock()
	return policyActivationFailures[s]
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

	// A refused activation that happened before any runtime existed (panel start)
	// has no syncer to carry the reason, so report the recorded one here. The state
	// stays "disabled": policy routing is off and the reason is exactly why.
	if failure := s.policyActivationFailure(); failure != "" && runtime == nil {
		status.LastError = failure
		status.SyncState = "error"
	}

	applyInventoryStatus(&status, s.effectiveInventoryOverride())
	applyCDNExclusionStatus(&status)
	return status
}

// applyInventoryStatus reports the Russian inventory's provenance and age, with
// any operator override distinguished from the committed set (issues #919, #920).
//
// The override is applied to the shipped set here exactly as the classifier
// applies it, so the counts an operator reads describe the set the packet path is
// consulting: the shipped prefix count and digest stay the shipped set's, and the
// override's own count and digest are reported beside them rather than folded in.
//
// An unusable artifact is reported as an error on the field rather than omitted:
// an operator who sees no inventory at all cannot tell "this build has no
// artifact" from "the artifact is broken and every address is being proxied",
// and only the first is harmless. A configured override is still reported then,
// because "an override is stored and currently useless" is a different fact from
// "nothing is configured".
func applyInventoryStatus(status *PolicyStatus, override *policy.InventoryOverride) {
	inventory, err := policy.ShippedInventory()
	if err != nil {
		status.Inventory = &policy.InventoryStatus{
			Error:               err.Error(),
			MaxAgeDays:          int(policy.DefaultInventoryMaxAge / (24 * time.Hour)),
			OverridePrefixCount: override.PrefixCount(),
			OverrideSHA256:      override.Digest(),
		}
		return
	}
	live := inventory.WithOverride(override).Status(time.Now().UTC(), policy.DefaultInventoryMaxAge)
	status.Inventory = &live
}

// applyCDNExclusionStatus reports the CDN exclusion set the classifier consults
// (issue #934), so an operator can answer why a destination inside the Russian
// allocation was proxied anyway.
//
// The entries come from geodb.CDNExclusions, which reads the table
// IsMultiRegionCDNASN matches against. Nothing is copied or restated here: a
// second list would drift from the classifier's and the surface would then
// describe a set that is not the one deciding packets.
//
// An unreadable set is reported as an error rather than omitted. An absent block
// or an empty list reads as "no CDN network is excluded" — every CDN destination
// proxied — which is the opposite of what an unusable set means.
func applyCDNExclusionStatus(status *PolicyStatus) {
	live := CDNExclusionStatus{Source: geodb.CDNExclusionSource}
	entries, err := geodb.CDNExclusions()
	if err != nil {
		live.Error = err.Error()
	} else {
		live.Entries = entries
	}
	status.CDN = &live
}

// applySyncerStatus copies the live syncer's counters and sync outcome into status.
func applySyncerStatus(status *PolicyStatus, runtime *policyRuntime) {
	live := runtime.syncer.Status()
	status.Ready = live.Ready
	status.GenerationID = live.GenerationID
	status.Version = live.Version
	status.CIDRCount = live.CIDRCount
	status.LastError = live.LastError
	status.SourceStats = live.SourceStats
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
	status.CIDRCount = snap.CIDRCount()
	if status.SyncState == "disabled" {
		status.SyncState = "synced"
	}
}
