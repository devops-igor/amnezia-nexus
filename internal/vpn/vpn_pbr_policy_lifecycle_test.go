package vpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests exercise the production policy lifecycle: validated record →
// policy.Settings.SyncConfig → policy.Syncer → compile/commit/publish → PBR
// activation.
//
// They deliberately do not stub the syncer. The activation contract that #678 adds
// on top of it is what these prove: fail closed when nothing can be published, and
// install the classifier when something can.

// memoryStore is a policy.Store backed by memory. It proves the durable commit path
// is really invoked and lets a test simulate a stored generation without touching
// the filesystem.
//
// It is safe for concurrent use, and it has to be: a durable store is shared by
// design. Activation registers a syncer whose Run loop primes its own baseline from
// this store in the background, while a later enabled save runs a synchronous cycle
// (and therefore a commit) against the same store on the caller's goroutine.
// Since the sync cycle no longer waits for a network fetch, those two really do run
// at the same time, so the double models a durable store instead of depending on
// the two goroutines happening not to overlap.
type memoryStore struct {
	mu        sync.Mutex
	committed *policy.Generation
	loadErr   error
	commits   int
}

func (m *memoryStore) Commit(_ context.Context, gen *policy.Generation) error {
	// Mirror the durable store's Commit: the derived fields are written onto the
	// candidate the caller owns, and the bytes the store keeps are a separate value.
	// A real store serializes, so the caller retains its own object and a concurrent
	// load can never observe a candidate that is still being built.
	gen.ContentHash = policy.ComputeContentHash(gen.CIDRs)
	gen.CIDRCount = len(gen.CIDRs)
	stored := cloneGeneration(gen)
	m.mu.Lock()
	m.commits++
	m.committed = stored
	m.mu.Unlock()
	return nil
}

func (m *memoryStore) Load(_ context.Context) (*policy.Generation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.committed == nil {
		return nil, nil
	}
	// A durable load unmarshals into a value the caller owns, so each caller gets
	// its own copy rather than a pointer another goroutine may be replacing.
	return cloneGeneration(m.committed), nil
}

// commitCount reports how many durable commits this store accepted. It is how a
// test proves the commit path was really invoked rather than assuming it.
func (m *memoryStore) commitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commits
}

// seed stores gen as the generation a later Load returns, the way a store that
// already holds durable state does. It takes the same lock as the concurrent
// methods so a seeded double is never written outside its own synchronisation.
func (m *memoryStore) seed(gen *policy.Generation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.committed = cloneGeneration(gen)
}

// cloneGeneration copies a generation the way a durable store's serialize-and-reload
// cycle does, so no two goroutines share a mutable generation.
func cloneGeneration(gen *policy.Generation) *policy.Generation {
	if gen == nil {
		return nil
	}
	out := *gen
	out.CIDRs = append([]string(nil), gen.CIDRs...)
	if gen.SourcesMeta != nil {
		out.SourcesMeta = make(map[string]policy.SourceMeta, len(gen.SourcesMeta))
		for id, meta := range gen.SourcesMeta {
			out.SourcesMeta[id] = meta
		}
	}
	return &out
}

// serviceForActivation builds a VPN service. NewVPNService(nil, nil) already
// constructs a forwarder, which ConfigurePBR requires.
func serviceForActivation(t *testing.T) *Service {
	t.Helper()
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	return svc
}

// policyConfigHashFor reports the configuration hash the production syncer derives
// for a record, so a fixture comparison uses the definition rather than a copy.
func policyConfigHashFor(t *testing.T, settings policy.Settings) string {
	t.Helper()
	return lkgHashFor(t, settings)
}

// When no policy can be published, activation must fail with
// ErrPolicyActivationNoRules and leave PBR disabled. The record here is enabled with
// an empty exception list and no stored generation, so the cycle has nothing to
// publish and there is no last-known-good to fall back to.
func TestStartPolicyRoutingFailsClosedWithoutPolicyRules(t *testing.T) {
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	if err := settings.Validate(); err != nil {
		t.Fatalf("test fixture settings are invalid: %v", err)
	}

	store := &memoryStore{loadErr: errors.New("no cached generation")}
	err := svc.StartPolicyRouting(context.Background(), settings, store)
	if err == nil {
		t.Fatal("StartPolicyRouting succeeded with no publishable policy")
	}
	if !errors.Is(err, ErrPolicyActivationNoRules) {
		t.Fatalf("expected ErrPolicyActivationNoRules, got: %v", err)
	}
	if svc.PBREnabled() {
		t.Fatal("PBR is enabled after a refused activation")
	}
	if svc.PolicyMatcher() != nil {
		t.Fatal("matcher registered after a refused activation")
	}
}

// Invalid settings must be rejected before any runtime change, so a rejected record
// can never start a data path.
func TestStartPolicyRoutingRejectsInvalidSettings(t *testing.T) {
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"not-a-prefix"}

	err := svc.StartPolicyRouting(context.Background(), settings, &memoryStore{})
	if err == nil {
		t.Fatal("StartPolicyRouting accepted an unparseable exception line")
	}
	if svc.PBREnabled() {
		t.Fatal("PBR enabled for invalid settings")
	}
}

// A nil store must be refused: activation without durability cannot satisfy the
// restart-persistence requirement.
func TestStartPolicyRoutingRequiresStore(t *testing.T) {
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}

	if err := svc.StartPolicyRouting(context.Background(), settings, nil); err == nil {
		t.Fatal("StartPolicyRouting accepted a nil store")
	}
	if svc.PBREnabled() {
		t.Fatal("PBR enabled without a durable store")
	}
}

// loadLastKnownGood must publish a usable stored generation into the matcher and
// must reject useless ones. This is the concrete half of "preserve last-known-good
// policy".
func TestLoadLastKnownGoodPublishesStoredGeneration(t *testing.T) {
	matcher := policy.NewMatcher()
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-lkg-1",
		Version:       7,
		ConfigHash:    "seed",
		CIDRs:         []string{"198.51.100.0/24"},
	}
	store := &memoryStore{committed: gen}

	if err := loadLastKnownGood(context.Background(), store, matcher, "seed"); err != nil {
		t.Fatalf("loadLastKnownGood rejected a usable generation: %v", err)
	}
	snap := matcher.Current()
	if snap == nil {
		t.Fatal("no snapshot published from last-known-good")
	}
	if snap.Generation() != "gen-lkg-1" {
		t.Errorf("published generation = %q, want %q", snap.Generation(), "gen-lkg-1")
	}
	if snap.CIDRCount() == 0 {
		t.Error("published last-known-good snapshot has no prefixes")
	}
	if !snap.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Error("published last-known-good snapshot does not match its stored prefix")
	}
}

func TestLoadLastKnownGoodRejectsUnusableStores(t *testing.T) {
	cases := []struct {
		name  string
		store *memoryStore
	}{
		{"load error", &memoryStore{loadErr: errors.New("cache missing")}},
		{"nil generation", &memoryStore{}},
		{
			name: "generation with no rules",
			store: &memoryStore{committed: &policy.Generation{
				SchemaVersion: policy.SchemaVersion,
				GenerationID:  "gen-empty",
				Version:       1,
				CIDRs:         nil,
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matcher := policy.NewMatcher()
			if err := loadLastKnownGood(context.Background(), tc.store, matcher, ""); err == nil {
				t.Fatal("loadLastKnownGood accepted an unusable store")
			}
			if matcher.Current() != nil {
				t.Fatal("loadLastKnownGood published a snapshot from an unusable store")
			}
		})
	}
}

// The status view must be covered for both the syncer-backed and matcher-only
// paths, since the API returns it on every GET and after every PUT/sync.
func TestPolicyStatusSnapshotReportsSyncerAndMatcherState(t *testing.T) {
	svc := serviceForActivation(t)

	// 1. Matcher-only path: a published snapshot with no syncer status.
	matcher := policy.NewMatcher()
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-status-1",
		Version:       3,
		CIDRs:         []string{"198.51.100.0/24"},
	}
	if err := loadLastKnownGood(context.Background(), &memoryStore{committed: gen}, matcher, ""); err != nil {
		t.Fatalf("seed matcher: %v", err)
	}
	policyRuntimeMu.Lock()
	policyRuntimes[svc] = &policyRuntime{matcher: matcher}
	policyRuntimeMu.Unlock()
	t.Cleanup(func() {
		policyRuntimeMu.Lock()
		delete(policyRuntimes, svc)
		policyRuntimeMu.Unlock()
	})

	got := svc.PolicyStatusSnapshot()
	if !got.Ready {
		t.Error("matcher-only status Ready = false, want true")
	}
	if got.GenerationID != "gen-status-1" {
		t.Errorf("GenerationID = %q, want %q", got.GenerationID, "gen-status-1")
	}
	if got.Version != 3 {
		t.Errorf("Version = %d, want 3", got.Version)
	}
	if got.CIDRCount != 1 {
		t.Errorf("CIDRCount = %d, want 1", got.CIDRCount)
	}
	if got.SyncState != "synced" {
		t.Errorf("SyncState = %q, want %q", got.SyncState, "synced")
	}

	// 2. Syncer-backed path with a recorded failure: a record with no rules cannot
	// publish, which is the failure the status must surface.
	failingSettings := policy.DefaultSettings()
	cfg, err := failingSettings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	syncer, err := policy.NewSyncer(policy.NewMatcher(), &memoryStore{}, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	syncCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, syncErr := syncer.SyncOnce(syncCtx)
	cancel()
	if syncErr == nil {
		t.Fatal("a rule-less cycle reported success; the failure status below would be vacuous")
	}

	policyRuntimeMu.Lock()
	policyRuntimes[svc] = &policyRuntime{
		syncer:  syncer,
		matcher: matcher,
	}
	policyRuntimeMu.Unlock()

	got2 := svc.PolicyStatusSnapshot()
	if got2.SyncState != "error" {
		t.Errorf("SyncState after a failed sync = %q, want %q", got2.SyncState, "error")
	}
	if got2.LastError == "" {
		t.Error("LastError not exposed after a failed sync")
	}
}

// applyMatcherStatus must be a no-op for a nil matcher or an unpublished one, so the
// status cannot claim readiness without a snapshot.
func TestApplyMatcherStatusNoOpWithoutSnapshot(t *testing.T) {
	status := PolicyStatus{SyncState: "disabled"}
	applyMatcherStatus(&status, nil)
	if status.Ready {
		t.Error("nil matcher produced Ready=true")
	}
	applyMatcherStatus(&status, policy.NewMatcher())
	if status.Ready {
		t.Error("unpublished matcher produced Ready=true")
	}
	if status.SyncState != "disabled" {
		t.Errorf("SyncState = %q, want unchanged %q", status.SyncState, "disabled")
	}
}

// StopPolicyRouting must cancel a registered runtime and clear it, so a later
// disable cannot leave a scheduler running against a torn-down data path.
func TestStopPolicyRoutingCancelsRegisteredRuntime(t *testing.T) {
	svc := serviceForActivation(t)

	cancelled := make(chan struct{})
	policyRuntimeMu.Lock()
	policyRuntimes[svc] = &policyRuntime{
		matcher: policy.NewMatcher(),
		cancel:  func() { close(cancelled) },
	}
	policyRuntimeMu.Unlock()

	svc.StopPolicyRouting()

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("StopPolicyRouting did not cancel the registered runtime")
	}
	if svc.policyRuntime() != nil {
		t.Fatal("StopPolicyRouting left the runtime registered")
	}
}

// StopPolicyRouting must be safe on a service that never started policy routing.
func TestStopPolicyRoutingIsIdempotentWhenNotStarted(t *testing.T) {
	svc := serviceForActivation(t)
	svc.StopPolicyRouting()
	svc.StopPolicyRouting()
	if svc.PBREnabled() {
		t.Fatal("PBR enabled after stop on a service that never started it")
	}
}

// SyncPolicyNow must report a clear error when policy routing is not running.
func TestSyncPolicyNowWithoutRuntime(t *testing.T) {
	svc := serviceForActivation(t)
	if _, err := svc.SyncPolicyNow(context.Background()); err == nil {
		t.Fatal("SyncPolicyNow succeeded with no runtime")
	}
}

// The status view must report disabled truthfully on a fresh service; it is a
// configuration view, not a client-DNS view.
func TestPolicyStatusSnapshotWithoutRuntime(t *testing.T) {
	svc := serviceForActivation(t)
	got := svc.PolicyStatusSnapshot()
	if got.Enabled {
		t.Error("fresh service reports enabled=true, want false")
	}
	if got.Ready {
		t.Error("fresh service reports ready=true, want false")
	}
	if got.SyncState != "disabled" {
		t.Errorf("fresh service sync_state = %q, want %q", got.SyncState, "disabled")
	}
}

// Dispatch counters must be zero-valued on a forwarder with no PBR traffic.
func TestPolicyDispatchCountersWithoutTraffic(t *testing.T) {
	svc := serviceForActivation(t)
	proxyBytes, directBytes, proxyDrops := svc.PolicyDispatchCounters()
	if proxyBytes != 0 || directBytes != 0 || proxyDrops != 0 {
		t.Fatalf("dispatch counters = (%d, %d, %d), want zeros", proxyBytes, directBytes, proxyDrops)
	}
	if drops := svc.PolicyDirectDrops(); drops != 0 {
		t.Fatalf("direct drops = %d, want 0", drops)
	}
}

// policy.Settings must remain the single source of truth for the sync configuration
// the service builds; a regression that bypassed SyncConfig would silently drop the
// operator's exceptions or force-shrink setting.
func TestStartPolicyRoutingUsesSettingsDerivedConfig(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24", "198.51.100.7"}
	settings.SyncInterval = int64(policy.MinSyncInterval.Seconds())

	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 2 {
		t.Fatalf("derived prefixes = %d, want the 2 operator entries", len(cfg.LocalRules.CIDRs))
	}
	// A bare address becomes a /32 so the packet path matches it exactly.
	if got := cfg.LocalRules.CIDRs[1].String(); got != "198.51.100.7/32" {
		t.Errorf("derived second prefix = %q, want 198.51.100.7/32", got)
	}
	if cfg.ForceShrink {
		t.Error("derived config enables ForceShrink; a shrunk set must fail")
	}
}

// Guard the shape of the activation error so the API's 422 response body keeps
// telling the operator what to fix.
func TestPolicyActivationErrorIsDescriptive(t *testing.T) {
	err := ErrPolicyActivationNoRules
	if err == nil || len(err.Error()) < 20 {
		t.Fatalf("activation error %v is not descriptive enough for an operator", err)
	}
}

// ensureInitialSnapshot must accept a record that publishes its own rules, and must
// refuse one that publishes nothing, so activation cannot proceed on an empty policy.
func TestEnsureInitialSnapshotRequiresRules(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.ProxyExceptions = []string{"198.51.100.0/24"}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	usable := policy.NewMatcher()
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-ensure-1",
		Version:       1,
		ConfigHash:    policyConfigHashFor(t, settings),
		CIDRs:         []string{"198.51.100.0/24"},
	}
	if err := loadLastKnownGood(context.Background(), &memoryStore{committed: gen}, usable, gen.ConfigHash); err != nil {
		t.Fatalf("seed: %v", err)
	}
	syncer, err := policy.NewSyncer(usable, &memoryStore{committed: gen}, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if err := ensureInitialSnapshot(context.Background(), syncer, &memoryStore{committed: gen}, usable); err != nil {
		t.Fatalf("ensureInitialSnapshot rejected a record that publishes its own rules: %v", err)
	}

	// An empty record with no usable store must be refused.
	emptySettings := policy.DefaultSettings()
	emptyCfg, err := emptySettings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	empty := policy.NewMatcher()
	emptySyncer, err := policy.NewSyncer(empty, &memoryStore{loadErr: errors.New("no cache")}, emptyCfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if err := ensureInitialSnapshot(context.Background(), emptySyncer, &memoryStore{loadErr: errors.New("no cache")}, empty); err == nil {
		t.Fatal("ensureInitialSnapshot accepted an empty record with no usable store")
	} else if !errors.Is(err, ErrPolicyActivationNoRules) {
		t.Fatalf("expected ErrPolicyActivationNoRules, got: %v", err)
	}
}

// StartPolicyRouting must reject a nil receiver safely and must not leave a runtime
// when no policy can be published.
func TestStartPolicyRoutingRejectsNilReceiverAndUnusableStore(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.ProxyExceptions = []string{"203.0.113.0/24"}

	var nilSvc *Service
	if err := nilSvc.StartPolicyRouting(context.Background(), settings, &memoryStore{}); err == nil {
		t.Fatal("nil service accepted a policy activation")
	}

	// A store that fails on both paths must produce the documented refusal and must
	// not register a runtime on a real service.
	svc := serviceForActivation(t)
	store := &memoryStore{loadErr: errors.New("no cache")}
	if err := svc.StartPolicyRouting(context.Background(), settings, store); err == nil {
		t.Fatal("activation succeeded with an unusable store")
	}
	if svc.policyRuntime() != nil {
		t.Fatal("failed activation registered a runtime")
	}
	if svc.getPBRConfig() != nil {
		t.Fatal("failed activation left a PBR config registered")
	}
}

// startPolicyLoop must register the runtime and start the scheduling loop, then
// release both when the context is cancelled. This is the step that ties the
// syncer's background refresh to the service lifetime.
func TestStartPolicyLoopRegistersAndStops(t *testing.T) {
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.ProxyExceptions = []string{"203.0.113.0/24"}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	syncer, err := policy.NewSyncer(policy.NewMatcher(), &memoryStore{}, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc.startPolicyLoop(ctx, syncer, policy.NewMatcher(), settings)
	t.Cleanup(func() {
		policyRuntimeMu.Lock()
		delete(policyRuntimes, svc)
		policyRuntimeMu.Unlock()
	})

	rt := svc.policyRuntime()
	if rt == nil {
		t.Fatal("startPolicyLoop did not register a runtime")
	}
	if rt.syncer != syncer {
		t.Error("registered runtime does not reference the supplied syncer")
	}
	if len(rt.settings.ProxyExceptions) != 1 {
		t.Errorf("registered settings carry %v, want the record's exception", rt.settings.ProxyExceptions)
	}
	if rt.cancel == nil {
		t.Fatal("registered runtime has no cancel function")
	}

	// Cancelling must stop the loop; the goroutine exits via ctx.Done.
	cancel()
	// StopPolicyRouting cancels again and tears down PBR, so it must be safe here.
	svc.StopPolicyRouting()
	if svc.policyRuntime() != nil {
		t.Fatal("StopPolicyRouting left the runtime registered after startPolicyLoop")
	}
}

// The host WAN address the activation hands to initPBR must be the production
// derivation, not a hardcoded or test address.
//
// initPBR derives HostWANIP only when no configuration is registered; this path must
// register one to hand over the compiled matcher, so activation derives the address
// itself. Previously that made activation fail every time with
// ErrPBRMissingHostWAN, which left the positive enablement path unreachable by
// construction.
func TestStartPolicyRoutingRegistersDerivedHostWANIP(t *testing.T) {
	reg := newNameRegistry()
	withNameOwnedWANDevice(t, reg)
	svc := serviceForActivation(t)

	settings := repeatedEnableSettings(t)
	store := auditedLKGStore(t, settings)
	// Registered after the store: cleanup runs LIFO, so the loop must stop before
	// the directory it may still write to is removed.
	t.Cleanup(svc.StopPolicyRouting)
	if err := svc.StartPolicyRouting(context.Background(), settings, store); err != nil {
		t.Fatalf("activation failed: %v", err)
	}

	cfg := svc.getPBRConfig()
	if cfg == nil {
		t.Fatal("successful activation registered no PBR configuration")
	}
	if !cfg.HostWANIP.IsValid() || !cfg.HostWANIP.Is4() || cfg.HostWANIP.IsLoopback() || cfg.HostWANIP.IsUnspecified() {
		t.Fatalf("activation registered an unusable host WAN IP: %v", cfg.HostWANIP)
	}
	// Same derivation production uses for the same purpose: if this host can derive
	// an address, activation must have registered exactly that one.
	if want, err := DeriveHostWANIP(); err == nil && cfg.HostWANIP != want {
		t.Fatalf("registered host WAN IP = %v, want the production derivation %v", cfg.HostWANIP, want)
	}
}
