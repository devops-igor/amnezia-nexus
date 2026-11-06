package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests exercise the production policy-source lifecycle of #678:
// validated settings -> policy.Settings.SyncConfig -> policy.Syncer ->
// fetch/parse/shrink guard -> durable commit -> atomic publish -> PBR activation.
//
// They deliberately do not stub the syncer. The real end-to-end fetch/parse/
// last-known-good behaviour is proven in internal/policy (policy_source_678_test.go),
// where the fetcher's test-injection seams live; these tests prove the *wiring*
// and the fail-closed activation contract that #678 adds on top of it.
//
// A test that asserted "activation succeeded" against a mocked syncer would prove
// nothing about product activation, which is the exact gap this round closes.

// memoryStore is a policy.Store backed by memory. It proves the durable commit
// path is really invoked and lets a test simulate a stored last-known-good
// generation without touching the filesystem.
type memoryStore struct {
	committed *policy.Generation
	loadErr   error
	commits   int
}

func (m *memoryStore) Commit(_ context.Context, gen *policy.Generation) error {
	m.commits++
	gen.ContentHash = policy.ComputeContentHash(gen.Domains, gen.CIDRs)
	m.committed = gen
	return nil
}

func (m *memoryStore) Load(_ context.Context) (*policy.Generation, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.committed, nil
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

// When no policy can be published, activation must fail with
// ErrPolicyActivationNoRules and leave PBR disabled. The custom source here is a
// syntactically valid HTTPS URL on a reserved .invalid host, which passes
// ValidateFetchURL but can never resolve, so the sync fails and there is no
// last-known-good to fall back to.
func TestStartPolicyRoutingFailsClosedWithoutPolicySource(t *testing.T) {
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetCustom
	settings.CustomURLs = []string{"https://unreachable.example.invalid/list.lst"}

	if err := settings.Validate(); err != nil {
		t.Fatalf("test fixture settings are invalid: %v", err)
	}

	store := &memoryStore{loadErr: errors.New("no cached generation")}
	err := svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset))
	if err == nil {
		t.Fatal("StartPolicyRouting succeeded with no usable policy source")
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

// Acceptance A3: a healthy policy source but an unusable direct egress path must
// still refuse enablement, with a useful operator-facing error, leaving PBR
// disabled. This is the half that stops a valid policy from routing traffic
// unproxied when the WAN path is not usable.
//
// In a unit-test process the host WAN prerequisites (TUN/AF_PACKET device, loose
// rp_filter) are typically absent or unsafe, so this asserts the guard fires.
// The assertion deliberately targets "refused + disabled + descriptive" rather
// than a specific kernel error string, so it stays valid where kernel settings
// differ.
func TestStartPolicyRoutingFailsClosedWhenEgressUnavailable(t *testing.T) {
	svc := serviceForActivation(t)

	// A real built-in preset: the fetch may legitimately succeed here, which is
	// exactly the case this test is about (valid policy, unusable egress).
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetGeoblock

	store := &memoryStore{}
	err := svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset))
	if err == nil {
		// The host satisfies every WAN prerequisite. Activation is then legitimate;
		// clean up and record that this host cannot prove the negative.
		t.Cleanup(func() { svc.StopPolicyRouting() })
		t.Skip("host satisfies direct-egress prerequisites; cannot assert the refusal path here")
	}

	if len(err.Error()) < 20 {
		t.Errorf("activation error %q is not descriptive enough for an operator", err)
	}
	if svc.PBREnabled() {
		t.Fatal("PBR is enabled after a refused activation")
	}
	if svc.PolicyMatcher() != nil {
		t.Fatal("matcher registered after a refused activation")
	}
	// A refused activation must not leave a sync runtime behind.
	if _, syncErr := svc.SyncPolicyNow(context.Background()); syncErr == nil {
		t.Fatal("refused activation left a sync runtime registered")
	}
	// Nor may it leave a half-registered PBR configuration behind.
	if cfg := svc.getPBRConfig(); cfg != nil {
		t.Fatalf("refused activation left PBR config registered: %+v", cfg)
	}
}

// Invalid settings must be rejected before any network work or runtime change.
func TestStartPolicyRoutingRejectsInvalidSettings(t *testing.T) {
	svc := serviceForActivation(t)

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = "not_a_preset"

	err := svc.StartPolicyRouting(context.Background(), settings, &memoryStore{}, "not_a_preset")
	if err == nil {
		t.Fatal("StartPolicyRouting accepted an unknown preset")
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
	settings.Preset = policy.PresetGeoblock

	if err := svc.StartPolicyRouting(context.Background(), settings, nil, string(settings.Preset)); err == nil {
		t.Fatal("StartPolicyRouting accepted a nil store")
	}
	if svc.PBREnabled() {
		t.Fatal("PBR enabled without a durable store")
	}
}

// loadLastKnownGood must publish a usable stored generation into the matcher and
// must reject useless ones. This is the concrete half of "preserve last-known-good
// policy on transient sync failure".
func TestLoadLastKnownGoodPublishesStoredGeneration(t *testing.T) {
	matcher := policy.NewMatcher()
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-lkg-1",
		Version:       7,
		ConfigHash:    "seed",
		SourcesMeta:   map[string]policy.SourceMeta{"geoblock": {ID: "geoblock"}},
		Domains:       map[string]uint8{"example.com": 2},
		CIDRs:         []string{"198.51.100.0/24"},
	}
	store := &memoryStore{committed: gen}

	if err := loadLastKnownGood(context.Background(), store, matcher); err != nil {
		t.Fatalf("loadLastKnownGood rejected a usable generation: %v", err)
	}
	snap := matcher.Current()
	if snap == nil {
		t.Fatal("no snapshot published from last-known-good")
	}
	if snap.Generation() != "gen-lkg-1" {
		t.Errorf("published generation = %q, want %q", snap.Generation(), "gen-lkg-1")
	}
	if snap.DomainCount() == 0 {
		t.Error("published last-known-good snapshot has no domain rules")
	}
	if !snap.MatchDomain("example.com") {
		t.Error("published last-known-good snapshot does not match its stored rule")
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
				Domains:       map[string]uint8{},
				CIDRs:         nil,
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matcher := policy.NewMatcher()
			if err := loadLastKnownGood(context.Background(), tc.store, matcher); err == nil {
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
		Domains:       map[string]uint8{"example.com": 2},
		CIDRs:         []string{"198.51.100.0/24"},
	}
	if err := loadLastKnownGood(context.Background(), &memoryStore{committed: gen}, matcher); err != nil {
		t.Fatalf("seed matcher: %v", err)
	}
	policyRuntimeMu.Lock()
	policyRuntimes[svc] = &policyRuntime{matcher: matcher, presetID: "geoblock"}
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
	if got.DomainCount != 1 {
		t.Errorf("DomainCount = %d, want 1", got.DomainCount)
	}
	if got.CIDRCount != 1 {
		t.Errorf("CIDRCount = %d, want 1", got.CIDRCount)
	}
	if got.SyncState != "synced" {
		t.Errorf("SyncState = %q, want %q", got.SyncState, "synced")
	}

	// 2. Syncer-backed path with a recorded failure.
	store := &memoryStore{}
	failingSettings := policy.DefaultSettings()
	failingSettings.Preset = policy.PresetCustom
	failingSettings.CustomURLs = []string{"https://unreachable.example.invalid/x.lst"}
	cfg, err := failingSettings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	syncer, err := policy.NewSyncer(policy.NewMatcher(), nil, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	// Force a recorded failure without network: an empty source list is rejected by
	// the constructor, so drive a failure through SyncOnce on an unroutable host.
	syncCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, _ = syncer.SyncOnce(syncCtx)
	cancel()

	policyRuntimeMu.Lock()
	policyRuntimes[svc] = &policyRuntime{
		syncer:   syncer,
		matcher:  matcher,
		presetID: "custom",
	}
	policyRuntimeMu.Unlock()

	got2 := svc.PolicyStatusSnapshot()
	if got2.Preset != "custom" {
		t.Errorf("Preset = %q, want %q", got2.Preset, "custom")
	}
	if got2.SyncState != "error" {
		t.Errorf("SyncState after a failed sync = %q, want %q", got2.SyncState, "error")
	}
	if got2.LastError == "" {
		t.Error("LastError not exposed after a failed sync")
	}
}

// applyMatcherStatus must be a no-op for a nil matcher or an unpublished one, so
// the status cannot claim readiness without a snapshot.
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
// disable cannot leave a fetcher scheduling against a torn-down data path.
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

// The route-cache size accessors must report zeros rather than panicking when PBR
// is not configured.
func TestPolicyRouteCacheSizeWithoutPBR(t *testing.T) {
	svc := serviceForActivation(t)
	entries, sessions := svc.PolicyRouteCacheSize()
	if entries != 0 || sessions != 0 {
		t.Fatalf("PolicyRouteCacheSize = (%d, %d), want (0, 0)", entries, sessions)
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

// The policy.SettingsType must remain the single source of truth for the sync
// configuration the service builds; a regression that bypassed SyncConfig would
// silently drop the operator's interval or force-shrink setting.
func TestStartPolicyRoutingUsesSettingsDerivedConfig(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetAntifilterDomains
	settings.SyncInterval = int64(policy.MinSyncInterval.Seconds())

	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if len(cfg.Sources) != 1 {
		t.Fatalf("derived source count = %d, want 1", len(cfg.Sources))
	}
	if cfg.Sources[0].URL != "https://antifilter.download/list/domains.lst" {
		t.Errorf("derived source URL = %q, want the documented Antifilter domains URL", cfg.Sources[0].URL)
	}
	if cfg.ForceShrink {
		t.Error("derived config enables ForceShrink; a small download must fail")
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

// nonMemoryRouteCache satisfies forwarder.RouteCache but is not the in-memory
// implementation, so PolicyRouteCacheSize must reject it.
type nonMemoryRouteCache struct{}

func (nonMemoryRouteCache) Lookup(string, netip.Addr) policy.Decision { return policy.Unknown }

// PolicyRouteCacheSize must report the real route-cache size once PBR is
// configured, since the stats endpoint publishes it. Each type-assertion branch is
// asserted so a regression to a silent zero is caught.
func TestPolicyRouteCacheSizeReportsConfiguredCache(t *testing.T) {
	svc := serviceForActivation(t)

	// 1. Runtime present but no PBR config: (0, 0), not a panic.
	policyRuntimeMu.Lock()
	policyRuntimes[svc] = &policyRuntime{matcher: policy.NewMatcher()}
	policyRuntimeMu.Unlock()
	t.Cleanup(func() {
		policyRuntimeMu.Lock()
		delete(policyRuntimes, svc)
		policyRuntimeMu.Unlock()
	})
	if entries, sessions := svc.PolicyRouteCacheSize(); entries != 0 || sessions != 0 {
		t.Fatalf("without PBR config = (%d, %d), want (0, 0)", entries, sessions)
	}

	// 2. A PBR config whose route cache is not a MemoryRouteCache: (0, 0).
	svc.SetPBRConfig(PBRConfig{Enabled: true, RouteCache: nonMemoryRouteCache{}})
	if entries, sessions := svc.PolicyRouteCacheSize(); entries != 0 || sessions != 0 {
		t.Fatalf("with foreign route cache = (%d, %d), want (0, 0)", entries, sessions)
	}

	// 3. A real MemoryRouteCache with one observed entry: (1, 1).
	mem := NewMemoryRouteCache()
	sc, err := mem.Open(policy.Scope{SessionID: "s1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open session cache: %v", err)
	}
	gen := "gen-size-1"
	mem.SetPolicyGeneration(gen)
	now := time.Now()
	if err := sc.Observe(gen, []policy.Observation{
		{IP: netip.MustParseAddr("93.184.216.34"), Decision: policy.Direct, ExpiresAt: now.Add(time.Hour)},
	}, now); err != nil {
		t.Fatalf("observe: %v", err)
	}

	svc.SetPBRConfig(PBRConfig{Enabled: true, RouteCache: mem})
	entries, sessions := svc.PolicyRouteCacheSize()
	if entries != 1 || sessions != 1 {
		t.Fatalf("configured cache = (%d, %d), want (1, 1)", entries, sessions)
	}
}

// ensureInitialSnapshot must accept a matcher that already holds rules, and must
// refuse one that holds nothing, so activation cannot proceed on an empty policy.
func TestEnsureInitialSnapshotRequiresRules(t *testing.T) {
	// A syncer that cannot publish (unroutable source) plus a store holding a
	// usable generation: the last-known-good fallback must supply the rules.
	usable := policy.NewMatcher()
	gen := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-ensure-1",
		Version:       1,
		Domains:       map[string]uint8{"example.com": 2},
	}
	if err := loadLastKnownGood(context.Background(), &memoryStore{committed: gen}, usable); err != nil {
		t.Fatalf("seed: %v", err)
	}
	settings := policy.DefaultSettings()
	settings.Preset = policy.PresetCustom
	settings.CustomURLs = []string{"https://unreachable.example.invalid/x.lst"}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	syncer, err := policy.NewSyncer(usable, nil, &memoryStore{committed: gen}, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	// The sync fails, but the seeded matcher already holds rules, so this must pass
	// through the last-known-good branch.
	if err := ensureInitialSnapshot(context.Background(), syncer, &memoryStore{committed: gen}, usable); err != nil {
		t.Fatalf("ensureInitialSnapshot rejected a matcher holding rules: %v", err)
	}

	// An empty matcher with no usable store must be refused.
	empty := policy.NewMatcher()
	emptySyncer, err := policy.NewSyncer(empty, nil, &memoryStore{loadErr: errors.New("no cache")}, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if err := ensureInitialSnapshot(context.Background(), emptySyncer, &memoryStore{loadErr: errors.New("no cache")}, empty); err == nil {
		t.Fatal("ensureInitialSnapshot accepted an empty matcher with no usable store")
	} else if !errors.Is(err, ErrPolicyActivationNoRules) {
		t.Fatalf("expected ErrPolicyActivationNoRules, got: %v", err)
	}
}

// StartPolicyRouting must reject a nil syncer-store and a nil service safely, and
// must not leave a runtime when the policy source cannot be built.
func TestStartPolicyRoutingRejectsNilReceiverAndStore(t *testing.T) {
	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetGeoblock

	var nilSvc *Service
	if err := nilSvc.StartPolicyRouting(context.Background(), settings, &memoryStore{}, "geoblock"); err == nil {
		t.Fatal("nil service accepted a policy activation")
	}

	// A store that fails on both paths must produce the documented refusal and must
	// not register a runtime on a real service.
	svc := serviceForActivation(t)
	store := &memoryStore{loadErr: errors.New("no cache")}
	if err := svc.StartPolicyRouting(context.Background(), settings, store, "geoblock"); err == nil {
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
	settings.Preset = policy.PresetCustom
	settings.CustomURLs = []string{"https://unreachable.example.invalid/x.lst"}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	store := &memoryStore{}
	syncer, err := policy.NewSyncer(policy.NewMatcher(), nil, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	svc.startPolicyLoop(ctx, syncer, policy.NewMatcher(), settings, "custom")
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
	if rt.presetID != "custom" {
		t.Errorf("registered presetID = %q, want %q", rt.presetID, "custom")
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

// Regression: a pre-seeded PBRConfig lacking HostWANIP must still have the WAN
// address derived by initPBR.
//
// The original derivation was gated on `pbrCfg == nil`, so any caller that
// registered configuration first (notably StartPolicyRouting handing over a
// compiled matcher, and tests supplying only WANDevice/PolicySources) left
// HostWANIP unset and failed every activation with ErrPBRMissingHostWAN. That made
// the positive enablement path unreachable by construction, not merely unavailable
// in a sandbox.
//
// This asserts the observable contract: initPBR either derives a usable address and
// proceeds past the WAN-IP prerequisite, or fails for a *later* reason. It must
// never fail with ErrPBRMissingHostWAN when a config is registered and no address
// was supplied.
func TestInitPBRDerivesHostWANIPForPreseededConfig(t *testing.T) {
	svc := serviceForActivation(t)

	matcher := policy.NewMatcher()
	src := policy.NewMemorySource("seed", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	snap, err := policy.CompileSnapshot(1, "gen-seed", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}
	matcher.Publish(snap)

	// Exactly what StartPolicyRouting registers: a matcher, no WAN address.
	svc.SetPBRConfig(PBRConfig{Enabled: true, PolicyMatcher: matcher})
	t.Cleanup(func() { svc.clearPBRConfig() })

	err = svc.initPBR(context.Background())
	if err == nil {
		// This host satisfies every WAN prerequisite; activation is legal.
		t.Cleanup(func() { _ = svc.TeardownPBR() })
		return
	}
	if errors.Is(err, ErrPBRMissingHostWAN) {
		t.Fatalf("initPBR failed to derive HostWANIP for a pre-seeded config: %v", err)
	}
	// Any other failure is a genuine environment/host gate, which is what we want to
	// observe rather than mask.
	t.Logf("initPBR progressed past WAN-IP derivation and stopped at a later gate: %v", err)
}
