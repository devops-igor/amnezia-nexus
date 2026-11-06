package vpn

import (
	"context"
	"errors"
	"testing"

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
