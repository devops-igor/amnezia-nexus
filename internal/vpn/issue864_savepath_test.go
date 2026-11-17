package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the consumer oracles for the supported settings-save path (#864).
//
// The admin PUT persists the operator's settings and then calls
// Service.StartPolicyRouting, which for an already-active data path routes into
// updateLivePolicyRouting. That path builds a *new* syncer for the save, so
// whether a save discards client DNS evidence is decided there and not by the
// scheduled loop: the forwarder's route cache keys a session's evidence on the
// generation the matcher publishes, and clears every view when it moves.
//
// The save that exposes this is the ordinary settings edit whose effective rules
// are unchanged — the upstream resolver list, the refresh interval — because the
// policy snapshot does not carry those fields. A save that changes the selected
// source or its content must still publish and invalidate, and a save whose fetch
// is refused must leave the authoritative record, the live policy and the write
// ownership exactly as they were.
//
// Everything below is production code except the two fixture-scoped seams the
// other policy oracles already use: TLS trust (and the approved-IP/dial pair) for
// the local list server, and the WAN device name registry. The service entry
// points, lifecycle mutexes, syncer, fetcher, parser, FileStore, matcher, route
// cache adapter and ownership boundary are all real.

// savePathFixture serves policy lists over TLS and can refuse a path, so a save
// can be made to fail at the fetch rather than later.
type savePathFixture struct {
	mu    sync.Mutex
	lists map[string][]string
	fail  map[string]bool
}

func newSavePathFixture(lists map[string][]string) *savePathFixture {
	return &savePathFixture{lists: lists, fail: make(map[string]bool)}
}

func (f *savePathFixture) allow(path string) {
	f.mu.Lock()
	delete(f.fail, path)
	f.mu.Unlock()
}

func (f *savePathFixture) refuse(path string) {
	f.mu.Lock()
	f.fail[path] = true
	f.mu.Unlock()
}

func (f *savePathFixture) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		list, known := f.lists[r.URL.Path]
		refuse := f.fail[r.URL.Path]
		f.mu.Unlock()
		if !known || refuse {
			http.Error(w, "fixture refuses this list", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		for _, domain := range list {
			fmt.Fprintln(w, domain)
		}
	}
}

// savePathServiceOptions builds the activated settings, the saved settings and the
// shared store for one save scenario.
type savePathScenario struct {
	svc    *Service
	store  *policy.FileStore
	cache  *MemoryRouteCache
	ctx    context.Context
	active policy.Settings
	saved  policy.Settings
}

// newSavePathScenario activates the fixture list at pathA, then installs the
// forwarder's route cache on the live matcher and records one DIRECT observation,
// which is the evidence a client's resolved connection depends on.
func newSavePathScenario(t *testing.T, fixture *savePathFixture, server *httptest.Server, active, saved policy.Settings) *savePathScenario {
	t.Helper()

	// Preconditions this oracle depends on: the save leaves the policy sources and
	// therefore the effective rules untouched, while it does change a setting the
	// policy snapshot does not carry.
	cfgActive, err := active.SyncConfig()
	if err != nil {
		t.Fatalf("active SyncConfig: %v", err)
	}
	cfgSaved, err := saved.SyncConfig()
	if err != nil {
		t.Fatalf("saved SyncConfig: %v", err)
	}
	if !reflect.DeepEqual(cfgActive.Sources, cfgSaved.Sources) {
		t.Fatalf("fixture precondition: the save changed the policy sources (%+v -> %+v)", cfgActive.Sources, cfgSaved.Sources)
	}
	if reflect.DeepEqual(active.EffectiveUpstreams(), saved.EffectiveUpstreams()) {
		t.Fatal("fixture precondition: the save does not change the upstream list")
	}

	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	store := policy.NewFileStore(t.TempDir())
	ctx := context.Background()
	if err := svc.StartPolicyRouting(ctx, active, store, string(active.Preset)); err != nil {
		t.Fatalf("activation of the fixture list: %v", err)
	}

	cache := NewMemoryRouteCache()
	cache.AttachMatcher(svc.PolicyMatcher())
	return &savePathScenario{svc: svc, store: store, cache: cache, ctx: ctx, active: active, saved: saved}
}

// observeDirect records the evidence of a client that resolved an address the
// policy list does not contain, which is what makes new flows to it direct.
func (sc *savePathScenario) observeDirect(t *testing.T) (string, netip.Addr) {
	t.Helper()
	const session = "session-save-path"
	evidence := netip.MustParseAddr("93.184.216.34")
	if got := sc.cache.Lookup(session, evidence); got != policy.Unknown {
		t.Fatalf("a fresh session answered %v for the evidence address, want UNKNOWN", got)
	}
	sc.cache.Observe(session, evidence, policy.Direct)
	if got := sc.cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("recorded evidence answered %v, want DIRECT", got)
	}
	return session, evidence
}

// effectiveUpstreams returns the upstream list the live resolver was last given.
func (sc *savePathScenario) effectiveUpstreams(t *testing.T) []policy.Upstream {
	t.Helper()
	sc.svc.mu.Lock()
	defer sc.svc.mu.Unlock()
	return append([]policy.Upstream(nil), sc.svc.dnsUpstreams...)
}

// TestSaveWithUnchangedRulesPreservesClientEvidence is the required oracle: an
// enabled save whose effective rules are unchanged must keep the generation and
// the client evidence, while the requested upstream list still takes effect.
func TestSaveWithUnchangedRulesPreservesClientEvidence(t *testing.T) {
	const pathA = "/policy.lst"
	fixture := newSavePathFixture(map[string][]string{pathA: domainList("savepath", 20)})
	server := httptest.NewTLSServer(fixture.handler())
	defer server.Close()

	active := policySettingsForURL(t, "https://save-path.example"+pathA)
	saved := active
	saved.UpstreamDNS = []policy.Upstream{{Address: "1.1.1.1", Port: 53}}
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	sc := newSavePathScenario(t, fixture, server, active, saved)
	session, evidence := sc.observeDirect(t)

	liveBefore := sc.svc.PolicyMatcher().Current()
	if liveBefore == nil {
		t.Fatal("no live snapshot after activation")
	}
	durableBefore, err := sc.store.Load(sc.ctx)
	if err != nil || durableBefore == nil {
		t.Fatalf("load durable generation before the save: gen=%v err=%v", durableBefore, err)
	}

	// The supported save path: the admin PUT persists the settings and calls this.
	if err := sc.svc.StartPolicyRouting(sc.ctx, saved, sc.store, string(saved.Preset)); err != nil {
		t.Fatalf("upstream-only save: %v", err)
	}

	live := sc.svc.PolicyMatcher().Current()
	if live == nil {
		t.Fatal("no live snapshot after the save")
	}
	if got := sc.cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("a save with unchanged effective rules discarded the client's DIRECT evidence (lookup answered %v): generation %q -> %q, so new flows fall back to the fail-closed PROXY path",
			got, liveBefore.Generation(), live.Generation())
	}
	if live.Generation() != liveBefore.Generation() {
		t.Errorf("save with unchanged effective rules advanced the generation %q -> %q", liveBefore.Generation(), live.Generation())
	}
	if !live.MatchDomain("savepath0.example.com") {
		t.Error("live snapshot lost a rule the fixture list contains")
	}
	durableAfter, err := sc.store.Load(sc.ctx)
	if err != nil || durableAfter == nil {
		t.Fatalf("load durable generation after the save: gen=%v err=%v", durableAfter, err)
	}
	if durableAfter.ContentHash != durableBefore.ContentHash {
		t.Errorf("durable content hash changed on a rules-unchanged save: %q -> %q", durableBefore.ContentHash, durableAfter.ContentHash)
	}
	if durableAfter.ConfigHash != durableBefore.ConfigHash {
		t.Errorf("durable config hash changed on a save that kept the same sources: %q -> %q", durableBefore.ConfigHash, durableAfter.ConfigHash)
	}

	// The requested setting must still be applied, and recorded as the runtime's.
	if got, want := sc.effectiveUpstreams(t), saved.EffectiveUpstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("live upstream list = %+v, want the saved %+v", got, want)
	}
	if got := sc.svc.policyRuntime().settings.UpstreamDNS; !reflect.DeepEqual(got, saved.UpstreamDNS) {
		t.Errorf("runtime settings upstreams = %+v, want the saved %+v", got, saved.UpstreamDNS)
	}
}

// TestSaveWithChangedSourceInvalidatesEvidence is the control that keeps the
// preservation from freezing the policy: selecting a different source publishes
// its content and invalidates the client evidence recorded under the old one.
func TestSaveWithChangedSourceInvalidatesEvidence(t *testing.T) {
	const (
		pathA = "/policy-a.lst"
		pathB = "/policy-b.lst"
	)
	fixture := newSavePathFixture(map[string][]string{
		pathA: domainList("savepath-a", 20),
		pathB: domainList("savepath-b", 20),
	})
	server := httptest.NewTLSServer(fixture.handler())
	defer server.Close()

	active := policySettingsForURL(t, "https://save-path.example"+pathA)
	saved := policySettingsForURL(t, "https://save-path.example"+pathB)
	saved.UpstreamDNS = []policy.Upstream{{Address: "1.1.1.1", Port: 53}}
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	// The scenario helper asserts the sources are equal, which is not this case, so
	// wire the scenario directly.
	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })
	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)
	store := policy.NewFileStore(t.TempDir())
	ctx := context.Background()
	if err := svc.StartPolicyRouting(ctx, active, store, string(active.Preset)); err != nil {
		t.Fatalf("activation of the fixture list: %v", err)
	}
	sc := &savePathScenario{svc: svc, store: store, cache: NewMemoryRouteCache(), ctx: ctx, active: active, saved: saved}
	sc.cache.AttachMatcher(svc.PolicyMatcher())
	session, evidence := sc.observeDirect(t)
	liveBefore := svc.PolicyMatcher().Current()
	durableBefore, err := store.Load(ctx)
	if err != nil || durableBefore == nil {
		t.Fatalf("load durable generation before the save: gen=%v err=%v", durableBefore, err)
	}

	if err := svc.StartPolicyRouting(ctx, saved, store, string(saved.Preset)); err != nil {
		t.Fatalf("changed-source save: %v", err)
	}

	if got := sc.cache.Lookup(session, evidence); got != policy.Unknown {
		t.Fatalf("a save that selected a different source kept the old evidence (lookup answered %v), want UNKNOWN", got)
	}
	live := svc.PolicyMatcher().Current()
	if live == nil || live.Generation() == liveBefore.Generation() {
		t.Fatalf("changed-source save did not publish a new generation (%q)", liveBefore.Generation())
	}
	if !live.MatchDomain("savepath-b0.example.com") {
		t.Error("live snapshot does not carry the saved source's rules")
	}
	if live.MatchDomain("savepath-a0.example.com") {
		t.Error("live snapshot still carries the previous source's rules")
	}
	durableAfter, err := store.Load(ctx)
	if err != nil || durableAfter == nil {
		t.Fatalf("load durable generation after the save: gen=%v err=%v", durableAfter, err)
	}
	if durableAfter.ContentHash == durableBefore.ContentHash {
		t.Errorf("changed-source save left the durable content hash at %q", durableBefore.ContentHash)
	}
	if got, want := sc.effectiveUpstreams(t), saved.EffectiveUpstreams(); !reflect.DeepEqual(got, want) {
		t.Errorf("live upstream list = %+v, want the saved %+v", got, want)
	}
}

// TestFailedSaveWithUnchangedSourcesKeepsWriteOwnership is the second half of the
// refused-save contract, and the one that decides *how* the baseline may be
// adopted: the source is unchanged, so a baseline that published during adoption
// would take write ownership before the fetch is attempted, and a save that then
// fails would leave the runtime that is still serving unable to refresh ever again.
func TestFailedSaveWithUnchangedSourcesKeepsWriteOwnership(t *testing.T) {
	const pathA = "/policy.lst"
	fixture := newSavePathFixture(map[string][]string{pathA: domainList("savepath", 20)})
	server := httptest.NewTLSServer(fixture.handler())
	defer server.Close()

	active := policySettingsForURL(t, "https://save-path.example"+pathA)
	saved := active
	saved.UpstreamDNS = []policy.Upstream{{Address: "1.1.1.1", Port: 53}}
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	sc := newSavePathScenario(t, fixture, server, active, saved)
	session, evidence := sc.observeDirect(t)
	liveBefore := sc.svc.PolicyMatcher().Current()
	if liveBefore == nil {
		t.Fatal("no live snapshot after activation")
	}
	upstreamsBefore := sc.effectiveUpstreams(t)

	// The list host fails exactly while the operator saves the new upstream list.
	fixture.refuse(pathA)
	if err := sc.svc.StartPolicyRouting(sc.ctx, saved, sc.store, string(saved.Preset)); err == nil {
		t.Fatal("an upstream-only save whose source fetch failed reported success")
	}

	if live := sc.svc.PolicyMatcher().Current(); live == nil || live.Generation() != liveBefore.Generation() {
		t.Fatalf("a failed save replaced the live generation (%q)", liveBefore.Generation())
	}
	if got := sc.cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("a failed save discarded the client's DIRECT evidence (lookup answered %v)", got)
	}
	if got := sc.effectiveUpstreams(t); !reflect.DeepEqual(got, upstreamsBefore) {
		t.Errorf("a failed save applied its upstream list anyway: %+v -> %+v", upstreamsBefore, got)
	}

	// The surviving runtime must still own its writes. Its periodic update may be
	// mid-cycle (409, not a refusal), so retry on that and fail on a superseded one.
	fixture.allow(pathA)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, syncErr := sc.svc.SyncPolicyNow(sc.ctx)
		if syncErr == nil {
			break
		}
		if errors.Is(syncErr, policy.ErrSyncSuperseded) {
			t.Fatalf("a refused save took write ownership from the runtime that survived it: %v", syncErr)
		}
		if !errors.Is(syncErr, policy.ErrSyncInProgress) {
			t.Fatalf("the runtime that survived a failed save can no longer publish: %v", syncErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the runtime that survived a failed save never became idle: %v", syncErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestFailedSavePreservesPriorPolicyAndWriteOwnership covers the refused save: the
// fetch fails, so nothing may be published, the prior evidence and durable record
// must survive, and the surviving runtime must still own its writes — otherwise a
// failed settings change would silently stop the running policy from refreshing.
func TestFailedSavePreservesPriorPolicyAndWriteOwnership(t *testing.T) {
	const (
		pathA = "/policy-a.lst"
		pathB = "/policy-b.lst"
	)
	fixture := newSavePathFixture(map[string][]string{
		pathA: domainList("savepath-a", 20),
		pathB: domainList("savepath-b", 20),
	})
	server := httptest.NewTLSServer(fixture.handler())
	defer server.Close()

	active := policySettingsForURL(t, "https://save-path.example"+pathA)
	saved := policySettingsForURL(t, "https://save-path.example"+pathB)

	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })
	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)
	store := policy.NewFileStore(t.TempDir())
	ctx := context.Background()
	if err := svc.StartPolicyRouting(ctx, active, store, string(active.Preset)); err != nil {
		t.Fatalf("activation of the fixture list: %v", err)
	}
	sc := &savePathScenario{svc: svc, store: store, cache: NewMemoryRouteCache(), ctx: ctx, active: active, saved: saved}
	sc.cache.AttachMatcher(svc.PolicyMatcher())
	session, evidence := sc.observeDirect(t)
	liveBefore := svc.PolicyMatcher().Current()
	durableBefore, err := store.Load(ctx)
	if err != nil || durableBefore == nil {
		t.Fatalf("load durable generation before the save: gen=%v err=%v", durableBefore, err)
	}

	fixture.refuse(pathB)
	if err := svc.StartPolicyRouting(ctx, saved, store, string(saved.Preset)); err == nil {
		t.Fatal("a save whose source fetch failed reported success")
	}

	if live := svc.PolicyMatcher().Current(); live == nil || live.Generation() != liveBefore.Generation() {
		t.Fatalf("a failed save replaced the live generation (%q)", liveBefore.Generation())
	}
	if got := sc.cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("a failed save discarded the client's DIRECT evidence (lookup answered %v)", got)
	}
	durableAfter, err := store.Load(ctx)
	if err != nil || durableAfter == nil {
		t.Fatalf("load durable generation after the failed save: gen=%v err=%v", durableAfter, err)
	}
	if durableAfter.GenerationID != durableBefore.GenerationID {
		t.Errorf("a failed save changed the durable generation %q -> %q", durableBefore.GenerationID, durableAfter.GenerationID)
	}
	if got := svc.policyRuntime().settings.CustomURLs; !reflect.DeepEqual(got, active.CustomURLs) {
		t.Errorf("a failed save changed the runtime's selected source to %v", got)
	}

	// The surviving runtime must still own its writes: a refused save may not take
	// write ownership away from the runtime that is still serving. Its loop may be
	// mid-cycle (the documented 409 answer), which is not a refusal, so retry while
	// the syncer reports that and fail only on a superseded write.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, syncErr := svc.SyncPolicyNow(ctx)
		if syncErr == nil {
			break
		}
		if errors.Is(syncErr, policy.ErrSyncSuperseded) {
			t.Fatalf("a refused save took write ownership from the runtime that survived it: %v", syncErr)
		}
		if !errors.Is(syncErr, policy.ErrSyncInProgress) {
			t.Fatalf("the runtime that survived a failed save can no longer publish: %v", syncErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the runtime that survived a failed save never became idle: %v", syncErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if live := svc.PolicyMatcher().Current(); live == nil || live.Generation() != liveBefore.Generation() {
		t.Errorf("the runtime changed its published generation after a failed save (%q)", liveBefore.Generation())
	}
}
