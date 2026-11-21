package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
// whether a save publishes a new generation or keeps the incumbent one is
// decided there and not by the scheduled loop.
//
// The save that exposes this is the ordinary settings edit whose effective rules
// are unchanged — the refresh interval — because the policy snapshot does not
// carry it. A save whose fetch is refused must leave the authoritative record,
// the live policy and the write ownership exactly as they were.
//
// Everything below is production code except the two fixture-scoped seams the
// other policy oracles already use: TLS trust (and the approved-IP/dial pair) for
// the local list server, and the WAN device name registry. The service entry
// points, lifecycle mutexes, syncer, fetcher, parser, FileStore, matcher and
// ownership boundary are all real.

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

// savePathScenario holds one save scenario's activated settings, saved settings
// and shared store.
type savePathScenario struct {
	svc    *Service
	store  *policy.FileStore
	ctx    context.Context
	active policy.Settings
	saved  policy.Settings
}

// newSavePathScenario activates the fixture list and returns the scenario the
// save cases run against, after asserting the precondition the preservation case
// depends on: the save leaves the policy sources untouched while it changes a
// setting the policy snapshot does not carry.
func newSavePathScenario(t *testing.T, fixture *savePathFixture, server *httptest.Server, active, saved policy.Settings) *savePathScenario {
	t.Helper()

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
	if active.SyncInterval == saved.SyncInterval {
		t.Fatal("fixture precondition: the save changes no setting outside the compiled snapshot")
	}

	return activateSavePathScenario(t, fixture, server, active, saved)
}

// activateSavePathScenario wires and activates one save scenario: the fixture TLS
// listener as the fetcher, a name-owned WAN device, the production service, a real
// FileStore and the production activation entry point. It asserts nothing about
// the settings, so the changed-source case can use it too.
func activateSavePathScenario(t *testing.T, fixture *savePathFixture, server *httptest.Server, active, saved policy.Settings) *savePathScenario {
	t.Helper()

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

	return &savePathScenario{svc: svc, store: store, ctx: ctx, active: active, saved: saved}
}

// liveRefreshInterval returns the refresh interval the live runtime was last
// given. It is the setting the save-path cases change: the policy snapshot does
// not carry it, so a save that changes only this must keep the published
// generation.
func (sc *savePathScenario) liveRefreshInterval(t *testing.T) time.Duration {
	t.Helper()
	runtime := sc.svc.policyRuntime()
	if runtime == nil {
		t.Fatal("no live policy runtime")
	}
	return runtime.settings.Interval()
}

// TestSaveWithUnchangedRulesPreservesGeneration is the required oracle for the
// supported settings-save path: an enabled save whose effective rules are
// unchanged must keep the published generation, leave the durable record as it
// was, and still apply the setting the operator changed.
//
// The generation is the fact every flow records, so republishing it for rules
// that did not change makes the panel report a policy change that never happened.
func TestSaveWithUnchangedRulesPreservesGeneration(t *testing.T) {
	const pathA = "/policy.lst"
	fixture := newSavePathFixture(map[string][]string{pathA: domainList("savepath", 20)})
	server := httptest.NewTLSServer(fixture.handler())
	defer server.Close()

	active := policySettingsForURL(t, "https://save-path.example"+pathA)
	saved := active
	saved.SyncInterval = active.SyncInterval + 600
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	sc := newSavePathScenario(t, fixture, server, active, saved)

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
	if live.Generation() != liveBefore.Generation() {
		t.Fatalf("a save whose effective rules are unchanged advanced the generation %q -> %q: every flow recorded after it would report a policy change that never happened",
			liveBefore.Generation(), live.Generation())
	}
	if !live.MatchDomain("savepath0.example.com") {
		t.Error("live snapshot lost a rule the fixture list contains")
	}
	durableAfter, err := sc.store.Load(sc.ctx)
	if err != nil || durableAfter == nil {
		t.Fatalf("load durable generation after the save: gen=%v err=%v", durableAfter, err)
	}
	if durableAfter.GenerationID != durableBefore.GenerationID {
		t.Errorf("durable generation changed on a rules-unchanged save: %q -> %q", durableBefore.GenerationID, durableAfter.GenerationID)
	}
	if durableAfter.ContentHash != durableBefore.ContentHash {
		t.Errorf("durable content hash changed on a rules-unchanged save: %q -> %q", durableBefore.ContentHash, durableAfter.ContentHash)
	}
	if durableAfter.ConfigHash != durableBefore.ConfigHash {
		t.Errorf("durable config hash changed on a save that kept the same sources: %q -> %q", durableBefore.ConfigHash, durableAfter.ConfigHash)
	}

	// The requested setting must still be applied, and recorded as the runtime's.
	if got, want := sc.liveRefreshInterval(t), saved.Interval(); got != want {
		t.Errorf("live refresh interval = %s, want the saved %s", got, want)
	}
	if got := sc.svc.policyRuntime().settings.SyncInterval; got != saved.SyncInterval {
		t.Errorf("runtime settings sync interval = %d, want the saved %d", got, saved.SyncInterval)
	}
}

// TestSaveWithChangedSourcePublishesNewGeneration is the control that keeps the
// preservation from freezing the policy: selecting a different source publishes
// its content under a new generation, drops the previous source's rules and still
// applies the requested setting.
func TestSaveWithChangedSourcePublishesNewGeneration(t *testing.T) {
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
	saved.SyncInterval = active.SyncInterval + 600
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	// The precondition helper asserts the sources are equal, which is not this
	// case, so the scenario is wired directly.
	sc := activateSavePathScenario(t, fixture, server, active, saved)

	liveBefore := sc.svc.PolicyMatcher().Current()
	if liveBefore == nil {
		t.Fatal("no live snapshot after activation")
	}
	durableBefore, err := sc.store.Load(sc.ctx)
	if err != nil || durableBefore == nil {
		t.Fatalf("load durable generation before the save: gen=%v err=%v", durableBefore, err)
	}

	if err := sc.svc.StartPolicyRouting(sc.ctx, saved, sc.store, string(saved.Preset)); err != nil {
		t.Fatalf("changed-source save: %v", err)
	}

	live := sc.svc.PolicyMatcher().Current()
	if live == nil || live.Generation() == liveBefore.Generation() {
		t.Fatalf("a save that selected a different source did not publish a new generation (%q)", liveBefore.Generation())
	}
	if !live.MatchDomain("savepath-b0.example.com") {
		t.Error("live snapshot does not carry the saved source's rules")
	}
	if live.MatchDomain("savepath-a0.example.com") {
		t.Error("live snapshot still carries the previous source's rules")
	}
	durableAfter, err := sc.store.Load(sc.ctx)
	if err != nil || durableAfter == nil {
		t.Fatalf("load durable generation after the save: gen=%v err=%v", durableAfter, err)
	}
	if durableAfter.GenerationID != live.Generation() {
		t.Errorf("durable generation = %q, want the published %q", durableAfter.GenerationID, live.Generation())
	}
	if durableAfter.ContentHash == durableBefore.ContentHash {
		t.Errorf("changed-source save left the durable content hash at %q", durableBefore.ContentHash)
	}
	if got, want := sc.liveRefreshInterval(t), saved.Interval(); got != want {
		t.Errorf("live refresh interval = %s, want the saved %s", got, want)
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
	saved.SyncInterval = active.SyncInterval + 600
	if err := saved.Validate(); err != nil {
		t.Fatalf("saved fixture settings are invalid: %v", err)
	}

	sc := newSavePathScenario(t, fixture, server, active, saved)
	liveBefore := sc.svc.PolicyMatcher().Current()
	if liveBefore == nil {
		t.Fatal("no live snapshot after activation")
	}
	intervalBefore := sc.liveRefreshInterval(t)

	// The list host fails exactly while the operator saves the new settings.
	fixture.refuse(pathA)
	if err := sc.svc.StartPolicyRouting(sc.ctx, saved, sc.store, string(saved.Preset)); err == nil {
		t.Fatal("a settings-only save whose source fetch failed reported success")
	}

	if live := sc.svc.PolicyMatcher().Current(); live == nil || live.Generation() != liveBefore.Generation() {
		t.Fatalf("a failed save replaced the live generation (%q)", liveBefore.Generation())
	}
	if got := sc.liveRefreshInterval(t); got != intervalBefore {
		t.Errorf("a failed save applied its refresh interval anyway: %s -> %s", intervalBefore, got)
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
