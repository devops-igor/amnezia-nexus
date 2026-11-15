package vpn

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This is the permanent regression oracle for issue #678 finding F678-06: a Run
// belonging to a replaced runtime republished its own last-known-good baseline
// after the replacement had been accepted and refreshed. PrimeBaseline prepared the
// generation (load, hash, compile) without any ownership check and then published it
// unconditionally, so the live matcher could hold the old source's rules while the
// durable store, the runtime status and the registered preset all named the new one.
//
// The decisive condition is a held *baseline load*, not a timing window: the store
// wrapper below returns the real read first and then blocks, so the old Run sits
// between "the generation has been obtained" and "it is published" while the new
// source is accepted and refreshed. Only the store wrapper, fixture TLS trust and
// the WAN device are substituted; the service entry points, syncer, fetch, parser,
// FileStore, matcher and ownership boundary are production code.

// gatedBaselineStore wraps a real store and holds exactly one Load call in flight,
// after the underlying read has returned.
type gatedBaselineStore struct {
	inner   policy.Store
	holdAt  int
	held    chan struct{}
	release chan struct{}

	mu    sync.Mutex
	loads int
	once  sync.Once
}

func newGatedBaselineStore(inner policy.Store, holdAt int) *gatedBaselineStore {
	return &gatedBaselineStore{
		inner:   inner,
		holdAt:  holdAt,
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (g *gatedBaselineStore) Load(ctx context.Context) (*policy.Generation, error) {
	gen, err := g.inner.Load(ctx)
	g.mu.Lock()
	g.loads++
	n := g.loads
	g.mu.Unlock()
	if n == g.holdAt {
		g.once.Do(func() { close(g.held) })
		<-g.release
	}
	return gen, err
}

func (g *gatedBaselineStore) Commit(ctx context.Context, gen *policy.Generation) error {
	return g.inner.Commit(ctx, gen)
}

// releaseHeld lets the frozen baseline preparation continue.
func (g *gatedBaselineStore) releaseHeld() {
	g.mu.Lock()
	select {
	case <-g.release:
	default:
		close(g.release)
	}
	g.mu.Unlock()
}

// TestSupersededRunBaselineCannotRepublishOldRules is the F678-06 regression.
func TestSupersededRunBaselineCannotRepublishOldRules(t *testing.T) {
	const (
		pathA = "/policy-a.lst"
		pathB = "/policy-b.lst"
	)
	// A serves 20 rules including a domain only A knows; B serves 12 (>= 50%, so the
	// shrink guard is not what decides anything here) including the protected one.
	listA := append(domainList("a", 19), "stale-a-only.example.com")
	listB := append(domainList("b", 11), "new-protected.example.com")

	gate := newPolicyGate()
	server := newGatedPolicyServer(gate, map[string][]string{pathA: listA, pathB: listB})
	defer server.Close()
	t.Cleanup(gate.releaseAll)

	settingsA := policySettingsForURL(t, "https://audit-a.example"+pathA)
	settingsB := policySettingsForURL(t, "https://audit-b.example"+pathB)

	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	// Load #1 is activation's own baseline prime; load #2 is the asynchronous Run
	// baseline of the runtime that activation just registered, which is the one this
	// regression freezes.
	store := newGatedBaselineStore(auditedLKGStore(t, settingsA), 2)
	t.Cleanup(store.releaseHeld)

	if err := svc.StartPolicyRouting(context.Background(), settingsA, store, string(settingsA.Preset)); err != nil {
		t.Fatalf("activation of source A failed: %v", err)
	}
	select {
	case <-store.held:
	case <-time.After(15 * time.Second):
		t.Fatal("source A's Run never reached its baseline load; the held-baseline scenario did not run")
	}

	// The operator saves source B while A's baseline preparation is frozen. B is
	// published, takes write ownership and A's loop is cancelled.
	if err := svc.StartPolicyRouting(context.Background(), settingsB, store, string(settingsB.Preset)); err != nil {
		t.Fatalf("replacement with source B failed: %v", err)
	}
	// Wait for B's immediate refresh to be *published*, not merely fetched: the
	// durable generation must differ from the one B's update committed, and the
	// matcher must already carry that newer generation. Releasing the old baseline
	// before this point would let B's own refresh mask a stale republication and make
	// the regression pass for the wrong reason.
	firstB, err := store.Load(context.Background())
	if err != nil || firstB == nil {
		t.Fatalf("reload B's committed generation: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		gen, loadErr := store.Load(context.Background())
		snap := svc.PolicyMatcher().Current()
		if loadErr == nil && gen != nil && snap != nil &&
			gen.GenerationID != firstB.GenerationID && snap.Generation() == gen.GenerationID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B's immediate refresh never published (requests=%d, durable=%v)", gate.count(pathB), gen != nil)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Release A's frozen baseline. It must be refused at publication.
	store.releaseHeld()

	// Bounded quiet window: a publication is immediate once the load returns, so if
	// the superseded baseline were still allowed to publish it would do so here and
	// stay until B's next scheduled refresh.
	quietUntil := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(quietUntil) {
		if snap := svc.PolicyMatcher().Current(); snap != nil && snap.MatchDomain("stale-a-only.example.com") {
			t.Fatalf("the superseded runtime republished its old baseline over the accepted policy (F678-06): live rules=%d include the retired source's rule", snap.DomainCount())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Live policy.
	live := svc.PolicyMatcher()
	if live == nil {
		t.Fatal("no live matcher after the replacement")
	}
	snap := live.Current()
	if snap == nil {
		t.Fatal("no live snapshot after the replacement")
	}
	if !snap.MatchDomain("new-protected.example.com") {
		t.Fatalf("the accepted source's protected rule is not live (F678-06): %d rules", snap.DomainCount())
	}
	if snap.MatchDomain("stale-a-only.example.com") {
		t.Fatal("the retired source's rule is live again: the superseded baseline was published (F678-06)")
	}
	if got := snap.DomainCount(); got != len(listB) {
		t.Fatalf("live policy has %d rules, want the accepted source's %d (F678-06)", got, len(listB))
	}
	// Durable policy, reloaded from the store. Live and durable must name the same
	// accepted generation; A's seeded last-known-good has a fixed generation id, so a
	// republished baseline is recognisable here as well as by its rules.
	reloaded, err := store.Load(context.Background())
	if err != nil || reloaded == nil {
		t.Fatalf("reload the durable generation: %v", err)
	}
	if reloaded.ConfigHash != svc.policyRuntime().syncer.ConfigHash() {
		t.Fatalf("durable generation does not belong to the accepted source: %s", reloaded.ConfigHash)
	}
	if got, want := snap.Generation(), reloaded.GenerationID; got == "gen-audit-seed" || got != want {
		t.Fatalf("live generation = %q, want the accepted durable generation %q (F678-06)", got, want)
	}
	if _, ok := reloaded.Domains["stale-a-only.example.com"]; ok {
		t.Fatal("the durable generation contains the retired source's rule (F678-06)")
	}
	if _, ok := reloaded.Domains["new-protected.example.com"]; !ok {
		t.Fatal("the durable generation lost the accepted source's protected rule (F678-06)")
	}

	// Runtime status and registered settings still describe the accepted source: a
	// superseded generation must never be advertised.
	status := svc.PolicyStatusSnapshot()
	if status.DomainCount != len(listB) {
		t.Fatalf("runtime status reports %d rules, want the accepted source's %d (F678-06)", status.DomainCount, len(listB))
	}
	if status.GenerationID == "gen-audit-seed" || status.GenerationID != reloaded.GenerationID {
		t.Fatalf("runtime status advertises generation %q, want the accepted %q (F678-06)", status.GenerationID, reloaded.GenerationID)
	}
	if status.LastError != "" {
		t.Fatalf("runtime status reports an error after a successful replacement: %q", status.LastError)
	}
	if !status.Enabled || !status.Ready {
		t.Fatalf("runtime status is not enabled/ready after the replacement: %+v", status)
	}
	runtimeSettings := svc.policyRuntime().settings
	if len(runtimeSettings.CustomURLs) != 1 || runtimeSettings.CustomURLs[0] != settingsB.CustomURLs[0] {
		t.Fatalf("runtime settings identify %v, want the accepted source %v", runtimeSettings.CustomURLs, settingsB.CustomURLs)
	}

	// Control: the accepted source can still sync and publish afterwards, so the
	// fence refuses obsolete writes without freezing the live runtime.
	if _, err := svc.SyncPolicyNow(context.Background()); err != nil {
		t.Fatalf("manual sync on the accepted source failed after the fence: %v", err)
	}
	after := svc.PolicyMatcher().Current()
	if after == nil || !after.MatchDomain("new-protected.example.com") {
		t.Fatal("the accepted source's rules are gone after a manual sync")
	}
}
