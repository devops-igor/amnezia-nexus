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
// configuration is accepted and refreshed.
//
// The policy content a save changes is the operator's IPv4 exception list. Only the
// store wrapper and the WAN device are substituted; the service entry points,
// syncer, FileStore, matcher and ownership boundary are production code.

// gatedBaselineStore wraps a real store and holds exactly one Load call in flight,
// after the underlying read has returned. It also counts accepted commits, which is
// the only boundary at which an immediate refresh is observable now that a refresh
// of unchanged rules keeps its generation identifier.
type gatedBaselineStore struct {
	inner   policy.Store
	holdAt  int
	held    chan struct{}
	release chan struct{}

	mu      sync.Mutex
	loads   int
	commits int
	once    sync.Once
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
	if err := g.inner.Commit(ctx, gen); err != nil {
		return err
	}
	g.mu.Lock()
	g.commits++
	g.mu.Unlock()
	return nil
}

// CommitCount reports how many durable commits this store has accepted.
func (g *gatedBaselineStore) CommitCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.commits
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
	settingsA, settingsB := ownershipConfigs()

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	// Load #1 is activation's own baseline prime; load #2 is the asynchronous Run
	// baseline of the runtime that activation just registered, which is the one this
	// regression freezes.
	store := newGatedBaselineStore(lkgStoreFor(t, settingsA), 2)
	t.Cleanup(store.releaseHeld)

	if err := svc.StartPolicyRouting(context.Background(), settingsA, store); err != nil {
		t.Fatalf("activation of configuration A failed: %v", err)
	}
	select {
	case <-store.held:
	case <-time.After(20 * time.Second):
		t.Fatal("configuration A's Run never reached its baseline load; the held-baseline scenario did not run")
	}

	// The operator saves configuration B while A's baseline preparation is frozen.
	// B is published, takes write ownership and A's loop is cancelled.
	//
	// The commit count is sampled *before* the replacement starts, because the
	// refresh it spawns may have committed before this test can look again.
	commitsBeforeB := store.CommitCount()
	if err := svc.StartPolicyRouting(context.Background(), settingsB, store); err != nil {
		t.Fatalf("replacement with configuration B failed: %v", err)
	}
	// Wait for B's immediate refresh to have committed and be live. The durable
	// commit is the completion signal: a refresh whose effective rules are unchanged
	// keeps the generation identifier, so that identifier is not one. Releasing the
	// old baseline before this point would let B's own refresh mask a stale
	// republication and make the regression pass for the wrong reason.
	const replacementCommits = 2
	refreshedAt := commitsBeforeB + replacementCommits
	deadline := time.Now().Add(30 * time.Second)
	for {
		gen, loadErr := store.Load(context.Background())
		snap := svc.PolicyMatcher().Current()
		if loadErr == nil && gen != nil && snap != nil &&
			store.CommitCount() >= refreshedAt && snap.Generation() == gen.GenerationID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("configuration B's immediate refresh never committed (commits=%d, want at least %d, durable=%v)",
				store.CommitCount(), refreshedAt, gen != nil)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Release A's frozen baseline. It must be refused at publication.
	store.releaseHeld()

	// Bounded quiet window: a publication is immediate once the load returns, so if
	// the superseded baseline were still allowed to publish it would do so here.
	quietUntil := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(quietUntil) {
		if snap := svc.PolicyMatcher().Current(); snap != nil && snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
			t.Fatalf("the superseded runtime republished its old baseline over the accepted policy (F678-06): live prefixes=%d include the retired configuration's prefix", snap.CIDRCount())
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
	if !snap.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Fatalf("the accepted configuration's prefix is not live (F678-06): %d prefixes", snap.CIDRCount())
	}
	if snap.MatchIPv4(mustAddr(t, "203.0.113.7")) {
		t.Fatal("the retired configuration's prefix is live again: the superseded baseline was published (F678-06)")
	}
	if got := snap.CIDRCount(); got != len(settingsB.ProxyExceptions) {
		t.Fatalf("live policy has %d prefixes, want the accepted configuration's %d (F678-06)", got, len(settingsB.ProxyExceptions))
	}

	// Durable policy, reloaded from the store. Live and durable must name the same
	// accepted generation; A's seeded last-known-good has a fixed generation id, so a
	// republished baseline is recognisable here as well as by its rules.
	reloaded, err := store.Load(context.Background())
	if err != nil || reloaded == nil {
		t.Fatalf("reload the durable generation: %v", err)
	}
	if reloaded.ConfigHash != svc.policyRuntime().syncer.ConfigHash() {
		t.Fatalf("durable generation does not belong to the accepted configuration: %s", reloaded.ConfigHash)
	}
	if got, want := snap.Generation(), reloaded.GenerationID; got == "gen-audit-seed" || got != want {
		t.Fatalf("live generation = %q, want the accepted durable generation %q (F678-06)", got, want)
	}
	for _, prefix := range reloaded.CIDRs {
		if prefix == "203.0.113.0/24" {
			t.Fatal("the durable generation contains the retired configuration's prefix (F678-06)")
		}
	}

	// Runtime status and registered settings still describe the accepted
	// configuration: a superseded generation must never be advertised.
	status := svc.PolicyStatusSnapshot()
	if status.CIDRCount != len(settingsB.ProxyExceptions) {
		t.Fatalf("runtime status reports %d prefixes, want the accepted configuration's %d (F678-06)",
			status.CIDRCount, len(settingsB.ProxyExceptions))
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
	if len(runtimeSettings.ProxyExceptions) != len(settingsB.ProxyExceptions) {
		t.Fatalf("runtime settings identify %v, want the accepted configuration %v",
			runtimeSettings.ProxyExceptions, settingsB.ProxyExceptions)
	}

	// Control: the accepted configuration can still sync and publish afterwards, so
	// the fence refuses obsolete writes without freezing the live runtime.
	if _, err := svc.SyncPolicyNow(context.Background()); err != nil {
		t.Fatalf("manual sync on the accepted configuration failed after the fence: %v", err)
	}
	after := svc.PolicyMatcher().Current()
	if after == nil || !after.MatchIPv4(mustAddr(t, "198.51.100.7")) {
		t.Fatal("the accepted configuration's rules are gone after a manual sync")
	}
}
