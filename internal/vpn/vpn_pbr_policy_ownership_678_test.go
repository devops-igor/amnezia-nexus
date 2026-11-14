package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the permanent regression oracles for issue #678 finding F678-04: a
// manual sync that is still in flight when the operator saves a different source
// used to commit and publish its old generation after the replacement had already
// been accepted. Settings and runtime status then named the new source while both
// the live matcher and the durable generation held the old one's rules.
//
// The decisive condition is a *held* HTTPS response, not a timing window: the
// fixture blocks the old source's fetch until the test releases it, so the stale
// commit is attempted strictly after the replacement published. Everything else —
// the service entry points, the write-ownership boundary, the real syncer, parser,
// FileStore and matcher — is production code. Only TLS trust and the dial target
// are substituted, both fixture-scoped.

// policyGate is a per-path request gate for the fixture list server.
type policyGate struct {
	mu       sync.Mutex
	counts   map[string]int
	blockAt  int
	blocked  chan struct{} // closed when a request reaches the gate
	release  chan struct{} // closed by the test to let the held request finish
	released bool
}

func newPolicyGate() *policyGate {
	return &policyGate{
		counts:  make(map[string]int),
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
}

// holdFrom makes the next request for path block until release is closed.
func (g *policyGate) holdFrom(path string) {
	g.mu.Lock()
	g.blockAt = g.counts[path] + 1
	g.mu.Unlock()
}

func (g *policyGate) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counts[path]
}

// admit records a request and reports whether it must wait for the release.
func (g *policyGate) admit(path string) bool {
	g.mu.Lock()
	g.counts[path]++
	hold := g.blockAt > 0 && g.counts[path] >= g.blockAt
	alreadyReleased := g.released
	g.mu.Unlock()
	if !hold || alreadyReleased {
		return false
	}
	select {
	case <-g.blocked:
	default:
		close(g.blocked)
	}
	<-g.release
	return true
}

func (g *policyGate) releaseAll() {
	g.mu.Lock()
	if !g.released {
		g.released = true
		close(g.release)
	}
	g.mu.Unlock()
}

// newGatedPolicyServer serves one list per path with an optional block.
func newGatedPolicyServer(gate *policyGate, lists map[string][]string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		list, ok := lists[r.URL.Path]
		if !ok {
			http.Error(w, "no such list", http.StatusNotFound)
			return
		}
		if gate.admit(r.URL.Path) {
			// The caller released this request after the replacement was accepted.
		}
		w.Header().Set("Content-Type", "text/plain")
		for _, domain := range list {
			fmt.Fprintln(w, domain)
		}
	}))
}

// policySettingsForURL returns enabled custom-URL settings for one fixture list.
func policySettingsForURL(t *testing.T, url string) policy.Settings {
	t.Helper()
	s := policy.DefaultSettings()
	s.Enabled = true
	s.Preset = policy.PresetCustom
	s.CustomURLs = []string{url}
	if err := s.Validate(); err != nil {
		t.Fatalf("fixture settings for %s are invalid: %v", url, err)
	}
	return s
}

// fixtureFetcherFor builds the real production Fetcher for one fixture server and
// sync configuration.
func fixtureFetcherFor(t *testing.T, server *httptest.Server, cfg policy.SyncConfig) *policy.Fetcher {
	t.Helper()
	fetch, _ := fixtureFetcherAndStore(t, server, cfg)
	return fetch
}

// domainList returns n synthetic domains with the given prefix.
func domainList(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s%d.example.com", prefix, i))
	}
	return out
}

// TestReplacedRuntimeCannotOverwriteAcceptedPolicy is the core F678-04 regression.
func TestReplacedRuntimeCannotOverwriteAcceptedPolicy(t *testing.T) {
	const (
		pathA = "/policy-a.lst"
		pathB = "/policy-b.lst"
	)
	// A serves 20 rules and includes a domain that only A's list knows about.
	listA := append(domainList("a", 19), "stale-a-only.example.com")
	// B serves 12 rules (>= 50% of A, so the shrink guard is not what refuses
	// anything here) and includes the domain that must stay protected.
	listB := append(domainList("b", 11), "new-protected.example.com")

	gate := newPolicyGate()
	server := newGatedPolicyServer(gate, map[string][]string{pathA: listA, pathB: listB})
	defer server.Close()
	t.Cleanup(gate.releaseAll)

	settingsA := policySettingsForURL(t, "https://audit-a.example"+pathA)
	settingsB := policySettingsForURL(t, "https://audit-b.example"+pathB)

	// The service builds its syncers through this seam, so its activation and its
	// manual sync reach the fixture through the real fetch pipeline.
	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	// A becomes the live runtime, seeded from a durable last-known-good generation
	// for A's exact configuration so activation needs no network round trip first.
	store := auditedLKGStore(t, settingsA)
	if err := svc.StartPolicyRouting(context.Background(), settingsA, store, string(settingsA.Preset)); err != nil {
		t.Fatalf("activation of source A failed: %v", err)
	}
	hashA := svc.policyRuntime().syncer.ConfigHash()

	// Wait until A's own immediate refresh has run, so the gate below can be aimed
	// at exactly the manual request instead of catching the loop's update.
	deadline := time.Now().Add(15 * time.Second)
	for gate.count(pathA) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("source A's activation and immediate refresh never completed (requests=%d)", gate.count(pathA))
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Hold A's next fetch, then start the manual sync that will be left in flight.
	gate.holdFrom(pathA)
	type syncOutcome struct {
		res policy.SyncResult
		err error
	}
	manual := make(chan syncOutcome, 1)
	manualCtx, cancelManual := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelManual()
	go func() {
		// The loop may still be finishing its own immediate update when this starts,
		// in which case the single-flight guard answers ErrSyncInProgress. That is
		// not the scenario under test, so retry until an attempt is accepted.
		for {
			res, err := svc.SyncPolicyNow(manualCtx)
			if errors.Is(err, policy.ErrSyncInProgress) && manualCtx.Err() == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			manual <- syncOutcome{res: res, err: err}
			return
		}
	}()
	select {
	case <-gate.blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("the manual sync never reached the fixture server; the held-response scenario did not run")
	}

	// The operator now saves a different source. This publishes B and registers it.
	if err := svc.StartPolicyRouting(context.Background(), settingsB, store, string(settingsB.Preset)); err != nil {
		t.Fatalf("replacement with source B failed: %v", err)
	}
	// Wait for B's own immediate refresh inside the new scheduling loop, so the
	// release below happens strictly after B is both accepted and refreshed.
	deadline = time.Now().Add(15 * time.Second)
	for gate.count(pathB) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("B's immediate refresh never ran (requests=%d)", gate.count(pathB))
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Release A's held response: its stale generation must not be written.
	gate.releaseAll()
	var outcome syncOutcome
	select {
	case outcome = <-manual:
	case <-time.After(20 * time.Second):
		t.Fatal("the manual sync never returned after its response was released")
	}
	if outcome.err == nil {
		t.Fatal("the superseded manual sync reported success (F678-04: a retired runtime published its stale generation)")
	}
	if !errors.Is(outcome.err, policy.ErrSyncSuperseded) {
		t.Fatalf("the superseded manual sync failed for an unrelated reason: %v", outcome.err)
	}

	// Live policy: B's protected rule is present and A's stale-only rule never came
	// back.
	live := svc.PolicyMatcher()
	if live == nil {
		t.Fatal("no live matcher after the replacement")
	}
	snap := live.Current()
	if snap == nil {
		t.Fatal("no live snapshot after the replacement")
	}
	if !snap.MatchDomain("new-protected.example.com") {
		t.Fatalf("the accepted source's protected rule is gone from the live policy after the stale sync (F678-04): %d rules", snap.DomainCount())
	}
	if snap.MatchDomain("stale-a-only.example.com") {
		t.Fatal("the retired source's rule is live again: the superseded sync published its generation (F678-04)")
	}
	if got := snap.DomainCount(); got != len(listB) {
		t.Fatalf("live policy has %d rules, want the accepted source's %d (F678-04)", got, len(listB))
	}

	// Durable policy: reload from the store, not from memory.
	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("reload the durable generation: %v", err)
	}
	if gen == nil {
		t.Fatal("no durable generation after the replacement")
	}
	hashB := svc.policyRuntime().syncer.ConfigHash()
	if hashA == hashB {
		t.Fatal("fixture is invalid: the two sources share a configuration hash")
	}
	if gen.ConfigHash != hashB {
		t.Fatalf("durable generation belongs to %s, want the accepted source %s (F678-04: the stale sync committed)", gen.ConfigHash, hashB)
	}
	if _, ok := gen.Domains["stale-a-only.example.com"]; ok {
		t.Fatal("the durable generation contains the retired source's rule (F678-04)")
	}
	if _, ok := gen.Domains["new-protected.example.com"]; !ok {
		t.Fatal("the durable generation lost the accepted source's protected rule (F678-04)")
	}

	// Settings and runtime status still identify the accepted source.
	runtimeSettings := svc.policyRuntime().settings
	if len(runtimeSettings.CustomURLs) != 1 || runtimeSettings.CustomURLs[0] != settingsB.CustomURLs[0] {
		t.Fatalf("runtime settings identify %v, want the accepted source %v", runtimeSettings.CustomURLs, settingsB.CustomURLs)
	}
	status := svc.PolicyStatusSnapshot()
	if status.DomainCount != len(listB) {
		t.Fatalf("runtime status reports %d rules, want the accepted source's %d (F678-04)", status.DomainCount, len(listB))
	}
	if status.LastError != "" {
		t.Fatalf("runtime status reports an error after a successful replacement: %q", status.LastError)
	}
	if !status.Enabled || !status.Ready {
		t.Fatalf("runtime status is not enabled/ready after the replacement: %+v", status)
	}
}

// TestSuccessfulManualSyncStillPublishesOnCurrentSource keeps the F678-04 boundary
// from turning every manual sync into a refusal: the current runtime must still be
// able to sync and publish on demand.
func TestSuccessfulManualSyncStillPublishesOnCurrentSource(t *testing.T) {
	const pathA = "/policy-a.lst"
	var grown atomic.Bool
	gate := newPolicyGate()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gate.admit(r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		list := domainList("a", 20)
		if grown.Load() {
			list = append(list, "manual-sync.example.com")
		}
		for _, domain := range list {
			fmt.Fprintln(w, domain)
		}
	}))
	defer server.Close()

	settings := policySettingsForURL(t, "https://audit-a.example"+pathA)
	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	store := auditedLKGStore(t, settings)
	if err := svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset)); err != nil {
		t.Fatalf("activation failed: %v", err)
	}

	grown.Store(true)
	res, err := svc.SyncPolicyNow(context.Background())
	if err != nil {
		t.Fatalf("manual sync on the current source failed: %v", err)
	}
	if !res.Published {
		t.Fatal("manual sync on the current source did not publish")
	}
	snap := svc.PolicyMatcher().Current()
	if snap == nil || !snap.MatchDomain("manual-sync.example.com") {
		t.Fatal("the manual sync's new rule is not live: a working manual sync was refused")
	}
	gen, err := store.Load(context.Background())
	if err != nil || gen == nil {
		t.Fatalf("reload durable generation: %v", err)
	}
	if _, ok := gen.Domains["manual-sync.example.com"]; !ok {
		t.Fatal("the manual sync's new rule was not committed durably")
	}
}

// TestFailedManualSyncKeepsCurrentPolicy is the refused-update control: a manual
// sync whose source is unavailable reports the failure and changes nothing live or
// durable, which is the last-known-good behavior the boundary must not disturb.
func TestFailedManualSyncKeepsCurrentPolicy(t *testing.T) {
	const pathA = "/policy-a.lst"
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "upstream maintenance", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		for _, domain := range domainList("a", 20) {
			fmt.Fprintln(w, domain)
		}
	}))
	defer server.Close()

	settings := policySettingsForURL(t, "https://audit-a.example"+pathA)
	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = nil })

	withNameOwnedWANDevice(t, newNameRegistry())
	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	store := auditedLKGStore(t, settings)
	if err := svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset)); err != nil {
		t.Fatalf("activation failed: %v", err)
	}
	before, err := store.Load(context.Background())
	if err != nil || before == nil {
		t.Fatalf("reload durable generation before the failed sync: %v", err)
	}

	fail.Store(true)
	if _, err := svc.SyncPolicyNow(context.Background()); err == nil {
		t.Fatal("a manual sync against an unavailable source reported success")
	}

	snap := svc.PolicyMatcher().Current()
	if snap == nil || snap.DomainCount() != 20 {
		t.Fatalf("the live policy changed after a failed manual sync: %+v", snap)
	}
	after, err := store.Load(context.Background())
	if err != nil || after == nil {
		t.Fatalf("reload durable generation after the failed sync: %v", err)
	}
	if after.GenerationID != before.GenerationID {
		t.Fatalf("the durable generation changed after a failed manual sync: %s -> %s", before.GenerationID, after.GenerationID)
	}
}
