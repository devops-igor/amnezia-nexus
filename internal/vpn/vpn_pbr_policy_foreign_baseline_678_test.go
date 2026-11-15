package vpn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the permanent regression oracles for issue #678 finding F678-05: a
// failed first sync of a newly selected source used to fall back to the durable
// last-known-good generation without checking which source/config it belonged to.
// A's stored rules were then published as B's policy and activation proceeded even
// though B's list had never loaded.
//
// The executed subject is ensureInitialSnapshot, which is the activation handshake
// itself: prime baseline → one synchronous sync → settle → require rules. Only TLS
// trust and the dial target are fixture-scoped; the fetcher, parser, shrink guard,
// FileStore and matcher are production code.

const (
	foreignListAPath = "/policy-a.lst"
	foreignListBPath = "/policy-b.lst"
)

// newForeignBaselineServer serves A's list always and B's list subject to the
// test's switch (503 while it is set).
func newForeignBaselineServer(t *testing.T, bUnavailable *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case foreignListAPath:
			w.Header().Set("Content-Type", "text/plain")
			for _, domain := range append(domainList("a", 19), "a-only.example.com") {
				fmt.Fprintln(w, domain)
			}
		case foreignListBPath:
			if bUnavailable.Load() {
				http.Error(w, "upstream maintenance", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			for _, domain := range append(domainList("b", 11), "b-protected.example.com") {
				fmt.Fprintln(w, domain)
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

// seedStoredGenerationForSyncs A's configuration into the store with a real sync,
// so the durable generation carries A's true configuration hash.
func seedStoredGenerationFor(t *testing.T, server *httptest.Server, settings policy.Settings) (*policy.FileStore, string) {
	t.Helper()
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)
	matcher := policy.NewMatcher()
	seeder, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer (seed): %v", err)
	}
	if _, err := seeder.SyncOnce(context.Background()); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	return store, seeder.ConfigHash()
}

// TestForeignBaselineIsNotAcceptedWhenSelectedSourceFails is the core F678-05
// regression.
func TestForeignBaselineIsNotAcceptedWhenSelectedSourceFails(t *testing.T) {
	var bUnavailable atomic.Bool
	server := newForeignBaselineServer(t, &bUnavailable)
	defer server.Close()

	// A has produced a valid durable generation.
	settingsA := policySettingsForURL(t, "https://audit-a.example"+foreignListAPath)
	store, hashA := seedStoredGenerationFor(t, server, settingsA)

	// The operator selects a different source/config B, and B's list is down.
	bUnavailable.Store(true)
	settingsB := policySettingsForURL(t, "https://audit-b.example"+foreignListBPath)
	cfgB, err := settingsB.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig B: %v", err)
	}
	fetchB, _ := fixtureFetcherAndStore(t, server, cfgB)
	matcher := policy.NewMatcher()
	syncerB, err := policy.NewSyncer(matcher, fetchB, store, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer (B): %v", err)
	}
	if syncerB.ConfigHash() == hashA {
		t.Fatal("fixture is invalid: the two sources share a configuration hash, so this is not a foreign baseline")
	}

	err = ensureInitialSnapshot(context.Background(), syncerB, store, matcher)
	if err == nil {
		t.Fatal("activation succeeded although the selected source never loaded and the only stored generation was foreign (F678-05)")
	}

	// No foreign snapshot may reach the live policy.
	if snap := matcher.Current(); snap != nil {
		t.Fatalf("a foreign cached policy was published into the matcher (F678-05): %d rules, first=%v",
			snap.DomainCount(), snap.MatchDomain("a-only.example.com"))
	}

	// A's durable bytes are kept, untouched, for recovery.
	gen, loadErr := store.Load(context.Background())
	if loadErr != nil {
		t.Fatalf("reload durable generation: %v", loadErr)
	}
	if gen == nil {
		t.Fatal("the foreign durable generation was removed instead of retained")
	}
	if gen.ConfigHash != hashA {
		t.Fatalf("durable generation now belongs to %s, want A's retained %s", gen.ConfigHash, hashA)
	}
	if _, ok := gen.Domains["a-only.example.com"]; !ok {
		t.Fatal("A's stored rules were lost while refusing the foreign baseline")
	}
}

// TestMatchingBaselineStillActivatesOnTransientFailure is the same-source
// last-known-good control: a transient refresh failure of the *selected* source
// must still activate on the verified baseline.
func TestMatchingBaselineStillActivatesOnTransientFailure(t *testing.T) {
	var aUnavailable atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if aUnavailable.Load() {
			http.Error(w, "upstream maintenance", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		for _, domain := range append(domainList("a", 19), "a-only.example.com") {
			fmt.Fprintln(w, domain)
		}
	}))
	defer server.Close()

	settings := policySettingsForURL(t, "https://audit-a.example"+foreignListAPath)
	store, hashA := seedStoredGenerationFor(t, server, settings)
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, _ := fixtureFetcherAndStore(t, server, cfg)
	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if syncer.ConfigHash() != hashA {
		t.Fatal("fixture is invalid: the selected configuration does not match the stored generation")
	}

	aUnavailable.Store(true)
	if err := ensureInitialSnapshot(context.Background(), syncer, store, matcher); err != nil {
		t.Fatalf("activation refused to use the verified same-source last-known-good policy: %v", err)
	}
	snap := matcher.Current()
	if snap == nil || !snap.MatchDomain("a-only.example.com") {
		t.Fatal("the verified last-known-good policy was not published for a transient failure of the same source")
	}
}

// TestChangedSourceActivatesOnSuccessfulFirstSync is the positive control that
// keeps the F678-05 fix from refusing a genuine source change: a foreign stored
// generation plus a successful first sync of the newly selected source must
// activate and commit the new source's rules.
func TestChangedSourceActivatesOnSuccessfulFirstSync(t *testing.T) {
	var bUnavailable atomic.Bool
	server := newForeignBaselineServer(t, &bUnavailable)
	defer server.Close()

	settingsA := policySettingsForURL(t, "https://audit-a.example"+foreignListAPath)
	store, hashA := seedStoredGenerationFor(t, server, settingsA)

	settingsB := policySettingsForURL(t, "https://audit-b.example"+foreignListBPath)
	cfgB, err := settingsB.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig B: %v", err)
	}
	fetchB, _ := fixtureFetcherAndStore(t, server, cfgB)
	matcher := policy.NewMatcher()
	syncerB, err := policy.NewSyncer(matcher, fetchB, store, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer (B): %v", err)
	}
	if syncerB.ConfigHash() == hashA {
		t.Fatal("fixture is invalid: the two sources share a configuration hash")
	}

	if err := ensureInitialSnapshot(context.Background(), syncerB, store, matcher); err != nil {
		t.Fatalf("activation of a successfully fetched new source was refused: %v", err)
	}
	snap := matcher.Current()
	if snap == nil || !snap.MatchDomain("b-protected.example.com") {
		t.Fatal("the new source's rules were not published after a successful first sync")
	}
	if snap.MatchDomain("a-only.example.com") {
		t.Fatal("the previous source's rules are still live after a successful source change")
	}
	gen, err := store.Load(context.Background())
	if err != nil || gen == nil {
		t.Fatalf("reload durable generation: %v", err)
	}
	if gen.ConfigHash != syncerB.ConfigHash() {
		t.Fatalf("durable generation belongs to %s, want the new source %s", gen.ConfigHash, syncerB.ConfigHash())
	}
	if _, ok := gen.Domains["b-protected.example.com"]; !ok {
		t.Fatal("the new source's rules were not committed durably")
	}
}
