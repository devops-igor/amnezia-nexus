package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These are the permanent regression oracles for issue #678 finding F678-03: the
// restart first-sync shrink bypass.
//
// The defect was ordering, not a missing guard. The shrink guard compares a
// candidate rule count against "the previous count" read from the matcher, so a
// fresh matcher created at restart had no previous count and accepted a
// complete-but-shortened upstream list as the first-ever snapshot — replacing both
// the live policy and the durable last-known-good generation.
//
// The oracles below pin both halves of the required behavior: a shortened first
// response must be refused while the good generation survives, and every
// legitimate case (fresh install, real content growth, changed source) must still
// work so the guard cannot degenerate into "refuse any first sync".
//
// Only two seams are substituted, both fixture-scoped and never configured by the
// production path: TLS trust (the local server's certificate stands in for a
// public CA) and the approved-IP/dial pair. Parsing, the shrink guard, the durable
// commit format and the matcher are production code.

// newPolicyListServer serves a plain-text 20-rule policy list over TLS.
func newPolicyListServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := 0; i < 20; i++ {
			fmt.Fprintf(w, "rule%d.example.com\n", i)
		}
	}))
}

// fixtureFetcherAndStore builds the real production Fetcher and FileStore pointed
// at the given TLS fixture.
func fixtureFetcherAndStore(t *testing.T, server *httptest.Server, cfg policy.SyncConfig) (*policy.Fetcher, *policy.FileStore) {
	t.Helper()
	return fixtureFetcherAndStoreIn(t, server, cfg, t.TempDir())
}

// fixtureFetcherAndStoreIn is fixtureFetcherAndStore with an explicit store
// directory, for tests that must place or inspect files in it.
func fixtureFetcherAndStoreIn(t *testing.T, server *httptest.Server, cfg policy.SyncConfig, dir string) (*policy.Fetcher, *policy.FileStore) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	fetch := policy.NewFetcher(cfg.FetchLimits)
	fetch.SetFixtureTLSTrust(
		&tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
		},
	)
	return fetch, policy.NewFileStore(dir)
}

// policyListSettings returns enabled custom-URL settings, the shape an operator
// saves before the source goes bad.
func policyListSettings(t *testing.T) policy.Settings {
	t.Helper()
	s := policy.DefaultSettings()
	s.Enabled = true
	s.Preset = policy.PresetCustom
	s.CustomURLs = []string{"https://audit-list.example/policy.lst"}
	if err := s.Validate(); err != nil {
		t.Fatalf("fixture settings are invalid: %v", err)
	}
	return s
}

// TestRestartInitialSnapshotRejectsShortenedFirstResponse is the core F678-03
// regression.
//
// The decisive condition is that the matcher is empty when activation begins, the
// source and config are unchanged, and the upstream returns a syntactically valid
// HTTP 200 document with complete content — only the rule *count* is suspicious.
// Transport, content-type and empty-list guards all pass, so nothing but a real
// baseline can reject it.
func TestRestartInitialSnapshotRejectsShortenedFirstResponse(t *testing.T) {
	var serveSmall atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if serveSmall.Load() {
			fmt.Fprintln(w, "only.example.com")
			return
		}
		for i := 0; i < 20; i++ {
			fmt.Fprintf(w, "rule%d.example.com\n", i)
		}
	}))
	defer server.Close()

	settings := policyListSettings(t)
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)

	// Establish a durable 20-rule generation for this exact source/config.
	first := policy.NewMatcher()
	syncer, err := policy.NewSyncer(first, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	if first.Current().DomainCount() != 20 {
		t.Fatalf("seed published %d domains, want 20", first.Current().DomainCount())
	}

	// Restart: a brand-new matcher, same source/config, upstream now serving a
	// complete one-rule document.
	serveSmall.Store(true)
	restarted := policy.NewMatcher()
	fresh, err := policy.NewSyncer(restarted, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer (restarted): %v", err)
	}
	if err := ensureInitialSnapshot(context.Background(), fresh, store, restarted); err != nil {
		t.Fatalf("activation refused a preserved last-known-good policy: %v", err)
	}

	// The shortened candidate must not have replaced the good generation.
	if got := restarted.Current().DomainCount(); got != 20 {
		t.Fatalf("restart published %d live rules, want the preserved 20 (F678-03: shortened first response was accepted)", got)
	}
	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if gen == nil || gen.DomainCount != 20 {
		t.Fatalf("restart replaced the durable generation, want the preserved 20 rules (F678-03): %+v", gen)
	}

	// Control: the identical payload submitted to an already-initialized matcher
	// is still refused by the shrink guard, so the rejection above is the guard
	// working rather than this test's fixture being inert.
	guarded, err := policy.NewSyncer(first, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer (guarded): %v", err)
	}
	if _, err := guarded.SyncOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "shrink guard") {
		t.Fatalf("initialized matcher did not reject the shrink: %v", err)
	}
}

// TestFreshInstallEstablishesBaselineFromFirstSync is the positive control that
// keeps the F678-03 fix from degenerating into "refuse any first sync".
//
// With no durable generation at all, a valid non-empty first response must be
// accepted and committed: that is the ordinary first activation of a new install.
func TestFreshInstallEstablishesBaselineFromFirstSync(t *testing.T) {
	server := newPolicyListServer(t)
	defer server.Close()

	cfg, err := policyListSettings(t).SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if err := ensureInitialSnapshot(context.Background(), syncer, store, matcher); err != nil {
		t.Fatalf("fresh install activation was refused: %v", err)
	}
	if got := matcher.Current().DomainCount(); got != 20 {
		t.Fatalf("fresh install published %d rules, want the 20 served", got)
	}
	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if gen == nil || gen.DomainCount != 20 {
		t.Fatalf("fresh install did not commit its first generation: %+v", gen)
	}
}

// TestLegitimateRefreshStillApplies proves the fix did not freeze the policy: a
// genuine content change that is not a suspicious shrink must still be applied on
// both the live matcher and the durable generation.
func TestLegitimateRefreshStillApplies(t *testing.T) {
	var serveGrown atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		n := 20
		if serveGrown.Load() {
			n = 30
		}
		for i := 0; i < n; i++ {
			fmt.Fprintf(w, "rule%d.example.com\n", i)
		}
	}))
	defer server.Close()

	cfg, err := policyListSettings(t).SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)

	first := policy.NewMatcher()
	syncer, err := policy.NewSyncer(first, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("seed sync: %v", err)
	}

	serveGrown.Store(true)
	restarted := policy.NewMatcher()
	fresh, err := policy.NewSyncer(restarted, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer (restarted): %v", err)
	}
	if err := ensureInitialSnapshot(context.Background(), fresh, store, restarted); err != nil {
		t.Fatalf("activation with a legitimate grown list failed: %v", err)
	}
	if got := restarted.Current().DomainCount(); got != 30 {
		t.Fatalf("legitimate refresh published %d rules, want the 30 served", got)
	}
	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if gen == nil || gen.DomainCount != 30 {
		t.Fatalf("legitimate refresh did not commit the new generation: %+v", gen)
	}
}

// TestCorruptStoredGenerationRefusesActivationInsteadOfSyncingOverIt covers the
// fail-closed half of the auditor's recommendation: a durable generation that
// exists but cannot be used must be reported, not silently overwritten. Syncing
// over an unreadable cache would destroy the last recoverable copy of the last
// good policy.
func TestCorruptStoredGenerationRefusesActivationInsteadOfSyncingOverIt(t *testing.T) {
	server := newPolicyListServer(t)
	defer server.Close()

	cfg, err := policyListSettings(t).SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}

	dir := t.TempDir()
	fetch, store := fixtureFetcherAndStoreIn(t, server, cfg, dir)
	corrupt := "{not valid json"
	if err := os.WriteFile(filepath.Join(dir, "policy_lkg.json"), []byte(corrupt), 0o600); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	err = ensureInitialSnapshot(context.Background(), syncer, store, matcher)
	if err == nil {
		t.Fatal("activation synced over an unreadable stored generation instead of refusing")
	}
	if !errors.Is(err, ErrPolicyActivationNoRules) {
		t.Fatalf("expected ErrPolicyActivationNoRules, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("refusal does not explain the unreadable cache: %v", err)
	}
	// The corrupt bytes must still be there for an operator to inspect; the
	// activation must not have replaced them with a fresh commit.
	raw, readErr := os.ReadFile(filepath.Join(dir, "policy_lkg.json"))
	if readErr != nil {
		t.Fatalf("read cache after refusal: %v", readErr)
	}
	if string(raw) != corrupt {
		t.Fatalf("refused activation overwrote the unreadable cache: %q", string(raw))
	}
}

// TestStoredGenerationForDifferentSourcesIsNotTreatedAsBaseline covers the
// "intentional source changes must remain explicit" half of the recommendation.
// A durable generation for a different source configuration must not be used as
// the comparison baseline, and must not block the new source from starting.
func TestStoredGenerationForDifferentSourcesIsNotTreatedAsBaseline(t *testing.T) {
	server := newPolicyListServer(t)
	defer server.Close()

	cfg, err := policyListSettings(t).SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)

	// A valid, self-consistent generation belonging to a *different* source.
	other := &policy.Generation{
		SchemaVersion: policy.SchemaVersion,
		GenerationID:  "gen-other-source",
		Version:       4,
		ConfigHash:    "hash-of-some-other-source-config",
		Domains:       map[string]uint8{"other.example.com": 1},
		DomainCount:   1,
	}
	if err := store.Commit(context.Background(), other); err != nil {
		t.Fatalf("seed foreign generation: %v", err)
	}

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	status, err := syncer.PrimeBaseline(context.Background())
	if err != nil {
		t.Fatalf("PrimeBaseline on a foreign generation: %v", err)
	}
	if status != policy.BaselineForeign {
		t.Fatalf("baseline status = %v, want BaselineForeign", status)
	}
	if matcher.Current() != nil {
		t.Fatal("PrimeBaseline published a generation belonging to a different source")
	}

	// Activation must still succeed: the new source simply has no baseline yet.
	if err := ensureInitialSnapshot(context.Background(), syncer, store, matcher); err != nil {
		t.Fatalf("activation with a changed source was refused: %v", err)
	}
	if got := matcher.Current().DomainCount(); got != 20 {
		t.Fatalf("changed source published %d rules, want the 20 served", got)
	}
}
