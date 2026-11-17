package policy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These are the regression oracles for the policy refresh contract: a refresh
// whose effective rules are unchanged keeps the published generation, and every
// genuine change still publishes a new one.
//
// The generation identifier is what the forwarder's route cache keys a client's
// DNS evidence on, so "retained" is the difference between a client's established
// flows staying DIRECT after a scheduled refresh and falling back to the
// fail-closed PROXY path until it resolves again.
//
// Only two seams are substituted, both fixture-scoped and never configured by the
// production path: TLS trust for the local listener (SetFixtureTLSTrust) and the
// approved-IP/dial pair. Parsing, the config hash, the durable commit format,
// publication and the equivalence decision are production code.

// refreshFixture serves one or more rule-list paths over TLS and lets a test
// change a body, its validator or the whole response class between cycles.
type refreshFixture struct {
	t      *testing.T
	server *httptest.Server

	mu        sync.Mutex
	bodies    map[string]string
	etags     map[string]string
	seen      map[string]string
	requested int
}

func newRefreshFixture(t *testing.T, paths ...string) *refreshFixture {
	t.Helper()
	f := &refreshFixture{
		t:      t,
		bodies: make(map[string]string, len(paths)),
		etags:  make(map[string]string, len(paths)),
		seen:   make(map[string]string, len(paths)),
	}
	for _, path := range paths {
		f.bodies[path] = ""
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *refreshFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	body, known := f.bodies[r.URL.Path]
	etag := f.etags[r.URL.Path]
	f.seen[r.URL.Path] = r.Header.Get("If-None-Match")
	f.requested++
	f.mu.Unlock()

	if !known {
		http.NotFound(w, r)
		return
	}
	// A real conditional server answers 304 only for a request that carries the
	// current validator, and 200 otherwise. Modelling anything else would let a
	// client with no validator receive 304 for content it never downloaded.
	if etag != "" && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	_, _ = io.WriteString(w, body)
}

// serve replaces the body served for path. A changed body must be accompanied by
// a new validator, or the fetcher's conditional request would be answered with
// 304 and the new bytes would never be downloaded.
func (f *refreshFixture) serve(path, body, etag string) {
	f.mu.Lock()
	f.bodies[path] = body
	f.etags[path] = etag
	f.mu.Unlock()
}

// conditional returns the validator the last request for path carried.
func (f *refreshFixture) conditional(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[path]
}

// fetcher builds the production Fetcher pointed at this fixture.
func (f *refreshFixture) fetcher() *Fetcher {
	f.t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	addr := strings.TrimPrefix(f.server.URL, "https://")
	fetch := NewFetcher(DefaultFetchLimits())
	fetch.SetFixtureTLSTrust(
		&tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	)
	return fetch
}

// refreshConfig builds a sync configuration for the given fixture paths.
func refreshConfig(paths ...string) SyncConfig {
	sources := make([]Source, 0, len(paths))
	for i, path := range paths {
		sources = append(sources, Source{
			ID:             fmt.Sprintf("source-%d", i+1),
			URL:            "https://rules.example.com" + path,
			Format:         FormatMixed,
			BareDomainMode: DomainModeExact,
			IsPreset:       true,
		})
	}
	return SyncConfig{
		Sources:         sources,
		RefreshInterval: time.Hour,
		FetchLimits:     DefaultFetchLimits(),
		ParseLimits:     DefaultParseLimits(),
	}
}

func newRefreshSyncer(t *testing.T, matcher *Matcher, fetch *Fetcher, store Store, cfg SyncConfig) *Syncer {
	t.Helper()
	syncer, err := NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	return syncer
}

// TestSyncer_UnchangedRefreshRetainsGeneration covers both content-equivalent
// shapes: an all-304 cycle, and a 200 that returns the identical list under a new
// validator. Both must keep the generation identity (so route evidence survives)
// while still recording the cycle's fetch and health metadata.
func TestSyncer_UnchangedRefreshRetainsGeneration(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "listed.example.com\n*.wild.example.com\n198.51.100.0/24\n", `"v1"`)

	cfg := refreshConfig("/rules.lst")
	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
	ctx := context.Background()
	started := time.Now().UTC()

	first, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !first.Published {
		t.Fatal("initial sync did not publish")
	}
	firstGen, err := store.Load(ctx)
	if err != nil || firstGen == nil {
		t.Fatalf("load initial durable generation: gen=%v err=%v", firstGen, err)
	}

	// Cycle 2: the upstream answers 304, as it does when nothing changed.
	second, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("304 refresh: %v", err)
	}
	if !second.Published {
		t.Fatal("a content-equivalent refresh reported that the live policy was not established")
	}
	if second.Version != first.Version || second.GenerationID != first.GenerationID {
		t.Fatalf("304 refresh advanced the generation from %s/v%d to %s/v%d; route evidence is keyed on it",
			first.GenerationID, first.Version, second.GenerationID, second.Version)
	}
	if !second.SourceStats["source-1"].NotModified {
		t.Errorf("304 refresh did not record the not-modified source: %+v", second.SourceStats["source-1"])
	}
	if got := matcher.Current().Generation(); got != first.GenerationID {
		t.Errorf("live snapshot generation = %q, want the retained %q", got, first.GenerationID)
	}
	if got := matcher.Current().Version(); got != first.Version {
		t.Errorf("live snapshot version = %d, want the retained %d", got, first.Version)
	}
	if !matcher.Current().MatchDomain("deep.wild.example.com") {
		t.Error("retained snapshot no longer matches a fetched rule")
	}

	// The durable record keeps its identity (same rules, same creation instant)
	// but carries this cycle's source metadata.
	afterNotModified, err := store.Load(ctx)
	if err != nil || afterNotModified == nil {
		t.Fatalf("load durable generation after 304: gen=%v err=%v", afterNotModified, err)
	}
	if afterNotModified.GenerationID != firstGen.GenerationID || afterNotModified.Version != firstGen.Version {
		t.Errorf("durable generation identity changed on a 304 refresh: %s/v%d -> %s/v%d",
			firstGen.GenerationID, firstGen.Version, afterNotModified.GenerationID, afterNotModified.Version)
	}
	if !afterNotModified.CreatedAt.Equal(firstGen.CreatedAt) {
		t.Errorf("durable generation creation time changed on a 304 refresh: %v -> %v",
			firstGen.CreatedAt, afterNotModified.CreatedAt)
	}
	if afterNotModified.ContentHash != firstGen.ContentHash {
		t.Errorf("durable content hash changed on a 304 refresh: %q -> %q",
			firstGen.ContentHash, afterNotModified.ContentHash)
	}
	meta := afterNotModified.SourcesMeta["source-1"]
	if !meta.CheckedAt.After(firstGen.SourcesMeta["source-1"].CheckedAt) {
		t.Errorf("durable source check time was not refreshed: %v is not after %v",
			meta.CheckedAt, firstGen.SourcesMeta["source-1"].CheckedAt)
	}
	if meta.ETag != `"v1"` || meta.LastModified != firstGen.SourcesMeta["source-1"].LastModified {
		t.Errorf("304 refresh lost the retained validators: etag=%q last-modified=%q", meta.ETag, meta.LastModified)
	}

	status := syncer.Status()
	if !status.Ready || status.LastError != "" {
		t.Errorf("status after a successful 304 refresh: ready=%v error=%q", status.Ready, status.LastError)
	}
	if status.GenerationID != first.GenerationID {
		t.Errorf("status reports generation %q, want the retained %q", status.GenerationID, first.GenerationID)
	}
	if !status.LastSyncTime.After(started) {
		t.Errorf("status last sync time %v was not advanced past the first cycle", status.LastSyncTime)
	}

	// Cycle 3: HTTP 200 with byte-identical rules under a new validator, so the
	// whole parse path runs again and the equivalence decision, not the transport,
	// is what retains the generation.
	fixture.serve("/rules.lst", "listed.example.com\n*.wild.example.com\n198.51.100.0/24\n", `"v2"`)
	third, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("identical-200 refresh: %v", err)
	}
	if got := fixture.conditional("/rules.lst"); got != `"v1"` {
		t.Errorf("identical-200 refresh sent If-None-Match %q, want the previous validator %q", got, `"v1"`)
	}
	if third.SourceStats["source-1"].NotModified {
		t.Error("fixture did not force a full download for the identical-200 refresh")
	}
	if third.Version != first.Version || third.GenerationID != first.GenerationID {
		t.Fatalf("identical-200 refresh advanced the generation from %s/v%d to %s/v%d",
			first.GenerationID, first.Version, third.GenerationID, third.Version)
	}
	afterFull, err := store.Load(ctx)
	if err != nil || afterFull == nil {
		t.Fatalf("load durable generation after identical 200: gen=%v err=%v", afterFull, err)
	}
	if got := afterFull.SourcesMeta["source-1"].ETag; got != `"v2"` {
		t.Errorf("durable validator = %q, want the refreshed %q", got, `"v2"`)
	}
	if afterFull.GenerationID != firstGen.GenerationID {
		t.Errorf("identical-200 refresh rewrote the durable generation identity: %q -> %q",
			firstGen.GenerationID, afterFull.GenerationID)
	}

	// Cycle 4: a real change after two retained cycles must advance the sequence
	// from the retained version, so retention cannot poison the version numbering.
	fixture.serve("/rules.lst", "listed.example.com\n*.wild.example.com\n198.51.100.0/24\n203.0.113.0/24\n", `"v3"`)
	fourth, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("change after retained cycles: %v", err)
	}
	if fourth.Version != first.Version+1 {
		t.Errorf("change after retained cycles published version %d, want %d", fourth.Version, first.Version+1)
	}
	if fourth.GenerationID == first.GenerationID {
		t.Error("change after retained cycles reused the retained generation identifier")
	}
}

// TestSyncer_DeclarationOrderAndDuplicatesAreEquivalent keeps canonical equality
// honest in the other direction: a list that only reorders its entries or repeats
// them describes the same effective rules and must not publish a new generation.
func TestSyncer_DeclarationOrderAndDuplicatesAreEquivalent(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "alpha.example.com\nbeta.example.com\n198.51.100.0/24\n203.0.113.0/24\n", `"v1"`)

	cfg := refreshConfig("/rules.lst")
	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
	ctx := context.Background()

	first, err := syncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("initial sync: published=%v err=%v", first.Published, err)
	}

	fixture.serve("/rules.lst",
		"203.0.113.0/24\nbeta.example.com\nalpha.example.com\n198.51.100.0/24\nbeta.example.com\n203.0.113.0/24\n",
		`"v2"`)
	second, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("reordered refresh: %v", err)
	}
	if got := fixture.conditional("/rules.lst"); got != `"v1"` {
		t.Fatalf("fixture answered conditionally (%q); the reordered list was never downloaded", got)
	}
	if second.Version != first.Version || second.GenerationID != first.GenerationID {
		t.Fatalf("reordered/duplicated list advanced the generation from %s/v%d to %s/v%d",
			first.GenerationID, first.Version, second.GenerationID, second.Version)
	}
	if got := matcher.Current().DomainCount(); got != 2 {
		t.Errorf("retained snapshot has %d domains, want 2", got)
	}
}

// TestSyncer_GenuineChangePublishesNewGeneration is the control that keeps
// retention from freezing the policy: every shape of real change must publish a
// new generation, which is what makes the forwarder invalidate evidence.
func TestSyncer_GenuineChangePublishesNewGeneration(t *testing.T) {
	cases := []struct {
		name   string
		first  string
		second string
	}{
		{
			name:   "domain added",
			first:  "alpha.example.com\n198.51.100.0/24\n",
			second: "alpha.example.com\nbeta.example.com\n198.51.100.0/24\n",
		},
		{
			name:   "domain match flags changed",
			first:  "alpha.example.com\n",
			second: "alpha.example.com\n*.alpha.example.com\n",
		},
		{
			name:   "prefix added",
			first:  "alpha.example.com\n198.51.100.0/24\n",
			second: "alpha.example.com\n198.51.100.0/24\n203.0.113.0/24\n",
		},
		{
			name:   "prefix replaced",
			first:  "alpha.example.com\n198.51.100.0/24\n",
			second: "alpha.example.com\n192.0.2.0/24\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newRefreshFixture(t, "/rules.lst")
			fixture.serve("/rules.lst", tc.first, `"v1"`)

			store := NewFileStore(t.TempDir())
			matcher := NewMatcher()
			syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, refreshConfig("/rules.lst"))
			ctx := context.Background()

			first, err := syncer.SyncOnce(ctx)
			if err != nil || !first.Published {
				t.Fatalf("initial sync: published=%v err=%v", first.Published, err)
			}

			fixture.serve("/rules.lst", tc.second, `"v2"`)
			second, err := syncer.SyncOnce(ctx)
			if err != nil {
				t.Fatalf("changed refresh: %v", err)
			}
			if !second.Published {
				t.Fatal("changed refresh did not publish")
			}
			if second.GenerationID == first.GenerationID || second.Version == first.Version {
				t.Fatalf("changed rules retained the old generation %s/v%d; the route cache would keep stale evidence",
					first.GenerationID, first.Version)
			}
			if got := matcher.Current().Generation(); got != second.GenerationID {
				t.Errorf("live snapshot generation = %q, want the published %q", got, second.GenerationID)
			}
			durable, err := store.Load(ctx)
			if err != nil || durable == nil {
				t.Fatalf("load durable generation: gen=%v err=%v", durable, err)
			}
			if durable.GenerationID != second.GenerationID {
				t.Errorf("durable generation = %q, want the published %q", durable.GenerationID, second.GenerationID)
			}
		})
	}
}

// TestSyncer_SourceAttributionChangePublishesNewGeneration covers the change a
// merged-content comparison cannot see: the same rule supplied by a different
// list. It decides which source an explanation names, so it publishes.
func TestSyncer_SourceAttributionChangePublishesNewGeneration(t *testing.T) {
	fixture := newRefreshFixture(t, "/a.lst", "/b.lst")
	fixture.serve("/a.lst", "shared.example.com\nalpha.example.com\n", `"a1"`)
	fixture.serve("/b.lst", "beta.example.com\n", `"b1"`)

	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, refreshConfig("/a.lst", "/b.lst"))
	ctx := context.Background()

	first, err := syncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("initial sync: published=%v err=%v", first.Published, err)
	}
	before, err := store.Load(ctx)
	if err != nil || before == nil {
		t.Fatalf("load initial durable generation: gen=%v err=%v", before, err)
	}

	// The same three rules, but shared.example.com now comes from the second list.
	fixture.serve("/a.lst", "alpha.example.com\n", `"a2"`)
	fixture.serve("/b.lst", "beta.example.com\nshared.example.com\n", `"b2"`)
	second, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("attribution refresh: %v", err)
	}
	after, err := store.Load(ctx)
	if err != nil || after == nil {
		t.Fatalf("load durable generation after attribution move: gen=%v err=%v", after, err)
	}
	if !equalFlagMap(before.Domains, after.Domains) {
		t.Fatalf("fixture changed the merged rules (%v -> %v); it does not exercise attribution", before.Domains, after.Domains)
	}
	if second.GenerationID == first.GenerationID {
		t.Fatal("a rule supplied by a different source retained the old generation, so the explanation would name the wrong list")
	}
}

// TestSyncer_RestartWithUnchangedRulesRetainsGeneration applies the retention to
// the activation path: after a restart the baseline is primed from durable state
// and the first refresh of unchanged content must not publish a new generation.
func TestSyncer_RestartWithUnchangedRulesRetainsGeneration(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "listed.example.com\n198.51.100.0/24\n", `"v1"`)

	cfg := refreshConfig("/rules.lst")
	store := NewFileStore(t.TempDir())
	ctx := context.Background()

	firstMatcher := NewMatcher()
	firstSyncer := newRefreshSyncer(t, firstMatcher, fixture.fetcher(), store, cfg)
	first, err := firstSyncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("seed sync: published=%v err=%v", first.Published, err)
	}

	// Restart: a fresh matcher and syncer over the same durable store, exactly as
	// activation rebuilds them.
	restarted := NewMatcher()
	restartedSyncer := newRefreshSyncer(t, restarted, fixture.fetcher(), store, cfg)
	baseline, err := restartedSyncer.PrimeBaseline(ctx)
	if err != nil {
		t.Fatalf("PrimeBaseline: %v", err)
	}
	if baseline != BaselinePrimed {
		t.Fatalf("baseline status = %v, want BaselinePrimed", baseline)
	}

	refresh, err := restartedSyncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("post-restart refresh: %v", err)
	}
	if !refresh.Published {
		t.Fatal("post-restart refresh did not establish the live policy")
	}
	if refresh.GenerationID != first.GenerationID || refresh.Version != first.Version {
		t.Fatalf("post-restart refresh advanced the generation from %s/v%d to %s/v%d",
			first.GenerationID, first.Version, refresh.GenerationID, refresh.Version)
	}
	if got := restarted.Current().Generation(); got != first.GenerationID {
		t.Errorf("post-restart live generation = %q, want the retained %q", got, first.GenerationID)
	}
	if !restarted.Current().MatchDomain("listed.example.com") {
		t.Error("retained post-restart snapshot lost a fetched rule")
	}
}

// failingCommitStore wraps the real durable store so a cycle's commit can be made
// to fail, which is how a full disk or an unwritable cache directory behaves.
type failingCommitStore struct {
	inner *FileStore
	fail  atomic.Bool
}

func (s *failingCommitStore) Load(ctx context.Context) (*Generation, error) {
	return s.inner.Load(ctx)
}

func (s *failingCommitStore) Commit(ctx context.Context, gen *Generation) error {
	if s.fail.Load() {
		return errors.New("policy cache is not writable")
	}
	return s.inner.Commit(ctx, gen)
}

// TestSyncer_RetainedRefreshKeepsPolicyWhenCommitFails pins the failure half of
// the retained path: a content-equivalent refresh still has to write its source
// metadata, so a failed commit must be reported and must leave the incumbent
// generation live and durable rather than reporting a refresh that did not land.
func TestSyncer_RetainedRefreshKeepsPolicyWhenCommitFails(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "listed.example.com\n198.51.100.0/24\n", `"v1"`)

	store := &failingCommitStore{inner: NewFileStore(t.TempDir())}
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, refreshConfig("/rules.lst"))
	ctx := context.Background()

	first, err := syncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("initial sync: published=%v err=%v", first.Published, err)
	}

	store.fail.Store(true)
	second, err := syncer.SyncOnce(ctx)
	if err == nil {
		t.Fatal("a refresh whose durable commit failed reported success")
	}
	if second.Published {
		t.Error("a refresh whose durable commit failed reported that the live policy was established by it")
	}
	if got := matcher.Current().Generation(); got != first.GenerationID {
		t.Errorf("live snapshot generation = %q, want the retained %q", got, first.GenerationID)
	}
	if !matcher.Current().MatchDomain("listed.example.com") {
		t.Error("failed refresh left the live snapshot without the fetched rules")
	}
	durable, loadErr := store.Load(ctx)
	if loadErr != nil || durable == nil {
		t.Fatalf("load durable generation after a failed commit: gen=%v err=%v", durable, loadErr)
	}
	if durable.GenerationID != first.GenerationID {
		t.Errorf("durable generation = %q, want the retained %q", durable.GenerationID, first.GenerationID)
	}
	if status := syncer.Status(); status.LastError == "" {
		t.Error("status did not report the failed refresh")
	}
}

// TestSyncer_SourceConfigChangePublishesNewGeneration proves the retention is
// scoped to one source configuration: a reconfigured source publishes even when
// the downloaded rules are identical, because the durable generation then belongs
// to a configuration that is no longer selected.
func TestSyncer_SourceConfigChangePublishesNewGeneration(t *testing.T) {
	const body = "listed.example.com\n198.51.100.0/24\n"
	fixture := newRefreshFixture(t, "/old.lst", "/new.lst")
	fixture.serve("/old.lst", body, `"old"`)
	fixture.serve("/new.lst", body, `"new"`)

	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	ctx := context.Background()

	oldCfg := refreshConfig("/old.lst")
	oldSyncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, oldCfg)
	first, err := oldSyncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("initial sync: published=%v err=%v", first.Published, err)
	}

	newCfg := refreshConfig("/new.lst")
	newSyncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, newCfg)
	baseline, err := newSyncer.PrimeBaseline(ctx)
	if err != nil {
		t.Fatalf("PrimeBaseline: %v", err)
	}
	if baseline != BaselineForeign {
		t.Fatalf("baseline status = %v, want BaselineForeign for a changed source configuration", baseline)
	}

	second, err := newSyncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("reconfigured sync: %v", err)
	}
	if !second.Published {
		t.Fatal("reconfigured sync did not publish")
	}
	if second.GenerationID == first.GenerationID {
		t.Fatal("a changed source configuration retained a generation belonging to the previous configuration")
	}
	durable, err := store.Load(ctx)
	if err != nil || durable == nil {
		t.Fatalf("load durable generation: gen=%v err=%v", durable, err)
	}
	if durable.ConfigHash != newSyncer.ConfigHash() {
		t.Errorf("durable config hash = %q, want the selected configuration %q", durable.ConfigHash, newSyncer.ConfigHash())
	}
	if durable.GenerationID != second.GenerationID {
		t.Errorf("durable generation = %q, want the published %q", durable.GenerationID, second.GenerationID)
	}
	if got := matcher.Current().Generation(); got != second.GenerationID {
		t.Errorf("live snapshot generation = %q, want the published %q", got, second.GenerationID)
	}
}
