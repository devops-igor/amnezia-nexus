package policy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// These tests prove the real production policy-source path introduced for #678:
// settings -> SyncConfig -> Syncer -> hardened fetch -> parse -> shrink guard ->
// durable commit -> atomic publish, plus last-known-good survival on failure.
//
// They use a real TLS server and the real parser. Only the network *route* is
// substituted (SSRF-safe dialing is redirected to the local listener), which is
// the same technique the existing fetch tests use. This matters because a test
// that stubs the parser or the syncer would not prove that operators actually get
// working rules from a real list download.

// newLocalListFetcher returns a Fetcher that reaches the given TLS test server
// while still passing through ValidateFetchURL for the requested public URL.
func newLocalListFetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	t.Helper()
	serverAddr := srv.Listener.Addr().String()
	f := NewFetcher(DefaultFetchLimits())
	f.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // test fixture cert
	f.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		// Approved public address so the SSRF gate passes; the actual TCP
		// connection is redirected to the local listener below.
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	f.dialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", serverAddr)
	}
	return f
}

// A real HTTPS download must produce a published, matchable snapshot and commit it
// durably. This is the positive path of the four-endpoint sync feature.
func TestPolicySourceEndToEndPublishesSnapshot(t *testing.T) {
	const body = "example.com\ncdn.example.net\n*.wild.example.org\n198.51.100.0/24\n"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	fetcher := newLocalListFetcher(t, srv)

	syncer, err := NewSyncer(matcher, fetcher, store, SyncConfig{
		Sources: []Source{{
			ID:             "antifilter_domains",
			URL:            "https://antifilter.download/list/domains.lst",
			Format:         FormatMixed,
			BareDomainMode: DomainModeInclusiveSuffix,
			IsPreset:       true,
		}},
		RefreshInterval: MinRefreshInterval,
	})
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	res, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("SyncOnce failed on a valid list: %v", err)
	}
	if !res.Published {
		t.Fatal("SyncOnce did not publish a snapshot")
	}

	snap := matcher.Current()
	if snap == nil {
		t.Fatal("no snapshot published")
	}
	if snap.DomainCount() != 3 {
		t.Errorf("domain count = %d, want 3", snap.DomainCount())
	}
	if snap.CIDRCount() != 1 {
		t.Errorf("CIDR count = %d, want 1", snap.CIDRCount())
	}
	for _, name := range []string{"example.com", "cdn.example.net", "sub.wild.example.org"} {
		if !snap.MatchDomain(name) {
			t.Errorf("published snapshot does not match %q", name)
		}
	}
	if !snap.MatchIPv4(netip.MustParseAddr("198.51.100.7")) {
		t.Error("published snapshot does not match CIDR rule 198.51.100.0/24")
	}

	// The durable commit must have happened, and must round-trip through the real
	// file store so a restart can recover it.
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("durable last-known-good store load failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("nothing committed to the durable store")
	}
	if loaded.GenerationID != res.GenerationID {
		t.Errorf("stored generation = %q, want %q", loaded.GenerationID, res.GenerationID)
	}
	restored, err := GenerationToSnapshot(loaded)
	if err != nil {
		t.Fatalf("GenerationToSnapshot: %v", err)
	}
	if !restored.MatchDomain("example.com") {
		t.Error("restored last-known-good snapshot does not match its rule")
	}
}

// A malformed payload must fail the sync and leave the previously published
// snapshot untouched: "fail without replacing a valid active policy".
func TestPolicySourceFailurePreservesLastKnownGood(t *testing.T) {
	var failNext atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failNext.Load() {
			// The hardened fetcher rejects HTML challenge documents outright.
			_, _ = w.Write([]byte("<!DOCTYPE html><html><body>challenge</body></html>"))
			return
		}
		_, _ = w.Write([]byte("good.example.com\n"))
	}))
	defer srv.Close()

	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	fetcher := newLocalListFetcher(t, srv)

	syncer, err := NewSyncer(matcher, fetcher, store, SyncConfig{
		Sources: []Source{{
			ID:             "custom-1",
			URL:            "https://lists.example/domains.lst",
			Format:         FormatMixed,
			BareDomainMode: DomainModeInclusiveSuffix,
		}},
		RefreshInterval: MinRefreshInterval,
	})
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	if _, err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatalf("first sync failed: %v", err)
	}
	first := matcher.Current()
	if first == nil || first.DomainCount() == 0 {
		t.Fatal("first sync did not publish a snapshot")
	}
	firstGen := first.Generation()

	failNext.Store(true)
	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("sync accepted an HTML payload, want rejection")
	}

	after := matcher.Current()
	if after == nil {
		t.Fatal("failed sync removed the last-known-good snapshot")
	}
	if after.Generation() != firstGen {
		t.Fatalf("failed sync replaced the live snapshot: %q -> %q", firstGen, after.Generation())
	}
	if !after.MatchDomain("good.example.com") {
		t.Fatal("last-known-good snapshot no longer matches its rule")
	}
	if status := syncer.Status(); status.LastError == "" {
		t.Error("failed sync did not record LastError for the operator")
	}

	// The durable store must still hold the good generation, so a restart after a
	// failed sync still comes up with the last working policy.
	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("durable store load: %v", err)
	}
	if stored == nil || stored.GenerationID != firstGen {
		t.Fatalf("durable store no longer holds the last-known-good generation")
	}
}

// An empty feed must be refused rather than publishing an empty snapshot, because
// an empty policy is indistinguishable from "proxy nothing".
func TestPolicySourceEmptyFeedRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# only comments\n\n"))
	}))
	defer srv.Close()

	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	fetcher := newLocalListFetcher(t, srv)

	syncer, err := NewSyncer(matcher, fetcher, store, SyncConfig{
		Sources: []Source{{
			ID:             "custom-1",
			URL:            "https://lists.example/empty.lst",
			Format:         FormatMixed,
			BareDomainMode: DomainModeInclusiveSuffix,
		}},
		RefreshInterval: MinRefreshInterval,
	})
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("empty feed was accepted and published")
	}
	if matcher.Current() != nil {
		t.Fatal("empty feed published a snapshot")
	}
}

// SyncOnce must keep reporting ErrSyncInProgress semantics through the same guard
// the scheduled loop uses, so the API's 409 branch is reachable.
func TestSyncOnceRespectsInProgressGuard(t *testing.T) {
	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()
	syncer, err := NewSyncer(matcher, nil, store, SyncConfig{
		Sources: []Source{{
			ID:             "antifilter_domains",
			URL:            "https://antifilter.download/list/domains.lst",
			Format:         FormatMixed,
			BareDomainMode: DomainModeInclusiveSuffix,
			IsPreset:       true,
		}},
		RefreshInterval: MinRefreshInterval,
	})
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	// Simulate a sync already running.
	syncer.active.Store(true)
	defer syncer.active.Store(false)

	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce ignored the in-progress guard")
	}
}

// SyncOnce must refuse work after the syncer has been closed.
func TestSyncOnceRefusesClosedSyncer(t *testing.T) {
	store := NewFileStore(t.TempDir())
	syncer, err := NewSyncer(NewMatcher(), nil, store, SyncConfig{
		Sources: []Source{{
			ID:             "antifilter_domains",
			URL:            "https://antifilter.download/list/domains.lst",
			Format:         FormatMixed,
			BareDomainMode: DomainModeInclusiveSuffix,
			IsPreset:       true,
		}},
		RefreshInterval: MinRefreshInterval,
	})
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	syncer.closed.Store(true)

	if _, err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce ran on a closed syncer")
	}
}

// Route-cache size accessors must report the real entry count, since the stats
// endpoint publishes it.
func TestRouteCacheEntryCountTracksObservations(t *testing.T) {
	rc, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("NewRouteCache: %v", err)
	}
	if rc.EntryCount() != 0 || rc.SessionCount() != 0 {
		t.Fatalf("fresh cache reports (%d, %d), want (0, 0)", rc.EntryCount(), rc.SessionCount())
	}

	scope := Scope{SessionID: "session-1", OwnershipEpoch: 1}
	sc, err := rc.Open(scope)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rc.SessionCount() != 1 {
		t.Errorf("session count = %d, want 1", rc.SessionCount())
	}

	gen := "gen-1"
	rc.SetPolicyGeneration(gen)
	now := time.Now()
	// 93.184.216.34 is a public address; the route cache rejects SSRF-reserved
	// ranges like 203.0.113.0/24 when recording observations.
	if err := sc.Observe(gen, []Observation{
		{IP: netip.MustParseAddr("93.184.216.34"), Decision: Direct, ExpiresAt: now.Add(time.Hour)},
	}, now); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := rc.EntryCount(); got != 1 {
		t.Errorf("entry count after one observation = %d, want 1", got)
	}
}
