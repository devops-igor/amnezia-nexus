package policy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSyncer_FullLifecycleAndLKGRecovery(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcher := NewMatcher()

	// Mock server
	var requestCount atomic.Int32
	var serverFail atomic.Bool

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if serverFail.Load() {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if r.Header.Get("If-None-Match") == `"v1.0"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", `"v1.0"`)
		w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("example.com\n.sub.example.com\n198.51.100.0/24\n10.0.0.1\n"))
	}))
	defer ts.Close()

	serverAddr := ts.Listener.Addr().String()

	newTestFetcher := func() *Fetcher {
		f := NewFetcher(DefaultFetchLimits())
		f.tlsConfig = &tls.Config{InsecureSkipVerify: true}
		f.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		f.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		}
		return f
	}

	cfg := SyncConfig{
		Sources: []Source{
			{
				ID:             "source-1",
				URL:            "https://rules.example.com/rules.lst",
				Format:         FormatMixed,
				BareDomainMode: DomainModeInclusiveSuffix,
				IsPreset:       true,
			},
		},
		RefreshInterval: 1 * time.Hour,
		FetchLimits:     DefaultFetchLimits(),
		ParseLimits:     DefaultParseLimits(),
	}

	fetcher := newTestFetcher()
	syncer, err := NewSyncer(matcher, fetcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- syncer.Run(ctx)
	}()

	// Wait for initial sync
	time.Sleep(100 * time.Millisecond)

	snap := matcher.Current()
	if snap == nil {
		t.Fatal("expected active snapshot after initial sync, got nil")
	}
	if snap.Version() != 1 {
		t.Errorf("snap.Version = %d, want 1", snap.Version())
	}
	if !snap.MatchDomain("example.com") {
		t.Error("expected example.com to match")
	}
	if !snap.MatchDomain("deep.sub.example.com") {
		t.Error("expected deep.sub.example.com to match")
	}
	if !snap.MatchIPv4(netip.MustParseAddr("198.51.100.5")) {
		t.Error("expected 198.51.100.5 to match")
	}
	if !snap.MatchIPv4(netip.MustParseAddr("10.0.0.1")) {
		t.Error("expected 10.0.0.1 to match")
	}

	// Verify LKG file was persisted
	lkgPath := filepath.Join(tempDir, cacheFileName)
	fi, err := os.Stat(lkgPath)
	if err != nil {
		t.Fatalf("expected cache file on disk: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("cache file permissions = %o, want 0600", fi.Mode().Perm())
	}

	// Test Conditional 304 sync
	res, err := syncer.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync 304 failed: %v", err)
	}
	if !res.SourceStats["source-1"].NotModified {
		t.Errorf("expected 304 NotModified, got %+v", res.SourceStats["source-1"])
	}

	// Test Server Failure: old snapshot remains active!
	serverFail.Store(true)
	_, err = syncer.Sync(ctx)
	if err == nil {
		t.Fatal("expected sync failure when server fails")
	}
	// Old snapshot must still be active!
	snapAfterFailure := matcher.Current()
	if snapAfterFailure == nil || snapAfterFailure.Version() != 2 { // wait, version 2 was the 304
		// The active snapshot must remain functional
		if !snapAfterFailure.MatchDomain("example.com") {
			t.Error("expected previous snapshot rules to remain active after failure")
		}
	}

	// Stop syncer
	cancel()
	_ = <-runErrCh

	// Test LKG recovery on restart without network
	newMatcher := NewMatcher()
	offlineFetcher := NewFetcher(DefaultFetchLimits()) // will fail if network is attempted
	newSyncer, err := NewSyncer(newMatcher, offlineFetcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	// Run with already canceled context to only test recovery in Run
	stopCtx, stopCancel := context.WithCancel(context.Background())
	stopCancel()
	_ = newSyncer.Run(stopCtx)

	recoveredSnap := newMatcher.Current()
	if recoveredSnap == nil {
		t.Fatal("expected recovered snapshot from LKG cache, got nil")
	}
	if !recoveredSnap.MatchDomain("example.com") {
		t.Error("expected recovered snapshot to match example.com")
	}
	if !recoveredSnap.MatchIPv4(netip.MustParseAddr("198.51.100.5")) {
		t.Error("expected recovered snapshot to match 198.51.100.5")
	}
}

func TestSyncer_ConcurrentReadersRace(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcher := NewMatcher()

	// Initial snapshot
	initialSnap, err := CompileSnapshot(1, "gen-init", []SourceParsedRules{
		{
			SourceID: "s1",
			Rules: ParsedRules{
				Domains: map[string]domainFlags{"example.com": domainInclusiveSuffix},
				CIDRs:   []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	matcher.Publish(initialSnap)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Start 10 concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					snap := matcher.Current()
					if snap != nil {
						_ = snap.MatchCanonicalDomain("example.com")
						_ = snap.MatchDomain("sub.example.com")
						_ = snap.MatchIPv4(netip.MustParseAddr("198.51.100.50"))
						_ = snap.Version()
					}
				}
			}
		}()
	}

	// Background publisher changing snapshots concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		var v uint64 = 2
		for {
			select {
			case <-ctx.Done():
				return
			default:
				nextSnap, compErr := CompileSnapshot(v, fmt.Sprintf("gen-%d", v), []SourceParsedRules{
					{
						SourceID: "s1",
						Rules: ParsedRules{
							Domains: map[string]domainFlags{
								"example.com":                domainInclusiveSuffix,
								fmt.Sprintf("test%d.org", v): domainExact,
							},
							CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
						},
					},
				})
				if compErr == nil {
					matcher.Publish(nextSnap)
					_ = store.Commit(context.Background(), &Generation{
						SchemaVersion: SchemaVersion,
						GenerationID:  fmt.Sprintf("gen-%d", v),
						Version:       v,
						Domains:       map[string]uint8{"example.com": uint8(domainInclusiveSuffix)},
						CIDRs:         []string{"198.51.100.0/24"},
					})
				}
				v++
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
}

func TestSyncer_ShrinkGuard(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcher := NewMatcher()

	// Initial snapshot with 10 rules
	domains := make(map[string]domainFlags)
	for i := 0; i < 10; i++ {
		domains[fmt.Sprintf("host%d.example.com", i)] = domainExact
	}
	initialSnap, _ := CompileSnapshot(1, "gen-1", []SourceParsedRules{
		{
			SourceID: "src-shrink",
			Rules:    ParsedRules{Domains: domains},
		},
	})
	matcher.Publish(initialSnap)

	var serverPayload atomic.Pointer[string]
	shrinkPayload := "single.com\n" // only 1 rule (< 50% of 10)
	serverPayload.Store(&shrinkPayload)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(*serverPayload.Load()))
	}))
	defer ts.Close()

	serverAddr := ts.Listener.Addr().String()

	fetcher := NewFetcher(DefaultFetchLimits())
	fetcher.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	fetcher.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	fetcher.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", serverAddr)
	}

	cfg := SyncConfig{
		Sources: []Source{
			{
				ID:       "src-shrink",
				URL:      "https://rules.example.com/rules.lst",
				Format:   FormatDomains,
				IsPreset: true,
			},
		},
		RefreshInterval: 1 * time.Hour,
		ForceShrink:     false,
	}

	syncer, err := NewSyncer(matcher, fetcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	// Update must fail due to shrink guard
	_, err = syncer.executeUpdate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "shrink guard") {
		t.Fatalf("expected shrink guard error, got %v", err)
	}

	// Active snapshot must remain the 10-rule snapshot
	if matcher.Current().DomainCount() != 10 {
		t.Errorf("expected active snapshot to retain 10 domains, got %d", matcher.Current().DomainCount())
	}

	// Now retry with ForceShrink = true
	syncer.cfg.ForceShrink = true
	res, err := syncer.executeUpdate(context.Background())
	if err != nil {
		t.Fatalf("expected forced shrink to succeed, got %v", err)
	}
	if !res.Published || matcher.Current().DomainCount() != 1 {
		t.Errorf("expected 1 domain published with force shrink, got %d", matcher.Current().DomainCount())
	}
}

func TestSyncer_ZeroByteFeedInitialSyncLeavesNotReady(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcher := NewMatcher()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Return 0 bytes
	}))
	defer ts.Close()

	serverAddr := ts.Listener.Addr().String()

	fetcher := NewFetcher(DefaultFetchLimits())
	fetcher.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	fetcher.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	fetcher.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", serverAddr)
	}

	cfg := SyncConfig{
		Sources: []Source{
			{
				ID:       "zero-src",
				URL:      "https://rules.example.com/rules.lst",
				Format:   FormatDomains,
				IsPreset: true,
			},
		},
		RefreshInterval: 1 * time.Hour,
	}

	syncer, err := NewSyncer(matcher, fetcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	// 1. Direct executeUpdate must return error and leave Ready == false
	_, err = syncer.executeUpdate(context.Background())
	if err == nil {
		t.Fatal("expected error on initial sync with zero-byte feed, got nil")
	}
	if !strings.Contains(err.Error(), "contained no valid rules") {
		t.Errorf("unexpected error: %v", err)
	}

	status := syncer.Status()
	if status.Ready {
		t.Error("syncer status.Ready must be false after zero-byte initial sync")
	}
	if matcher.Current() != nil {
		t.Error("matcher.Current() must be nil when syncer is not ready")
	}

	// 2. Also verify through Run(ctx) background loop with concurrent Sync()
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- syncer.Run(runCtx)
	}()

	time.Sleep(50 * time.Millisecond)

	status = syncer.Status()
	if status.Ready {
		t.Error("syncer status.Ready must remain false after Run initial sync with zero-byte feed")
	}
	if matcher.Current() != nil {
		t.Error("matcher.Current() must remain nil")
	}

	// Calling syncer.Sync() while Run is executing
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer syncCancel()
	_, syncErr := syncer.Sync(syncCtx)
	if syncErr == nil {
		t.Fatal("expected error from syncer.Sync with zero-byte feed, got nil")
	}
	if !strings.Contains(syncErr.Error(), "contained no valid rules") {
		t.Errorf("unexpected error from Sync: %v", syncErr)
	}

	runCancel()
	_ = <-runErrCh
}

func TestSyncer_MultiSourceZeroByteRefreshPreservesActiveAndLKG(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcher := NewMatcher()

	var sourceABody atomic.Pointer[string]
	initA := "domain-a.com\n"
	sourceABody.Store(&initA)

	var sourceBBody atomic.Pointer[string]
	initB := "domain-b.com\n"
	sourceBBody.Store(&initB)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/source-a.lst":
			_, _ = w.Write([]byte(*sourceABody.Load()))
		case "/source-b.lst":
			_, _ = w.Write([]byte(*sourceBBody.Load()))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	serverAddr := ts.Listener.Addr().String()

	fetcher := NewFetcher(DefaultFetchLimits())
	fetcher.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	fetcher.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	fetcher.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", serverAddr)
	}

	cfg := SyncConfig{
		Sources: []Source{
			{
				ID:             "source-a",
				URL:            "https://rules.example.com/source-a.lst",
				Format:         FormatDomains,
				BareDomainMode: DomainModeExact,
				IsPreset:       true,
			},
			{
				ID:             "source-b",
				URL:            "https://rules.example.com/source-b.lst",
				Format:         FormatDomains,
				BareDomainMode: DomainModeExact,
				IsPreset:       true,
			},
		},
		RefreshInterval: 1 * time.Hour,
	}

	syncer, err := NewSyncer(matcher, fetcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	// Initial sync: both sources provide rules
	res, err := syncer.executeUpdate(context.Background())
	if err != nil {
		t.Fatalf("initial executeUpdate failed: %v", err)
	}
	if !res.Published {
		t.Fatal("expected initial update to be published")
	}

	snap := matcher.Current()
	if snap == nil {
		t.Fatal("expected active snapshot after initial sync")
	}
	if snap.DomainCount() != 2 {
		t.Fatalf("expected 2 domains, got %d", snap.DomainCount())
	}
	if !snap.MatchDomain("domain-a.com") || !snap.MatchDomain("domain-b.com") {
		t.Fatal("expected both domain-a.com and domain-b.com to match")
	}

	// Verify LKG exists with both sources
	lkgGen, err := store.Load(context.Background())
	if err != nil || lkgGen == nil {
		t.Fatalf("expected durable LKG generation on disk: %v", err)
	}
	if len(lkgGen.Domains) != 2 {
		t.Fatalf("expected LKG to have 2 domains, got %d", len(lkgGen.Domains))
	}

	// Now simulate refresh where Source A returns zero bytes
	emptyA := ""
	sourceABody.Store(&emptyA)

	// Refresh cycle
	res2, err := syncer.executeUpdate(context.Background())
	if err == nil {
		t.Fatal("expected executeUpdate to fail when source-a returns zero bytes, got nil")
	}
	if res2.Published {
		t.Error("update must not be published on failure")
	}

	// Verify active snapshot is still intact and retains source A rules!
	snapAfter := matcher.Current()
	if snapAfter == nil {
		t.Fatal("active snapshot became nil after failed refresh")
	}
	if snapAfter.DomainCount() != 2 {
		t.Errorf("active snapshot lost rules: got %d domains, want 2", snapAfter.DomainCount())
	}
	if !snapAfter.MatchDomain("domain-a.com") {
		t.Error("domain-a.com was lost from active snapshot")
	}
	if !snapAfter.MatchDomain("domain-b.com") {
		t.Error("domain-b.com was lost from active snapshot")
	}

	// Verify durable LKG still has both source A and source B rules
	lkgGenAfter, err := store.Load(context.Background())
	if err != nil || lkgGenAfter == nil {
		t.Fatalf("failed loading LKG: %v", err)
	}
	if len(lkgGenAfter.Domains) != 2 {
		t.Errorf("LKG lost domains: got %d, want 2", len(lkgGenAfter.Domains))
	}
	if _, ok := lkgGenAfter.Domains["domain-a.com"]; !ok {
		t.Error("domain-a.com missing from durable LKG")
	}
	if _, ok := lkgGenAfter.Domains["domain-b.com"]; !ok {
		t.Error("domain-b.com missing from durable LKG")
	}
}

func TestSyncer_ConfigHashMismatchRejectsStaleCache(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcherA := NewMatcher()

	// Initial configuration A
	cfgA := SyncConfig{
		Sources: []Source{
			{
				ID:             "source-a",
				URL:            "https://rules.example.com/rules-a.lst",
				Format:         FormatDomains,
				BareDomainMode: DomainModeExact,
			},
		},
		RefreshInterval: 1 * time.Hour,
	}

	// Compute config hash for A
	h := sha256.New()
	for _, src := range cfgA.Sources {
		_, _ = fmt.Fprintf(h, "%s:%s:%d:%d:%v\n", src.ID, src.URL, src.Format, src.BareDomainMode, src.IsPreset)
	}
	configHashA := hex.EncodeToString(h.Sum(nil))

	genA := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  "gen-a-1",
		Version:       1,
		CreatedAt:     time.Now().UTC(),
		ConfigHash:    configHashA,
		Domains:       map[string]uint8{"old-domain.com": uint8(domainExact)},
		DomainCount:   1,
	}
	if err := store.Commit(context.Background(), genA); err != nil {
		t.Fatalf("failed committing genA: %v", err)
	}

	// Verify that with cfgA, an offline syncer recovers genA from cache
	offlineFetcher := NewFetcher(DefaultFetchLimits())
	syncerA, err := NewSyncer(matcherA, offlineFetcher, store, cfgA)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}
	stopCtxA, stopCancelA := context.WithCancel(context.Background())
	stopCancelA()
	_ = syncerA.Run(stopCtxA)

	if matcherA.Current() == nil {
		t.Fatal("expected matcherA to have recovered snapshot")
	}
	if !syncerA.Status().Ready {
		t.Fatal("expected syncerA to be ready after matching config cache recovery")
	}

	// Now reconfigure to Source B (different ID and URL -> different config hash)
	matcherB := NewMatcher()
	cfgB := SyncConfig{
		Sources: []Source{
			{
				ID:             "source-b",
				URL:            "https://rules.example.com/rules-b.lst",
				Format:         FormatDomains,
				BareDomainMode: DomainModeExact,
			},
		},
		RefreshInterval: 1 * time.Hour,
	}

	syncerB, err := NewSyncer(matcherB, offlineFetcher, store, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	// Offline restart: context canceled or network unreachable
	stopCtxB, stopCancelB := context.WithCancel(context.Background())
	stopCancelB()
	_ = syncerB.Run(stopCtxB)

	// Since ConfigHash of genA does not match cfgB, cache MUST be rejected
	if matcherB.Current() != nil {
		t.Fatalf("expected nil active snapshot on config hash mismatch, got %v", matcherB.Current())
	}
	stB := syncerB.Status()
	if stB.Ready {
		t.Fatalf("expected syncerB.Status().Ready to be false, got true")
	}
	if stB.Version != 0 {
		t.Fatalf("expected syncerB.Status().Version to be 0, got %d", stB.Version)
	}

	// Also verify with a live context where executeUpdate fails due to offline network
	matcherC := NewMatcher()
	syncerC, err := NewSyncer(matcherC, offlineFetcher, store, cfgB)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}
	runCtxC, runCancelC := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer runCancelC()
	_ = syncerC.Run(runCtxC)

	if matcherC.Current() != nil {
		t.Fatalf("expected nil active snapshot after failed offline fetch, got %v", matcherC.Current())
	}
	stC := syncerC.Status()
	if stC.Ready {
		t.Fatalf("expected syncerC.Status().Ready to be false after failed offline fetch, got true")
	}
}

func TestSyncer_RetainConditionalValidatorsOn304(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)
	matcher := NewMatcher()

	var reqStep atomic.Int32
	var receivedIfNoneMatch atomic.Value
	var receivedIfModifiedSince atomic.Value

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step := reqStep.Add(1)
		receivedIfNoneMatch.Store(r.Header.Get("If-None-Match"))
		receivedIfModifiedSince.Store(r.Header.Get("If-Modified-Since"))

		switch step {
		case 1:
			// Initial full download
			w.Header().Set("ETag", `"etag-v1"`)
			w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 10:00:00 GMT")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("domain1.com\n10.0.0.1\n"))
		case 2:
			// 304 Not Modified WITHOUT ETag and WITHOUT Last-Modified in response headers
			w.WriteHeader(http.StatusNotModified)
		case 3:
			// 304 Not Modified with UPDATED ETag, but NO Last-Modified
			w.Header().Set("ETag", `"etag-v2"`)
			w.WriteHeader(http.StatusNotModified)
		default:
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer ts.Close()

	serverAddr := ts.Listener.Addr().String()
	testFetcher := NewFetcher(DefaultFetchLimits())
	testFetcher.tlsConfig = &tls.Config{InsecureSkipVerify: true}
	testFetcher.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	testFetcher.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", serverAddr)
	}

	cfg := SyncConfig{
		Sources: []Source{
			{
				ID:             "source-304",
				URL:            "https://rules.example.com/rules.lst",
				Format:         FormatMixed,
				BareDomainMode: DomainModeExact,
			},
		},
		RefreshInterval: 1 * time.Hour,
	}

	syncer, err := NewSyncer(matcher, testFetcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	go func() {
		_ = syncer.Run(runCtx)
	}()

	// Wait for initial sync from Run() to complete (Step 1: 200 OK)
	deadline := time.Now().Add(2 * time.Second)
	for !syncer.Status().Ready && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !syncer.Status().Ready {
		t.Fatal("syncer not ready after initial sync in Run")
	}

	meta1 := syncer.cachedSources["source-304"].meta
	if meta1.ETag != `"etag-v1"` {
		t.Errorf("Sync 1: ETag = %q, want %q", meta1.ETag, `"etag-v1"`)
	}
	if meta1.LastModified != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("Sync 1: LastModified = %q, want %q", meta1.LastModified, "Mon, 02 Nov 2026 10:00:00 GMT")
	}

	ctx := context.Background()

	// Step 2: 304 response omitting ETag and Last-Modified
	res2, err := syncer.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync 2 error: %v", err)
	}
	if !res2.SourceStats["source-304"].NotModified {
		t.Fatalf("Sync 2: expected NotModified=true")
	}
	// Verify server received the conditional headers from Step 1
	if receivedIfNoneMatch.Load() != `"etag-v1"` {
		t.Errorf("Sync 2: server got If-None-Match = %v, want %q", receivedIfNoneMatch.Load(), `"etag-v1"`)
	}
	if receivedIfModifiedSince.Load() != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("Sync 2: server got If-Modified-Since = %v, want %q", receivedIfModifiedSince.Load(), "Mon, 02 Nov 2026 10:00:00 GMT")
	}
	// Verify Syncer RETAINED ETag and Last-Modified despite 304 omitting them
	meta2 := syncer.cachedSources["source-304"].meta
	if meta2.ETag != `"etag-v1"` {
		t.Errorf("Sync 2: retained ETag = %q, want %q", meta2.ETag, `"etag-v1"`)
	}
	if meta2.LastModified != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("Sync 2: retained LastModified = %q, want %q", meta2.LastModified, "Mon, 02 Nov 2026 10:00:00 GMT")
	}
	// Also verify durable cached generation retained them
	if syncer.cachedGen.SourcesMeta["source-304"].ETag != `"etag-v1"` {
		t.Errorf("Sync 2: cachedGen ETag = %q, want %q", syncer.cachedGen.SourcesMeta["source-304"].ETag, `"etag-v1"`)
	}

	// Step 3: Next sync MUST send the retained validators
	res3, err := syncer.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync 3 error: %v", err)
	}
	if !res3.SourceStats["source-304"].NotModified {
		t.Fatalf("Sync 3: expected NotModified=true")
	}
	if receivedIfNoneMatch.Load() != `"etag-v1"` {
		t.Errorf("Sync 3: server got If-None-Match = %v, want %q", receivedIfNoneMatch.Load(), `"etag-v1"`)
	}
	if receivedIfModifiedSince.Load() != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("Sync 3: server got If-Modified-Since = %v, want %q", receivedIfModifiedSince.Load(), "Mon, 02 Nov 2026 10:00:00 GMT")
	}
	// Step 3 returned updated ETag: "etag-v2", but omitted Last-Modified
	meta3 := syncer.cachedSources["source-304"].meta
	if meta3.ETag != `"etag-v2"` {
		t.Errorf("Sync 3: updated ETag = %q, want %q", meta3.ETag, `"etag-v2"`)
	}
	if meta3.LastModified != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("Sync 3: retained LastModified = %q, want %q", meta3.LastModified, "Mon, 02 Nov 2026 10:00:00 GMT")
	}

	// Step 4: Next sync sends the updated ETag and retained LastModified
	_, err = syncer.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync 4 error: %v", err)
	}
	if receivedIfNoneMatch.Load() != `"etag-v2"` {
		t.Errorf("Sync 4: server got If-None-Match = %v, want %q", receivedIfNoneMatch.Load(), `"etag-v2"`)
	}
	if receivedIfModifiedSince.Load() != "Mon, 02 Nov 2026 10:00:00 GMT" {
		t.Errorf("Sync 4: server got If-Modified-Since = %v, want %q", receivedIfModifiedSince.Load(), "Mon, 02 Nov 2026 10:00:00 GMT")
	}
}
