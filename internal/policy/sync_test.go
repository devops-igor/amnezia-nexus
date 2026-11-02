package policy

import (
	"context"
	"crypto/tls"
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
