package policy

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestDecision_String(t *testing.T) {
	if Unknown.String() != "UNKNOWN" {
		t.Errorf("expected UNKNOWN, got %s", Unknown.String())
	}
	if Direct.String() != "DIRECT" {
		t.Errorf("expected DIRECT, got %s", Direct.String())
	}
	if Proxy.String() != "PROXY" {
		t.Errorf("expected PROXY, got %s", Proxy.String())
	}
	if Decision(99).String() != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for invalid decision, got %s", Decision(99).String())
	}
}

func TestRouteCache_ConfigAndOpen(t *testing.T) {
	// Defaults check
	rc, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.cfg.MaxSessions != defaultMaxSessions ||
		rc.cfg.MaxEntriesPerSession != defaultMaxEntriesPerSession ||
		rc.cfg.MaxEntriesTotal != defaultMaxEntriesTotal ||
		rc.cfg.MaxTTL != defaultMaxTTL {
		t.Errorf("defaults not applied correctly: %+v", rc.cfg)
	}

	// Hard maximums check
	_, err = NewRouteCache(CacheConfig{MaxSessions: 70000})
	if err == nil {
		t.Errorf("expected error for exceeding hardMaxSessions")
	}

	// Open empty session ID
	_, err = rc.Open(Scope{SessionID: ""})
	if err != ErrInvalidScope {
		t.Errorf("expected ErrInvalidScope, got %v", err)
	}

	// Open valid session
	scope1 := Scope{SessionID: "sess-1", OwnershipEpoch: 1}
	s1, err := rc.Open(scope1)
	if err != nil {
		t.Fatalf("failed to open session: %v", err)
	}
	s1Again, err := rc.Open(scope1)
	if err != nil || s1 != s1Again {
		t.Errorf("expected idempotent Open to return existing handle")
	}

	// Max sessions check
	smallRC, _ := NewRouteCache(CacheConfig{MaxSessions: 1})
	_, err = smallRC.Open(Scope{SessionID: "s1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	_, err = smallRC.Open(Scope{SessionID: "s2", OwnershipEpoch: 1})
	if err != ErrMaxSessionsReached {
		t.Errorf("expected ErrMaxSessionsReached, got %v", err)
	}
}

func TestRouteCache_ClientIsolation(t *testing.T) {
	rc, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	rc.SetPolicyGeneration("gen-1")

	now := time.Now()
	ip := netip.MustParseAddr("1.1.1.1") // Valid public IPv4

	scopeA := Scope{SessionID: "client-A", OwnershipEpoch: 1}
	scopeB := Scope{SessionID: "client-B", OwnershipEpoch: 1}
	scopeC := Scope{SessionID: "client-C", OwnershipEpoch: 1}

	sessA, _ := rc.Open(scopeA)
	sessB, _ := rc.Open(scopeB)
	sessC, _ := rc.Open(scopeC)

	// Client A resolves IP to PROXY
	err = sessA.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now.Add(60 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("sessA.Observe failed: %v", err)
	}

	// Client B resolves same IP to DIRECT
	err = sessB.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(60 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("sessB.Observe failed: %v", err)
	}

	// Verify isolated route decisions
	if got := sessA.Lookup(ip, "gen-1", now); got != Proxy {
		t.Errorf("sessA expected Proxy, got %v", got)
	}
	if got := sessB.Lookup(ip, "gen-1", now); got != Direct {
		t.Errorf("sessB expected Direct, got %v", got)
	}
	// Client C has no observation for this IP -> UNKNOWN
	if got := sessC.Lookup(ip, "gen-1", now); got != Unknown {
		t.Errorf("sessC expected Unknown, got %v", got)
	}
}

func TestRouteCache_ConflictResolution_ProxyWins(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("8.8.8.8")

	s, _ := rc.Open(Scope{SessionID: "sess-test", OwnershipEpoch: 1})

	// 1. Absent + DIRECT -> DIRECT
	err := s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(30 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("observe 1 failed: %v", err)
	}
	if got := s.Lookup(ip, "gen-1", now); got != Direct {
		t.Errorf("expected Direct, got %v", got)
	}

	// 2. DIRECT + DIRECT -> DIRECT with max(deadline)
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(50 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("observe 2 failed: %v", err)
	}
	// At now + 40s (past first 30s deadline), should still be Direct
	if got := s.Lookup(ip, "gen-1", now.Add(40*time.Second)); got != Direct {
		t.Errorf("expected Direct at +40s, got %v", got)
	}

	// 3. DIRECT + PROXY -> PROXY with only PROXY deadline (discards old DIRECT evidence)
	proxyDeadline := now.Add(20 * time.Second)
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: proxyDeadline},
	}, now)
	if err != nil {
		t.Fatalf("observe 3 failed: %v", err)
	}
	// Check at now: must be Proxy
	if got := s.Lookup(ip, "gen-1", now); got != Proxy {
		t.Errorf("expected Proxy, got %v", got)
	}
	// Check at now + 25s: proxy expired! Old DIRECT (which was +50s) must NOT resurrect!
	if got := s.Lookup(ip, "gen-1", now.Add(25*time.Second)); got != Unknown {
		t.Errorf("expected Unknown at +25s (no resurrection), got %v", got)
	}

	// 4. Reset & test PROXY + DIRECT -> keep PROXY and its deadline (ignores DIRECT)
	s.Invalidate()
	s2, _ := rc.Open(Scope{SessionID: "sess-test-2", OwnershipEpoch: 1})
	err = s2.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now.Add(20 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("s2 observe proxy failed: %v", err)
	}
	// Try to observe DIRECT with longer deadline
	err = s2.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(60 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("s2 observe direct failed: %v", err)
	}
	// At now + 10s: PROXY
	if got := s2.Lookup(ip, "gen-1", now.Add(10*time.Second)); got != Proxy {
		t.Errorf("expected Proxy at +10s, got %v", got)
	}
	// At now + 25s: PROXY expired, DIRECT ignored -> UNKNOWN
	if got := s2.Lookup(ip, "gen-1", now.Add(25*time.Second)); got != Unknown {
		t.Errorf("expected Unknown at +25s, got %v", got)
	}

	// 5. PROXY + PROXY -> PROXY with max(deadline)
	s2.Invalidate()
	s3, _ := rc.Open(Scope{SessionID: "sess-test-3", OwnershipEpoch: 1})
	_ = s3.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now.Add(20 * time.Second)},
	}, now)
	_ = s3.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now.Add(40 * time.Second)},
	}, now)
	if got := s3.Lookup(ip, "gen-1", now.Add(30*time.Second)); got != Proxy {
		t.Errorf("expected Proxy at +30s, got %v", got)
	}
	if got := s3.Lookup(ip, "gen-1", now.Add(45*time.Second)); got != Unknown {
		t.Errorf("expected Unknown at +45s, got %v", got)
	}
}

func TestRouteCache_BatchFolding(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("9.9.9.9")

	s, _ := rc.Open(Scope{SessionID: "sess-fold", OwnershipEpoch: 1})

	// Batch has both Direct (longer TTL) and Proxy (shorter TTL) for the same IP
	batch := []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(100 * time.Second)},
		{IP: ip, Decision: Proxy, ExpiresAt: now.Add(20 * time.Second)},
	}
	err := s.Observe("gen-1", batch, now)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	if got := s.Lookup(ip, "gen-1", now); got != Proxy {
		t.Errorf("expected Proxy, got %v", got)
	}
	// At +25s, proxy expired -> UNKNOWN (Direct must not be active)
	if got := s.Lookup(ip, "gen-1", now.Add(25*time.Second)); got != Unknown {
		t.Errorf("expected Unknown at +25s, got %v", got)
	}
}

func TestRouteCache_TTLRulesAndClamping(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{MaxTTL: 3600 * time.Second})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("1.1.1.1")
	s, _ := rc.Open(Scope{SessionID: "sess-ttl", OwnershipEpoch: 1})

	// Expired / zero deadline rejected
	err := s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now},
	}, now)
	if err == nil {
		t.Errorf("expected error for zero/expired deadline")
	}

	// Deadline beyond MaxTTL rejected
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(3601 * time.Second)},
	}, now)
	if err == nil {
		t.Errorf("expected error for deadline exceeding MaxTTL")
	}

	// 1 second TTL expires at exactly 1 second
	expiry := now.Add(1 * time.Second)
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: expiry},
	}, now)
	if err != nil {
		t.Fatalf("observe failed: %v", err)
	}

	// Just before expiry (now + 999ms)
	if got := s.Lookup(ip, "gen-1", now.Add(999*time.Millisecond)); got != Direct {
		t.Errorf("expected Direct before expiry, got %v", got)
	}
	// Exactly at expiry (now + 1s)
	if got := s.Lookup(ip, "gen-1", expiry); got != Unknown {
		t.Errorf("expected Unknown at exact expiry, got %v", got)
	}
	// After expiry
	if got := s.Lookup(ip, "gen-1", now.Add(2*time.Second)); got != Unknown {
		t.Errorf("expected Unknown after expiry, got %v", got)
	}
}

func TestRouteCache_AddressValidation(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	s, _ := rc.Open(Scope{SessionID: "sess-addr", OwnershipEpoch: 1})

	invalidAddrs := []string{
		"10.0.0.1",             // Private RFC 1918
		"192.168.1.1",          // Private RFC 1918
		"172.16.0.1",           // Private RFC 1918
		"127.0.0.1",            // Loopback
		"169.254.169.254",      // Link-local / Cloud metadata
		"100.64.0.1",           // CGNAT
		"224.0.0.1",            // Multicast
		"0.0.0.0",              // Unspecified
		"::1",                  // IPv6
		"2001:4860:4860::8888", // IPv6
	}

	for _, addrStr := range invalidAddrs {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", addrStr, err)
		}
		err = s.Observe("gen-1", []Observation{
			{IP: addr, Decision: Direct, ExpiresAt: now.Add(10 * time.Second)},
		}, now)
		if err == nil {
			t.Errorf("expected address %s to be rejected by Observe", addrStr)
		}
	}
}

func TestRouteCache_PolicyGenerationAndInvalidation(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("8.8.4.4")
	s, _ := rc.Open(Scope{SessionID: "sess-gen", OwnershipEpoch: 1})

	_ = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(30 * time.Second)},
	}, now)

	// Valid lookup with matching generation
	if got := s.Lookup(ip, "gen-1", now); got != Direct {
		t.Errorf("expected Direct, got %v", got)
	}

	// Lookup with mismatched generation returns Unknown
	if got := s.Lookup(ip, "gen-2", now); got != Unknown {
		t.Errorf("expected Unknown for mismatched generation, got %v", got)
	}

	// Observe with stale generation returns error
	err := s.Observe("gen-0", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(30 * time.Second)},
	}, now)
	if err != ErrGenerationMismatch {
		t.Errorf("expected ErrGenerationMismatch, got %v", err)
	}

	// Advance policy generation in cache
	rc.SetPolicyGeneration("gen-2")
	// Old entries flushed, lookups return Unknown
	if got := s.Lookup(ip, "gen-2", now); got != Unknown {
		t.Errorf("expected Unknown after SetPolicyGeneration, got %v", got)
	}

	// Invalidation
	s.Invalidate()
	if got := s.Lookup(ip, "gen-2", now); got != Unknown {
		t.Errorf("expected Unknown after Invalidate, got %v", got)
	}
	err = s.Observe("gen-2", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(30 * time.Second)},
	}, now)
	if err != ErrSessionRetired {
		t.Errorf("expected ErrSessionRetired after Invalidate, got %v", err)
	}
}

func TestRouteCache_CapacityAndQuarantine(t *testing.T) {
	// Configure tight per-session capacity: 2 entries
	rc, _ := NewRouteCache(CacheConfig{
		MaxSessions:          10,
		MaxEntriesPerSession: 2,
		MaxEntriesTotal:      100,
	})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()

	s, _ := rc.Open(Scope{SessionID: "sess-cap", OwnershipEpoch: 1})

	ip1 := netip.MustParseAddr("1.1.1.1")
	ip2 := netip.MustParseAddr("1.1.1.2")
	ip3 := netip.MustParseAddr("1.1.1.3")

	// 1. Direct entry eviction to make room
	_ = s.Observe("gen-1", []Observation{
		{IP: ip1, Decision: Direct, ExpiresAt: now.Add(30 * time.Second)},
		{IP: ip2, Decision: Proxy, ExpiresAt: now.Add(30 * time.Second)},
	}, now)
	// Add ip3 as Direct: should evict one Direct entry, keep ip2 (Proxy)
	err := s.Observe("gen-1", []Observation{
		{IP: ip3, Decision: Direct, ExpiresAt: now.Add(30 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("observe ip3 failed: %v", err)
	}
	if got := s.Lookup(ip2, "gen-1", now); got != Proxy {
		t.Errorf("expected ip2 to remain Proxy, got %v", got)
	}
	// Eviction has no ordering guarantee; name the survivor ip3 for the steps below.
	if s.Lookup(ip1, "gen-1", now) == Direct {
		ip1, ip3 = ip3, ip1
	}
	if got := s.Lookup(ip3, "gen-1", now); got != Direct {
		t.Errorf("expected surviving Direct entry, got %v", got)
	}
	if got := s.Lookup(ip1, "gen-1", now); got != Unknown {
		t.Errorf("expected evicted Direct entry to be Unknown, got %v", got)
	}

	// 2. Quarantine trigger: when PROXY cannot fit
	// Now we have ip2 (Proxy) and ip3 (Direct). Let's make ip3 Proxy as well.
	_ = s.Observe("gen-1", []Observation{
		{IP: ip3, Decision: Proxy, ExpiresAt: now.Add(40 * time.Second)},
	}, now)
	// Now both entries in session are PROXY (ip2 and ip3).
	// Incoming ip1 is PROXY with deadline +50s. Max capacity is 2, so it cannot fit without evicting PROXY!
	err = s.Observe("gen-1", []Observation{
		{IP: ip1, Decision: Proxy, ExpiresAt: now.Add(50 * time.Second)},
	}, now)
	if err != ErrCapacityExceeded {
		t.Errorf("expected ErrCapacityExceeded, got %v", err)
	}

	// Session is now quarantined! All lookups return Unknown
	if got := s.Lookup(ip1, "gen-1", now); got != Unknown {
		t.Errorf("expected ip1 Unknown during quarantine, got %v", got)
	}
	if got := s.Lookup(ip2, "gen-1", now); got != Unknown {
		t.Errorf("expected ip2 Unknown during quarantine, got %v", got)
	}
	if got := s.Lookup(ip3, "gen-1", now); got != Unknown {
		t.Errorf("expected ip3 Unknown during quarantine, got %v", got)
	}

	// Incoming DIRECT during quarantine is rejected with ErrCapacityExceeded
	err = s.Observe("gen-1", []Observation{
		{IP: ip1, Decision: Direct, ExpiresAt: now.Add(20 * time.Second)},
	}, now)
	if err != ErrCapacityExceeded {
		t.Errorf("expected ErrCapacityExceeded for Direct during quarantine, got %v", err)
	}

	// Incoming PROXY with longer deadline extends quarantine
	err = s.Observe("gen-1", []Observation{
		{IP: ip1, Decision: Proxy, ExpiresAt: now.Add(60 * time.Second)},
	}, now)
	if err != ErrCapacityExceeded {
		t.Errorf("expected ErrCapacityExceeded for extending Proxy, got %v", err)
	}

	// Advance clock past quarantine (+61s)
	afterQuarantine := now.Add(61 * time.Second)
	// Cache sweep clears expired quarantine
	rc.Sweep(afterQuarantine)

	// Now fresh observations can be admitted
	err = s.Observe("gen-1", []Observation{
		{IP: ip1, Decision: Direct, ExpiresAt: afterQuarantine.Add(20 * time.Second)},
	}, afterQuarantine)
	if err != nil {
		t.Fatalf("expected successful observe after quarantine, got %v", err)
	}
	if got := s.Lookup(ip1, "gen-1", afterQuarantine); got != Direct {
		t.Errorf("expected Direct after quarantine cleared, got %v", got)
	}
}

func TestRouteCache_Sweep(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("8.8.8.8")

	s, _ := rc.Open(Scope{SessionID: "sess-sweep", OwnershipEpoch: 1})
	_ = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(10 * time.Second)},
	}, now)

	if rc.totalEntries != 1 {
		t.Errorf("expected totalEntries 1, got %d", rc.totalEntries)
	}

	// Sweep before expiry: entry stays
	rc.Sweep(now.Add(5 * time.Second))
	if rc.totalEntries != 1 {
		t.Errorf("expected totalEntries 1 after partial sweep, got %d", rc.totalEntries)
	}

	// Sweep after expiry: entry pruned
	rc.Sweep(now.Add(15 * time.Second))
	if rc.totalEntries != 0 {
		t.Errorf("expected totalEntries 0 after full sweep, got %d", rc.totalEntries)
	}
}

func TestRouteCache_ConcurrencyRace(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("1.1.1.1")

	s, _ := rc.Open(Scope{SessionID: "sess-concur", OwnershipEpoch: 1})

	var wg sync.WaitGroup
	// Concurrently observe
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			decision := Direct
			if id%2 == 0 {
				decision = Proxy
			}
			_ = s.Observe("gen-1", []Observation{
				{IP: ip, Decision: decision, ExpiresAt: now.Add(time.Duration(10+id) * time.Second)},
			}, now)
		}(i)
	}

	// Concurrently lookup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Lookup(ip, "gen-1", now)
		}()
	}

	// Concurrently sweep
	wg.Add(1)
	go func() {
		defer wg.Done()
		rc.Sweep(now)
	}()

	wg.Wait()
}

func TestRouteCache_ZeroTTLProxyRevokesActiveDirect(t *testing.T) {
	rc, _ := NewRouteCache(CacheConfig{})
	rc.SetPolicyGeneration("gen-1")
	now := time.Now()
	ip := netip.MustParseAddr("93.184.216.34")

	s, _ := rc.Open(Scope{SessionID: "sess-zero-ttl", OwnershipEpoch: 1})

	// 1. Establish an active DIRECT entry with 300s TTL.
	err := s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now.Add(300 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("initial direct observe failed: %v", err)
	}
	if got := s.Lookup(ip, "gen-1", now); got != Direct {
		t.Fatalf("expected Direct initially, got %v", got)
	}

	// 2. Observe zero-TTL Proxy observation (ExpiresAt == now).
	// Must immediately revoke the active DIRECT entry so subsequent lookups return UNKNOWN.
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now},
	}, now)
	if err != nil {
		t.Fatalf("zero-ttl proxy observe failed: %v", err)
	}
	if got := s.Lookup(ip, "gen-1", now); got != Unknown {
		t.Errorf("expected Unknown (safe fallback) after zero-TTL proxy suppression, got %v", got)
	}

	// 3. Confirm that zero-TTL DIRECT is still rejected as invalid.
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Direct, ExpiresAt: now},
	}, now)
	if err == nil {
		t.Errorf("expected error for zero-TTL Direct observation, got nil")
	}

	// 4. Confirm that zero-TTL Proxy does NOT revoke an already active PROXY entry.
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now.Add(60 * time.Second)},
	}, now)
	if err != nil {
		t.Fatalf("proxy observe failed: %v", err)
	}
	if got := s.Lookup(ip, "gen-1", now); got != Proxy {
		t.Fatalf("expected Proxy, got %v", got)
	}
	err = s.Observe("gen-1", []Observation{
		{IP: ip, Decision: Proxy, ExpiresAt: now},
	}, now)
	if err != nil {
		t.Fatalf("zero-ttl proxy observe over existing proxy failed: %v", err)
	}
	if got := s.Lookup(ip, "gen-1", now); got != Proxy {
		t.Errorf("expected active Proxy to remain Proxy after zero-TTL proxy observation, got %v", got)
	}
}
