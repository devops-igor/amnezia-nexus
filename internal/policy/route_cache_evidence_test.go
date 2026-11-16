package policy

import (
	"net/netip"
	"testing"
	"time"
)

// TestSessionCacheInspectStates pins every state a dry run can report, including
// the three that Lookup cannot distinguish: expired, quarantined and stale
// generation. Inspect must classify them exactly as the packet path treats them
// (anything but fresh is not Direct evidence) while never mutating the cache.

func TestSessionCacheInspectStates(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	const gen = "gen-5"

	cache, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	cache.SetPolicyGeneration(gen)
	scope, err := cache.Open(Scope{SessionID: "session-1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}

	fresh := netip.MustParseAddr("198.51.201.10")
	if err := scope.Observe(gen, []Observation{{
		IP: fresh, Decision: Direct, ExpiresAt: now.Add(90 * time.Second),
	}}, now); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}

	t.Run("fresh", func(t *testing.T) {
		got := scope.Inspect(fresh, gen, now)
		if got.State != EvidenceFresh || got.Decision != Direct {
			t.Fatalf("evidence = %+v, want fresh Direct", got)
		}
		if remaining := got.Remaining(now); remaining != 90*time.Second {
			t.Fatalf("remaining = %v, want 90s", remaining)
		}
		if got.Generation != gen {
			t.Errorf("generation = %q, want %q", got.Generation, gen)
		}
	})

	t.Run("expired", func(t *testing.T) {
		got := scope.Inspect(fresh, gen, now.Add(2*time.Minute))
		if got.State != EvidenceExpired {
			t.Fatalf("evidence = %+v, want expired", got)
		}
		if remaining := got.Remaining(now.Add(2 * time.Minute)); remaining >= 0 {
			t.Errorf("remaining = %v, want a negative value for expired evidence", remaining)
		}
	})

	t.Run("absent", func(t *testing.T) {
		got := scope.Inspect(netip.MustParseAddr("198.51.201.11"), gen, now)
		if got.State != EvidenceAbsent {
			t.Fatalf("evidence = %+v, want absent", got)
		}
		if got.Decision != Unknown {
			t.Errorf("decision = %v, want Unknown for absent evidence", got.Decision)
		}
	})

	t.Run("stale generation", func(t *testing.T) {
		got := scope.Inspect(fresh, "gen-6", now)
		if got.State != EvidenceStaleGeneration {
			t.Fatalf("evidence = %+v, want stale_generation", got)
		}
	})

	t.Run("retired scope", func(t *testing.T) {
		retired, err := cache.Open(Scope{SessionID: "session-2", OwnershipEpoch: 1})
		if err != nil {
			t.Fatalf("open second scope: %v", err)
		}
		retired.Invalidate()
		if got := retired.Inspect(fresh, gen, now); got.State != EvidenceRetired {
			t.Fatalf("evidence = %+v, want retired", got)
		}
	})

	t.Run("nil scope", func(t *testing.T) {
		var nilScope *SessionCache
		if got := nilScope.Inspect(fresh, gen, now); got.State != EvidenceRetired {
			t.Fatalf("evidence = %+v, want retired", got)
		}
	})

	t.Run("scope without a published view", func(t *testing.T) {
		empty := &SessionCache{}
		if got := empty.Inspect(fresh, gen, now); got.State != EvidenceRetired {
			t.Fatalf("evidence = %+v, want retired", got)
		}
	})
}

// TestSessionCacheInspectQuarantined covers the eviction state: capacity
// overflow drops the session's entries and answers Unknown until the quarantine
// deadline, and Inspect reports exactly that.
func TestSessionCacheInspectQuarantined(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	const gen = "gen-5"

	cache, err := NewRouteCache(CacheConfig{MaxEntriesPerSession: 1})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	cache.SetPolicyGeneration(gen)
	scope, err := cache.Open(Scope{SessionID: "session-1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}

	first := netip.MustParseAddr("198.51.201.20")
	if err := scope.Observe(gen, []Observation{{
		IP: first, Decision: Proxy, ExpiresAt: now.Add(time.Minute),
	}}, now); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	if err := scope.Observe(gen, []Observation{
		{IP: netip.MustParseAddr("198.51.201.21"), Decision: Proxy, ExpiresAt: now.Add(time.Minute)},
		{IP: netip.MustParseAddr("198.51.201.22"), Decision: Proxy, ExpiresAt: now.Add(time.Minute)},
	}, now); err == nil {
		t.Fatal("expected the overflow to quarantine the session")
	}

	got := scope.Inspect(first, gen, now)
	if got.State != EvidenceQuarantined {
		t.Fatalf("evidence = %+v, want quarantined", got)
	}
	if got.ExpiresAt.IsZero() {
		t.Error("a quarantine must report its deadline")
	}
	// The packet path answers Unknown for a quarantined session.
	if decision := scope.Lookup(first, gen, now); decision != Unknown {
		t.Errorf("Lookup = %v, want Unknown while quarantined", decision)
	}
}

// TestSessionCacheInspectIsReadOnly asserts the accessor changed nothing: same
// entry and session counts, same views, no pruning of the expired entry it just
// reported.
func TestSessionCacheInspectIsReadOnly(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	const gen = "gen-5"

	cache, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	cache.SetPolicyGeneration(gen)
	scope, err := cache.Open(Scope{SessionID: "session-1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}
	addr := netip.MustParseAddr("198.51.201.30")
	if err := scope.Observe(gen, []Observation{{
		IP: addr, Decision: Direct, ExpiresAt: now.Add(10 * time.Second),
	}}, now); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}

	entriesBefore := cache.EntryCount()
	sessionsBefore := cache.SessionCount()
	viewBefore := scope.view.Load()

	// Inspect at a time when the entry has expired, at a stale generation and at
	// the absent address: the expired entry must still be there afterwards.
	_ = scope.Inspect(addr, gen, now.Add(time.Hour))
	_ = scope.Inspect(addr, "gen-stale", now)
	_ = scope.Inspect(netip.MustParseAddr("198.51.201.31"), gen, now)

	if got := cache.EntryCount(); got != entriesBefore {
		t.Errorf("entry count = %d, want %d", got, entriesBefore)
	}
	if got := cache.SessionCount(); got != sessionsBefore {
		t.Errorf("session count = %d, want %d", got, sessionsBefore)
	}
	if after := scope.view.Load(); after != viewBefore {
		t.Error("Inspect published a new cache view")
	}
	if got := scope.Inspect(addr, gen, now); got.State != EvidenceFresh {
		t.Errorf("evidence after inspection = %+v, want the untouched fresh entry", got)
	}
}
