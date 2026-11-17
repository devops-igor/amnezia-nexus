package policy

import (
	"net/netip"
	"testing"
	"time"
)

// Behavioural coverage for the read-only session listing (issue #861).
//
// The listing is the whole-session counterpart of Inspect, and the property that
// matters is that reading it changes nothing: every case below asserts the
// reported state and then re-reads the same cache through Lookup/Count to show
// the read did not prune, extend, allocate or quarantine anything.

func newListingCache(t *testing.T, cfg CacheConfig, generation string) *RouteCache {
	t.Helper()
	rc, err := NewRouteCache(cfg)
	if err != nil {
		t.Fatalf("NewRouteCache: %v", err)
	}
	rc.SetPolicyGeneration(generation)
	return rc
}

func mustScope(t *testing.T, rc *RouteCache, sessionID string) *SessionCache {
	t.Helper()
	sc, err := rc.Open(Scope{SessionID: sessionID, OwnershipEpoch: 1})
	if err != nil || sc == nil {
		t.Fatalf("Open(%s): %v", sessionID, err)
	}
	return sc
}

func entryAddresses(list SessionEntryList) []string {
	out := make([]string, 0, len(list.Entries))
	for _, entry := range list.Entries {
		out = append(out, entry.Address.String())
	}
	return out
}

func TestSessionEntriesListsRetainedDecisionsNewestFirst(t *testing.T) {
	rc := newListingCache(t, CacheConfig{}, "gen-1")
	sc := mustScope(t, rc, "sess-list")
	now := time.Now()

	direct := netip.MustParseAddr("1.1.1.10")
	proxy := netip.MustParseAddr("1.1.1.11")
	expired := netip.MustParseAddr("1.1.1.12")

	if err := sc.Observe("gen-1", []Observation{
		{IP: direct, Decision: Direct, ExpiresAt: now.Add(10 * time.Minute)},
		{IP: proxy, Decision: Proxy, ExpiresAt: now.Add(10 * time.Minute)},
	}, now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// A second batch with a later instant, so ordering is observable rather than
	// map iteration order. Its deadline is already past the read instant, which
	// makes the entry reportable as expired instead of being pruned away.
	if err := sc.Observe("gen-1", []Observation{
		{IP: expired, Decision: Direct, ExpiresAt: now.Add(-time.Minute)},
	}, now.Add(-90*time.Second)); err != nil {
		t.Fatalf("Observe expired: %v", err)
	}

	list := sc.Entries("gen-1", now, 0)
	if list.State != EvidenceFresh {
		t.Fatalf("state = %q, want fresh", list.State)
	}
	if list.Generation != "gen-1" {
		t.Errorf("generation = %q, want gen-1", list.Generation)
	}
	if list.Total != 3 || list.Truncated {
		t.Errorf("total/truncated = %d/%v, want 3/false", list.Total, list.Truncated)
	}
	got := entryAddresses(list)
	want := []string{expired.String(), direct.String(), proxy.String()}
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addresses = %v, want newest-observation-first %v", got, want)
		}
	}

	byAddress := map[string]SessionEntry{}
	for _, entry := range list.Entries {
		byAddress[entry.Address.String()] = entry
	}
	if e := byAddress[proxy.String()]; e.Decision != Proxy || e.State != EvidenceFresh {
		t.Errorf("proxy entry = %+v, want a fresh PROXY decision", e)
	}
	if e := byAddress[expired.String()]; e.State != EvidenceExpired {
		t.Errorf("expired entry state = %q, want expired", e.State)
	}
	if e := byAddress[direct.String()]; e.ObservedAt.IsZero() {
		t.Error("a stored observation instant must be reported, not dropped")
	}

	// Read-only proof: the same listing again, and the packet-path readers,
	// report the same state after the read.
	again := sc.Entries("gen-1", now, 0)
	if entryAddresses(again)[0] != got[0] || again.Total != list.Total {
		t.Errorf("a second listing differs from the first: %v vs %v", entryAddresses(again), got)
	}
	if sc.Count() != 3 {
		t.Errorf("Count = %d after listing, want 3", sc.Count())
	}
	if d := sc.Lookup(direct, "gen-1", now); d != Direct {
		t.Errorf("Lookup after listing = %v, want Direct (a read must not prune)", d)
	}
}

func TestSessionEntriesTruncatesWithoutLosingTheTotal(t *testing.T) {
	rc := newListingCache(t, CacheConfig{}, "gen-1")
	sc := mustScope(t, rc, "sess-trunc")
	now := time.Now()

	batch := make([]Observation, 0, 5)
	for i := 1; i <= 5; i++ {
		batch = append(batch, Observation{
			IP:        netip.AddrFrom4([4]byte{1, 1, 1, byte(i)}),
			Decision:  Direct,
			ExpiresAt: now.Add(time.Hour),
		})
	}
	if err := sc.Observe("gen-1", batch, now); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	list := sc.Entries("gen-1", now, 2)
	if list.Total != 5 {
		t.Errorf("total = %d, want 5", list.Total)
	}
	if !list.Truncated {
		t.Error("a page smaller than the retained set must report truncation")
	}
	if len(list.Entries) != 2 {
		t.Errorf("entries = %d, want the requested page size 2", len(list.Entries))
	}

	// The maximum page never exceeds the documented bound, and a caller asking
	// for more than the cache can hold gets the bound rather than an error.
	if huge := sc.Entries("gen-1", now, SessionEntriesMaxLimit*4); huge.Truncated || len(huge.Entries) != 5 {
		t.Errorf("page above the maximum = %d entries truncated=%v, want all 5", len(huge.Entries), huge.Truncated)
	}
}

func TestSessionEntriesReportsViewStatesWithoutEntries(t *testing.T) {
	now := time.Now()

	t.Run("AbsentForNilScope", func(t *testing.T) {
		var nilScope *SessionCache
		list := nilScope.Entries("gen-1", now, 0)
		if list.State != EvidenceAbsent {
			t.Fatalf("state = %q, want absent", list.State)
		}
		if list.Entries == nil {
			t.Error("entries must be an empty slice, not nil")
		}
	})

	t.Run("AbsentForEmptyScope", func(t *testing.T) {
		rc := newListingCache(t, CacheConfig{}, "gen-1")
		sc := mustScope(t, rc, "sess-empty")
		list := sc.Entries("gen-1", now, 0)
		if list.State != EvidenceAbsent || list.Generation != "gen-1" {
			t.Fatalf("state/generation = %q/%q, want absent/gen-1", list.State, list.Generation)
		}
	})

	t.Run("StaleGenerationHidesEntries", func(t *testing.T) {
		rc := newListingCache(t, CacheConfig{}, "gen-1")
		sc := mustScope(t, rc, "sess-stale")
		if err := sc.Observe("gen-1", []Observation{{
			IP:        netip.MustParseAddr("1.1.1.20"),
			Decision:  Direct,
			ExpiresAt: now.Add(time.Hour),
		}}, now); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		list := sc.Entries("gen-2", now, 0)
		if list.State != EvidenceStaleGeneration {
			t.Fatalf("state = %q, want stale_generation", list.State)
		}
		if len(list.Entries) != 0 {
			t.Errorf("entries = %v, want none for a stale generation", entryAddresses(list))
		}
		if list.Generation != "gen-1" {
			t.Errorf("generation = %q, want the view's own gen-1", list.Generation)
		}
	})

	t.Run("RetiredAfterInvalidate", func(t *testing.T) {
		rc := newListingCache(t, CacheConfig{}, "gen-1")
		sc := mustScope(t, rc, "sess-retired")
		sc.Invalidate()
		list := sc.Entries("gen-1", now, 0)
		if list.State != EvidenceRetired {
			t.Fatalf("state = %q, want retired", list.State)
		}
		if len(list.Entries) != 0 {
			t.Errorf("entries = %v, want none for a retired scope", entryAddresses(list))
		}
	})

	t.Run("QuarantinedReportsDeadlineAndNoEntries", func(t *testing.T) {
		// A PROXY batch that cannot fit the session's capacity quarantines the
		// session and drops its entries; the listing must say so and must not
		// derive an entry deadline from the quarantine window.
		rc := newListingCache(t, CacheConfig{MaxSessions: 4, MaxEntriesPerSession: 2, MaxEntriesTotal: 32}, "gen-1")
		sc := mustScope(t, rc, "sess-quar")
		batch := make([]Observation, 0, 3)
		for i := 1; i <= 3; i++ {
			batch = append(batch, Observation{
				IP:        netip.AddrFrom4([4]byte{8, 8, 8, byte(i)}),
				Decision:  Proxy,
				ExpiresAt: now.Add(30 * time.Minute),
			})
		}
		if err := sc.Observe("gen-1", batch, now); err != ErrCapacityExceeded {
			t.Fatalf("Observe overflow = %v, want ErrCapacityExceeded", err)
		}

		list := sc.Entries("gen-1", now, 0)
		if list.State != EvidenceQuarantined {
			t.Fatalf("state = %q, want quarantined", list.State)
		}
		if len(list.Entries) != 0 {
			t.Errorf("entries = %v, want none while quarantined", entryAddresses(list))
		}
		if list.QuarantinedUntil.IsZero() {
			t.Error("a quarantine must report its deadline")
		}
	})
}

// TestCompareSessionEntryOrdersNewestFirst pins the page ordering rule and its
// tie-breaks, including the entry that carries no recorded instant.
func TestCompareSessionEntryOrdersNewestFirst(t *testing.T) {
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	addr := netip.MustParseAddr("1.1.1.1")
	other := netip.MustParseAddr("1.1.1.2")

	recorded := SessionEntry{Address: addr, ObservedAt: base}
	unrecorded := SessionEntry{Address: addr}
	if compareSessionEntry(recorded, unrecorded) >= 0 {
		t.Error("an entry with a recorded instant must rank before one without")
	}
	if compareSessionEntry(unrecorded, recorded) <= 0 {
		t.Error("an entry without an instant must rank last")
	}

	newer := SessionEntry{Address: other, ObservedAt: base.Add(time.Second)}
	if compareSessionEntry(recorded, newer) <= 0 {
		t.Error("the newer observation must rank first regardless of address")
	}
	if compareSessionEntry(recorded, SessionEntry{Address: other, ObservedAt: base}) >= 0 {
		t.Error("equal instants must be ordered by address")
	}
	if compareSessionEntry(recorded, recorded) != 0 {
		t.Error("identical entries must compare equal")
	}
}

func TestSessionEntriesPageSizeClampsTheRequest(t *testing.T) {
	cases := map[string]struct {
		requested int
		want      int
	}{
		"Default":     {0, SessionEntriesDefaultLimit},
		"Negative":    {-5, SessionEntriesDefaultLimit},
		"Small":       {8, 8},
		"AboveTheMax": {SessionEntriesMaxLimit * 2, SessionEntriesMaxLimit},
	}
	for name, tc := range cases {
		if got := sessionEntriesPageSize(tc.requested); got != tc.want {
			t.Errorf("%s page size = %d, want %d", name, got, tc.want)
		}
	}
}

func TestSessionEntriesNeverAllocatesAScope(t *testing.T) {
	rc := newListingCache(t, CacheConfig{}, "gen-1")
	sessionsBefore := rc.SessionCount()

	var missing *SessionCache = rc.Get(Scope{SessionID: "sess-never-seen", OwnershipEpoch: 1})
	list := missing.Entries("gen-1", time.Now(), 0)
	if list.State != EvidenceAbsent {
		t.Fatalf("state = %q, want absent", list.State)
	}
	if got := rc.SessionCount(); got != sessionsBefore {
		t.Fatalf("session count moved from %d to %d during a read", sessionsBefore, got)
	}
}
