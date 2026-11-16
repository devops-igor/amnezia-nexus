package policy

import (
	"net/netip"
	"testing"
	"time"
)

// These tests cover the observation instant recorded for evidence age (issue
// #825, acceptance criterion 3). Age is measured from a recorded instant; it is
// never inferred from the deadline.

func ageFixture(t *testing.T) (*SessionCache, string, time.Time) {
	t.Helper()
	cache, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	cache.SetPolicyGeneration("gen-age")
	scope, err := cache.Open(Scope{SessionID: "age", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}
	return scope, "gen-age", time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
}

func observeAt(t *testing.T, s *SessionCache, gen, ip string, d Decision, at time.Time, ttl time.Duration) {
	t.Helper()
	err := s.Observe(gen, []Observation{{IP: netip.MustParseAddr(ip), Decision: d, ExpiresAt: at.Add(ttl)}}, at)
	if err != nil {
		t.Fatalf("observe %s: %v", ip, err)
	}
}

// TestEvidenceAgeIsMeasuredFromTheRecordedInstant proves the age follows the
// observation instant, and that two entries with the SAME remaining lifetime but
// different observation instants report different ages. A TTL-derived age could
// not tell them apart.
func TestEvidenceAgeIsMeasuredFromTheRecordedInstant(t *testing.T) {
	s, gen, start := ageFixture(t)
	observeAt(t, s, gen, "198.51.201.10", Direct, start, time.Hour)
	later := start.Add(40 * time.Second)
	// Same deadline as the first entry, observed 40s later with a shorter TTL.
	observeAt(t, s, gen, "198.51.201.11", Direct, later, time.Hour-40*time.Second)

	now := start.Add(100 * time.Second)
	older := s.Inspect(netip.MustParseAddr("198.51.201.10"), gen, now)
	newer := s.Inspect(netip.MustParseAddr("198.51.201.11"), gen, now)
	if older.Remaining(now) != newer.Remaining(now) {
		t.Fatalf("fixture must share a remaining lifetime: %v vs %v", older.Remaining(now), newer.Remaining(now))
	}
	if age, why := older.Age(now); why != AgeReported || age != 100*time.Second {
		t.Fatalf("older age = %v (%q), want 100s", age, why)
	}
	if age, why := newer.Age(now); why != AgeReported || age != 60*time.Second {
		t.Fatalf("newer age = %v (%q), want 60s", age, why)
	}
}

// TestEvidenceWithoutARecordedInstantReportsNoAge covers records written before
// the instant was stored. Observe cannot produce one (a zero instant fails
// validation), so the legacy shape is constructed directly. It must report no
// age and name the reason, never zero and never a TTL-derived number.
func TestEvidenceWithoutARecordedInstantReportsNoAge(t *testing.T) {
	s, gen, start := ageFixture(t)
	ip := netip.MustParseAddr("198.51.201.20")
	s.view.Store(&routeView{
		policyGeneration: gen,
		entries: map[[4]byte]routeEntry{
			ip.As4(): {decision: Direct, expiresAt: start.Add(time.Hour)},
		},
	})

	now := start.Add(10 * time.Minute)
	got := s.Inspect(ip, gen, now)
	if got.State != EvidenceFresh || !got.ObservedAt.IsZero() {
		t.Fatalf("evidence = %+v, want fresh with no observation instant", got)
	}
	age, why := got.Age(now)
	if why != AgeInstantNotRecorded || age != 0 {
		t.Fatalf("age = %v (%q), want no age with %q", age, why, AgeInstantNotRecorded)
	}
}

// TestEvidenceAgeIsAbsentUnlessFresh pins the reason for each state that has no
// usable stored observation.
func TestEvidenceAgeIsAbsentUnlessFresh(t *testing.T) {
	s, gen, start := ageFixture(t)
	ip := netip.MustParseAddr("198.51.201.30")
	observeAt(t, s, gen, ip.String(), Direct, start, time.Minute)

	cases := []struct {
		name string
		ev   Evidence
		now  time.Time
		want AgeReason
	}{
		{"absent", s.Inspect(netip.MustParseAddr("198.51.201.31"), gen, start), start, AgeNoEvidence},
		{"expired", s.Inspect(ip, gen, start.Add(2*time.Minute)), start.Add(2 * time.Minute), AgeNotFresh},
		{"stale generation", s.Inspect(ip, "other-gen", start), start, AgeNotFresh},
	}
	for _, tc := range cases {
		if age, why := tc.ev.Age(tc.now); why != tc.want || age != 0 {
			t.Errorf("%s: age = %v (%q), want no age with %q", tc.name, age, why, tc.want)
		}
	}
	if age, why := s.Inspect(ip, gen, start.Add(30*time.Second)).Age(start.Add(30 * time.Second)); why != AgeReported || age != 30*time.Second {
		t.Errorf("fresh: age = %v (%q), want 30s", age, why)
	}
}

// TestObservationInstantFollowsTheObservationThatSuppliedTheEntry proves a stored
// entry's instant belongs to the observation that supplied its decision and
// deadline, across every merge outcome.
func TestObservationInstantFollowsTheObservationThatSuppliedTheEntry(t *testing.T) {
	ip := netip.MustParseAddr("198.51.201.40")
	t0 := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(20 * time.Second)

	cases := []struct {
		name      string
		firstD    Decision
		firstTTL  time.Duration
		secondD   Decision
		secondTTL time.Duration
		wantAt    time.Time
		wantD     Decision
	}{
		{"direct refreshed with a later deadline", Direct, time.Minute, Direct, 5 * time.Minute, t1, Direct},
		{"direct kept when the repeat expires sooner", Direct, 10 * time.Minute, Direct, time.Minute, t0, Direct},
		{"proxy replaces direct", Direct, 10 * time.Minute, Proxy, time.Minute, t1, Proxy},
		{"direct never displaces proxy", Proxy, 10 * time.Minute, Direct, 20 * time.Minute, t0, Proxy},
		{"proxy refreshed with a later deadline", Proxy, time.Minute, Proxy, 5 * time.Minute, t1, Proxy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, gen, _ := ageFixture(t)
			observeAt(t, s, gen, ip.String(), tc.firstD, t0, tc.firstTTL)
			observeAt(t, s, gen, ip.String(), tc.secondD, t1, tc.secondTTL)
			got := s.Inspect(ip, gen, t1)
			if got.Decision != tc.wantD || !got.ObservedAt.Equal(tc.wantAt) {
				t.Fatalf("evidence = %v observed %v, want %v observed %v",
					got.Decision, got.ObservedAt, tc.wantD, tc.wantAt)
			}
		})
	}
}
