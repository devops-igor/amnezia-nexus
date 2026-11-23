package policy

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// The default record must leave an existing install on the old all-proxy route:
// acceptance bullet 1 of issue #678. Disabled, no exceptions, default interval.
// No migration or default settings row is involved.
func TestDefaultSettingsIsDisabled(t *testing.T) {
	got := DefaultSettings()
	if got.Enabled {
		t.Error("DefaultSettings().Enabled = true, want false (all-proxy default)")
	}
	if len(got.ProxyExceptions) != 0 {
		t.Errorf("DefaultSettings().ProxyExceptions = %v, want none", got.ProxyExceptions)
	}
	if len(got.InventoryOverride) != 0 {
		t.Errorf("DefaultSettings().InventoryOverride = %v, want none", got.InventoryOverride)
	}
	if got.Interval() != DefaultSyncInterval {
		t.Errorf("DefaultSettings().Interval() = %v, want %v", got.Interval(), DefaultSyncInterval)
	}
}

// An absent settings row deserializes into the zero value. That zero value must
// itself remain disabled, so an install upgraded without any settings change
// cannot switch routing modes.
func TestZeroValueSettingsIsDisabled(t *testing.T) {
	var zero Settings
	if zero.Enabled {
		t.Error("zero Settings.Enabled = true, want false")
	}

	var decoded Settings
	if err := json.Unmarshal([]byte("null"), &decoded); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if decoded.Enabled {
		t.Error("Settings decoded from null is enabled, want disabled")
	}
}

func TestNormalizeFillsDefaultIntervalOnly(t *testing.T) {
	got := Settings{}.Normalize()
	if got.Interval() != DefaultSyncInterval {
		t.Errorf("Normalize() interval = %v, want %v", got.Interval(), DefaultSyncInterval)
	}
	if len(got.ProxyExceptions) != 0 {
		t.Errorf("Normalize() invented exceptions %v; the list must stay an operator action", got.ProxyExceptions)
	}

	// An explicit interval must survive normalization untouched.
	explicit := Settings{SyncInterval: int64(2 * time.Hour / time.Second)}
	if n := explicit.Normalize(); n.Interval() != 2*time.Hour {
		t.Errorf("Normalize() interval = %v, want 2h", n.Interval())
	}
}

func TestNormalizeCopiesProxyExceptions(t *testing.T) {
	original := Settings{ProxyExceptions: []string{"203.0.113.0/24"}}
	normalized := original.Normalize()

	normalized.ProxyExceptions[0] = "192.0.2.0/24"
	if original.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatal("Normalize() shares the ProxyExceptions backing array with its input")
	}
}

// The exception list is the one operator control, so its accepted shape is
// pinned directly: addresses, prefix lines, comments and blank lines.
func TestValidateAcceptsProxyExceptionShapes(t *testing.T) {
	s := DefaultSettings()
	s.ProxyExceptions = []string{
		"# operator PROXY exceptions",
		"203.0.113.7",
		"198.51.100.0/24",
		"",
		"! ignore me too",
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	prefixes, err := s.ProxyExceptionPrefixes()
	if err != nil {
		t.Fatalf("ProxyExceptionPrefixes() = %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("parsed %d prefixes, want 2", len(prefixes))
	}
	// A bare address becomes a /32 so the packet path matches it exactly.
	if got := prefixes[0].String(); got != "203.0.113.7/32" {
		t.Errorf("first prefix = %q, want 203.0.113.7/32", got)
	}
	if got := prefixes[1].String(); got != "198.51.100.0/24" {
		t.Errorf("second prefix = %q, want 198.51.100.0/24", got)
	}
}

// A source-less record is the shipped shape: the classifier is the policy
// authority and the operator contributes address exceptions locally, so nothing
// is fetched. This is what the settings page offers, so it must be accepted.
func TestValidateAcceptsNoSourceSelection(t *testing.T) {
	s := DefaultSettings()
	s.Enabled = true
	s.ProxyExceptions = []string{"203.0.113.0/24"}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a local-only record", err)
	}
	cfg, err := s.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 1 {
		t.Fatalf("SyncConfig local prefixes = %d, want 1", len(cfg.LocalRules.CIDRs))
	}
	if _, err := NewSyncer(NewMatcher(), NewFileStore(t.TempDir()), cfg); err != nil {
		t.Fatalf("NewSyncer rejected the derived configuration: %v", err)
	}
}

// An empty record is valid: enabling it is a runtime decision made by the VPN
// layer, which refuses with the operator-facing empty-policy error. Validation
// must not pretend to decide that.
func TestValidateAcceptsEmptyRecord(t *testing.T) {
	s := DefaultSettings()
	s.Enabled = true
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v; enablement is gated by the VPN layer", err)
	}
	cfg, err := s.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 0 {
		t.Fatalf("empty record derived %d prefixes", len(cfg.LocalRules.CIDRs))
	}
}

// Each rejection is asserted on the reason, not merely on a non-nil error: a
// case that starts failing for an unrelated reason must break this test rather
// than silently keep passing.
func TestValidateRejectsBadInput(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Settings)
		wantSub string
	}{
		{
			// A domain line would be saved and never applied, because the packet
			// path matches addresses only. It is refused by name.
			name:    "domain line in the exception list",
			mutate:  func(s *Settings) { s.ProxyExceptions = []string{"example.com"} },
			wantSub: "proxy exception rejected",
		},
		{
			name:    "wildcard in the exception list",
			mutate:  func(s *Settings) { s.ProxyExceptions = []string{"*.example.org"} },
			wantSub: "proxy exception rejected",
		},
		{
			name:    "mistyped address in the exception list",
			mutate:  func(s *Settings) { s.ProxyExceptions = []string{"203.0.113.999"} },
			wantSub: "proxy exception rejected",
		},
		{
			name:    "IPv6 in the exception list",
			mutate:  func(s *Settings) { s.ProxyExceptions = []string{"2001:db8::/32"} },
			wantSub: "proxy exception rejected",
		},
		{
			name:    "interval below minimum",
			mutate:  func(s *Settings) { s.SyncInterval = int64(MinSyncInterval/time.Second) - 1 },
			wantSub: "shorter than the minimum",
		},
		{
			name:    "negative interval",
			mutate:  func(s *Settings) { s.SyncInterval = -1 },
			wantSub: "shorter than the minimum",
		},
		{
			name:    "interval above maximum",
			mutate:  func(s *Settings) { s.SyncInterval = int64(MaxSyncInterval/time.Second) + 1 },
			wantSub: "longer than the maximum",
		},
		{
			name: "too many exception lines",
			mutate: func(s *Settings) {
				entries := make([]string, 0, MaxLocalExceptions+1)
				for i := 0; i <= MaxLocalExceptions; i++ {
					entries = append(entries, "203.0.113.0/24")
				}
				s.ProxyExceptions = entries
			},
			wantSub: "exceed the maximum",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := DefaultSettings()
			tc.mutate(&s)

			err := s.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want rejection")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Validate() error = %q, want it to mention %q", err, tc.wantSub)
			}

			// A rejected record must also refuse to produce a sync configuration,
			// so a handler cannot persist-then-derive around the validation gate.
			if cfg, cfgErr := s.SyncConfig(); cfgErr == nil {
				t.Errorf("SyncConfig() succeeded for invalid settings: %+v", cfg)
			}
		})
	}
}

func TestValidateIntervalBoundariesAccepted(t *testing.T) {
	for _, interval := range []time.Duration{MinSyncInterval, MaxSyncInterval} {
		t.Run(interval.String(), func(t *testing.T) {
			s := DefaultSettings()
			s.ProxyExceptions = []string{"203.0.113.0/24"}
			s.SyncInterval = int64(interval / time.Second)
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil at boundary %v", err, interval)
			}
		})
	}
}

// Disabled with a configured exception list must be allowed: an operator has to
// be able to prepare the list before turning PBR on. Enablement itself is gated
// at runtime by the VPN layer, not by this record.
func TestValidateAllowsDisabledWithConfiguredExceptions(t *testing.T) {
	s := DefaultSettings()
	s.Enabled = false
	s.ProxyExceptions = []string{"203.0.113.0/24"}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for disabled-but-configured", err)
	}
}

// A shorter exception list is a deliberate operator edit, not a suspicious
// download. The derived configuration therefore carries no truncation guard, and
// the cycle's only count-based refusal is the zero-rule one.
func TestSyncConfigUsesProductionBounds(t *testing.T) {
	s := DefaultSettings()
	s.ProxyExceptions = []string{"203.0.113.0/24"}
	s.SyncInterval = int64(3 * time.Hour / time.Second)

	cfg, err := s.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if cfg.RefreshInterval != 3*time.Hour {
		t.Errorf("RefreshInterval = %v, want 3h", cfg.RefreshInterval)
	}
	wantParse := DefaultParseLimits()
	if cfg.ParseLimits != wantParse {
		t.Errorf("ParseLimits = %+v, want production defaults %+v", cfg.ParseLimits, wantParse)
	}
}

// A valid reduction of the operator's own list must reach the matcher, and so
// must the shortest reduction there is — an empty list.
//
// The exception list is an override over the destination classifier, not the
// routing authority, so "no overrides" is a valid configuration and the cycle
// publishes it. The zero-rule refusal this test used to assert has moved to the
// place that can actually distinguish the two states: activation, which refuses
// when the classifier is absent (vpn.ValidatePBRPrerequisites /
// ensureInitialSnapshot). That negative direction is asserted there; here it is
// asserted that the cycle has no count-based refusal left, because a cycle that
// refused an empty list would keep the operator's clear from taking effect.
func TestSyncerAcceptsExplicitShrinkAndStillRefusesZeroRules(t *testing.T) {
	store := NewFileStore(t.TempDir())
	matcher := NewMatcher()

	publish := func(t *testing.T, entries ...string) (SyncResult, error) {
		t.Helper()
		settings := DefaultSettings()
		settings.Enabled = true
		settings.ProxyExceptions = entries
		cfg, err := settings.SyncConfig()
		if err != nil {
			t.Fatalf("SyncConfig(%v) = %v", entries, err)
		}
		syncer, err := NewSyncer(matcher, store, cfg)
		if err != nil {
			t.Fatalf("NewSyncer: %v", err)
		}
		return syncer.SyncOnce(context.Background())
	}

	// Four distinct exceptions activate.
	if _, err := publish(t, "198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"); err != nil {
		t.Fatalf("four-entry activation: %v", err)
	}
	if got := matcher.Current().CIDRCount(); got != 4 {
		t.Fatalf("published count = %d, want 4", got)
	}

	// Removing three of the four is the ordinary edit this list exists for. It must
	// publish, not be refused as a truncated download.
	res, err := publish(t, "198.51.100.1")
	if err != nil {
		t.Fatalf("a valid reduction to one exception must publish: %v", err)
	}
	if !res.Published {
		t.Fatal("the reduction published nothing")
	}
	if got := matcher.Current(); got.CIDRCount() != 1 || !got.MatchIPv4(netip.MustParseAddr("198.51.100.1")) {
		t.Fatalf("after the reduction the matcher holds %d prefixes and match(198.51.100.1)=%t, want 1 and true",
			got.CIDRCount(), got.MatchIPv4(netip.MustParseAddr("198.51.100.1")))
	}
	// The removed prefixes are gone from the live policy, which is the point of the
	// edit: they return to the classifier instead of staying forced through PROXY.
	for _, removed := range []string{"198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		if matcher.Current().MatchIPv4(netip.MustParseAddr(removed)) {
			t.Errorf("removed exception %s still matches after the reduction", removed)
		}
	}

	// The shortest reduction — clearing the list entirely — is the operator's
	// deliberate edit too, and it must publish an empty snapshot rather than be
	// refused. Every destination then takes the classifier's answer, which is the
	// configuration a default install runs.
	emptyRes, err := publish(t)
	if err != nil {
		t.Fatalf("an empty exception list must publish; the routing authority is the classifier, "+
			"so zero overrides is a valid policy: %v", err)
	}
	if !emptyRes.Published {
		t.Fatal("the empty list published nothing")
	}
	if got := matcher.Current().CIDRCount(); got != 0 {
		t.Fatalf("published count after clearing = %d, want 0", got)
	}
	if matcher.Current().MatchIPv4(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("a cleared exception still matches; the operator's clear did not take effect")
	}
}

// Duplicate and reordered declarations describe the same rule set, and the
// derived configuration must say so: neither may look like a new policy.
func TestSyncConfigCollapsesDuplicateExceptions(t *testing.T) {
	s := DefaultSettings()
	s.ProxyExceptions = []string{"203.0.113.0/24", "203.0.113.9/24", "198.51.100.0/24"}
	cfg, err := s.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 2 {
		t.Fatalf("prefixes = %d, want 2 after collapsing the duplicate /24", len(cfg.LocalRules.CIDRs))
	}
}

func TestSettingsJSONRoundTrip(t *testing.T) {
	original := Settings{
		Enabled:         true,
		ProxyExceptions: []string{"203.0.113.0/24"},
		SyncInterval:    int64(90 * time.Minute / time.Second),
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Settings
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Enabled != original.Enabled {
		t.Errorf("Enabled = %v, want %v", decoded.Enabled, original.Enabled)
	}
	if len(decoded.ProxyExceptions) != 1 || decoded.ProxyExceptions[0] != original.ProxyExceptions[0] {
		t.Errorf("ProxyExceptions = %v, want %v", decoded.ProxyExceptions, original.ProxyExceptions)
	}
	if decoded.SyncInterval != original.SyncInterval {
		t.Errorf("SyncInterval = %d, want %d", decoded.SyncInterval, original.SyncInterval)
	}
	if err := decoded.Validate(); err != nil {
		t.Errorf("round-tripped record failed validation: %v", err)
	}
}

// Field names are the wire contract for both the settings row and the admin API.
//
// The exception list serializes under its current name. The load path accepts the
// old "local_entries" key as well, which the migration case below asserts.
func TestSettingsJSONFieldNames(t *testing.T) {
	encoded, err := json.Marshal(Settings{ProxyExceptions: []string{"203.0.113.0/24"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, field := range []string{"enabled", "proxy_exceptions", "sync_interval_seconds"} {
		if _, ok := asMap[field]; !ok {
			t.Errorf("expected JSON field %q missing from %s", field, encoded)
		}
	}
	for _, removed := range []string{"preset", "custom_urls", "excluded_domains", "local_entries"} {
		if _, ok := asMap[removed]; ok {
			t.Errorf("record still serializes %q: %s", removed, encoded)
		}
	}
}

// A record written by an earlier build carries the operator's addresses under
// "local_entries". The rename must read them, or an upgrade would silently discard
// a configuration the operator saved.
//
// This is a stored-record case, so it uses the migration reader. The wire reader
// accepts the same key for an already-open predecessor client, which the handler
// tests cover; the two readers are deliberately not interchangeable.
func TestDecodeStoredRecordLoadsTheLegacyExceptionKey(t *testing.T) {
	const stored = `{"enabled":true,"local_entries":["203.0.113.0/24"],"sync_interval_seconds":3600}`

	decoded, err := DecodeStoredRecord([]byte(stored))
	if err != nil {
		t.Fatalf("a stored record from an earlier build must still load: %v", err)
	}
	if len(decoded.ProxyExceptions) != 1 || decoded.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatalf("loaded exceptions = %v, want the stored entry", decoded.ProxyExceptions)
	}

	// A record carrying both keys is read from the current one.
	const both = `{"proxy_exceptions":["198.51.100.0/24"],"local_entries":["203.0.113.0/24"]}`
	stored2, err := DecodeStoredRecord([]byte(both))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(stored2.ProxyExceptions) != 1 || stored2.ProxyExceptions[0] != "198.51.100.0/24" {
		t.Fatalf("a record carrying both keys read %v, want the current field", stored2.ProxyExceptions)
	}
}

// An explicitly empty current list is operator intent, and the decoder must not
// turn it into "the key was absent" and substitute the predecessor list. The
// consequence is not cosmetic: the handler treats a nil list as an omission and
// merges the stored entries back, so clearing the only exception textarea answered
// 200 while the old overrides stayed installed.
//
// Each case names the decoded list AND its nilness, because only the nilness
// distinguishes "the operator cleared this" from "there was nothing to read" for
// every consumer downstream of the decoder.
func TestSettingsDecodeSeparatesEmptyListFromAbsentKey(t *testing.T) {
	cases := []struct {
		name     string
		stored   string
		wantList []string
		wantNil  bool
	}{
		{
			name:     "explicit_empty_current_key",
			stored:   `{"enabled":true,"proxy_exceptions":[],"sync_interval_seconds":3600}`,
			wantList: []string{},
			wantNil:  false,
		},
		{
			name:     "absent_current_key_falls_back",
			stored:   `{"enabled":true,"local_entries":["203.0.113.0/24"],"sync_interval_seconds":3600}`,
			wantList: []string{"203.0.113.0/24"},
			wantNil:  false,
		},
		{
			name:     "null_current_key_falls_back_to_predecessor",
			stored:   `{"enabled":true,"proxy_exceptions":null,"local_entries":["203.0.113.0/24"],"sync_interval_seconds":3600}`,
			wantList: []string{"203.0.113.0/24"},
			wantNil:  false,
		},
		{
			name:     "both_keys_read_current",
			stored:   `{"proxy_exceptions":[],"local_entries":["203.0.113.0/24"],"sync_interval_seconds":3600}`,
			wantList: []string{},
			wantNil:  false,
		},
		{
			name:     "no_list_key_at_all",
			stored:   `{"enabled":true,"sync_interval_seconds":3600}`,
			wantList: nil,
			wantNil:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var decoded Settings
			if err := json.Unmarshal([]byte(tc.stored), &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := decoded.ProxyExceptions == nil; got != tc.wantNil {
				t.Fatalf("ProxyExceptions nil = %t, want %t; the decoder must preserve the difference "+
					"between an empty list the operator saved and no list at all", got, tc.wantNil)
			}
			if !slices.Equal(decoded.ProxyExceptions, tc.wantList) {
				t.Fatalf("ProxyExceptions = %v, want %v", decoded.ProxyExceptions, tc.wantList)
			}
			// An explicit empty record must survive Normalize unchanged: that is the
			// value the handler's merge step reads as a deliberate removal.
			if !tc.wantNil && len(tc.wantList) == 0 && decoded.Normalize().ProxyExceptions == nil {
				t.Error("Normalize turned an explicit empty list into nil")
			}
		})
	}
}

// A JSON body whose current key is the only list and holds an empty array must
// validate and derive zero prefixes rather than erroring, so the clear reaches the
// runtime guards instead of being rejected as malformed.
func TestSettingsExplicitEmptyListValidates(t *testing.T) {
	const stored = `{"enabled":true,"proxy_exceptions":[],"sync_interval_seconds":3600}`
	var decoded Settings
	if err := json.Unmarshal([]byte(stored), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("an explicit empty list must be a valid record (the runtime owns the refusal): %v", err)
	}
	cfg, err := decoded.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 0 {
		t.Fatalf("derived %d prefixes from an empty list, want 0", len(cfg.LocalRules.CIDRs))
	}
}

// A predecessor record's exception list accepted domain lines beside prefixes.
// Those lines cannot be applied by this build, and copying them into an IPv4-only
// field made whole-record validation reject the record — which took the operator's
// working IPv4 policy down with an inert domain entry.
//
// The MIGRATION reader therefore keeps the prefixes and separates the rest. Both
// halves are asserted, so a fix that silently dropped the whole list would fail
// just as loudly as one that copied it through.
//
// The same bytes through the WIRE reader keep the domain line, because a request is
// refused whole rather than shortened. That pairing is the point of the next test;
// this one pins the stored-record half.
func TestDecodeStoredRecordKeepsIPv4AndRetiresDomains(t *testing.T) {
	const stored = `{"enabled":true,"preset":"aggregate",` +
		`"local_entries":["198.51.100.0/24","example.com","203.0.113.7"],` +
		`"sync_interval_seconds":3600}`

	decoded, err := DecodeStoredRecord([]byte(stored))
	if err != nil {
		t.Fatalf("a predecessor record with a mixed list must still load: %v", err)
	}
	want := []string{"198.51.100.0/24", "203.0.113.7"}
	if !slices.Equal(decoded.ProxyExceptions, want) {
		t.Fatalf("loaded exceptions = %v, want only the IPv4 entries %v", decoded.ProxyExceptions, want)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("the record must be usable so the operator keeps their IPv4 policy: %v", err)
	}
	cfg, err := decoded.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if len(cfg.LocalRules.CIDRs) != 2 {
		t.Fatalf("derived %d prefixes, want the 2 surviving IPv4 entries", len(cfg.LocalRules.CIDRs))
	}

	// The retired content is reported from the same stored bytes, so the surface
	// that shows the record can explain the shorter list.
	retirement := ReviewStoredRecord([]byte(stored))
	if !slices.Equal(retirement.NonIPv4Entries, []string{"example.com"}) {
		t.Fatalf("retired entries = %v, want [example.com]", retirement.NonIPv4Entries)
	}
	if retirement.SourceSelection != "aggregate" {
		t.Errorf("retired source selection = %q, want %q", retirement.SourceSelection, "aggregate")
	}

	// A domain-only predecessor list leaves no usable prefix. The record is then
	// empty for this build, which the runtime's zero-rule guard reports — it is not
	// a validation failure that hides the reason.
	const domainsOnly = `{"enabled":true,"local_entries":["example.com"],"sync_interval_seconds":3600}`
	empty, err := DecodeStoredRecord([]byte(domainsOnly))
	if err != nil {
		t.Fatalf("a domain-only predecessor list must load: %v", err)
	}
	if len(empty.ProxyExceptions) != 0 {
		t.Fatalf("domain-only list kept %v, want nothing applicable", empty.ProxyExceptions)
	}
	if err := empty.Validate(); err != nil {
		t.Fatalf("the empty-for-this-build record must validate; an empty override list is a valid policy: %v", err)
	}
	if got := ReviewStoredRecord([]byte(domainsOnly)).NonIPv4Entries; !slices.Equal(got, []string{"example.com"}) {
		t.Errorf("retired entries for a domain-only list = %v, want [example.com]", got)
	}
}

// The two readers must not be interchangeable, and this is the asymmetry that
// makes the distinction worth having.
//
// Identical bytes holding one unusable entry: the stored-record reader keeps the
// usable prefix and reports the rest, because an earlier build legitimately wrote
// that row and it must still load. The wire reader keeps every submitted line, so
// Validate sees the bad one and refuses the whole request. A single lenient decoder
// serving both is what let a live typo become a shorter valid list.
func TestStoredRecordReaderIsForgivingAndWireReaderIsNot(t *testing.T) {
	const body = `{"enabled":true,"local_entries":["198.51.100.0/24","213.180.192.0/33"],` +
		`"sync_interval_seconds":3600}`

	stored, err := DecodeStoredRecord([]byte(body))
	if err != nil {
		t.Fatalf("the migration reader must load an accepted predecessor row: %v", err)
	}
	if !slices.Equal(stored.ProxyExceptions, []string{"198.51.100.0/24"}) {
		t.Fatalf("migration reader kept %v, want the one usable prefix", stored.ProxyExceptions)
	}
	if retired := ReviewStoredRecord([]byte(body)).NonIPv4Entries; !slices.Equal(retired, []string{"213.180.192.0/33"}) {
		t.Errorf("reported retired entries = %v, want the unusable line named", retired)
	}

	var wire Settings
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		t.Fatalf("the wire reader must decode the submitted body: %v", err)
	}
	if !slices.Equal(wire.ProxyExceptions, []string{"198.51.100.0/24", "213.180.192.0/33"}) {
		t.Fatalf("wire reader produced %v; a submitted entry must not be filtered before validation", wire.ProxyExceptions)
	}
	if err := wire.Validate(); err == nil {
		t.Fatal("the wire reader's output validated; one unusable submitted entry must refuse the whole request")
	}
}

// An explicit empty predecessor list is a deliberate clear, so the migration reader
// must not return nil for it. The handler's merge step reads nil as "the save
// omitted the field" and merges the stored entries back, which would answer 200
// while the old overrides stayed installed.
func TestDecodeStoredRecordKeepsExplicitEmptyLegacyListNonNil(t *testing.T) {
	for _, tc := range []struct{ name, stored string }{
		{name: "predecessor_key", stored: `{"enabled":false,"local_entries":[],"sync_interval_seconds":3600}`},
		{name: "current_key", stored: `{"enabled":false,"proxy_exceptions":[],"sync_interval_seconds":3600}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeStoredRecord([]byte(tc.stored))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.ProxyExceptions == nil {
				t.Fatal("an explicit empty list decoded as nil, which reads as an absent key downstream")
			}
			if len(decoded.ProxyExceptions) != 0 {
				t.Fatalf("empty list decoded as %v", decoded.ProxyExceptions)
			}
		})
	}
}

// A record already written in the current shape retires nothing, so an ordinary
// upgrade and an ordinary save raise no warning.
func TestReviewStoredRecordReportsNothingForCurrentShape(t *testing.T) {
	current := []byte(`{"enabled":true,"proxy_exceptions":["198.51.100.0/24"],"sync_interval_seconds":3600}`)
	if retirement := ReviewStoredRecord(current); !retirement.Empty() {
		t.Fatalf("current-shape record reported a retirement: %+v (%s)", retirement, retirement.Summary())
	}
	prefixOnlyLegacy := []byte(`{"enabled":true,"local_entries":["198.51.100.0/24"],"sync_interval_seconds":3600}`)
	if retirement := ReviewStoredRecord(prefixOnlyLegacy); !retirement.Empty() {
		t.Fatalf("prefix-only predecessor record reported a retirement: %+v", retirement)
	}
	if retirement := ReviewStoredRecord([]byte(`not json`)); !retirement.Empty() {
		t.Fatalf("unparsable bytes produced a retirement claim: %+v", retirement)
	}
}

func TestSettingsKeyValue(t *testing.T) {
	// The key is persistence-visible: changing it orphans an operator's saved
	// configuration, so pin it.
	if SettingsKey != "pbr_policy" {
		t.Fatalf("SettingsKey = %q, want %q", SettingsKey, "pbr_policy")
	}
}

// A record written by an earlier build must still load, keep the operator's
// address exceptions, and explain what it could not carry: the source selection
// and the domain half are gone, and silence about that would read as a dropped
// configuration that nobody was told about.
func TestLegacyRecordKeepsExceptionsAndExplainsDroppedFields(t *testing.T) {
	const legacy = `{
		"enabled": true,
		"preset": "aggregate",
		"custom_urls": ["https://lists.example/a.lst"],
		"local_entries": ["203.0.113.0/24", "198.51.100.7"],
		"excluded_domains": ["bank.example"],
		"sync_interval_seconds": 21600
	}`

	var decoded Settings
	if err := json.Unmarshal([]byte(legacy), &decoded); err != nil {
		t.Fatalf("a stored record from an earlier build must still load: %v", err)
	}
	if !decoded.Enabled {
		t.Error("the enabled flag from the stored record did not survive the load")
	}
	if len(decoded.ProxyExceptions) != 2 {
		t.Fatalf("operator addresses = %v, want the 2 stored entries; a rename must not drop them", decoded.ProxyExceptions)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("the migrated record is not usable: %v", err)
	}
	prefixes, err := decoded.ProxyExceptionPrefixes()
	if err != nil {
		t.Fatalf("ProxyExceptionPrefixes: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("parsed %d prefixes, want 2", len(prefixes))
	}

	// The dropped content is reported, not silently discarded, and it is reported
	// from the stored bytes by the reader the production surfaces use.
	retirement := ReviewStoredRecord([]byte(legacy))
	if retirement.SourceSelection != "aggregate" {
		t.Errorf("retirement source selection = %q, want %q", retirement.SourceSelection, "aggregate")
	}
	if retirement.CustomURLCount != 1 {
		t.Errorf("retirement custom URL count = %d, want 1", retirement.CustomURLCount)
	}
	if retirement.ExcludedDomainCount != 1 {
		t.Errorf("retirement excluded domain count = %d, want 1", retirement.ExcludedDomainCount)
	}
	if len(retirement.NonIPv4Entries) != 0 {
		t.Errorf("a prefix-only exception list retired %v, want nothing", retirement.NonIPv4Entries)
	}
	joined := retirement.Summary()
	for _, want := range []string{"aggregate", "custom list URL", "excluded domain"} {
		if !strings.Contains(joined, want) {
			t.Errorf("retirement summary %q does not mention %q", joined, want)
		}
	}
}

// A legacy record with nothing but operator addresses reports nothing dropped,
// so the ordinary upgrade path carries no alarming notice.
func TestLegacyRecordWithOnlyExceptionsReportsNoLoss(t *testing.T) {
	const prefixOnly = `{"enabled":true,"local_entries":["203.0.113.0/24"]}`
	if retirement := ReviewStoredRecord([]byte(prefixOnly)); !retirement.Empty() {
		t.Fatalf("migration report = %+v, want none", retirement)
	}
}
