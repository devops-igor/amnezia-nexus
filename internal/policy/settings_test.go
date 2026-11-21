package policy

import (
	"encoding/json"
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
	if cfg.ForceShrink {
		t.Error("ForceShrink = true; a shrunk rule set must fail rather than replace a valid policy")
	}
	wantParse := DefaultParseLimits()
	if cfg.ParseLimits != wantParse {
		t.Errorf("ParseLimits = %+v, want production defaults %+v", cfg.ParseLimits, wantParse)
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
func TestSettingsLoadsTheLegacyExceptionKey(t *testing.T) {
	const stored = `{"enabled":true,"local_entries":["203.0.113.0/24"],"sync_interval_seconds":3600}`

	var decoded Settings
	if err := json.Unmarshal([]byte(stored), &decoded); err != nil {
		t.Fatalf("a stored record from an earlier build must still load: %v", err)
	}
	if len(decoded.ProxyExceptions) != 1 || decoded.ProxyExceptions[0] != "203.0.113.0/24" {
		t.Fatalf("loaded exceptions = %v, want the stored entry", decoded.ProxyExceptions)
	}

	// A record carrying both keys is read from the current one.
	const both = `{"proxy_exceptions":["198.51.100.0/24"],"local_entries":["203.0.113.0/24"]}`
	if err := json.Unmarshal([]byte(both), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.ProxyExceptions) != 1 || decoded.ProxyExceptions[0] != "198.51.100.0/24" {
		t.Fatalf("a record carrying both keys read %v, want the current field", decoded.ProxyExceptions)
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

	// The dropped content is reported, not silently discarded.
	var legacyRecord legacySettings
	if err := json.Unmarshal([]byte(legacy), &legacyRecord); err != nil {
		t.Fatalf("unmarshal legacy shape: %v", err)
	}
	dropped := migrateLegacyRecord(legacyRecord)
	if len(dropped) != 3 {
		t.Fatalf("migration report = %v, want 3 dropped items (selection, custom URLs, exclusions)", dropped)
	}
	joined := strings.Join(dropped, "; ")
	for _, want := range []string{"aggregate", "custom list URL", "excluded domain"} {
		if !strings.Contains(joined, want) {
			t.Errorf("migration report %q does not mention %q", joined, want)
		}
	}
}

// A legacy record with nothing but operator addresses reports nothing dropped,
// so the ordinary upgrade path carries no alarming notice.
func TestLegacyRecordWithOnlyExceptionsReportsNoLoss(t *testing.T) {
	legacyRecord := legacySettings{
		Enabled:      true,
		LocalEntries: []string{"203.0.113.0/24"},
	}
	if dropped := migrateLegacyRecord(legacyRecord); len(dropped) != 0 {
		t.Fatalf("migration report = %v, want none", dropped)
	}
}
