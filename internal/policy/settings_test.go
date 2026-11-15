package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The default record must leave an existing install on the old all-proxy route:
// acceptance bullet 1 of issue #678. Disabled, no invented preset, default
// interval. No migration or default settings row is involved.
func TestDefaultSettingsIsDisabled(t *testing.T) {
	got := DefaultSettings()
	if got.Enabled {
		t.Error("DefaultSettings().Enabled = true, want false (all-proxy default)")
	}
	if got.Preset != "" {
		t.Errorf("DefaultSettings().Preset = %q, want empty (no implied source)", got.Preset)
	}
	if len(got.CustomURLs) != 0 {
		t.Errorf("DefaultSettings().CustomURLs = %v, want none", got.CustomURLs)
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
	if got.Preset != "" {
		t.Errorf("Normalize() invented preset %q; selecting a source must stay an operator action", got.Preset)
	}

	// An explicit interval must survive normalization untouched.
	explicit := Settings{SyncInterval: int64(2 * time.Hour / time.Second)}
	if n := explicit.Normalize(); n.Interval() != 2*time.Hour {
		t.Errorf("Normalize() interval = %v, want 2h", n.Interval())
	}
}

func TestNormalizeCopiesCustomURLs(t *testing.T) {
	original := Settings{CustomURLs: []string{"https://lists.example/domains.lst"}}
	normalized := original.Normalize()

	normalized.CustomURLs[0] = "https://mutated.example/x.lst"
	if original.CustomURLs[0] != "https://lists.example/domains.lst" {
		t.Fatal("Normalize() shares the CustomURLs backing array with its input")
	}
}

func TestValidateAcceptsEachBuiltinPreset(t *testing.T) {
	for _, p := range Presets() {
		t.Run(string(p.ID), func(t *testing.T) {
			s := DefaultSettings()
			s.Preset = p.ID
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate() for preset %q = %v, want nil", p.ID, err)
			}
			sources, err := s.Sources()
			if err != nil {
				t.Fatalf("Sources() for preset %q = %v", p.ID, err)
			}
			if len(sources) != 1 {
				t.Fatalf("Sources() for preset %q returned %d sources, want 1", p.ID, len(sources))
			}
			if sources[0].URL != p.URL {
				t.Errorf("source URL = %q, want %q", sources[0].URL, p.URL)
			}
			if !sources[0].IsPreset {
				t.Error("built-in preset source not flagged IsPreset")
			}
			if sources[0].ID != string(p.ID) {
				t.Errorf("source ID = %q, want %q", sources[0].ID, p.ID)
			}
		})
	}
}

func TestValidateAcceptsCustomURLs(t *testing.T) {
	s := DefaultSettings()
	s.Preset = PresetCustom
	s.CustomURLs = []string{
		"https://antifilter.download/list/subnet.lst",
		"https://lists.example/extra.lst",
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	sources, err := s.Sources()
	if err != nil {
		t.Fatalf("Sources() = %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("len(Sources()) = %d, want 2", len(sources))
	}
	for i, src := range sources {
		if src.IsPreset {
			t.Errorf("custom source %d flagged IsPreset; a custom list is strictly parsed", i)
		}
		if src.Format != FormatMixed {
			t.Errorf("custom source %d Format = %v, want %v", i, src.Format, FormatMixed)
		}
	}
	if sources[0].URL != "https://antifilter.download/list/subnet.lst" {
		t.Errorf("custom source order not preserved: first = %q", sources[0].URL)
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
			name:    "no preset selected",
			mutate:  func(s *Settings) { s.Preset = "" },
			wantSub: "preset must be selected",
		},
		{
			name:    "unknown preset",
			mutate:  func(s *Settings) { s.Preset = "russia_outside" },
			wantSub: `unknown policy preset "russia_outside"`,
		},
		{
			name:    "custom preset without URLs",
			mutate:  func(s *Settings) { s.Preset = PresetCustom },
			wantSub: "requires at least one custom URL",
		},
		{
			name: "builtin preset mixed with custom URLs",
			mutate: func(s *Settings) {
				s.Preset = PresetGeoblock
				s.CustomURLs = []string{"https://lists.example/extra.lst"}
			},
			wantSub: "cannot be combined with custom URLs",
		},
		{
			name: "http custom URL",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"http://lists.example/plain.lst"}
			},
			wantSub: "only https scheme is permitted",
		},
		{
			name: "private SSRF target",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"https://10.0.0.5/list.lst"}
			},
			wantSub: "prohibited network range",
		},
		{
			name: "cloud metadata SSRF target",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"https://169.254.169.254/latest/meta-data/"}
			},
			wantSub: "special-use address",
		},
		{
			name: "loopback SSRF target",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"https://127.0.0.1/list.lst"}
			},
			wantSub: "special-use address",
		},
		{
			name: "nonstandard port",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"https://lists.example:8443/list.lst"}
			},
			wantSub: "only port 443 is permitted",
		},
		{
			name: "URL with credentials",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"https://user:pass@lists.example/list.lst"}
			},
			wantSub: "userinfo in URL is not permitted",
		},
		{
			name: "single-label host",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{"https://intranet/list.lst"}
			},
			wantSub: "single-label hostname",
		},
		{
			name: "duplicate custom URL",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				s.CustomURLs = []string{
					"https://lists.example/a.lst",
					"https://lists.example/a.lst",
				}
			},
			wantSub: "duplicates an earlier entry",
		},
		{
			name: "interval below minimum",
			mutate: func(s *Settings) {
				s.Preset = PresetGeoblock
				s.SyncInterval = int64(MinSyncInterval/time.Second) - 1
			},
			wantSub: "shorter than the minimum",
		},
		{
			name: "negative interval",
			mutate: func(s *Settings) {
				s.Preset = PresetGeoblock
				s.SyncInterval = -1
			},
			wantSub: "shorter than the minimum",
		},
		{
			name: "interval above maximum",
			mutate: func(s *Settings) {
				s.Preset = PresetGeoblock
				s.SyncInterval = int64(MaxSyncInterval/time.Second) + 1
			},
			wantSub: "longer than the maximum",
		},
		{
			name: "too many custom URLs",
			mutate: func(s *Settings) {
				s.Preset = PresetCustom
				urls := make([]string, 0, MaxCustomURLs+1)
				for i := 0; i <= MaxCustomURLs; i++ {
					urls = append(urls, "https://lists.example/"+string(rune('a'+i))+".lst")
				}
				s.CustomURLs = urls
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

			// A rejected record must also refuse to produce sources or a sync
			// configuration, so a handler cannot persist-then-derive around the
			// validation gate.
			if sources, srcErr := s.Sources(); srcErr == nil {
				t.Errorf("Sources() succeeded for invalid settings: %v", sources)
			}
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
			s.Preset = PresetRussiaInside
			s.SyncInterval = int64(interval / time.Second)
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil at boundary %v", err, interval)
			}
		})
	}
}

// Disabled with a valid source selection must be allowed: an operator has to be
// able to configure and pre-sync before turning PBR on. Enablement itself is
// gated at runtime by the VPN layer, not by this record.
func TestValidateAllowsDisabledWithValidSelection(t *testing.T) {
	s := DefaultSettings()
	s.Enabled = false
	s.Preset = PresetAntifilterDomains
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for disabled-but-configured", err)
	}
}

// The record carries no snapshot or egress state, so its validation must not
// pretend to decide enablement. That guard lives in vpn.ValidatePBRPrerequisites
// / ErrPBREmptyPolicy, which policy cannot import (policy is the lower layer).
func TestValidateDoesNotClaimRuntimePrerequisites(t *testing.T) {
	s := DefaultSettings()
	s.Enabled = true
	s.Preset = PresetGeoblock
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v; runtime prerequisite gating belongs to the VPN layer", err)
	}
}

func TestSyncConfigUsesProductionBounds(t *testing.T) {
	s := DefaultSettings()
	s.Preset = PresetAntifilterIPv4
	s.SyncInterval = int64(3 * time.Hour / time.Second)

	cfg, err := s.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig() = %v", err)
	}
	if cfg.RefreshInterval != 3*time.Hour {
		t.Errorf("RefreshInterval = %v, want 3h", cfg.RefreshInterval)
	}
	if cfg.ForceShrink {
		t.Error("ForceShrink = true; a small download must fail rather than replace a valid policy")
	}
	if len(cfg.Sources) != 1 {
		t.Fatalf("len(Sources) = %d, want 1", len(cfg.Sources))
	}
	wantLimits := DefaultFetchLimits()
	if cfg.FetchLimits != wantLimits {
		t.Errorf("FetchLimits = %+v, want production defaults %+v", cfg.FetchLimits, wantLimits)
	}
	wantParse := DefaultParseLimits()
	if cfg.ParseLimits != wantParse {
		t.Errorf("ParseLimits = %+v, want production defaults %+v", cfg.ParseLimits, wantParse)
	}
}

// The derived configuration must satisfy the Syncer's own constructor rules, so
// a saved record can always build a live syncer without a surprise rejection.
func TestSyncConfigSatisfiesSyncerConstructor(t *testing.T) {
	for _, preset := range Presets() {
		t.Run(string(preset.ID), func(t *testing.T) {
			s := DefaultSettings()
			s.Preset = preset.ID

			cfg, err := s.SyncConfig()
			if err != nil {
				t.Fatalf("SyncConfig() = %v", err)
			}
			if _, err := NewSyncer(NewMatcher(), nil, NewFileStore(t.TempDir()), cfg); err != nil {
				t.Fatalf("NewSyncer rejected a derived configuration: %v", err)
			}
		})
	}
}

func TestSettingsJSONRoundTrip(t *testing.T) {
	original := Settings{
		Enabled:      true,
		Preset:       PresetCustom,
		CustomURLs:   []string{"https://lists.example/a.lst"},
		SyncInterval: int64(90 * time.Minute / time.Second),
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
	if decoded.Preset != original.Preset {
		t.Errorf("Preset = %q, want %q", decoded.Preset, original.Preset)
	}
	if len(decoded.CustomURLs) != 1 || decoded.CustomURLs[0] != original.CustomURLs[0] {
		t.Errorf("CustomURLs = %v, want %v", decoded.CustomURLs, original.CustomURLs)
	}
	if decoded.SyncInterval != original.SyncInterval {
		t.Errorf("SyncInterval = %d, want %d", decoded.SyncInterval, original.SyncInterval)
	}
	if err := decoded.Validate(); err != nil {
		t.Errorf("round-tripped record failed validation: %v", err)
	}
}

// Field names are the wire contract for both the settings row and the admin API.
func TestSettingsJSONFieldNames(t *testing.T) {
	encoded, err := json.Marshal(DefaultSettings())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, field := range []string{"enabled", "preset", "custom_urls", "sync_interval_seconds"} {
		if _, ok := asMap[field]; !ok {
			t.Errorf("expected JSON field %q missing from %s", field, encoded)
		}
	}
}

func TestSettingsKeyValue(t *testing.T) {
	// The key is persistence-visible: changing it orphans an operator's saved
	// configuration, so pin it.
	if SettingsKey != "pbr_policy" {
		t.Fatalf("SettingsKey = %q, want %q", SettingsKey, "pbr_policy")
	}
}
