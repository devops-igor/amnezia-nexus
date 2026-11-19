package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// The persisted operator override (issue #920) closes the gap #919 left: the
// library type existed with precedence and validation but no settings record
// supplied it, so nothing an operator did could reach the classifier. These
// assertions pin the record's own contract, at the boundary the API validates:
//
//   - a valid body is stored and parses to the same set the classifier will use;
//   - an invalid body is refused, so it can never be persisted as an override
//     that silently applies nothing;
//   - an absent body means "the shipped set alone", not an empty override.

func settingsWithOverride(t *testing.T, entries ...string) Settings {
	t.Helper()
	settings := Settings{
		Preset:            PresetAggregate,
		SyncInterval:      int64(DefaultSyncInterval.Seconds()),
		InventoryOverride: entries,
	}
	return settings
}

func TestSettingsAcceptsAValidInventoryOverride(t *testing.T) {
	settings := settingsWithOverride(t, "203.0.113.0/24", "198.51.100.0/24")

	if err := settings.Validate(); err != nil {
		t.Fatalf("a valid inventory override was rejected: %v", err)
	}

	override, err := settings.ParsedInventoryOverride()
	if err != nil {
		t.Fatalf("ParsedInventoryOverride: %v", err)
	}
	if override == nil || override.PrefixCount() != 2 {
		t.Fatalf("parsed override = %+v, want two prefixes", override)
	}

	// The record survives the settings-table JSON round trip, so a restart
	// activates the same override the operator saved.
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	var decoded Settings
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if len(decoded.InventoryOverride) != 2 || decoded.InventoryOverride[1] != "198.51.100.0/24" {
		t.Fatalf("decoded override = %v, want the saved entries", decoded.InventoryOverride)
	}
	if !strings.Contains(string(encoded), `"inventory_override"`) {
		t.Fatalf("encoded record does not name the override field: %s", encoded)
	}
}

// An override that cannot be applied must be refused where it is written. A
// stored override that parses to nothing would look configured while changing no
// routing decision, which is the failure this record exists to prevent.
func TestSettingsRejectsAnUnusableInventoryOverride(t *testing.T) {
	cases := map[string][]string{
		"no_prefix_only_domains": {"example.com", "example.org"},
		"mistyped_address":       {"203.0.113.0/24", "203.0.113.999"},
		"bare_token":             {"not-a-prefix"},
		"ipv6_only":              {"2001:db8::/32"},
		"markup_document":        {"<html><body>blocked</body></html>"},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			settings := settingsWithOverride(t, entries...)
			err := settings.Validate()
			if err == nil {
				t.Fatalf("Settings.Validate accepted the override %v", entries)
			}
			if !strings.Contains(err.Error(), "inventory override") {
				t.Fatalf("refusal does not name the inventory override: %v", err)
			}
		})
	}

	tooMany := make([]string, MaxInventoryOverrideEntries+1)
	for i := range tooMany {
		tooMany[i] = "203.0.113.0/24"
	}
	if err := settingsWithOverride(t, tooMany...).Validate(); err == nil {
		t.Fatal("Settings.Validate accepted an override past the entry cap")
	}
}

// An absent override is the shipped-set-only state. It must not be reported as
// an empty override, because a consumer that treats the two as equal cannot tell
// "nothing configured" from "configured to override nothing".
func TestSettingsAbsentInventoryOverrideMeansShippedSetOnly(t *testing.T) {
	settings := Settings{Preset: PresetAggregate, SyncInterval: int64(DefaultSyncInterval.Seconds())}
	if err := settings.Validate(); err != nil {
		t.Fatalf("settings without an override were rejected: %v", err)
	}
	override, err := settings.ParsedInventoryOverride()
	if err != nil {
		t.Fatalf("ParsedInventoryOverride on an absent override: %v", err)
	}
	if override != nil {
		t.Fatalf("absent override parsed as %+v, want nil", override)
	}

	explicitEmpty := settings
	explicitEmpty.InventoryOverride = []string{}
	override, err = explicitEmpty.ParsedInventoryOverride()
	if err != nil {
		t.Fatalf("ParsedInventoryOverride on an empty override: %v", err)
	}
	if override != nil {
		t.Fatalf("empty override parsed as %+v, want nil (shipped set only)", override)
	}
}

// Normalize must hand back an owned copy: a caller mutating the returned record
// cannot change the override another reader is holding.
func TestSettingsNormalizeCopiesTheInventoryOverride(t *testing.T) {
	original := settingsWithOverride(t, "203.0.113.0/24")
	normalized := original.Normalize()
	normalized.InventoryOverride[0] = "192.0.2.0/24"
	if original.InventoryOverride[0] != "203.0.113.0/24" {
		t.Fatalf("Normalize shared the override slice: original = %v", original.InventoryOverride)
	}
}
