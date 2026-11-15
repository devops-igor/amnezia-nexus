package policy

import (
	"strings"
	"testing"
)

// Documented source URLs from issue #678 / epic #674. These are contract values:
// an operator selects a preset by name and must reach exactly this URL.
var documentedPresetURLs = map[PresetID]string{
	PresetRussiaInside:      "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
	PresetGeoblock:          "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst",
	PresetAntifilterDomains: "https://antifilter.download/list/domains.lst",
	PresetAntifilterIPv4:    "https://antifilter.download/list/allyouneed.lst",
}

func TestPresetsResolveToDocumentedURLs(t *testing.T) {
	got := Presets()
	if len(got) != len(documentedPresetURLs) {
		t.Fatalf("len(Presets()) = %d, want %d", len(got), len(documentedPresetURLs))
	}

	seen := make(map[PresetID]bool, len(got))
	for _, p := range got {
		if seen[p.ID] {
			t.Errorf("preset %q appears more than once in the catalog", p.ID)
		}
		seen[p.ID] = true

		wantURL, ok := documentedPresetURLs[p.ID]
		if !ok {
			t.Errorf("undocumented preset %q exposed in catalog", p.ID)
			continue
		}
		if p.URL != wantURL {
			t.Errorf("preset %q URL = %q, want %q", p.ID, p.URL, wantURL)
		}
	}

	for id := range documentedPresetURLs {
		if !seen[id] {
			t.Errorf("documented preset %q missing from catalog", id)
		}
	}
}

// Every built-in source must pass the same SSRF/URL gate that operator-supplied
// URLs pass, otherwise a preset would be an unchecked bypass of the fetch rules.
func TestPresetsPassFetchURLValidation(t *testing.T) {
	for _, p := range Presets() {
		t.Run(string(p.ID), func(t *testing.T) {
			if _, err := ValidateFetchURL(p.URL); err != nil {
				t.Fatalf("built-in preset %q URL failed validation: %v", p.ID, err)
			}
		})
	}
}

// The catalog order is observable: it drives the order operators see. Appending
// is fine; silent reordering is not.
func TestPresetsOrderIsStable(t *testing.T) {
	want := []PresetID{
		PresetRussiaInside,
		PresetGeoblock,
		PresetAntifilterDomains,
		PresetAntifilterIPv4,
	}
	got := Presets()
	if len(got) != len(want) {
		t.Fatalf("len(Presets()) = %d, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("Presets()[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestPresetsReturnsCopy(t *testing.T) {
	first := Presets()
	if len(first) == 0 {
		t.Fatal("catalog is empty")
	}
	first[0].URL = "https://evil.example/list.lst"

	if second := Presets(); second[0].URL == "https://evil.example/list.lst" {
		t.Fatal("Presets() shares its backing array with callers")
	}
}

// russia_outside must not exist: it implies a Russian egress Nexus does not
// provide, and exposing it as a one-click preset is explicitly refused by #678.
func TestRussiaOutsidePresetAbsent(t *testing.T) {
	const forbidden = "russia_outside"
	if PresetID(forbidden).Valid() {
		t.Fatalf("preset %q must not be modelled", forbidden)
	}
	if _, ok := LookupPreset(forbidden); ok {
		t.Fatalf("LookupPreset(%q) unexpectedly resolved", forbidden)
	}
	for _, p := range Presets() {
		if string(p.ID) == forbidden || strings.Contains(p.URL, "outside") {
			t.Errorf("catalog exposes russia_outside-like entry: %+v", p)
		}
	}
}

// Antifilter must be modelled as a source, never as a separate routing mode, and
// urls.lst / BGP feeds are out of v1 scope.
func TestAntifilterPresetsAreSourcesOnly(t *testing.T) {
	antifilterURLs := 0
	for _, p := range Presets() {
		if !strings.Contains(p.URL, "antifilter.download") {
			continue
		}
		antifilterURLs++
		if strings.Contains(p.URL, "urls.lst") {
			t.Errorf("preset %q uses urls.lst, which is out of v1 scope", p.ID)
		}
		if !p.ID.IsBuiltin() {
			t.Errorf("preset %q is not flagged as a preset source", p.ID)
		}
	}
	if antifilterURLs != 2 {
		t.Fatalf("found %d Antifilter presets, want 2 (domains + ipv4)", antifilterURLs)
	}
}

func TestPresetFormatsMatchPayloadShape(t *testing.T) {
	// Domain presets must parse domains and suffix-match them; the broad IPv4
	// preset must parse prefixes. A mismatch here silently mismatches traffic.
	cases := []struct {
		id     PresetID
		format Format
		mode   DomainMode
	}{
		{PresetRussiaInside, FormatDomains, DomainModeInclusiveSuffix},
		{PresetGeoblock, FormatDomains, DomainModeInclusiveSuffix},
		{PresetAntifilterDomains, FormatDomains, DomainModeInclusiveSuffix},
		{PresetAntifilterIPv4, FormatIPv4, DomainModeExact},
	}
	for _, tc := range cases {
		p, ok := LookupPreset(tc.id)
		if !ok {
			t.Fatalf("LookupPreset(%q) not found", tc.id)
		}
		if p.Format != tc.format {
			t.Errorf("preset %q Format = %v, want %v", tc.id, p.Format, tc.format)
		}
		if p.BareDomainMode != tc.mode {
			t.Errorf("preset %q BareDomainMode = %v, want %v", tc.id, p.BareDomainMode, tc.mode)
		}
	}
}

func TestLookupPresetCustomAndUnknown(t *testing.T) {
	custom, ok := LookupPreset(PresetCustom)
	if !ok {
		t.Fatal("PresetCustom must resolve")
	}
	if custom.URL != "" {
		t.Errorf("PresetCustom URL = %q, want empty (operator-supplied)", custom.URL)
	}
	if PresetCustom.IsBuiltin() {
		t.Error("PresetCustom must not be reported as builtin")
	}
	if _, ok := LookupPreset("no_such_preset"); ok {
		t.Error("unknown preset resolved")
	}
	if PresetID("no_such_preset").Valid() {
		t.Error("unknown preset reported valid")
	}
	if PresetID("").Valid() {
		t.Error("empty preset reported valid")
	}
}
