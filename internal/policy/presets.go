package policy

// This file defines the built-in policy list presets exposed to operators by the
// admin API (issue #678). A preset is a list SOURCE, never a routing mode: every
// preset still means PROXY on match, and no preset is ever enabled implicitly.
//
// The catalog is intentionally limited to the sources documented in the parent
// epic (#674). In particular "russia_outside" is NOT modeled: it represents
// sites needing a Russian egress and would be misleading unless Nexus can route
// them through a known Russian exit. Antifilter's urls.lst and BGP feed are out
// of v1 scope for the same reason.

// PresetID identifies a selectable policy list source.
type PresetID string

// Supported preset identifiers. The four URL-bearing presets are built-ins;
// PresetCustom selects operator-supplied HTTPS list URLs instead.
const (
	// PresetRussiaInside selects the itdoginfo "Russia inside" allow list.
	PresetRussiaInside PresetID = "russia_inside"
	// PresetGeoblock selects the itdoginfo "geoblock" category list.
	PresetGeoblock PresetID = "geoblock"
	// PresetAntifilterDomains selects the Antifilter domain list.
	PresetAntifilterDomains PresetID = "antifilter_domains"
	// PresetAntifilterIPv4 selects the Antifilter aggregated IPv4 prefix list.
	// Its ranges are broad and can proxy unrelated traffic, so it is never
	// enabled implicitly.
	PresetAntifilterIPv4 PresetID = "antifilter_ipv4"
	// PresetCustom selects operator-supplied HTTPS domain/CIDR list URLs.
	PresetCustom PresetID = "custom"
)

// Documented preset source URLs (issue #678).
const (
	russiaInsideURL      = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst"
	geoblockURL          = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst"
	antifilterDomainsURL = "https://antifilter.download/list/domains.lst"
	antifilterIPv4URL    = "https://antifilter.download/list/allyouneed.lst"
)

// Preset describes one built-in list source and how its payload must be parsed.
type Preset struct {
	// ID is the stable preset identifier stored in the settings record.
	ID PresetID
	// URL is the documented HTTPS source location.
	URL string
	// Format selects the parser used for the downloaded payload.
	Format Format
	// BareDomainMode decides whether a bare domain matches its apex only or the
	// apex plus every subdomain. Domain presets use inclusive suffix matching so
	// that a shared CDN or subdomain is proxied rather than leaked.
	BareDomainMode DomainMode
}

// Valid reports whether id names a known preset, including PresetCustom.
func (id PresetID) Valid() bool {
	_, ok := LookupPreset(id)
	return ok
}

// IsBuiltin reports whether id names a preset that carries a documented URL.
// PresetCustom is a valid selection but is not builtin: it carries no URL of
// its own and requires operator-supplied sources.
func (id PresetID) IsBuiltin() bool {
	p, ok := LookupPreset(id)
	return ok && p.URL != ""
}

// builtinPresets is the ordered catalog. Order is part of the observable API
// (it drives the order operators see and the stable sync source order), so
// append new presets rather than reordering existing ones.
var builtinPresets = []Preset{
	{ID: PresetRussiaInside, URL: russiaInsideURL, Format: FormatDomains, BareDomainMode: DomainModeInclusiveSuffix},
	{ID: PresetGeoblock, URL: geoblockURL, Format: FormatDomains, BareDomainMode: DomainModeInclusiveSuffix},
	{ID: PresetAntifilterDomains, URL: antifilterDomainsURL, Format: FormatDomains, BareDomainMode: DomainModeInclusiveSuffix},
	{ID: PresetAntifilterIPv4, URL: antifilterIPv4URL, Format: FormatIPv4, BareDomainMode: DomainModeExact},
}

// Presets returns a copy of the built-in catalog in its documented order.
// PresetCustom is not included: it has no URL and is not a downloadable source.
func Presets() []Preset {
	out := make([]Preset, len(builtinPresets))
	copy(out, builtinPresets)
	return out
}

// LookupPreset resolves a preset identifier. PresetCustom resolves to a Preset
// with an empty URL, which callers must treat as "operator-supplied sources".
func LookupPreset(id PresetID) (Preset, bool) {
	if id == PresetCustom {
		return Preset{ID: PresetCustom}, true
	}
	for _, p := range builtinPresets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
