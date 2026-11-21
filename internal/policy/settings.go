package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// This file defines the persisted policy-routing configuration record for
// issue #678 and the pure validation/derivation that the admin API needs.
//
// Design constraints taken from the issue and the parent epic:
//   - PBR defaults to DISABLED, and disabled always means the previous
//     all-proxy behavior. The zero value of Settings is therefore the
//     correct state for existing and fresh installs: no migration and no
//     default row are required, because an absent settings row deserializes to
//     a zero value whose Enabled is false.
//   - A preset is a list SOURCE, never a routing mode. Presets still mean
//     PROXY on match.
//   - Invalid settings are rejected; they never overwrite a last working
//     configuration. Validation is pure so a handler can reject before writing.
//   - One source selection at a time. A built-in preset and custom URLs are not
//     silently merged; choosing both is an operator error.
//
// Runtime prerequisite gating (a published non-empty snapshot plus working
// direct egress) is deliberately NOT re-implemented here. That contract lives in
// vpn.ValidatePBRPrerequisites / ErrPBREmptyPolicy and the Syncer's zero-rule
// and shrink guards, which stay the single owner of fail-closed enablement.

// SettingsKey is the settings-table key holding the persisted policy record.
// The existing key/value settings table is sufficient: the issue asks for "a
// small configuration record", not a new table.
const SettingsKey = "pbr_policy"

// Sync interval bounds for the operator-facing configuration.
const (
	// MinSyncInterval is the shortest accepted refresh interval. It matches the
	// Syncer's own floor so a saved value can always build a sync configuration.
	MinSyncInterval = MinRefreshInterval
	// MaxSyncInterval bounds how stale a proxied list may become.
	MaxSyncInterval = 24 * time.Hour
	// DefaultSyncInterval is applied when the operator does not choose one.
	DefaultSyncInterval = DefaultRefreshInterval
	// MaxCustomURLs bounds custom sources. The Syncer's total source budget is
	// larger because the aggregate manifest contributes 24 reviewed sources.
	MaxCustomURLs = 4
	// MaxSyncSources bounds the total source list, including the aggregate
	// manifest and the local source.
	MaxSyncSources = 32
	// MaxInventoryOverrideEntries bounds the operator inventory override. It
	// matches the local-rule cap because the override is pasted into a form field
	// like a local list: a body past that size is a mistake, not a routing set.
	MaxInventoryOverrideEntries = 4096
)

// Settings is the persisted policy-routing configuration.
//
// Field names are part of the admin API contract and the settings-table JSON,
// so they are stable. SyncInterval is stored in whole seconds because it travels
// as JSON through both the settings row and the HTTP request body.
type Settings struct {
	// Enabled reports whether policy-based routing is turned on. Disabled (the
	// default) means every client uses its assigned proxy backend, unchanged.
	Enabled bool `json:"enabled"`
	// Preset is the selected list source. Empty means the operator has not
	// chosen one; it is not silently replaced by a default source.
	Preset PresetID `json:"preset"`
	// CustomURLs holds operator-supplied HTTPS list URLs. It is only meaningful
	// when Preset is PresetCustom, and must be empty for a built-in preset.
	CustomURLs []string `json:"custom_urls"`
	// LocalEntries holds operator-supplied domain/CIDR rules merged on top of the
	// selected external source. It is additive and works with every preset.
	LocalEntries []string `json:"local_entries,omitempty"`
	// ExcludedDomains holds operator-supplied domains that must never enter the
	// PROXY set. It is applied with the built-in never-proxy guard and works
	// with every preset.
	ExcludedDomains []string `json:"excluded_domains,omitempty"`
	// SyncInterval is the refresh period in seconds.
	SyncInterval int64 `json:"sync_interval_seconds"`
	// InventoryOverride holds operator-supplied IPv4 prefixes that take
	// precedence over the committed Russian allocation inventory for every
	// address they contain, so a deployment can correct the shipped set without
	// waiting for a release. Empty is the default and means "the shipped set
	// alone". The body uses the same line shape as LocalEntries (blank lines and
	// comments are ignored), but this field is an IPv4 prefix list: a body with
	// no prefix, or one that also carries a domain rule, is refused rather than
	// stored as an override that would apply only part of what was submitted.
	InventoryOverride []string `json:"inventory_override,omitempty"`
}

// DefaultSettings returns the fresh-install configuration: policy routing
// disabled, no preset selected, no custom URLs and the default refresh interval.
func DefaultSettings() Settings {
	return Settings{
		Enabled:      false,
		Preset:       "",
		CustomURLs:   nil,
		SyncInterval: int64(DefaultSyncInterval / time.Second),
	}
}

// Normalize fills in a valid default refresh interval when the field is absent
// (zero), and returns a copy with owned slices so a caller cannot mutate shared
// state through the returned value.
//
// Normalize deliberately does NOT invent a preset. Selecting a source is an
// operator action, and a synthesized default would be the "dummy policy" the
// issue forbids.
func (s Settings) Normalize() Settings {
	out := s
	if out.SyncInterval == 0 {
		out.SyncInterval = int64(DefaultSyncInterval / time.Second)
	}
	if s.CustomURLs != nil {
		out.CustomURLs = make([]string, len(s.CustomURLs))
		copy(out.CustomURLs, s.CustomURLs)
	}
	if s.LocalEntries != nil {
		out.LocalEntries = make([]string, len(s.LocalEntries))
		copy(out.LocalEntries, s.LocalEntries)
	}
	if s.ExcludedDomains != nil {
		out.ExcludedDomains = make([]string, len(s.ExcludedDomains))
		copy(out.ExcludedDomains, s.ExcludedDomains)
	}
	if s.InventoryOverride != nil {
		out.InventoryOverride = make([]string, len(s.InventoryOverride))
		copy(out.InventoryOverride, s.InventoryOverride)
	}
	return out
}

// Interval returns the configured refresh period as a duration.
func (s Settings) Interval() time.Duration {
	return time.Duration(s.SyncInterval) * time.Second
}

// IsZero reports whether the record says nothing at all.
//
// An absent settings row deserializes to this value, so "zero" is the
// fresh-install state: policy routing disabled, no source selected. Three
// callers need exactly that distinction — the admin handler's loader, the
// panel's startup loader, and the compensation path that must restore "no
// record" rather than materialize a default one — so the predicate lives with
// the type instead of being repeated as a field-by-field comparison.
//
// Settings contains a slice and is therefore not comparable with ==, which is
// why this exists rather than a comparison at each call site.
func (s Settings) IsZero() bool {
	return s.Preset == "" && !s.Enabled && s.SyncInterval == 0 && len(s.CustomURLs) == 0 && len(s.LocalEntries) == 0 && len(s.ExcludedDomains) == 0 && len(s.InventoryOverride) == 0
}

// Validate reports whether the configuration may be persisted. A nil result
// means the record is internally coherent and every URL is fetchable under the
// same SSRF rules the fetcher enforces.
//
// Validate intentionally does not consult live runtime state: whether enablement
// is currently possible depends on a published snapshot and direct egress, which
// the VPN layer decides.
func (s Settings) Validate() error {
	if err := s.validateInterval(); err != nil {
		return err
	}
	if !s.Preset.Valid() {
		if s.Preset == "" {
			return errors.New("policy preset must be selected")
		}
		return fmt.Errorf("unknown policy preset %q", s.Preset)
	}
	if err := s.validateSourceSelection(); err != nil {
		return err
	}
	if err := s.validateExcludedDomains(); err != nil {
		return err
	}
	if err := s.validateLocalEntries(); err != nil {
		return err
	}
	return s.validateInventoryOverride()
}

func (s Settings) validateInterval() error {
	interval := s.Interval()
	if interval < MinSyncInterval {
		return fmt.Errorf("sync interval %s is shorter than the minimum %s", interval, MinSyncInterval)
	}
	if interval > MaxSyncInterval {
		return fmt.Errorf("sync interval %s is longer than the maximum %s", interval, MaxSyncInterval)
	}
	return nil
}

func (s Settings) validateSourceSelection() error {
	if s.Preset == PresetCustom {
		return s.validateCustomURLs()
	}
	if len(s.CustomURLs) > 0 {
		return fmt.Errorf("preset %q cannot be combined with custom URLs; select the %q preset to use them", s.Preset, PresetCustom)
	}
	if s.Preset == PresetAggregate {
		for _, src := range AggregateSources() {
			if _, err := ValidateFetchURL(src.URL); err != nil {
				return fmt.Errorf("aggregate source %q has an unusable URL: %w", src.ID, err)
			}
		}
		return nil
	}
	// Defense in depth: the built-in constants must still satisfy the same
	// fetch rules the operator-supplied URLs are held to.
	preset, _ := LookupPreset(s.Preset)
	if _, err := ValidateFetchURL(preset.URL); err != nil {
		return fmt.Errorf("built-in preset %q has an unusable source URL: %w", s.Preset, err)
	}
	return nil
}

func (s Settings) validateExcludedDomains() error {
	if len(s.ExcludedDomains) > MaxExcludedDomains {
		return fmt.Errorf("%d excluded domains exceed the maximum of %d", len(s.ExcludedDomains), MaxExcludedDomains)
	}
	if _, err := ParseExcludedDomains(s.ExcludedDomains); err != nil {
		return fmt.Errorf("excluded domain rejected: %w", err)
	}
	return nil
}

func (s Settings) validateLocalEntries() error {
	if len(s.LocalEntries) > 4096 {
		return fmt.Errorf("%d local entries exceed the maximum of 4096", len(s.LocalEntries))
	}
	local, _, err := ParseLocalRules(s.LocalEntries)
	if err != nil {
		return fmt.Errorf("local entry rejected: %w", err)
	}
	exclusions, err := ParseExcludedDomains(s.ExcludedDomains)
	if err != nil {
		return fmt.Errorf("excluded domain rejected: %w", err)
	}
	for base := range local.Domains {
		if _, excluded := neverProxyReason(base, exclusions); excluded {
			return fmt.Errorf("local entry rejected: %q is also listed in excluded_domains; a name cannot be both proxied and excluded", base)
		}
	}
	return nil
}

// ErrInventoryOverrideNotPrefixOnly means the stored override carried a rule
// that is not an IPv4 prefix. ParseInventoryOverride deliberately accepts mixed
// input for other consumers, but the persisted field is an address set: a domain
// line there would be saved and never applied, so the settings boundary refuses
// it with this reason instead of storing an override that partly does nothing.
var ErrInventoryOverrideNotPrefixOnly = errors.New("inventory override must contain only IPv4 prefixes")

// validateInventoryOverride refuses an override body the classifier could not
// apply. It uses the same parser the activation path uses, so a body that saves
// is a body that classifies: an invalid override is rejected at the settings
// boundary instead of being persisted and then silently ignored.
//
// The field is documented as an IPv4 prefix list, so a mixed body is refused
// even when it also carries a usable prefix. Accepting it would store rules the
// parser reports as ignored and no surface ever shows, which reads as applied.
func (s Settings) validateInventoryOverride() error {
	if len(s.InventoryOverride) == 0 {
		return nil
	}
	if len(s.InventoryOverride) > MaxInventoryOverrideEntries {
		return fmt.Errorf("%d inventory override entries exceed the maximum of %d", len(s.InventoryOverride), MaxInventoryOverrideEntries)
	}
	override, err := s.ParsedInventoryOverride()
	if err != nil {
		return fmt.Errorf("inventory override rejected: %w", err)
	}
	if ignored := override.DomainRuleCount(); ignored > 0 {
		return fmt.Errorf("inventory override rejected: %w: the body also carries %d domain %s beside %d prefix %s; only prefixes are applied here",
			ErrInventoryOverrideNotPrefixOnly, ignored, pluralWord(ignored, "rule", "rules"),
			override.PrefixCount(), pluralWord(override.PrefixCount(), "prefix", "prefixes"))
	}
	return nil
}

// pluralWord returns singular for exactly one, otherwise plural.
func pluralWord(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// ParsedInventoryOverride parses the stored override body. A nil result with a
// nil error means no override is configured, which is the shipped-set-only
// state; the caller does not have to distinguish it from an empty body.
//
// Validation and activation both go through this method, so a record that
// validated is exactly the record the classifier receives.
func (s Settings) ParsedInventoryOverride() (*InventoryOverride, error) {
	if len(s.InventoryOverride) == 0 {
		return nil, nil
	}
	return ParseInventoryOverride([]byte(strings.Join(s.InventoryOverride, "\n")))
}

func (s Settings) validateCustomURLs() error {
	if len(s.CustomURLs) == 0 {
		return fmt.Errorf("preset %q requires at least one custom URL", PresetCustom)
	}
	if len(s.CustomURLs) > MaxCustomURLs {
		return fmt.Errorf("%d custom URLs exceed the maximum of %d", len(s.CustomURLs), MaxCustomURLs)
	}
	seen := make(map[string]struct{}, len(s.CustomURLs))
	for i, raw := range s.CustomURLs {
		u, err := ValidateFetchURL(raw)
		if err != nil {
			return fmt.Errorf("custom URL %d rejected: %w", i+1, err)
		}
		canonical := u.String()
		if _, dup := seen[canonical]; dup {
			return fmt.Errorf("custom URL %d duplicates an earlier entry", i+1)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}

// Sources derives the ordered policy sources for the current selection. The
// order is deterministic so the Syncer's config hash, conditional validators and
// per-source statistics stay stable across restarts.
//
// A built-in preset yields exactly one preset source. The custom preset yields
// one strictly parsed source per URL, in the operator's order.
func (s Settings) Sources() ([]Source, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.Preset == PresetAggregate {
		return AggregateSources(), nil
	}
	if s.Preset != PresetCustom {
		preset, _ := LookupPreset(s.Preset)
		return []Source{{
			ID:             string(preset.ID),
			URL:            preset.URL,
			Format:         preset.Format,
			BareDomainMode: preset.BareDomainMode,
			IsPreset:       true,
		}}, nil
	}

	sources := make([]Source, 0, len(s.CustomURLs))
	for i, raw := range s.CustomURLs {
		u, err := ValidateFetchURL(raw)
		if err != nil {
			// Validate already rejected this; keep the error path honest rather
			// than trusting the caller to have validated.
			return nil, fmt.Errorf("custom URL %d rejected: %w", i+1, err)
		}
		sources = append(sources, Source{
			ID:             fmt.Sprintf("custom-%d", i+1),
			URL:            u.String(),
			Format:         FormatMixed,
			BareDomainMode: DomainModeInclusiveSuffix,
			IsPreset:       false,
		})
	}
	return sources, nil
}

// SyncConfig derives the Syncer configuration for the current selection using
// the production fetch and parse bounds. ForceShrink stays false: a suspiciously
// small download must fail rather than silently replace a valid active policy.
func (s Settings) SyncConfig() (SyncConfig, error) {
	sources, err := s.Sources()
	if err != nil {
		return SyncConfig{}, err
	}
	localRules, _, err := ParseLocalRules(s.LocalEntries)
	if err != nil {
		return SyncConfig{}, err
	}
	excludedDomains, err := ParseExcludedDomains(s.ExcludedDomains)
	if err != nil {
		return SyncConfig{}, err
	}
	return SyncConfig{
		Sources:         sources,
		LocalRules:      localRules,
		ExcludedDomains: excludedDomains,
		RefreshInterval: s.Interval(),
		FetchLimits:     DefaultFetchLimits(),
		ParseLimits:     DefaultParseLimits(),
		ForceShrink:     false,
	}, nil
}
