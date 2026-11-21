package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
//   - The policy authority is the destination classifier: the committed Russian
//     allocation plus the CDN exclusion set decides every destination. This
//     record adds exactly one operator input on top, an IPv4 PROXY exception
//     list whose prefixes are forced to PROXY ahead of the classifier.
//   - No source is ever fetched. A control an operator can see must actually
//     work, and a fetched list is both an availability dependency and a second
//     policy authority that silently outranks the classifier. Addresses an
//     operator needs proxied belong in the exception list.
//   - Invalid settings are rejected; they never overwrite a last working
//     configuration. Validation is pure so a handler can reject before writing.
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
	// MaxLocalExceptions bounds the operator IPv4 exception list. The cap
	// matches the pasted-form size: a body past this is a mistake, not a
	// routing set.
	MaxLocalExceptions = 4096
	// MaxInventoryOverrideEntries bounds the operator inventory override. It
	// matches the local-rule cap because the override is pasted into a form field
	// like a local list: a body past that size is a mistake, not a routing set.
	MaxInventoryOverrideEntries = 4096
)

// Settings is the persisted policy-routing configuration.
//
// Field names are part of the admin API contract and the settings-table JSON, so
// they are stable. SyncInterval is stored in whole seconds because it travels as
// JSON through both the settings row and the HTTP request body.
type Settings struct {
	// Enabled reports whether policy-based routing is turned on. Disabled (the
	// default) means every client uses its assigned proxy backend, unchanged.
	Enabled bool `json:"enabled"`
	// ProxyExceptions holds operator-supplied IPv4 prefixes that are forced to
	// PROXY ahead of the destination classifier, so an operator can always take
	// an address off the direct path. Lines are prefixes or single addresses;
	// blank lines and comments are ignored.
	//
	// The wire name is "proxy_exceptions". A record written by an earlier build
	// carries the same operator addresses under "local_entries"; UnmarshalJSON
	// accepts that key so an upgrade does not silently drop them, and a save
	// always writes the current name.
	ProxyExceptions []string `json:"proxy_exceptions,omitempty"`
	// SyncInterval is the refresh period in seconds.
	SyncInterval int64 `json:"sync_interval_seconds"`
	// InventoryOverride holds operator-supplied IPv4 prefixes that take
	// precedence over the committed Russian allocation inventory for every
	// address they contain, so a deployment can correct the shipped set without
	// waiting for a release. Empty is the default and means "the shipped set
	// alone". The body uses the same line shape as ProxyExceptions (blank lines
	// and comments are ignored), but this field is an IPv4 prefix list: a body
	// with no prefix, or one that also carries a domain rule, is refused rather
	// than stored as an override that would apply only part of what was
	// submitted.
	InventoryOverride []string `json:"inventory_override,omitempty"`
}

// legacySettings is the record shape earlier builds persisted. It exists only to
// migrate a stored row: the preset, custom-URL and excluded-domain selections no
// longer exist, and domain rules no longer reach a packet decision.
type legacySettings struct {
	Enabled           bool     `json:"enabled"`
	Preset            string   `json:"preset"`
	CustomURLs        []string `json:"custom_urls"`
	LocalEntries      []string `json:"local_entries"`
	ExcludedDomains   []string `json:"excluded_domains"`
	SyncInterval      int64    `json:"sync_interval_seconds"`
	InventoryOverride []string `json:"inventory_override"`
}

// UnmarshalJSON accepts the current wire shape and the shape an earlier build
// wrote.
//
// The exception list was called "local_entries" when it also accepted domain
// lines. A stored record still carries the operator's addresses under that key, so
// reading only the new name would silently discard a configuration the operator
// saved — the opposite of what a rename should do. The old key is read as a
// fallback and only when the new one is absent, so a record carrying both is read
// from the current field.
//
// The other legacy fields decode into nothing: their content cannot be represented
// any more, and migrateLegacyRecord reports what a stored record could not carry.
func (s *Settings) UnmarshalJSON(data []byte) error {
	type current Settings
	var decoded current
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	// A separate pass reads only the legacy exception key. Decoding it into the
	// legacy struct keeps the field names in one place.
	if len(decoded.ProxyExceptions) == 0 {
		var legacy wireLegacyExceptions
		if err := json.Unmarshal(data, &legacy); err != nil {
			return err
		}
		decoded.ProxyExceptions = legacy.LocalEntries
	}
	*s = Settings(decoded)
	return nil
}

// wireLegacyExceptions is the one legacy field a load still honors.
type wireLegacyExceptions struct {
	LocalEntries []string `json:"local_entries"`
}

// migrateLegacyRecord reports which stored values cannot be carried into the
// current record, so loading a row written by an earlier build is an explained
// downgrade rather than a silent loss.
//
// The exception list survives: an operator's IPv4 prefixes under the old
// local_entries key are still the prefixes this build proxies. What cannot
// survive is the source selection and its fetched content — there is no feed any
// more — and the domain half of the old record, because a domain rule never
// determined a packet's route.
func migrateLegacyRecord(legacy legacySettings) []string {
	var dropped []string
	if legacy.Preset != "" {
		dropped = append(dropped, fmt.Sprintf("source selection %q", legacy.Preset))
	}
	if len(legacy.CustomURLs) > 0 {
		dropped = append(dropped, fmt.Sprintf("%d custom list URL(s)", len(legacy.CustomURLs)))
	}
	if len(legacy.ExcludedDomains) > 0 {
		dropped = append(dropped, fmt.Sprintf("%d excluded domain name(s)", len(legacy.ExcludedDomains)))
	}
	return dropped
}

// DefaultSettings returns the fresh-install configuration: policy routing
// disabled, no exceptions and the default refresh interval.
func DefaultSettings() Settings {
	return Settings{
		Enabled:      false,
		SyncInterval: int64(DefaultSyncInterval / time.Second),
	}
}

// Normalize fills in a valid default refresh interval when the field is absent
// (zero), and returns a copy with owned slices so a caller cannot mutate shared
// state through the returned value.
func (s Settings) Normalize() Settings {
	out := s
	if out.SyncInterval == 0 {
		out.SyncInterval = int64(DefaultSyncInterval / time.Second)
	}
	if s.ProxyExceptions != nil {
		out.ProxyExceptions = make([]string, len(s.ProxyExceptions))
		copy(out.ProxyExceptions, s.ProxyExceptions)
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
// fresh-install state: policy routing disabled, no exceptions. Three callers
// need exactly that distinction — the admin handler's loader, the panel's
// startup loader, and the compensation path that must restore "no record" rather
// than materialize a default one — so the predicate lives with the type instead
// of being repeated as a field-by-field comparison.
//
// Settings contains a slice and is therefore not comparable with ==, which is
// why this exists rather than a comparison at each call site.
func (s Settings) IsZero() bool {
	return !s.Enabled && s.SyncInterval == 0 && len(s.ProxyExceptions) == 0 && len(s.InventoryOverride) == 0
}

// Validate reports whether the configuration may be persisted. A nil result
// means the record is internally coherent: every exception line is an IPv4
// prefix, and every override line is a prefix the classifier could apply.
//
// Validate intentionally does not consult live runtime state: whether enablement
// is currently possible depends on a published snapshot and direct egress, which
// the VPN layer decides.
func (s Settings) Validate() error {
	if err := s.validateInterval(); err != nil {
		return err
	}
	if err := s.validateProxyExceptions(); err != nil {
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

// ErrLocalRuleNotPrefix means an exception line was not an IPv4 prefix.
//
// The list is documented as an address set, and the packet path matches it
// against the destination address. A domain line here would be saved and never
// applied — a control that looks configured and decides nothing — so the
// boundary refuses it with this reason instead of storing it.
var ErrLocalRuleNotPrefix = errors.New("proxy exception must be an IPv4 address or prefix")

// validateProxyExceptions refuses an exception body the packet path could not
// apply.
//
// It deliberately does not judge whether a prefix overlaps a prohibited
// destination. The packet path's first row drops such a destination before any
// PROXY rule can route it, and the one authoritative prohibited set lives in the
// forwarder (IsProhibitedIPv4Destination). Restating that set here would create a
// second copy to drift from, and refusing the line would reject a body earlier
// builds accepted. The honest position is the one the routing contract already
// states: an exception naming such a range cannot route it, and the drop wins.
func (s Settings) validateProxyExceptions() error {
	if len(s.ProxyExceptions) > MaxLocalExceptions {
		return fmt.Errorf("%d local entries exceed the maximum of %d", len(s.ProxyExceptions), MaxLocalExceptions)
	}
	for _, raw := range s.ProxyExceptions {
		line := strings.TrimSpace(raw)
		if isIgnoredLine(line) {
			continue
		}
		if _, err := ParseIPv4Rule(line); err != nil {
			return fmt.Errorf("proxy exception rejected: %w", err)
		}
	}
	return nil
}

// ProxyExceptionPrefixes returns the parsed, deduplicated prefixes of the
// exception list in declaration order. A blank line or comment is ignored. The
// caller has already validated the body, so a parse error here means the stored
// record changed underneath validation; it is returned rather than swallowed.
func (s Settings) ProxyExceptionPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(s.ProxyExceptions))
	seen := make(map[netip.Prefix]struct{}, len(s.ProxyExceptions))
	for _, raw := range s.ProxyExceptions {
		line := strings.TrimSpace(raw)
		if isIgnoredLine(line) {
			continue
		}
		prefix, err := ParseIPv4Rule(line)
		if err != nil {
			return nil, fmt.Errorf("proxy exception rejected: %w", err)
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
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

// SyncConfig derives the Syncer configuration for the current record using the
// production parse bounds. ForceShrink stays false: a suspiciously short list
// must fail rather than silently replace a valid active policy.
//
// The derived configuration has no sources. The classifier is the policy
// authority and the exception list is local, so the cycle compiles the operator's
// prefixes alone and needs no network.
func (s Settings) SyncConfig() (SyncConfig, error) {
	if err := s.Validate(); err != nil {
		return SyncConfig{}, err
	}
	prefixes, err := s.ProxyExceptionPrefixes()
	if err != nil {
		return SyncConfig{}, err
	}
	return SyncConfig{
		LocalRules:      ParsedRules{CIDRs: prefixes},
		RefreshInterval: s.Interval(),
		ParseLimits:     DefaultParseLimits(),
		ForceShrink:     false,
	}, nil
}
