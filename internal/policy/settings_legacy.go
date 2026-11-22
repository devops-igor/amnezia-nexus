package policy

// Reading a record that an earlier build persisted.
//
// The exception list was renamed from "local_entries" to "proxy_exceptions" when
// domain rules were retired, and the two representations differ in more than a key
// name: the predecessor list also accepted domain lines beside its prefixes.
//
// This file owns that transition end to end — the fallback decode, the separation
// of what this build can apply from what it cannot, and the report an operator
// surface reads. It is separate from settings.go (the current record, its
// validation and the sync configuration derived from it) because a rename's
// compatibility rules are a concern of their own: they will be read far less often
// than the record itself, and they must be able to change without touching
// validation.
//
// One rule governs the whole file: decide on what the stored bytes SAY, never on
// what a decoded value happens to contain. A list is allowed to be empty, and an
// empty list the operator saved is intent, not absence.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// legacySettings is the record shape earlier builds persisted. It exists only to
// describe a stored row: the preset, custom-URL and excluded-domain selections no
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
// saved — the opposite of what a rename should do.
//
// Two decisions here are deliberately made on what the bytes SAY rather than on
// what the decoded value happens to contain, because a list is allowed to be
// empty and an empty list is operator intent:
//
//   - the fallback applies only when the current key is ABSENT. Presence, not
//     list length, decides. A record carrying an explicit "proxy_exceptions": []
//     is an operator who cleared the list, and treating that as "no key here"
//     would merge the stored entries back and answer 200 while the old list stays
//     installed;
//   - a record carrying both keys is read from the current one.
//
// The predecessor list accepted domain lines beside prefixes. Those lines cannot
// be applied by this build, so they are separated from the prefixes here, at the
// one boundary that reads a stored record, instead of being copied into a field
// whose validation would reject the whole record and take the operator's working
// IPv4 policy down with an inert domain entry. What was separated is reported by
// ReviewStoredRecord, so the retirement is explained rather than silent.
func (s *Settings) UnmarshalJSON(data []byte) error {
	type current Settings
	var decoded current
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if !jsonObjectHasKey(data, "proxy_exceptions") {
		legacy, err := decodeLegacyExceptionKey(data)
		if err != nil {
			return err
		}
		kept, _ := splitLegacyEntries(legacy.LocalEntries)
		decoded.ProxyExceptions = kept
	}
	*s = Settings(decoded)
	return nil
}

// jsonObjectHasKey reports whether a JSON object carries a usable value under key,
// which is how a decoder tells "the operator sent an empty list" from "the operator
// sent no list at all". An empty array is a value; explicit null is not, because
// null is how JSON spells "absent" and a record carrying null beside a predecessor
// key still holds operator entries this build must read.
func jsonObjectHasKey(data []byte, key string) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return false
	}
	raw, ok := fields[key]
	if !ok {
		return false
	}
	return string(bytes.TrimSpace(raw)) != "null"
}

// wireLegacyExceptions is the one legacy field a load still honors.
type wireLegacyExceptions struct {
	LocalEntries []string `json:"local_entries"`
}

// decodeLegacyExceptionKey reads the predecessor exception key from a stored
// record.
func decodeLegacyExceptionKey(data []byte) (wireLegacyExceptions, error) {
	var legacy wireLegacyExceptions
	err := json.Unmarshal(data, &legacy)
	return legacy, err
}

// splitLegacyEntries separates a predecessor exception list into the IPv4 rules
// this build can still apply and the lines it cannot.
//
// Blank lines and comments are neither: they never were content. Everything else
// is either a prefix the packet path can match or content this build has no rule
// for, and the two are reported separately so the caller can keep the first and
// explain the second.
func splitLegacyEntries(entries []string) (kept, retired []string) {
	for _, raw := range entries {
		line := strings.TrimSpace(raw)
		if isIgnoredLine(line) {
			continue
		}
		if _, err := ParseIPv4Rule(line); err != nil {
			retired = append(retired, line)
			continue
		}
		kept = append(kept, line)
	}
	return kept, retired
}

// LegacyRetirement is what a stored record from an earlier build could not carry
// into this one. It exists so a load is an explained downgrade instead of a
// silent loss, and so the surface that shows an operator their record can say
// what happened to it.
//
// Every field is derived from the stored bytes, not from the retirement code, so
// the report cannot drift from what the decoder actually did.
type LegacyRetirement struct {
	// SourceSelection is the preset name the stored record selected, if any.
	SourceSelection string
	// CustomURLCount is how many operator list URLs the stored record held.
	CustomURLCount int
	// ExcludedDomainCount is how many excluded domain names it held.
	ExcludedDomainCount int
	// NonIPv4Entries are the exception-list lines that are not IPv4 prefixes —
	// the content the current field cannot represent. They are named verbatim so
	// the operator can recognize what was dropped.
	NonIPv4Entries []string
}

// Empty reports whether the stored record carried nothing this build had to
// retire, which is the ordinary upgrade of a prefix-only record.
func (r LegacyRetirement) Empty() bool {
	return r.SourceSelection == "" && r.CustomURLCount == 0 &&
		r.ExcludedDomainCount == 0 && len(r.NonIPv4Entries) == 0
}

// Summary describes the retirement in one line, for a log.
func (r LegacyRetirement) Summary() string {
	if r.Empty() {
		return ""
	}
	var parts []string
	if r.SourceSelection != "" {
		parts = append(parts, fmt.Sprintf("source selection %q", r.SourceSelection))
	}
	if r.CustomURLCount > 0 {
		parts = append(parts, fmt.Sprintf("%d custom list URL(s)", r.CustomURLCount))
	}
	if r.ExcludedDomainCount > 0 {
		parts = append(parts, fmt.Sprintf("%d excluded domain name(s)", r.ExcludedDomainCount))
	}
	if len(r.NonIPv4Entries) > 0 {
		parts = append(parts, fmt.Sprintf("%d exception-line(s) that are not IPv4 prefixes", len(r.NonIPv4Entries)))
	}
	return strings.Join(parts, "; ")
}

// ReviewStoredRecord reports what the stored record bytes hold that this build
// cannot apply. It is the production reader for that fact: the settings API
// reports it to the operator, so a retirement is stated on the surface that shows
// the record instead of living in a helper only a test calls.
//
// An unreadable record reports nothing: the caller's own decode has already
// failed, and inventing a retirement list for bytes that do not parse would
// describe a record nobody wrote.
func ReviewStoredRecord(raw []byte) LegacyRetirement {
	var current map[string]json.RawMessage
	if err := json.Unmarshal(raw, &current); err != nil {
		return LegacyRetirement{}
	}
	var legacy legacySettings
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return LegacyRetirement{}
	}
	retirement := LegacyRetirement{
		SourceSelection:     legacy.Preset,
		CustomURLCount:      len(legacy.CustomURLs),
		ExcludedDomainCount: len(legacy.ExcludedDomains),
	}
	// Only a record that still stores its exceptions under the predecessor key
	// has entries this build had to separate. A record already written in the
	// current shape holds only what its own validation accepted, so nothing was
	// retired from it.
	if _, currentShape := current["proxy_exceptions"]; !currentShape {
		_, retirement.NonIPv4Entries = splitLegacyEntries(legacy.LocalEntries)
	}
	return retirement
}
