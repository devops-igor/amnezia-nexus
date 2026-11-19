package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// This file owns the committed Russian IPv4 allocation inventory (issue #919).
//
// The inventory answers one question — "is this destination address inside the
// Russian allocation?" — from RIR delegation data rather than from BGP origin.
// That distinction is the whole reason the artifact exists: Yandex prefixes are
// originated by a Serbian-registered network, so a country-of-origin lookup
// reports Serbia for a Russian service (see the epic's field verification).
//
// The artifact is committed source, not a runtime download: two builds of the
// same revision therefore route identically and no build needs egress. It is
// updated only through the maintenance entry point in inventory_update.go,
// which validates the replacement before it can be written.
//
// Two properties keep the committed bytes and their record from drifting:
//
//   - the data file is committed verbatim, so its recorded SHA-256 can be
//     reproduced from the published feed by anyone reviewing the change;
//   - the loader re-derives the prefix count and digest from the bytes it
//     actually parsed and refuses the artifact when they disagree with the
//     provenance file. A hand-edited zone, a truncated copy or a mismatched
//     provenance update is therefore an error at load time — including the
//     mixed pair a regeneration interrupted between its two renames leaves
//     behind — never a silently smaller routing set.
//
// Uncovered addresses are out of scope here: the consumer treats "not a member"
// as the fail-safe proxy default.

//go:embed inventory/ru-ipv4.txt inventory/ru-ipv4.json inventory/Copyrights.txt
var inventoryArtifacts embed.FS

// inventoryNotice is the upstream copyright notice, compiled in so it travels
// with the data it covers. The redistribution terms require the notice to be
// kept intact and distributed with the zone files; embedding it is what makes
// that true for a binary as well as for the repository, and LoadInventory
// refuses a provenance record that does not name the notice it ships.
var inventoryNotice, _ = inventoryArtifacts.ReadFile("inventory/" + ShippedInventoryNoticeFile)

const (
	// InventoryArtifactDir is where the committed artifact lives, relative to
	// the repository root. The maintenance tool writes here by default.
	InventoryArtifactDir = "internal/policy/inventory"
	// ShippedInventoryDataFile holds one IPv4 prefix per line, verbatim as the
	// feed published it.
	ShippedInventoryDataFile = "ru-ipv4.txt"
	// ShippedInventoryMetaFile records the source, retrieval date and digest of
	// the data file beside it.
	ShippedInventoryMetaFile = "ru-ipv4.json"
	// ShippedInventoryNoticeFile is the upstream copyright notice, committed
	// verbatim beside the data because the redistribution terms require it to
	// travel with the zone.
	ShippedInventoryNoticeFile = "Copyrights.txt"

	// InventorySchemaVersion identifies the provenance record layout. An
	// unrecognized version is refused rather than half-read.
	InventorySchemaVersion = 1
	// InventoryKind names the artifact so a provenance file for some other
	// committed list cannot be mistaken for this one.
	InventoryKind = "russian_ipv4_allocations"

	// MinInventoryPrefixes is the smallest body accepted as a country
	// allocation set. It is a truncation guard, not a policy about the data:
	// the committed set holds roughly 8,700 prefixes, and a body of a few dozen
	// lines is a partial download or an error page that happened to parse, not
	// a smaller Russia. Refusing it keeps the previous artifact in place.
	MinInventoryPrefixes = 1024

	// DefaultInventoryMaxAge is how old the committed artifact may become
	// before it is reported as stale. Allocations change slowly; half a year is
	// stale enough to be worth an operator's attention without flagging every
	// ordinary quarter.
	DefaultInventoryMaxAge = 180 * 24 * time.Hour
)

// Errors reported by the inventory loader and validator.
var (
	// ErrInventoryNotPrefixList means the body is not an IPv4 prefix list at
	// all: an HTML or plain-text response, an empty body, or a line that is not
	// a prefix.
	ErrInventoryNotPrefixList = errors.New("inventory body is not an IPv4 prefix list")
	// ErrInventoryProvenanceMismatch means the provenance record does not
	// describe the committed data: a different prefix count, a different
	// digest, or an unsupported schema.
	ErrInventoryProvenanceMismatch = errors.New("inventory provenance does not match the committed data")
	// ErrInventoryLargeReduction means the body is a well formed prefix list
	// that would keep far fewer prefixes than the artifact it replaces, which is
	// what a feed truncated mid-download looks like.
	ErrInventoryLargeReduction = errors.New("inventory body would greatly reduce the committed set")
)

// InventorySource names the set that answered a membership question, so a
// direct decision can say whether the shipped allocation data or an operator
// override placed the address in the Russian set.
type InventorySource string

const (
	// InventorySourceShipped is the committed allocation inventory.
	InventorySourceShipped InventorySource = "shipped"
	// InventorySourceOverride is the operator-supplied override, which takes
	// precedence over the shipped set for every address it contains.
	InventorySourceOverride InventorySource = "operator-override"
)

// InventoryProvenance is the record committed beside the data file. PrefixCount
// and SHA256 are derived from the committed bytes by the loader, which refuses
// the artifact when they disagree, so they cannot be edited into agreement with
// a changed body.
type InventoryProvenance struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	// Source names the feed that published the zone.
	Source string `json:"source"`
	// SourceURL is the exact location the zone was downloaded from, so the
	// digest can be reproduced.
	SourceURL string `json:"source_url"`
	// RetrievedAt is the retrieval date in UTC, formatted 2006-01-02.
	RetrievedAt string `json:"retrieved_at"`
	// PrefixCount is the number of distinct prefixes in the data file.
	PrefixCount int `json:"prefix_count"`
	// SHA256 is the digest of the data file exactly as committed.
	SHA256 string `json:"sha256"`
	// NoticeFile names the upstream copyright notice committed beside the data.
	// The redistribution terms require it to be kept intact and distributed
	// with the zone files, so the record names it rather than repeating it.
	NoticeFile string `json:"notice_file,omitempty"`
	// NoticeSHA256 is the digest of that notice, so the copy that travels with
	// the data is the copy this record describes. LoadInventory refuses a
	// record whose digest does not match the notice it ships.
	NoticeSHA256 string `json:"notice_sha256,omitempty"`
	// License states the redistribution terms that actually apply.
	License string `json:"license,omitempty"`
	// Notes carries the update procedure for a human reviewer.
	Notes string `json:"notes,omitempty"`
}

// InventoryNotice returns a copy of the upstream copyright notice shipped with
// the inventory. It is committed beside the data and embedded in the binary, so
// a deployment carries the notice the redistribution terms require.
func InventoryNotice() []byte {
	out := make([]byte, len(inventoryNotice))
	copy(out, inventoryNotice)
	return out
}

// retrievedTime parses the recorded retrieval date.
func (p InventoryProvenance) retrievedTime() (time.Time, error) {
	if p.RetrievedAt == "" {
		return time.Time{}, errors.New("provenance has no retrieval date")
	}
	retrieved, err := time.Parse(time.DateOnly, p.RetrievedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("provenance retrieval date %q is not YYYY-MM-DD: %w", p.RetrievedAt, err)
	}
	return retrieved.UTC(), nil
}

// Inventory is a resolved Russian IPv4 allocation set: the committed shipped
// zone, plus an optional operator override that takes precedence for every
// address it contains.
//
// A resolved value is immutable once built; WithOverride returns a new value
// rather than mutating the receiver, so the cached shipped set can be shared
// between callers and goroutines.
type Inventory struct {
	prov          InventoryProvenance
	retrieved     time.Time
	shippedCount  int
	shipped       ipv4Index
	overrideCount int
	override      ipv4Index
	overrideHash  string
}

// InventoryFromBody parses body as the shipped zone and derives its count and
// digest. It refuses a body that is not a prefix list — a line that does not
// parse as an IPv4 prefix, an HTML/JSON document, an empty body — and one too
// small to be a country allocation set.
//
// The update entry point and the loader both call this, so a body can never be
// written by a rule the loader does not also enforce.
func InventoryFromBody(body []byte) (*Inventory, error) {
	prefixes, err := parseInventoryPrefixes(body)
	if err != nil {
		return nil, err
	}
	return &Inventory{
		shippedCount: len(prefixes),
		shipped:      newIPv4Index(prefixes),
		prov: InventoryProvenance{
			PrefixCount: len(prefixes),
			SHA256:      digestHex(body),
		},
	}, nil
}

// parseInventoryPrefixes validates a shipped zone body and returns its distinct
// masked prefixes.
func parseInventoryPrefixes(body []byte) ([]netip.Prefix, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("%w: body is empty", ErrInventoryNotPrefixList)
	}
	if looksLikeMarkupDocument(body) {
		return nil, fmt.Errorf("%w: body looks like a markup or data document, not a zone file", ErrInventoryNotPrefixList)
	}

	// The strict, non-preset path is what makes "every line must be a prefix"
	// true: for a non-preset source the parser reports the first offending line
	// instead of applying a preset rejection budget.
	src := Source{ID: "ru-inventory", Format: FormatIPv4, BareDomainMode: DomainModeExact}
	parsed, _, err := Parse(context.Background(), bytes.NewReader(body), src, DefaultParseLimits())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInventoryNotPrefixList, err)
	}
	if err := validateCanonicalLines(body); err != nil {
		return nil, err
	}

	distinct := distinctMaskedPrefixes(parsed.CIDRs)
	if len(distinct) < MinInventoryPrefixes {
		return nil, fmt.Errorf("%w: body holds %d distinct prefixes, below the %d prefix floor for a country allocation set",
			ErrInventoryNotPrefixList, len(distinct), MinInventoryPrefixes)
	}
	return distinct, nil
}

// validateCanonicalLines requires every data line to be the canonical form of
// its own prefix. The parser masks host bits, so without this a body saying
// "77.88.55.88/18" would be committed verbatim while the loader silently
// treated it as 77.88.0.0/18 — the bytes a reviewer reads would not be the bytes
// that decide routing. Refusing it keeps the committed file literal.
func validateCanonicalLines(body []byte) error {
	for i, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if isIgnoredLine(line) {
			continue
		}
		prefix, err := ParseIPv4Rule(line)
		if err != nil {
			// The parser above already rejected this line with a better message.
			continue
		}
		if prefix.String() != line {
			return fmt.Errorf("%w: line %d %q is not canonical CIDR notation (want %q)",
				ErrInventoryNotPrefixList, i+1, line, prefix.String())
		}
	}
	return nil
}

// looksLikeMarkupDocument reports whether the body opens like HTML, XML or JSON.
// A zone file starts with a prefix (or a comment), never with these, so this is
// a clearer diagnosis for the realistic failure — a captive portal or error page
// served in place of the feed — than the parser's per-line error. Comment and
// blank lines are ignored, as they are when parsing.
func looksLikeMarkupDocument(body []byte) bool {
	for _, raw := range bytes.Split(body, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if isIgnoredLine(line) {
			continue
		}
		lower := strings.ToLower(line)
		for _, prefix := range []string{"<!doctype", "<html", "<?xml", "<head", "<body", "{", "["} {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
		return false
	}
	return false
}

// distinctMaskedPrefixes returns the distinct masked prefixes of a list in the
// order they first appear. Declaration order and duplicate lines are not data.
func distinctMaskedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		canon := prefix.Masked()
		if _, exists := seen[canon]; exists {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon)
	}
	return out
}

// digestHex returns the SHA-256 of data in lowercase hex.
func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LoadInventory builds a shipped inventory from a data body and its provenance
// record, refusing either when the record does not describe the data or does not
// name the copyright notice that ships with it.
func LoadInventory(body, meta []byte) (*Inventory, error) {
	inv, err := InventoryFromBody(body)
	if err != nil {
		return nil, err
	}

	var prov InventoryProvenance
	if err := json.Unmarshal(meta, &prov); err != nil {
		return nil, fmt.Errorf("inventory provenance: %w", err)
	}
	if err := inv.adoptProvenance(prov); err != nil {
		return nil, err
	}
	return inv, nil
}

// adoptProvenance verifies a provenance record against the bytes that were
// actually parsed and, when it agrees, adopts it.
//
// The notice digest is checked here rather than left to a test: the
// redistribution terms require the notice to travel with the zone, and a record
// that does not describe the notice this build ships would let a future update
// replace or drop it unnoticed.
func (inv *Inventory) adoptProvenance(prov InventoryProvenance) error {
	if prov.SchemaVersion != InventorySchemaVersion || prov.Kind != InventoryKind {
		return fmt.Errorf("%w: schema %d kind %q is not the supported %d/%q",
			ErrInventoryProvenanceMismatch, prov.SchemaVersion, prov.Kind, InventorySchemaVersion, InventoryKind)
	}
	retrieved, err := prov.retrievedTime()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInventoryProvenanceMismatch, err)
	}
	if prov.PrefixCount != inv.shippedCount {
		return fmt.Errorf("%w: provenance records %d prefixes, committed data holds %d",
			ErrInventoryProvenanceMismatch, prov.PrefixCount, inv.shippedCount)
	}
	if prov.SHA256 != inv.prov.SHA256 {
		return fmt.Errorf("%w: provenance records digest %s, committed data hashes to %s",
			ErrInventoryProvenanceMismatch, prov.SHA256, inv.prov.SHA256)
	}
	if want := NoticeDigest(); prov.NoticeSHA256 != want {
		return fmt.Errorf("%w: provenance records notice digest %q, the shipped %s hashes to %s",
			ErrInventoryProvenanceMismatch, prov.NoticeSHA256, ShippedInventoryNoticeFile, want)
	}
	inv.prov = prov
	inv.retrieved = retrieved
	return nil
}

// NoticeDigest returns the SHA-256 of the shipped copyright notice.
func NoticeDigest() string {
	return digestHex(inventoryNotice)
}

var (
	shippedInventoryOnce sync.Once
	shippedInventory     *Inventory
	shippedInventoryErr  error
)

// ShippedInventory returns the committed Russian allocation inventory, parsed
// once per process.
//
// A returned error means the committed artifact is unusable: unparsable, or
// disagreeing with its provenance record. Callers must report it rather than
// treat the set as empty, because "the artifact is broken" and "no address is
// Russian" are different facts and only the second one is safe to act on.
//
// The returned value is immutable and safe to share; use WithOverride to obtain
// a resolved set that includes an operator override.
func ShippedInventory() (*Inventory, error) {
	shippedInventoryOnce.Do(func() {
		body, err := inventoryArtifacts.ReadFile("inventory/" + ShippedInventoryDataFile)
		if err != nil {
			shippedInventoryErr = fmt.Errorf("read committed inventory data: %w", err)
			return
		}
		meta, err := inventoryArtifacts.ReadFile("inventory/" + ShippedInventoryMetaFile)
		if err != nil {
			shippedInventoryErr = fmt.Errorf("read committed inventory provenance: %w", err)
			return
		}
		shippedInventory, shippedInventoryErr = LoadInventory(body, meta)
	})
	return shippedInventory, shippedInventoryErr
}

// Provenance returns the record describing this set: for the shipped set the
// committed record, and for a set built from a bare body the derived count and
// digest with the descriptive fields unset.
func (inv *Inventory) Provenance() InventoryProvenance {
	if inv == nil {
		return InventoryProvenance{}
	}
	return inv.prov
}

// PrefixCount returns the number of distinct prefixes in the shipped set.
func (inv *Inventory) PrefixCount() int {
	if inv == nil {
		return 0
	}
	return inv.shippedCount
}

// OverridePrefixCount returns the number of prefixes in the operator override.
func (inv *Inventory) OverridePrefixCount() int {
	if inv == nil {
		return 0
	}
	return inv.overrideCount
}

// Match reports whether addr is inside the Russian allocation and which set
// placed it there. The operator override takes precedence: an address in both
// sets is reported as override, because that is the set the operator chose.
//
// A false result means "not covered", which consumers must treat as the
// fail-safe proxy default rather than as "not Russian".
func (inv *Inventory) Match(addr netip.Addr) (InventorySource, bool) {
	if inv == nil {
		return "", false
	}
	if inv.override.match(addr) {
		return InventorySourceOverride, true
	}
	if inv.shipped.match(addr) {
		return InventorySourceShipped, true
	}
	return "", false
}

// InventoryStatus is the operator-facing view of the resolved inventory: where
// the committed set came from, how old it is, and whether an override is in
// force. It carries no client addresses.
type InventoryStatus struct {
	// Source names the feed that published the committed zone.
	Source string `json:"source,omitempty"`
	// SourceURL is where that zone was downloaded from.
	SourceURL string `json:"source_url,omitempty"`
	// RetrievedAt is the recorded retrieval date, YYYY-MM-DD.
	RetrievedAt string `json:"retrieved_at,omitempty"`
	// SHA256 is the digest of the committed data file.
	SHA256 string `json:"sha256,omitempty"`
	// PrefixCount is the number of distinct prefixes in the shipped set.
	PrefixCount int `json:"prefix_count"`
	// OverridePrefixCount is the number of operator override prefixes, which
	// take precedence over the shipped set. It is a count for that set only;
	// the two counts are not a partition, because an override may repeat a
	// shipped prefix.
	OverridePrefixCount int `json:"override_prefix_count"`
	// OverrideSHA256 is the digest of the operator override body, so a
	// deployment's override is distinguishable from the shipped set by content
	// and not only by a count. Empty when no override is in force.
	OverrideSHA256 string `json:"override_sha256,omitempty"`
	// AgeDays is the whole number of days since the recorded retrieval date.
	AgeDays int `json:"age_days"`
	// MaxAgeDays is the staleness threshold in days.
	MaxAgeDays int `json:"max_age_days"`
	// Stale reports whether the artifact has exceeded that threshold.
	Stale bool `json:"stale"`
	// Error reports an unusable artifact. The counts and dates are then zero
	// or absent, and consumers must not read them as an empty set.
	Error string `json:"error,omitempty"`
}

// Status reports the inventory's age and provenance at now. maxAge is the
// staleness threshold; a non-positive value falls back to
// DefaultInventoryMaxAge.
func (inv *Inventory) Status(now time.Time, maxAge time.Duration) InventoryStatus {
	if maxAge <= 0 {
		maxAge = DefaultInventoryMaxAge
	}
	status := InventoryStatus{
		MaxAgeDays: days(maxAge),
	}
	if inv == nil {
		return status
	}
	status.Source = inv.prov.Source
	status.SourceURL = inv.prov.SourceURL
	status.RetrievedAt = inv.prov.RetrievedAt
	status.SHA256 = inv.prov.SHA256
	status.PrefixCount = inv.shippedCount
	status.OverridePrefixCount = inv.overrideCount
	status.OverrideSHA256 = inv.overrideHash
	if inv.retrieved.IsZero() {
		return status
	}
	age := now.Sub(inv.retrieved)
	if age < 0 {
		// A retrieval date in the future is clock skew or a typo, not a
		// negative age. Report zero and let the provenance date speak for
		// itself rather than manufacturing freshness arithmetic.
		age = 0
	}
	status.AgeDays = days(age)
	status.Stale = age > maxAge
	return status
}

// days converts a duration to whole days.
func days(d time.Duration) int {
	return int(d / (24 * time.Hour))
}

// InventoryDataPath returns the committed data file path inside dir, so the
// maintenance tool writes exactly the file the loader embeds.
func InventoryDataPath(dir string) string {
	return filepath.Join(dir, ShippedInventoryDataFile)
}

// InventoryMetaPath returns the committed provenance file path inside dir.
func InventoryMetaPath(dir string) string {
	return filepath.Join(dir, ShippedInventoryMetaFile)
}
