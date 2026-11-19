package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// These tests assert on the committed artifact that ships in the build. They
// never touch the network: the data file is read from the working tree, which is
// the same byte range the loader embeds, so a bad artifact fails here before it
// can fail in a deployment.

// committedInventoryData reads the reviewed data file from the working tree.
func committedInventoryData(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(InventoryDataPath("inventory"))
	if err != nil {
		t.Fatalf("read committed inventory data: %v", err)
	}
	return data
}

// committedInventoryMeta reads the reviewed provenance file from the working tree.
func committedInventoryMeta(t *testing.T) []byte {
	t.Helper()
	meta, err := os.ReadFile(InventoryMetaPath("inventory"))
	if err != nil {
		t.Fatalf("read committed inventory provenance: %v", err)
	}
	return meta
}

// dataLines returns the non-comment, non-blank lines of a zone body.
func dataLines(body []byte) []string {
	out := make([]string, 0, 1024)
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if isIgnoredLine(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// syntheticZone renders count distinct, canonical /24 prefixes from 10.0.0.0.
func syntheticZone(count int) []byte {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24\n", i/256, i%256)
	}
	return []byte(b.String())
}

// mustShippedInventory returns the committed inventory or fails the test.
func mustShippedInventory(t *testing.T) *Inventory {
	t.Helper()
	inv, err := ShippedInventory()
	if err != nil {
		t.Fatalf("ShippedInventory: %v", err)
	}
	return inv
}

func TestCommittedInventoryEveryLineIsAPrefix(t *testing.T) {
	lines := dataLines(committedInventoryData(t))
	if len(lines) < MinInventoryPrefixes {
		t.Fatalf("committed inventory holds %d prefixes, want at least %d", len(lines), MinInventoryPrefixes)
	}

	for i, line := range lines {
		prefix, err := ParseIPv4Rule(line)
		if err != nil {
			t.Fatalf("line %d %q does not parse as a CIDR prefix: %v", i+1, line, err)
		}
		if prefix.String() != line {
			t.Fatalf("line %d %q is not canonical CIDR notation (would normalize to %q)", i+1, line, prefix.String())
		}
	}

	inv := mustShippedInventory(t)
	if inv.PrefixCount() != len(lines) {
		t.Fatalf("loaded prefix count %d, committed data holds %d lines", inv.PrefixCount(), len(lines))
	}

	prov := inv.Provenance()
	if prov.PrefixCount != len(lines) {
		t.Fatalf("provenance records %d prefixes, data holds %d", prov.PrefixCount, len(lines))
	}
	if prov.Source == "" || prov.SourceURL == "" {
		t.Fatalf("provenance does not record a source and URL: %+v", prov)
	}
	if _, err := time.Parse(time.DateOnly, prov.RetrievedAt); err != nil {
		t.Fatalf("provenance retrieval date %q is not YYYY-MM-DD: %v", prov.RetrievedAt, err)
	}
	if len(prov.SHA256) != 64 {
		t.Fatalf("provenance digest %q is not a SHA-256 hex string", prov.SHA256)
	}
}

// The classification this inventory exists for: Yandex is originated by a
// Serbian-registered network, so a country-of-origin lookup reports Serbia. Only
// allocation membership answers "inside the Russian allocation" correctly.
func TestShippedInventoryClassifiesRussianAllocation(t *testing.T) {
	inv := mustShippedInventory(t)
	cases := []struct {
		addr string
		want bool
		note string
	}{
		{"77.88.55.88", true, "yandex.ru, embedded ASN table reports RS"},
		{"87.250.250.242", true, "yandex.ru second address"},
		{"213.180.204.186", true, "music.yandex.ru"},
		{"185.73.194.82", true, "ozon.ru"},
		{"87.240.132.74", true, "vk.com"},
		{"94.100.180.201", true, "mail.ru"},
		{"194.54.14.131", true, "sber.ru"},
		{"1.1.1.1", false, "Cloudflare"},
		{"8.8.8.8", false, "Google public DNS"},
		{"142.251.146.6", false, "Google address from the live diagnosis"},
		{"147.91.1.1", false, "Serbian control"},
	}
	for _, c := range cases {
		t.Run(strings.ReplaceAll(c.addr, ".", "_"), func(t *testing.T) {
			source, got := inv.Match(netip.MustParseAddr(c.addr))
			if got != c.want {
				t.Fatalf("Match(%s) = %v, want %v (%s)", c.addr, got, c.want, c.note)
			}
			if got && source != InventorySourceShipped {
				t.Fatalf("Match(%s) source = %q, want %q", c.addr, source, InventorySourceShipped)
			}
			if !got && source != "" {
				t.Fatalf("Match(%s) source = %q on a miss, want empty", c.addr, source)
			}
		})
	}
}

// The shipped set is about 8,700 prefixes, which is why it cannot travel the
// operator local-entry path. This proves both halves: the loader accepts and
// matches the whole set, and the capped path still refuses it (the cap was
// bypassed, not raised).
func TestCommittedInventoryLoadsWholeSetBeyondLocalEntryCap(t *testing.T) {
	inv := mustShippedInventory(t)
	if inv.PrefixCount() <= 4096 {
		t.Fatalf("committed inventory holds %d prefixes; the 4096-prefix local-entry cap is no longer the reason for this path", inv.PrefixCount())
	}

	for _, line := range dataLines(committedInventoryData(t)) {
		prefix, err := ParseIPv4Rule(line)
		if err != nil {
			t.Fatalf("prefix %q: %v", line, err)
		}
		if _, ok := inv.Match(prefix.Addr()); !ok {
			t.Fatalf("committed prefix %s is not matched by the loaded set", prefix)
		}
	}

	if _, _, err := ParseLocalRules(dataLines(committedInventoryData(t))); err == nil {
		t.Fatal("ParseLocalRules accepted the shipped inventory; the operator local-entry cap is not enforced")
	}
}

func TestInventoryBodyRejectionControls(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"captive_portal_html", []byte("<!DOCTYPE html>\n<html><head><title>Sign in</title></head><body>Please log in to continue</body></html>\n")},
		{"plain_prose", []byte("This network requires authentication before you can reach the internet.\n")},
		{"json_error_document", []byte("{\"error\":\"rate limited\",\"retry_after\":60}\n")},
		{"empty", []byte("")},
		{"whitespace_only", []byte(" \n\t\n")},
		{"one_bad_line", append(syntheticZone(1100), []byte("not-a-prefix\n")...)},
		{"non_canonical_host_bits", append(syntheticZone(1100), []byte("77.88.55.88/18\n")...)},
		{"truncated_below_floor", syntheticZone(100)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := InventoryFromBody(c.body); !errors.Is(err, ErrInventoryNotPrefixList) {
				t.Fatalf("InventoryFromBody error = %v, want %v", err, ErrInventoryNotPrefixList)
			}
		})
	}

	// The offending line is named, so an operator can find it in the download.
	_, err := InventoryFromBody(append(syntheticZone(1100), []byte("not-a-prefix\n")...))
	if err == nil || !strings.Contains(err.Error(), "line 1101") {
		t.Fatalf("error %v does not name line 1101", err)
	}

	// A prefix whose host bits are set is refused rather than committed and then
	// masked at load: the file a reviewer reads must be the file that routes.
	_, err = InventoryFromBody(append(syntheticZone(1100), []byte("77.88.55.88/18\n")...))
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("error %v does not report a non-canonical prefix", err)
	}
}

func TestCommittedInventoryProvenanceIsVerified(t *testing.T) {
	body := committedInventoryData(t)
	meta := committedInventoryMeta(t)
	if _, err := LoadInventory(body, meta); err != nil {
		t.Fatalf("committed artifact does not load: %v", err)
	}

	mutations := map[string]func(*InventoryProvenance){
		"prefix_count": func(p *InventoryProvenance) { p.PrefixCount++ },
		"digest":       func(p *InventoryProvenance) { p.SHA256 = strings.Repeat("0", 64) },
		"schema":       func(p *InventoryProvenance) { p.SchemaVersion = 99 },
		"kind":         func(p *InventoryProvenance) { p.Kind = "some_other_list" },
		"date":         func(p *InventoryProvenance) { p.RetrievedAt = "19.11.2026" },
		"no_date":      func(p *InventoryProvenance) { p.RetrievedAt = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var prov InventoryProvenance
			if err := json.Unmarshal(meta, &prov); err != nil {
				t.Fatalf("unmarshal provenance: %v", err)
			}
			mutate(&prov)
			tampered, err := json.Marshal(prov)
			if err != nil {
				t.Fatalf("marshal provenance: %v", err)
			}
			if _, err := LoadInventory(body, tampered); !errors.Is(err, ErrInventoryProvenanceMismatch) {
				t.Fatalf("LoadInventory error = %v, want %v", err, ErrInventoryProvenanceMismatch)
			}
		})
	}

	// A body that lost its last line no longer matches the record either.
	truncated := bytes.TrimSuffix(bytes.TrimSuffix(body, []byte("\n")), []byte("\n"))
	if _, err := LoadInventory(truncated, meta); !errors.Is(err, ErrInventoryProvenanceMismatch) {
		t.Fatalf("truncated body error = %v, want %v", err, ErrInventoryProvenanceMismatch)
	}

	if _, err := LoadInventory(body, nil); err == nil {
		t.Fatal("LoadInventory accepted a missing provenance record")
	}
}

func TestRejectedUpdateLeavesCommittedArtifactIntact(t *testing.T) {
	dir := t.TempDir()
	prov := InventoryProvenance{
		Source:      "ipdeny",
		SourceURL:   "https://example.invalid/ru-aggregated.zone",
		RetrievedAt: "2026-11-19",
	}
	good := syntheticZone(1200)
	record, meta, err := ValidateInventoryUpdate(good, prov)
	if err != nil {
		t.Fatalf("ValidateInventoryUpdate: %v", err)
	}
	if record.PrefixCount != 1200 || record.SHA256 != digestHex(good) {
		t.Fatalf("derived provenance = %+v, want 1200 prefixes and the body digest", record)
	}
	if err := WriteInventoryArtifact(dir, good, meta); err != nil {
		t.Fatalf("WriteInventoryArtifact: %v", err)
	}
	seededData, err := os.ReadFile(InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read written data: %v", err)
	}
	seededMeta, err := os.ReadFile(InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read written provenance: %v", err)
	}

	// The tool validates before it writes, so a rejected body never reaches
	// WriteInventoryArtifact. This is that sequence with a captive-portal body.
	if _, _, err := ValidateInventoryUpdate([]byte("<!DOCTYPE html><html>Login</html>"), prov); !errors.Is(err, ErrInventoryNotPrefixList) {
		t.Fatalf("ValidateInventoryUpdate error = %v, want %v", err, ErrInventoryNotPrefixList)
	}
	afterData, err := os.ReadFile(InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read data after rejected update: %v", err)
	}
	afterMeta, err := os.ReadFile(InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read provenance after rejected update: %v", err)
	}
	if !bytes.Equal(seededData, afterData) || !bytes.Equal(seededMeta, afterMeta) {
		t.Fatal("a rejected update modified the committed artifact")
	}

	inv, err := LoadInventory(afterData, afterMeta)
	if err != nil {
		t.Fatalf("artifact does not load after the rejected update: %v", err)
	}
	if inv.PrefixCount() != 1200 {
		t.Fatalf("committed inventory holds %d prefixes after the rejected update, want 1200", inv.PrefixCount())
	}
}

// The two committed files are replaced by separate renames, so an interrupted
// update can leave new data beside the previous provenance record. This is the
// failure the atomicity comments describe: the loader refuses that pair rather
// than serving it, and one re-run of the tool writes both files from one
// matching generation.
func TestMixedInventoryPairIsRefusedAndRerunRestoresCoherence(t *testing.T) {
	dir := t.TempDir()
	prov := InventoryProvenance{
		Source:      "ipdeny",
		SourceURL:   "https://example.invalid/ru-aggregated.zone",
		RetrievedAt: "2026-11-19",
	}
	first := syntheticZone(1200)
	_, firstMeta, err := ValidateInventoryUpdate(first, prov)
	if err != nil {
		t.Fatalf("ValidateInventoryUpdate: %v", err)
	}
	if err := WriteInventoryArtifact(dir, first, firstMeta); err != nil {
		t.Fatalf("WriteInventoryArtifact: %v", err)
	}

	// Only the data file is replaced, as if the first rename succeeded and the
	// process died before the second.
	second := syntheticZone(1201)
	if err := os.WriteFile(InventoryDataPath(dir), second, 0o600); err != nil {
		t.Fatalf("simulate the interrupted update: %v", err)
	}
	mixedData, err := os.ReadFile(InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read mixed data: %v", err)
	}
	mixedMeta, err := os.ReadFile(InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read mixed provenance: %v", err)
	}
	if _, err := LoadInventory(mixedData, mixedMeta); !errors.Is(err, ErrInventoryProvenanceMismatch) {
		t.Fatalf("mixed pair error = %v, want %v", err, ErrInventoryProvenanceMismatch)
	}

	// Re-running the tool is the documented recovery: both files come from one
	// generation, so the pair is coherent again.
	record, rerunMeta, err := ValidateInventoryUpdate(second, prov)
	if err != nil {
		t.Fatalf("ValidateInventoryUpdate on re-run: %v", err)
	}
	if err := WriteInventoryArtifact(dir, second, rerunMeta); err != nil {
		t.Fatalf("WriteInventoryArtifact on re-run: %v", err)
	}
	recoveredData, err := os.ReadFile(InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read recovered data: %v", err)
	}
	recoveredMeta, err := os.ReadFile(InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read recovered provenance: %v", err)
	}
	recovered, err := LoadInventory(recoveredData, recoveredMeta)
	if err != nil {
		t.Fatalf("re-running the tool did not restore a coherent pair: %v", err)
	}
	if recovered.PrefixCount() != record.PrefixCount || recovered.PrefixCount() != 1201 {
		t.Fatalf("recovered inventory holds %d prefixes, want 1201", recovered.PrefixCount())
	}
}

func TestWriteInventoryArtifactRequiresWritableDirectory(t *testing.T) {
	err := WriteInventoryArtifact(os.TempDir()+"/does-not-exist-919/inventory", []byte("10.0.0.0/8\n"), []byte("{}"))
	if err == nil {
		t.Fatal("WriteInventoryArtifact accepted an unwritable directory")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("WriteInventoryArtifact error = %v, want a not-exist error", err)
	}
}

func TestValidateInventoryUpdateRequiresProvenanceSource(t *testing.T) {
	if _, _, err := ValidateInventoryUpdate(syntheticZone(1200), InventoryProvenance{RetrievedAt: "2026-11-19"}); err == nil {
		t.Fatal("ValidateInventoryUpdate accepted a provenance record with no source or URL")
	}
	if _, _, err := ValidateInventoryUpdate(syntheticZone(1200), InventoryProvenance{Source: "ipdeny", SourceURL: "https://example.invalid/x"}); err == nil {
		t.Fatal("ValidateInventoryUpdate accepted a provenance record with no retrieval date")
	}
}

func TestInventoryStatusReportsAgeAndStaleness(t *testing.T) {
	inv := mustShippedInventory(t)
	prov := inv.Provenance()
	retrieved, err := time.Parse(time.DateOnly, prov.RetrievedAt)
	if err != nil {
		t.Fatalf("parse retrieval date: %v", err)
	}

	fresh := inv.Status(retrieved.Add(24*time.Hour), DefaultInventoryMaxAge)
	if fresh.AgeDays != 1 || fresh.Stale {
		t.Fatalf("status one day after retrieval = %+v, want age 1 and not stale", fresh)
	}
	if fresh.Source != prov.Source || fresh.SourceURL != prov.SourceURL || fresh.RetrievedAt != prov.RetrievedAt {
		t.Fatalf("status provenance = %+v, want %+v", fresh, prov)
	}
	if fresh.PrefixCount != inv.PrefixCount() || fresh.SHA256 != prov.SHA256 {
		t.Fatalf("status counts = %+v, want the shipped set's", fresh)
	}
	if fresh.MaxAgeDays != int(DefaultInventoryMaxAge/(24*time.Hour)) {
		t.Fatalf("MaxAgeDays = %d, want %d", fresh.MaxAgeDays, int(DefaultInventoryMaxAge/(24*time.Hour)))
	}

	stale := inv.Status(retrieved.Add(200*24*time.Hour), DefaultInventoryMaxAge)
	if stale.AgeDays != 200 || !stale.Stale {
		t.Fatalf("status 200 days after retrieval = %+v, want age 200 and stale", stale)
	}

	skewed := inv.Status(retrieved.Add(-48*time.Hour), DefaultInventoryMaxAge)
	if skewed.AgeDays != 0 || skewed.Stale {
		t.Fatalf("status with a future retrieval date = %+v, want age 0 and not stale", skewed)
	}

	fallback := inv.Status(retrieved, 0)
	if fallback.MaxAgeDays != int(DefaultInventoryMaxAge/(24*time.Hour)) {
		t.Fatalf("MaxAgeDays with a zero threshold = %d, want the default", fallback.MaxAgeDays)
	}
}

// An operator override must win over the committed set and must be visibly
// distinguishable from it in the reported status.
func TestOperatorOverrideTakesPrecedenceOverCommittedSet(t *testing.T) {
	shipped := mustShippedInventory(t)
	overrideOnly := netip.MustParsePrefix("203.0.113.0/24")
	overrideBody := []byte("203.0.113.0/24\n77.88.0.0/16\n")
	override, err := ParseInventoryOverride(overrideBody)
	if err != nil {
		t.Fatalf("ParseInventoryOverride: %v", err)
	}
	if override.PrefixCount() != 2 {
		t.Fatalf("override prefix count = %d, want 2", override.PrefixCount())
	}

	resolved := shipped.WithOverride(override)

	if source, ok := resolved.Match(overrideOnly.Addr().Next()); !ok || source != InventorySourceOverride {
		t.Fatalf("Match(override-only address) = (%q, %v), want (%q, true)", source, ok, InventorySourceOverride)
	}
	// Present in both sets: the operator's set is what answers.
	if source, ok := resolved.Match(netip.MustParseAddr("77.88.55.88")); !ok || source != InventorySourceOverride {
		t.Fatalf("Match(shipped+override) = (%q, %v), want (%q, true)", source, ok, InventorySourceOverride)
	}
	// Shipped only: still answered by the shipped set.
	if source, ok := resolved.Match(netip.MustParseAddr("87.240.132.74")); !ok || source != InventorySourceShipped {
		t.Fatalf("Match(shipped-only) = (%q, %v), want (%q, true)", source, ok, InventorySourceShipped)
	}
	if source, ok := resolved.Match(netip.MustParseAddr("1.1.1.1")); ok || source != "" {
		t.Fatalf("Match(uncovered) = (%q, %v), want (\"\", false)", source, ok)
	}

	// The cached shipped set is not mutated by resolving an override.
	if _, ok := shipped.Match(overrideOnly.Addr().Next()); ok {
		t.Fatal("WithOverride mutated the shipped inventory")
	}

	status := resolved.Status(time.Now().UTC(), DefaultInventoryMaxAge)
	if resolved.OverridePrefixCount() != 2 {
		t.Fatalf("OverridePrefixCount() = %d, want 2", resolved.OverridePrefixCount())
	}
	if status.OverridePrefixCount != 2 {
		t.Fatalf("OverridePrefixCount = %d, want 2", status.OverridePrefixCount)
	}
	if status.OverrideSHA256 != override.Digest() || status.OverrideSHA256 == "" {
		t.Fatalf("OverrideSHA256 = %q, want the override body digest", status.OverrideSHA256)
	}
	if status.SHA256 == status.OverrideSHA256 {
		t.Fatal("status reports the same digest for the shipped and override sets")
	}
	if status.PrefixCount != shipped.PrefixCount() {
		t.Fatalf("PrefixCount = %d, want the shipped count %d", status.PrefixCount, shipped.PrefixCount())
	}
}

func TestParseInventoryOverrideControls(t *testing.T) {
	mixed := []byte("example.com\n198.51.100.0/24\n")
	override, err := ParseInventoryOverride(mixed)
	if err != nil {
		t.Fatalf("mixed-format override rejected: %v", err)
	}
	if override.PrefixCount() != 1 {
		t.Fatalf("mixed-format override prefix count = %d, want 1", override.PrefixCount())
	}
	if override.DomainRuleCount() != 1 {
		t.Fatalf("mixed-format domain rule count = %d, want 1", override.DomainRuleCount())
	}

	rejected := map[string][]byte{
		"empty":            []byte(""),
		"domains_only":     []byte("example.com\nexample.org\n"),
		"html_document":    []byte("<html><body>nope</body></html>\n"),
		"invalid_prefix":   []byte("198.51.100.0/24\nnot-a-prefix\n"),
		"ipv6_prefix_only": []byte("2001:db8::/32\n"),
	}
	for name, body := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInventoryOverride(body); err == nil {
				t.Fatalf("ParseInventoryOverride accepted %q", string(body))
			}
		})
	}
}
