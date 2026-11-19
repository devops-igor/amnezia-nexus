package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// zone renders count distinct /24 prefixes, enough to clear the country-set
// floor the validator enforces.
func zone(count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24\n", i/256, i%256)
	}
	return b.String()
}

// runTool invokes the command's own entry point with a body on stdin.
func runTool(t *testing.T, body, args string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	err := run(strings.NewReader(body), &stdout, strings.Fields(args))
	return stdout.String(), err
}

func TestRunWritesValidatedArtifact(t *testing.T) {
	dir := t.TempDir()
	out, err := runTool(t, zone(1200), "-dir "+dir+" -url https://example.invalid/ru.zone -retrieved 2026-11-19 -allow-large-reduction")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"prefix_count: 1200", "sha256: ", "source: ipdeny", "retrieved_at: 2026-11-19"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output does not contain %q:\n%s", want, out)
		}
	}

	data, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read written data: %v", err)
	}
	meta, err := os.ReadFile(policy.InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read written provenance: %v", err)
	}
	inv, err := policy.LoadInventory(data, meta)
	if err != nil {
		t.Fatalf("written artifact does not load: %v", err)
	}
	if inv.PrefixCount() != 1200 {
		t.Fatalf("loaded %d prefixes, want 1200", inv.PrefixCount())
	}
	got := inv.Provenance()
	if got.SourceURL != "https://example.invalid/ru.zone" || got.Source != "ipdeny" {
		t.Fatalf("provenance = %+v, want the invocation's source and URL", got)
	}
	if got.NoticeFile != policy.ShippedInventoryNoticeFile || got.NoticeSHA256 != policy.NoticeDigest() {
		t.Fatalf("provenance does not record the shipped notice: file %q digest %q", got.NoticeFile, got.NoticeSHA256)
	}
	for _, want := range []string{"notice: Copyrights.txt ", "previous_prefix_count: "} {
		if !strings.Contains(out, want) {
			t.Fatalf("output does not contain %q:\n%s", want, out)
		}
	}
}

func TestRunRejectsNonPrefixBodyAndKeepsArtifact(t *testing.T) {
	dir := t.TempDir()
	args := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19 -allow-large-reduction"
	if _, err := runTool(t, zone(1200), args); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	seeded, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read seeded data: %v", err)
	}

	_, err = runTool(t, "<!DOCTYPE html><html><body>Hotel Wi-Fi login</body></html>", args)
	if err == nil {
		t.Fatal("run accepted a captive-portal body")
	}
	if !errors.Is(err, policy.ErrInventoryNotPrefixList) {
		t.Fatalf("error = %v, want %v", err, policy.ErrInventoryNotPrefixList)
	}
	if !strings.Contains(err.Error(), "committed inventory left unchanged") {
		t.Fatalf("error %q does not tell the operator the artifact was kept", err)
	}

	after, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read data after rejected run: %v", err)
	}
	if !bytes.Equal(seeded, after) {
		t.Fatal("a rejected run modified the committed data")
	}
}

func TestRunDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	out, err := runTool(t, zone(1200), "-dir "+dir+" -url https://example.invalid/ru.zone -retrieved 2026-11-19 -dry-run -allow-large-reduction")
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(out, "dry_run: true") {
		t.Fatalf("dry run output does not say nothing was written:\n%s", out)
	}
	if _, err := os.Stat(policy.InventoryDataPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run created the data file: %v", err)
	}
	if _, err := os.Stat(policy.InventoryMetaPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run created the provenance file: %v", err)
	}
}

func TestRunRequiresProvenance(t *testing.T) {
	dir := t.TempDir()
	if _, err := runTool(t, zone(1200), "-dir "+dir+" -retrieved 2026-11-19 -allow-large-reduction"); err == nil {
		t.Fatal("run accepted an invocation with no source URL")
	}
	if _, err := runTool(t, zone(1200), "-dir "+dir+" -url https://example.invalid/ru.zone -allow-large-reduction"); err == nil {
		t.Fatal("run accepted an invocation with no retrieval date")
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	if _, err := runTool(t, zone(1200), "-url https://example.invalid/ru.zone -retrieved 2026-11-19 ru.zone"); err == nil {
		t.Fatal("run accepted a file argument instead of reading stdin")
	}
}

// A well formed but truncated feed clears the absolute floor, so the command
// compares against the artifact it is about to replace and refuses a large
// reduction unless the operator asked for one.
func TestRunRefusesTruncatedFeedWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	base := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19"

	// The fresh directory holds no record, so this seed is compared against the
	// committed set this build ships and needs the explicit decision.
	if _, err := runTool(t, zone(3000), base+" -allow-large-reduction"); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	seeded, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read seeded data: %v", err)
	}

	// 1,200 clears the 1,024 floor but is below half of 3,000: refused, and the
	// message carries both counts and the flag that overrides it.
	_, err = runTool(t, zone(1200), base)
	if !errors.Is(err, policy.ErrInventoryLargeReduction) {
		t.Fatalf("error = %v, want %v", err, policy.ErrInventoryLargeReduction)
	}
	for _, want := range []string{"1200", "3000", "-" + policy.InventoryLargeReductionFlag} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q does not name %q", err, want)
		}
	}
	if !strings.Contains(err.Error(), "committed inventory left unchanged") {
		t.Fatalf("message %q does not tell the operator the artifact was kept", err)
	}
	after, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read data after refused run: %v", err)
	}
	if !bytes.Equal(seeded, after) {
		t.Fatal("a refused run modified the committed data")
	}

	// The same body is accepted as an explicit maintenance decision.
	if _, err := runTool(t, zone(1200), base+" -allow-large-reduction"); err != nil {
		t.Fatalf("large reduction with the flag: %v", err)
	}
}

// The count compared against is the artifact in the target directory, not the
// set compiled into this build: 1,800 is below half of the shipped 8,664 but
// above half of the 3,000 in this directory.
func TestRunUsesDirectoryArtifactAsBaseline(t *testing.T) {
	dir := t.TempDir()
	base := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19"
	if _, err := runTool(t, zone(3000), base+" -allow-large-reduction"); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	if _, err := runTool(t, zone(1800), base); err != nil {
		t.Fatalf("1800 prefixes over a 3000-prefix artifact should be accepted: %v", err)
	}
	// A genuine growth needs no flag.
	if _, err := runTool(t, zone(2000), base); err != nil {
		t.Fatalf("a growing feed was refused: %v", err)
	}
}

// A damaged provenance record must not disable the truncation guard: the count
// can be measured from the committed data file, which is the file the update
// would replace.
func TestRunUsesDataFileWhenRecordIsDamaged(t *testing.T) {
	dir := t.TempDir()
	base := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19"
	if _, err := runTool(t, zone(3000), base+" -allow-large-reduction"); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	seeded, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read seeded data: %v", err)
	}
	if err := os.WriteFile(policy.InventoryMetaPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("damage the record: %v", err)
	}

	_, err = runTool(t, zone(1200), base)
	if !errors.Is(err, policy.ErrInventoryLargeReduction) {
		t.Fatalf("error = %v, want %v", err, policy.ErrInventoryLargeReduction)
	}
	for _, want := range []string{"1200", "3000", "-" + policy.InventoryLargeReductionFlag} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q does not name %q", err, want)
		}
	}
	after, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read data after the refused run: %v", err)
	}
	if !bytes.Equal(seeded, after) {
		t.Fatal("a refused run modified the committed data")
	}
}

// When neither the record nor the data file yields a count, the run is refused
// with the artifact left exactly as it was: the guard is never skipped for want
// of a baseline.
func TestRunRefusesWhenNoBaselineCanBeEstablished(t *testing.T) {
	dir := t.TempDir()
	base := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19"
	if _, err := runTool(t, zone(3000), base+" -allow-large-reduction"); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if err := os.WriteFile(policy.InventoryMetaPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("damage the record: %v", err)
	}
	broken := []byte("not a prefix list\n")
	if err := os.WriteFile(policy.InventoryDataPath(dir), broken, 0o600); err != nil {
		t.Fatalf("damage the data file: %v", err)
	}

	_, err := runTool(t, zone(1200), base)
	if !errors.Is(err, policy.ErrInventoryBaselineUnavailable) {
		t.Fatalf("error = %v, want %v", err, policy.ErrInventoryBaselineUnavailable)
	}
	if !strings.Contains(err.Error(), "committed inventory left unchanged") {
		t.Fatalf("message %q does not tell the operator the artifact was kept", err)
	}
	after, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read data after the refused run: %v", err)
	}
	if !bytes.Equal(broken, after) {
		t.Fatal("a refused run replaced the damaged data file")
	}
	record, err := os.ReadFile(policy.InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read record after the refused run: %v", err)
	}
	if string(record) != "{not json" {
		t.Fatalf("a refused run replaced the damaged record: %q", record)
	}
}

// rewriteRecordCount makes the committed record claim a different prefix count
// while staying valid JSON: the state an interrupted update leaves when it renamed
// only one of the two files.
func rewriteRecordCount(t *testing.T, dir string, count int) {
	t.Helper()
	meta, err := os.ReadFile(policy.InventoryMetaPath(dir))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}
	var prov policy.InventoryProvenance
	if err := json.Unmarshal(meta, &prov); err != nil {
		t.Fatalf("unmarshal the record: %v", err)
	}
	prov.PrefixCount = count
	rewritten, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		t.Fatalf("marshal the record: %v", err)
	}
	if err := os.WriteFile(policy.InventoryMetaPath(dir), append(rewritten, '\n'), 0o600); err != nil {
		t.Fatalf("write the record: %v", err)
	}
}

// The recorded count must never set the baseline: a record understating the data
// would otherwise let a feed truncated to exactly that number look like no
// reduction. The measured data decides, and a disagreement is reported.
func TestRunIgnoresARecordThatUnderstatesTheData(t *testing.T) {
	dir := t.TempDir()
	base := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19"

	// Seed 8,664 prefixes. The fresh directory has no data file, so the baseline
	// is the shipped set and an equal count needs no flag.
	if _, err := runTool(t, zone(8664), base); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	seeded, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read seeded data: %v", err)
	}
	rewriteRecordCount(t, dir, 1200)

	// A 1,200-prefix replacement, which the record alone would call no reduction.
	_, err = runTool(t, zone(1200), base)
	if !errors.Is(err, policy.ErrInventoryLargeReduction) {
		t.Fatalf("error = %v, want %v", err, policy.ErrInventoryLargeReduction)
	}
	for _, want := range []string{"1200", "8664", "-" + policy.InventoryLargeReductionFlag} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q does not name %q", err, want)
		}
	}
	after, err := os.ReadFile(policy.InventoryDataPath(dir))
	if err != nil {
		t.Fatalf("read data after the refused run: %v", err)
	}
	if !bytes.Equal(seeded, after) {
		t.Fatal("a refused run modified the committed data")
	}

	// The explicit decision applies it, and the run reports the disagreement it
	// is repairing.
	out, err := runTool(t, zone(1200), base+" -allow-large-reduction")
	if err != nil {
		t.Fatalf("large reduction with the flag: %v", err)
	}
	for _, want := range []string{"previous_prefix_count: 8664", "recorded_prefix_count: 1200", "the measured count decides"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output does not contain %q:\n%s", want, out)
		}
	}
}
