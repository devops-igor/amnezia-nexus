package main

import (
	"bytes"
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
	out, err := runTool(t, zone(1200), "-dir "+dir+" -url https://example.invalid/ru.zone -retrieved 2026-11-19")
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
	if got := inv.Provenance(); got.SourceURL != "https://example.invalid/ru.zone" || got.Source != "ipdeny" {
		t.Fatalf("provenance = %+v, want the invocation's source and URL", got)
	}
}

func TestRunRejectsNonPrefixBodyAndKeepsArtifact(t *testing.T) {
	dir := t.TempDir()
	args := "-dir " + dir + " -url https://example.invalid/ru.zone -retrieved 2026-11-19"
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
	out, err := runTool(t, zone(1200), "-dir "+dir+" -url https://example.invalid/ru.zone -retrieved 2026-11-19 -dry-run")
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
	if _, err := runTool(t, zone(1200), "-dir "+dir+" -retrieved 2026-11-19"); err == nil {
		t.Fatal("run accepted an invocation with no source URL")
	}
	if _, err := runTool(t, zone(1200), "-dir "+dir+" -url https://example.invalid/ru.zone"); err == nil {
		t.Fatal("run accepted an invocation with no retrieval date")
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	if _, err := runTool(t, zone(1200), "-url https://example.invalid/ru.zone -retrieved 2026-11-19 ru.zone"); err == nil {
		t.Fatal("run accepted a file argument instead of reading stdin")
	}
}
