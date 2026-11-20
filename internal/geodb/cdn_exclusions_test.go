package geodb

// The CDN exclusion surface (issue #934) reports the set the classifier
// consults, so an operator can answer why a destination inside the Russian
// allocation was proxied anyway.
//
// These tests pin the property that makes the surface trustworthy from both
// directions: the accessor follows the live table (it cannot become a copy), and
// no second enumeration of the excluded networks exists in shipped code (two
// lists drift, and an operator would then read the wrong one).

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// cdnTableFile is the one file allowed to enumerate the excluded networks: the
// declaration the classifier, IsMultiRegionCDNASN and CDNExclusions all read.
const cdnTableFile = "internal/geodb/geodb.go"

func TestCDNExclusionsAreTheClassifierTable(t *testing.T) {
	entries, err := CDNExclusions()
	if err != nil {
		t.Fatalf("CDNExclusions: %v", err)
	}
	if len(entries) != len(KnownCDNASNs) {
		t.Fatalf("CDNExclusions reported %d entries, the classifier table holds %d", len(entries), len(KnownCDNASNs))
	}
	for i, entry := range entries {
		provider, known := KnownCDNASNs[entry.ASN]
		if !known || provider != entry.Provider {
			t.Errorf("entry %d reports AS%d %q, but the table says %q (present=%v)", i, entry.ASN, entry.Provider, provider, known)
		}
		// The classifier's own predicate must agree with every reported entry;
		// otherwise the surface describes a rule the packet path does not apply.
		if !IsMultiRegionCDNASN(entry.ASN) {
			t.Errorf("AS%d is reported as excluded, but IsMultiRegionCDNASN does not exclude it", entry.ASN)
		}
		if i > 0 && entries[i-1].ASN >= entry.ASN {
			t.Errorf("entries are not in ascending ASN order: AS%d precedes AS%d", entries[i-1].ASN, entry.ASN)
		}
	}
}

// TestCDNExclusionsFollowTheTable is the anti-copy assertion. A new entry in the
// table must reach the surface without anyone editing the accessor; a second,
// hardcoded list would silently keep reporting the old set.
func TestCDNExclusionsFollowTheTable(t *testing.T) {
	const probeASN = 64512
	const probeProvider = "Test Provider"
	// The probe is added and removed within this test, and no other test in this
	// package reads the table concurrently, so the classifier's own view is
	// unchanged by the time this function returns.
	KnownCDNASNs[probeASN] = probeProvider
	defer delete(KnownCDNASNs, probeASN)

	entries, err := CDNExclusions()
	if err != nil {
		t.Fatalf("CDNExclusions: %v", err)
	}
	for _, entry := range entries {
		if entry.ASN == probeASN {
			if entry.Provider != probeProvider {
				t.Fatalf("the surface reports the live entry as %q, want %q", entry.Provider, probeProvider)
			}
			return
		}
	}
	t.Fatalf("an entry added to KnownCDNASNs (AS%d %q) is missing from the surface projection; the accessor is not reading the classifier's table",
		probeASN, probeProvider)
}

func TestCDNExclusionsRefuseUnusableEntries(t *testing.T) {
	for name, table := range map[string]map[uint32]string{
		"zero_asn":       {0: "Nobody"},
		"blank_provider": {13335: "   "},
	} {
		t.Run(name, func(t *testing.T) {
			entries, err := cdnExclusions(table)
			if !errors.Is(err, ErrCDNExclusionEntryUnusable) {
				t.Fatalf("cdnExclusions(%v) error = %v, want ErrCDNExclusionEntryUnusable", table, err)
			}
			if entries != nil {
				t.Fatalf("cdnExclusions(%v) returned %v beside the error", table, entries)
			}
		})
	}

	// An empty table is not an unusable one: it means the classifier excludes
	// nothing, which the surface has to be able to say out loud.
	empty, err := cdnExclusions(map[uint32]string{})
	if err != nil {
		t.Fatalf("cdnExclusions(empty) error = %v, want nil", err)
	}
	if len(empty) != 0 {
		t.Fatalf("cdnExclusions(empty) = %v, want an empty set", empty)
	}
}

// TestNoSecondCDNExclusionList fails when shipped code enumerates the excluded
// networks anywhere but the canonical table. Documentation and tests may name an
// ASN for a fixture; a second list is what this guard is for, so it looks at
// executable sources and templates only and requires at least two of the table's
// ASNs in one file to call it a list.
func TestNoSecondCDNExclusionList(t *testing.T) {
	root := repositoryRoot(t)
	pattern := cdnASNPattern(t)

	scanned := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "tasks":
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !cdnScanCandidate(rel) {
			return nil
		}
		scanned++
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		found := map[string]bool{}
		for _, match := range pattern.FindAllSubmatch(body, -1) {
			found[string(match[1])] = true
		}
		if len(found) >= 2 {
			t.Errorf("%s enumerates %d of the networks the classifier excludes (%s). The policy surface must report %s, not a second list: two lists drift, and the one an operator reads would be the wrong one.",
				rel, len(found), strings.Join(sortedASNs(found), ", "), CDNExclusionSource)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("scan the repository for a second CDN exclusion list: %v", walkErr)
	}
	// A scan that found nothing proves nothing; the working tree ships hundreds of
	// these files.
	if scanned < 200 {
		t.Fatalf("scanned only %d shipped source files; the extraction is wrong", scanned)
	}
}

// cdnASNPattern matches the table's ASNs as whole numbers.
func cdnASNPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	asns := make([]string, 0, len(KnownCDNASNs))
	for asn := range KnownCDNASNs {
		asns = append(asns, strconv.FormatUint(uint64(asn), 10))
	}
	if len(asns) < 2 {
		t.Fatalf("the classifier table holds %d ASNs; the exclusion guard would be vacuous", len(asns))
	}
	// Longest first, so an alternation cannot match a prefix of a longer ASN.
	sort.Slice(asns, func(i, j int) bool {
		if len(asns[i]) != len(asns[j]) {
			return len(asns[i]) > len(asns[j])
		}
		return asns[i] < asns[j]
	})
	return regexp.MustCompile(`\b(` + strings.Join(asns, "|") + `)\b`)
}

// sortedASNs orders the numbers a scan found, so a failure names them readably.
func sortedASNs(found map[string]bool) []string {
	out := make([]string, 0, len(found))
	for asn := range found {
		out = append(out, "AS"+asn)
	}
	sort.Slice(out, func(i, j int) bool {
		left, _ := strconv.Atoi(strings.TrimPrefix(out[i], "AS"))
		right, _ := strconv.Atoi(strings.TrimPrefix(out[j], "AS"))
		return left < right
	})
	return out
}

// cdnScanCandidate reports whether a repository-relative path ships behaviour: Go
// sources that are not tests, the shipped scripts, and the templates that would
// render a second copy of the set.
func cdnScanCandidate(rel string) bool {
	switch {
	case strings.HasSuffix(rel, ".go"):
		return !strings.HasSuffix(rel, "_test.go") && rel != cdnTableFile
	case strings.HasPrefix(rel, "web/static/js/"):
		return strings.HasSuffix(rel, ".js")
	case strings.HasPrefix(rel, "web/templates/"):
		return strings.HasSuffix(rel, ".html")
	}
	return false
}

// repositoryRoot resolves the module root from this file's own location, so the
// scan does not depend on the working directory `go test` was started from.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve this test file's path")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}
