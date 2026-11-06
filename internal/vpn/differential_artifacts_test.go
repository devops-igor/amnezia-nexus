package vpn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// artifactDirEnv is the explicit evidence-export directory honoured by the differential
// producers. scripts/run_differential_qualification.sh exports it so that qualification
// evidence lands in the caller's output directory.
const artifactDirEnv = "NEXUS_ARTIFACT_DIR"

// differentialArtifactDirFor resolves the destination for differential evidence artifacts.
//
// Ordinary test runs are invocation-owned: when no export is requested the artifacts go to
// testArtifactDir (the per-test directory behind t.ArtifactDir()), which belongs to this
// invocation only and is discarded with it. A relative export keeps its documented meaning
// and is anchored at repoRoot, so callers such as the qualification runner are unaffected.
func differentialArtifactDirFor(exported, testArtifactDir, repoRoot string) (string, error) {
	exported = strings.TrimSpace(exported)
	if exported == "" {
		if testArtifactDir == "" {
			return "", errors.New("no invocation-owned artifact directory available")
		}
		return testArtifactDir, nil
	}
	if filepath.IsAbs(exported) {
		return exported, nil
	}
	if repoRoot == "" {
		return "", fmt.Errorf("relative %s %q needs a repository root to resolve against", artifactDirEnv, exported)
	}
	return filepath.Join(repoRoot, exported), nil
}

// differentialArtifactDir returns the directory that receives this test's differential
// evidence artifacts. It never returns a repository working-tree path unless the caller
// explicitly exported one.
func differentialArtifactDir(t *testing.T) string {
	t.Helper()
	exported := strings.TrimSpace(os.Getenv(artifactDirEnv))
	repoRoot := ""
	if exported != "" && !filepath.IsAbs(exported) {
		root, err := FindRepoRoot()
		if err != nil {
			t.Fatalf("%s=%q is relative and the repository root could not be resolved: %v", artifactDirEnv, exported, err)
		}
		repoRoot = root
	}
	dir, err := differentialArtifactDirFor(exported, t.ArtifactDir(), repoRoot)
	if err != nil {
		t.Fatalf("resolve differential artifact directory: %v", err)
	}
	return dir
}

// writeDifferentialArtifact writes data to name inside dir, replacing any file a previous
// invocation left behind in a single rename. A cancelled predecessor can therefore only leave
// a complete artifact or an unrecognisable temporary file, never a half-written manifest that
// a later run would silently accept.
func writeDifferentialArtifact(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(name)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary artifact: %w", err)
	}
	tmpPath := tmp.Name()
	// Removes the temporary file unless the rename below already consumed it.
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary artifact: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary artifact: %w", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("publish artifact: %w", err)
	}
	return nil
}

// emitDifferentialArtifact writes one evidence artifact and fails the test when it cannot be
// published: a qualification run that cannot produce its evidence must not report success.
func emitDifferentialArtifact(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := writeDifferentialArtifact(dir, name, data); err != nil {
		t.Fatalf("emit differential artifact %s: %v", filepath.Join(dir, name), err)
	}
}

// upstreamCompatibilityDir and upstreamSoakDir are the repository working-tree paths the
// differential producers used to write into unconditionally. They are retained here only as a
// negative control: no ordinary run may recreate them.
const (
	upstreamCompatibilityDir = "tasks/issue-392-differential-compatibility"
	upstreamSoakDir          = "tasks/issue-392-phase3-soak"
)

// TestDifferentialArtifactDirFor covers destination resolution, including the explicit export
// contract that scripts/run_differential_qualification.sh and the evidence verifier rely on.
func TestDifferentialArtifactDirFor(t *testing.T) {
	tests := []struct {
		name        string
		exported    string
		testDir     string
		repoRoot    string
		want        string
		wantErrPart string
	}{
		{
			name:     "no export uses the invocation directory",
			testDir:  "/artifact-dir/t",
			repoRoot: "/repo",
			want:     "/artifact-dir/t",
		},
		{
			name:     "absolute export is honoured verbatim",
			exported: "/out/evidence",
			testDir:  "/artifact-dir/t",
			repoRoot: "/repo",
			want:     "/out/evidence",
		},
		{
			name:     "relative export resolves against the repository root",
			exported: "test-artifacts/public",
			testDir:  "/artifact-dir/t",
			repoRoot: "/repo",
			want:     "/repo/test-artifacts/public",
		},
		{
			name:        "relative export without a repository root is an error",
			exported:    "test-artifacts",
			testDir:     "/artifact-dir/t",
			wantErrPart: "repository root",
		},
		{
			name:        "no export and no invocation directory is an error",
			wantErrPart: "invocation-owned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := differentialArtifactDirFor(tt.exported, tt.testDir, tt.repoRoot)
			if tt.wantErrPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got dir %q", tt.wantErrPart, got)
				}
				if !strings.Contains(err.Error(), tt.wantErrPart) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("dir = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDifferentialArtifactDefaultIsInvocationOwned proves the ordinary path: with no export the
// artifact lands in a directory owned by this test invocation, and repeated runs over a stale
// partial file (a cancelled predecessor) converge on complete content only.
func TestDifferentialArtifactDefaultIsInvocationOwned(t *testing.T) {
	t.Setenv(artifactDirEnv, "")

	dir := differentialArtifactDir(t)
	if dir == "" {
		t.Fatal("artifact directory is empty")
	}
	if repoRoot, err := FindRepoRoot(); err == nil {
		if rel, err := filepath.Rel(repoRoot, dir); err == nil && !strings.HasPrefix(rel, "..") {
			t.Fatalf("artifact directory %q is inside the repository working tree %q", dir, repoRoot)
		}
	}

	// A predecessor that was cancelled mid-write can leave a truncated file behind. Simulating
	// that with a partial write first makes the repeat assertion meaningful.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("seed artifact dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence_manifest.json"), []byte(`{"schema_ver`), 0o600); err != nil {
		t.Fatalf("seed stale artifact: %v", err)
	}

	first := []byte(`{"schema_version":"1.0.0","run":"first"}`)
	emitDifferentialArtifact(t, dir, "evidence_manifest.json", first)
	assertArtifactContent(t, dir, "evidence_manifest.json", first)
	firstInfo, err := os.Stat(filepath.Join(dir, "evidence_manifest.json"))
	if err != nil {
		t.Fatalf("stat artifact: %v", err)
	}
	if mode := firstInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("artifact mode = %04o, want 0600", mode)
	}

	// A second invocation writing the same name replaces the content completely.
	second := []byte(`{"schema_version":"1.0.0","run":"second","extra":true}`)
	emitDifferentialArtifact(t, dir, "evidence_manifest.json", second)
	assertArtifactContent(t, dir, "evidence_manifest.json", second)

	assertNoTempArtifactsLeft(t, dir)
}

// TestDifferentialArtifactExplicitExportPreserved proves the qualification export still receives
// the artifacts, in the same directory names the evidence verifier reads.
func TestDifferentialArtifactExplicitExportPreserved(t *testing.T) {
	exportDir := t.TempDir()
	t.Setenv(artifactDirEnv, exportDir)

	dir := differentialArtifactDir(t)
	if dir != exportDir {
		t.Fatalf("artifact dir = %q, want explicit export %q", dir, exportDir)
	}

	manifest := []byte(`{"schema_version":"1.0.0"}`)
	emitDifferentialArtifact(t, dir, "evidence_manifest.json", manifest)
	assertArtifactContent(t, exportDir, "evidence_manifest.json", manifest)

	visitAnnouncement := []byte(`{"tcp_continuity_passed":true,"idle_phase_passed":true}`)
	emitDifferentialArtifact(t, dir, "soak_report_reference_bounded_verification.json", visitAnnouncement)
	assertArtifactContent(t, exportDir, "soak_report_reference_bounded_verification.json", visitAnnouncement)
}

// TestDifferentialArtifactRelativeExportResolvesAtRepoRoot keeps the documented meaning of a
// relative NEXUS_ARTIFACT_DIR: it is anchored at the repository root, not at the process cwd.
func TestDifferentialArtifactRelativeExportResolvesAtRepoRoot(t *testing.T) {
	repoRoot, err := FindRepoRoot()
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	absExport := filepath.Join(t.TempDir(), "public")

	relative, err := filepath.Rel(repoRoot, absExport)
	if err != nil {
		t.Fatalf("compute relative export: %v", err)
	}
	t.Setenv(artifactDirEnv, relative)

	dir := differentialArtifactDir(t)
	if !filepath.IsAbs(dir) {
		t.Fatalf("resolved artifact dir %q is not absolute", dir)
	}
	// Publish through the same seam the producers use, which is also what creates the directory.
	emitDifferentialArtifact(t, dir, "evidence_manifest.json", []byte(`{"schema_version":"1.0.0"}`))

	got, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval artifact dir: %v", err)
	}
	want, err := filepath.EvalSymlinks(absExport)
	if err != nil {
		t.Fatalf("eval expected export dir: %v", err)
	}
	if got != want {
		t.Fatalf("artifact dir = %q, want %q", got, want)
	}
	assertArtifactContent(t, absExport, "evidence_manifest.json", []byte(`{"schema_version":"1.0.0"}`))
}

// TestDifferentialArtifactConcurrentInvocationsIndependent proves parallel invocations never
// share an artifact directory or overwrite one another's reports.
func TestDifferentialArtifactConcurrentInvocationsIndependent(t *testing.T) {
	t.Setenv(artifactDirEnv, "")

	const invocations = 4
	t.Run("group", func(t *testing.T) {
		for i := range invocations {
			t.Run(fmt.Sprintf("invocation-%d", i), func(t *testing.T) {
				t.Parallel()
				dir := differentialArtifactDir(t)
				payload := []byte(fmt.Sprintf(`{"invocation":%d}`, i))
				emitDifferentialArtifact(t, dir, "evidence_manifest.json", payload)
				emitDifferentialArtifact(t, dir, "soak_report_subject_bounded_verification.json", payload)
				assertArtifactContent(t, dir, "evidence_manifest.json", payload)
				assertArtifactContent(t, dir, "soak_report_subject_bounded_verification.json", payload)
				assertNoTempArtifactsLeft(t, dir)
			})
		}
	})
}

// TestDifferentialProducersLeaveNoRepoTasksOutput is the ownership regression for the reported
// failure: after the producers run, the legacy repository working-tree artifact directories must
// not exist unless something outside these producers created them. A pre-existing leftover from
// an earlier revision is not repaired here (that is not a durable contract), so the check only
// asserts the producers write nothing there.
func TestDifferentialProducersLeaveNoRepoTasksOutput(t *testing.T) {
	repoRoot, err := FindRepoRoot()
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	legacyDirs := []string{
		filepath.Join(repoRoot, upstreamCompatibilityDir),
		filepath.Join(repoRoot, upstreamSoakDir),
	}
	before := make([]bool, len(legacyDirs))
	for i, dir := range legacyDirs {
		if _, err := os.Stat(dir); err == nil {
			before[i] = true
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat legacy dir %q: %v", dir, err)
		}
	}

	// Exercise both producer paths at their shared seam, in the ordinary (no-export) mode.
	t.Setenv(artifactDirEnv, "")
	dir := differentialArtifactDir(t)
	emitDifferentialArtifact(t, dir, "evidence_manifest.json", []byte(`{"schema_version":"1.0.0"}`))
	emitDifferentialArtifact(t, dir, "soak_report_subject_bounded_verification.json", []byte(`{"run_mode":"bounded_verification"}`))

	for i, legacyDir := range legacyDirs {
		_, statErr := os.Stat(legacyDir)
		if before[i] {
			if statErr != nil {
				t.Fatalf("pre-existing legacy dir %q disappeared: %v", legacyDir, statErr)
			}
			continue
		}
		if statErr == nil {
			t.Fatalf("producer recreated repository working-tree artifact dir %q", legacyDir)
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("stat legacy dir %q: %v", legacyDir, statErr)
		}
	}
}

// assertArtifactContent asserts the artifact exists with exactly want as its content.
func assertArtifactContent(t *testing.T, dir, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read artifact %s/%s: %v", dir, name, err)
	}
	if string(got) != string(want) {
		t.Fatalf("artifact %s content = %q, want %q", name, got, want)
	}
}

// assertNoTempArtifactsLeft asserts no half-written temporary artifact survived publication.
func assertNoTempArtifactsLeft(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read artifact dir %s: %v", dir, err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary artifact %q left behind in %s", entry.Name(), dir)
		}
	}
}
