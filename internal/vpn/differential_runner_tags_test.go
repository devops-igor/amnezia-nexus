package vpn

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// qualificationRunnerBuildTag is the build tag the repository's Go packages require. The
// Makefile and the CI workflows supply it through GOFLAGS; a script that calls `go`
// directly has to pass it itself.
const qualificationRunnerBuildTag = "with_utls"

// Stub race-probe outcomes the guards inject.
const (
	stubGoOK              = "ok"
	stubGoBuildFailure    = "build-failure"
	stubGoHostUnsupported = "host-unsupported"
)

// qualificationRunnerStubGo is the argument-recording `go` stand-in the guard puts first on
// PATH. It logs every invocation and can reproduce, for the race probe package only, the
// two failure shapes the runner has to tell apart: a build failure and a host that cannot
// run the race detector.
const qualificationRunnerStubGo = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_GO_LOG"
if [[ "${STUB_GO_MODE}" != "ok" && "$*" == *"./cmd/panel"* ]]; then
    case "${STUB_GO_MODE}" in
        build-failure)
            echo "# internal/vpn/tunnel/vless" >&2
            printf '%s\n' 'internal/vpn/tunnel/vless/tags_guard.go:5:13: cannot use "package internal/vpn/tunnel/vless requires build tag with_utls" (untyped string constant) as int value in variable declaration' >&2
            printf 'FAIL\texample.test/cmd/panel [build failed]\n' >&2
            exit 1
            ;;
        host-unsupported)
            echo "fatal error: unsupported VMA range 52 - 57 when -race is enabled: invalid pointer found on stack" >&2
            exit 1
            ;;
    esac
fi
exit 0
`

// qualificationRun is what one execution of the runner script produced.
type qualificationRun struct {
	output string
	dir    string
	calls  []string
	err    error
}

// qualificationSummary is the part of the runner's summary artifact these guards assert on.
type qualificationSummary struct {
	RaceEnabled bool   `json:"race_enabled"`
	RaceProbe   string `json:"race_probe"`
}

// runQualificationRunner executes the real qualification runner with a recording `go`
// stand-in first on PATH, so the assertions read the arguments the script actually passes
// to `go` rather than a copy of what the script is supposed to pass them.
func runQualificationRunner(t *testing.T, stubMode string, args ...string) qualificationRun {
	t.Helper()

	repoRoot, err := FindRepoRoot()
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}

	scratch := t.TempDir()
	binDir := filepath.Join(scratch, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create stub bin directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(qualificationRunnerStubGo), 0o755); err != nil {
		t.Fatalf("write stub go: %v", err)
	}

	logPath := filepath.Join(scratch, "go-invocations.log")
	outputDir := filepath.Join(scratch, "artifacts")
	script := filepath.Join(repoRoot, "scripts", "run_differential_qualification.sh")
	scriptArgs := append(append([]string{}, args...), "--output-dir", outputDir)

	cmd := exec.Command("bash", append([]string{script}, scriptArgs...)...)
	cmd.Dir = repoRoot
	// GOFLAGS is cleared for the child so the assertion cannot be satisfied by an ambient
	// build-tag setting in the developer's shell: the tag has to come from the script.
	cmd.Env = environmentWithOverrides(map[string]string{
		"PATH":         binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"STUB_GO_LOG":  logPath,
		"STUB_GO_MODE": stubMode,
		"GOFLAGS":      "",
	})

	raw, runErr := cmd.CombinedOutput()
	return qualificationRun{
		output: string(raw),
		dir:    outputDir,
		calls:  recordedGoInvocations(logPath),
		err:    runErr,
	}
}

// environmentWithOverrides returns the current environment with the given keys replaced, so
// a child process cannot inherit a duplicate PATH or a stale stub setting.
func environmentWithOverrides(overrides map[string]string) []string {
	current := os.Environ()
	merged := make([]string, 0, len(current)+len(overrides))
	for _, entry := range current {
		key := entry
		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			key = entry[:idx]
		}
		if _, replaced := overrides[key]; replaced {
			continue
		}
		merged = append(merged, entry)
	}
	for key, value := range overrides {
		merged = append(merged, key+"="+value)
	}
	return merged
}

// recordedGoInvocations reads the argument log the stub wrote. A missing log means `go` was
// never invoked at all, which the callers report through their per-marker assertions.
func recordedGoInvocations(logPath string) []string {
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return nil
	}
	var invocations []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			invocations = append(invocations, line)
		}
	}
	return invocations
}

// singleGoInvocation returns the one recorded invocation that mentions marker, failing the
// test when the runner made none or more than one.
func singleGoInvocation(t *testing.T, calls []string, marker string) string {
	t.Helper()

	var matches []string
	for _, call := range calls {
		if strings.Contains(call, marker) {
			matches = append(matches, call)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one go invocation matching %q, got %d: %v", marker, len(matches), calls)
	}
	return matches[0]
}

// carriesBuildTag reports whether a recorded invocation asks for tag, in either the
// separated or the joined flag form.
func carriesBuildTag(invocation, tag string) bool {
	return strings.Contains(invocation, "-tags "+tag) || strings.Contains(invocation, "-tags="+tag)
}

// readQualificationSummary loads the summary artifact the runner wrote.
func readQualificationSummary(t *testing.T, run qualificationRun) qualificationSummary {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(run.dir, "qualification_summary.json"))
	if err != nil {
		t.Fatalf("read qualification summary: %v\nrunner output:\n%s", err, run.output)
	}
	var summary qualificationSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("parse qualification summary: %v\nsummary: %s", err, raw)
	}
	return summary
}

// TestDifferentialRunnerPassesRequiredBuildTagsToGoTest guards the regression that made four
// scheduled soak runs report "[build failed]" with zero executed cases: the runner invoked
// `go test` without the build tag the repository's packages require. The assertion is on the
// arguments the script really passes to `go`, so dropping the tag from either the race probe
// or the suite invocation fails here instead of silently in the weekly job.
func TestDifferentialRunnerPassesRequiredBuildTagsToGoTest(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	run := runQualificationRunner(t, stubGoOK, "--suite", "baseline", "--race")
	if run.err != nil {
		t.Fatalf("qualification runner failed: %v\n%s", run.err, run.output)
	}

	for _, marker := range []string{"./cmd/panel", "./internal/vpn"} {
		invocation := singleGoInvocation(t, run.calls, marker)
		if !carriesBuildTag(invocation, qualificationRunnerBuildTag) {
			t.Fatalf("go invocation for %s does not carry the required build tag %q: %q",
				marker, qualificationRunnerBuildTag, invocation)
		}
	}
}

// TestDifferentialRunnerKeepsRaceOnSupportingHost is the positive control for the race
// pre-check: when the probe succeeds, the suite invocation must still be built with -race,
// and the run summary must record that race coverage was enabled.
func TestDifferentialRunnerKeepsRaceOnSupportingHost(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	run := runQualificationRunner(t, stubGoOK, "--suite", "baseline", "--race")
	if run.err != nil {
		t.Fatalf("qualification runner failed: %v\n%s", run.err, run.output)
	}

	invocation := singleGoInvocation(t, run.calls, "./internal/vpn")
	if !strings.Contains(invocation, "-race") {
		t.Fatalf("host supports the race detector but the suite invocation has no -race: %q", invocation)
	}
	if summary := readQualificationSummary(t, run); !summary.RaceEnabled {
		t.Fatalf("summary reports race_enabled=false although the probe succeeded: %+v", summary)
	}
}

// TestDifferentialRunnerReportsRealCauseWhenProbeBuildFails is the negative control for the
// same pre-check: a probe that fails to build says nothing about the host, so the runner must
// report the build failure and stop instead of converting it into the host-limitation path
// that quietly removes race coverage.
func TestDifferentialRunnerReportsRealCauseWhenProbeBuildFails(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	run := runQualificationRunner(t, stubGoBuildFailure, "--suite", "baseline", "--race")
	if run.err == nil {
		t.Fatalf("runner reported success although the race probe failed to build:\n%s", run.output)
	}
	if !strings.Contains(run.output, "tags_guard.go") {
		t.Fatalf("runner did not report the real build cause:\n%s", run.output)
	}
	for _, silent := range []string{"does not support the Go race detector", "Disabling -race"} {
		if strings.Contains(run.output, silent) {
			t.Fatalf("runner treated a build failure as an unsupported host (%q):\n%s", silent, run.output)
		}
	}
	for _, call := range run.calls {
		if strings.Contains(call, "./internal/vpn") {
			t.Fatalf("runner started a suite after an unclassified probe failure: %q", call)
		}
	}
}

// TestDifferentialRunnerDisablesRaceOnlyForUnsupportedHost proves the deliberate disable path
// still exists for the host limitation it was written for, keeps the build tag, and publishes
// the reason it disabled -race.
func TestDifferentialRunnerDisablesRaceOnlyForUnsupportedHost(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	run := runQualificationRunner(t, stubGoHostUnsupported, "--suite", "baseline", "--race")
	if run.err != nil {
		t.Fatalf("unsupported host must degrade instead of failing the run: %v\n%s", run.err, run.output)
	}
	if !strings.Contains(run.output, "does not support the Go race detector") {
		t.Fatalf("runner did not report the unsupported host:\n%s", run.output)
	}

	invocation := singleGoInvocation(t, run.calls, "./internal/vpn")
	if strings.Contains(invocation, "-race") {
		t.Fatalf("suite invocation kept -race on a host that cannot run it: %q", invocation)
	}
	if !carriesBuildTag(invocation, qualificationRunnerBuildTag) {
		t.Fatalf("suite invocation lost the required build tag %q: %q", qualificationRunnerBuildTag, invocation)
	}

	summary := readQualificationSummary(t, run)
	if summary.RaceEnabled {
		t.Fatalf("summary reports race_enabled=true for an unsupported host: %+v", summary)
	}
	if !strings.HasPrefix(summary.RaceProbe, "host-unsupported") {
		t.Fatalf("summary does not publish the disable reason: %+v", summary)
	}
}
