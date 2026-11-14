//go:build linux

package vpn

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// This file pins the CI consumer of the iptables child capability proof.
//
// The positive proof (TestIPTablesChild_NonRootConsumerGetsNetAdminOnly) starts its own
// user namespace, which an ordinary unprivileged runner refuses, so it is excluded from
// the unprivileged test job and required by name in the isolated WAN job. Those two
// selections are the whole obligation: the exclusion is only legitimate because the
// other job runs it and fails without its PASS. If a later edit drops one half, every
// remaining test still passes while the real child-capability boundary goes unproven —
// which is how it failed in CI the first time. These controls read the workflow as text
// and fail in exactly that case.
//
// Nothing here is a new parser or schema: each control locates one job block and one
// line inside it. The runtime properties (ambient NET_ADMIN requested, NET_ADMIN only,
// unchanged parent sets) stay where they already are, in the two namespace-free
// controls that the unprivileged job keeps running.

const (
	childCapsPositiveTest = "TestIPTablesChild_NonRootConsumerGetsNetAdminOnly"
	childCapsAmbientTest  = "TestIPTablesChild_AmbientCapabilityIsOnlyNetAdmin"
	childCapsRefusalTest  = "TestIPTablesChild_MissingAuthorityRefusesInsteadOfSkipping"
)

// childCapsWorkflowLines returns the lines of the CI workflow that owns both jobs.
func childCapsWorkflowLines(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the CI workflow at %s: %v", path, err)
	}
	return strings.Split(string(raw), "\n")
}

// childCapsJobLines returns the lines of one top-level job block, from its key to the
// line before the next job key.
func childCapsJobLines(t *testing.T, workflow []string, job string) []string {
	t.Helper()
	start := -1
	for i, line := range workflow {
		if line == "  "+job+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("the CI workflow has no %q job; the capability proof's CI consumer is gone", job)
	}
	for i := start + 1; i < len(workflow); i++ {
		line := workflow[i]
		if len(line) > 3 && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") &&
			strings.HasSuffix(line, ":") {
			return workflow[start:i]
		}
	}
	return workflow[start:]
}

// childCapsLineContaining returns the single line of a block that contains want.
func childCapsLineContaining(t *testing.T, block []string, want, failure string) string {
	t.Helper()
	var found []string
	for _, line := range block {
		if strings.Contains(line, want) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s (found %d lines containing %q)", failure, len(found), want)
	}
	return found[0]
}

// TestIPTablesChildCapabilityProofOrdinaryCIExcludesOnlyThePrivilegedPositive pins both
// halves of the unprivileged job: the positive proof must not run there, and the two
// namespace-free controls must keep running there. Dropping the exclusion reintroduces
// the setup failure that needed no assertion to report; dropping either control would
// leave the ambient NET_ADMIN request (and the fail-closed refusal) unproven on ordinary
// CI.
func TestIPTablesChildCapabilityProofOrdinaryCIExcludesOnlyThePrivilegedPositive(t *testing.T) {
	block := childCapsJobLines(t, childCapsWorkflowLines(t), "test")
	skip := childCapsLineContaining(t, block, "-skip '^(", "the unprivileged test job no longer has a -skip selection")

	if !strings.Contains(skip, childCapsPositiveTest) {
		t.Fatalf("the unprivileged test job does not exclude %s, so it would create a user namespace there and fail before its assertions", childCapsPositiveTest)
	}
	for _, control := range []string{childCapsAmbientTest, childCapsRefusalTest} {
		if strings.Contains(skip, control) {
			t.Fatalf("the unprivileged test job now skips %s; that control is namespace-free and is the ordinary-CI proof of the capability boundary, so excluding it removes the proof instead of moving it", control)
		}
	}
}

// TestIPTablesChildCapabilityProofQualifiedJobSelectsThePositive pins that the exclusion
// above is paired with real execution: the isolated WAN job must select the positive
// proof in the test-run pattern it executes.
func TestIPTablesChildCapabilityProofQualifiedJobSelectsThePositive(t *testing.T) {
	block := childCapsJobLines(t, childCapsWorkflowLines(t), "wan-qualification")
	run := childCapsLineContaining(t, block,
		`-test.run "^(TestS4ProductionContainerHostWANQualification`,
		"the isolated WAN job no longer selects the VPN WAN gates by name")

	if !strings.Contains(run, childCapsPositiveTest) {
		t.Fatalf("the isolated WAN job does not select %s, so the child-capability positive is excluded from ordinary CI and never executed anywhere", childCapsPositiveTest)
	}
}

// TestIPTablesChildCapabilityProofQualifiedJobRequiresItsVerdict pins the second half of
// the paired exclusion: a selected test that reports no PASS, or reports a SKIP, must
// fail the job. Selection alone would leave a silently skipped proof green.
func TestIPTablesChildCapabilityProofQualifiedJobRequiresItsVerdict(t *testing.T) {
	names := childCapsVerdictNames(t, childCapsJobLines(t, childCapsWorkflowLines(t), "wan-qualification"))
	for _, name := range names {
		if name == childCapsPositiveTest {
			return
		}
	}
	t.Fatalf("the required-verdict list %v does not name %s, so its PASS is not required and a skip would leave the job green", names, childCapsPositiveTest)
}

// childCapsVerdictNames returns the test names the isolated WAN job requires a PASS for:
// the entries of its `for name in \ ... do` loop.
func childCapsVerdictNames(t *testing.T, block []string) []string {
	t.Helper()
	start := -1
	for i, line := range block {
		if strings.TrimSpace(line) == "for name in \\" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("the isolated WAN job no longer inspects per-test verdicts by name, so a skipped or missing capability proof would not fail it")
	}
	var names []string
	for _, line := range block[start+1:] {
		entry := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\\"))
		if entry == "do" {
			break
		}
		if entry != "" {
			names = append(names, entry)
		}
	}
	if len(names) == 0 {
		t.Fatal("the required-verdict list of the isolated WAN job is empty")
	}
	return names
}

// The isolated WAN step ends its single-quoted `bash -c` body with an absolute launch
// of the staged binary. Text controls cannot see a broken shell parse: a stray
// apostrophe inside that body ends the quoted script early and the launch becomes a
// command of the runner shell instead, so the required tests never start. This is the
// one executable control: it extracts the step's own shell and runs it with every
// privileged or absolute command replaced by a recording fixture.
const (
	childCapsWANStep       = "Run the VPN WAN qualification"
	childCapsWANStagedPath = "/run/wan/vpn-wan.test"

	// childCapsQuotingFixed is the body comment that carries the regression: its first
	// version contained an apostrophe ("the executed child's capability sets") and
	// terminated the outer single-quoted script. The retired spelling is reintroduced by
	// the control below.
	childCapsQuotingFixed  = "capability sets of the executed child,"
	childCapsQuotingBroken = "executed child's capability sets,"
)

// childCapsStepLines returns the shell body of one named step in a job block, dedented
// to column zero, as the runner shell would receive it.
func childCapsStepLines(t *testing.T, block []string, step string) []string {
	t.Helper()
	start := -1
	for i, line := range block {
		if strings.TrimSpace(line) == "- name: "+step {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("the isolated WAN job has no %q step, so the required proof is no longer executed anywhere", step)
	}
	runAt := -1
	for i := start + 1; i < len(block); i++ {
		trimmed := strings.TrimSpace(block[i])
		if trimmed == "run: |" {
			runAt = i
			break
		}
		if strings.HasPrefix(trimmed, "- name: ") {
			break
		}
	}
	if runAt < 0 {
		t.Fatalf("the %q step no longer has a `run: |` block", step)
	}
	indent := 0
	for _, line := range block[runAt+1:] {
		if trimmed := strings.TrimLeft(line, " "); trimmed != "" {
			indent = len(line) - len(trimmed)
			break
		}
	}
	if indent == 0 {
		t.Fatalf("the %q step has an empty `run: |` block", step)
	}
	var body []string
	for _, line := range block[runAt+1:] {
		if strings.TrimSpace(line) == "" {
			body = append(body, "")
			continue
		}
		if len(line)-len(strings.TrimLeft(line, " ")) < indent {
			break
		}
		body = append(body, line[indent:])
	}
	return body
}

// childCapsStepScript joins a step's shell body back into one script.
func childCapsStepScript(t *testing.T, block []string, step string) string {
	t.Helper()
	return strings.Join(childCapsStepLines(t, block, step), "\n") + "\n"
}

// childCapsSelectionPattern returns the -test.run pattern the isolated WAN job passes to
// the compiled test binary.
func childCapsSelectionPattern(t *testing.T, stepLines []string) string {
	t.Helper()
	const marker = `-test.run "`
	line := childCapsLineContaining(t, stepLines, marker,
		"the isolated WAN step no longer selects tests by name in the binary it launches")
	rest := line[strings.Index(line, marker)+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("the -test.run pattern of the isolated WAN step is not a complete quoted argument: %q", line)
	}
	return rest[:end]
}

// childCapsWANRun is one offline execution of the extracted step.
type childCapsWANRun struct {
	dir     string
	script  string
	env     []string
	logPath string
}

// newChildCapsWANRun stages a sandbox around script: recording fixtures named after the
// privileged and absolute-path commands the body uses, an inner-launch hook for the
// absolute `exec`, and a stand-in test binary. Nothing outside the sandbox is read or
// written, so no sudo, unshare, mount or /run path is ever touched.
func newChildCapsWANRun(t *testing.T, script string, verdictNames []string) *childCapsWANRun {
	t.Helper()
	dir := t.TempDir()
	realPath := os.Getenv("PATH")
	binDir := filepath.Join(dir, "bin")
	runnerTemp := filepath.Join(dir, "runner-temp")
	staged := filepath.Join(dir, "staged", "vpn-wan.test")

	childCapsWriteFile(t, filepath.Join(dir, "exec-hook.sh"), childCapsExecHook, 0o644)
	childCapsWriteFile(t, filepath.Join(dir, "fixture-binary"), childCapsBinaryFixture, 0o755)
	childCapsWriteFile(t, filepath.Join(runnerTemp, "vpn-wan.test"), childCapsBinaryFixture, 0o755)
	childCapsWriteFile(t, filepath.Join(dir, "verdict-names.txt"), strings.Join(verdictNames, "\n")+"\n", 0o644)

	// The absolute-path commands of the isolated body, all served by one fixture that
	// records its argv and never writes to the path it was given.
	for _, name := range []string{"mount", "mkdir", "chmod", "install", "stat", "namei", "findmnt"} {
		childCapsWriteFile(t, filepath.Join(binDir, name), childCapsPathFixture, 0o755)
	}
	childCapsWriteFile(t, filepath.Join(binDir, "sudo"), childCapsSudoFixture, 0o755)
	childCapsWriteFile(t, filepath.Join(binDir, "unshare"), childCapsUnshareFixture, 0o755)

	return &childCapsWANRun{
		dir:     dir,
		script:  childCapsWriteFile(t, filepath.Join(dir, "step.sh"), script, 0o644),
		env:     childCapsSandboxEnv(dir, binDir, runnerTemp, staged, realPath),
		logPath: filepath.Join(runnerTemp, "vpn-wan.log"),
	}
}

// childCapsSandboxEnv returns the environment for the extracted step: the inherited one
// minus everything that would change how the shell parses (an inherited BASH_ENV or an
// exported function such as exec) and minus the variables the sandbox sets itself.
func childCapsSandboxEnv(dir, binDir, runnerTemp, staged, realPath string) []string {
	owned := map[string]bool{
		"PATH": true, "RUNNER_TEMP": true, "BASH_ENV": true, "ENV": true,
		"FI_DIR": true, "FI_STAGED": true, "FI_REAL_PATH": true, "FI_MODE": true, "FI_CHILD": true,
		"FI_WAN_PATH": true,
	}
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if owned[name] || strings.HasPrefix(name, "BASH_FUNC_") {
			continue
		}
		env = append(env, entry)
	}
	return append(env,
		"PATH="+binDir+":"+realPath,
		"RUNNER_TEMP="+runnerTemp,
		"FI_DIR="+dir,
		"FI_STAGED="+staged,
		"FI_REAL_PATH="+realPath,
		"FI_CHILD="+childCapsPositiveTest,
		"FI_WAN_PATH="+childCapsWANStagedPath,
	)
}

// run executes the extracted step with the stand-in binary in the given mode and returns
// its exit status and combined output.
func (r *childCapsWANRun) run(t *testing.T, mode string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", r.script)
	cmd.Dir = r.dir
	cmd.Env = append(r.env, "FI_MODE="+mode)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run the extracted WAN step offline: %v (%s)", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

// record returns the lines a fixture wrote, or nil when the fixture never ran.
func (r *childCapsWANRun) record(t *testing.T, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read the fixture record %s: %v", name, err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func childCapsWriteFile(t *testing.T, path, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create the sandbox directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write the sandbox file %s: %v", path, err)
	}
	return path
}

// TestIPTablesChildCapabilityProofWANStepLaunchesItsStagedBinary is the executable half
// of the two text controls above. It runs the isolated WAN step's own shell, with the
// privileged wrapper and the tmpfs commands recorded instead of executed, and requires
// the legitimate outcome: the step exits 0, the absolute launch of the staged binary
// arrives with exactly the intended flags and selection, the required CI markers reach
// that binary, and the step's own log inspection sees a PASS for every test it demands.
// A body that only looks right cannot satisfy this; the CI failure that motivated the
// control reported a missing binary and exit 127 before any test ran.
func TestIPTablesChildCapabilityProofWANStepLaunchesItsStagedBinary(t *testing.T) {
	block := childCapsJobLines(t, childCapsWorkflowLines(t), "wan-qualification")
	step := childCapsStepLines(t, block, childCapsWANStep)
	script := strings.Join(step, "\n") + "\n"
	names := childCapsVerdictNames(t, block)
	selection := childCapsSelectionPattern(t, step)

	run := newChildCapsWANRun(t, script, append(slices.Clone(names),
		"TestWANCaptureProductionPath/positive", "TestWANCaptureProductionPath/negative"))

	exit, output := run.run(t, "pass")
	if exit != 0 {
		t.Fatalf("the isolated WAN step exited %d without a complete pass, so the required binary never reported its verdicts: %s", exit, output)
	}

	want := []string{childCapsWANStagedPath, "-test.v", "-test.timeout=12m", "-test.run", selection}
	if got := run.record(t, "exec-argv.txt"); !slices.Equal(got, want) {
		t.Fatalf("the step launched %q, want the staged binary %q with %q; the required tests are not executed with the intended arguments", got, childCapsWANStagedPath, want[1:])
	}
	// The stand-in binary is started by the hook with the requested path replaced by its
	// sandbox copy, so it must receive the same arguments minus that path.
	if got := run.record(t, "binary-argv.txt"); !slices.Equal(got, want[1:]) {
		t.Fatalf("the staged binary received %q, want %q; the arguments are changed between the launch and the binary", got, want[1:])
	}
	for _, name := range names {
		if !strings.Contains(selection, name) {
			t.Fatalf("the executed selection %q does not name %s, so a test the step requires a verdict for is never selected", selection, name)
		}
	}
	if got := run.record(t, "binary-env.txt"); !slices.Equal(got, []string{"true true 1"}) {
		t.Fatalf("the staged binary inherited %q, want CI=true GITHUB_ACTIONS=true NEXUS_S4_REQUIRED=1; the required CI markers decide fail-closed behaviour and must reach the binary", got)
	}

	childCapsRequireCollectedVerdicts(t, run, names)
	childCapsRequireStaging(t, run)
}

// childCapsRequireCollectedVerdicts asserts that the step's own log inspection sees a
// PASS for every name it demands, both capture subtests and the S4 verdict line.
func childCapsRequireCollectedVerdicts(t *testing.T, r *childCapsWANRun, names []string) {
	t.Helper()
	raw, err := os.ReadFile(r.logPath)
	if err != nil {
		t.Fatalf("the step did not collect its own log at %s: %v", r.logPath, err)
	}
	log := string(raw)
	for _, name := range names {
		if !strings.Contains(log, "--- PASS: "+name+" ") {
			t.Fatalf("the collected log has no PASS verdict for %s, so the step's own inspection would not see it: %s", name, log)
		}
	}
	for _, sub := range []string{"TestWANCaptureProductionPath/positive", "TestWANCaptureProductionPath/negative", "S4 RESULT: PASS"} {
		if !strings.Contains(log, sub) {
			t.Fatalf("the collected log is missing %q, so the step's own obligations cannot be satisfied: %s", sub, log)
		}
	}
}

// childCapsRequireStaging asserts that the step mounted its private tmpfs and copied the
// staged binary into it from the runner temp path with an executable mode.
func childCapsRequireStaging(t *testing.T, r *childCapsWANRun) {
	t.Helper()
	staging := strings.Join(r.record(t, "absolute-argv.txt"), "\n")
	for _, want := range []string{
		"mount -t tmpfs tmpfs /run",
		"install -d -m 0755 /run/wan",
		"install -m 0755 " + filepath.Join(r.dir, "runner-temp", "vpn-wan.test") + " " + childCapsWANStagedPath,
	} {
		if !strings.Contains(staging, want) {
			t.Fatalf("the step did not perform %q, so the private tmpfs or the binary staging is gone: %s", want, staging)
		}
	}
}

// TestIPTablesChildCapabilityProofWANStepRejectsTheRetiredQuoting reintroduces the one
// apostrophe that ended the outer single-quoted body. The step must then report the
// missing binary and exit 127 before any test runs — the exact signature CI produced —
// and must not reach the absolute launch at all.
func TestIPTablesChildCapabilityProofWANStepRejectsTheRetiredQuoting(t *testing.T) {
	block := childCapsJobLines(t, childCapsWorkflowLines(t), "wan-qualification")
	script := childCapsStepScript(t, block, childCapsWANStep)
	broken := strings.Replace(script, childCapsQuotingFixed, childCapsQuotingBroken, 1)
	if broken == script {
		t.Fatalf("the isolated WAN step no longer contains %q, so this control cannot reintroduce the quoting defect it guards", childCapsQuotingFixed)
	}
	if _, err := os.Stat(childCapsWANStagedPath); err == nil {
		t.Fatalf("%s exists on this host; refusing to run a control whose defect launches that absolute path", childCapsWANStagedPath)
	}

	run := newChildCapsWANRun(t, broken, childCapsVerdictNames(t, block))
	exit, output := run.run(t, "pass")
	if exit != 127 {
		t.Fatalf("the step with the retired apostrophe exited %d, want 127: the single-quoted body is no longer terminated early, so the launch never reaches the runner shell", exit)
	}
	if !strings.Contains(output, childCapsWANStagedPath+": No such file or directory") {
		t.Fatalf("the step with the retired apostrophe did not report %s as a missing path: %s", childCapsWANStagedPath, output)
	}
	if got := run.record(t, "exec-argv.txt"); got != nil {
		t.Fatalf("the step with the retired apostrophe still reached the absolute launch through the hook (%q), so the defect did not truncate the quoted body", got)
	}
	if strings.Contains(output, "--- PASS:") {
		t.Fatalf("the step with the retired apostrophe reported test verdicts: %s", output)
	}
	if _, err := os.Stat(run.logPath); !os.IsNotExist(err) {
		t.Fatalf("the step with the retired apostrophe collected a log at %s, but the launch failure precedes the redirection and CI had none", run.logPath)
	}
}

// TestIPTablesChildCapabilityProofWANStepRejectsUnprovenVerdicts requires the step to
// fail when the staged binary does not prove what the step demands: a nonzero process
// status, a skipped required test, a skipped required subtest, or a required test that
// reports no verdict at all. Without this, the launch could be repaired and a missing
// or skipped proof would still leave the required job green.
func TestIPTablesChildCapabilityProofWANStepRejectsUnprovenVerdicts(t *testing.T) {
	block := childCapsJobLines(t, childCapsWorkflowLines(t), "wan-qualification")
	script := childCapsStepScript(t, block, childCapsWANStep)
	names := append(slices.Clone(childCapsVerdictNames(t, block)),
		"TestWANCaptureProductionPath/positive", "TestWANCaptureProductionPath/negative")

	for _, tc := range []struct {
		mode   string
		marker string
	}{
		{"fail", "::error::the qualification process exited 1"},
		{"skip", "::error::a required WAN test or subtest SKIPPED"},
		{"omit-child", "::error::required test did not report PASS: " + childCapsPositiveTest},
		{"skip-subtest", "::error::required subtest did not report PASS: TestWANCaptureProductionPath/positive"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			run := newChildCapsWANRun(t, script, names)
			exit, output := run.run(t, tc.mode)
			if exit == 0 {
				t.Fatalf("the step exited 0 although the binary did not prove the required verdicts (%s): %s", tc.mode, output)
			}
			if !strings.Contains(output, tc.marker) {
				t.Fatalf("the step failed without reporting %q: %s", tc.marker, output)
			}
		})
	}
}

// childCapsSudoFixture records the requested privileged wrapper and then runs it, so the
// isolation wrapper below still receives the arguments and environment the step passes.
const childCapsSudoFixture = `#!/bin/bash
set -uo pipefail
printf '%s\n' "$@" > "$FI_DIR/sudo-argv.txt"
exec "$@"
`

// childCapsUnshareFixture records the isolation wrapper, drops its flags, and runs the
// wrapped command in the current (already unprivileged and offline) namespaces. The one
// wrapped command that is the inner bash also receives the exec hook, which is where the
// absolute launch of the staged binary is intercepted.
const childCapsUnshareFixture = `#!/bin/bash
set -uo pipefail
printf '%s\n' "$@" >> "$FI_DIR/unshare-argv.txt"
while [ $# -gt 0 ]; do
  case "$1" in
    --propagation) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
if [ "${1:-}" = "bash" ]; then
  export BASH_ENV="$FI_DIR/exec-hook.sh"
fi
exec "$@"
`

// childCapsPathFixture stands in for the tmpfs and inspection commands of the isolated
// body. Each invocation is recorded and none writes to the path it was given; the binary
// staging is copied into the sandbox instead, so the recorded launch has a real file.
const childCapsPathFixture = `#!/bin/bash
set -uo pipefail
name="$(basename "$0")"
printf '%s %s\n' "$name" "$*" >> "$FI_DIR/absolute-argv.txt"
case "$name" in
  install)
    mode=create src="" dst=""
    while [ $# -gt 0 ]; do
      case "$1" in
        -d) mode=dir; shift ;;
        -m|-o|-g) shift 2 ;;
        -*) shift ;;
        *) if [ -z "$src" ]; then src="$1"; else dst="$1"; fi; shift ;;
      esac
    done
    if [ "$mode" = create ] && [ -n "$dst" ]; then
      PATH="$FI_REAL_PATH" mkdir -p "$(dirname "$FI_STAGED")" || exit 1
      PATH="$FI_REAL_PATH" cp "$src" "$FI_STAGED" || exit 1
      PATH="$FI_REAL_PATH" chmod 0755 "$FI_STAGED" || exit 1
    fi
    ;;
  stat) echo "mode=0755 uid=0 gid=0" ;;
  namei) echo "f: /run/wan/vpn-wan.test" ;;
  findmnt) echo "/run tmpfs rw" ;;
esac
exit 0
`

// childCapsExecHook is sourced through BASH_ENV by the inner launch. The extracted body
// ends with `exec "<private tmpfs path>" <args...>`; a shell function shadows that
// builtin, so the requested path and arguments are recorded and the staged stand-in runs
// with the identical argv. Any other exec — including the launch inside a fixture — is
// handed to the real builtin, so the hook cannot mask an unexpected launch.
const childCapsExecHook = `exec() {
  if [ "${1:-}" != "$FI_WAN_PATH" ]; then
    builtin exec "$@"
  fi
  printf '%s\n' "$@" > "$FI_DIR/exec-argv.txt"
  if [ ! -x "$FI_STAGED" ]; then
    echo "fixture: nothing was staged at $FI_STAGED" >&2
    return 127
  fi
  command "$FI_STAGED" "${@:2}"
}
`

// childCapsBinaryFixture stands in for the compiled ./internal/vpn test binary: it records
// the argv and CI markers it received, reports a verdict for every name the step demands,
// and FI_MODE removes or downgrades one of them so the step's own inspection is tested.
const childCapsBinaryFixture = `#!/bin/bash
set -uo pipefail
printf '%s\n' "$@" > "$FI_DIR/binary-argv.txt"
printf '%s %s %s\n' "${CI:-}" "${GITHUB_ACTIONS:-}" "${NEXUS_S4_REQUIRED:-}" > "$FI_DIR/binary-env.txt"
mode="${FI_MODE:-pass}"
while read -r name; do
  case "$name" in
    */positive) if [ "$mode" = skip-subtest ]; then continue; fi ;;
  esac
  if [ "${name##*/}" != "$name" ]; then
    echo "    --- PASS: $name (0.50s)"
    continue
  fi
  if [ "$name" = "$FI_CHILD" ] && [ "$mode" = omit-child ]; then continue; fi
  if [ "$name" = "$FI_CHILD" ] && [ "$mode" = skip ]; then
    echo "--- SKIP: $name (0.00s)"
    continue
  fi
  echo "=== RUN   $name"
  echo "--- PASS: $name (1.00s)"
done < "$FI_DIR/verdict-names.txt"
echo "S4 RESULT: PASS"
if [ "$mode" = fail ]; then exit 1; fi
exit 0
`
