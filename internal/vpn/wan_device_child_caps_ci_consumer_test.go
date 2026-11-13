//go:build linux

package vpn

import (
	"os"
	"path/filepath"
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
