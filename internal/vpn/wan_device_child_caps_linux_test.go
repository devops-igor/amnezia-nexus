//go:build linux

package vpn

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// This file pins the capability boundary of the iptables child process.
//
// The panel runs as a non-root user and receives CAP_NET_ADMIN from a file capability
// on its own binary, which is not inherited across exec, so a plain child would start
// with no permitted capability and every rule change would fail with exit 4. None of
// the other WAN tests observe that boundary: they either replace the runner or run as
// root inside a namespace, where a child inherits everything.

// TestIPTablesChild_AmbientCapabilityIsOnlyNetAdmin pins the request at the boundary
// the production runner uses. It executes nothing: it fails if the ambient request is
// absent, widened to NET_RAW, or arrives with changed arguments.
func TestIPTablesChild_AmbientCapabilityIsOnlyNetAdmin(t *testing.T) {
	args := []string{"-N", resetSubchain}
	cmd := iptablesCommand("/sbin/iptables", args...)

	if cmd.SysProcAttr == nil {
		t.Fatal("the iptables command carries no SysProcAttr, so in the non-root deployment the child would run with no permitted capability at all")
	}
	ambient := cmd.SysProcAttr.AmbientCaps
	if len(ambient) != 1 {
		t.Fatalf("the iptables child requests %d ambient capabilities (%v), want exactly the one it needs", len(ambient), ambient)
	}
	if ambient[0] != uintptr(unix.CAP_NET_ADMIN) {
		t.Fatalf("the iptables child requests capability %d, want CAP_NET_ADMIN (%d)", ambient[0], unix.CAP_NET_ADMIN)
	}
	// Stated separately because it is a security property, not a detail of the list
	// length above: NET_RAW is not needed to change rules and must not be propagated.
	for _, c := range ambient {
		if c == uintptr(unix.CAP_NET_RAW) {
			t.Fatalf("the iptables child must not receive CAP_NET_RAW")
		}
	}
	if cmd.Path != "/sbin/iptables" {
		t.Fatalf("command path = %q, want the resolved iptables path unchanged", cmd.Path)
	}
	if len(cmd.Args) != len(args)+1 {
		t.Fatalf("command arguments = %v, want %q followed by %v", cmd.Args, cmd.Path, args)
	}
	for i, want := range args {
		if cmd.Args[i+1] != want {
			t.Fatalf("command argument %d = %q, want %q", i, cmd.Args[i+1], want)
		}
	}
}

// iptablesChildCapProbeEnv marks the child that re-executes the capability probe
// inside the run-owned namespace fixture.
const iptablesChildCapProbeEnv = "NEXUS_IPTABLES_CHILD_CAP_PROBE"

// TestIPTablesChild_NonRootConsumerGetsNetAdminOnly runs the real production runner
// against a substitute iptables in the repository's own unprivileged namespace fixture
// and reads the capability sets the executed child actually had.
//
// Evidence class: a genuine child process started through defaultIPTablesRunner with a
// real exec; the parent's capability state is emulated (permitted/effective
// NET_ADMIN+NET_RAW, empty inheritable and ambient sets, no CAP_SETPCAP, SECBIT_NOROOT)
// because the fixture cannot run as a non-root user carrying file capabilities, and the
// child binary is a substitute because installing real rules is out of scope here. The
// kernel rules being exercised are the ones that decide the container outcome.
func TestIPTablesChild_NonRootConsumerGetsNetAdminOnly(t *testing.T) {
	if os.Getenv(iptablesChildCapProbeEnv) != "1" {
		out, err := s4LaunchInOwnedNamespace("^"+t.Name()+"$", []string{iptablesChildCapProbeEnv + "=1"})
		if err != nil {
			if s4RequiredEnvironment() {
				t.Fatalf("the iptables child capability probe could not run inside a run-owned namespace, so the boundary is unproven: %v\n%s", err, out)
			}
			t.Skipf("skipping: cannot create an owned namespace here: %v", err)
		}
		if !strings.Contains(out, "--- PASS") || strings.Contains(out, "--- SKIP") {
			t.Fatalf("the child capability assertions did not run and pass inside the owned namespace:\n%s", out)
		}
		t.Logf("capability assertions on the executed iptables child passed:\n%s", out)
		return
	}

	if err := s4RequireOwnedNamespace(); err != nil {
		t.Fatalf("child was selected without a run-owned namespace: %v", err)
	}
	// Capability sets and securebits are per-thread and the fork happens on this
	// goroutine's current thread, so pin it for the whole body.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := emulateNonRootFileCapabilityParent(); err != nil {
		t.Fatalf("reproduce the non-root file-capability parent: %v", err)
	}

	child, parentBefore, parentAfter, argv := runSubstituteIPTablesFromPanel(t)
	assertIPTablesChildBoundary(t, child, parentBefore, parentAfter, argv)
}

// runSubstituteIPTablesFromPanel starts a substitute iptables through the production
// runner and returns what the executed child reported about itself, the arguments it
// received, and the panel's own capability sets before and after the exec.
func runSubstituteIPTablesFromPanel(t *testing.T) (child, before, after capabilitySets, argv string) {
	t.Helper()
	dir := t.TempDir()
	recordPath := filepath.Join(dir, "iptables-child-status.txt")
	script := fmt.Sprintf("#!/bin/sh\n{ echo \"argv: $*\"; grep -E '^Cap(Prm|Eff|Inh|Amb):' /proc/self/status; } > %q\nexit 0\n", recordPath)
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the substitute iptables: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	before, err := readCapabilitySets("/proc/self/status")
	if err != nil {
		t.Fatalf("read the panel's capability sets: %v", err)
	}
	t.Logf("emulated panel capability sets: %s", before.describe())

	if runErr := defaultIPTablesRunner("-N", resetSubchain); runErr != nil {
		t.Fatalf("the production runner failed to start iptables from a parent that holds NET_ADMIN: %v", runErr)
	}

	after, err = readCapabilitySets("/proc/self/status")
	if err != nil {
		t.Fatalf("re-read the panel's capability sets: %v", err)
	}
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("the substitute iptables did not run: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "argv: ") {
		t.Fatalf("unexpected record from the iptables child: %q", raw)
	}
	child, err = readCapabilitySets(recordPath)
	if err != nil {
		t.Fatalf("read the iptables child's capability sets: %v", err)
	}
	t.Logf("executed iptables child capability sets: %s", child.describe())
	return child, before, after, strings.TrimPrefix(lines[0], "argv: ")
}

// assertIPTablesChildBoundary states the whole boundary in one place: the child got
// NET_ADMIN and nothing else, it received the intended arguments, and the panel's own
// capability sets did not move.
func assertIPTablesChildBoundary(t *testing.T, child, before, after capabilitySets, argv string) {
	t.Helper()
	if got, want := argv, "-N "+resetSubchain; got != want {
		t.Fatalf("the iptables child received argv %q, want %q", got, want)
	}
	if before != after {
		t.Fatalf("the panel's own capability sets changed across the child exec: before %s, after %s", before.describe(), after.describe())
	}
	netAdmin := uint64(1) << unix.CAP_NET_ADMIN
	netRaw := uint64(1) << unix.CAP_NET_RAW
	if child.effective&netAdmin == 0 {
		t.Fatalf("the iptables child has no effective NET_ADMIN, so every rule change would fail with permission denied: %s", child.describe())
	}
	if child.ambient&netAdmin == 0 {
		t.Fatalf("the iptables child did not carry NET_ADMIN ambiently, so its capability came from somewhere other than this runner: %s", child.describe())
	}
	if child.effective&netRaw != 0 || child.permitted&netRaw != 0 || child.ambient&netRaw != 0 {
		t.Fatalf("CAP_NET_RAW was propagated to the iptables child: %s", child.describe())
	}
}

// emulateNonRootFileCapabilityParent configures this process like the documented image
// configures the panel: permitted and effective NET_ADMIN+NET_RAW from its file
// capability, empty inheritable and ambient sets, and no CAP_SETPCAP.
//
// SECBIT_NOROOT is required because the fixture runs as uid 0 inside its own user
// namespace, where an exec would otherwise hand the child the entire bounding set and
// hide what the ambient request actually does. Without CAP_SETPCAP the later
// inheritable addition is only legal because NET_ADMIN is already permitted, which is
// exactly the container's situation.
func emulateNonRootFileCapabilityParent() error {
	const secbitNoRoot = 1 << 0 // SECBIT_NOROOT; x/sys/unix exports no name for it
	if err := unix.Prctl(unix.PR_SET_SECUREBITS, secbitNoRoot, 0, 0, 0); err != nil {
		return fmt.Errorf("set SECBIT_NOROOT so uid 0 stops granting the bounding set at exec: %w", err)
	}
	const panelCaps = uint32(1)<<unix.CAP_NET_ADMIN | uint32(1)<<unix.CAP_NET_RAW
	var sets [2]unix.CapUserData // LINUX_CAPABILITY_VERSION_3 uses two 32-bit words
	sets[0].Permitted = panelCaps
	sets[0].Effective = panelCaps
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capset(&hdr, &sets[0]); err != nil {
		return fmt.Errorf("restrict this process to the panel's NET_ADMIN|NET_RAW: %w", err)
	}
	return nil
}

// TestIPTablesChild_MissingAuthorityRefusesInsteadOfSkipping pins that a process
// without NET_ADMIN still gets an error from the production runner and never reaches
// the command: a missing capability must not become a silent skip or a success.
func TestIPTablesChild_MissingAuthorityRefusesInsteadOfSkipping(t *testing.T) {
	parent, err := readCapabilitySets("/proc/self/status")
	if err != nil {
		t.Fatalf("read this process's capability sets: %v", err)
	}
	if parent.permitted&(uint64(1)<<unix.CAP_NET_ADMIN) != 0 {
		t.Skipf("this process holds CAP_NET_ADMIN (%s), so the missing-authority path is not reachable in it", parent.describe())
	}

	dir := t.TempDir()
	markerPath := filepath.Join(dir, "iptables-ran")
	script := fmt.Sprintf("#!/bin/sh\necho ran > %q\nexit 0\n", markerPath)
	if err := os.WriteFile(filepath.Join(dir, "iptables"), []byte(script), 0o755); err != nil {
		t.Fatalf("write the substitute iptables: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	err = defaultIPTablesRunner("-N", resetSubchain)
	if err == nil {
		t.Fatal("without NET_ADMIN the production runner reported success, so a refused activation could look installed")
	}
	if _, statErr := os.Stat(markerPath); statErr == nil {
		t.Fatalf("the substitute iptables ran even though the process has no NET_ADMIN, so the capability boundary is not enforced")
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("check whether the substitute iptables ran: %v", statErr)
	}
	t.Logf("a process without NET_ADMIN was refused before the child ran: %v", err)
}

// capabilitySets is the subset of a process's capability lines this probe needs.
type capabilitySets struct {
	inheritable uint64
	permitted   uint64
	effective   uint64
	ambient     uint64
}

func (s capabilitySets) describe() string {
	return fmt.Sprintf("inh=%#x prm=%#x eff=%#x amb=%#x", s.inheritable, s.permitted, s.effective, s.ambient)
}

// readCapabilitySets parses the capability lines of a /proc status-format file, so the
// assertion is on the values the kernel reports rather than on this test's own model.
func readCapabilitySets(statusPath string) (capabilitySets, error) {
	var sets capabilitySets
	// #nosec G304 -- statusPath is either /proc/self/status or a file this test wrote
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return sets, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		var target *uint64
		switch key {
		case "CapInh":
			target = &sets.inheritable
		case "CapPrm":
			target = &sets.permitted
		case "CapEff":
			target = &sets.effective
		case "CapAmb":
			target = &sets.ambient
		default:
			continue
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return sets, fmt.Errorf("parse %s: %w", key, err)
		}
		*target = parsed
	}
	return sets, nil
}
