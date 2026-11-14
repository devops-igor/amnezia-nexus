//go:build linux

package vpn

// Offline controls for the namespace-ownership proof. Nothing here creates a namespace,
// writes a sysctl or runs a command: identity and the command boundary are injected, so
// every case is pure and reproducible.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestS4OwnedNamespaceGuard pins the identity proof that decides whether this process
// may configure kernel settings.
//
// It is pure and offline: it supplies synthetic namespace identities through
// s4NetNSInode and a recording command boundary through s4RunCommand, so it proves both
// directions — refusal and acceptance — and proves that a refused path executed NO
// command, without creating a namespace or touching a kernel setting.
func TestS4OwnedNamespaceGuard(t *testing.T) {
	const (
		launcherNS = "net:[4026531840]" // the namespace the launcher recorded
		childNS    = "net:[4026532999]" // a different namespace: unshare moved us
	)

	// recordFor writes a launch record and returns its path plus a matching env.
	recordFor := func(t *testing.T, launcherIdentity string) (string, []string) {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "launch.json")
		token := "tok-" + strings.ReplaceAll(t.Name(), "/", "-")
		rec := `{"token":"` + token + `","launcher_netns":"` + launcherIdentity + `"}`
		if err := os.WriteFile(path, []byte(rec), 0o600); err != nil {
			t.Fatalf("write launch record: %v", err)
		}
		return path, []string{s4LaunchRecordEnv + "=" + path, s4LaunchTokenEnv + "=" + token}
	}

	// instrument records every command a path attempts, so "no command ran" is provable.
	instrument := func(t *testing.T) *[]string {
		t.Helper()
		var ran []string
		prev := s4RunCommand
		s4RunCommand = func(name string, args ...string) (string, error) {
			ran = append(ran, strings.Join(append([]string{name}, args...), " "))
			return "", nil
		}
		t.Cleanup(func() { s4RunCommand = prev })
		return &ran
	}

	withInode := func(t *testing.T, identity string) {
		t.Helper()
		prev := s4NetNSInode
		s4NetNSInode = func() (string, error) { return identity, nil }
		t.Cleanup(func() { s4NetNSInode = prev })
	}

	// freshProcess clears this process's admission so each case starts as an unadmitted
	// process. Admission is process-global state, so without this a case could inherit a
	// previous case's acceptance.
	freshProcess := func(t *testing.T) {
		t.Helper()
		s4ResetOwnedAdmissionForTest()
		t.Cleanup(s4ResetOwnedAdmissionForTest)
	}

	clearLaunchEnv := func(t *testing.T) {
		t.Helper()
		t.Setenv(s4LaunchRecordEnv, "")
		t.Setenv(s4LaunchTokenEnv, "")
	}

	useRecord := func(t *testing.T, launcherIdentity string) (string, []string) {
		t.Helper()
		path, env := recordFor(t, launcherIdentity)
		for _, kv := range env {
			parts := strings.SplitN(kv, "=", 2)
			t.Setenv(parts[0], parts[1])
		}
		return path, env
	}

	t.Run("no launch environment refuses", func(t *testing.T) {
		freshProcess(t)
		clearLaunchEnv(t)
		withInode(t, childNS)
		ran := instrument(t)
		if err := s4RequireOwnedNamespace(); err == nil {
			t.Fatal("the guard accepted a process with no launch record")
		}
		if len(*ran) != 0 {
			t.Fatalf("the guard ran commands while refusing: %v", *ran)
		}
	})

	t.Run("inherited marker in the launcher namespace refuses", func(t *testing.T) {
		// The reported defect: the child is in the SAME namespace as the launcher, so an
		// inherited/forged marker must not authorize writes against that host.
		freshProcess(t)
		path, _ := useRecord(t, launcherNS)
		withInode(t, launcherNS)
		ran := instrument(t)
		if err := s4RequireOwnedNamespace(); err == nil {
			t.Fatal("the guard accepted a process still in the launching namespace")
		}
		if len(*ran) != 0 {
			t.Fatalf("the guard ran commands while refusing: %v", *ran)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("a refused claim consumed the launch record: %v", statErr)
		}
	})

	t.Run("mismatched token refuses", func(t *testing.T) {
		freshProcess(t)
		path, _ := recordFor(t, launcherNS)
		t.Setenv(s4LaunchRecordEnv, path)
		t.Setenv(s4LaunchTokenEnv, "different-token")
		withInode(t, childNS)
		if err := s4RequireOwnedNamespace(); err == nil {
			t.Fatal("the guard accepted a record whose token does not match")
		}
	})

	t.Run("same process is accepted repeatedly, a different process is not", func(t *testing.T) {
		freshProcess(t)
		path, _ := useRecord(t, launcherNS)
		withInode(t, childNS)

		// Admission, then repeated checks in the SAME process must all succeed. This is the
		// composition the delivered guard broke: it consumed the record on the first call,
		// so the very next legitimate check failed.
		for i := 0; i < 3; i++ {
			if err := s4RequireOwnedNamespace(); err != nil {
				t.Fatalf("repeated check %d in the admitted process was refused: %v", i+1, err)
			}
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("the claimed record should be gone, stat error: %v", statErr)
		}

		// A DIFFERENT process has no admission and must present its own record, which is
		// already consumed, so replay is refused.
		s4ResetOwnedAdmissionForTest()
		if err := s4RequireOwnedNamespace(); err == nil {
			t.Fatal("a second process replayed the consumed launch record")
		}
	})

	t.Run("stale record path refuses", func(t *testing.T) {
		freshProcess(t)
		t.Setenv(s4LaunchRecordEnv, filepath.Join(t.TempDir(), "absent.json"))
		t.Setenv(s4LaunchTokenEnv, "tok")
		withInode(t, childNS)
		if err := s4RequireOwnedNamespace(); err == nil {
			t.Fatal("the guard accepted a missing launch record")
		}
	})

	// The mutation entry points must refuse BEFORE their first write. A fresh process that
	// has never been admitted has to prove itself from the record.
	t.Run("initial setup refuses without running a command", func(t *testing.T) {
		freshProcess(t)
		clearLaunchEnv(t)
		withInode(t, launcherNS)
		ran := instrument(t)
		if err := configurePrivateNamespaceSetup(); err == nil {
			t.Fatal("initial setup configured sysctls without an owned namespace")
		}
		if len(*ran) != 0 {
			t.Fatalf("initial setup ran commands while refusing: %v", *ran)
		}
	})

	t.Run("live refusal refuses without running a command", func(t *testing.T) {
		freshProcess(t)
		clearLaunchEnv(t)
		withInode(t, launcherNS)
		ran := instrument(t)
		if err := s4AssertLiveIncompatibleConfigRefused(); err == nil {
			t.Fatal("the live refusal proceeded without an owned namespace")
		}
		if len(*ran) != 0 {
			t.Fatalf("the live refusal ran commands while refusing: %v", *ran)
		}
	})

	// The uplink builder is the newest mutation path, so it must refuse before its first
	// command exactly like the sysctl writers, and it must issue the documented topology
	// when it IS admitted.
	t.Run("uplink build refuses without running a command", func(t *testing.T) {
		freshProcess(t)
		clearLaunchEnv(t)
		withInode(t, launcherNS)
		ran := instrument(t)
		if err := s4BuildOwnedNamespaceUplink(); err == nil {
			t.Fatal("the uplink was built without an owned namespace")
		}
		if len(*ran) != 0 {
			t.Fatalf("the uplink build ran commands while refusing: %v", *ran)
		}
	})

	t.Run("uplink build issues the host WAN topology when owned", func(t *testing.T) {
		freshProcess(t)
		path, env := recordFor(t, launcherNS)
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			t.Setenv(k, v)
		}
		_ = path
		withInode(t, childNS)
		ran := instrument(t)
		if err := s4BuildOwnedNamespaceUplink(); err != nil {
			t.Fatalf("uplink build refused in an owned namespace: %v", err)
		}
		got := strings.Join(*ran, "\n")
		// NewProductionWANDevice only needs an up, non-loopback IPv4 interface, and this
		// is the same sequence the capture probe uses. Assert the load-bearing steps.
		for _, want := range []string{
			"ip link add " + s4WANIface + " type veth peer name " + s4WANPeerIface,
			"ip addr add " + s4HostWAN + "/24 dev " + s4WANIface,
			"ip link set " + s4WANIface + " up",
			"ip route add default dev " + s4WANIface,
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("uplink build did not issue %q; ran:\n%s", want, got)
			}
		}
		if !strings.Contains(got, "ip link set lo up") {
			t.Fatalf("uplink build did not bring lo up; ran:\n%s", got)
		}
	})
}

// TestS4OwnedNamespaceComposition pins the ACTUAL consumer composition rather than the
// guard in isolation.
//
// The delivered guard consumed the launch record on every call, so a process that
// legitimately proves ownership more than once — init, then initial setup, then the live
// refusal — failed on its second check before configuring anything. This test drives that
// real order in one process and asserts it proceeds, while every refusal case still
// refuses, and it proves the no-effect boundary via the injected command recorder.
func TestS4OwnedNamespaceComposition(t *testing.T) {
	const launcherNS = "net:[4026531840]"
	const childNS = "net:[4026532999]"

	// runSequence performs the real consumer order and returns the recorded commands.
	runSequence := func(t *testing.T, setup func(t *testing.T)) (commands []string, err error) {
		t.Helper()
		s4ResetOwnedAdmissionForTest()
		t.Cleanup(s4ResetOwnedAdmissionForTest)

		prevInode := s4NetNSInode
		s4NetNSInode = func() (string, error) { return childNS, nil }
		t.Cleanup(func() { s4NetNSInode = prevInode })

		prevRun := s4RunCommand
		s4RunCommand = func(name string, args ...string) (string, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			// `ip link show <dev>` must report absence: a no-effect boundary that claims
			// every probe succeeded would falsely "prove" the TUN was created.
			if name == "ip" && len(args) > 0 && args[0] == "link" {
				return "", fmt.Errorf("device does not exist")
			}
			return "", nil
		}
		t.Cleanup(func() { s4RunCommand = prevRun })

		setup(t)

		// 1. init-time admission (the probe/participant entry point does this first).
		if err := s4RequireOwnedNamespace(); err != nil {
			return commands, fmt.Errorf("init admission: %w", err)
		}
		// 2. the normal initial setup, which re-checks before its first write.
		if err := configurePrivateNamespaceSetup(); err != nil {
			return commands, fmt.Errorf("initial setup: %w", err)
		}
		// 3. the live-refusal phase, which re-checks before its first write.
		if err := s4AssertLiveIncompatibleConfigRefused(); err != nil {
			return commands, fmt.Errorf("live refusal: %w", err)
		}
		return commands, nil
	}

	t.Run("admitted child runs init then setup then live refusal", func(t *testing.T) {
		var recordPath string
		commands, err := runSequence(t, func(t *testing.T) {
			dir := t.TempDir()
			recordPath = filepath.Join(dir, "launch.json")
			token := "tok-composition"
			rec := `{"token":"` + token + `","launcher_netns":"` + launcherNS + `"}`
			if werr := os.WriteFile(recordPath, []byte(rec), 0o600); werr != nil {
				t.Fatalf("write launch record: %v", werr)
			}
			t.Setenv(s4LaunchRecordEnv, recordPath)
			t.Setenv(s4LaunchTokenEnv, token)
		})
		_ = recordPath
		// The composition must PROCEED: this is the case the delivered guard broke.
		if err != nil {
			t.Fatalf("the supported same-child sequence was refused: %v", err)
		}
		if len(commands) == 0 {
			t.Fatal("the sequence proceeded without reaching the command boundary; the assertions would prove nothing")
		}
		// It must have configured the namespace, i.e. actually attempted the writes.
		joined := strings.Join(commands, "\n")
		for _, want := range []string{"net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("initial setup did not reach %q; recorded: %v", want, commands)
			}
		}
		// The live-refusal phase must have run after the setup: it sets the incompatible
		// value and restores it, which is the ordered composition under test.
		if !strings.Contains(joined, "net.ipv4.conf.all.rp_filter=2") {
			t.Fatalf("the live-refusal phase did not run after setup; recorded: %v", commands)
		}
	})

	t.Run("forged marker in the launcher namespace runs nothing", func(t *testing.T) {
		commands, err := runSequence(t, func(t *testing.T) {
			prevInode := s4NetNSInode
			s4NetNSInode = func() (string, error) { return launcherNS, nil }
			t.Cleanup(func() { s4NetNSInode = prevInode })

			dir := t.TempDir()
			path := filepath.Join(dir, "launch.json")
			token := "tok-forged"
			rec := `{"token":"` + token + `","launcher_netns":"` + launcherNS + `"}`
			if werr := os.WriteFile(path, []byte(rec), 0o600); werr != nil {
				t.Fatalf("write launch record: %v", werr)
			}
			t.Setenv(s4LaunchRecordEnv, path)
			t.Setenv(s4LaunchTokenEnv, token)
		})
		if err == nil {
			t.Fatal("an unshared-in-name-only process was admitted")
		}
		if len(commands) != 0 {
			t.Fatalf("a refused composition ran commands: %v", commands)
		}
	})

	t.Run("inherited marker without a record runs nothing", func(t *testing.T) {
		commands, err := runSequence(t, func(t *testing.T) {
			t.Setenv(s4LaunchRecordEnv, "")
			t.Setenv(s4LaunchTokenEnv, "")
		})
		if err == nil {
			t.Fatal("a process with no launch record was admitted")
		}
		if len(commands) != 0 {
			t.Fatalf("a refused composition ran commands: %v", commands)
		}
	})
}

// TestS4OwnedNamespaceCaptureComposition covers the OTHER real consumer: the capture
// probe guards its init entry point and then guards again inside applyProbeSysctls, two
// legitimate checks in one process. Under the delivered guard the second call failed, so
// the probe reported "sysctls not writable" for a namespace it actually owned.
func TestS4OwnedNamespaceCaptureComposition(t *testing.T) {
	const launcherNS = "net:[4026531840]"
	const childNS = "net:[4026532999]"

	dir := t.TempDir()
	recordPath := filepath.Join(dir, "launch.json")
	const token = "tok-capture"
	rec := `{"token":"` + token + `","launcher_netns":"` + launcherNS + `"}`
	if err := os.WriteFile(recordPath, []byte(rec), 0o600); err != nil {
		t.Fatalf("write launch record: %v", err)
	}
	t.Setenv(s4LaunchRecordEnv, recordPath)
	t.Setenv(s4LaunchTokenEnv, token)

	s4ResetOwnedAdmissionForTest()
	t.Cleanup(s4ResetOwnedAdmissionForTest)
	prevInode := s4NetNSInode
	s4NetNSInode = func() (string, error) { return childNS, nil }
	t.Cleanup(func() { s4NetNSInode = prevInode })

	// 1. the init entry point's check
	if err := s4RequireOwnedNamespace(); err != nil {
		t.Fatalf("capture probe init check was refused: %v", err)
	}
	// 2. the in-body check before writing sysctls
	if err := s4RequireOwnedNamespace(); err != nil {
		t.Fatalf("capture probe's second (in-body) check was refused: %v", err)
	}
}

// TestS4LaunchArgvCarriesVerbose pins the launcher's argv without creating a
// namespace: a stub `unshare` is placed first on PATH and records the arguments it
// receives, then exits non-zero so nothing is launched.
//
// It exists because the lifecycle caller reads its child's per-test "--- PASS" line,
// and the Go test framework only prints those under -test.v. Dropping the flag makes a
// child that ran its assertions correctly report no per-test result, which the caller
// then treats as a failure.
func TestS4LaunchArgvCarriesVerbose(t *testing.T) {
	dir := t.TempDir()
	argvPath := filepath.Join(dir, "argv")
	// Refuses instead of launching: no namespace, no child, no kernel state.
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvPath + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "unshare"), []byte(script), 0o755); err != nil {
		t.Fatalf("write stub unshare: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// The launch fails (the stub refuses); only its argv is under test.
	_, _ = s4LaunchInOwnedNamespace("^TestExample$", nil)

	raw, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatalf("the launcher did not invoke unshare at all: %v", err)
	}
	argv := strings.Fields(string(raw))
	for _, want := range []string{"-Urn", "--map-root-user", "-test.v", "-test.run=^TestExample$"} {
		if !strings.Contains(strings.Join(argv, " "), want) {
			t.Fatalf("launcher argv is missing %q; got %v", want, argv)
		}
	}
}
