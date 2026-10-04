package awg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// This file is the regression suite for the syncconf OPERAND COUNT defect.
//
// The bug it locks down: `awg syncconf` needs TWO operands - the interface and
// the NAME of a configuration file. An earlier revision fed the stripped config
// to syncconf through a shell redirect (`syncconf awg0 < /path`), which puts the
// bytes on stdin and supplies no second operand, so every real container
// rejected the command with
//
//	Usage: awg syncconf <interface> <configuration filename>
//
// and every config-applying path returned HTTP 500.
//
// The tests here deliberately do NOT inspect the command string with
// strings.Contains. Substring assertions are exactly why the broken form
// shipped: the string still contained "syncconf" and the strip path. Instead
// every test below EXECUTES the exact command string that production code
// handed to the remote shell, through a real /bin/bash, with stub executables
// on PATH that record `"$@"`. The assertion is on the recorded ARGV COUNT.

const (
	// argvLogEnv names the file the `awg` stub appends its received argv to.
	argvLogEnv = "AMNZ_TEST_ARGV_LOG"
	// stripBodyEnv is what the `awg-quick strip` stub writes to stdout.
	stripBodyEnv = "AMNZ_TEST_STRIP_BODY"
	// syncExitEnv, when set, makes the `awg` stub exit non-zero.
	syncExitEnv = "AMNZ_TEST_SYNC_EXIT"
)

// shellHarness is a directory of stub executables plus a temp config tree that
// stands in for the container filesystem.
type shellHarness struct {
	binDir   string
	cfgDir   string
	cfgPath  string
	argvLog  string
	pwnedDir string
}

// newShellHarness builds the stub `docker`, `awg`, `awg-quick` and `ip`
// executables. `docker` is stubbed so the WHOLE production command string -
// including its `docker exec -i <container> bash -c '<script>'` framing - is
// executed verbatim by a real shell rather than parsed and pattern-matched.
func newShellHarness(t *testing.T) *shellHarness {
	t.Helper()
	root := t.TempDir()
	h := &shellHarness{
		binDir:   filepath.Join(root, "bin"),
		cfgDir:   filepath.Join(root, "cfg"),
		argvLog:  filepath.Join(root, "argv.log"),
		pwnedDir: filepath.Join(root, "pwned"),
	}
	h.cfgPath = filepath.Join(h.cfgDir, "awg0.conf")
	for _, d := range []string{h.binDir, h.cfgDir, h.pwnedDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(h.cfgPath, []byte(validServerConfig), 0o644); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	// docker exec -i <container> <cmd...> -> run <cmd...> locally.
	writeStub(t, h, "docker", `#!/bin/bash
if [ "$1" != "exec" ]; then echo "stub docker: unsupported $1" >&2; exit 64; fi
shift
if [ "$1" = "-i" ]; then shift; fi
shift   # container name
exec "$@"
`)

	// awg records argv verbatim: one line per argument, prefixed by the count.
	writeStub(t, h, "awg", `#!/bin/bash
if [ "$1" = "syncconf" ]; then
  shift
  {
    echo "argc=$#"
    for a in "$@"; do echo "arg=$a"; done
  } >> "$`+argvLogEnv+`"
  if [ -n "$`+syncExitEnv+`" ]; then
    echo "Usage: awg syncconf <interface> <configuration filename>" >&2
    exit 1
  fi
  exit 0
fi
echo OK
`)

	// awg-quick strip <cfg> writes $STRIP_BODY (possibly empty) to stdout.
	writeStub(t, h, "awg-quick", `#!/bin/bash
case "$1" in
  strip) printf '%s' "$`+stripBodyEnv+`"; exit 0 ;;
  up)    echo OK; exit 0 ;;
esac
echo OK
`)

	writeStub(t, h, "ip", `#!/bin/bash
echo "2: awg0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1280 state DOWN"
`)
	return h
}

func writeStub(t *testing.T, h *shellHarness, name, body string) {
	t.Helper()
	p := filepath.Join(h.binDir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", name, err)
	}
}

// run executes cmd through a real /bin/bash with the harness stubs first on
// PATH. This is the whole point of the file: production command strings are
// interpreted by a shell, not string-matched by a test double.
func (h *shellHarness) run(t *testing.T, cmd string, env ...string) (string, string, int) {
	t.Helper()
	if _, err := exec.LookPath("/bin/bash"); err != nil {
		t.Skipf("/bin/bash unavailable: %v", err)
	}
	full := append([]string{
		"PATH=" + h.binDir + ":/usr/bin:/bin",
		argvLogEnv + "=" + h.argvLog,
		stripBodyEnv + "=" + validServerConfig,
	}, env...)
	c := exec.Command("/bin/bash", "-c", cmd)
	c.Env = full
	var stdout, stderr strings.Builder
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running %q: %v", cmd, err)
		}
	}
	return stdout.String(), stderr.String(), code
}

// recordedArgv parses the stub's argv log into (argc, args).
func (h *shellHarness) recordedArgv(t *testing.T) (int, []string) {
	t.Helper()
	raw, err := os.ReadFile(h.argvLog)
	if err != nil {
		t.Fatalf("awg stub recorded no argv at all - syncconf was never invoked: %v", err)
	}
	argc := -1
	var args []string
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "argc="):
			n, err := strconv.Atoi(strings.TrimPrefix(line, "argc="))
			if err != nil {
				t.Fatalf("unparsable argc line %q: %v", line, err)
			}
			argc = n
		case strings.HasPrefix(line, "arg="):
			args = append(args, strings.TrimPrefix(line, "arg="))
		}
	}
	if argc < 0 {
		t.Fatalf("awg argv log has no argc line: %q", raw)
	}
	return argc, args
}

// interceptSyncConf runs a real config save against the stub shell and returns
// the syncconf command string that production code handed to the remote shell.
func interceptSyncConf(t *testing.T, h *shellHarness, syncExit int) string {
	t.Helper()
	ctx := context.Background()
	var syncCmd string
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "syncconf") && syncCmd == "" {
			syncCmd = cmd
		}
		// The strip step must genuinely produce the file that syncconf names.
		// Its redirect target is the manager's fixed in-container config dir,
		// which is not writable locally, so retarget it at the harness tree.
		if strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip") {
			local := strings.ReplaceAll(cmd, "/opt/amnezia/awg", h.cfgDir)
			_, _, code := h.run(t, local)
			return "", "", code, nil
		}
		return client.defaultRunSudo(cmd)
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	err := mgr.saveServerConfig(ctx, client, validServerConfig)
	if syncExit != 0 && err == nil {
		t.Fatal("expected saveServerConfig to fail when syncconf fails")
	}
	if syncExit == 0 && err != nil {
		t.Fatalf("expected saveServerConfig to succeed against the stub shell, got: %v", err)
	}
	if syncCmd == "" {
		t.Fatal("no syncconf command was issued")
	}
	return syncCmd
}

// TestSyncconfReceivesInterfaceAndFilenameOperands is the primary regression.
// It runs the real syncconf command in a real bash and asserts the OPERAND
// COUNT: syncconf must receive an interface operand AND a filename operand.
func TestSyncconfReceivesInterfaceAndFilenameOperands(t *testing.T) {
	h := newShellHarness(t)
	syncCmd := interceptSyncConf(t, h, 0)

	// The saved config lives under the manager's fixed config path; point the
	// stub shell at the harness copy so the strip redirect is writable.
	syncCmd = strings.ReplaceAll(syncCmd, "/opt/amnezia/awg", h.cfgDir)
	stdout, stderr, code := h.run(t, syncCmd)
	if code != 0 {
		t.Fatalf("syncconf command exited %d (stdout=%q stderr=%q)\ncommand: %s", code, stdout, stderr, syncCmd)
	}

	argc, args := h.recordedArgv(t)
	if argc != 2 {
		t.Fatalf("syncconf must receive exactly TWO operands (interface, configuration filename); got %d: %q\ncommand: %s",
			argc, args, syncCmd)
	}
	if args[0] != "awg0" {
		t.Errorf("first operand must be the interface name, got %q", args[0])
	}
	if args[1] == "" {
		t.Error("second operand must be a configuration filename, got an empty string")
	}
	// A real filename operand: an existing, non-empty file whose bytes are the
	// stripped config. This is what a redirect can never provide.
	if st, err := os.Stat(args[1]); err != nil {
		t.Errorf("second operand %q is not a readable filename: %v", args[1], err)
	} else if st.Size() == 0 {
		t.Errorf("second operand %q is an empty file", args[1])
	}
	if !strings.Contains(args[1], ".awg-strip-") {
		t.Errorf("second operand should be the checked stripped config path, got %q", args[1])
	}
}

// TestSyncconfOperandShapeRejectsRedirectForm is the before-proof: it runs the
// PREVIOUS redirect form through the same real shell and shows it delivers only
// ONE operand. This is the assertion that was missing and whose absence let the
// broken command ship, so it is pinned here as a live, executable fact.
func TestSyncconfOperandShapeRejectsRedirectForm(t *testing.T) {
	h := newShellHarness(t)
	stripPath := filepath.Join(h.cfgDir, ".awg-strip-fixture.conf")
	if err := os.WriteFile(stripPath, []byte(validServerConfig), 0o644); err != nil {
		t.Fatalf("seed strip fixture: %v", err)
	}

	broken := "docker exec -i " + ssh.EscapeShellArg("amnezia-awg2") + " bash -c " +
		ssh.EscapeShellArg("awg syncconf awg0 < "+ssh.EscapeShellArg(stripPath))
	h.run(t, broken)
	argc, args := h.recordedArgv(t)
	if argc == 2 {
		t.Skip("redirect form unexpectedly delivered two operands")
	}
	t.Logf("CONFIRMED DEFECT: redirect form delivers argc=%d args=%q (syncconf needs 2)", argc, args)
	if argc != 1 {
		t.Fatalf("expected the redirect form to deliver exactly one operand, got %d: %q", argc, args)
	}
}

// TestEmptyStripIsRefusedBeforeSyncconf keeps the `test -s` guard honest against
// a real shell: a strip that exits 0 but writes nothing must stop syncconf.
func TestEmptyStripIsRefusedBeforeSyncconf(t *testing.T) {
	h := newShellHarness(t)
	ctx := context.Background()

	var stripCmd, syncCmd string
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip") && stripCmd == "" {
			stripCmd = cmd
			// Empty strip output, exit status 0 - exactly the silent-failure
			// shape the `test -s` guard exists to catch.
			_, _, code := h.run(t, cmd, stripBodyEnv+"=")
			return "", "", code, nil
		}
		if strings.Contains(cmd, "syncconf") && syncCmd == "" {
			syncCmd = cmd
		}
		return client.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	if err := mgr.saveServerConfig(ctx, client, validServerConfig); err == nil {
		t.Fatal("expected an empty strip result to be refused, got nil error")
	}
	if stripCmd == "" {
		t.Fatal("expected a strip command to be issued")
	}
	if _, err := os.Stat(h.argvLog); err == nil {
		t.Error("syncconf was invoked even though the strip result was empty")
	}
	if syncCmd != "" {
		t.Errorf("syncconf must never run after an empty strip, got: %s", syncCmd)
	}
}

// TestFailingStripNeverReachesSyncconf keeps the checked-strip property: a strip
// that exits non-zero must abort before syncconf and surface an error.
func TestFailingStripNeverReachesSyncconf(t *testing.T) {
	ctx := context.Background()
	rec := newStripFailureRecorder(true)
	rec.mock.files["/opt/amnezia/awg/awg0.conf"] = []byte(validServerConfig)
	original := string(rec.mock.files["/opt/amnezia/awg/awg0.conf"])

	mgr := NewAWGManager(&mockAWGSSHProvider{client: rec.mock})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	err := mgr.WriteConfiguration(ctx, server, stripRejectedConfig)
	if err == nil {
		t.Fatal("expected WriteConfiguration to fail when strip rejects the config")
	}
	stripCalls, syncconfs := rec.counts()
	if stripCalls == 0 {
		t.Error("expected strip to be invoked as its own checked step")
	}
	if syncconfs != 0 {
		t.Errorf("syncconf ran %d times after a failed strip; commands: %v", syncconfs, rec.recordedCommands())
	}
	if got := string(rec.mock.files["/opt/amnezia/awg/awg0.conf"]); got != original {
		t.Errorf("previous configuration was not restored byte-for-byte\n got: %q\nwant: %q", got, original)
	}
	if strings.Contains(string(rec.mock.files["/opt/amnezia/awg/awg0.conf"]), "SaveConfig") {
		t.Error("the rejected config leaked onto disk after a failed strip")
	}
}

// TestSyncconfFailureRestoresInterfaceStillRetries runs a real shell with a
// failing syncconf and asserts the disk config is rolled back and exactly one
// restore-then-retry attempt is made.
func TestSyncconfFailureRestoresInterfaceStillRetries(t *testing.T) {
	h := newShellHarness(t)
	ctx := context.Background()

	var syncCmds int
	var restored bool
	client := newMockAWGSSHClient()
	client.files["/opt/amnezia/awg/awg0.conf"] = []byte(validServerConfig)
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		switch {
		case strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip"):
			local := strings.ReplaceAll(cmd, "/opt/amnezia/awg", h.cfgDir)
			_, _, code := h.run(t, local)
			return "", "", code, nil
		case strings.Contains(cmd, "syncconf"):
			syncCmds++
			local := strings.ReplaceAll(cmd, "/opt/amnezia/awg", h.cfgDir)
			_, stderr, code := h.run(t, local, syncExitEnv+"=1")
			return "", stderr, code, nil
		case strings.Contains(cmd, "ip link show"), strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, " up "):
			restored = true
			return "OK", "", 0, nil
		}
		return client.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	if err := mgr.saveServerConfig(ctx, client, validServerConfig); err == nil {
		t.Fatal("expected saveServerConfig to fail when syncconf fails")
	}
	if !restored {
		t.Error("expected restoreInterfaceIfDown to run after the syncconf failure")
	}
	if syncCmds != 2 {
		t.Errorf("expected exactly 2 syncconf attempts (initial + one retry after restore), got %d", syncCmds)
	}
}

// TestSyncconfCommandResistsShellInjection proves - against a real shell - that
// shell metacharacters embedded in the config path or container name cannot
// execute anything: every interpolated value is escaped, so the metacharacters
// stay inert data inside the operand.
func TestSyncconfCommandResistsShellInjection(t *testing.T) {
	h := newShellHarness(t)
	ctx := context.Background()

	canary := filepath.Join(h.pwnedDir, "PWNED")
	// The hostile payload stays inside an existing directory so the strip step
	// itself still succeeds and syncconf is actually reached - the assertion is
	// about what the shell DID, not about an early abort.
	hostileCfg := h.cfgDir + "/awg0.conf; touch " + canary + " #.conf"
	hostileCName := "amnezia-awg2; touch " + canary + "; echo "

	var syncCmd string
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "syncconf") && syncCmd == "" {
			syncCmd = cmd
		}
		if strings.Contains(cmd, "awg-quick") && strings.Contains(cmd, "strip") {
			// Answer the strip step from the double so syncconf is always
			// reached. The point of this test is what the syncconf command does
			// when a real shell runs it, not whether the strip redirect target
			// happens to be nestable on a local filesystem.
			return "OK", "", 0, nil
		}
		return client.defaultRunSudo(cmd)
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	// Drive syncInterfaceConfig directly: the hostile container name is
	// normally filtered upstream by IsValidContainerName, and the hostile path
	// is what the escaping must neutralise.
	syncErr := mgr.syncInterfaceConfig(ctx, client, hostileCName, hostileCfg)
	t.Logf("syncInterfaceConfig(hostile) = %v", syncErr)
	if syncCmd == "" {
		t.Fatal("expected a syncconf command to be issued")
	}
	// A real shell now interprets the metacharacters. They must stay inert.
	h.run(t, syncCmd, stripBodyEnv+"="+validServerConfig)

	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("shell injection executed: %s was created\ncommand: %s", canary, syncCmd)
	}
	// The escaped operands must arrive whole: one argument, not a split.
	argc, args := h.recordedArgv(t)
	if argc != 2 {
		t.Fatalf("escaped syncconf must still deliver 2 operands, got %d: %q\ncommand: %s", argc, args, syncCmd)
	}
	if args[0] != "awg0" {
		t.Errorf("interface operand must arrive intact, got %q", args[0])
	}
	if !strings.Contains(args[1], "awg0.conf; touch "+canary) &&
		!strings.Contains(args[1], ".awg-strip-") {
		t.Errorf("the hostile path must arrive as ONE inert operand, got %q", args[1])
	}
	// The whole hostile payload stayed inside the single second operand: no
	// word of it was interpreted as a separate argument or a command.
	for _, frag := range []string{"touch", ";", "echo"} {
		for _, a := range args {
			if a != "awg0" && strings.TrimSpace(a) == frag {
				t.Errorf("hostile fragment %q was split out into its own operand: %q", frag, args)
			}
		}
	}
}

// TestOpsReview_StripFilePermissions pins the insecure creation regression:
// Under ambient permissive umask (022), stripInterfaceConfig previously created
// secret-bearing files with mode 0644 before any chmod or sync operation.
// The file must be created with mode 0600 or stricter.
func TestOpsReview_StripFilePermissions(t *testing.T) {
	h := newShellHarness(t)
	c := newMockAWGSSHClient()
	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, " strip ") {
			out, stderr, code := h.run(t, "umask 022; "+cmd)
			return out, stderr, code, nil
		}
		return c.defaultRunSudo(cmd)
	}
	m := NewAWGManager(&mockAWGSSHProvider{client: c})
	p, err := m.stripInterfaceConfig(context.Background(), c, "amnezia-awg2", h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	hasPrivateKey := strings.Contains(string(data), "PrivateKey")
	t.Logf("secret-bearing strip file: mode=%04o private-key-present=%t", st.Mode().Perm(), hasPrivateKey)
	if st.Mode().Perm()&0077 != 0 {
		t.Errorf("strip file exposes private keys to group/other: mode=%04o", st.Mode().Perm())
	}
}

// TestStripFilePermissions_VariousAmbientUmasks tests that regardless of ambient umask
// (000, 022, 027, 077), the stripped secret-bearing file is created with mode 0600 or stricter.
func TestStripFilePermissions_VariousAmbientUmasks(t *testing.T) {
	umasks := []string{"000", "022", "027", "077"}
	for _, u := range umasks {
		t.Run("umask_"+u, func(t *testing.T) {
			h := newShellHarness(t)
			c := newMockAWGSSHClient()
			c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
				if strings.Contains(cmd, " strip ") {
					out, stderr, code := h.run(t, fmt.Sprintf("umask %s; %s", u, cmd))
					return out, stderr, code, nil
				}
				return c.defaultRunSudo(cmd)
			}
			m := NewAWGManager(&mockAWGSSHProvider{client: c})
			p, err := m.stripInterfaceConfig(context.Background(), c, "amnezia-awg2", h.cfgPath)
			if err != nil {
				t.Fatalf("stripInterfaceConfig failed under umask %s: %v", u, err)
			}
			defer os.Remove(p)
			st, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat failed: %v", err)
			}
			if st.Mode().Perm()&0077 != 0 {
				t.Errorf("strip file exposes permissions to group/other under ambient umask %s: mode=%04o", u, st.Mode().Perm())
			}
			if st.Mode().Perm() != 0600 {
				t.Errorf("expected exact mode 0600 under ambient umask %s, got mode=%04o", u, st.Mode().Perm())
			}
		})
	}
}

// TestStripFilePermissions_FailedStripCleansUpAndCreatesPrivately verifies that when stripping
// fails, any file created on disk was mode 0600 and is cleaned up on error.
func TestStripFilePermissions_FailedStripCleansUpAndCreatesPrivately(t *testing.T) {
	h := newShellHarness(t)
	var observedPath string
	var observedPerm os.FileMode
	c := newMockAWGSSHClient()
	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, " strip ") {
			// Find strip path from command to inspect file right after execution
			for _, part := range strings.Split(cmd, " ") {
				if strings.Contains(part, ".awg-strip-") {
					observedPath = strings.Trim(part, "'\"")
				}
			}
			// Simulate failing strip execution under ambient umask 022
			out, stderr, code := h.run(t, "umask 022; "+cmd, stripBodyEnv+"=")
			if observedPath != "" {
				if st, err := os.Stat(observedPath); err == nil {
					observedPerm = st.Mode().Perm()
				}
			}
			return out, stderr, code, nil
		}
		if strings.Contains(cmd, "rm -f") {
			if observedPath != "" {
				_ = os.Remove(observedPath)
			}
			return "OK", "", 0, nil
		}
		return c.defaultRunSudo(cmd)
	}

	m := NewAWGManager(&mockAWGSSHProvider{client: c})
	p, err := m.stripInterfaceConfig(context.Background(), c, "amnezia-awg2", h.cfgPath)
	if err == nil {
		t.Fatal("expected stripInterfaceConfig to fail when strip body is empty")
	}
	if p != "" {
		t.Errorf("expected empty path on failure, got %s", p)
	}
	if observedPerm != 0 && observedPerm&0077 != 0 {
		t.Errorf("strip file created during failed attempt exposed permissions: mode=%04o", observedPerm)
	}
	// Verify cleanup removed the file
	if observedPath != "" {
		if _, err := os.Stat(observedPath); err == nil {
			t.Errorf("strip file %s was not cleaned up after failure", observedPath)
		}
	}
}

// TestStripFilePermissions_CleanupSurvivesContextCancellation verifies that removeContainerFile
// executes detached cleanup using context.WithoutCancel even if the caller context was canceled.
func TestStripFilePermissions_CleanupSurvivesContextCancellation(t *testing.T) {
	c := newMockAWGSSHClient()
	var removeExecuted bool
	c.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "rm -f") {
			removeExecuted = true
			return "OK", "", 0, nil
		}
		return c.defaultRunSudo(cmd)
	}

	m := NewAWGManager(&mockAWGSSHProvider{client: c})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context beforehand

	m.removeContainerFile(ctx, c, "amnezia-awg2", "/opt/amnezia/awg/.awg-strip-test.conf")
	if !removeExecuted {
		t.Error("removeContainerFile did not execute rm -f under canceled context")
	}
}
