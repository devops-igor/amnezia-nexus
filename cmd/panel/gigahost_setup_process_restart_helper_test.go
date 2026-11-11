package main

// Fresh-OS-process application lifecycle proof for durable unattended setup.
//
// Why this file exists
// --------------------
// gigahost_setup_lifecycle_test.go proves restart at the PERSISTENCE boundary: it
// calls run() and shuts it down, then calls run() again IN THE SAME OS PROCESS.
// That cannot exclude process memory as the thing that carried the resumed state,
// and its own header says so.
//
// Here the panel is started in a genuinely different OS process - this test binary
// re-executed with the repository's existing subprocess pattern (see
// internal/handlers/gigahost_setup_process_test.go and
// internal/config/secret_key_test.go) - twice, over the same disposable encrypted
// database. The parent asserts on the durable row and on an effects journal both
// processes append to, so "did the second process do it again?" is answered by
// evidence from that process.
//
// What a child process can observe WITHOUT a production test seam
// ---------------------------------------------------------------
// A child running run() has no test hooks, so only naturally reachable effects
// count. This file relies on four of them, all verified in the source:
//
//  1. Provider-unavailable progress. With GIGAHOST_API_KEY unset, provider
//     resolution fails and Tracker.RunOnce takes its resolveErr branch, recording a
//     read failure and leaving the intent pending (tracker.go:287-291, 375-392).
//     That is progress a stale memory cannot fake.
//  2. Default-off automatic refusal. The shipped binary never installs an
//     automation policy, so h.setupAutomationPolicy is nil and
//     requireAutomaticSetupEnabled returns ErrAutomaticSetupDisabled; for an
//     intent whose trust policy is first_contact, prepareInstall refuses BEFORE a
//     credential is sent or a host dialled (gigahost_setup_install.go:122-125).
//     This proves the real default is off, using the real default.
//  3. Identity preservation. Authority, mode, options, credential and pin are
//     durable columns; a second process must not rewrite them or add a row.
//  4. No replay of an uncertain install. A paused row is not even due for the
//     installer (gigahost_setup_intents.go:577-583 selects ready_for_setup and
//     installing only), and the automatic refusal above fires before any dial, so
//     a fresh process appends no install effect.
//
// What this file deliberately does NOT claim
// -----------------------------------------
// A HEALTHY installation completing in a child process is not provable from
// configuration alone: gigahost.NewClient takes no BaseURL override and there is
// no environment variable for one, so a child holding GIGAHOST_API_KEY would talk
// to the real provider - which this assignment forbids. Building that would need a
// product change (a base-URL configuration hook), not a test. So the tests below
// prove resumption, identity continuity, refusal and no-replay; they do not prove
// a completed install, and no assertion here says "ready" for that reason.
//
// Scope: this is application-process composition over a disposable database. It is
// not VPN traffic, not a real host, not a provider call, and not a whole-deployment
// acceptance.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const (
	// envRestartChild marks this binary as the child and names what it must do.
	envRestartChild = "PANEL_RESTART_CHILD_MODE"
	// envRestartPort is the loopback port the child's HTTP server binds.
	envRestartPort = "PANEL_RESTART_CHILD_PORT"
	// envRestartJournal is the effects file both processes append to.
	envRestartJournal = "PANEL_RESTART_CHILD_JOURNAL"
	// envRestartReady is a marker file the child creates once run() is serving.
	envRestartReady = "PANEL_RESTART_CHILD_READY"
)

// Child modes. Each starts the real application once and stops it.
const (
	// modeServe: boot run(), wait until the HTTP listener answers, then shut down
	// cleanly. Used for both the first and the second lifecycle.
	modeServe = "serve"
)

// restartFixtureSecret is a fixed 32-byte test key. It is a fixture value, not a
// deployment secret, and it never leaves this process except as an environment
// entry for the child.
const restartFixtureSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// restartChildTimeout bounds one child process end to end.
const restartChildTimeout = 90 * time.Second

// TestPanelRestartChildHelper is the child entry point.
//
// It returns immediately unless the parent set the mode variable, so it is inert
// during an ordinary test run. This is the pattern internal/config and
// internal/handlers already use for their multi-process tests, not a new runtime
// mode.
func TestPanelRestartChildHelper(t *testing.T) {
	mode := os.Getenv(envRestartChild)
	if mode == "" {
		return
	}
	if mode != modeServe {
		fmt.Fprintf(os.Stderr, "restart child: unknown mode %q\n", mode)
		os.Exit(4)
	}
	os.Exit(runServeChild())
}

// runServeChild boots the real application, reports readiness, and shuts it down.
//
// Exit codes are the child's out-of-band report:
//
//	0  run() completed cleanly after a real HTTP bind
//	3  the server never became ready, or run() returned an error
//	4  the child's environment is incomplete
func runServeChild() int {
	port := os.Getenv(envRestartPort)
	journal := os.Getenv(envRestartJournal)
	readyPath := os.Getenv(envRestartReady)
	if port == "" || journal == "" || readyPath == "" {
		fmt.Fprintln(os.Stderr, "restart child: required environment is missing")
		return 4
	}
	// The application refuses to start without a secret; the parent supplies it
	// through the environment exactly as a deployment does.
	if strings.TrimSpace(os.Getenv("SECRET_KEY")) == "" {
		fmt.Fprintln(os.Stderr, "restart child: SECRET_KEY is not set")
		return 4
	}

	appendEffect(journal, "boot")

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx) }()

	// Readiness is observed from OUTSIDE run(): poll the port it binds. Waiting on
	// run()'s own internals would need a seam; a TCP accept needs none.
	if !waitLoopbackReady(port, 30*time.Second) {
		cancel()
		select {
		case err := <-errCh:
			fmt.Fprintf(os.Stderr, "restart child: run() returned before serving: %v\n", err)
		case <-time.After(15 * time.Second):
			fmt.Fprintln(os.Stderr, "restart child: run() did not return after cancellation")
		}
		return 3
	}
	// The application is serving: record that fact for the parent, then allow it a
	// moment to complete its first supervisor pass (the tracker's initial pass runs
	// immediately at startup).
	_ = os.WriteFile(readyPath, []byte("ready\n"), 0o600)
	appendEffect(journal, "serving")
	time.Sleep(1500 * time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "restart child: run() returned %v on shutdown\n", err)
			return 3
		}
		appendEffect(journal, "clean_shutdown")
		return 0
	case <-time.After(30 * time.Second):
		fmt.Fprintln(os.Stderr, "restart child: run() did not shut down within 30s")
		return 3
	}
}

// waitLoopbackReady polls a TCP accept on the loopback port run() binds.
func waitLoopbackReady(port string, limit time.Duration) bool {
	addr := net.JoinHostPort("127.0.0.1", port)
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// appendEffect appends "kind\n" to the shared journal. Appending is the point: two
// OS processes record into one file, so the parent can count each process's work.
func appendEffect(path, kind string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(kind + "\n")
}

// effectCount counts journal lines of one kind.
func effectCount(path, kind string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == kind {
			count++
		}
	}
	return count
}

// restartEnv is one disposable application environment shared by both children.
type restartEnv struct {
	t       *testing.T
	dataDir string
	dbPath  string
	journal string
	port    string
}

// newRestartEnv creates the isolated environment: its own data directory, its own
// encrypted database, its own journal and its own reserved loopback port.
//
// Ports are reserved and released rather than reused across children, and the two
// children run sequentially - never concurrently - because they share one SQLite
// file and each binds a listener.
func newRestartEnv(t *testing.T) *restartEnv {
	t.Helper()
	dir := t.TempDir()
	return &restartEnv{
		t:       t,
		dataDir: dir,
		dbPath:  filepath.Join(dir, "panel_restart.db"),
		journal: filepath.Join(dir, "effects.log"),
		port:    reserveLoopbackPort(t),
	}
}

// reserveLoopbackPort returns a currently unused loopback port.
func reserveLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release loopback port: %v", err)
	}
	return strconv.Itoa(port)
}

// startChild runs one real application process and returns its exit code and
// captured output.
//
// The child's environment is built explicitly instead of inherited wholesale, so a
// developer's own DATA_DIR, GIGAHOST_API_KEY or VPN_ENABLED cannot silently change
// what the child does. VPN_ENABLED is omitted deliberately: VPN is opt-in, and
// leaving it unset is what keeps the fixture from touching a TUN device.
func (e *restartEnv) startChild() (exitCode int, stdout, stderr string) {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), restartChildTimeout)
	defer cancel()

	readyPath := filepath.Join(e.dataDir, "ready-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestPanelRestartChildHelper$",
		"-test.timeout="+restartChildTimeout.String())
	cmd.Env = append(childEnvironment(e.dataDir, e.dbPath, e.port, e.journal, readyPath),
		envRestartChild+"="+modeServe,
		envRestartPort+"="+e.port,
		envRestartJournal+"="+e.journal,
		envRestartReady+"="+readyPath,
	)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()

	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if ctx.Err() != nil {
			e.t.Fatalf("child exceeded the %s budget: %v\nstdout:\n%s\nstderr:\n%s",
				restartChildTimeout, err, outBuf.String(), errBuf.String())
		} else {
			e.t.Fatalf("child failed to run: %v", err)
		}
	}
	if code != 0 {
		e.t.Fatalf("child exited %d\nstdout:\n%s\nstderr:\n%s",
			code, outBuf.String(), errBuf.String())
	}
	return code, outBuf.String(), errBuf.String()
}

// childEnvironment builds the child's environment from a small explicit allowlist.
//
// Only PATH, HOME and TMPDIR are inherited (a Go toolchain and SQLite need nothing
// more), plus the fixture's own DATA_DIR/DB_PATH/SECRET_KEY/PORT. VPN_ENABLED and
// GIGAHOST_API_KEY are deliberately absent.
func childEnvironment(dataDir, dbPath, port, journal, readyPath string) []string {
	_ = journal
	_ = readyPath
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.Getenv("TMPDIR"),
		"DATA_DIR=" + dataDir,
		"DB_PATH=" + dbPath,
		"SECRET_KEY=" + restartFixtureSecret,
		"PORT=" + port,
		"HOST=127.0.0.1",
		"LOG_LEVEL=WARN",
	}
	// GIGAHOST_API_KEY is intentionally not forwarded: provider resolution must
	// fail, which is the safe, observable state these tests are built on.
	return env
}

// openDB opens the environment's database with the fixture secret.
func (e *restartEnv) openDB() *database.DB {
	e.t.Helper()
	db, err := database.Open(e.dbPath, restartFixtureSecret)
	if err != nil {
		e.t.Fatalf("open fixture database: %v", err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedIntent records one approval in the requested persisted shape.
//
// The row is written with the application's own encrypted credential path, so the
// child reads real persisted state rather than a hand-built file.
func (e *restartEnv) seedIntent(shape restartShape) *models.GigahostSetupIntent {
	e.t.Helper()
	db := e.openDB()
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID:    restartOrderID,
		ServerID:   4101,
		Status:     "ready",
		AssignedIP: "198.51.100.77",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		e.t.Fatalf("seed order: %v", err)
	}
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:    restartOrderID,
		PrivateKey: "FIXTURE-ONLY-PRIVATE-KEY-BODY-NOT-A-REAL-KEY",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	}); err != nil {
		e.t.Fatalf("seed credential: %v", err)
	}

	intent := &models.GigahostSetupIntent{
		OrderID:          restartOrderID,
		ProviderServerID: 4101,
		AssignedIP:       "198.51.100.77",
		Protocol:         models.ProtocolAWG,
		Port:             "51820",
		CredentialMode:   models.SetupCredentialManaged,
		HostFingerprint:  restartFixtureFingerprint,
		HostTrustPolicy:  shape.trustPolicy,
		State:            models.SetupStatePending,
		Step:             "approved",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if shape.state != "" {
		intent.State = shape.state
		intent.Step = shape.state
	}
	if shape.installPhase != "" {
		intent.InstallPhase = shape.installPhase
		intent.InstallGeneration = 3
	}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		e.t.Fatalf("seed intent: %v", err)
	}
	got, found, err := db.GetGigahostSetupIntent(ctx, restartOrderID)
	if err != nil || !found {
		e.t.Fatalf("read seeded intent: found=%v err=%v", found, err)
	}
	return got
}

const (
	// restartOrderID is the single order these proofs use.
	restartOrderID = "ord_panel_restart"
	// restartFixtureFingerprint is a syntactically valid canonical SHA256 pin.
	restartFixtureFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// restartShape describes the persisted situation to seed.
type restartShape struct {
	// trustPolicy selects automatic (first_contact) or manual (anything else)
	// provenance; it is the switch the policy gate keys on.
	trustPolicy string
	// state overrides the initial state (default pending).
	state string
	// installPhase seeds an in-flight install journal, which is what an
	// interrupted attempt leaves behind.
	installPhase string
}

// readIntent reloads the row a child left behind.
func (e *restartEnv) readIntent() *models.GigahostSetupIntent {
	e.t.Helper()
	db := e.openDB()
	intent, found, err := db.GetGigahostSetupIntent(context.Background(), restartOrderID)
	if err != nil || !found {
		e.t.Fatalf("re-read intent: found=%v err=%v", found, err)
	}
	return intent
}

// requireStillPending asserts the child made provider-unavailable progress without
// settling the job. This is the distinction the acceptance demands: pending progress
// is not a healthy installation.
func (e *restartEnv) requireStillPending(after, before *models.GigahostSetupIntent, when string) {
	e.t.Helper()
	if after.State != models.SetupStatePending {
		e.t.Fatalf("%s: state = %q, want %q (step %q, last error %q)",
			when, after.State, models.SetupStatePending, after.Step, after.LastError)
	}
	if after.Attempts <= before.Attempts {
		e.t.Fatalf("%s: the child process did not track the saved approval (attempts stayed at %d)",
			when, before.Attempts)
	}
	if after.ReadFailures == 0 {
		e.t.Fatalf("%s: no provider read failure was recorded, so the child did not attempt the read",
			when)
	}
	// A pending row must never present itself as a completed installation.
	if after.Step == "ready" || after.State == models.SetupStateReady {
		e.t.Fatalf("%s: a pending job was reported as completed", when)
	}
}

// requireIdentityPreserved asserts the restart did not rewrite the identities the
// acceptance names: authority, mode, options, credential and pin.
func (e *restartEnv) requireIdentityPreserved(after, before *models.GigahostSetupIntent, when string) {
	e.t.Helper()
	if after.Protocol != before.Protocol || after.Port != before.Port {
		e.t.Fatalf("%s: approved options changed: protocol %q->%q port %q->%q",
			when, before.Protocol, after.Protocol, before.Port, after.Port)
	}
	if after.CredentialMode != before.CredentialMode {
		e.t.Fatalf("%s: credential mode changed: %q->%q", when, before.CredentialMode, after.CredentialMode)
	}
	if after.HostTrustPolicy != before.HostTrustPolicy {
		e.t.Fatalf("%s: trust policy changed: %q->%q", when, before.HostTrustPolicy, after.HostTrustPolicy)
	}
	if after.HostFingerprint != before.HostFingerprint {
		e.t.Fatalf("%s: the pinned host identity was rewritten: %q -> %q",
			when, before.HostFingerprint, after.HostFingerprint)
	}
	if after.ProviderServerID != before.ProviderServerID || after.AssignedIP != before.AssignedIP {
		e.t.Fatalf("%s: the resource association changed: server %d->%d address %q->%q",
			when, before.ProviderServerID, after.ProviderServerID, before.AssignedIP, after.AssignedIP)
	}
	// The stored credential must still decrypt in a process that never saw it.
	db := e.openDB()
	cred, found, err := db.GetGigahostOrderCredential(context.Background(), restartOrderID)
	if err != nil || !found {
		e.t.Fatalf("%s: the managed credential is no longer readable: found=%v err=%v", when, found, err)
	}
	if cred.PrivateKey == "" {
		e.t.Fatalf("%s: the managed credential decrypted to nothing", when)
	}
}

// requireSingleIntent asserts the restart did not create a second job.
func (e *restartEnv) requireSingleIntent(when string) {
	e.t.Helper()
	db := e.openDB()
	intents, err := db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		e.t.Fatalf("%s: list intents: %v", when, err)
	}
	if len(intents) != 1 {
		e.t.Fatalf("%s: intent count = %d, want exactly 1 (a restart must not add a job)",
			when, len(intents))
	}
}

// makeWorkDue moves the persisted next-attempt into the past, modelling a panel that
// was offline longer than the backoff its previous pass scheduled.
//
// Honouring the saved backoff is deliberate behaviour, not a bug: a restart must not
// hammer the provider. This helper only creates the elapsed-time condition a real
// downtime would have produced anyway - the same reasoning the existing
// same-process lifecycle fixture uses.
func (e *restartEnv) makeWorkDue() {
	e.t.Helper()
	db := e.openDB()
	ctx := context.Background()
	intent, found, err := db.GetGigahostSetupIntent(ctx, restartOrderID)
	if err != nil || !found {
		e.t.Fatalf("read intent before making work due: found=%v err=%v", found, err)
	}
	intent.NextAttemptAt = time.Now().UTC().Add(-time.Minute)
	changed, err := db.TransitionGigahostSetupIntent(ctx, intent, []string{models.SetupStatePending})
	if err != nil {
		e.t.Fatalf("make saved work due: %v", err)
	}
	if !changed {
		e.t.Fatalf("could not make saved work due: intent is in state %q", intent.State)
	}
}
