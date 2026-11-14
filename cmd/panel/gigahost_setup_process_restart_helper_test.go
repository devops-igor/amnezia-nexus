package main

// Fresh-OS-process restart fixture: parent/child plumbing and durable oracles.
//
// The existing gigahost_setup_lifecycle_test.go restarts at the persistence boundary
// only - run() twice in one OS process - so process memory cannot be excluded. Here
// the real application runs in a genuinely separate OS process (this test binary
// re-executed, the pattern internal/handlers and internal/config already use) over
// the same disposable encrypted database.
//
// Which observations are REAL
// ---------------------------
// A child running run() has no test hooks, so only state production itself writes may
// be asserted. Two producers are used, plus the tracker's own row writes:
//
//	P1 install-claim generation. Installer.claim increments InstallGeneration in the
//	   database before any install work (installer.go:247-276). A generation that
//	   advanced proves the installer worker ran a real pass over the row - the
//	   precondition required before any refusal may be claimed.
//	P2 persisted pause boundary. InstallJournal.Pause writes state=install_paused with
//	   the step that stopped it (installer.go:374-384). The step string discriminates:
//	   an automatic policy refusal stops at "automatic_setup_disabled", while a manual
//	   job is answered nil by automaticJobRefusal and stops elsewhere.
//	T  tracker row writes. recordReadFailure advances Attempts/ReadFailures and leaves
//	   the row pending with step "provider_unreadable" (tracker.go:287-291, 347-392).
//
// There is deliberately no test-side effects journal: an earlier version appended
// "install"/"enable" markers nothing in production ever wrote, so zero counts proved
// nothing. Effects are now read from the durable row, which production owns.
//
// What is NOT proven here
// -----------------------
//   - A healthy installation completing in a child: gigahost.NewClient takes no
//     base-URL override and no environment variable supplies one, so a child holding
//     GIGAHOST_API_KEY would reach the real provider. Out of scope.
//   - Child-side credential use: the child never reports it. The parent asserts only
//     that the credential still decrypts after the child ran.
//   - Loopback-only binding: HOST is pinned to 127.0.0.1 and Server.Start binds that
//     address (server.go:199), but a successful connect cannot prove no 0.0.0.0 bind
//     exists. The claim is limited to "it answered on loopback".
//
// Scope: application-process composition over a disposable database. Not VPN traffic,
// not a real host, not a provider call, not whole-deployment acceptance.

import (
	"context"
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
	// envChildMode marks this binary as the child process.
	envChildMode = "PANEL_RESTART_CHILD_MODE"
	// envChildPort is the loopback port the child's HTTP server binds.
	envChildPort = "PANEL_RESTART_CHILD_PORT"
	// envChildJournal records only markers the child itself emits (boot,
	// clean_shutdown). It carries no effect claims.
	envChildJournal = "PANEL_RESTART_CHILD_JOURNAL"
)

// childModeServe boots run(), waits for the loopback listener, then shuts down.
const childModeServe = "serve"

// restartSecret is a fixed 32-byte fixture key. Not a deployment secret.
const restartSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// childTimeout bounds one child process end to end.
const childTimeout = 90 * time.Second

// serveDwell is how long the child stays up after its listener answers. The first
// supervisor pass runs immediately at startup, so this only needs to exceed one pass;
// the parent still asserts the persisted outcome rather than trusting the duration.
const serveDwell = 2 * time.Second

// TestPanelRestartChildHelper is the child entry point. It is inert unless the parent
// set the mode variable, so an ordinary test run does nothing.
func TestPanelRestartChildHelper(t *testing.T) {
	mode := os.Getenv(envChildMode)
	if mode == "" {
		return
	}
	if mode != childModeServe {
		os.Exit(4)
	}
	os.Exit(serveChild())
}

// serveChild boots the real application, reports the listener, and shuts down.
//
// Exit codes: 0 clean lifecycle, 3 the server never answered or run() failed, 4
// incomplete environment.
func serveChild() int {
	port := os.Getenv(envChildPort)
	journal := os.Getenv(envChildJournal)
	if port == "" || journal == "" || strings.TrimSpace(os.Getenv("SECRET_KEY")) == "" {
		return 4
	}

	appendMarker(journal, "boot")
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx) }()

	if !waitLoopbackListener(port, 30*time.Second) {
		cancel()
		select {
		case <-errCh:
		case <-time.After(15 * time.Second):
		}
		return 3
	}
	appendMarker(journal, "serving")
	time.Sleep(serveDwell)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			return 3
		}
		appendMarker(journal, "clean_shutdown")
		return 0
	case <-time.After(30 * time.Second):
		return 3
	}
}

// waitLoopbackListener polls until the port accepts, which is the child's own
// listener answering. It cannot prove the absence of a wider bind.
func waitLoopbackListener(port string, limit time.Duration) bool {
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

// appendMarker appends one child-emitted lifecycle marker.
func appendMarker(path, kind string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(kind + "\n")
}

// markerCount counts one child-emitted marker kind.
func markerCount(path, kind string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == kind {
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

// newRestartEnv creates an isolated home: its own DATA_DIR, database, journal and
// reserved loopback port, all inside t.TempDir().
func newRestartEnv(t *testing.T) *restartEnv {
	t.Helper()
	dir := t.TempDir()
	return &restartEnv{
		t:       t,
		dataDir: dir,
		dbPath:  filepath.Join(dir, "panel_restart.db"),
		journal: filepath.Join(dir, "lifecycle.log"),
		port:    reservePort(t),
	}
}

func reservePort(t *testing.T) string {
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

// startChild runs one real application process, failing the test on a non-zero exit
// and reporting the child's own output.
//
// The environment is an explicit allowlist, so a developer's own DATA_DIR,
// VPN_ENABLED or GIGAHOST_API_KEY cannot change what the child does.
func (e *restartEnv) startChild() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), childTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestPanelRestartChildHelper$",
		"-test.timeout="+childTimeout.String())
	cmd.Env = append([]string{
		"HOME=" + e.dataDir,
		"TMPDIR=" + e.dataDir,
		"PATH=" + os.Getenv("PATH"),
		"DATA_DIR=" + e.dataDir,
		"DB_PATH=" + e.dbPath,
		"SECRET_KEY=" + restartSecret,
		"HOST=127.0.0.1",
		"PORT=" + e.port,
		"LOG_LEVEL=WARN",
	},
		envChildMode+"="+childModeServe,
		envChildPort+"="+e.port,
		envChildJournal+"="+e.journal,
	)
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		e.t.Fatalf("child failed (%v)\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	// A credential value must never reach any log.
	if strings.Contains(out.String()+errOut.String(), "PRIVATE-KEY-BODY") {
		e.t.Fatal("a fixture credential body appeared in child output")
	}
}

// open opens the environment database with the fixture secret.
func (e *restartEnv) open() *database.DB {
	e.t.Helper()
	db, err := database.Open(e.dbPath, restartSecret)
	if err != nil {
		e.t.Fatalf("open fixture database: %v", err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	return db
}

const (
	restartOrderID   = "ord_panel_restart"
	restartPin       = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	restartAssigned  = "198.51.100.77"
	restartPortValue = "51820"
	// fixtureKeyBody is synthetic and must never be printed.
	fixtureKeyBody = "FIXTURE-ONLY-PRIVATE-KEY-BODY-NOT-A-REAL-KEY"
)

// restartProvider is the provider server id these fixtures claim.
const restartProvider int64 = 4101

// seedShape describes the persisted situation to create.
type seedShape struct {
	// trustPolicy: models.SetupTrustPolicyFirstContact for unattended, "" for manual.
	trustPolicy string
	// state overrides pending.
	state string
	// installPhase/installDone seed an interrupted install journal.
	installPhase string
	installDone  string
	// generation seeds InstallGeneration (non-zero with a phase).
	generation int64
}

// seed writes one order, its encrypted credential and one intent, through the
// application's own APIs, and returns the row as persisted.
func (e *restartEnv) seed(shape seedShape) *models.GigahostSetupIntent {
	e.t.Helper()
	db := e.open()
	ctx := context.Background()
	now := time.Now().UTC()

	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: restartOrderID, ServerID: restartProvider, Status: "ready",
		AssignedIP: restartAssigned, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed order: %v", err)
	}
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:    restartOrderID,
		PrivateKey: fixtureKeyBody,
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	}); err != nil {
		e.t.Fatalf("seed credential: %v", err)
	}

	intent := &models.GigahostSetupIntent{
		OrderID:           restartOrderID,
		ProviderServerID:  restartProvider,
		AssignedIP:        restartAssigned,
		Protocol:          models.ProtocolAWG,
		Port:              restartPortValue,
		CredentialMode:    models.SetupCredentialManaged,
		HostFingerprint:   restartPin,
		HostTrustPolicy:   shape.trustPolicy,
		HostTrustMode:     models.SetupTrustModeConfirmed,
		State:             models.SetupStatePending,
		Step:              "approved",
		CreatedAt:         now,
		UpdatedAt:         now,
		InstallPhase:      shape.installPhase,
		InstallPhaseDone:  shape.installDone,
		InstallGeneration: shape.generation,
	}
	if shape.state != "" {
		intent.State = shape.state
		intent.Step = shape.state
	}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		e.t.Fatalf("seed intent: %v", err)
	}
	return e.read()
}

// read reloads the row.
func (e *restartEnv) read() *models.GigahostSetupIntent {
	e.t.Helper()
	intent, found, err := e.open().GetGigahostSetupIntent(context.Background(), restartOrderID)
	if err != nil || !found {
		e.t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	return intent
}

// requireNotReady fails if any lifecycle claimed a completed job.
func (e *restartEnv) requireNotReady(got *models.GigahostSetupIntent, when string) {
	e.t.Helper()
	if got.State == models.SetupStateReady {
		e.t.Fatalf("%s: a completed job was reported (step %q, last error %q)",
			when, got.Step, got.LastError)
	}
}

// requireWorkerPassed asserts the installer worker actually ran a pass, which is the
// precondition for any refusal claim. P1: production's claim() increments the
// generation before doing any install work.
func (e *restartEnv) requireWorkerPassed(before, after *models.GigahostSetupIntent, when string) {
	e.t.Helper()
	if after.InstallGeneration <= before.InstallGeneration {
		e.t.Fatalf("%s: the installer worker never claimed the row (generation stayed at %d), "+
			"so this case cannot say anything about refusal", when, before.InstallGeneration)
	}
}

// requireAutomaticPolicyRefusal asserts the refusal happened at the automatic policy
// boundary. P2: the paused step names it.
func (e *restartEnv) requireAutomaticPolicyRefusal(got *models.GigahostSetupIntent, when string) {
	e.t.Helper()
	if got.State != models.SetupStateInstallPaused {
		e.t.Fatalf("%s: state = %q, want %q (step %q, last error %q)",
			when, got.State, models.SetupStateInstallPaused, got.Step, got.LastError)
	}
	if got.Step != "automatic_setup_disabled" {
		e.t.Fatalf("%s: the pause was at step %q, want the automatic policy boundary %q "+
			"(last error %q)", when, got.Step, "automatic_setup_disabled", got.LastError)
	}
	if !strings.Contains(got.LastError, "not enabled") {
		e.t.Fatalf("%s: the refusal reason does not name the disabled policy: %q", when, got.LastError)
	}
}

// requireIdentityPreserved compares every persisted identity field. It says nothing
// about the child's internal use of the credential; see the file header.
func (e *restartEnv) requireIdentityPreserved(before, after *models.GigahostSetupIntent, when string) {
	e.t.Helper()
	if after.Protocol != before.Protocol || after.Port != before.Port {
		e.t.Fatalf("%s: approved options changed: %q/%q -> %q/%q",
			when, before.Protocol, before.Port, after.Protocol, after.Port)
	}
	if after.CredentialMode != before.CredentialMode {
		e.t.Fatalf("%s: credential mode changed: %q -> %q", when, before.CredentialMode, after.CredentialMode)
	}
	if after.ProviderServerID != before.ProviderServerID || after.AssignedIP != before.AssignedIP {
		e.t.Fatalf("%s: resource association changed: %d/%q -> %d/%q", when,
			before.ProviderServerID, before.AssignedIP, after.ProviderServerID, after.AssignedIP)
	}
	// Authority: the full set, not just the policy string.
	if after.HostTrustPolicy != before.HostTrustPolicy ||
		after.HostTrustMode != before.HostTrustMode ||
		after.HostFingerprint != before.HostFingerprint ||
		after.HostCandidateFingerprint != before.HostCandidateFingerprint ||
		after.HostTrustOrderID != before.HostTrustOrderID ||
		after.HostTrustServerID != before.HostTrustServerID ||
		after.HostTrustAddress != before.HostTrustAddress ||
		after.HostTrustKeyID != before.HostTrustKeyID ||
		!after.HostTrustGrantedAt.Equal(before.HostTrustGrantedAt) {
		e.t.Fatalf("%s: persisted authority changed across the process boundary:\n"+
			"  before policy=%q mode=%q pin=%q candidate=%q order=%q server=%d addr=%q key=%d granted=%s\n"+
			"  after  policy=%q mode=%q pin=%q candidate=%q order=%q server=%d addr=%q key=%d granted=%s",
			when,
			before.HostTrustPolicy, before.HostTrustMode, before.HostFingerprint,
			before.HostCandidateFingerprint, before.HostTrustOrderID, before.HostTrustServerID,
			before.HostTrustAddress, before.HostTrustKeyID, before.HostTrustGrantedAt,
			after.HostTrustPolicy, after.HostTrustMode, after.HostFingerprint,
			after.HostCandidateFingerprint, after.HostTrustOrderID, after.HostTrustServerID,
			after.HostTrustAddress, after.HostTrustKeyID, after.HostTrustGrantedAt)
	}
	// The credential must still decrypt after the child ran. Child-side use is not
	// observable; this is durable continuity only, and is labelled as such.
	cred, found, err := e.open().GetGigahostOrderCredential(context.Background(), restartOrderID)
	if err != nil || !found {
		e.t.Fatalf("%s: the managed credential is unreadable after the child ran: found=%v err=%v",
			when, found, err)
	}
	if cred.PrivateKey != fixtureKeyBody {
		e.t.Fatalf("%s: the stored credential material changed across the process boundary", when)
	}
}

// requireSingleIntent asserts no second job was created.
func (e *restartEnv) requireSingleIntent(when string) {
	e.t.Helper()
	intents, err := e.open().ListGigahostSetupIntents(context.Background())
	if err != nil {
		e.t.Fatalf("%s: list intents: %v", when, err)
	}
	if len(intents) != 1 {
		e.t.Fatalf("%s: intent count = %d, want exactly 1", when, len(intents))
	}
}

// makeWorkDue ages the persisted next-attempt so a resumed pass is due, which is what
// downtime would have produced. Honouring the backoff is deliberate.
func (e *restartEnv) makeWorkDue() {
	e.t.Helper()
	db := e.open()
	ctx := context.Background()
	intent := e.read()
	intent.NextAttemptAt = time.Now().UTC().Add(-time.Minute)
	changed, err := db.TransitionGigahostSetupIntent(ctx, intent, []string{models.SetupStatePending})
	if err != nil || !changed {
		e.t.Fatalf("make saved work due: changed=%v err=%v (state %q)", changed, err, intent.State)
	}
}
