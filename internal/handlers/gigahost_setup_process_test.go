package handlers

// Parent side of the fresh-process proof.
//
// Each test here seeds ONE persisted situation in a temporary database, starts a
// genuinely separate process over it, and asserts on two independent things:
//
//  1. the outcome the child reported about the persisted row, and
//  2. the effect journal the child appended to, which is how "did it install or
//     enable again?" is answered by evidence from the child's own run rather than
//     by a counter the parent happened to hold.
//
// The child is always bounded by a parent timeout, and a non-zero exit is a test
// failure with the child's stderr, never a silent skip.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// processProofTimeout bounds one child process. The work is a single installer
// pass over a local database, so this is generous rather than tight.
const processProofTimeout = 90 * time.Second

// processProofEnv is one temporary database plus its effect journal.
type processProofEnv struct {
	t       *testing.T
	dbPath  string
	journal string
	secret  string
}

func newProcessProofEnv(t *testing.T, secret string) *processProofEnv {
	t.Helper()
	dir := t.TempDir()
	return &processProofEnv{
		t:       t,
		dbPath:  filepath.Join(dir, "process_proof.db"),
		journal: filepath.Join(dir, "effects.log"),
		secret:  secret,
	}
}

// childResult is what one child process reported.
type childResult struct {
	exitCode int
	stdout   string
	stderr   string
}

// runChild starts a genuinely separate process of this test binary in one mode.
//
// The exit code is read from the process itself, and stdout/stderr are captured so
// a violation is reported with the child's own words.
func (e *processProofEnv) runChild(mode, secret string) childResult {
	e.t.Helper()
	return e.runChildWith(mode, secret)
}

// runChildWith is runChild plus extra environment entries, used by controls that
// must hand the child a specific stale generation.
func (e *processProofEnv) runChildWith(mode, secret string, extraEnv ...string) childResult {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), processProofTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestSetupInstallProcessHelper$",
		"-test.timeout="+processProofTimeout.String())
	cmd.Env = append(filteredProcessEnv(),
		envProcessMode+"="+mode,
		envProcessDBPath+"="+e.dbPath,
		envProcessJournal+"="+e.journal,
		envProcessSecret+"="+secret,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	result := childResult{exitCode: 0, stdout: stdout.String(), stderr: stderr.String()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.exitCode = exitErr.ExitCode()
		} else if ctx.Err() != nil {
			e.t.Fatalf("child mode %q exceeded the parent timeout %s: %v\nstdout:\n%s\nstderr:\n%s",
				mode, processProofTimeout, err, result.stdout, result.stderr)
		} else {
			e.t.Fatalf("child mode %q failed to run: %v", mode, err)
		}
	}
	// A credential value must never appear in any output, success or failure.
	e.assertNoSecretInOutput(result, secret)
	return result
}

// seedRegisteredServer records the panel server the journal's completed
// registration implies, with the identity the approval confirmed.
//
// When the journal also claims the installation is proven, the server row must
// carry that installation - a row with no protocol metadata would be a
// contradiction between durable records, and enablement is right to refuse it.
func (e *processProofEnv) seedRegisteredServer(db *database.DB, withInstalledProtocol bool) {
	e.t.Helper()
	protocols := map[string]any{"provider": "gigahost", "provider_server_id": 7001}
	if withInstalledProtocol {
		protocols[models.ProtocolAWG] = map[string]any{
			"installed":  true,
			"port":       "51820",
			"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
		}
	}
	if _, err := db.CreateServerWithFingerprint(context.Background(), &models.Server{
		Name:      "Gigahost-process-proof",
		Host:      "198.51.100.200",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: protocols,
		CreatedAt: time.Now().UTC(),
	}, installFixtureFingerprint); err != nil {
		e.t.Fatalf("seed registered server: %v", err)
	}
}

// assertNoSecretInOutput fails the test if the fixture key body leaked.
func (e *processProofEnv) assertNoSecretInOutput(result childResult, secret string) {
	e.t.Helper()
	for _, body := range []string{processProofPlaintext, secret} {
		if body == "" {
			continue
		}
		if strings.Contains(result.stdout, body) || strings.Contains(result.stderr, body) {
			e.t.Fatalf("a credential value appeared in child output; refusing to report it")
		}
	}
}

// requireExit asserts the child's exit code.
func (e *processProofEnv) requireExit(result childResult, want int, what string) {
	e.t.Helper()
	if result.exitCode != want {
		e.t.Fatalf("%s: child exit = %d, want %d\nstdout:\n%s\nstderr:\n%s",
			what, result.exitCode, want, result.stdout, result.stderr)
	}
}

// open opens the database the child used.
func (e *processProofEnv) open() *database.DB {
	e.t.Helper()
	db, err := database.Open(e.dbPath, e.secret)
	if err != nil {
		e.t.Fatalf("open proof database: %v", err)
	}
	e.t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedOrderAndCredential records the placed order and its encrypted credential.
func (e *processProofEnv) seedOrderAndCredential(db *database.DB, withCredential bool) {
	e.t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: processProofOrderID, ServerID: 7001, Status: "ready",
		AssignedIP: "198.51.100.200", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed order: %v", err)
	}
	if !withCredential {
		return
	}
	// Stored through the application's own encryption boundary.
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:       processProofOrderID,
		PrivateKey:    processProofPlaintext,
		PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
		ProviderKeyID: 424242,
	}); err != nil {
		e.t.Fatalf("seed credential: %v", err)
	}
}

// seedIntent records an approval in the requested persisted shape.
func (e *processProofEnv) seedIntent(db *database.DB, shape processProofShape) *models.GigahostSetupIntent {
	e.t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	intent := &models.GigahostSetupIntent{
		OrderID:           processProofOrderID,
		ProviderServerID:  7001,
		AssignedIP:        "198.51.100.200",
		Protocol:          models.ProtocolAWG,
		Port:              "51820",
		CredentialMode:    models.SetupCredentialManaged,
		HostFingerprint:   installFixtureFingerprint,
		State:             models.SetupStateReadyForSetup,
		Step:              "approved",
		InstallGeneration: 1,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	// The persisted situation is written directly at create time. The journal writer
	// deliberately accepts only `installing`, so it cannot be used to force a terminal
	// state - and using it that way silently matched nothing.
	if shape.state != "" {
		intent.State = shape.state
		intent.Step = shape.state
	} else if shape.installing {
		intent.State = models.SetupStateInstalling
	}
	if shape.phase != "" {
		intent.InstallPhase = shape.phase
	}
	if shape.phaseDone != "" {
		intent.InstallPhaseDone = shape.phaseDone
	}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		e.t.Fatalf("seed intent: %v", err)
	}
	if shape.serverRegistered {
		// A journal that claims registration implies a server row. Seeding one keeps
		// the durable records consistent instead of handing the code a contradiction
		// that it is right to refuse.
		e.seedRegisteredServer(db, shape.installProven)
	}
	if shape.revoked {
		if _, changed, err := db.CancelGigahostSetupIntent(ctx, processProofOrderID, "revoked"); err != nil || !changed {
			e.t.Fatalf("seed revocation: changed=%v err=%v", changed, err)
		}
	}
	if shape.resumeToInstalling {
		// A resume is only accepted from a state that stopped for a decision, so the
		// row is moved to the paused state first - exactly the persisted situation a
		// paused-then-resumed job has. The resume then issues a NEW generation, so any
		// writer holding the old number is superseded.
		paused := *intent
		paused.State = models.SetupStateInstallPaused
		paused.Step = models.SetupStateInstallPaused
		if _, err := db.UpdateGigahostSetupInstall(ctx, &paused, intent.InstallGeneration); err != nil {
			e.t.Fatalf("seed paused state before resume: %v", err)
		}
		if _, changed, err := db.ResumeGigahostSetupInstall(ctx, processProofOrderID); err != nil || !changed {
			e.t.Fatalf("resume seeded row: changed=%v err=%v", changed, err)
		}
	}
	got, found, err := db.GetGigahostSetupIntent(ctx, processProofOrderID)
	if err != nil || !found {
		e.t.Fatalf("read seeded intent: found=%v err=%v", found, err)
	}
	return got
}

// processProofShape describes the persisted situation to seed.
type processProofShape struct {
	// installing seeds the row at the install handoff's claimed state.
	installing bool
	// state seeds an explicit state at create time (terminal states included).
	state string
	// phase/phaseDone are the persisted crash journal.
	phase     string
	phaseDone string
	// serverRegistered seeds the server row that the journal's completed
	// registration implies; without it the records contradict and the code
	// correctly refuses.
	serverRegistered bool
	// installProven seeds the server row with the protocol metadata that a
	// completed installation would have recorded.
	installProven bool
	// revoked seeds a revocation through the real revocation writer.
	revoked bool
	// resumeToInstalling leaves the row owned by a NEWER generation, which is what
	// a parent-side resume produces.
	resumeToInstalling bool
}

// filteredProcessEnv returns the current environment without the helper variables,
// so a parent value can never leak into a child unasked.
func filteredProcessEnv() []string {
	drop := []string{envProcessMode + "=", envProcessDBPath + "=", envProcessJournal + "=",
		envProcessSecret + "=", envProcessStaleGeneration + "="}
	out := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		skip := false
		for _, prefix := range drop {
			if strings.HasPrefix(entry, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, entry)
		}
	}
	return out
}

// assertJournal asserts the child's own effect journal.
func (e *processProofEnv) assertJournal(installs, enables int, what string) {
	e.t.Helper()
	if got := effectCount(e.journal, "install"); got != installs {
		e.t.Fatalf("%s: installs in the shared journal = %d, want %d", what, got, installs)
	}
	if got := effectCount(e.journal, "enable"); got != enables {
		e.t.Fatalf("%s: enables in the shared journal = %d, want %d", what, got, enables)
	}
}

// TestProcessCrashTakeoverCompletesWithoutReinstall is the core positive control.
//
// The row is persisted mid-enablement with installation already proven and no
// backend tunnel, which is exactly what a process that died inside enablement
// leaves. A genuinely separate process must take the claim over, decide from the
// persisted journal that enablement never landed, enable exactly once and finish -
// while the install count stays at one.
func TestProcessCrashTakeoverCompletesWithoutReinstall(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	db := env.open()
	env.seedOrderAndCredential(db, true)
	env.seedIntent(db, processProofShape{
		installing:       true,
		phase:            models.SetupPhaseEnabled,
		phaseDone:        models.SetupPhaseInstalled,
		serverRegistered: true,
		installProven:    true,
	})
	// The interrupted attempt's install is part of the persisted history.
	appendEffect(env.journal, "install")

	before, _, _ := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)

	result := env.runChild(procCrashTakeoverComplete, env.secret)
	if result.exitCode != 0 {
		t.Fatalf("child exit = %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, result.stdout, result.stderr)
	}

	after, found, err := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)
	if err != nil || !found {
		t.Fatalf("re-read intent: found=%v err=%v", found, err)
	}
	if after.State != models.SetupStateReady {
		t.Fatalf("state after takeover = %q, want %q (step %q, err %q)",
			after.State, models.SetupStateReady, after.Step, after.LastError)
	}
	// The child must have re-owned the row: a new generation, not the parent's.
	if after.InstallGeneration <= before.InstallGeneration {
		t.Fatalf("generation = %d, want greater than the parent's %d",
			after.InstallGeneration, before.InstallGeneration)
	}
	// Exactly one install in total: the child proved the step instead of repeating it.
	env.assertJournal(1, 1, "after a completed takeover")
	if after.NexusServerID <= 0 {
		t.Fatalf("no registered server recorded by the child: %+v", after)
	}
	// The child reported the same outcome it persisted.
	if !strings.Contains(result.stdout, "state=ready") {
		t.Fatalf("child did not report ready: %s", result.stdout)
	}
}

// TestProcessCrashUnknownOutcomePausesInsteadOfReplaying is the unknown-effect
// control: a persisted in-flight installation with no proof it completed must stop
// the fresh process, not provoke a second install.
func TestProcessCrashUnknownOutcomePausesInsteadOfReplaying(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	db := env.open()
	env.seedOrderAndCredential(db, true)
	env.seedIntent(db, processProofShape{
		installing:       true,
		phase:            models.SetupPhaseInstalled,
		phaseDone:        models.SetupPhaseRegistered,
		serverRegistered: true,
	})
	appendEffect(env.journal, "install")

	before, _, _ := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)

	result := env.runChild(procCrashUnknownPauses, env.secret)
	env.requireExit(result, 0, "unknown outcome")

	after, _, _ := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)
	if after.State != models.SetupStateInstallPaused {
		t.Fatalf("state = %q, want %q (err %q)", after.State, models.SetupStateInstallPaused, after.LastError)
	}
	if !strings.Contains(after.LastError, "interrupted") {
		t.Fatalf("pause reason = %q, want it to name the unverified step", after.LastError)
	}
	// No second install and no enablement at all.
	env.assertJournal(1, 0, "after an unknown-outcome pause")
	if after.InstallGeneration <= before.InstallGeneration {
		t.Fatalf("generation did not advance on takeover: %d -> %d",
			before.InstallGeneration, after.InstallGeneration)
	}
}

// TestProcessCompletedJobIsNotReplayed is the completed-step positive control: a
// finished order must produce no effect at all in a fresh process.
func TestProcessCompletedJobIsNotReplayed(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	db := env.open()
	env.seedOrderAndCredential(db, true)
	env.seedIntent(db, processProofShape{
		state:     models.SetupStateReady,
		phaseDone: models.SetupPhaseEnabled,
	})
	appendEffect(env.journal, "install")
	appendEffect(env.journal, "enable")

	result := env.runChild(procAlreadyCompleteNoop, env.secret)
	env.requireExit(result, 0, "completed job")

	after, _, _ := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)
	if after.State != models.SetupStateReady {
		t.Fatalf("state = %q, want the completed state unchanged", after.State)
	}
	env.assertJournal(1, 1, "after a completed job")
}

// TestProcessRevokedJobProducesNoEffect proves a revocation reaches a fresh process.
func TestProcessRevokedJobProducesNoEffect(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	db := env.open()
	env.seedOrderAndCredential(db, true)
	env.seedIntent(db, processProofShape{
		installing: true,
		phase:      models.SetupPhaseInstalled,
		phaseDone:  models.SetupPhaseRegistered,
		revoked:    true,
	})

	result := env.runChild(procRevokedRefuses, env.secret)
	env.requireExit(result, 0, "revoked job")

	after, _, _ := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)
	if after.State != models.SetupStateCanceled {
		t.Fatalf("state = %q, want the revocation to stand", after.State)
	}
	env.assertJournal(0, 0, "after a revoked job")
}

// TestProcessStaleGenerationProducesNoEffect proves a superseded attempt cannot be
// picked up by a fresh process either.
func TestProcessStaleGenerationProducesNoEffect(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	db := env.open()
	env.seedOrderAndCredential(db, true)
	seeded := env.seedIntent(db, processProofShape{
		installing:         true,
		phase:              models.SetupPhaseInstalled,
		phaseDone:          models.SetupPhaseRegistered,
		serverRegistered:   true,
		resumeToInstalling: true,
	})
	if seeded.State != models.SetupStateInstalling || seeded.InstallGeneration < 2 {
		t.Fatalf("precondition: state=%q generation=%d, want installing under a newer generation",
			seeded.State, seeded.InstallGeneration)
	}

	// The child holds ONLY the superseded generation. Every write it attempts with
	// it must be refused in that other process, with no effect at all.
	result := env.runChildWith(procStaleGenerationRefuses, env.secret,
		envProcessStaleGeneration+"="+strconv.FormatInt(seeded.InstallGeneration-1, 10))
	env.requireExit(result, 0, "stale generation")

	after, _, err := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)
	if err != nil {
		t.Fatalf("re-read intent: %v", err)
	}
	if after.InstallGeneration != seeded.InstallGeneration {
		t.Fatalf("a superseded attempt advanced the generation: %d -> %d",
			seeded.InstallGeneration, after.InstallGeneration)
	}
	env.assertJournal(0, 0, "after a superseded attempt")

	// The live generation, by contrast, is accepted - so the refusal above is about
	// ownership and not about a permanently frozen row.
	live := env.runChildWith(procStaleGenerationRefuses, env.secret,
		envProcessStaleGeneration+"="+strconv.FormatInt(seeded.InstallGeneration, 10))
	if live.exitCode == 0 {
		t.Fatal("the control expected the live generation to be accepted, but the child refused it")
	}
}

// TestProcessCredentialSurvivesIntentSchemaUpgrade is the credential-continuity
// proof, at the real upgrade boundary.
//
// The parent writes the PRE-install-column intent table plus an order row whose SSH
// key is encrypted with the application secret, then reopens the file through
// database.Open so the production migration chain upgrades it in place. A genuinely
// separate process then loads the credential through the application path and
// reports only a digest.
func TestProcessCredentialSurvivesIntentSchemaUpgrade(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	seedLegacyCredentialDatabase(t, env.dbPath, env.secret)

	// Reopen through the application: this is the upgrade under test.
	db := env.open()
	upgraded, found, err := db.GetGigahostSetupIntent(context.Background(), processProofOrderID)
	if err != nil || !found {
		t.Fatalf("legacy intent lost across the upgrade: found=%v err=%v", found, err)
	}
	if upgraded.InstallGeneration != 0 || upgraded.InstallPhase != "" {
		t.Fatalf("upgraded install columns are not at their zero value: %+v", upgraded)
	}
	// The credential is still readable through the application boundary, before any
	// child runs.
	cred, foundCred, err := db.GetGigahostOrderCredential(context.Background(), processProofOrderID)
	if err != nil || !foundCred {
		t.Fatalf("credential lost across the upgrade: found=%v err=%v", foundCred, err)
	}
	if cred.PrivateKey != processProofPlaintext {
		t.Fatal("credential plaintext changed across the upgrade")
	}
	if cred.ProviderKeyID != 424242 {
		t.Fatalf("provider key id = %d, want 424242 preserved", cred.ProviderKeyID)
	}

	want := digestOf(processProofPlaintext)
	result := env.runChild(procCredentialOK, env.secret)
	env.requireExit(result, 0, "credential continuity")
	if !strings.Contains(result.stdout, "credential_sha256="+want) {
		t.Fatalf("child did not report the expected credential digest\nstdout:\n%s\nstderr:\n%s",
			result.stdout, result.stderr)
	}
	env.assertJournal(0, 0, "after loading a credential")
}

// TestProcessWrongSecretRefusesCredential proves the same persisted row does not
// yield a usable credential under a different application secret.
func TestProcessWrongSecretRefusesCredential(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	seedLegacyCredentialDatabase(t, env.dbPath, env.secret)
	env.open() // run the real upgrade before the child opens it

	const otherSecret = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	result := env.runChild(procCredentialWrongSecret, otherSecret)
	env.requireExit(result, 0, "wrong secret")
	env.assertJournal(0, 0, "after a wrong-secret refusal")
}

// TestProcessMissingCredentialRefusesBeforeAnyEffect proves an absent credential is
// a refusal, not a login attempt with no authentication.
func TestProcessMissingCredentialRefusesBeforeAnyEffect(t *testing.T) {
	env := newProcessProofEnv(t, testSecretKey)
	db := env.open()
	env.seedOrderAndCredential(db, false) // no credential
	env.seedIntent(db, processProofShape{})

	result := env.runChild(procCredentialMissing, env.secret)
	env.requireExit(result, 0, "missing credential")
	env.assertJournal(0, 0, "after a missing-credential refusal")
}

// seedLegacyCredentialDatabase writes the pre-install-column state by raw SQL, which
// is the same seam the database package's own legacy-migration tests use.
func seedLegacyCredentialDatabase(t *testing.T, dbPath, secret string) {
	t.Helper()
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw legacy database: %v", err)
	}
	defer func() { _ = raw.Close() }()

	now := time.Now().UTC().Format(time.RFC3339)
	stmts := []struct {
		sql  string
		args []any
	}{
		{`CREATE TABLE IF NOT EXISTS gigahost_orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL,
			server_id INTEGER DEFAULT 0, status TEXT NOT NULL,
			plan_id INTEGER NOT NULL, region_id INTEGER NOT NULL,
			hourly_price_nok REAL NOT NULL DEFAULT 0.0, assigned_ip TEXT DEFAULT '',
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
			ssh_key_enc TEXT DEFAULT '', ssh_public_key TEXT DEFAULT '',
			provider_ssh_key_id INTEGER DEFAULT 0
		)`, nil},
		{`CREATE TABLE IF NOT EXISTS gigahost_setup_intents (
			id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL,
			provider_server_id INTEGER NOT NULL DEFAULT 0, assigned_ip TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT '', port TEXT NOT NULL DEFAULT '',
			tls_domain TEXT NOT NULL DEFAULT '', engine_profile TEXT NOT NULL DEFAULT '',
			credential_mode TEXT NOT NULL DEFAULT '', state TEXT NOT NULL,
			provider_status TEXT NOT NULL DEFAULT '', step TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '', host_fingerprint TEXT NOT NULL DEFAULT '',
			host_mismatch INTEGER NOT NULL DEFAULT 0, read_failures INTEGER NOT NULL DEFAULT 0,
			attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL DEFAULT '',
			last_checked_at TEXT NOT NULL DEFAULT '', approved_by TEXT NOT NULL DEFAULT '',
			revoked_at TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		)`, nil},
	}

	// The credential must be encrypted by the application boundary, not by hand.
	encKey, err := security.EncryptCredential(processProofPlaintext, secret)
	if err != nil {
		t.Fatalf("encrypt fixture credential: %v", err)
	}
	stmts = append(stmts,
		struct {
			sql  string
			args []any
		}{`INSERT INTO gigahost_orders
			(order_id, server_id, status, plan_id, region_id, assigned_ip, created_at, updated_at,
			 ssh_key_enc, ssh_public_key, provider_ssh_key_id)
			VALUES (?, 7001, 'ready', 1, 1, '198.51.100.200', ?, ?,
			        ?, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000', 424242)`,
			[]any{processProofOrderID, now, now, encKey}},
		struct {
			sql  string
			args []any
		}{`INSERT INTO gigahost_setup_intents
			(order_id, provider_server_id, assigned_ip, protocol, port, credential_mode,
			 state, step, host_fingerprint, approved_by, created_at, updated_at)
			VALUES (?, 7001, '198.51.100.200', 'awg', '51820', 'managed',
			        'ready_for_setup', 'ready_for_setup', ?, 'admin-fixture', ?, ?)`,
			[]any{processProofOrderID, installFixtureFingerprint, now, now}},
	)

	for _, stmt := range stmts {
		if _, err := raw.Exec(stmt.sql, stmt.args...); err != nil {
			t.Fatalf("seed legacy database: %v", err)
		}
	}
}

// digestOf reports a SHA-256 digest of a fixture value, which is how a child can
// prove it holds the right credential without printing it.
func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
