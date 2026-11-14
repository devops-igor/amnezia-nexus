package main

// Application-lifecycle tests for the durable Gigahost setup tracker.
//
// These are the tests that separate "a worker exists" from "the application runs
// it". Each one boots the real panel through run() against a real SQLite file,
// and asserts on state the tracker can only have produced if the supervisor
// actually started it at startup.
//
// Restart is modelled at the strongest boundary these tests can reach without a
// second OS process: a full run()/shutdown cycle over the *same database file*,
// followed by a second run() that must load the saved approval from disk. That is
// a genuine lifecycle restart at the persistence boundary; it is labelled as such
// rather than described as an OS process restart.

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// lifecycleEnv prepares an isolated data directory and returns the DB path.
func lifecycleEnv(t *testing.T) (dataDir, dbPath, secretKey string) {
	t.Helper()
	dataDir = t.TempDir()
	dbPath = filepath.Join(dataDir, "panel_lifecycle.db")
	secretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("DATA_DIR", dataDir)
	t.Setenv("DB_PATH", dbPath)
	t.Setenv("SECRET_KEY", secretKey)
	return dataDir, dbPath, secretKey
}

// freePort returns a currently unused local port so two sequential runs of the
// panel do not collide.
func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return strconv.Itoa(port)
}

// runPanel boots run() in the background and returns a cancel function that
// performs a clean shutdown, plus a channel reporting run()'s outcome.
func runPanel(t *testing.T, port string) (context.CancelFunc, <-chan error) {
	t.Helper()
	t.Setenv("PORT", port)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx) }()
	return cancel, errCh
}

// stopPanel cancels and waits for a clean exit.
func stopPanel(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned %v on graceful shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("panel did not shut down within 15s")
	}
}

// seedSetupWork records a placed order and its pending approval directly in the
// database, before the panel starts. This is the "administrator approved setup,
// then the panel was restarted" situation.
func seedSetupWork(t *testing.T, dbPath, secretKey string) {
	t.Helper()
	db, err := database.Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("open seed database: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID:   "ord_lifecycle",
		ServerID:  31337,
		Status:    gigahost.StatusDeploying,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:    "ord_lifecycle",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if err := db.CreateGigahostSetupIntent(ctx, &models.GigahostSetupIntent{
		OrderID:          "ord_lifecycle",
		ProviderServerID: 31337,
		Protocol:         models.ProtocolAWG,
		Port:             "51820",
		CredentialMode:   models.SetupCredentialManaged,
		State:            models.SetupStatePending,
		Step:             "approved",
		HostFingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		CreatedAt:        now,
		UpdatedAt:        now,
	}); err != nil {
		t.Fatalf("seed intent: %v", err)
	}
}

// makeSavedWorkDue moves the persisted next-attempt into the past, modelling a
// panel that was offline longer than the backoff its last pass scheduled.
//
// Honouring the saved backoff is deliberate behaviour, not a bug: a restart must
// not hammer the provider. This helper only creates the elapsed-time condition a
// real downtime would have produced anyway.
func makeSavedWorkDue(t *testing.T, dbPath, secretKey string) {
	t.Helper()
	db, err := database.Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	intent, found, err := db.GetGigahostSetupIntent(ctx, "ord_lifecycle")
	if err != nil || !found {
		t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	intent.NextAttemptAt = time.Now().UTC().Add(-time.Minute)
	changed, err := db.TransitionGigahostSetupIntent(ctx, intent, []string{models.SetupStatePending})
	if err != nil {
		t.Fatalf("make work due: %v", err)
	}
	if !changed {
		t.Fatalf("could not make saved work due: intent is in state %q", intent.State)
	}
}

// readIntent reloads the approval from disk.
func readIntent(t *testing.T, dbPath, secretKey string) *models.GigahostSetupIntent {
	t.Helper()
	db, err := database.Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	intent, found, err := db.GetGigahostSetupIntent(context.Background(), "ord_lifecycle")
	if err != nil || !found {
		t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	return intent
}

// TestPanelStartupRegistersGigahostSetupTracker proves the tracker is part of the
// real startup path: the panel boots, the tracker's row is visible, and shutdown
// is clean. A tracker that only existed in tests would leave the row untouched
// and, more importantly, this test would have nothing to observe at all.
//
// The observable used is deliberate: with no provider key configured, the real
// tracker's only possible effect is to record that it could not ask, which it
// does by advancing the attempt counter. Seeing that advance proves the panel ran
// the worker, not merely that the type compiles.
func TestPanelStartupRegistersGigahostSetupTracker(t *testing.T) {
	dataDir, dbPath, secretKey := lifecycleEnv(t)
	// No GIGAHOST_API_KEY: the real resolution fails, which is exactly the
	// "tracker is running but cannot reach the provider" state.
	t.Setenv("GIGAHOST_API_KEY", "")

	seedSetupWork(t, dbPath, secretKey)

	before := readIntent(t, dbPath, secretKey)
	if before.Attempts != 0 {
		t.Fatalf("seeded attempts = %d, want 0", before.Attempts)
	}

	cancel, errCh := runPanel(t, freePort(t))

	// The tracker's first pass runs immediately at startup, so a short wait is
	// enough for the attempt counter to move. This waits on the real worker's
	// effect, not on an assumption about scheduling.
	deadline := time.Now().Add(10 * time.Second)
	var after *models.GigahostSetupIntent
	for time.Now().Before(deadline) {
		after = readIntent(t, dbPath, secretKey)
		if after.Attempts > before.Attempts {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if after.Attempts <= before.Attempts {
		t.Fatalf("tracker never ran: attempts stayed at %d (data dir %s)", before.Attempts, dataDir)
	}
	if after.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q: an unreachable provider must not settle the intent",
			after.State, models.SetupStatePending)
	}
	if after.ReadFailures == 0 {
		t.Fatal("read failure was not recorded")
	}

	stopPanel(t, cancel, errCh)
	// Clean shutdown must leave the row readable and still pending.
	final := readIntent(t, dbPath, secretKey)
	if final.State != models.SetupStatePending {
		t.Fatalf("state after clean shutdown = %q, want pending", final.State)
	}
}

// TestPanelRestartResumesSavedSetupWork proves the restart requirement at the
// lifecycle boundary: an approval recorded before the panel last stopped is
// resumed by the next start, without a new job and without a provider write.
func TestPanelRestartResumesSavedSetupWork(t *testing.T) {
	_, dbPath, secretKey := lifecycleEnv(t)
	t.Setenv("GIGAHOST_API_KEY", "")

	seedSetupWork(t, dbPath, secretKey)

	// First lifecycle: the panel starts, sees the saved approval, and stops.
	cancel, errCh := runPanel(t, freePort(t))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && readIntent(t, dbPath, secretKey).Attempts == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	firstAttempts := readIntent(t, dbPath, secretKey).Attempts
	if firstAttempts == 0 {
		t.Fatal("first panel run did not track the saved approval")
	}
	stopPanel(t, cancel, errCh)

	// A real restart normally happens long after the failure backoff the first run
	// persisted. Model that by moving the saved next-attempt into the past: the
	// panel was down longer than the backoff, which is what makes the work due.
	makeSavedWorkDue(t, dbPath, secretKey)

	// Second lifecycle: a restart must pick the same row up again.
	cancel, errCh = runPanel(t, freePort(t))
	defer stopPanel(t, cancel, errCh)

	deadline = time.Now().Add(10 * time.Second)
	var resumed *models.GigahostSetupIntent
	for time.Now().Before(deadline) {
		resumed = readIntent(t, dbPath, secretKey)
		if resumed.Attempts > firstAttempts {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resumed.Attempts <= firstAttempts {
		t.Fatalf("restart did not resume the saved approval: attempts stayed at %d", firstAttempts)
	}
	if resumed.Protocol != models.ProtocolAWG || resumed.Port != "51820" {
		t.Fatalf("approval options changed across restart: %+v", resumed)
	}

	// Still exactly one job: resuming must not have created a second.
	db, err := database.Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	intents, err := db.ListGigahostSetupIntents(context.Background())
	if err != nil {
		t.Fatalf("list intents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("intent count after restart = %d, want 1", len(intents))
	}
}
