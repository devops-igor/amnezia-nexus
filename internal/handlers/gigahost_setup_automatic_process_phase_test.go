package handlers

// The persisted-phase, terminal and recovery boundaries of the automatic fresh-process
// proof.
//
// These are separated from the continuity and refusal matrix because they ask a different
// question: not "may this process act at all" but "given that it may, does it read the
// journal it inherited instead of replaying it". Each starts from state the parent's own
// production path produced, then hands it to a child.

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestFreshProcessDoesNotReplayProvenPhases covers the persisted-phase boundary.
//
// A job whose install was interrupted leaves evidence in its journal. A fresh process must
// read that evidence: a proven phase is not repeated, and an unproven in-flight phase is a
// pause rather than a retry.
func TestFreshProcessDoesNotReplayProvenPhases(t *testing.T) {
	cases := []struct {
		name         string
		phase        string
		phaseDone    string
		state        string
		wantInstalls int
		wantEnables  int
		wantState    string
		// noServerRow suppresses the server row a proven install implies, so the case can
		// assert the contradiction is refused rather than silently repaired.
		noServerRow bool
	}{
		{
			name:         "an unproven in-flight protocol install pauses",
			phase:        models.SetupPhaseInstalled,
			phaseDone:    models.SetupPhaseRegistered,
			state:        models.SetupStateInstalling,
			wantInstalls: 0,
			wantEnables:  0,
			wantState:    models.SetupStateInstallPaused,
		},
		{
			name:         "a proven protocol install is not repeated",
			phase:        "",
			phaseDone:    models.SetupPhaseInstalled,
			state:        models.SetupStateInstalling,
			wantInstalls: 0,
			wantEnables:  1,
			wantState:    models.SetupStateReady,
		},
		{
			// The journal claims the install completed but no server row claims it. That
			// is a contradiction between durable records, and the right answer is a pause:
			// the child must not register a second server on the strength of a phase name.
			name:         "a proven install with no server row pauses instead of re-registering",
			phase:        "",
			phaseDone:    models.SetupPhaseInstalled,
			state:        models.SetupStateInstalling,
			noServerRow:  true,
			wantInstalls: 0,
			wantEnables:  0,
			wantState:    models.SetupStateInstallPaused,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const orderID = autoProcessOrderID
			env, _, _ := newAutomaticProcessEnv(t, orderID)

			registry := newHandshakeSigner(t)
			peer := newChallengePeer(t, registry)
			setupAutomaticHandoffInParent(t, env, orderID, peer)
			// A journal that claims a completed protocol install implies the server row that
			// installation wrote. Seeding it keeps the durable records consistent instead of
			// handing the code a contradiction it would be right to refuse, which is a
			// different case with its own control below.
			if tc.phaseDone == models.SetupPhaseInstalled && !tc.noServerRow {
				seedProcessRegisteredServer(t, env, orderID, readProcessIntent(t, env, orderID).HostFingerprint)
			}
			executeProcessSQL(t,
				env, `UPDATE gigahost_setup_intents SET state = ?, install_phase = ?, install_phase_done = ?, install_generation = install_generation + 1 WHERE order_id = ?`,
				tc.state, tc.phase, tc.phaseDone, orderID)

			// The child reaches the same peer the handoff used, which is the honest case:
			// the identity it pinned is the one answering.
			endpoint := "127.0.0.1:" + strconv.Itoa(peerPortOf(t, peer))
			result, report := env.runAutoChild(procAutomaticInstall,
				envProcessSSHEndpoint+"="+endpoint,
				envProcessPolicy+"=on")
			requireChildExit(t, result, 0, tc.name)

			if got := effectCount(env.journal, "install"); got != tc.wantInstalls {
				t.Fatalf("protocol installs = %d, want %d", got, tc.wantInstalls)
			}
			if got := effectCount(env.journal, "enable"); got != tc.wantEnables {
				t.Fatalf("backend enablements = %d, want %d (report %v, installs %d)",
					got, tc.wantEnables, report, effectCount(env.journal, "install"))
			}
			if report["state"] != tc.wantState {
				t.Fatalf("state = %q, want %q (step %q, last error %q) full report %v",
					report["state"], tc.wantState, report["step"], report["last_error"], report)
			}
		})
	}
}

// TestFreshProcessLeavesACompletedJobInert is the terminal control.
//
// A job that already finished must produce nothing in a fresh process: no command, no
// authentication, no state change.
func TestFreshProcessLeavesACompletedJobInert(t *testing.T) {
	const orderID = autoProcessOrderID
	env, _, _ := newAutomaticProcessEnv(t, orderID)

	firstSigner := newHandshakeSigner(t)
	firstPeer := newChallengePeer(t, firstSigner)
	setupAutomaticHandoffInParent(t, env, orderID, firstPeer)

	// Complete it in one fresh process first, so the completed state is produced by a
	// child rather than by a fixture statement.
	firstEndpoint := "127.0.0.1:" + strconv.Itoa(peerPortOf(t, firstPeer))
	first, _ := env.runAutoChild(procAutomaticTrackAndInstall,
		envProcessSSHEndpoint+"="+firstEndpoint,
		envProcessPolicy+"=on",
		envProcessClock+"="+strconv.FormatInt(time.Now().Add(2*time.Hour).Unix(), 10))
	requireChildExit(t, first, 0, "completing pass")
	installsAfterCompletion := effectCount(env.journal, "install")
	if installsAfterCompletion != 1 {
		t.Fatalf("precondition: installs after completion = %d, want 1", installsAfterCompletion)
	}

	// A second fresh process over the completed job must do nothing at all.
	secondSigner := newHandshakeSigner(t)
	secondPeer := newChallengePeer(t, secondSigner)
	secondEndpoint := "127.0.0.1:" + strconv.Itoa(peerPortOf(t, secondPeer))
	result, report := env.runAutoChild(procAutomaticTrackAndInstall,
		envProcessSSHEndpoint+"="+secondEndpoint,
		envProcessPolicy+"=on",
		envProcessClock+"="+strconv.FormatInt(time.Now().Add(4*time.Hour).Unix(), 10))
	requireChildExit(t, result, 0, "pass over a completed job")

	if n := secondPeer.auths.Load(); n != 0 {
		t.Fatalf("a completed job authenticated %d times", n)
	}
	if got := effectCount(env.journal, "install"); got != installsAfterCompletion {
		t.Fatalf("a completed job was installed again: installs = %d, want %d", got, installsAfterCompletion)
	}
	if report["state"] != models.SetupStateReady {
		t.Fatalf("state = %q, want %q", report["state"], models.SetupStateReady)
	}
}

// TestFreshProcessProvisioningFailureThenRecovery covers the HOST-CONTACT retry boundary.
//
// This is not the provider-outage proof, and it must not be read as one: the provider keeps
// answering "ready" throughout, and what fails is the SSH dial to a closed port. Both events
// leave the job pending, which is precisely why a state label cannot distinguish them - see
// the provider-recovery tests for the outage case, which counts provider reads rather than
// inferring from the state.
//
// What this test does hold: an unreachable host leaves the job pending with its purchase
// identity intact, and a later fresh process completes it once the host answers. Long
// provisioning is demonstrated with the child's pinned clock, not an hour-long wait.
func TestFreshProcessProvisioningFailureThenRecovery(t *testing.T) {
	const orderID = autoProcessOrderID
	env, _, _ := newAutomaticProcessEnv(t, orderID)

	// The parent creates the job and stops. The provider is NOT registered in the child yet
	// in the failing case: the child is given no endpoint, so its provider resolution cannot
	// produce a host answer.
	firstSigner := newHandshakeSigner(t)
	firstPeer := newChallengePeer(t, firstSigner)
	endpoint := "127.0.0.1:" + strconv.Itoa(peerPortOf(t, firstPeer))

	// Seed the job only, then run a child whose provider is unreachable by giving it an
	// endpoint that refuses connections.
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	seedAutomaticIntent(t, db, orderID)
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}

	// A dead endpoint: the port is closed, so the challenge cannot complete. The provider
	// still answers, which is the deploy-status path; the host is what is unreachable.
	deadEndpoint := "127.0.0.1:1"
	failing, failingReport := env.runAutoChild(procAutomaticTrack,
		envProcessSSHEndpoint+"="+deadEndpoint,
		envProcessPolicy+"=on",
		envProcessClock+"="+strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	requireChildExit(t, failing, 0, "failing pass")

	if failingReport["state"] != models.SetupStatePending {
		t.Fatalf("a failed pass left state %q, want %q so the job retries (step %q, last error %q)",
			failingReport["state"], models.SetupStatePending, failingReport["step"], failingReport["last_error"])
	}
	// The purchase identity is untouched by a failure.
	order, found, orderErr := readProcessOrder(env, orderID)
	if orderErr != nil || !found {
		t.Fatalf("read order: found=%v err=%v", found, orderErr)
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		t.Fatalf("a failed pass changed purchase provenance to %q", order.PurchaseOrigin)
	}

	// Recovery: a fresh process with a reachable host and a later pinned clock completes it.
	recovered, recoveredReport := env.runAutoChild(procAutomaticTrack,
		envProcessSSHEndpoint+"="+endpoint,
		envProcessPolicy+"=on",
		envProcessClock+"="+strconv.FormatInt(time.Now().Add(3*time.Hour).Unix(), 10))
	requireChildExit(t, recovered, 0, "recovery pass")

	if recoveredReport["grant_order"] != orderID {
		t.Fatalf("the recovery pass did not grant this order: %v", recoveredReport)
	}
	if recoveredReport["fingerprint"] == "" {
		t.Fatalf("the recovery pass did not pin an identity (step %q, last error %q)",
			recoveredReport["step"], recoveredReport["last_error"])
	}
	// No purchase was retried: the ledger still has exactly one row for this order.
	rows := countProcessOrderRows(t, env, orderID)
	if rows != 1 {
		t.Fatalf("order ledger rows = %d, want exactly 1 (no purchase retry)", rows)
	}
}

// seedProcessRegisteredServer records the panel server row that a completed protocol
// installation implies, so the journal and the server table agree.
//
// Without it a row claiming `protocol_installed` contradicts the absence of the server it
// installed onto, and the installer is right to pause. That contradiction is covered as its
// own case; here the point is that a genuinely proven phase is not repeated.
//
// The server is bound to the job's own pinned identity, because a server bound to any other
// identity is the changed-host case and would pause for a different, correct reason.
func seedProcessRegisteredServer(t *testing.T, env *processProofEnv, orderID, pinnedFingerprint string) {
	t.Helper()
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	defer func() { _ = db.Close() }()
	protocols := map[string]any{
		"provider":           "gigahost",
		"provider_server_id": autoProcessServerID,
		models.ProtocolAWG: map[string]any{
			"installed":  true,
			"port":       "51820",
			"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
		},
	}
	if _, err := db.CreateServerWithFingerprint(context.Background(), &models.Server{
		Name:      "automatic process proof",
		Host:      "127.0.0.1",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: protocols,
		CreatedAt: time.Now().UTC(),
	}, pinnedFingerprint); err != nil {
		t.Fatalf("seed registered server: %v", err)
	}
}

// readProcessOrder reads the ledger row the parent asserts on.
func readProcessOrder(env *processProofEnv, orderID string) (*models.GigahostOrder, bool, error) {
	db, err := openProcessProofDB(env)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = db.Close() }()
	return db.GetGigahostOrder(context.Background(), orderID)
}

// countProcessOrderRows counts ledger rows for one order id.
//
// More than one would mean a second purchase attempt was recorded, which is the specific
// failure this check exists to catch.
func countProcessOrderRows(t *testing.T, env *processProofEnv, orderID string) int {
	t.Helper()
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	defer func() { _ = db.Close() }()
	var count int
	if err := db.SQLDB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM gigahost_orders WHERE order_id = ?`, orderID).Scan(&count); err != nil {
		t.Fatalf("count order rows: %v", err)
	}
	return count
}

// TestAutomaticProcessHelperIsInertInAnOrdinaryRun guards the child entry point.
//
// The helper returns immediately unless the parent set the mode variable, so an ordinary
// `go test ./internal/handlers/` cannot accidentally spawn work or touch a database.
func TestAutomaticProcessHelperIsInertInAnOrdinaryRun(t *testing.T) {
	if os.Getenv(envProcessMode) != "" {
		t.Skip("this process IS a child")
	}
	// The helper is what would run; calling it with no mode must return without acting.
	TestSetupInstallProcessHelper(t)
}
