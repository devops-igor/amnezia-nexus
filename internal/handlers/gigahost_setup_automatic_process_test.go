package handlers

// Parent side of the automatic fresh-process proof.
//
// Each test seeds ONE persisted automatic situation, starts one or two genuinely separate
// OS processes over the same SQLite file, and asserts on three independent things:
//
//  1. the durable row the parent reads back after the children exit;
//  2. the effect journal the children appended to, which is how "did it install again?"
//     is answered across a process boundary;
//  3. a real loopback SSH peer owned by the PARENT, whose authentication and session
//     counters are the evidence for "the child offered no credential". That is a socket
//     counter in another process, not an assertion about the child's code.
//
// The child inherits no closures: it receives a database path, the application secret, an
// effect-journal path, an SSH endpoint and a policy mode, and builds its own handlers from
// those facts. Whatever it achieves, it achieved from durable state.
//
// Boundaries kept explicit: protocol installation and traffic qualification are the
// repository's existing fixture replacements. This is NOT VPN traffic, NOT a real provider
// and NOT a healthy-pool proof. C3b owns those.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// autoProcessSecret is the application secret the children open the database with. The
// wrong-secret control uses a different one, which is what makes a decryption failure real
// rather than simulated.
const autoProcessSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// wrongProcessSecret is a syntactically valid but different key.
const wrongProcessSecret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// peerPortOf is the port of a loopback peer, for the child's SSH endpoint.
func peerPortOf(t *testing.T, peer *challengePeer) int {
	t.Helper()
	return peer.port()
}

// runAutoChild starts one automatic child process with the given mode and extras.
//
// It returns the parsed `key=value` report so a test asserts on the child's own facts
// rather than re-deriving them.
func (e *processProofEnv) runAutoChild(
	mode string, extraEnv ...string,
) (childResult, map[string]string) {
	e.t.Helper()
	result := e.runChildWith(mode, e.secret, extraEnv...)
	return result, parseChildReport(result.stdout)
}

// parseChildReport reads the child's `key=value` lines into one map.
//
// Later keys win, which is what the two-pass modes rely on: the report is printed once
// after the last pass, so there is one set of values anyway. A malformed line is skipped
// rather than failing, because the parent asserts on specific keys.
func parseChildReport(stdout string) map[string]string {
	report := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		for _, field := range strings.Fields(line) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			report[key] = strings.Trim(value, `"`)
		}
	}
	return report
}

// requireChildExit asserts the child's exit code with its own stderr on failure.
func requireChildExit(t *testing.T, result childResult, want int, what string) {
	t.Helper()
	if result.exitCode != want {
		t.Fatalf("%s: child exit = %d, want %d\nstdout:\n%s\nstderr:\n%s",
			what, result.exitCode, want, result.stdout, result.stderr)
	}
}

// automaticProcessEnv builds a disposable environment holding one entry-created automatic
// job whose order carries the purchase stamp and the managed credential but no provider
// address yet - the state a fresh purchase is actually in.
//
// It returns the parent's own environment (for seeding and reading back), the activity
// directory, and the key material's digest computed from the parent's side of the store.
func newAutomaticProcessEnv(t *testing.T, orderID string) (*processProofEnv, string, managedTestKey) {
	t.Helper()
	env := newProcessProofEnv(t, autoProcessSecret)
	key := newManagedTestKey(t)
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, Status: "pending_order",
		PlanID: 7, RegionID: 3,
		PurchaseOrigin:     models.PurchaseOriginPanelPurchase,
		PurchaseRecordedAt: now, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed purchase: %v", err)
	}
	if err := db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText, ProviderKeyID: 4242,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}
	return env, env.journal, key
}

// openProcessProofDB opens the proof database for parent-side seeding and reads.
func openProcessProofDB(env *processProofEnv) (*database.DB, error) {
	return database.Open(env.dbPath, env.secret)
}

// seedAutomaticIntent records the entry's own job row in the parent, so the children start
// from exactly what the production entry would have written.
//
// It uses the production entry itself rather than hand-writing a row: the whole claim is
// that a job the entry created continues in another process.
func seedAutomaticIntent(t *testing.T, db *database.DB, orderID string) *models.GigahostSetupIntent {
	t.Helper()
	h := NewHandlers(Dependencies{
		Config: &config.Config{SecretKey: autoProcessSecret},
		DB:     db,
	})
	// The entry requires the opt-in, exactly as it does in a deployment.
	h.SetGigahostSetupAutomationPolicyForTest(childAutomationPolicy{enabled: true})
	intent, created, err := h.StartAutomaticGigahostSetup(context.Background(), orderID,
		AutomaticGigahostSetupOptions{Protocol: models.ProtocolAWG, Port: "51820"})
	if err != nil || !created {
		t.Fatalf("create the automatic job: created=%v err=%v", created, err)
	}
	return intent
}

// readProcessIntent reads the durable row the parent will assert on.
func readProcessIntent(t *testing.T, env *processProofEnv, orderID string) *models.GigahostSetupIntent {
	t.Helper()
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	defer func() { _ = db.Close() }()
	intent, found, err := db.GetGigahostSetupIntent(context.Background(), orderID)
	if err != nil || !found {
		t.Fatalf("read intent %s: found=%v err=%v", orderID, found, err)
	}
	return intent
}

// TestAutomaticJobContinuesInAFreshProcess is the decisive C3a positive.
//
// The parent creates the job and stops. One child process discovers the provider facts,
// records the association, grants and pins; a second child installs and completes. Neither
// child inherits a handler, a policy or a provider stub. The parent's loopback peer
// witnesses that no credential was offered before the pin became durable, and that the
// completing pass did authenticate.
func TestAutomaticJobContinuesInAFreshProcess(t *testing.T) {
	const orderID = autoProcessOrderID
	env, _, key := newAutomaticProcessEnv(t, orderID)

	// The parent seeds the job the entry would create, then stops touching the state.
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	seedAutomaticIntent(t, db, orderID)
	if err := db.Close(); err != nil {
		t.Fatalf("close seeding database: %v", err)
	}

	// The parent owns the host the children will dial.
	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	presented := sshFingerprintOf(t, hostSigner)
	endpoint := "127.0.0.1:" + strconv.Itoa(peerPortOf(t, peer))

	// Child 1: discovery, association, grant, pin.
	result, report := env.runAutoChild(procAutomaticTrack,
		envProcessSSHEndpoint+"="+endpoint,
		envProcessPolicy+"=on",
		envProcessClock+"="+strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	requireChildExit(t, result, 0, "first fresh process (tracking)")

	if report["state"] != models.SetupStateReadyForSetup {
		t.Fatalf("after the first fresh process: state = %q, want %q (step %q, last error %q)",
			report["state"], models.SetupStateReadyForSetup, report["step"], report["last_error"])
	}
	if report["grant_order"] != orderID || report["grant_server"] != strconv.FormatInt(autoProcessServerID, 10) {
		t.Fatalf("the grant does not name this order and server: %v", report)
	}
	if report["grant_address"] != "127.0.0.1" {
		t.Fatalf("the grant names address %q, want the provider's 127.0.0.1", report["grant_address"])
	}
	if report["fingerprint"] != presented {
		t.Fatalf("pinned identity = %q, want the parent peer's %q", report["fingerprint"], presented)
	}
	if report["mode"] != models.SetupTrustModeFirstContact {
		t.Fatalf("trust provenance = %q, want %q", report["mode"], models.SetupTrustModeFirstContact)
	}
	// The ordering claim, measured at the parent's own socket.
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the first fresh process offered a credential before the pin was durable (%d attempts)", n)
	}
	if got := effectCount(env.journal, "install"); got != 0 {
		t.Fatalf("a discovery pass installed %d times", got)
	}

	// The pinned identity is durable state, not the child's memory: the parent reads it.
	pinned := readProcessIntent(t, env, orderID)
	if pinned.HostFingerprint != presented {
		t.Fatalf("the parent reads pinned identity %q, want %q", pinned.HostFingerprint, presented)
	}
	if pinned.HostTrustGrantedAt.IsZero() {
		t.Fatal("the grant did not survive the first child's exit")
	}
	// The credential the first child loaded is the material this test seeded: same digest,
	// computed independently on both sides.
	wantDigest := credentialDigestOfKey(key.privPEM)
	if report["credential_sha256"] != wantDigest {
		t.Fatalf("the first fresh process decrypted a different credential: got %q, want %q",
			report["credential_sha256"], wantDigest)
	}

	// Child 2: the install, with the credential decrypted from the same file.
	installResult, installReport := env.runAutoChild(procAutomaticInstall,
		envProcessSSHEndpoint+"="+endpoint,
		envProcessPolicy+"=on")
	requireChildExit(t, installResult, 0, "second fresh process (install)")

	if installReport["state"] != models.SetupStateReady {
		t.Fatalf("after the second fresh process: state = %q, want %q (step %q, last error %q)",
			installReport["state"], models.SetupStateReady, installReport["step"], installReport["last_error"])
	}
	if installReport["fingerprint"] != presented {
		t.Fatalf("the install changed the pin to %q", installReport["fingerprint"])
	}
	if got := effectCount(env.journal, "install"); got != 1 {
		t.Fatalf("protocol installs across both processes = %d, want exactly 1", got)
	}
	if got := effectCount(env.journal, "enable"); got != 1 {
		t.Fatalf("backend enablements across both processes = %d, want exactly 1", got)
	}
	if n := peer.auths.Load(); n == 0 {
		t.Fatal("the parent peer never saw an authentication attempt, so its zero counter proves nothing")
	}
	// The second process decrypted the SAME credential from disk, so credential continuity
	// across the restart is measured, not assumed.
	if installReport["credential_sha256"] != wantDigest {
		t.Fatalf("the install process decrypted a different credential: got %q, want %q",
			installReport["credential_sha256"], wantDigest)
	}

	// Immutable facts survived two process boundaries.
	final := readProcessIntent(t, env, orderID)
	if final.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		t.Fatalf("the automation provenance was lost: policy = %q", final.HostTrustPolicy)
	}
	if final.Protocol != models.ProtocolAWG || final.Port != "51820" {
		t.Fatalf("the recorded options changed to %q/%q", final.Protocol, final.Port)
	}
	if final.HostTrustOrderID != orderID || final.HostTrustAddress != "127.0.0.1" {
		t.Fatalf("the binding changed: order=%q address=%q", final.HostTrustOrderID, final.HostTrustAddress)
	}
}

// credentialDigestOfKey is the digest the children report for the credential they
// decrypted. Computing it from the seeded material gives an independent expectation.
func credentialDigestOfKey(privateKey string) string {
	sum := sha256.Sum256([]byte(privateKey))
	return hex.EncodeToString(sum[:])
}

// TestFreshProcessRefusesAutomaticEffectsWhenItMustNotAct covers every refusal that must
// hold across a process boundary.
//
// Each case seeds a job the parent's own production path got to a specific point, then runs
// one fresh child in one of the states that must not produce a remote command. The
// assertions are at the effect: zero authentication at the parent's peer and zero journal
// entries.
func TestFreshProcessRefusesAutomaticEffectsWhenItMustNotAct(t *testing.T) {
	cases := []struct {
		name string
		// prepare mutates the seeded state in the parent before the child runs.
		prepare func(t *testing.T, env *processProofEnv, orderID string)
		// mode is the child mode to run.
		mode string
		// policy is the child's policy mode; empty means no policy installed.
		policy string
		// secret overrides the child's application secret.
		secret string
		// wantStep, when set, is the step the row must record.
		wantStep string
		// wantDial marks a case where the child must REACH the host and be refused at the
		// host key. That is a different and stronger claim than "never dialled", and only a
		// connection counter can tell them apart.
		wantDial bool
	}{
		{
			name: "a credential that cannot be decrypted",
			prepare: func(t *testing.T, env *processProofEnv, orderID string) {
				// Nothing to change: the child is started with a different secret, so the
				// stored credential cannot be decrypted by it.
			},
			mode:   procAutomaticInstall,
			policy: "on",
			secret: wrongProcessSecret,
		},
		{
			name: "no stored credential",
			prepare: func(t *testing.T, env *processProofEnv, orderID string) {
				executeProcessSQL(t, env, `UPDATE gigahost_orders SET ssh_key_enc = '', ssh_public_key = '' WHERE order_id = ?`, orderID)
			},
			mode:   procAutomaticInstall,
			policy: "on",
		},
		{
			name:    "the policy is disabled in the fresh process",
			prepare: func(t *testing.T, env *processProofEnv, orderID string) {},
			mode:    procAutomaticInstall,
			policy:  "off",
		},
		{
			name:    "the policy cannot be read in the fresh process",
			prepare: func(t *testing.T, env *processProofEnv, orderID string) {},
			mode:    procAutomaticInstall,
			policy:  "error",
		},
		{
			name: "the intent was revoked",
			prepare: func(t *testing.T, env *processProofEnv, orderID string) {
				executeProcessSQL(t,
					env, `UPDATE gigahost_setup_intents SET state = ?, step = ? WHERE order_id = ?`,
					models.SetupStateCanceled, "canceled", orderID)
			},
			mode:   procAutomaticInstall,
			policy: "on",
		},
		{
			name: "the host key changed after the pin",
			prepare: func(t *testing.T, env *processProofEnv, orderID string) {
				// Re-pin to a DIFFERENT identity than the peer the child will reach, which
				// is exactly the changed-key case: the durable pin and the live host
				// disagree.
				otherSigner := newHandshakeSigner(t)
				executeProcessSQL(t,
					env, `UPDATE gigahost_setup_intents SET host_fingerprint = ?, host_trust_mode = ? WHERE order_id = ?`,
					sshFingerprintOf(t, otherSigner), models.SetupTrustModeFirstContact, orderID)
			},
			mode:     procAutomaticInstall,
			policy:   "on",
			wantDial: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const orderID = autoProcessOrderID
			env, _, _ := newAutomaticProcessEnv(t, orderID)

			// The parent brings the job to a granted, pinned handoff through its own
			// production path over a first peer, so every case starts from the state a
			// real restart would find.
			firstSigner := newHandshakeSigner(t)
			firstPeer := newChallengePeer(t, firstSigner)
			setupAutomaticHandoffInParent(t, env, orderID, firstPeer)

			// The child will reach a DIFFERENT peer, so any effect it produces is measured
			// at a socket that has never been touched.
			childSigner := newHandshakeSigner(t)
			childPeer := newChallengePeer(t, childSigner)

			// The changed-key case is the one where the child SHOULD reach the pinned
			// identity's host; it is prepared before the child runs and re-points the pin.
			tc.prepare(t, env, orderID)

			endpoint := "127.0.0.1:" + strconv.Itoa(peerPortOf(t, childPeer))
			secret := env.secret
			if tc.secret != "" {
				secret = tc.secret
			}
			result := env.runChildWith(tc.mode, secret,
				envProcessSSHEndpoint+"="+endpoint,
				envProcessPolicy+"="+tc.policy)

			// The child must exit 0: it ran the pass it was asked to run. Whether an effect
			// was allowed is the parent's judgment, not the child's.
			requireChildExit(t, result, 0, tc.name)

			if tc.wantDial && childPeer.conns.Load() == 0 {
				t.Fatal("the fresh process never reached the host, so its refusal was not a host-key refusal")
			}
			if n := childPeer.auths.Load(); n != 0 {
				t.Fatalf("the fresh process offered a credential (%d attempts)", n)
			}
			if n := childPeer.sessions.Load(); n != 0 {
				t.Fatalf("the fresh process opened %d session channels", n)
			}
			if got := effectCount(env.journal, "install"); got != 0 {
				t.Fatalf("the fresh process installed %d times", got)
			}
			if got := effectCount(env.journal, "enable"); got != 0 {
				t.Fatalf("the fresh process enabled the backend %d times", got)
			}

			after := readProcessIntent(t, env, orderID)
			if after.State == models.SetupStateReady {
				t.Fatalf("a refused fresh process still reported the job %q", after.State)
			}
			if after.LastError == "" && after.Step != "canceled" {
				t.Fatalf("the refusal recorded no reason (state %q, step %q)", after.State, after.Step)
			}
			if tc.wantStep != "" && after.Step != tc.wantStep {
				t.Fatalf("step = %q, want %q", after.Step, tc.wantStep)
			}
		})
	}
}

// setupAutomaticHandoffInParent drives the job to a granted, pinned handoff using the
// parent's own production consumers over the supplied peer.
//
// It exists so the refusal cases start from a genuinely restarted state instead of a
// hand-written one: the grant, the pin and the association are all written by production
// code, and only then does a child process take over.
func setupAutomaticHandoffInParent(
	t *testing.T, env *processProofEnv, orderID string, peer *challengePeer,
) {
	t.Helper()
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	defer func() { _ = db.Close() }()

	h := NewHandlers(Dependencies{
		Config: &config.Config{SecretKey: env.secret},
		DB:     db,
	})
	h.SetGigahostSetupAutomationPolicyForTest(childAutomationPolicy{enabled: true})
	h.SetGigahostClient(&mockGigahostClient{
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID, Status: gigahost.StatusReady,
				ServerID: autoProcessServerID, AssignedIP: "127.0.0.1",
			}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{ID: autoProcessServerID, OrderID: orderID, IPv4: "127.0.0.1", Status: "ready"},
			}, nil
		},
	})
	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		cfg.Port = peerPortOf(t, peer)
		cfg.Timeout = 5 * time.Second
		return ssh.Dial(ctx, cfg)
	})

	intent, created, err := h.StartAutomaticGigahostSetup(context.Background(), orderID,
		AutomaticGigahostSetupOptions{Protocol: models.ProtocolAWG, Port: "51820"})
	if err != nil || !created {
		t.Fatalf("create the automatic job: created=%v err=%v", created, err)
	}
	_ = intent

	// One production tracking pass: association, grant, pin.
	tracker := h.NewGigahostSetupTracker()
	if tracker == nil {
		t.Fatal("the parent tracker was not constructed")
	}
	if err := tracker.RunOnce(context.Background()); err != nil {
		t.Fatalf("parent tracking pass: %v", err)
	}
	handoff := readProcessIntent(t, env, orderID)
	if handoff.HostTrustOrderID == "" || handoff.HostFingerprint == "" {
		t.Fatalf("the parent did not reach a granted, pinned handoff (state %q, step %q, last error %q)",
			handoff.State, handoff.Step, handoff.LastError)
	}
}

// executeProcessSQL applies one fixture statement to the proof database.
func executeProcessSQL(t *testing.T, env *processProofEnv, query string, args ...any) {
	t.Helper()
	db, err := openProcessProofDB(env)
	if err != nil {
		t.Fatalf("open proof database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.SQLDB().ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("fixture statement failed: %v", err)
	}
}
