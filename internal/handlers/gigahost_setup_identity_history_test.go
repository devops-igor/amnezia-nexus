package handlers

// Fresh-host identity confirmation and uncertain-install preservation.
//
// Two obligations meet in one transition, so they are proved together through the
// real HTTP endpoints, the real SQLite store, the real tracker and the real
// installer:
//
//  1. a newly approved managed-key order must be actionable. The panel performs
//     its own read-only first-contact challenge, shows the exact identity the
//     host presented, and requires an administrator to confirm that exact value
//     before the same durable job continues;
//  2. confirming an identity must never resolve an installation whose remote
//     outcome is unknown. The install journal survives the trust decision and the
//     existing verify-not-replay path owns the row afterwards, so no further
//     Install call is issued.
//
// Only the external boundaries are replaced (provider, protocol manager, and the
// SSH peer); the durable state, the endpoint contracts and the ordering logic are
// the production ones. The real-handshake proof below uses a real loopback SSH
// server and the real client configuration.

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

// TestSetupFreshOrderChallengeThenConfirmedContinuation is the fresh-order
// positive.
//
// A fresh managed-key order is approved with no fingerprint. The tracker must
// pause with the identity the host presented, the shipped status endpoint must
// expose that identity through the same DTO the saved-job view renders, and
// confirming exactly that value must let the same job reach ready with a single
// installation.
func TestSetupFreshOrderChallengeThenConfirmedContinuation(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_f13_fresh"
	env.seedOrder(orderID, 6301, "198.51.100.131")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 6301, "198.51.100.131")
	env.approve(orderID, models.ProtocolAWG, "51820", "")

	// One tracker pass: the approval carries no identity, so the panel challenges
	// the address itself. The install fixture's dialer reports the identity it
	// presents, which is the same answer a real handshake gives.
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	paused := env.requireState(orderID, models.SetupStateAwaitingHostConfirm)
	if paused.HostCandidateFingerprint != installFixtureFingerprint {
		t.Fatalf("candidate = %q, want the identity the host presented (%q)",
			paused.HostCandidateFingerprint, installFixtureFingerprint)
	}
	if paused.HostFingerprint != "" {
		t.Fatalf("discovery authorized an identity nobody confirmed: %q", paused.HostFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("installs during discovery = %d, want 0", n)
	}

	// The saved-job view exposes the challenge through the DTO it renders.
	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodGet,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, body)
	}
	setup, _ := body["setup"].(map[string]any)
	if setup["host_candidate_fingerprint"] != installFixtureFingerprint {
		t.Fatalf("the saved-job DTO exposes candidate %v, want %q",
			setup["host_candidate_fingerprint"], installFixtureFingerprint)
	}

	// Confirming a value the panel did not display is refused by the endpoint
	// itself, not only by the shipped UI.
	code, body = doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprintBound})
	if code != http.StatusConflict {
		t.Fatalf("confirmation of an undisplayed identity = %d, want 409 (body: %v)", code, body)
	}
	env.requireState(orderID, models.SetupStateAwaitingHostConfirm)

	// Confirming the displayed identity continues the same durable job.
	code, body = doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprint})
	if code != http.StatusOK {
		t.Fatalf("confirmation = %d, want 200 (body: %v)", code, body)
	}
	if confirmed, _ := body["confirmed"].(bool); !confirmed {
		t.Fatalf("confirmed = %v, want true", body["confirmed"])
	}

	env.trackerAndInstall()
	final := env.requireState(orderID, models.SetupStateReady)
	if final.HostFingerprint != installFixtureFingerprint {
		t.Fatalf("stored identity = %q, want the confirmed value", final.HostFingerprint)
	}
	if final.HostCandidateFingerprint != "" {
		t.Fatalf("the confirmed candidate was left on the row: %q", final.HostCandidateFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("installs = %d, want exactly 1", n)
	}
	if server := env.registeredServer(6301); server == nil {
		t.Fatal("no server row was registered for the confirmed address")
	}
}

// challengePeer is a real loopback SSH server that records what a client actually
// did: whether it tried to authenticate and whether it opened a session.
//
// conns counts accepted TCP connections, which is the evidence that a client reached this
// peer at all. Without it a "zero authentications" assertion cannot distinguish "refused at
// the host key, as required" from "never dialled", and only the first of those is a
// meaningful refusal.
type challengePeer struct {
	listener *net.TCPListener
	conns    atomic.Int32
	auths    atomic.Int32
	sessions atomic.Int32
}

func newChallengePeer(t *testing.T, hostSigner gossh.Signer) *challengePeer {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	peer := &challengePeer{listener: listener}
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			peer.auths.Add(1)
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			peer.conns.Add(1)
			go func() {
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				serverConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = serverConn.Close() }()
				go gossh.DiscardRequests(reqs)
				for newChan := range chans {
					peer.sessions.Add(1)
					_ = newChan.Reject(gossh.Prohibited, "no sessions in this fixture")
				}
			}()
		}
	}()
	return peer
}

func (p *challengePeer) port() int { return p.listener.Addr().(*net.TCPAddr).Port }

// TestSetupChallengeUsesRealHandshakeReadOnly drives the production challenge
// against a real loopback SSH server and proves what it does and does not do.
//
// The subject is the production challenge function with the production client
// configuration: a real transport handshake and the real strict host-key callback.
// Host key verification precedes authentication, so a first contact must report
// the presented identity, send no credential, open no session and write no
// durable binding or approval.
func TestSetupChallengeUsesRealHandshakeReadOnly(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_f13_real"
	env.seedOrder(orderID, 6401, "127.0.0.1")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 6401, "127.0.0.1")
	// The approval is at the handoff point: a registered server exists for this
	// provider identity, and its host identity was never bound.
	env.approve(orderID, models.ProtocolAWG, "51820", "")

	key := newManagedTestKey(t)
	if err := env.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText,
	}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	if _, err := env.db.CreateServer(ctx, &models.Server{
		Name: "Gigahost-real", Host: "127.0.0.1", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": 6401},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("register server: %v", err)
	}

	hostSigner := newHandshakeSigner(t)
	peer := newChallengePeer(t, hostSigner)
	env.realSSHAt(map[string]int{"127.0.0.1": peer.port()}, 2*time.Second)

	intent := env.intent(orderID)
	fingerprint, err := env.h.challengeGigahostSetupHostIdentity(ctx, *intent)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	presented := gossh.FingerprintSHA256(hostSigner.PublicKey())
	if fingerprint != presented {
		t.Fatalf("challenge reported %q, want the identity the host presented (%q)", fingerprint, presented)
	}

	// Nothing was authorized and nothing was sent: no credential was offered, no
	// session was opened, and the durable row is unchanged.
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("the challenge offered a credential (%d authentication attempts)", n)
	}
	if n := peer.sessions.Load(); n != 0 {
		t.Fatalf("the challenge opened %d sessions", n)
	}
	after := env.intent(orderID)
	if after.HostFingerprint != "" || after.HostCandidateFingerprint != "" {
		t.Fatalf("the challenge wrote trust state: confirmed=%q candidate=%q",
			after.HostFingerprint, after.HostCandidateFingerprint)
	}
	if after.State != models.SetupStatePending {
		t.Fatalf("the challenge moved the job to %q", after.State)
	}
}

// TestSetupUnknownInstallConfirmationKeepsJournal is the uncertain-install
// negative.
//
// The order stopped with a protocol installation whose outcome nobody can prove.
// An administrator then confirms the same correct identity. That is a trust
// decision, and it must not become an installation decision: the complete
// confirmation -> tracker -> installer sequence must issue zero new Install calls
// and must keep the journal so the existing verify path can decide.
func TestSetupUnknownInstallConfirmationKeepsJournal(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_f15_unknown"
	env.crashDuringInstall(orderID, 6501, "198.51.100.151")
	// The crashed attempt left the row owned; put it back in the paused shape an
	// operator actually sees, which is also a state the confirmation accepts.
	env.executeSQL(`UPDATE gigahost_setup_intents SET state = ? WHERE order_id = ?`,
		models.SetupStateInstallPaused, orderID)
	env.executeSQL(`UPDATE gigahost_setup_intents SET host_candidate_fingerprint = ? WHERE order_id = ?`,
		installFixtureFingerprint, orderID)

	paused := env.intent(orderID)
	if paused.InstallPhase != models.SetupPhaseInstalled || paused.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("precondition: journal = (%q, %q), want the interrupted install",
			paused.InstallPhase, paused.InstallPhaseDone)
	}
	installsBefore := env.counters.totalInstalls()

	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprint})
	if code != http.StatusOK {
		t.Fatalf("confirmation = %d, want 200 (body: %v)", code, body)
	}

	confirmed := env.intent(orderID)
	if confirmed.InstallPhase != models.SetupPhaseInstalled || confirmed.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("the confirmation discarded the journal: phase=%q done=%q",
			confirmed.InstallPhase, confirmed.InstallPhaseDone)
	}
	if confirmed.State != models.SetupStateInstalling {
		t.Fatalf("state = %q, want %q so the verify path owns the row",
			confirmed.State, models.SetupStateInstalling)
	}

	// The full sequence: tracking and installation passes must reach the same
	// conclusion they reach on an ordinary restart - verify, never replay.
	env.trackerAndInstall()
	env.trackerAndInstall()

	if n := env.counters.totalInstalls() - installsBefore; n != 0 {
		t.Fatalf("the confirmation sequence issued %d new protocol installs, want 0", n)
	}
	after := env.intent(orderID)
	if after.InstallPhase != models.SetupPhaseInstalled || after.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("the journal was lost after the sequence: phase=%q done=%q",
			after.InstallPhase, after.InstallPhaseDone)
	}
	if after.State == models.SetupStateReady {
		t.Fatal("an unproven installation was admitted after a trust confirmation")
	}
	if after.State != models.SetupStateInstallPaused {
		t.Fatalf("state = %q, want the unproven install to pause for a human", after.State)
	}
	if after.HostFingerprint != installFixtureFingerprint {
		t.Fatalf("the confirmed identity was not stored: %q", after.HostFingerprint)
	}
	_ = ctx
}

// TestSetupUnknownInstallConfirmationWithChangedIdentityIsRefused proves the
// changed-key direction: a confirmation cannot bypass the uncertainty boundary by
// naming a different host.
func TestSetupUnknownInstallConfirmationWithChangedIdentityIsRefused(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)

	const orderID = "ord_f15_changed"
	env.crashDuringInstall(orderID, 6601, "198.51.100.161")
	env.executeSQL(`UPDATE gigahost_setup_intents SET state = ? WHERE order_id = ?`,
		models.SetupStateInstallPaused, orderID)
	env.executeSQL(`UPDATE gigahost_setup_intents SET host_candidate_fingerprint = ? WHERE order_id = ?`,
		installFixtureFingerprint, orderID)
	installsBefore := env.counters.totalInstalls()

	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprintBound})
	if code != http.StatusConflict {
		t.Fatalf("confirmation with a changed identity = %d, want 409 (body: %v)", code, body)
	}

	after := env.intent(orderID)
	if after.State != models.SetupStateInstallPaused {
		t.Fatalf("state = %q, want the pause preserved", after.State)
	}
	if after.HostFingerprint != installFixtureFingerprint {
		t.Fatalf("a refused confirmation rewrote the identity to %q", after.HostFingerprint)
	}
	env.trackerAndInstall()
	if n := env.counters.totalInstalls() - installsBefore; n != 0 {
		t.Fatalf("a refused confirmation still installed %d times", n)
	}
}

// TestSetupConfirmationRefusesAJobWithNoDisplayedIdentity proves an approval that
// never went through a challenge is not confirmable at the HTTP level. Without
// this, a client could name any host and have the panel trust it.
func TestSetupConfirmationRefusesAJobWithNoDisplayedIdentity(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)

	const orderID = "ord_f13_nocandidate"
	env.seedOrder(orderID, 6701, "198.51.100.171")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 6701, "198.51.100.171")
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	env.requireState(orderID, models.SetupStatePending)

	r := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, r, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": installFixtureFingerprint})
	if code != http.StatusConflict {
		t.Fatalf("confirmation with nothing displayed = %d, want 409 (body: %v)", code, body)
	}
	after := env.intent(orderID)
	if after.HostFingerprint != "" {
		t.Fatalf("an undisplayed identity was trusted: %q", after.HostFingerprint)
	}
	if after.State != models.SetupStatePending {
		t.Fatalf("state = %q, want the row untouched", after.State)
	}
}

// executeSQL applies a fixture statement to the intent table. It is used only to
// place a row in a state a real crash or operator action produces; the behaviour
// under test always runs through the production code.
func (e *installEnv) executeSQL(query string, args ...any) {
	e.t.Helper()
	if _, err := e.db.SQLDB().ExecContext(context.Background(), query, args...); err != nil {
		e.t.Fatalf("fixture statement failed: %v", err)
	}
}
