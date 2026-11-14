package handlers

// Queue and shutdown proof for the SSH handshake lifetime.
//
// The subject is the production adapter: this file does NOT supply a
// context-aware fake SSH client. Every attempt here performs a real ssh.Dial, a
// real transport handshake and the real strict host-key callback. The only things
// the fixture controls are the transport target (a loopback address/port) and,
// where the proof is about the CONFIGURED bound, the configured connection budget
// - because neither is expressible through a durable approval, which records an
// address and a fingerprint but not a test port.
//
// Two properties are shown, both through the real installer:
//
//  1. queue availability - a first due approval whose node accepts TCP and then
//     goes silent must terminate on its configured bound and let the next due
//     approval complete in the same pass;
//  2. clean shutdown - with no usable configured bound, so only cancellation can
//     end the exchange, the supervised installer still joins promptly when the
//     application asks it to stop.
//
// These are the consumer consequences the adapter defect had: one nonresponsive
// node used to pin the serial worker indefinitely.

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

// silentPeer accepts TCP connections and never sends an SSH identification
// string. Connections are closed when the test ends.
type silentPeer struct {
	listener *net.TCPListener
	accepted chan net.Conn
}

func newSilentPeer(t *testing.T, ip string) *silentPeer {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	peer := &silentPeer{listener: listener, accepted: make(chan net.Conn, 8)}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		for {
			select {
			case conn := <-peer.accepted:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			peer.accepted <- conn
		}
	}()
	return peer
}

func (p *silentPeer) port() int { return p.listener.Addr().(*net.TCPAddr).Port }

// managedTestKey is a real generated managed credential plus its public half.
type managedTestKey struct {
	privPEM string
	pubText string
	public  gossh.PublicKey
}

// newManagedTestKey generates the credential material the proofs need.
func newManagedTestKey(t *testing.T) managedTestKey {
	t.Helper()
	privPEM, pubText, err := ssh.GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("generate managed key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(privPEM, "")
	if err != nil {
		t.Fatalf("parse managed key: %v", err)
	}
	return managedTestKey{privPEM: privPEM, pubText: pubText, public: signer.PublicKey()}
}

// seedReadyInstall records an approval already at the install handoff point with
// the supplied managed credential and a placed order row, which is what the
// installer consumes. Nothing about the SSH boundary is faked here.
//
// The credential is a real generated Ed25519 key rather than a placeholder: these
// proofs perform a genuine transport handshake, so the key has to be usable.
func (e *installEnv) seedReadyInstall(orderID string, providerServerID int64, ip, fingerprint string, key managedTestKey) {
	e.t.Helper()
	now := time.Now().UTC()
	if err := e.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: "ready",
		AssignedIP: ip, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed order %s: %v", orderID, err)
	}
	if err := e.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID: orderID, PrivateKey: key.privPEM, PublicKey: key.pubText,
	}); err != nil {
		e.t.Fatalf("seed managed credential for %s: %v", orderID, err)
	}
	intent := &models.GigahostSetupIntent{
		OrderID:          orderID,
		ProviderServerID: providerServerID,
		AssignedIP:       ip,
		Protocol:         models.ProtocolAWG,
		Port:             "51820",
		CredentialMode:   models.SetupCredentialManaged,
		HostFingerprint:  fingerprint,
		State:            models.SetupStateReadyForSetup,
		Step:             "ready_for_setup",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := e.db.CreateGigahostSetupIntent(context.Background(), intent); err != nil {
		e.t.Fatalf("seed setup intent %s: %v", orderID, err)
	}
}

// realSSHAt makes the production SSH seam dial the real adapter at the fixture
// transport targets, optionally overriding the configured connection budget.
//
// This is the whole injection: cfg still carries the approval's user, credentials
// and strict host-key callback, and ssh.Dial is the production entry point. That
// sshDialerHook is set at all also makes the protocol manager skip its own probe,
// which is the repository's existing convention for a controlled SSH boundary.
func (e *installEnv) realSSHAt(targets map[string]int, budget time.Duration) {
	e.h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		port, ok := targets[cfg.Host]
		if !ok {
			e.t.Errorf("unexpected SSH target %q: the fixture maps %v", cfg.Host, targets)
			return nil, &net.AddrError{Err: "unmapped fixture target", Addr: cfg.Host}
		}
		cfg.Port = port
		if budget > 0 {
			cfg.Timeout = budget
		}
		return ssh.Dial(ctx, cfg)
	})
}

// realHandshakeServer starts a real SSH server on the given loopback address that
// accepts the supplied managed key. It returns the address it is reachable on and
// the identity it presents, which is what the approval must confirm.
func realHandshakeServer(t *testing.T, ip string, managedKey gossh.PublicKey) (host string, port int, fingerprint string) {
	t.Helper()
	signer := newHandshakeSigner(t)
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if !bytesEqualKeys(key, managedKey) {
				return nil, errors.New("unknown public key")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)
	host, port = startHandshakeServerOn(t, ip, cfg, new(atomic.Int32))
	return host, port, ssh.FingerprintSHA256(signer.PublicKey())
}

// startHandshakeServerOn is startHandshakeServer bound to a specific loopback
// address, so a test can address two different peers by host and keep the real
// adapter's (host, port) routing meaningful.
func startHandshakeServerOn(t *testing.T, ip string, cfg *gossh.ServerConfig, commands *atomic.Int32) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
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
			go func() {
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				serverConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = serverConn.Close() }()
				go gossh.DiscardRequests(reqs)
				for newChan := range chans {
					commands.Add(1)
					_ = newChan.Reject(gossh.Prohibited, "no sessions in this fixture")
				}
			}()
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split fixture address: %v", err)
	}
	port, convErr := strconv.Atoi(portText)
	if convErr != nil {
		t.Fatalf("parse fixture port: %v", convErr)
	}
	return host, port
}

// TestSetupInstallSilentPeerCannotPinTheQueue is the queue-availability proof.
//
// The first due approval points at a peer that accepts TCP and says nothing; the
// second points at a real SSH server. One installer pass must terminate the first
// attempt on its configured bound and still complete the second, which is exactly
// what a serial worker could not do before the handshake was bounded.
func TestSetupInstallSilentPeerCannotPinTheQueue(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	blockedKey := newManagedTestKey(t)

	blocked := newSilentPeer(t, "127.0.0.1")
	// A confirmation is required for the blocked attempt to reach SSH at all; the
	// peer never presents a key, so this value only satisfies the approval gate.
	env.seedReadyInstall("ord_queue_blind", 7001, "127.0.0.1", installFixtureFingerprint, blockedKey)

	goodKey := newManagedTestKey(t)
	host, goodPort, fingerprint := realHandshakeServer(t, "127.0.0.2", goodKey.public)
	env.seedReadyInstall("ord_queue_ok", 7002, host, fingerprint, goodKey)

	env.realSSHAt(map[string]int{"127.0.0.1": blocked.port(), host: goodPort}, 250*time.Millisecond)

	started := time.Now()
	if err := env.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	elapsed := time.Since(started)

	blind := env.intent("ord_queue_blind")
	if blind.State != models.SetupStateInstallPaused {
		t.Fatalf("blocked approval state = %q, want %q (step %q, last error %q)",
			blind.State, models.SetupStateInstallPaused, blind.Step, blind.LastError)
	}
	// The stop came from the SSH gate, not from some later step: that is what shows
	// the handshake itself was bounded rather than the attempt surviving it.
	if !strings.Contains(blind.LastError, "SSH verification failed") {
		t.Fatalf("blocked approval diagnosis = %q, want the SSH verification gate", blind.LastError)
	}
	t.Logf("blocked approval diagnosis: %s", blind.LastError)
	if blind.InstallPhaseDone != "" {
		t.Fatalf("blocked approval recorded a proven install phase %q before SSH succeeded",
			blind.InstallPhaseDone)
	}

	// The later approval in the same pass used the real adapter and completed.
	ok := env.intent("ord_queue_ok")
	if ok.State != models.SetupStateReady {
		t.Fatalf("queued approval state = %q, want %q (step %q, last error %q)",
			ok.State, models.SetupStateReady, ok.Step, ok.LastError)
	}
	if ok.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("queued approval phase done = %q, want %q", ok.InstallPhaseDone, models.SetupPhaseEnabled)
	}

	// Both attempts were reached in one pass without the blocked peer holding the
	// queue beyond its bound.
	if elapsed > 10*time.Second {
		t.Fatalf("the pass took %s; a bounded first peer must not hold the queue", elapsed)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want exactly the one completed approval", n)
	}
}

// TestSetupInstallStopJoinsABlockedHandshake is the shutdown proof.
//
// No usable configured bound is supplied, so only cancellation can end the
// exchange. The supervised installer must still stop promptly, which is the
// property the panel's own shutdown depends on.
func TestSetupInstallStopJoinsABlockedHandshake(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	blocked := newSilentPeer(t, "127.0.0.1")
	// A budget beyond any test duration: the handshake is bounded only by
	// cancellation here.
	env.realSSHAt(map[string]int{"127.0.0.1": blocked.port()}, time.Hour)

	env.seedReadyInstall("ord_stop_blind", 7101, "127.0.0.1", installFixtureFingerprint, newManagedTestKey(t))

	installer := env.h.NewGigahostSetupInstaller()
	if installer == nil {
		t.Fatal("installer was not constructed")
	}
	startErr := make(chan error, 1)
	go func() { startErr <- installer.Start(context.Background()) }()

	// Wait until the attempt is genuinely inside the blocked handshake.
	select {
	case <-blocked.accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the installer never reached the silent peer")
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stopStarted := time.Now()
	if err := installer.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v (after %s)", err, time.Since(stopStarted))
	}
	if elapsed := time.Since(stopStarted); elapsed > 3*time.Second {
		t.Fatalf("Stop took %s; a blocked handshake must not delay shutdown", elapsed)
	}
	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("Start returned %v after Stop", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after Stop")
	}

	// The interrupted attempt never became a completed install.
	stopped := env.intent("ord_stop_blind")
	if stopped.State == models.SetupStateReady {
		t.Fatalf("a canceled attempt admitted the approval: %+v", stopped)
	}
	if stopped.InstallPhaseDone == models.SetupPhaseEnabled {
		t.Fatal("a canceled attempt recorded a completed enablement phase")
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("protocol installs = %d, want 0: the attempt never got past SSH", n)
	}
}
