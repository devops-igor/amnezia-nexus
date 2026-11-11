package handlers

// Controlled environment for the durable install lifecycle.
//
// Every test here drives the real database, the real installer state machine and
// the real handlers, and replaces only the three boundaries the repository
// already replaces for the synchronous deploy path: the provider, SSH, and the
// protocol manager. The traffic qualification boundary is the VPN service's own
// existing test seam.
//
// What the fixtures therefore prove is ordering and durability, not that a real
// host was configured. That distinction is stated on each test rather than implied
// by a green result.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// installFixtureFingerprint is the identity the approval and the fixture host
// both present. It is a syntactically valid canonical SHA256 fingerprint.
const installFixtureFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// installFixtureFingerprintBound is a second canonical fingerprint, used for the
// already-bound-server cases so "matches the binding" and "contradicts it" are
// distinct values rather than the same string in two roles. Both are the strict
// base64 encoding of a real 32-byte digest, which is what the stored-identity
// validator requires.
const installFixtureFingerprintBound = "SHA256:ERERERERERERERERERERERERERERERERERERERERERE"

// installCounters records every effect the install pipeline performed, so a test
// can assert "exactly once" rather than only "eventually".
type installCounters struct {
	mu            sync.Mutex
	installs      map[string]int // protocol -> Install calls
	enables       int
	sshDials      int
	failInstall   error // when set, Install returns this
	omitPublicKey bool  // when set, the AWG row records no public key so enablement fails
	failNextProbe bool  // when set, the next outer handshake probe fails
	// duringInstall, when set, runs inside the protocol manager's own Install call.
	// It is how a test places an administrative revocation in the middle of a real
	// install effect instead of simulating that window from outside.
	duringInstall func()
}

func newInstallCounters() *installCounters {
	return &installCounters{installs: map[string]int{}}
}
func (c *installCounters) totalInstalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, n := range c.installs {
		total += n
	}
	return total
}

func (c *installCounters) recordInstall(protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.installs[protocol]++
}

// installEnv is one isolated lifecycle environment.
type installEnv struct {
	t        *testing.T
	h        *Handlers
	db       *database.DB
	counters *installCounters
	provider *mockGigahostClient
}

// newInstallEnv builds the environment with the supplied protocol managers
// registered, so a test can choose AWG or a proxy without changing the setup.
func newInstallEnv(t *testing.T, protocols ...string) *installEnv {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	counters := newInstallCounters()

	vpnCfg := &models.VPNConfig{EnableMultiProtocolBackends: true, ListenPort: 51820}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("init vpn service: %v", err)
	}
	h.vpnSvc = vpnSvc
	vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		counters.mu.Lock()
		fail := counters.failNextProbe
		counters.failNextProbe = false
		counters.mu.Unlock()
		if fail {
			return 0, errors.New("outer handshake probe timed out")
		}
		return 10 * time.Millisecond, nil
	})
	// The proxy path admits a backend only after an authenticated application
	// exchange; that network boundary is the existing seam, not a new one.
	vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		return 5, nil
	})

	reg := manager.NewRegistry()
	for _, proto := range protocols {
		reg.Register(&mockProtocolManager{
			protocol:  proto,
			installFn: counters.installFnFor(proto),
		})
	}
	h.registry = reg

	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		counters.mu.Lock()
		counters.sshDials++
		counters.mu.Unlock()
		return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
	})

	env := &installEnv{t: t, h: h, db: db, counters: counters, provider: &mockGigahostClient{}}
	// Backend enablement is counted from the VPN service's own pre-add hook, which
	// is the same observation point its existing enrollment tests use.
	vpnSvc.SetEnableBackendPreAddTunnelHookForTest(func() {
		counters.mu.Lock()
		counters.enables++
		counters.mu.Unlock()
	})
	h.SetGigahostClient(env.provider)
	return env
}

// failNextEnablement makes backend enablement fail on its real error path by
// making the outer handshake probe fail inside the enablement phase. That is the
// same failure the synchronous deploy path handles, so the fixture exercises
// production error handling rather than a synthetic seam.
func (e *installEnv) failNextEnablement() {
	e.counters.mu.Lock()
	e.counters.failNextProbe = true
	e.counters.mu.Unlock()
}

// allowEnablement clears any pending enablement failure.
func (e *installEnv) allowEnablement() {
	e.counters.mu.Lock()
	e.counters.failNextProbe = false
	e.counters.omitPublicKey = false
	e.counters.mu.Unlock()
}

// installFnFor is the protocol manager's Install behaviour for this fixture.
func (c *installCounters) installFnFor(protocol string) func(context.Context, *models.Server, map[string]any) error {
	return func(_ context.Context, server *models.Server, params map[string]any) error {
		c.mu.Lock()
		fail := c.failInstall
		during := c.duringInstall
		c.mu.Unlock()
		if during != nil {
			during()
		}
		if fail != nil {
			return fail
		}
		c.recordInstall(protocol)
		if server.Protocols == nil {
			server.Protocols = map[string]any{}
		}
		port, _ := params["port"].(string)
		if port == "" {
			port = "51820"
		}
		server.Protocols[protocol] = map[string]any{
			"installed": true,
			"port":      port,
		}
		if protocol == models.ProtocolAWG {
			// Enablement resolves the WG public key and port from the server row,
			// exactly as a real AWG installation records them. Suppressing the key
			// makes enablement fail on its real error path.
			if meta := server.Protocols[protocol].(map[string]any); meta != nil {
				c.mu.Lock()
				omit := c.omitPublicKey
				c.mu.Unlock()
				if !omit {
					meta["public_key"] = "x9aB1234567890abcdef1234567890abcdef1234567="
				}
			}
		}
		return nil
	}
}

// seedOrder records the placed order identity the approval must match.
func (e *installEnv) seedOrder(orderID string, providerServerID int64, ip string) {
	e.t.Helper()
	now := time.Now().UTC()
	if err := e.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, ServerID: providerServerID, Status: gigahost.StatusDeploying,
		AssignedIP: ip, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		e.t.Fatalf("seed order: %v", err)
	}
}

// seedManagedCredential gives the order the encrypted credential the managed mode
// refers to. The material is a fixture string, never a real key.
func (e *installEnv) seedManagedCredential(orderID string) {
	e.t.Helper()
	err := e.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID:    orderID,
		PrivateKey: "[REDACTED PRIVATE KEY]",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	})
	if err != nil {
		e.t.Fatalf("seed managed credential: %v", err)
	}
}

// providerServes makes the fake provider report a ready server with identity.
func (e *installEnv) providerServes(orderID string, providerServerID int64, ip string) {
	e.provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID, Status: gigahost.StatusReady,
			ServerID: providerServerID, AssignedIP: ip,
		}, nil
	}
	e.provider.getServersFn = func(context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, IPv4: ip, Status: "ready"}}, nil
	}
}

// approve records the administrator's approval for a ready order.
func (e *installEnv) approve(orderID, protocol, port, fingerprint string) *models.GigahostSetupIntent {
	e.t.Helper()
	intent, created, err := e.h.ApproveGigahostSetup(context.Background(), orderID, GigahostSetupApproveRequest{
		Protocol:            protocol,
		Port:                port,
		ExpectedFingerprint: fingerprint,
		UseOrderCredential:  true,
	}, "admin-fixture")
	if err != nil || !created {
		e.t.Fatalf("approve: created=%v err=%v", created, err)
	}
	return intent
}

// tracker builds a tracker over the environment's own provider and clock.
//
// The host-identity challenge is the production one, wired exactly as the
// application wires it, so a pass over a fresh approval exercises the real
// challenge path (`h.challengeGigahostSetupHostIdentity`) rather than a stub. The
// install fixture's dialer hook is what that challenge dials.
//
// The current-policy gate is the production one too, for the same reason: a fixture
// that asked a different question would stop proving anything about the shipped path.
// It reads this environment's own AutomationPolicy, so a test turns unattended setup on
// with enableAutomaticSetup and off by flipping the same policy.
//
// The grantor is the production one as well, because issuing scoped authority is exactly
// the behaviour under test. The inert-configuration case builds its tracker with
// grantor nil, which is the deployment that cannot grant at all.
func (e *installEnv) tracker(now func() time.Time) *gigahostsetup.Tracker {
	return e.trackerWithGrantor(now, e.h.GrantAutomaticGigahostSetupBinding)
}

// trackerWithGrantor builds the same tracker with an explicit grant seam, so a test can
// represent a deployment that cannot grant, or observe the grant attempt.
func (e *installEnv) trackerWithGrantor(
	now func() time.Time, grantor gigahostsetup.AutomaticBindingGrantor,
) *gigahostsetup.Tracker {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return gigahostsetup.New(e.db, gigahostsetup.Options{
		Resolve: func(context.Context) (gigahostsetup.ProviderReader, error) {
			return readOnlyGigahostProvider{client: e.h.gigahostClient}, nil
		},
		ChallengeHost:           e.h.challengeGigahostSetupHostIdentity,
		FirstContactEligible:    e.h.firstContactEligible,
		AutomaticEffectAllowed:  e.h.automaticEffectPermitted,
		AutomaticBindingGrantor: grantor,
		Pinner:                  e.db,
		Now:                     now,
		Interval:                time.Minute,
		FailureBack:             time.Second,
		MaxBackoff:              time.Minute,
		Batch:                   10,
		CallTimeout:             5 * time.Second,
	})
}

// installer builds the production installer over the environment's handlers.
func (e *installEnv) installer() *gigahostsetup.Installer {
	installer := e.h.NewGigahostSetupInstaller()
	if installer == nil {
		e.t.Fatal("installer was not constructed")
	}
	return installer
}

// trackerAndInstall runs one tracker pass and one install pass, which is what the
// two supervised workers do in production.
func (e *installEnv) trackerAndInstall() {
	e.t.Helper()
	if err := e.tracker(nil).RunOnce(context.Background()); err != nil {
		e.t.Fatalf("tracker pass: %v", err)
	}
	if err := e.installer().RunOnce(context.Background()); err != nil {
		e.t.Fatalf("install pass: %v", err)
	}
}

// intent reloads the durable row.
func (e *installEnv) intent(orderID string) *models.GigahostSetupIntent {
	e.t.Helper()
	intent, found, err := e.db.GetGigahostSetupIntent(context.Background(), orderID)
	if err != nil || !found {
		e.t.Fatalf("read intent %s: found=%v err=%v", orderID, found, err)
	}
	return intent
}

// registeredServer returns the panel server registered for a provider server id.
func (e *installEnv) registeredServer(providerServerID int64) *models.Server {
	e.t.Helper()
	servers, err := e.db.GetAllServers(context.Background())
	if err != nil {
		e.t.Fatalf("list servers: %v", err)
	}
	for k := range servers {
		if servers[k].Protocols == nil {
			continue
		}
		if servers[k].Protocols["provider"] != "gigahost" {
			continue
		}
		if matchProviderServerID(servers[k].Protocols["provider_server_id"], providerServerID) {
			return &servers[k]
		}
	}
	return nil
}

// requireState asserts the durable state and names the recorded step on failure.
func (e *installEnv) requireState(orderID, want string) *models.GigahostSetupIntent {
	e.t.Helper()
	got := e.intent(orderID)
	if got.State != want {
		e.t.Fatalf("state = %q, want %q (step %q, last error %q)",
			got.State, want, got.Step, got.LastError)
	}
	return got
}

// pauseAtEnablement drives an order to a genuine pause inside the enablement
// phase: registration and installation are proven, then enablement fails on its
// real error path and the attempt records the in-flight enablement phase.
func (e *installEnv) pauseAtEnablement(orderID string, providerServerID int64, ip string) *models.GigahostSetupIntent {
	e.t.Helper()
	e.failNextEnablement()
	defer e.allowEnablement()
	e.seedOrder(orderID, providerServerID, ip)
	e.seedManagedCredential(orderID)
	e.providerServes(orderID, providerServerID, ip)
	e.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	e.trackerAndInstall()

	intent := e.requireState(orderID, models.SetupStateInstallPaused)
	if intent.InstallPhaseDone != models.SetupPhaseInstalled {
		e.t.Fatalf("installation was not proven before the pause: done=%q err=%q",
			intent.InstallPhaseDone, intent.LastError)
	}
	if intent.InstallPhase != models.SetupPhaseEnabled {
		e.t.Fatalf("in-flight phase = %q, want %q", intent.InstallPhase, models.SetupPhaseEnabled)
	}
	return intent
}

// crashDuringInstall leaves the row exactly as a process that died inside the
// protocol-installation phase would leave it: the server is registered and the
// installation is in flight, with no proven outcome.
//
// The state is produced by the real code path that writes it (a failing install
// attempt records the in-flight phase and stops), and then written back to
// `installing` so the takeover branch - the one a real restart takes - is
// exercised. The manipulation is a test fixture standing in for a process that
// vanished; it is stated here rather than hidden in a mock.
func (e *installEnv) crashDuringInstall(orderID string, providerServerID int64, ip string) {
	e.t.Helper()
	e.seedOrder(orderID, providerServerID, ip)
	e.seedManagedCredential(orderID)
	e.providerServes(orderID, providerServerID, ip)
	e.setInstallFailure(errors.New("the host stopped responding mid-install"))
	e.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	e.trackerAndInstall()
	e.setInstallFailure(nil)

	paused := e.requireState(orderID, models.SetupStateInstallPaused)
	if paused.InstallPhaseDone != models.SetupPhaseRegistered {
		e.t.Fatalf("installation was proven before the crash: done=%q", paused.InstallPhaseDone)
	}
	if paused.InstallPhase != models.SetupPhaseInstalled {
		e.t.Fatalf("in-flight phase = %q, want %q", paused.InstallPhase, models.SetupPhaseInstalled)
	}
	// A crashed attempt leaves the claim in place: state installing, same generation.
	if _, err := e.db.SQLDB().ExecContext(context.Background(),
		`UPDATE gigahost_setup_intents SET state = ? WHERE order_id = ?`,
		models.SetupStateInstalling, orderID); err != nil {
		e.t.Fatalf("model the crashed claim: %v", err)
	}
}

// setInstallFailure controls the protocol manager's Install outcome.
func (e *installEnv) setInstallFailure(err error) {
	e.counters.mu.Lock()
	e.counters.failInstall = err
	e.counters.mu.Unlock()
}

// describeCounters renders the effect counters for a failure message.
func (e *installEnv) describeCounters() string {
	e.counters.mu.Lock()
	defer e.counters.mu.Unlock()
	return fmt.Sprintf("installs=%v enables=%d ssh_dials=%d",
		e.counters.installs, e.counters.enables, e.counters.sshDials)
}
