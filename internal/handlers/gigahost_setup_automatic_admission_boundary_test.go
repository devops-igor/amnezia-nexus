package handlers

// Automatic admission proved at the qualification CROSSING, on both protocol paths, with an
// unrelated healthy backend present.
//
// The previous admission tests flipped the policy from `SetEnableBackendPreAddTunnelHookForTest`,
// which runs before EnableBackendWithConfig returns - i.e. before qualification starts. That is
// a real sequence ("policy refused, so qualification never ran") but it is not the one the
// requirement is about: authority withdrawn while a qualification that is succeeding is about
// to be committed.
//
// Here the flip happens INSIDE the canary qualification callback, which is the last code to
// run before the promotion commit, and the callback is counted so "qualification really ran"
// is measured rather than assumed.
//
// The pool oracle is the production selection path, not a hand-written rule:
// `tunnel.Pool.GetActiveTunnels` -> `loadbalancer.FilterHealthy`, the same pair the balancers
// use to choose a backend. The durable enrollment marker is asserted alongside it, because it
// is the independent authority the ingress admission path consults.
//
// Injected traffic outcome is labelled: the canary callback is a fixture. This proves
// admission authority, NOT real protocol request/reply.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// admissionFixture bundles one automatic job driven to the install handoff, with a counted
// canary qualification callback the test can flip the policy inside.
type admissionFixture struct {
	*installEnv
	orderID          string
	providerServerID int64
	policy           *stubAutomationPolicy
	// qualifications counts how many times the canary callback was entered.
	qualifications int
}

// newAdmissionFixture drives one entry-created automatic job to the install handoff.
//
// The job is created by the production entry, granted through the production grant path, and
// pinned by a production tracking pass over a real loopback peer - so the install attempt that
// follows is the real consumer, not a hand-constructed intent.
func newAdmissionFixture(t *testing.T, protocol, orderID string, providerServerID int64) *admissionFixture {
	t.Helper()
	env := newInstallEnv(t, protocol)
	const ip = "127.0.0.1"

	env.seedAutomaticOrder(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)

	// The shared fixture policy type matters: grantAutomationTrust reuses an existing
	// *stubAutomationPolicy and REPLACES any other implementation, so a bespoke type here
	// would be orphaned and this test would flip an object nothing consults.
	policy := env.enableAutomaticSetup(true)

	env.startAutomatic(orderID, AutomaticGigahostSetupOptions{Protocol: protocol, Port: "51820"})
	env.grantAutomationTrust(orderID, providerServerID)

	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	return &admissionFixture{
		installEnv:       env,
		orderID:          orderID,
		providerServerID: providerServerID,
		policy:           policy,
	}
}

// flipPolicyInsideQualification installs a counted canary callback that changes the policy
// once it has been entered, then reports success.
//
// This is the boundary the requirement names: qualification is running and succeeding, and
// authority is withdrawn immediately before the caller would promote.
func (f *admissionFixture) flipPolicyInsideQualification(t *testing.T, change func()) {
	t.Helper()
	f.h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		f.qualifications++
		// Change authority AFTER the callback was entered and before it returns success,
		// which is exactly the window between "qualified" and "promoted".
		change()
		return nil
	})
}

// admit runs one installer pass.
func (f *admissionFixture) admit(t *testing.T) {
	t.Helper()
	if err := f.installer().RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
}

// healthyPool returns the production selection result: the active tunnels the balancers would
// choose from, filtered by the same function every balancer uses.
//
// `GetTunnels` is the service's own snapshot of every tunnel; `FilterHealthy` is the exact
// filter least-connections, weighted-RR, round-robin and sticky selection all apply. Together
// they answer the question a client connection asks, without a hand-written rule.
func (f *admissionFixture) healthyPool(t *testing.T) []*models.BackendTunnel {
	t.Helper()
	all, err := f.h.vpnSvc.GetTunnels(context.Background())
	if err != nil {
		t.Fatalf("read service tunnels: %v", err)
	}
	return loadbalancer.FilterHealthy(all, 0)
}

// poolContains reports whether a server id is selectable by the production path.
func (f *admissionFixture) poolContains(t *testing.T, serverID int64) bool {
	t.Helper()
	for _, tun := range f.healthyPool(t) {
		if tun.ServerID == serverID {
			return true
		}
	}
	return false
}

// durableQuarantine reports whether the server still carries the durable enrollment marker.
func (f *admissionFixture) durableQuarantine(t *testing.T, serverID int64) bool {
	t.Helper()
	marks, err := f.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment markers: %v", err)
	}
	return marks[serverID]
}

// TestAutomaticAdmissionRefusesAtQualificationCrossingAWG is Q1.
//
// The policy is withdrawn inside a qualification callback that has already been entered and
// still returns success. The backend must not reach the production healthy pool, must keep its
// durable quarantine, and the job must keep its pin and proven install history.
func TestAutomaticAdmissionRefusesAtQualificationCrossingAWG(t *testing.T) {
	cases := []struct {
		name   string
		change func(*stubAutomationPolicy)
	}{
		{name: "policy disabled during qualification", change: func(p *stubAutomationPolicy) {
			p.setEnabled(false)
		}},
		{name: "policy unreadable during qualification", change: func(p *stubAutomationPolicy) {
			p.setError(errors.New("the unattended setup setting could not be read"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmissionFixture(t, models.ProtocolAWG, "ord_cross_awg", 9951)
			pinned := f.intent(f.orderID).HostFingerprint
			if pinned == "" {
				t.Fatal("precondition: the job was not pinned")
			}

			f.flipPolicyInsideQualification(t, func() { tc.change(f.policy) })
			f.admit(t)

			// Qualification genuinely ran: the callback was entered at least once.
			if f.qualifications == 0 {
				t.Fatal("the canary qualification callback never ran, so this is not the qualification boundary")
			}

			server := f.registeredServer(f.providerServerID)
			if server == nil {
				t.Fatal("the install did not register a server")
			}

			// The production selection path must exclude it.
			if f.poolContains(t, server.ID) {
				tun, _ := f.h.vpnSvc.GetTunnel(server.ID)
				all, _ := f.h.vpnSvc.GetTunnels(context.Background())
				t.Fatalf("the refused backend is selectable by FilterHealthy(GetActiveTunnels())\n on GetTunnel: enabled=%v status=%q reason=%q\n GetTunnels count=%d\n qual=%d intent_state=%q step=%q err=%q",
					tun.Enabled, tun.Status, tun.DisableReason, len(all), f.qualifications,
					f.intent(f.orderID).State, f.intent(f.orderID).Step, f.intent(f.orderID).LastError)
			}
			// The independent durable authority must still exclude it too.
			if !f.durableQuarantine(t, server.ID) {
				t.Fatal("the durable enrollment quarantine was released without admission")
			}
			// And the runtime state must not claim health.
			tun, err := f.h.vpnSvc.GetTunnel(server.ID)
			if err == nil && tun != nil {
				if tun.Enabled && tun.Status == models.TunnelStatusActive {
					t.Fatalf("the refused backend is enabled and active (status=%q)", tun.Status)
				}
			}

			// Nothing is reported as a completed setup.
			got := f.intent(f.orderID)
			if got.State == models.SetupStateReady {
				t.Fatal("a job refused at the qualification crossing was reported ready")
			}
			// Provenance and proven history are retained.
			if got.HostFingerprint != pinned {
				t.Fatalf("the pin was revoked: %q, want %q", got.HostFingerprint, pinned)
			}
			if got.InstallPhaseDone == "" {
				t.Fatal("proven install history was lost")
			}
			if got.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
				t.Fatalf("the automation provenance was rewritten to %q", got.HostTrustPolicy)
			}
			if n := f.counters.totalInstalls(); n != 1 {
				t.Fatalf("protocol installs = %d, want exactly 1 (nothing replayed)", n)
			}
		})
	}
}

// TestAutomaticAdmissionRefusesAtQualificationCrossingProxy is Q2.
//
// The proxy qualification path has its own gate (`refuseAutomaticAdmissionOrQuarantine`), and
// until now no test exercised it. The proxy callback is the equivalent counted seam.
func TestAutomaticAdmissionRefusesAtQualificationCrossingProxy(t *testing.T) {
	const orderID = "ord_cross_proxy"
	const providerServerID = 9952

	f := newAdmissionFixture(t, models.ProtocolVLESS, orderID, providerServerID)
	// The proxy path bootstraps containers over SSH, so it needs the command-capable mock
	// client rather than the read-only loopback peer the AWG challenge uses. This is the same
	// boundary the existing proxy install tests use.
	f.h.SetSSHDialerForTest(func(context.Context, ssh.Config) (ssh.SSHClient, error) {
		return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
	})
	validVLESSClientFixture(t, f.installEnv)
	// The proxy path dials the mock client, which presents installFixtureFingerprint. The
	// tracking pass pinned the loopback peer's identity, so the two disagree; re-point the
	// pin to the identity this path will actually present. That is a fixture alignment, NOT a
	// relaxation: the pin is still durable and still compared before authentication.
	f.executeSQL(`UPDATE gigahost_setup_intents SET host_fingerprint = ? WHERE order_id = ?`,
		installFixtureFingerprint, orderID)
	pinned := f.intent(orderID).HostFingerprint
	if pinned == "" {
		t.Fatal("precondition: the job was not pinned")
	}

	// The proxy path uses its own qualification callback seam.
	entered := 0
	f.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		entered++
		// Withdraw authority after the callback was entered and before it returns success.
		f.policy.setEnabled(false)
		return 5, nil
	})

	f.admit(t)

	if entered == 0 {
		got := f.intent(orderID)
		t.Fatalf("the proxy qualification callback never ran (state=%q step=%q err=%q installs=%d enables=%d)",
			got.State, got.Step, got.LastError, f.counters.totalInstalls(), f.counters.enables)
	}
	server := f.registeredServer(providerServerID)
	if server == nil {
		t.Fatal("the proxy install did not register a server")
	}
	if f.poolContains(t, server.ID) {
		t.Fatal("the refused proxy backend is selectable by FilterHealthy(GetActiveTunnels())")
	}
	if !f.durableQuarantine(t, server.ID) {
		t.Fatal("the refused proxy backend lost its durable quarantine")
	}
	got := f.intent(orderID)
	if got.State == models.SetupStateReady {
		t.Fatal("a proxy job refused at qualification was reported ready")
	}
	if got.HostFingerprint != pinned {
		t.Fatalf("the proxy pin was revoked: %q", got.HostFingerprint)
	}
}

// TestAutomaticAdmissionLeavesAnUnrelatedHealthyBackendAlone is Q3.
//
// The previous checkpoint claimed unrelated backends were untouched while stating that no
// second backend was tested. This seeds one: an already-qualified, enabled, active backend with
// no setup approval, and asserts its durable marker, runtime state and production pool
// membership are unchanged across (a) the refusal of the automatic job and (b) a subsequent
// normal prober sweep.
func TestAutomaticAdmissionLeavesAnUnrelatedHealthyBackendAlone(t *testing.T) {
	const orderID = "ord_cross_unrelated"
	const providerServerID = 9953
	// The unrelated server's id is assigned by the store, so it is read back from the seed
	// rather than assumed.
	var otherServerID int64

	f := newAdmissionFixture(t, models.ProtocolAWG, orderID, providerServerID)

	// An unrelated backend that is already qualified and healthy. It has no setup approval at
	// all, which is what makes it unrelated to the automatic job under test.
	other := seedQualifiedBackend(t, f.installEnv, "198.51.100.201")
	otherServerID = other.ID

	beforeOther := snapshotTunnel(t, f.installEnv, otherServerID)
	beforePool := f.poolContains(t, otherServerID)
	if !beforePool {
		t.Fatal("precondition: the unrelated backend is not selectable before the refusal")
	}
	if f.durableQuarantine(t, otherServerID) {
		t.Fatal("precondition: the unrelated backend is under the durable quarantine")
	}

	// The automatic job now refuses at the qualification crossing.
	f.flipPolicyInsideQualification(t, func() { f.policy.setEnabled(false) })
	f.admit(t)
	if f.qualifications == 0 {
		t.Fatal("the automatic qualification callback never ran")
	}

	// The unrelated backend is byte-for-byte unchanged.
	afterOther := snapshotTunnel(t, f.installEnv, otherServerID)
	if afterOther != beforeOther {
		t.Fatalf("the refusal changed the unrelated backend:\n before=%+v\n after=%+v",
			beforeOther, afterOther)
	}
	if !f.poolContains(t, otherServerID) {
		t.Fatal("the refusal removed the unrelated backend from the healthy pool")
	}
	if f.durableQuarantine(t, otherServerID) {
		t.Fatal("the refusal quarantined the unrelated backend")
	}

	// A subsequent normal prober sweep must not disturb it either.
	if f.h.vpnSvc != nil {
		f.h.vpnSvc.SelfHealSweep(context.Background())
	}
	if after := snapshotTunnel(t, f.installEnv, otherServerID); after != beforeOther {
		t.Fatalf("a prober sweep changed the unrelated backend:\n before=%+v\n after=%+v",
			beforeOther, after)
	}
	if !f.poolContains(t, otherServerID) {
		t.Fatal("a prober sweep removed the unrelated backend from the healthy pool")
	}
}

// TestAutomaticAdmissionAdmitsAtTheSameCrossingUnderEnabledPolicy is Q4.
//
// The positive control for the crossing: the same production consumers, the same counted
// callback, the policy left enabled. The backend must appear in the production selection path
// exactly once.
func TestAutomaticAdmissionAdmitsAtTheSameCrossingUnderEnabledPolicy(t *testing.T) {
	for _, protocol := range []string{models.ProtocolAWG, models.ProtocolVLESS} {
		t.Run(protocol, func(t *testing.T) {
			f := newAdmissionFixture(t, protocol, "ord_cross_positive_"+protocol, 9954)
			if protocol == models.ProtocolVLESS {
				// The proxy path bootstraps over SSH: command-capable mock client, and the
				// client fixture the existing VLESS install test uses.
				f.h.SetSSHDialerForTest(func(context.Context, ssh.Config) (ssh.SSHClient, error) {
					return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
				})
				validVLESSClientFixture(t, f.installEnv)
				f.executeSQL(`UPDATE gigahost_setup_intents SET host_fingerprint = ? WHERE order_id = ?`,
					installFixtureFingerprint, f.orderID)
			}

			counted := 0
			if protocol == models.ProtocolAWG {
				f.h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
					counted++
					return nil
				})
			} else {
				f.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
					counted++
					return 5, nil
				})
			}

			f.admit(t)

			if counted == 0 {
				t.Fatalf("%s: the qualification callback never ran", protocol)
			}
			server := f.registeredServer(f.providerServerID)
			if server == nil {
				t.Fatalf("%s: no server was registered", protocol)
			}
			if !f.poolContains(t, server.ID) {
				t.Fatalf("%s: the admitted backend is not in the production healthy pool", protocol)
			}
			if f.durableQuarantine(t, server.ID) {
				t.Fatalf("%s: an admitted backend still carries the durable quarantine", protocol)
			}
			// Exactly once: the server appears a single time in the selection result.
			count := 0
			for _, tun := range f.healthyPool(t) {
				if tun.ServerID == server.ID {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("%s: the backend appears %d times in the healthy pool, want exactly 1", protocol, count)
			}
			if got := f.intent(f.orderID); got.State != models.SetupStateReady {
				t.Fatalf("%s: the positive job did not complete: state=%q step=%q error=%q",
					protocol, got.State, got.Step, got.LastError)
			}
		})
	}
}

// tunnelSnapshot is the subset of runtime state an unrelated backend must not change.
type tunnelSnapshot struct {
	Enabled       bool
	Status        string
	DisableReason string
	ServerID      int64
}

// snapshotTunnel reads the runtime state of one backend.
func snapshotTunnel(t *testing.T, env *installEnv, serverID int64) tunnelSnapshot {
	t.Helper()
	tun, err := env.h.vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil {
		t.Fatalf("read tunnel %d: err=%v tun=%v", serverID, err, tun)
	}
	return tunnelSnapshot{
		Enabled:       tun.Enabled,
		Status:        tun.Status,
		DisableReason: tun.DisableReason,
		ServerID:      tun.ServerID,
	}
}

// seedQualifiedBackend registers an enabled, active, non-quarantined backend with no setup
// approval - the shape of an unrelated healthy backend in a live deployment.
func seedQualifiedBackend(
	t *testing.T, env *installEnv, host string,
) *models.Server {
	t.Helper()
	ctx := context.Background()

	created := &models.Server{
		Name:      "unrelated healthy backend",
		Host:      host,
		SSHPort:   22,
		SSHUser:   "root",
		CreatedAt: time.Now().UTC(),
		// Enablement needs the protocol recorded as installed, exactly as a real qualified
		// backend has it.
		Protocols: map[string]any{
			models.ProtocolAWG: map[string]any{
				"installed":  true,
				"port":       "51820",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
	}
	// CreateServer returns the new row id, not the struct.
	if id, err := env.db.CreateServer(ctx, created); err != nil {
		t.Fatalf("seed unrelated server: %v", err)
	} else {
		created.ID = id
	}
	server := created

	// Enrol it through the real service so the tunnel row, the pool entry and the durable
	// marker are all produced by production code paths.
	if err := env.h.vpnSvc.EnableBackendWithConfig(ctx, server.ID,
		tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}); err != nil {
		t.Fatalf("enable unrelated backend: %v", err)
	}

	if err := env.h.vpnSvc.PromoteQualifiedTunnel(ctx, server.ID, 10); err != nil {
		t.Fatalf("promote unrelated backend: %v", err)
	}

	tun, err := env.h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		t.Fatalf("read unrelated tunnel: err=%v", err)
	}
	if !tun.Enabled || !strings.EqualFold(tun.Status, models.TunnelStatusActive) {
		t.Fatalf("precondition: unrelated backend is enabled=%v status=%q", tun.Enabled, tun.Status)
	}
	return server
}
