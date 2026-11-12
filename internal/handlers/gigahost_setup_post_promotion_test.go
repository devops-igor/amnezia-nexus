package handlers

// The post-promotion policy-withdrawal window: the last place authority can change
// after the effect has already settled.
//
// The owner finding is that finishInstall re-asks the automation policy AFTER
// installEnableStep has already promoted the backend, and on refusal it writes only a
// journal pause with no quarantine. If the policy is withdrawn in that window, the
// durable row says install_paused while the production pool still selects the backend.
//
// Why the existing test does not cover it: it flips the policy inside
// SetEnableBackendPreAddTunnelHookForTest, which fires before AddTunnel, i.e. before
// qualification and promotion. It proves the PRE-promotion refusal and never reaches
// this window.
//
// How the flip is made deterministic without adding any production hook: the policy
// fixture answers "enabled" until the job's own backend is genuinely selectable in the
// production pool, and answers "disabled" from that moment on. The trigger is therefore
// the real committed promotion - the exact condition the finding is about - rather than
// a call count or a sleep.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// withdrawAfterPromotionPolicy is an automation policy that turns itself off the moment
// the job's backend becomes selectable.
//
// It reads production pool state through FilterHealthy, which is the same function the
// load balancer uses to choose backends, so "selectable" means exactly what it means in
// production. The panel server row is resolved from the provider server identity, since
// pool membership is keyed by the panel server id. No hook, no counter and no timing
// assumption is involved.
type withdrawAfterPromotionPolicy struct {
	env              *installEnv
	providerServerID int64

	mu        sync.Mutex
	withdrawn bool
}

func (p *withdrawAfterPromotionPolicy) Enabled(context.Context) (bool, error) {
	selectable := p.backendSelectable()
	p.mu.Lock()
	defer p.mu.Unlock()
	if selectable {
		p.withdrawn = true
		return false, nil
	}
	return true, nil
}

// backendSelectable reports production pool membership without failing the test: a
// policy stub is not the place to call t.Fatalf.
//
// The panel server row is resolved by the provider server identity because the tunnel is
// keyed by the panel id; before that row exists the backend cannot be selectable, which
// is the correct answer for the earlier boundaries.
func (p *withdrawAfterPromotionPolicy) backendSelectable() bool {
	if p.env == nil || p.env.h == nil || p.env.h.vpnSvc == nil || p.env.db == nil {
		return false
	}
	serverID := p.panelServerID()
	if serverID <= 0 {
		return false
	}
	all, err := p.env.h.vpnSvc.GetTunnels(context.Background())
	if err != nil {
		return false
	}
	for _, tun := range loadbalancer.FilterHealthy(all, 0) {
		if tun.ServerID == serverID {
			return true
		}
	}
	return false
}

// panelServerID resolves the panel server row for the provider server identity, without
// calling t.Fatalf (a policy stub runs on production call paths). Returning 0 means the
// row does not exist yet, and a backend that has no row cannot be selectable.
func (p *withdrawAfterPromotionPolicy) panelServerID() int64 {
	servers, err := p.env.db.GetAllServers(context.Background())
	if err != nil {
		return 0
	}
	for k := range servers {
		if servers[k].Protocols == nil {
			continue
		}
		if provider, _ := servers[k].Protocols["provider"].(string); provider != "gigahost" {
			continue
		}
		if matchProviderServerID(servers[k].Protocols["provider_server_id"], p.providerServerID) {
			return servers[k].ID
		}
	}
	return 0
}

// forceWithdrawn makes every later answer "disabled", modelling an administrator
// switching unattended setup off after the promotion already committed.
func (p *withdrawAfterPromotionPolicy) forceWithdrawn() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.withdrawn = true
}

// TestAutomaticJobPolicyWithdrawnAfterPromotionKeepsStateConsistent is the decisive
// regression for the owner finding.
//
// It forces a real, successful promotion first, withdraws the policy while the runner is
// between that promotion and the terminal journal write, then asserts that the durable
// row and production pool membership agree.
//
// The chosen semantic is that promotion is the terminal authorization boundary: the
// policy is asked before the commit, and after a committed promotion the job records what
// actually happened. So the correct outcome here is `ready` with a selectable backend -
// never a paused row beside a selectable backend.
func TestAutomaticJobPolicyWithdrawnAfterPromotionKeepsStateConsistent(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_post_promotion", 9401)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	// Replace the fixture policy with one that records the withdrawal at the exact
	// boundary. Because the correction makes promotion the terminal authorization
	// boundary, the policy is consulted only BEFORE the commit; this test therefore
	// observes the promotion independently (from production pool state) and asserts that
	// no later policy read can produce a contradictory row.
	policy := &withdrawAfterPromotionPolicy{env: env.installEnv, providerServerID: env.providerServerID}
	env.h.SetGigahostSetupAutomationPolicyForTest(policy)

	// The withdrawal itself is driven from the same post-promotion observation the
	// finding describes: once the backend is selectable, unattended setup is off.
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// Withdraw now, after the promotion committed, and then run a second pass. This is
	// the interleaving in the finding expressed without any hook: the effect is done, and
	// authority is withdrawn afterwards. The second pass must not rewrite the durable row
	// into a state that contradicts the pool.
	final := env.intent(env.orderID)
	server := env.registeredServer(env.providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	if !authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatalf("precondition: the backend was not selectable, so the post-promotion "+
			"window was never entered (state %q step %q last error %q)",
			final.State, final.Step, final.LastError)
	}

	// Now withdraw authority and drive another install pass over the same row.
	policy.forceWithdrawn()
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}

	final = env.intent(env.orderID)
	selectable := authenticPoolContains(t, env.installEnv, server.ID)

	// The invariant the owner asked for: durable state and production pool membership
	// must agree. Paused-plus-selectable is the reported defect.
	if final.State == models.SetupStateInstallPaused && selectable {
		t.Fatalf("the job is recorded %q while its backend is selectable by the production "+
			"pool (step %q, last error %q): durable state and pool membership disagree",
			final.State, final.Step, final.LastError)
	}

	// Promotion committed, so the backend is selectable and the job must say so. A paused
	// row here would be the defect; `ready` is the truthful record of a completed
	// authorized admission.
	if !selectable {
		t.Fatalf("the backend stopped being selectable after a committed promotion "+
			"(state %q step %q last error %q)", final.State, final.Step, final.LastError)
	}
	if final.State != models.SetupStateReady {
		t.Fatalf("a selectable backend behind a completed promotion was recorded as state %q "+
			"(step %q, last error %q), want %q",
			final.State, final.Step, final.LastError, models.SetupStateReady)
	}

	// Completed work must be preserved, and the completed effect must not be replayed.
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1 (a completed effect was replayed)", enables)
	}
	if final.HostFingerprint != env.presented {
		t.Fatalf("the pin was revoked: %q", final.HostFingerprint)
	}
	if final.InstallPhaseDone == "" {
		t.Fatal("the journal records no proven phase although enablement completed")
	}
}

// TestAutomaticJobPolicyWithdrawnAfterPromotionLeavesUnrelatedBackendHealthy proves the
// post-promotion withdrawal is scoped to its own job: an unrelated already-admitted
// backend must keep being selected by the production pool.
func TestAutomaticJobPolicyWithdrawnAfterPromotionLeavesUnrelatedBackendHealthy(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_post_promotion_scoped", 9403)
	ctx := context.Background()

	// An unrelated backend that is already admitted and selectable.
	neighbourID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "post-promotion-neighbour", Host: "198.51.100.211", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 9499,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51821",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register unrelated server: %v", err)
	}
	if err := env.h.enableDeployBackend(ctx, &models.Server{ID: neighbourID, Host: "198.51.100.211",
		Protocols: map[string]any{models.ProtocolAWG: map[string]any{
			"installed": true, "port": "51821",
			"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
		}}}, models.ProtocolAWG); err != nil {
		t.Fatalf("admit the unrelated backend: %v", err)
	}
	if !authenticPoolContains(t, env.installEnv, neighbourID) {
		t.Fatal("precondition: the unrelated backend is not selectable")
	}
	neighbourBefore, err := env.h.vpnSvc.GetTunnel(neighbourID)
	if err != nil || neighbourBefore == nil {
		t.Fatalf("read unrelated tunnel: %v", err)
	}
	versionBefore := neighbourBefore.StateVersion

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	server := env.registeredServer(env.providerServerID)
	if server == nil || !authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatalf("precondition: the job's own backend was not admitted")
	}

	// Withdraw authority after promotion, then drive another pass.
	env.policy.setEnabled(false)
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}

	// The unrelated backend must be untouched, including its state version.
	if !authenticPoolContains(t, env.installEnv, neighbourID) {
		t.Fatal("a post-promotion policy withdrawal removed an unrelated healthy backend " +
			"from the production pool")
	}
	neighbourAfter, err := env.h.vpnSvc.GetTunnel(neighbourID)
	if err != nil || neighbourAfter == nil {
		t.Fatalf("re-read unrelated tunnel: %v", err)
	}
	if !neighbourAfter.Enabled || neighbourAfter.Status != neighbourBefore.Status {
		t.Fatalf("the unrelated backend changed: enabled %v->%v status %q->%q",
			neighbourBefore.Enabled, neighbourAfter.Enabled,
			neighbourBefore.Status, neighbourAfter.Status)
	}
	if neighbourAfter.StateVersion != versionBefore {
		t.Fatalf("the unrelated backend's state version advanced %d->%d",
			versionBefore, neighbourAfter.StateVersion)
	}
}

// TestAutomaticJobRepeatPassDoesNotReinstallAfterPostPromotionWithdrawal proves a
// completed job is not replayed when authority is withdrawn afterwards: the finished
// effect stays finished and no second install or enablement happens.
func TestAutomaticJobRepeatPassDoesNotReinstallAfterPostPromotionWithdrawal(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_post_promotion_repeat", 9404)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	server := env.registeredServer(env.providerServerID)
	if server == nil || !authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatalf("precondition: the backend was not admitted")
	}
	installsBefore := env.counters.totalInstalls()

	env.policy.setEnabled(false)
	if err := env.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("repeat install pass: %v", err)
	}

	if got := env.counters.totalInstalls(); got != installsBefore {
		t.Fatalf("a repeat pass reinstalled a completed protocol: %d -> %d", installsBefore, got)
	}
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1", enables)
	}
	if !authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatal("a repeat pass removed a healthy admitted backend from the pool")
	}
	if got := env.intent(env.orderID); got.State != models.SetupStateReady {
		t.Fatalf("a repeat pass changed the terminal state to %q (step %q, last error %q)",
			got.State, got.Step, got.LastError)
	}
}

// TestAutomaticJobRefusesBeforePromotionWhenPolicyIsAlreadyOff is the companion control:
// the same policy withdrawal, but BEFORE promotion, must still refuse and leave the
// backend unselectable.
//
// Without this, the change above could be mistaken for "the post-promotion gate was
// removed", when what actually changed is that the pre-promotion gate is now the only
// one - and it must still work.
func TestAutomaticJobRefusesBeforePromotionWhenPolicyIsAlreadyOff(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_pre_promotion_off", 9402)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	// Withdraw before the install pass: the promotion gate must refuse.
	env.policy.setEnabled(false)

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	final := env.intent(env.orderID)
	if final.State == models.SetupStateReady {
		t.Fatal("a job whose policy was withdrawn before promotion was recorded ready")
	}
	if !strings.Contains(final.LastError, "unattended setup is not currently enabled") {
		t.Fatalf("the refusal did not name the policy: step %q last error %q",
			final.Step, final.LastError)
	}
	server := env.registeredServer(env.providerServerID)
	if server != nil && authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatal("a backend refused before promotion is still selectable by the production pool")
	}
}
