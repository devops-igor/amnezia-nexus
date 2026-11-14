package handlers

// Same-job recovery from a transient first-contact SSH failure.
//
// A managed-key VPS becomes provider-ready with no confirmed identity. The
// panel's read-only first-contact challenge can legitimately fail at that moment:
// the host is still booting, or its network is not up yet. That is a temporary
// condition and not an identity answer, so the same saved approval has to remain
// in the scheduled pass and be able to ask again.
//
// These tests drive the whole supported lifecycle through the real tracker, the
// real compare-and-set store, the real HTTP action endpoints and the real
// installer. Only the external SSH transport outcome changes, from "refused" to
// "this is my key", and only the clock is virtual, so a backoff window is proven
// without sleeping.
//
// What is asserted, in order:
//
//  1. a failed challenge leaves the row retryable, with no confirmable identity
//     and a scheduled next attempt;
//  2. a later scheduled pass over the same approval obtains the candidate, and the
//     shipped status DTO exposes it for the portal to display;
//  3. the stored candidate is not an authorization: until an administrator
//     confirms it, no installer pass issues a single Install call;
//  4. confirming that exact value lets the same job install exactly once;
//  5. an explicit resume of the retrying job re-enters discovery rather than
//     jumping to the install-only precheck;
//  6. repeated failure stays bounded by a growing backoff and never becomes
//     confirmable;
//  7. a canceled job that is still retrying stays canceled and installs nothing.
//
// Not asserted here: a real host, a real provider call or a browser. The SSH
// boundary is the fixture's dialer, and the traffic outcome is the VPN service's
// existing test seam.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// discoveryStepUnreachable is the recorded step of a discovery that could not
// obtain an identity. The test names it literally so a rename of the production
// constant cannot silently satisfy both sides.
const discoveryStepUnreachable = "host_identity_unreachable"

// transientChallengeEnv seeds a fresh managed-key approval whose provider server
// is ready and whose host identity nobody has confirmed: the exact starting point
// of the counterexample.
func transientChallengeEnv(t *testing.T, orderID string, serverID int64, ip string) *installEnv {
	t.Helper()
	env := newInstallEnv(t, models.ProtocolAWG)
	env.seedOrder(orderID, serverID, ip)
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, serverID, ip)
	env.approve(orderID, models.ProtocolAWG, "51820", "")
	return env
}

// refuseFirstChallengeThenAnswer installs a dialer that fails the first N dials
// with a transport-style error and then presents the fixture identity. It returns a
// counter of the dials that actually happened.
func refuseFirstChallengeThenAnswer(env *installEnv, refusals int) *int {
	dials := 0
	env.h.SetSSHDialerForTest(func(context.Context, ssh.Config) (ssh.SSHClient, error) {
		dials++
		if dials <= refusals {
			return nil, errors.New("connect: connection refused during first boot")
		}
		return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
	})
	return &dials
}

// r14Clock is a virtual clock for the retry-schedule assertions. The tracker's own
// tests drive scheduling this way; using it here means a backoff window is proven
// without sleeping.
type r14Clock struct{ now time.Time }

func newR14Clock() *r14Clock       { return &r14Clock{now: time.Now().UTC()} }
func (c *r14Clock) Now() time.Time { return c.now }
func (c *r14Clock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

// runTrackerPass performs one real tracking pass under the virtual clock.
func (e *installEnv) runTrackerPass(clock *r14Clock) {
	e.t.Helper()
	if err := e.tracker(clock.Now).RunOnce(context.Background()); err != nil {
		e.t.Fatalf("tracker pass: %v", err)
	}
}

// runInstallPass performs one real install pass, which does not depend on the
// tracker's clock.
func (e *installEnv) runInstallPass() {
	e.t.Helper()
	if err := e.installer().RunOnce(context.Background()); err != nil {
		e.t.Fatalf("install pass: %v", err)
	}
}

// retryWhenDue advances the virtual clock past this order's stored next-attempt
// time and runs one tracking pass, which is exactly what the scheduled worker does
// once the backoff elapses.
func (e *installEnv) retryWhenDue(clock *r14Clock, orderID string) {
	e.t.Helper()
	next := e.intent(orderID).NextAttemptAt
	if next.After(clock.Now()) {
		clock.Advance(next.Sub(clock.Now()) + time.Microsecond)
	}
	e.runTrackerPass(clock)
}

// TestSetupTransientChallengeKeepsTheApprovalRetryable is the red assertion of the
// counterexample: one temporary refusal must not strand the saved approval.
func TestSetupTransientChallengeKeepsTheApprovalRetryable(t *testing.T) {
	const orderID = "ord_r14_retryable"
	env := transientChallengeEnv(t, orderID, 9101, "198.51.100.101")
	dials := refuseFirstChallengeThenAnswer(env, 1)
	clock := newR14Clock()

	env.runTrackerPass(clock)

	after := env.intent(orderID)
	if after.State != models.SetupStatePending {
		t.Fatalf("state after a temporary refusal = %q, want %q: a transport failure is not an identity decision",
			after.State, models.SetupStatePending)
	}
	if after.Step != discoveryStepUnreachable {
		t.Fatalf("step = %q, want the retryable discovery step %q", after.Step, discoveryStepUnreachable)
	}
	if after.HostCandidateFingerprint != "" {
		t.Fatalf("a failed challenge displayed a candidate: %q", after.HostCandidateFingerprint)
	}
	if after.HostFingerprint != "" {
		t.Fatalf("a failed challenge confirmed an identity: %q", after.HostFingerprint)
	}
	if after.NextAttemptAt.IsZero() {
		t.Fatal("no next attempt was scheduled, so nothing would ever retry")
	}
	if !after.NextAttemptAt.After(after.LastCheckedAt) {
		t.Fatalf("the scheduled retry is not in the future: next=%v last=%v",
			after.NextAttemptAt, after.LastCheckedAt)
	}
	if after.ReadFailures != 1 {
		t.Fatalf("read failures = %d, want 1", after.ReadFailures)
	}
	if *dials != 1 {
		t.Fatalf("challenge dials = %d, want exactly 1", *dials)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("installs during a failed discovery = %d, want 0", n)
	}
}

// TestSetupTransientChallengeThenScheduledPassObtainsTheCandidate is the green
// half: the same approval, a later pass, the host now answering.
func TestSetupTransientChallengeThenScheduledPassObtainsTheCandidate(t *testing.T) {
	const orderID = "ord_r14_scheduled"
	env := transientChallengeEnv(t, orderID, 9102, "198.51.100.102")
	dials := refuseFirstChallengeThenAnswer(env, 1)
	clock := newR14Clock()

	env.runTrackerPass(clock)
	env.requireState(orderID, models.SetupStatePending)

	// The scheduled pass is the supported retry: no operator action, no
	// restart-only path.
	env.retryWhenDue(clock, orderID)
	env.runInstallPass()

	got := env.intent(orderID)
	if got.HostCandidateFingerprint != installFixtureFingerprint {
		t.Fatalf("candidate after the retry = %q, want the identity the host presented (%q)",
			got.HostCandidateFingerprint, installFixtureFingerprint)
	}
	if got.HostFingerprint != "" {
		t.Fatalf("the retry confirmed an identity without an administrator: %q", got.HostFingerprint)
	}
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q so the portal offers the confirmation action",
			got.State, models.SetupStateAwaitingHostConfirm)
	}
	if got.ReadFailures != 0 {
		t.Fatalf("read failures after a successful challenge = %d, want 0", got.ReadFailures)
	}
	if *dials != 2 {
		t.Fatalf("challenge dials = %d, want 2", *dials)
	}
	// Discovery authorized nothing: the approval-time fingerprint was empty and
	// the candidate alone must not install.
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("an unconfirmed candidate installed %d times, want 0", n)
	}
}

// TestSetupTransientChallengeCandidateIsDisplayedByTheShippedDTO proves the value
// the retry obtained is the value the portal renders: the status endpoint, not a
// direct SQL read, is what a browser consumes.
func TestSetupTransientChallengeCandidateIsDisplayedByTheShippedDTO(t *testing.T) {
	const orderID = "ord_r14_displayed"
	env := transientChallengeEnv(t, orderID, 9103, "198.51.100.103")
	refuseFirstChallengeThenAnswer(env, 1)
	clock := newR14Clock()

	env.runTrackerPass(clock)
	env.retryWhenDue(clock, orderID)
	env.runInstallPass()

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodGet,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, body)
	}
	setup, _ := body["setup"].(map[string]any)
	if setup["state"] != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %v, want %q so the portal offers the confirmation action",
			setup["state"], models.SetupStateAwaitingHostConfirm)
	}
	if setup["host_candidate_fingerprint"] != installFixtureFingerprint {
		t.Fatalf("the retry candidate is not exposed to the portal: %v", setup["host_candidate_fingerprint"])
	}
}

// TestSetupTransientChallengeFullLifecycleInstallsOnce is the auditor's oracle end
// to end: fail the first challenge, let the same peer answer, obtain and confirm
// the displayed candidate, and let the same job install exactly once.
func TestSetupTransientChallengeFullLifecycleInstallsOnce(t *testing.T) {
	const orderID = "ord_r14_lifecycle"
	env := transientChallengeEnv(t, orderID, 9104, "198.51.100.104")
	dials := refuseFirstChallengeThenAnswer(env, 1)
	clock := newR14Clock()

	env.runTrackerPass(clock)
	env.retryWhenDue(clock, orderID)
	env.runInstallPass()
	candidate := env.intent(orderID).HostCandidateFingerprint
	if candidate == "" {
		t.Fatal("the retry produced no candidate to confirm")
	}

	// A full pass with no confirmation must install nothing, even now that the
	// identity is displayed.
	env.runTrackerPass(clock)
	env.runInstallPass()
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("an unconfirmed job installed %d times, want 0", n)
	}

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": candidate})
	if code != http.StatusOK {
		t.Fatalf("confirmation = %d, want 200 (body: %v)", code, body)
	}
	if confirmed, _ := body["confirmed"].(bool); !confirmed {
		t.Fatalf("confirmed = %v, want true", body["confirmed"])
	}

	env.runTrackerPass(clock)
	env.runInstallPass()
	final := env.requireState(orderID, models.SetupStateReady)
	if final.HostFingerprint != installFixtureFingerprint {
		t.Fatalf("stored identity = %q, want the confirmed value", final.HostFingerprint)
	}
	if final.HostCandidateFingerprint != "" {
		t.Fatalf("the confirmed candidate was left on the row: %q", final.HostCandidateFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("installs = %d, want exactly 1 for the same job", n)
	}
	// Two challenge dials (one refusal, one answer) plus the install path's own
	// host verification, which an attempt performs again before its first remote
	// command. The install dial is expected here; it is why the count is 3.
	if *dials < 2 {
		t.Fatalf("challenge dials = %d, want at least the refusal and the answer", *dials)
	}
	if server := env.registeredServer(9104); server == nil {
		t.Fatal("no server row was registered for the confirmed address")
	}

	// A further pass over the finished job changes nothing.
	env.runTrackerPass(clock)
	env.runInstallPass()
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("a pass over a finished job installed again: %d", n)
	}
}

// TestSetupTransientChallengeExplicitResumeReentersDiscovery covers the supported
// explicit action. A job that is retrying must be resumed into discovery, not into
// the install-only trust precheck, which would leave it paused on an identity the
// panel could have discovered.
func TestSetupTransientChallengeExplicitResumeReentersDiscovery(t *testing.T) {
	const orderID = "ord_r14_resume"
	env := transientChallengeEnv(t, orderID, 9105, "198.51.100.105")
	refuseFirstChallengeThenAnswer(env, 1)
	clock := newR14Clock()
	env.runTrackerPass(clock)
	env.requireState(orderID, models.SetupStatePending)

	// The resume makes the job immediately due rather than re-entering the install
	// path, so one ordinary pass at the same clock time is enough.
	router := setupActionTestRouter(t, env.h)
	if code, body := doJSON(t, router, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-resume", nil); code != http.StatusOK {
		t.Fatalf("resume of a retrying job = %d, want 200 (body: %v)", code, body)
	}
	env.runTrackerPass(clock)
	env.runInstallPass()

	got := env.intent(orderID)
	if got.HostCandidateFingerprint != installFixtureFingerprint {
		t.Fatalf("candidate after an explicit resume = %q, want the presented identity", got.HostCandidateFingerprint)
	}
	if got.State != models.SetupStateAwaitingHostConfirm {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateAwaitingHostConfirm)
	}
	if got.HostFingerprint != "" {
		t.Fatalf("a resume confirmed an identity without an administrator: %q", got.HostFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("a resume of a trust pause installed %d times, want 0", n)
	}
}

// TestSetupTransientChallengeRepeatedFailureStaysBounded is the negative control
// for a host that stays away: the retry must not become a hot loop and must never
// present an identity to confirm.
func TestSetupTransientChallengeRepeatedFailureStaysBounded(t *testing.T) {
	const orderID = "ord_r14_bounded"
	env := transientChallengeEnv(t, orderID, 9106, "198.51.100.106")
	dials := refuseFirstChallengeThenAnswer(env, 1<<20)
	clock := newR14Clock()

	env.runTrackerPass(clock)
	first := env.intent(orderID)
	if first.ReadFailures != 1 || first.NextAttemptAt.IsZero() {
		t.Fatalf("first failure not recorded with a schedule: failures=%d next=%v",
			first.ReadFailures, first.NextAttemptAt)
	}

	// A pass before the retry is due must not dial at all.
	env.runTrackerPass(clock)
	env.runInstallPass()
	if *dials != 1 {
		t.Fatalf("retried before the schedule was due: dials = %d", *dials)
	}

	// Once the schedule is due the retry happens, and the delay grows rather than
	// staying flat.
	env.retryWhenDue(clock, orderID)
	second := env.intent(orderID)
	if second.ReadFailures != 2 {
		t.Fatalf("read failures = %d, want 2", second.ReadFailures)
	}
	if *dials != 2 {
		t.Fatalf("dials after the due retry = %d, want 2", *dials)
	}
	firstWindow := first.NextAttemptAt.Sub(first.LastCheckedAt)
	secondWindow := second.NextAttemptAt.Sub(second.LastCheckedAt)
	if secondWindow <= firstWindow {
		t.Fatalf("backoff did not grow: first %v, second %v", firstWindow, secondWindow)
	}
	if second.HostCandidateFingerprint != "" || second.HostFingerprint != "" {
		t.Fatalf("a persistently unreachable host produced a confirmable identity: candidate=%q confirmed=%q",
			second.HostCandidateFingerprint, second.HostFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("a persistently unreachable host installed %d times, want 0", n)
	}
}

// TestSetupTransientChallengeRetryLosesToCancellation proves the retrying row is
// still an ordinary revocable job: a revocation committed while the job is waiting
// to retry stands, and no later pass revives or installs it.
func TestSetupTransientChallengeRetryLosesToCancellation(t *testing.T) {
	const orderID = "ord_r14_canceled"
	env := transientChallengeEnv(t, orderID, 9107, "198.51.100.107")
	refuseFirstChallengeThenAnswer(env, 1)
	clock := newR14Clock()

	env.runTrackerPass(clock)
	env.requireState(orderID, models.SetupStatePending)

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK || body["changed"] != true {
		t.Fatalf("revoke of a retrying job = %d %v, want 200 changed", code, body)
	}

	// The retry and an explicit resume must both leave the revocation standing.
	env.retryWhenDue(clock, orderID)
	env.runInstallPass()
	if code, _ := doJSON(t, router, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-resume", nil); code == http.StatusOK {
		t.Fatal("a revoked job accepted a resume")
	}

	got := env.requireState(orderID, models.SetupStateCanceled)
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("a canceled job kept a candidate: %q", got.HostCandidateFingerprint)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("a canceled job installed %d times, want 0", n)
	}
}

// TestSetupTransientChallengeStaleCandidateIsCleared covers the persisted half of
// the stale-identity rule on the retry path: a candidate displayed by an earlier
// pass cannot stay confirmable once the address stops presenting it.
func TestSetupTransientChallengeStaleCandidateIsCleared(t *testing.T) {
	const orderID = "ord_r14_stale"
	env := transientChallengeEnv(t, orderID, 9108, "198.51.100.108")
	const stale = installFixtureFingerprintBound
	env.executeSQL(`UPDATE gigahost_setup_intents SET host_candidate_fingerprint = ? WHERE order_id = ?`,
		stale, orderID)
	refuseFirstChallengeThenAnswer(env, 1<<20)
	clock := newR14Clock()

	env.runTrackerPass(clock)

	got := env.intent(orderID)
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("a stale candidate survived a failed challenge: %q", got.HostCandidateFingerprint)
	}
	// The cleared value is no longer confirmable, so the stale identity cannot be
	// trusted through the shipped endpoint either.
	router := setupActionTestRouter(t, env.h)
	if code, _ := doJSON(t, router, http.MethodPost,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-host-confirmation",
		map[string]any{"fingerprint": stale}); code == http.StatusOK {
		t.Fatal("a stale identity was still confirmable")
	}
}
