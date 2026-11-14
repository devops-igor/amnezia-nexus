package handlers

// Sequential enrollment retry ownership (issue #794, group B).
//
// A backend has three quarantine owners: the durable row marker, the pool's
// generation gate and the prober's server-keyed caller mark. A deploy enrollment
// must end with all three released by the attempt that actually qualified, and
// only by that attempt.
//
// The case below is the ordinary operator sequence, not a concurrency schedule:
// a deployment whose inner canary fails, the same order retried after the network
// recovers, and then ordinary background health sweeps. It asserts the ownership
// consumers production actually has — the deployment's reported Ready, the runtime
// snapshot, the persisted row and the healthy-routable set — rather than an
// internal marker the test installs itself.
//
// No marker, row or attempt is seeded here. The failed attempt's runtime
// quarantine is produced by the real failure path, and the successful retry's
// attempt is issued by the real deploy re-enrollment.

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// retryDeployRequest is the ordinary admin payload: one order, retried as-is.
func retryDeployRequest(orderID string) GigahostDeployRequest {
	return GigahostDeployRequest{
		OrderID:     orderID,
		SSHPassword: "ValidSSHPass123!",
		ServerName:  "retry-owner",
		Protocol:    "awg",
		Port:        "51820",
		WaitReady:   true,
	}
}

// healthySweep runs one ordinary background health probe (no deploy context, no
// qualification intent) and returns the runtime and durable status it produced.
func healthySweep(t *testing.T, h *Handlers, serverID int64) (runtime, durable string) {
	t.Helper()
	ctx := context.Background()
	cur, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || cur == nil {
		t.Fatalf("read tunnel for a healthy sweep: %v", err)
	}
	if _, err := h.vpnSvc.ProbeTunnel(ctx, cur); err != nil {
		t.Fatalf("ordinary healthy sweep failed: %v", err)
	}
	live, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || live == nil {
		t.Fatalf("read runtime after the sweep: %v", err)
	}
	row, err := h.db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || row == nil {
		t.Fatalf("read durable row after the sweep: %v", err)
	}
	return live.Status, row.Status
}

// routable reports whether the backend is in the healthy-routable set through the
// same consumer the routing path uses.
func routable(t *testing.T, h *Handlers, serverID int64) bool {
	t.Helper()
	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil {
		t.Fatalf("list backends: %v", err)
	}
	for _, b := range loadbalancer.FilterHealthy(backends, 0) {
		if b.ServerID == serverID {
			return true
		}
	}
	return false
}

// durableQuarantined reads the persisted enrollment marker, which is the
// authoritative gate across a restart. The pool's generation gate and the
// prober's caller mark are not readable from this package without inventing a
// production getter for a test, so this test proves their release by its only
// user-visible consequence: a successful ordinary sweep commits active and the
// backend stays in the healthy-routable set.
func durableQuarantined(t *testing.T, h *Handlers, serverID int64) bool {
	t.Helper()
	pending, err := h.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment: %v", err)
	}
	return pending[serverID]
}

// TestDeployRetryAfterFailedEnrollmentKeepsQualifiedBackend is the sequential
// retry regression: a failed deployment must not leave its runtime quarantine on
// the backend that a later successful retry qualified.
//
// The failure this pins: the failed attempt's withdraw path stamps the server-keyed
// caller mark with its own attempt id. The retry commits a NEW attempt on the same
// row, releases the durable and pool owners, reports Ready — and then its own
// release is refused, because nothing ever re-bound the caller mark to the attempt
// that now owns the row. The next ordinary healthy probe reads the retained mark
// and persists connecting, on every sweep, indefinitely.
func TestDeployRetryAfterFailedEnrollmentKeepsQualifiedBackend(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()
	req := retryDeployRequest("ord_test_1001")

	// --- attempt A: a real deployment whose inner canary fails ---
	h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		return errors.New("controlled first-attempt inner timeout")
	})
	first, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("fixture: the first deployment must fail its canary")
	}
	if first == nil || first.ServerID <= 0 {
		t.Fatalf("fixture: the failed deployment reported no server: %v", err)
	}
	if first.Status != DeployStatusFailed {
		t.Fatalf("fixture: failed deployment reported %q", first.Status)
	}
	serverID := first.ServerID
	a, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || a == nil {
		t.Fatalf("read attempt A: %v", err)
	}
	// A genuinely failed enrollment: withdrawn, administratively disabled and
	// carrying a real attempt. These are failing preconditions, not comments.
	if a.Enabled {
		t.Fatal("fixture: the failed attempt was left administratively enabled")
	}
	if a.EnrollmentAttempt == 0 {
		t.Fatal("fixture: the failed attempt carries no enrollment attempt")
	}
	if !durableQuarantined(t, h, serverID) {
		t.Fatal("fixture: the failed attempt is not durably quarantined")
	}
	if routable(t, h, serverID) {
		t.Fatal("fixture: a failed, unqualified backend is routable")
	}
	attemptA := a.EnrollmentAttempt

	// --- attempt B: the same order retried after the network recovers ---
	h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error { return nil })
	second, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("the retry deployment failed: %v", err)
	}
	if second == nil || second.Status != DeployStatusReady {
		t.Fatalf("the retry did not report ready: %+v", second)
	}
	if second.ServerID != serverID {
		t.Fatalf("the retry moved to a different server: %d -> %d", serverID, second.ServerID)
	}
	b, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || b == nil {
		t.Fatalf("read attempt B: %v", err)
	}
	if b.EnrollmentAttempt == attemptA {
		t.Fatalf("fixture: the retry did not start a new enrollment attempt (still %d)", b.EnrollmentAttempt)
	}
	if !b.Enabled || b.Status != models.TunnelStatusActive {
		t.Fatalf("the successful retry did not qualify: enabled=%v status=%q", b.Enabled, b.Status)
	}
	// Ready must agree with the persisted row and with the two owners this test can
	// read directly.
	row, err := h.db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || row == nil {
		t.Fatalf("read the durable row after the retry: %v", err)
	}
	if row.Status != models.TunnelStatusActive {
		t.Fatalf("the durable row disagrees with Ready: status=%q", row.Status)
	}
	if durableQuarantined(t, h, serverID) {
		t.Fatal("the successful retry kept the durable quarantine")
	}
	if !routable(t, h, serverID) {
		t.Fatal("the successfully qualified retry is not routable")
	}

	// --- ordinary health sweeps: the retained caller mark's only consumer ---
	// Two sweeps, because the defect's first sweep already wrote connecting: a
	// single sample cannot tell a recovered backend from the one that was broken.
	for sweep := 1; sweep <= 2; sweep++ {
		runtimeStatus, durableStatus := healthySweep(t, h, serverID)
		if runtimeStatus != models.TunnelStatusActive || durableStatus != models.TunnelStatusActive {
			t.Fatalf("healthy sweep %d returned the qualified backend to a quarantined state: runtime=%q durable=%q; "+
				"the failed attempt's runtime quarantine was never handed to the successful attempt",
				sweep, runtimeStatus, durableStatus)
		}
		if !routable(t, h, serverID) {
			t.Fatalf("healthy sweep %d dropped the qualified backend from the routable set", sweep)
		}
	}

	// The sweeps committed real health writes rather than leaving the row static.
	after, err := h.db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || after == nil {
		t.Fatalf("read the durable row after the sweeps: %v", err)
	}
	if after.StateVersion <= row.StateVersion {
		t.Fatalf("the sweeps did not commit: state_version %d -> %d", row.StateVersion, after.StateVersion)
	}
	if after.Enabled != row.Enabled || after.DisableReason != row.DisableReason {
		t.Fatalf("the sweeps changed administrative state: enabled=%v/%v reason=%q/%q",
			row.Enabled, after.Enabled, row.DisableReason, after.DisableReason)
	}
}

// TestDeployRetryKeepsFailingEnrollmentQuarantined is the adjacent negative: a
// retry that fails TOO must not consume the protection it inherited. The chain is
// fail A -> fail B -> succeed C, and only C may release anything.
//
// This is what keeps the ownership handoff from degenerating into an unconditional
// release: ownership follows a committed ENROLLMENT, not merely a later request.
func TestDeployRetryKeepsFailingEnrollmentQuarantined(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()
	req := retryDeployRequest("ord_test_1001")

	// A fails, B fails, both for the same controlled reason.
	h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		return errors.New("controlled inner timeout")
	})
	first, err := h.DeployGigahostOrder(ctx, req)
	if err == nil || first == nil || first.ServerID <= 0 {
		t.Fatalf("fixture: the first deployment did not fail with a server: %v", err)
	}
	serverID := first.ServerID
	attemptA, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || attemptA == nil || attemptA.EnrollmentAttempt == 0 {
		t.Fatalf("fixture: attempt A carries no enrollment attempt: %v", err)
	}

	second, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("a retry that failed its canary reported success")
	}
	if second != nil && second.Status != DeployStatusFailed {
		t.Fatalf("failed retry reported %q", second.Status)
	}
	b, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || b == nil {
		t.Fatalf("read attempt B after its failure: %v", err)
	}
	if b.EnrollmentAttempt == attemptA.EnrollmentAttempt {
		t.Fatalf("fixture: the failing retry did not start a new attempt (still %d)", b.EnrollmentAttempt)
	}
	if b.Enabled {
		t.Fatal("the failed retry left the backend administratively enabled")
	}
	if !durableQuarantined(t, h, serverID) {
		t.Fatal("the failed retry consumed the inherited durable quarantine")
	}
	if routable(t, h, serverID) {
		t.Fatal("the failed retry left the backend routable")
	}

	// A third attempt on the same row still succeeds and is the only release point.
	h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error { return nil })
	third, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("the successful third attempt failed: %v", err)
	}
	if third == nil || third.Status != DeployStatusReady {
		t.Fatalf("the third attempt did not report ready: %+v", third)
	}
	c, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || c == nil {
		t.Fatalf("read attempt C: %v", err)
	}
	if c.EnrollmentAttempt == b.EnrollmentAttempt {
		t.Fatalf("fixture: the third attempt reused attempt %d", b.EnrollmentAttempt)
	}
	if durableQuarantined(t, h, serverID) {
		t.Fatal("the successful third attempt kept the durable quarantine")
	}
	for sweep := 1; sweep <= 2; sweep++ {
		runtimeStatus, durableStatus := healthySweep(t, h, serverID)
		if runtimeStatus != models.TunnelStatusActive || durableStatus != models.TunnelStatusActive {
			t.Fatalf("healthy sweep %d after the successful third attempt: runtime=%q durable=%q",
				sweep, runtimeStatus, durableStatus)
		}
	}
	if !routable(t, h, serverID) {
		t.Fatal("the backend qualified by the third attempt is not routable")
	}
}
