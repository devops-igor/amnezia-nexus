package handlers

// Owner finding 5, exact sequence (issue #794 group B).
//
// The retained audit probe and the committed same-row control both move the backend
// through UpdateServerHostHandler alone — a production administrative mutation that
// changes the endpoint WITHOUT being a deploy enrollment, so it never produces the new
// enrollment attempt finding 5 is about.
//
// Finding 5's own sequence is both facts at once: the SAME backend row is RE-ENROLLED
// (deploy enrollment B) and that enrollment has a CHANGED identity, which resets health
// to connecting, establishes a NEW quarantine boundary and advances the state version. An
// AWG canary verdict belonging to the previous enrollment must then be inert for B's
// status, reason, state version, enabled state and enrollment, in runtime AND in SQLite.
//
// The changed identity is produced by combining the two production paths: the operator's
// host correction changes the endpoint, and the deploy re-enrollment is the real producer
// of the new attempt. Neither pool rows nor markers are hand-seeded here.
//
// Every precondition is a FAILING assertion rather than a comment. An earlier version of
// this file described a "different endpoint" in prose while the bare re-enrollment
// actually kept the identity identical, so the case proved finding 4's unchanged-identity
// shape instead of this one.
//
// Subject: real deployment handler, host-update handler, Service, Pool and SQLite. The
// provider, SSH transport and the network verdicts are the standard fixtures.
//
// Consumers used are the ones production actually has: the tunnel snapshot read, the
// durable row/marker reads, and loadbalancer.FilterHealthy — the same eligibility
// consumer the deploy tests use. No getter is added purely for this test.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// backendEligible reports whether the server is currently in the healthy-routable set,
// through the production eligibility consumer rather than a status-string guess.
func backendEligible(t *testing.T, h *Handlers, serverID int64) bool {
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

// requireBackendQuarantined asserts the backend is genuinely held out of routing and
// still durably enrolled, before or after the stale verdict.
func requireBackendQuarantined(t *testing.T, h *Handlers, serverID int64, when string) {
	t.Helper()
	pending, err := h.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("%s: read durable enrollment: %v", when, err)
	}
	if !pending[serverID] {
		t.Fatalf("%s: backend %d is not durably quarantined", when, serverID)
	}
	if backendEligible(t, h, serverID) {
		t.Fatalf("%s: backend %d is routable while unqualified", when, serverID)
	}
}

// sameRowChangedIdentityReenrollmentDuringCanary produces finding 5's sequence inside the
// live qualification window and returns the ACTUAL durable snapshot captured before the
// obsolete verdict is released.
//
// Required preconditions, each fatal: same row id, CHANGED identity, a new enrollment
// attempt, B connecting+enabled, and B genuinely quarantined and unroutable.
func sameRowChangedIdentityReenrollmentDuringCanary(
	t *testing.T, h *Handlers, verdict error,
) (serverID *int64, runtimeBefore, durableBefore *models.BackendTunnel) {
	t.Helper()
	serverID = new(int64)
	runtimeBefore = new(models.BackendTunnel)
	durableBefore = new(models.BackendTunnel)
	ctx := context.Background()

	h.vpnSvc.SetCanaryProbeFunc(func(_ context.Context, observed *models.BackendTunnel) error {
		*serverID = observed.ServerID
		if observed.EnrollmentAttempt == 0 {
			t.Fatalf("fixture: the observation carries no enrollment attempt (id=%d status=%s)",
				observed.ID, observed.Status)
		}

		// (a) Production-supported identity mutation: the operator's host correction,
		//     which rewrites the endpoint on the SAME row without enrolling it.
		updateServerHostThroughHandler(t, h, observed.ServerID, "198.51.100.99")

		// (b) The real deploy-enrollment producer: same row, new attempt, health reset.
		if err := h.vpnSvc.EnableBackendWithConfig(
			context.WithValue(ctx, tunnel.DeployEnrollmentKey, true),
			observed.ServerID,
			tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG},
		); err != nil {
			t.Fatalf("re-enroll the same row as attempt B: %v", err)
		}
		b, err := h.vpnSvc.GetTunnel(observed.ServerID)
		if err != nil || b == nil {
			t.Fatalf("read attempt B: %v", err)
		}

		// Precondition 1: SAME row.
		if b.ID != observed.ID {
			t.Fatalf("fixture: row id changed %d -> %d; finding5 re-enrolls the SAME row",
				observed.ID, b.ID)
		}
		// Precondition 2: CHANGED identity. This is exactly the gap the previous version
		// left as prose; without it the case would be finding4's shape, not finding5's.
		if models.SameTunnelIdentity(observed, b) {
			t.Fatalf("fixture: identity did not change (endpoint %q -> %q); the case would be "+
				"finding4's unchanged-identity shape, not finding5's",
				observed.Endpoint, b.Endpoint)
		}
		// Precondition 3: a genuinely NEW enrollment attempt.
		if b.EnrollmentAttempt == observed.EnrollmentAttempt {
			t.Fatalf("fixture: re-enrollment did not start a new attempt (still %d)", b.EnrollmentAttempt)
		}
		// Precondition 4: B is a real, unqualified, administratively enabled boundary.
		if b.Status != models.TunnelStatusConnecting || !b.Enabled {
			t.Fatalf("fixture: B is not connecting+enabled: status=%q enabled=%v", b.Status, b.Enabled)
		}
		// Precondition 5: quarantine and ineligibility are REAL before the verdict.
		requireBackendQuarantined(t, h, observed.ServerID, "before releasing the obsolete verdict")

		// Capture the ACTUAL persisted snapshot, so the after-comparison enforces durable
		// state instead of re-deriving expectations from runtime.
		row, err := h.db.GetBackendTunnelByServerID(ctx, observed.ServerID)
		if err != nil || row == nil {
			t.Fatalf("read durable B before releasing the verdict: %v", err)
		}
		if row.ID != b.ID {
			t.Fatalf("fixture: durable row id %d != runtime %d", row.ID, b.ID)
		}
		if row.Status != models.TunnelStatusConnecting || !row.Enabled {
			t.Fatalf("fixture: durable B is not connecting+enabled: status=%q enabled=%v",
				row.Status, row.Enabled)
		}
		if row.StateVersion != b.StateVersion {
			t.Fatalf("fixture: durable version %d != runtime %d", row.StateVersion, b.StateVersion)
		}
		pending, err := h.db.GetBackendPendingEnrollments(ctx)
		if err != nil {
			t.Fatalf("read durable enrollment before the verdict: %v", err)
		}
		if !pending[observed.ServerID] {
			t.Fatal("fixture: B is not durably quarantined before the verdict")
		}
		*runtimeBefore = *b
		*durableBefore = *row
		return verdict
	})
	return serverID, runtimeBefore, durableBefore
}

// TestSameRowDeployReenrollmentSurvivesObsoleteAWGCanaryFailure is finding 5's exact
// sequence: an obsolete AWG canary failure must not touch the re-enrolled B, in runtime
// or in SQLite.
func TestSameRowDeployReenrollmentSurvivesObsoleteAWGCanaryFailure(t *testing.T) {
	h, _, provider := setupDeployTestEnv(t)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID: 2120, Status: gigahost.StatusReady, AssignedIP: "198.51.100.80",
		}, nil
	}
	h.vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})
	serverID, runtimeBefore, durableBefore := sameRowChangedIdentityReenrollmentDuringCanary(t, h,
		errors.New("old AWG inner canary timed out"))

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "same-row-reenroll-failure", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if durableBefore == nil || durableBefore.ID == 0 {
		t.Fatalf("fixture: the changed-identity re-enrollment was never established (deploy err=%v)", err)
	}
	if err == nil {
		t.Fatal("an obsolete failed qualification reported a ready deployment")
	}

	ctx := context.Background()
	live, getErr := h.vpnSvc.GetTunnel(*serverID)
	if getErr != nil || live == nil {
		t.Fatalf("read live B: %v", getErr)
	}
	row, getErr := h.db.GetBackendTunnelByServerID(ctx, *serverID)
	if getErr != nil || row == nil {
		t.Fatalf("read durable B: %v", getErr)
	}

	// Runtime: same row, same generation, same enrollment attempt. Compared against the
	// RUNTIME snapshot, because the attempt is deliberately runtime-only and the durable
	// row has no attempt to compare with.
	if runtimeBefore == nil || runtimeBefore.ID == 0 {
		t.Fatal("fixture: no runtime snapshot was captured before the verdict")
	}
	if live.ID != runtimeBefore.ID {
		t.Fatalf("the row changed: got %d, want %d", live.ID, runtimeBefore.ID)
	}
	if live.EnrollmentAttempt != runtimeBefore.EnrollmentAttempt {
		t.Fatalf("the enrolled attempt changed: got %d, want %d",
			live.EnrollmentAttempt, runtimeBefore.EnrollmentAttempt)
	}
	if live.Status != runtimeBefore.Status || live.DisableReason != runtimeBefore.DisableReason ||
		live.StateVersion != runtimeBefore.StateVersion || live.Enabled != runtimeBefore.Enabled {
		t.Fatalf("obsolete AWG failure drifted runtime B: status=%q reason=%q v=%d enabled=%v; want %q/%q/%d/%v",
			live.Status, live.DisableReason, live.StateVersion, live.Enabled,
			runtimeBefore.Status, runtimeBefore.DisableReason, runtimeBefore.StateVersion, runtimeBefore.Enabled)
	}

	// SQLite: the persisted snapshot captured before the verdict, including the version.
	if row.ID != durableBefore.ID {
		t.Fatalf("durable row id changed: got %d, want %d", row.ID, durableBefore.ID)
	}
	if row.Status != durableBefore.Status {
		t.Fatalf("obsolete AWG failure persisted status=%q on B, want %q", row.Status, durableBefore.Status)
	}
	if row.DisableReason != durableBefore.DisableReason {
		t.Fatalf("obsolete AWG failure persisted reason=%q on B, want %q",
			row.DisableReason, durableBefore.DisableReason)
	}
	if row.Enabled != durableBefore.Enabled {
		t.Fatalf("obsolete AWG failure persisted enabled=%v on B, want %v", row.Enabled, durableBefore.Enabled)
	}
	if row.StateVersion != durableBefore.StateVersion {
		t.Fatalf("obsolete AWG failure persisted state_version=%d on B, want %d unchanged",
			row.StateVersion, durableBefore.StateVersion)
	}

	// Enrollment and eligibility unchanged: B is still quarantined, still unroutable.
	requireBackendQuarantined(t, h, *serverID, "after the obsolete verdict")
}
