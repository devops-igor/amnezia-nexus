package handlers

// Owner finding 5, exact sequence (issue #794 group B).
//
// The retained audit probe and the committed same-row control both move the backend
// through UpdateServerHostHandler. Finding 5 describes a different, also real
// sequence: the SAME backend row is RE-ENROLLED (deploy enrollment B) with a changed
// identity, which resets health to connecting, establishes a NEW quarantine boundary
// and advances the state version. An AWG canary verdict belonging to the previous
// enrollment must then be inert for B's status, reason, version, enabled state and
// enrollment, in runtime AND in SQLite.
//
// This file closes that distinction instead of letting the host-update control stand
// in for it. Subject: real deployment handler, Service, Pool and SQLite. The provider,
// SSH transport and the network verdicts are the standard fixtures.
//
// Consumers used are the ones production actually has: the tunnel snapshot read, the
// durable marker read, and loadbalancer.FilterHealthy — the same eligibility consumer
// the deploy tests use. No getter is added purely for this test.

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

// reenrollSameRowDuringCanary re-enrolls the observed backend as deploy attempt B on
// the SAME row with a CHANGED identity, verifies B is genuinely quarantined, then
// returns the canary verdict for the previous observation.
func reenrollSameRowDuringCanary(
	t *testing.T, h *Handlers, verdict error,
) (serverID *int64, before *models.BackendTunnel) {
	t.Helper()
	serverID = new(int64)
	before = new(models.BackendTunnel)
	ctx := context.Background()
	h.vpnSvc.SetCanaryProbeFunc(func(_ context.Context, observed *models.BackendTunnel) error {
		*serverID = observed.ServerID
		if observed.EnrollmentAttempt == 0 {
			t.Fatalf("fixture: the observation carries no enrollment attempt (id=%d status=%s)", observed.ID, observed.Status)
		}

		// A deploy re-enrollment of the same row with a different endpoint. The
		// deploy-enrollment context is what makes this enrollment B rather than an
		// ordinary re-enable.
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
		if b.ID != observed.ID {
			t.Fatalf("fixture: row id changed %d -> %d; this sequence re-enrolls the SAME row",
				observed.ID, b.ID)
		}
		if b.Status != models.TunnelStatusConnecting || !b.Enabled {
			t.Fatalf("fixture: B is not connecting+enabled: status=%q enabled=%v", b.Status, b.Enabled)
		}
		if b.EnrollmentAttempt == observed.EnrollmentAttempt {
			t.Fatalf("fixture: re-enrollment did not start a new attempt (still %d)", b.EnrollmentAttempt)
		}
		// B must be a REAL quarantine boundary BEFORE the obsolete verdict is released.
		requireBackendQuarantined(t, h, observed.ServerID, "before releasing the obsolete verdict")
		*before = *b
		return verdict
	})
	return serverID, before
}

// TestSameRowDeployReenrollmentSurvivesObsoleteAWGCanaryFailure is the finding5 exact
// sequence: an obsolete AWG canary failure must not touch the re-enrolled B.
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
	serverID, before := reenrollSameRowDuringCanary(t, h,
		errors.New("old AWG inner canary timed out"))

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "same-row-reenroll-failure", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if before == nil || before.ID == 0 {
		t.Fatalf("fixture: the re-enrollment was never established (deploy err=%v)", err)
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
	if live.ID != before.ID {
		t.Fatalf("the row changed: got %d, want %d", live.ID, before.ID)
	}
	// Exact before/after equality on every field the obsolete writer could move.
	if live.Status != before.Status || live.DisableReason != before.DisableReason ||
		live.StateVersion != before.StateVersion || live.Enabled != before.Enabled ||
		live.EnrollmentAttempt != before.EnrollmentAttempt {
		t.Fatalf("obsolete AWG failure drifted B: status=%q reason=%q v=%d enabled=%v attempt=%d; want %q/%q/%d/%v/%d",
			live.Status, live.DisableReason, live.StateVersion, live.Enabled, live.EnrollmentAttempt,
			before.Status, before.DisableReason, before.StateVersion, before.Enabled, before.EnrollmentAttempt)
	}
	if row.Status != before.Status || row.DisableReason != before.DisableReason || !row.Enabled {
		t.Fatalf("obsolete AWG failure persisted on B: status=%q reason=%q enabled=%v",
			row.Status, row.DisableReason, row.Enabled)
	}
	// Enrollment and eligibility unchanged: B is still quarantined, still unroutable.
	requireBackendQuarantined(t, h, *serverID, "after the obsolete verdict")
}
