package handlers

// Observed-owner finalization through the production Gigahost deployment path
// (issue #794 group B).
//
// The included counterexamples prove the harm through the deployment handler; these
// are the retained regression controls for it, and they judge the END STATE of the
// backend that actually owns the server slot, not an error string:
//
//	stale success -> the replacement must not become active/enabled/durable-active
//	stale failure -> the replacement must not become disabled/quarantined
//	current owner -> both verdicts still apply to the generation they observed
//
// The subject is production code: the real deployment handler, service, pool, and
// SQLite store. Provider, SSH transport and network verdicts are the same fixtures
// the rest of this suite uses. No deployment, namespace or live device is involved.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// lateReplacementParams is a distinct proxy identity for the SAME server slot: same
// protocol, different endpoint and different client credentials. That is what an
// operator's delete-and-re-create produces, and it is why the slot id alone cannot
// identify the generation a qualification observed.
const lateReplacementParams = `{"uuid":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","port":8443,` +
	`"server_name":"replacement.example.com",` +
	`"public_key":"K4Z2q0m1nJ9v3xY8wT7rS6pQ5oN4lM3kJ2hG1fE0dC8","short_id":"0123456789abcdef"}`

// replaceBackendDuringQualification installs a proxy qualification verdict that
// first deletes the observed backend and creates a distinct replacement on the same
// server, then returns the verdict. It mirrors an operator acting on the backend
// while an in-flight deployment is still doing network work.
//
// It returns pointers the assertions read after the deployment has finished, so the
// control can prove which generation ended up where.
func replaceBackendDuringQualification(
	t *testing.T, h *Handlers, verdict func() (int64, error),
) (serverID, observedID, replacementID *int64) {
	t.Helper()
	serverID, observedID, replacementID = new(int64), new(int64), new(int64)
	ctx := context.Background()
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(_ context.Context, observed *models.BackendTunnel) (int64, error) {
		*serverID = observed.ServerID
		*observedID = observed.ID
		if err := h.vpnSvc.DeleteBackend(ctx, observed.ServerID); err != nil {
			t.Fatalf("retire the observed backend: %v", err)
		}
		// An ordinary administrative re-enable is not a deployment enrollment: the
		// replacement starts with no quarantine of its own, so anything that
		// quarantines it afterwards is the stale verdict under test.
		if err := h.vpnSvc.EnableBackendWithConfig(ctx, observed.ServerID, tunnel.BackendTunnelOptions{
			Protocol:       models.ProtocolVLESS,
			ProtocolParams: json.RawMessage(lateReplacementParams),
		}); err != nil {
			t.Fatalf("create the replacement backend: %v", err)
		}
		replacement, err := h.vpnSvc.GetTunnel(observed.ServerID)
		if err != nil || replacement == nil {
			t.Fatalf("read the replacement backend: %v", err)
		}
		if replacement.ID == observed.ID {
			t.Fatal("fixture: the replacement did not get a new generation")
		}
		*replacementID = replacement.ID
		return verdict()
	})
	return serverID, observedID, replacementID
}

// requireDeploymentBackendOutcome asserts what the deployment left on the server
// slot: which generation owns it, and whether that generation is still exactly the
// unqualified but administratively enabled backend the operator created.
func requireDeploymentBackendOutcome(
	t *testing.T, h *Handlers, serverID, replacementID int64, wantEnabled bool, wantQuarantined bool,
) *models.BackendTunnel {
	t.Helper()
	ctx := context.Background()
	live, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || live == nil {
		t.Fatalf("read the slot after the deployment: %v", err)
	}
	if live.ID != replacementID {
		t.Fatalf("the slot holds generation %d, want the operator's replacement %d", live.ID, replacementID)
	}
	if live.Enabled != wantEnabled {
		t.Fatalf("replacement enabled = %v, want %v", live.Enabled, wantEnabled)
	}
	if live.Status == models.TunnelStatusActive || live.Status == models.TunnelStatusDegraded {
		t.Fatalf("the replacement was admitted by a verdict about another generation (status %q)", live.Status)
	}
	durable, err := h.db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || durable == nil {
		t.Fatalf("read the stored slot: %v", err)
	}
	if durable.ID != replacementID {
		t.Fatalf("stored row id = %d, want the replacement generation %d", durable.ID, replacementID)
	}
	if durable.Enabled != wantEnabled {
		t.Fatalf("stored replacement enabled = %v, want %v", durable.Enabled, wantEnabled)
	}
	pending, err := h.db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatalf("read durable enrollments: %v", err)
	}
	if pending[serverID] != wantQuarantined {
		t.Fatalf("durable quarantine for the replacement = %v, want %v", pending[serverID], wantQuarantined)
	}
	return live
}

// TestRetiredProxySuccessDoesNotAdmitReplacement is the retained stale-SUCCESS
// regression: the deployment may report a truthful failure, but it must not hand
// the operator's replacement an admission it never earned.
func TestRetiredProxySuccessDoesNotAdmitReplacement(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	payload, _ := json.Marshal("fixture-only")

	// The qualification of the DELETED backend succeeds: this is exactly the stale
	// success the finding describes.
	serverID, observedID, replacementID := replaceBackendDuringQualification(t, h, func() (int64, error) {
		return 5, nil
	})

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: string(payload[1 : len(payload)-1]),
		ServerName: "retired-success", Protocol: models.ProtocolVLESS, Port: "443", WaitReady: true,
	})
	if *replacementID == 0 {
		t.Fatalf("fixture: the replacement was never created (deploy err=%v)", err)
	}
	if err == nil {
		t.Fatal("a deployment whose backend was replaced mid-flight reported success")
	}
	live := requireDeploymentBackendOutcome(t, h, *serverID, *replacementID, true, false)
	if live.LatencyMS != 0 {
		t.Fatalf("the retired observation's latency %d ms was applied to the replacement", live.LatencyMS)
	}
	if *observedID == *replacementID {
		t.Fatal("fixture: the observed and replacement generations are the same")
	}
}

// TestRetiredProxyFailureDoesNotWithdrawReplacement is the retained stale-FAILURE
// regression: an obsolete timeout must not disable, detach or quarantine the
// replacement, through either the qualification cleanup or the enclosing install
// failure path.
func TestRetiredProxyFailureDoesNotWithdrawReplacement(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	payload, _ := json.Marshal("fixture-only")

	serverID, observedID, replacementID := replaceBackendDuringQualification(t, h, func() (int64, error) {
		return 0, errors.New("old transport timed out")
	})

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: string(payload[1 : len(payload)-1]),
		ServerName: "retired-failure", Protocol: models.ProtocolVLESS, Port: "443", WaitReady: true,
	})
	if *replacementID == 0 {
		t.Fatalf("fixture: the replacement was never created (deploy err=%v)", err)
	}
	if err == nil {
		t.Fatal("a failed qualification reported success")
	}
	requireDeploymentBackendOutcome(t, h, *serverID, *replacementID, true, false)
	if *observedID == *replacementID {
		t.Fatal("fixture: the observed and replacement generations are the same")
	}
}

// TestCurrentOwnerProxyQualificationStillAdmits is the CURRENT-OWNER success
// control. It proves the identity fence did not narrow the legitimate path through
// the deployment handler: an uninterrupted deployment still admits its backend and
// releases the durable quarantine.
func TestCurrentOwnerProxyQualificationStillAdmits(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		return 5, nil
	})

	status, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "current-owner-success", Protocol: models.ProtocolVLESS, Port: "443", WaitReady: true,
	})
	if err != nil {
		t.Fatalf("an uninterrupted qualified deployment failed: %v", err)
	}
	serverID := status.ServerID
	live, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || live == nil {
		t.Fatalf("read the admitted backend: %v", err)
	}
	if live.Status != models.TunnelStatusActive || !live.Enabled {
		t.Fatalf("admitted backend = status %q enabled %v, want active/enabled", live.Status, live.Enabled)
	}
	pending, err := h.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pending[serverID] {
		t.Fatal("the admitted backend kept its durable quarantine")
	}
}

// TestCurrentOwnerProxyQualificationFailureStillWithdraws is the CURRENT-OWNER
// failure control: a genuine failure of the generation that still owns the slot
// keeps the established withdrawal semantics — quarantined and administratively
// disabled — rather than becoming inert.
func TestCurrentOwnerProxyQualificationFailureStillWithdraws(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		return 0, errors.New("authenticated application exchange failed")
	})

	status, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "current-owner-failure", Protocol: models.ProtocolVLESS, Port: "443", WaitReady: true,
	})
	if err == nil {
		t.Fatal("a failed qualification reported success")
	}
	if status == nil || status.ServerID <= 0 {
		t.Fatalf("no deployment status for the failed backend: %+v", status)
	}
	live, getErr := h.vpnSvc.GetTunnel(status.ServerID)
	if getErr != nil || live == nil {
		t.Fatalf("read the failed backend: %v", getErr)
	}
	if live.Enabled {
		t.Fatal("a backend that failed its own qualification was left administratively enabled")
	}
	pending, getErr := h.db.GetBackendPendingEnrollments(context.Background())
	if getErr != nil {
		t.Fatal(getErr)
	}
	if !pending[status.ServerID] {
		t.Fatal("a backend that failed its own qualification released its durable quarantine")
	}
}
