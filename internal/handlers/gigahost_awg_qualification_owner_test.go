package handlers

// Observed-owner finalization on the SIBLING AWG qualification consumer
// (issue #794 group B).
//
// The proxy finalizer is not the only one: a non-proxy deployment reaches
// qualifyBackendTraffic, which owns the same success/failure decision through a
// different pair of seams (outer handshake probe + inner canary). The finding named
// this consumer explicitly, so its own stale-result control is required rather than
// inferred from the proxy one.
//
// The subject is production code — the real deployment handler, service, pool and
// SQLite store — driven through the same deploy fixture the rest of this suite uses.
// The outer handshake verdict, the inner canary verdict, the provider answer and the
// SSH transport are that fixture's controlled boundaries; no device, namespace or
// deployment is involved.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// replaceBackendDuringCanary installs an inner-canary verdict that first retires the
// observed backend and creates a distinct replacement on the same server, then
// returns that verdict. This is an operator acting while the deployment is still
// qualifying, which is precisely the schedule the finding describes.
//
// It returns pointers the assertions read after the deployment finished, so the
// control can prove which generation ended up where.
func replaceBackendDuringCanary(
	t *testing.T, h *Handlers, verdict error,
) (serverID, observedID, replacementID *int64) {
	t.Helper()
	serverID, observedID, replacementID = new(int64), new(int64), new(int64)
	ctx := context.Background()
	h.vpnSvc.SetCanaryProbeFunc(func(_ context.Context, observed *models.BackendTunnel) error {
		*serverID = observed.ServerID
		*observedID = observed.ID
		if err := h.vpnSvc.DeleteBackend(ctx, observed.ServerID); err != nil {
			t.Fatalf("retire the observed backend: %v", err)
		}
		// An ordinary administrative re-enable, not a deployment enrollment: the
		// replacement therefore starts with no quarantine of its own, so anything
		// that quarantines it afterwards is the stale verdict under test.
		if err := h.vpnSvc.EnableBackendWithConfig(ctx, observed.ServerID,
			tunnel.BackendTunnelOptions{Protocol: models.ProtocolAWG}); err != nil {
			t.Fatalf("create the replacement backend: %v", err)
		}
		replacement, err := h.vpnSvc.GetTunnel(observed.ServerID)
		if err != nil || replacement == nil {
			t.Fatalf("read the replacement backend: %v", err)
		}
		if replacement.ID == observed.ID {
			t.Fatal("fixture: the replacement did not get a new generation")
		}
		// Establish the operator baseline explicitly: an unqualified (connecting)
		// but administratively enabled backend. An AWG enable with no explicit
		// protocol records `active` for a legacy reason unrelated to this control,
		// so the status is set here rather than inferred from the fixture.
		if err := h.vpnSvc.SetTunnelStatus(ctx, observed.ServerID, models.TunnelStatusConnecting, 0); err != nil {
			t.Fatalf("set the replacement connecting: %v", err)
		}
		replacement, err = h.vpnSvc.GetTunnel(observed.ServerID)
		if err != nil || replacement == nil {
			t.Fatalf("re-read the replacement backend: %v", err)
		}
		if !replacement.Enabled || replacement.Status != models.TunnelStatusConnecting {
			t.Fatalf("fixture: replacement precondition = enabled %v status %q, want enabled/connecting",
				replacement.Enabled, replacement.Status)
		}
		*replacementID = replacement.ID
		return verdict
	})
	return serverID, observedID, replacementID
}

// requireAWGReplacementUntouched asserts that the operator's replacement still owns
// the slot and is still the unqualified but administratively enabled backend the
// re-create produced.
func requireAWGReplacementUntouched(t *testing.T, h *Handlers, serverID, replacementID int64) *models.BackendTunnel {
	t.Helper()
	ctx := context.Background()
	live, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || live == nil {
		t.Fatalf("read the slot: %v", err)
	}
	if live.ID != replacementID {
		t.Fatalf("the slot holds generation %d, want the replacement %d", live.ID, replacementID)
	}
	if !live.Enabled {
		t.Fatal("a retired AWG verdict administratively disabled the replacement")
	}
	if live.Status == models.TunnelStatusActive || live.Status == models.TunnelStatusDegraded {
		t.Fatalf("a retired AWG verdict admitted the replacement (status %q)", live.Status)
	}
	durable, err := h.db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || durable == nil {
		t.Fatalf("read the stored slot: %v", err)
	}
	if durable.ID != replacementID {
		t.Fatalf("stored row id = %d, want the replacement %d", durable.ID, replacementID)
	}
	if !durable.Enabled {
		t.Fatal("a retired AWG verdict disabled the replacement in the store")
	}
	pending, err := h.db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[serverID] {
		t.Fatal("a retired AWG verdict quarantined the replacement it never observed")
	}
	return live
}

// TestRetiredAWGCanaryFailureDoesNotWithdrawReplacement is the AWG stale-FAILURE
// control: the inner canary of a since-retired backend fails, and the replacement the
// operator created keeps its administrative state and enrollment.
func TestRetiredAWGCanaryFailureDoesNotWithdrawReplacement(t *testing.T) {
	h, _, provider := setupDeployTestEnv(t)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID:   2101,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.61",
		}, nil
	}
	// The outer handshake succeeds; only the inner payload verdict fails.
	h.vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})
	serverID, observedID, replacementID := replaceBackendDuringCanary(t, h,
		errors.New("inner canary: payload did not traverse"))

	_, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "awg-retired-failure", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if *replacementID == 0 {
		t.Fatalf("fixture: the replacement was never created (deploy err=%v)", err)
	}
	if err == nil {
		t.Fatal("a failed canary reported a successful deployment")
	}
	requireAWGReplacementUntouched(t, h, *serverID, *replacementID)
	if *observedID == *replacementID {
		t.Fatal("fixture: the observed and replacement generations are the same")
	}
}

// TestRetiredAWGSuccessDoesNotAdmitReplacement is the AWG stale-SUCCESS control: the
// handshake and canary of a since-retired backend both succeed, and the replacement
// must not be admitted on that evidence.
func TestRetiredAWGSuccessDoesNotAdmitReplacement(t *testing.T) {
	h, _, provider := setupDeployTestEnv(t)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			ServerID:   2102,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.62",
		}, nil
	}
	h.vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	})
	serverID, observedID, replacementID := replaceBackendDuringCanary(t, h, nil)

	status, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "awg-retired-success", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if *replacementID == 0 {
		t.Fatalf("fixture: the replacement was never created (deploy status=%+v err=%v)", status, err)
	}
	if status != nil && status.Status == DeployStatusReady {
		t.Fatal("a deployment whose backend was replaced mid-flight reported ready")
	}
	requireAWGReplacementUntouched(t, h, *serverID, *replacementID)
	if *observedID == *replacementID {
		t.Fatal("fixture: the observed and replacement generations are the same")
	}
}

// TestCurrentOwnerAWGQualificationStillAdmits is the AWG CURRENT-OWNER success
// control, so the identity fence is not proven only for proxies: an uninterrupted
// AWG deployment still admits its backend and releases the durable quarantine.
func TestCurrentOwnerAWGQualificationStillAdmits(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	h.vpnSvc.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error { return nil })

	status, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID: "ord_test_1001", SSHPassword: "ValidSSHPass123!",
		ServerName: "awg-current-owner", Protocol: "awg", Port: "51820", WaitReady: true,
	})
	if err != nil {
		t.Fatalf("an uninterrupted AWG deployment failed: %v", err)
	}
	if status == nil || status.Status != DeployStatusReady {
		t.Fatalf("deployment status = %+v, want ready", status)
	}
	live, getErr := h.vpnSvc.GetTunnel(status.ServerID)
	if getErr != nil || live == nil {
		t.Fatalf("read the admitted backend: %v", getErr)
	}
	if live.Status != models.TunnelStatusActive || !live.Enabled {
		t.Fatalf("admitted AWG backend = status %q enabled %v, want active/enabled", live.Status, live.Enabled)
	}
	pending, getErr := h.db.GetBackendPendingEnrollments(context.Background())
	if getErr != nil {
		t.Fatal(getErr)
	}
	if pending[status.ServerID] {
		t.Fatal("the admitted AWG backend kept its durable quarantine")
	}
}
