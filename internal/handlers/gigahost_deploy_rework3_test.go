package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	gossh "golang.org/x/crypto/ssh"
)

// TestRework3_FirstContactHostKeyEnforcement verifies F1:
// 1. Unconfirmed host key on brand-new VPS is rejected before password auth.
// 2. Matching expected fingerprint is accepted.
// 3. Mismatched expected fingerprint is rejected.
// 4. Explicit confirm_host_key is accepted.
func TestRework3_FirstContactHostKeyEnforcement(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(hostKey)

	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		cb := cfg.HostKeyCallback
		if cb != nil {
			if err := cb(cfg.Host, &net.TCPAddr{}, hostKey); err != nil {
				return nil, err
			}
		}
		return &mockDeploySSHClient{fingerprint: fp}, nil
	})

	// 1. Unconfirmed first contact without fingerprint must fail
	_, err = h.verifyDeploySSHAccess(ctx, "198.51.100.50", GigahostDeployRequest{
		OrderID:     "ord_f1_unconfirmed",
		SSHPassword: "fixture-password",
	})
	if err == nil {
		t.Fatal("expected unconfirmed first contact to be rejected")
	}

	// 2. Matching expected fingerprint succeeds
	gotFP, err := h.verifyDeploySSHAccess(ctx, "198.51.100.50", GigahostDeployRequest{
		OrderID:             "ord_f1_matching",
		SSHPassword:         "fixture-password",
		ExpectedFingerprint: fp,
	})
	if err != nil {
		t.Fatalf("expected matching fingerprint to succeed, got: %v", err)
	}
	if gotFP != fp {
		t.Fatalf("expected captured fingerprint %s, got %s", fp, gotFP)
	}

	// 3. Mismatched expected fingerprint fails
	_, err = h.verifyDeploySSHAccess(ctx, "198.51.100.50", GigahostDeployRequest{
		OrderID:             "ord_f1_mismatched",
		SSHPassword:         "fixture-password",
		ExpectedFingerprint: "SHA256:mismatchedfingerprint1234567890abcdef1234=",
	})
	if err == nil {
		t.Fatal("expected mismatched fingerprint to be rejected")
	}

	// 4. Explicit confirmation flag succeeds
	gotFP, err = h.verifyDeploySSHAccess(ctx, "198.51.100.50", GigahostDeployRequest{
		OrderID:        "ord_f1_confirmed",
		SSHPassword:    "fixture-password",
		ConfirmHostKey: true,
	})
	if err != nil {
		t.Fatalf("expected explicitly confirmed first contact to succeed, got: %v", err)
	}
	if gotFP != fp {
		t.Fatalf("expected captured fingerprint %s, got %s", fp, gotFP)
	}
}

// TestRework3_TrafficQualificationFailClosed verifies F3:
// 1. During enablement, new backend starts in non-eligible connecting status (FilterHealthy returns 0).
// 2. Failed qualification probe transitions deploy status to "failed" and disables backend.
func TestRework3_TrafficQualificationFailClosed(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	// 1. Ineligible window check
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	h.vpnSvc.SetEnableBackendPostAddTunnelHookForTest(func() {
		close(entered)
		<-release
	})

	go func() {
		_, err := h.DeployGigahostOrder(ctx, GigahostDeployRequest{
			OrderID:        "ord_f3_window",
			SSHPassword:    "fixture-password",
			ConfirmHostKey: true,
		})
		done <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for post-AddTunnel boundary")
	}

	tunnels, err := h.vpnSvc.GetBackends(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eligible := loadbalancer.FilterHealthy(tunnels, 0)
	close(release)

	select {
	case deployErr := <-done:
		if deployErr != nil {
			t.Fatalf("deployment error: %v", deployErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deployment did not join")
	}

	if len(eligible) > 0 {
		t.Fatalf("expected 0 eligible backends during enablement window, got %d (status=%s)", len(eligible), eligible[0].Status)
	}

	// 2. Probe failure fail-closed check
	h2, _, _ := setupDeployTestEnv(t)
	h2.vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("fixture: probe handshake failed")
	})

	st, err := h2.DeployGigahostOrder(ctx, GigahostDeployRequest{
		OrderID:        "ord_f3_probe_fail",
		SSHPassword:    "fixture-password",
		ConfirmHostKey: true,
	})
	if err != nil {
		t.Fatalf("DeployGigahostOrder returned error instead of failed deploy DTO: %v", err)
	}
	if st.Status != DeployStatusFailed {
		t.Fatalf("expected deploy status %q on probe failure, got %q", DeployStatusFailed, st.Status)
	}

	tun, tunErr := h2.vpnSvc.GetTunnel(st.ServerID)
	if tunErr != nil {
		t.Fatal(tunErr)
	}
	if tun.Enabled {
		t.Fatal("expected backend tunnel to be disabled on qualification probe failure")
	}
	if tun.Status == models.TunnelStatusActive {
		t.Fatal("expected backend tunnel status to not be active on qualification probe failure")
	}

	order, _, lastErr, step, readErr := h2.getDeployOrderByID(ctx, "ord_f3_probe_fail")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if order.Status != DeployStatusFailed {
		t.Fatalf("expected persisted order status %q, got %q", DeployStatusFailed, order.Status)
	}
	if step != DeployStatusEnablingBackend {
		t.Fatalf("expected persisted step %q, got %q", DeployStatusEnablingBackend, step)
	}
	if !strings.Contains(lastErr, "qualification probe failed") {
		t.Fatalf("expected qualification error in lastErr, got %q", lastErr)
	}
}

// TestRework3_DeployStatusHandlerServesDiagnostics verifies F6:
// Deployment status endpoint serves step, error, and server_id diagnostics.
func TestRework3_DeployStatusHandlerServesDiagnostics(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	orderID := "ord_f6_diag"
	err := h.updateDeployOrderStatus(ctx, orderID, DeployStatusFailed, DeployStatusInstallingProtocol, "fixture protocol error", 1001, 42, "198.51.100.60")
	if err != nil {
		t.Fatal(err)
	}

	st, err := h.GetGigahostDeployStatus(ctx, orderID)
	if err != nil {
		t.Fatal(err)
	}

	if st.Status != DeployStatusFailed {
		t.Errorf("expected status %q, got %q", DeployStatusFailed, st.Status)
	}
	if st.Step != DeployStatusInstallingProtocol {
		t.Errorf("expected step %q, got %q", DeployStatusInstallingProtocol, st.Step)
	}
	if st.Error != "fixture protocol error" {
		t.Errorf("expected error %q, got %q", "fixture protocol error", st.Error)
	}
	if st.ServerID != 42 {
		t.Errorf("expected server_id 42, got %d", st.ServerID)
	}
	if st.AssignedIP != "198.51.100.60" {
		t.Errorf("expected assigned_ip 198.51.100.60, got %s", st.AssignedIP)
	}
}
