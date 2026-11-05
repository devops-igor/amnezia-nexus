package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/naive"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	gossh "golang.org/x/crypto/ssh"
)

// TestRework2_KnownHostMismatchRejected verifies that verifyDeploySSHAccess verifies
// host key against existing server identity and rejects mismatching keys before auth (F1).
func TestRework2_KnownHostMismatchRejected(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()
	srv := &models.Server{Name: "known-host-srv", Host: "198.51.100.20", SSHPort: 22, SSHUser: "root"}
	id, err := h.db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.SaveKnownHostFingerprint(ctx, id, ssh.FingerprintSHA256(trusted)); err != nil {
		t.Fatal(err)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := gossh.NewPublicKey(other)
	if err != nil {
		t.Fatal(err)
	}

	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		cb := ssh.NewHostKeyCallback(ctx, ssh.HostKeyCallbackOptions{
			ServerID:       cfg.ServerID,
			Store:          cfg.Store,
			RequireConfirm: cfg.RequireFingerprintConfirm,
		})
		if err := cb(cfg.Host, &net.TCPAddr{}, untrusted); err != nil {
			return nil, err
		}
		return &mockDeploySSHClient{}, nil
	})

	_, err = h.verifyDeploySSHAccess(ctx, srv.Host, GigahostDeployRequest{SSHPassword: "fixture-only"})
	if err == nil {
		t.Fatal("expected verifyDeploySSHAccess to reject mismatching known host key")
	}
}

// TestRework2_DeployTimeoutBudgetExtended verifies that deploy routes receive the 15-minute budget (F4).
func TestRework2_DeployTimeoutBudgetExtended(t *testing.T) {
	for _, path := range []string{
		"/api/admin/hosting/gigahost/deploy",
		"/api/admin/hosting/gigahost/orders/order-1/setup",
	} {
		t.Run(path, func(t *testing.T) {
			handler := middleware.OperationTimeout(60 * time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				deadline, ok := r.Context().Deadline()
				if !ok {
					t.Fatal("no deadline")
				}
				remaining := time.Until(deadline)
				if remaining < 14*time.Minute {
					t.Errorf("expected at least 14m timeout budget for %s, got %v", path, remaining)
				}
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil))
		})
	}
}

// TestRework2_FailDeployStatusPreservesOnCanceledContext verifies that failDeployStatus
// uses a cancellation-independent context so timeouts still persist failed status in DB (F4).
func TestRework2_FailDeployStatusPreservesOnCanceledContext(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	orderID := "ord-canceled-ctx"
	st, err := h.failDeployStatus(canceledCtx, orderID, DeployStatusInstallingProtocol, errors.New("timeout reached"), 0, 0, "198.51.100.30", "awg", "51820")
	if err == nil || st.Status != DeployStatusFailed {
		t.Fatalf("expected failed status, got %v", st)
	}

	order, _, lastErr, step, getErr := h.getDeployOrderByID(context.Background(), orderID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if order == nil || order.Status != DeployStatusFailed {
		t.Fatalf("expected order status failed in DB, got %v", order)
	}
	if step != DeployStatusInstallingProtocol || !strings.Contains(lastErr, "timeout reached") {
		t.Fatalf("expected step and error persisted, got step=%q error=%q", step, lastErr)
	}
}

// TestRework2_FreshProxyHostBootstrapsDocker verifies Docker bootstrap on fresh VLESS/Naive hosts (F5).
func TestRework2_FreshProxyHostBootstrapsDocker(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			h, _, _ := setupDeployTestEnv(t)
			dockerInstalled := false
			client := &testMockSSHClient{
				fileExistsFn: func(ctx context.Context, path string) (bool, error) {
					return false, nil
				},
				cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
					if cmd == "docker --version" {
						if dockerInstalled {
							return "Docker version 24.0.5, build cedb786", "", 0, nil
						}
						return "", "docker: command not found", 127, nil
					}
					if strings.Contains(cmd, "docker.io") || strings.Contains(cmd, "enable --now docker") {
						dockerInstalled = true
						return "", "", 0, nil
					}
					return "", "", 0, nil
				},
			}
			pool := &testMockSSHPool{client: client}
			if proto == models.ProtocolVLESS {
				h.registry.Register(xray.NewXrayManager(pool))
			} else {
				h.registry.Register(naive.NewNaiveManager(pool))
			}
			st, err := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
				OrderID:     "rework2-fresh-" + proto,
				SSHPassword: "fixture-only",
				Protocol:    proto,
				TLSDomain:   "vpn.example.com",
			})
			if err != nil {
				t.Fatalf("fresh ready VPS onboarding failed: status=%s step=%s error=%v", st.Status, st.Step, err)
			}
			if !dockerInstalled {
				t.Errorf("expected Docker to be bootstrapped for protocol %s", proto)
			}
		})
	}
}

// TestRework2_AWGRetryPreservesIdentity verifies that retrying AWG does not wipe containers or mismatch DB (F2).
func TestRework2_AWGRetryPreservesIdentity(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()
	req := GigahostDeployRequest{OrderID: "rework2-retry-awg", SSHPassword: "fixture-only", Protocol: models.ProtocolAWG}
	first, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	destructive := false
	var uploadedConfig string
	client := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "docker rm -fv") {
				destructive = true
			}
			return "", "", 0, nil
		},
		uploadFn: func(ctx context.Context, path string, b []byte) error {
			if path == "/tmp/_amnz_awg0.conf" {
				uploadedConfig = string(b)
			}
			return nil
		},
	}
	h.registry.Register(awg.NewAWGManager(&testMockSSHPool{client: client}))

	st, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if destructive {
		t.Errorf("retry executed destructive container removal (docker rm -fv)")
	}
	if uploadedConfig == "" {
		t.Errorf("expected configuration to be written on retry")
	}

	after, err := h.db.GetServer(ctx, first.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	dbPub := after.Protocols["awg"].(map[string]any)["public_key"].(string)

	var newPriv string
	for _, line := range strings.Split(uploadedConfig, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "PrivateKey") {
			_, newPriv, _ = strings.Cut(line, "=")
			newPriv = strings.TrimSpace(newPriv)
		}
	}
	if newPriv != "" {
		newPub, err := tunnel.PublicKeyFromPrivateKey(newPriv)
		if err != nil {
			t.Fatal(err)
		}
		if newPub != dbPub {
			t.Errorf("cryptographic identity mismatch: container has %s, DB has %s (status: %s)", newPub, dbPub, st.Status)
		}
	}
}

// TestRework2_RetryFailureDisablesBackend verifies that retry failure quarantines the backend (F2).
func TestRework2_RetryFailureDisablesBackend(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()
	req := GigahostDeployRequest{OrderID: "rework2-retry-fail", SSHPassword: "fixture-only", Protocol: models.ProtocolAWG}
	first, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		installFn: func(context.Context, *models.Server, map[string]any) error {
			return errors.New("remote build failure")
		},
	})

	st, err := h.DeployGigahostOrder(ctx, req)
	if err == nil || st.Status != DeployStatusFailed {
		t.Fatal("expected deployment failure")
	}

	tun, err := h.vpnSvc.GetTunnel(first.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	if tun.Enabled {
		t.Errorf("failed retry left backend enabled")
	}
}

// TestRework2_AWGNonEligibleBeforeTrafficQualification verifies that AWG starts in connecting state
// and is not admitted to the healthy load balancer pool before traffic qualification (F3).
func TestRework2_AWGNonEligibleBeforeTrafficQualification(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	h.vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("unqualified traffic")
	})
	st, _ := h.DeployGigahostOrder(context.Background(), GigahostDeployRequest{
		OrderID:        "rework2-awg-traffic",
		SSHPassword:    "fixture-only",
		Protocol:       models.ProtocolAWG,
		ConfirmHostKey: true,
	})

	tun, err := h.vpnSvc.GetTunnel(st.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	eligible := loadbalancer.FilterHealthy([]*models.BackendTunnel{tun}, 0)
	if len(eligible) != 0 {
		t.Fatalf("AWG was admitted to healthy pool without traffic qualification: status=%s enabled=%t", tun.Status, tun.Enabled)
	}
}
