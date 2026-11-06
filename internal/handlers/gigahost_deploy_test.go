package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/go-chi/chi/v5"
)

type mockDeploySSHClient struct {
	testMockSSHClient
	fingerprint string
	closeCalled bool
}

func (m *mockDeploySSHClient) CapturedFingerprint() string {
	if m.fingerprint != "" {
		return m.fingerprint
	}
	return "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

func (m *mockDeploySSHClient) Close() error {
	m.closeCalled = true
	return nil
}

func setupDeployTestEnv(t *testing.T) (*Handlers, *chi.Mux, *mockGigahostClient) {
	t.Helper()
	h, db, _ := setupTestHandlers(t)

	vpnCfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("failed to init vpn service: %v", err)
	}
	h.vpnSvc = vpnSvc
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})

	mockClient := &mockGigahostClient{
		getDeployStatusFn: func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID:    orderID,
				ServerID:   1001,
				Status:     gigahost.StatusReady,
				AssignedIP: "198.51.100.10",
			}, nil
		},
		getServersFn: func(ctx context.Context) ([]gigahost.ServerInfo, error) {
			return []gigahost.ServerInfo{
				{
					ID:      1001,
					OrderID: "ord_test_1001",
					IPv4:    "198.51.100.10",
					Status:  "ready",
				},
			}, nil
		},
	}
	h.SetGigahostClient(mockClient)

	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		return &mockDeploySSHClient{fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, nil
	})

	// Setup managers in registry
	reg := manager.NewRegistry()
	reg.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			if server.Protocols == nil {
				server.Protocols = make(map[string]any)
			}
			server.Protocols["awg"] = map[string]any{
				"installed":  true,
				"port":       float64(51820),
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			}
			return nil
		},
	})
	reg.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			if server.Protocols == nil {
				server.Protocols = make(map[string]any)
			}
			server.Protocols["vless"] = map[string]any{
				"installed": true,
				"port":      "443",
				"params": map[string]any{
					"uuid":       "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
					"port":       443,
					"public_key": "x9aBVLESS1234567890abcdef1234567890abcdef12=",
				},
			}
			return nil
		},
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id":  "vless-client-1",
				"uuid":       "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
				"port":       443,
				"public_key": "x9aBVLESS1234567890abcdef1234567890abcdef12=",
			}, nil
		},
	})
	reg.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			if server.Protocols == nil {
				server.Protocols = make(map[string]any)
			}
			server.Protocols["naive"] = map[string]any{
				"installed": true,
				"port":      "443",
				"domain":    "naive.example.com",
				"params": map[string]any{
					"username": "naive-user-1",
					"password": "naive-pass-1",
					"domain":   "naive.example.com",
					"port":     443,
				},
			}
			return nil
		},
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id": "naive-user-1",
				"username":  "naive-user-1",
				"password":  "naive-pass-1",
				"domain":    "naive.example.com",
				"port":      443,
			}, nil
		},
	})
	h.registry = reg

	r := chi.NewRouter()
	r.Use(middleware.RequireAdmin)
	r.Route("/api/admin/hosting/gigahost", func(r chi.Router) {
		r.Post("/deploy", h.GigahostDeployHandler)
		r.Post("/orders/{order_id}/setup", h.GigahostDeployHandler)
		r.Get("/deploy/{order_id}", h.GigahostDeployStatusHandler)
		r.Get("/orders/{order_id}/status", h.GigahostDeployStatusHandler)
	})

	return h, r, mockClient
}

func TestGigahostDeploy_Success_AWG(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	req := GigahostDeployRequest{
		OrderID:     "ord_test_1001",
		SSHPassword: "ValidSSHPass123!",
		ServerName:  "Gigahost-AWG-1",
		Protocol:    "awg",
		Port:        "51820",
		WaitReady:   true,
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("DeployGigahostOrder failed: %v", err)
	}

	if status.Status != DeployStatusReady {
		t.Errorf("expected status %s, got %s", DeployStatusReady, status.Status)
	}
	if status.Step != DeployStatusReady {
		t.Errorf("expected step %s, got %s", DeployStatusReady, status.Step)
	}
	if status.AssignedIP != "198.51.100.10" {
		t.Errorf("expected assigned IP 198.51.100.10, got %s", status.AssignedIP)
	}
	if status.ProviderServerID != 1001 {
		t.Errorf("expected provider server ID 1001, got %d", status.ProviderServerID)
	}
	if status.ServerID <= 0 {
		t.Fatalf("expected valid Nexus DB server ID, got %d", status.ServerID)
	}

	// Verify server registration in database with provider metadata
	server, err := h.db.GetServer(ctx, status.ServerID)
	if err != nil || server == nil {
		t.Fatalf("expected server %d to exist in database: %v", status.ServerID, err)
	}
	if server.Name != "Gigahost-AWG-1" {
		t.Errorf("expected server name Gigahost-AWG-1, got %s", server.Name)
	}
	if server.Host != "198.51.100.10" {
		t.Errorf("expected server host 198.51.100.10, got %s", server.Host)
	}
	if server.Protocols["provider"] != "gigahost" {
		t.Errorf("expected provider 'gigahost', got %v", server.Protocols["provider"])
	}
	if !matchProviderServerID(server.Protocols["provider_server_id"], 1001) {
		t.Errorf("expected provider_server_id 1001, got %v", server.Protocols["provider_server_id"])
	}

	// Verify host key fingerprint was saved
	fp, err := h.db.GetKnownHostFingerprint(ctx, status.ServerID)
	if err != nil || fp != "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("expected saved fingerprint SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, got %s (err: %v)", fp, err)
	}

	// Verify backend is active in VPN service
	tun, err := h.vpnSvc.GetTunnel(status.ServerID)
	if err != nil || tun == nil || !tun.Enabled {
		t.Errorf("expected backend tunnel for server %d to be active and enabled, got %+v err=%v", status.ServerID, tun, err)
	}
}

func TestGigahostDeploy_Success_VLESS(t *testing.T) {
	h, _, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()
	// A proxy is only reported ready after an authenticated application
	// traffic qualification succeeds; supply that network outcome.
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(
		func(context.Context, *models.BackendTunnel) (int64, error) { return 5, nil },
	)

	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID:    orderID,
			ServerID:   1002,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.20",
		}, nil
	}

	req := GigahostDeployRequest{
		OrderID:       "ord_test_1002",
		SSHPrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
		Protocol:      "vless",
		Port:          "443",
		TLSDomain:     "gateway.icloud.com",
		EngineProfile: "sing-box",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("DeployGigahostOrder VLESS failed: %v", err)
	}

	if status.Status != DeployStatusReady {
		t.Errorf("expected status %s, got %s", DeployStatusReady, status.Status)
	}
	if status.Protocol != models.ProtocolVLESS {
		t.Errorf("expected protocol vless, got %s", status.Protocol)
	}

	tun, err := h.vpnSvc.GetTunnel(status.ServerID)
	if err != nil || tun == nil || !tun.Enabled {
		t.Fatalf("expected active vless backend tunnel, got %+v err=%v", tun, err)
	}
	if tun.Protocol != models.ProtocolVLESS {
		t.Errorf("expected tunnel protocol vless, got %s", tun.Protocol)
	}
}

func TestGigahostDeploy_Success_Naive(t *testing.T) {
	h, _, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()
	// A proxy is only reported ready after an authenticated application
	// traffic qualification succeeds; supply that network outcome.
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(
		func(context.Context, *models.BackendTunnel) (int64, error) { return 5, nil },
	)

	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID:    orderID,
			ServerID:   1003,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.30",
		}, nil
	}

	req := GigahostDeployRequest{
		OrderID:     "ord_test_1003",
		SSHPassword: "Password123!",
		Protocol:    "naive",
		Port:        "443",
		TLSDomain:   "naive.example.com",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("DeployGigahostOrder Naive failed: %v", err)
	}

	if status.Status != DeployStatusReady {
		t.Errorf("expected status %s, got %s", DeployStatusReady, status.Status)
	}
	if status.Protocol != models.ProtocolNaive {
		t.Errorf("expected protocol naive, got %s", status.Protocol)
	}

	tun, err := h.vpnSvc.GetTunnel(status.ServerID)
	if err != nil || tun == nil || !tun.Enabled {
		t.Fatalf("expected active naive backend tunnel, got %+v err=%v", tun, err)
	}
	if tun.Protocol != models.ProtocolNaive {
		t.Errorf("expected tunnel protocol naive, got %s", tun.Protocol)
	}
}

func TestGigahostDeploy_IdempotentDeduplication_DuplicateRejected(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	// 1. First order registers server ID 1001
	req1 := GigahostDeployRequest{
		OrderID:     "ord_dedup_1",
		SSHPassword: "Password123!",
		Protocol:    "awg",
	}
	status1, err := h.DeployGigahostOrder(ctx, req1)
	if err != nil || status1.Status != DeployStatusReady {
		t.Fatalf("initial order deploy failed: %v", err)
	}

	// 2. Second order attempts to register the same provider server ID 1001
	req2 := GigahostDeployRequest{
		OrderID:          "ord_dedup_2",
		ProviderServerID: 1001,
		AssignedIP:       "198.51.100.10",
		SSHPassword:      "Password123!",
		Protocol:         "awg",
	}
	status2, err := h.DeployGigahostOrder(ctx, req2)
	if err == nil {
		t.Fatal("expected duplicate server registration to be rejected with error, got nil")
	}
	if !errors.Is(err, ErrDuplicateServerID) && !strings.Contains(err.Error(), "duplicate server registration rejected") {
		t.Errorf("expected ErrDuplicateServerID, got: %v", err)
	}
	if status2.Status != DeployStatusFailed {
		t.Errorf("expected status %s, got %s", DeployStatusFailed, status2.Status)
	}

	// 3. Verify exactly 1 server row exists in servers table
	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		t.Fatalf("GetAllServers failed: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected exactly 1 server in database, found %d", len(servers))
	}
}

func TestGigahostDeploy_FailureHandling_DeployCheckFailed(t *testing.T) {
	h, _, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()

	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID,
			Status:  gigahost.StatusFailed,
			Error:   "insufficient host capacity in region 3",
		}, nil
	}

	req := GigahostDeployRequest{
		OrderID:     "ord_fail_provider",
		SSHPassword: "Password123!",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("expected error on failed provider deployment, got nil")
	}
	if status.Status != DeployStatusFailed {
		t.Errorf("expected status %s, got %s", DeployStatusFailed, status.Status)
	}
	if status.Step != DeployStatusDeploying {
		t.Errorf("expected step %s, got %s", DeployStatusDeploying, status.Step)
	}
	if !strings.Contains(status.Error, "insufficient host capacity") {
		t.Errorf("expected diagnostic error containing capacity message, got: %s", status.Error)
	}

	// Verify no server registered and no backend in pool
	servers, _ := h.db.GetAllServers(ctx)
	if len(servers) != 0 {
		t.Errorf("expected 0 servers in database, got %d", len(servers))
	}
}

func TestGigahostDeploy_FailureHandling_DeployCheckStillDeploying(t *testing.T) {
	h, _, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()

	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID: orderID,
			Status:  gigahost.StatusDeploying,
		}, nil
	}
	mockClient.getServersFn = func(ctx context.Context) ([]gigahost.ServerInfo, error) {
		return nil, nil
	}

	req := GigahostDeployRequest{
		OrderID:     "ord_still_deploying",
		SSHPassword: "Password123!",
		WaitReady:   false,
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("expected non-blocking deploying return without error, got: %v", err)
	}
	if status.Status != DeployStatusDeploying {
		t.Errorf("expected status %s, got %s", DeployStatusDeploying, status.Status)
	}
	if status.Step != DeployStatusDeploying {
		t.Errorf("expected step %s, got %s", DeployStatusDeploying, status.Step)
	}

	servers, _ := h.db.GetAllServers(ctx)
	if len(servers) != 0 {
		t.Errorf("expected 0 servers in database, got %d", len(servers))
	}
}

func TestGigahostDeploy_FailureHandling_SSHVerificationFailed(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		return nil, errors.New("connection refused: port 22 unreachable")
	})

	req := GigahostDeployRequest{
		OrderID:     "ord_ssh_fail",
		SSHPassword: "WrongPassword!",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("expected error on failed SSH dial, got nil")
	}
	if status.Status != DeployStatusFailed {
		t.Errorf("expected status %s, got %s", DeployStatusFailed, status.Status)
	}
	if status.Step != DeployStatusSSHVerifying {
		t.Errorf("expected step %s, got %s", DeployStatusSSHVerifying, status.Step)
	}
	if !strings.Contains(status.Error, "connection refused") {
		t.Errorf("expected error diagnostics mentioning connection refused, got: %s", status.Error)
	}

	servers, _ := h.db.GetAllServers(ctx)
	if len(servers) != 0 {
		t.Errorf("expected 0 servers in database, got %d", len(servers))
	}
}

func TestGigahostDeploy_FailureHandling_ProtocolInstallFailed(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	// Override AWG manager to return an installation error
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			return errors.New("docker daemon is not running on host")
		},
	})

	req := GigahostDeployRequest{
		OrderID:     "ord_proto_fail",
		SSHPassword: "ValidPassword123!",
		Protocol:    "awg",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("expected error on failed protocol install, got nil")
	}
	if status.Status != DeployStatusFailed {
		t.Errorf("expected status %s, got %s", DeployStatusFailed, status.Status)
	}
	if status.Step != DeployStatusInstallingProtocol {
		t.Errorf("expected step %s, got %s", DeployStatusInstallingProtocol, status.Step)
	}
	if !strings.Contains(status.Error, "docker daemon is not running") {
		t.Errorf("expected diagnostic error mentioning docker daemon, got: %s", status.Error)
	}

	// Backend must remain disabled and not active in the pool
	if status.ServerID > 0 {
		tun, _ := h.vpnSvc.GetTunnel(status.ServerID)
		if tun != nil && tun.Enabled {
			t.Errorf("expected backend tunnel for server %d to NOT be active, but it was enabled", status.ServerID)
		}
	}
}

func TestGigahostDeploy_FailureHandling_BackendEnableFailed(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	// Register AWG manager without public_key so EnableBackend fails reachability/validation
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			if server.Protocols == nil {
				server.Protocols = make(map[string]any)
			}
			server.Protocols["awg"] = map[string]any{
				"installed": true,
				"port":      51820,
				// public_key omitted intentionally so EnableBackend fails
			}
			return nil
		},
	})

	req := GigahostDeployRequest{
		OrderID:     "ord_backend_fail",
		SSHPassword: "ValidPassword123!",
		Protocol:    "awg",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("expected error when backend enablement fails, got nil")
	}
	if status.Status != DeployStatusFailed {
		t.Errorf("expected status %s, got %s", DeployStatusFailed, status.Status)
	}
	if status.Step != DeployStatusEnablingBackend {
		t.Errorf("expected step %s, got %s", DeployStatusEnablingBackend, status.Step)
	}

	// Backend must not be active in the pool
	tun, _ := h.vpnSvc.GetTunnel(status.ServerID)
	if tun != nil && tun.Enabled {
		t.Errorf("expected backend tunnel for server %d to remain disabled, but it was enabled", status.ServerID)
	}
}

func TestGigahostDeploy_RestartResumeBehavior(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	// 1. First run fails at protocol install
	failOnce := true
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			if failOnce {
				failOnce = false
				return errors.New("transient network error downloading container image")
			}
			if server.Protocols == nil {
				server.Protocols = make(map[string]any)
			}
			server.Protocols["awg"] = map[string]any{
				"installed":  true,
				"port":       float64(51820),
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			}
			return nil
		},
	})

	req := GigahostDeployRequest{
		OrderID:     "ord_resume_flow",
		SSHPassword: "Password123!",
		Protocol:    "awg",
	}

	firstStatus, err := h.DeployGigahostOrder(ctx, req)
	if err == nil || firstStatus.Status != DeployStatusFailed {
		t.Fatalf("expected first attempt to fail at protocol install, got err=%v status=%s", err, firstStatus.Status)
	}
	if firstStatus.ServerID <= 0 {
		t.Fatalf("expected server to be created during attempt 1, got ID %d", firstStatus.ServerID)
	}
	initialServerID := firstStatus.ServerID

	// Verify database count is 1
	servers, _ := h.db.GetAllServers(ctx)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server registered in database, got %d", len(servers))
	}

	// 2. Retry deployment for the SAME order
	retryStatus, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("resumed deployment failed: %v", err)
	}
	if retryStatus.Status != DeployStatusReady {
		t.Errorf("expected resumed status %s, got %s", DeployStatusReady, retryStatus.Status)
	}
	if retryStatus.ServerID != initialServerID {
		t.Errorf("expected resumed deployment to reuse server %d, got %d", initialServerID, retryStatus.ServerID)
	}

	// Verify no duplicate row was created in database
	serversAfter, _ := h.db.GetAllServers(ctx)
	if len(serversAfter) != 1 {
		t.Fatalf("expected server count to remain 1, but found %d", len(serversAfter))
	}

	// Verify backend is now enabled
	tun, err := h.vpnSvc.GetTunnel(retryStatus.ServerID)
	if err != nil || tun == nil || !tun.Enabled {
		t.Fatalf("expected backend to be enabled after successful resume, got %+v err=%v", tun, err)
	}
}

func TestGigahostDeploy_HTTPHandlers_FullCycle(t *testing.T) {
	_, r, _ := setupDeployTestEnv(t)

	adminSession := &models.SessionData{
		UserID:   "admin-1",
		Username: "admin",
		Role:     models.RoleAdmin,
	}
	supportSession := &models.SessionData{
		UserID:   "support-1",
		Username: "support",
		Role:     models.RoleSupport,
	}

	// 1. RBAC check: Support cannot trigger deploy
	payload := GigahostDeployRequest{
		OrderID:     "ord_http_1",
		SSHPassword: "Password123!",
	}
	bodyBytes, _ := json.Marshal(payload)
	reqSupport := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/deploy", bytes.NewReader(bodyBytes))
	reqSupport = reqSupport.WithContext(middleware.WithSession(reqSupport.Context(), supportSession))
	wSupport := httptest.NewRecorder()
	r.ServeHTTP(wSupport, reqSupport)
	if wSupport.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for support role, got %d", wSupport.Code)
	}

	// 2. Validation check: Missing order_id
	badPayload := GigahostDeployRequest{SSHPassword: "pwd"}
	badBytes, _ := json.Marshal(badPayload)
	reqBad := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/deploy", bytes.NewReader(badBytes))
	reqBad = reqBad.WithContext(middleware.WithSession(reqBad.Context(), adminSession))
	wBad := httptest.NewRecorder()
	r.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for missing order_id, got %d", wBad.Code)
	}

	// 3. Admin successfully triggers deploy via POST /deploy
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/deploy", bytes.NewReader(bodyBytes))
	reqAdmin = reqAdmin.WithContext(middleware.WithSession(reqAdmin.Context(), adminSession))
	wAdmin := httptest.NewRecorder()
	r.ServeHTTP(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin deploy, got %d: %s", wAdmin.Code, wAdmin.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(wAdmin.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
	deployData, ok := resp["deploy"].(map[string]any)
	if !ok || deployData["status"] != DeployStatusReady {
		t.Fatalf("expected deploy status 'ready', got: %+v", deployData)
	}

	// 4. Query status via GET /deploy/{order_id}
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/deploy/ord_http_1", nil)
	reqStatus = reqStatus.WithContext(middleware.WithSession(reqStatus.Context(), adminSession))
	wStatus := httptest.NewRecorder()
	r.ServeHTTP(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for deploy status, got %d", wStatus.Code)
	}
	var statusResp map[string]any
	_ = json.Unmarshal(wStatus.Body.Bytes(), &statusResp)
	deployStatus := statusResp["deploy"].(map[string]any)
	if deployStatus["status"] != DeployStatusReady {
		t.Errorf("expected deploy status ready, got %v", deployStatus["status"])
	}

	// 5. Setup via route /orders/{order_id}/setup
	payloadSetup := GigahostDeployRequest{
		SSHPassword: "Password123!",
		Protocol:    "awg",
	}
	setupBytes, _ := json.Marshal(payloadSetup)
	reqSetup := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/orders/ord_http_2/setup", bytes.NewReader(setupBytes))
	reqSetup = reqSetup.WithContext(middleware.WithSession(reqSetup.Context(), adminSession))
	wSetup := httptest.NewRecorder()
	r.ServeHTTP(wSetup, reqSetup)
	// ord_http_2 attempts to register same provider server ID 1001 -> duplicate rejection 409
	if wSetup.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate server ID on second order, got %d: %s", wSetup.Code, wSetup.Body.String())
	}
}

func TestGigahostDeploy_ConcurrentInFlightLock(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	ctx := context.Background()

	// Acquire lock for order
	unlock, ok := h.lockGigahostDeploy("ord_locked_1")
	if !ok {
		t.Fatal("expected first lock to succeed")
	}
	defer unlock()

	req := GigahostDeployRequest{
		OrderID:     "ord_locked_1",
		SSHPassword: "Password123!",
	}

	_, err := h.DeployGigahostOrder(ctx, req)
	if err == nil {
		t.Fatal("expected deploy call while locked to fail with in-progress error, got nil")
	}
	if !strings.Contains(err.Error(), "already in progress") {
		t.Errorf("expected error mentioning 'already in progress', got: %v", err)
	}
}

func TestGigahostDeploy_Polling_TransitionsToReady(t *testing.T) {
	h, _, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()

	pollCount := 0
	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		pollCount++
		if pollCount < 2 {
			return &gigahost.DeployStatusResponse{
				OrderID: orderID,
				Status:  gigahost.StatusDeploying,
			}, nil
		}
		return &gigahost.DeployStatusResponse{
			OrderID:    orderID,
			ServerID:   8801,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.88",
		}, nil
	}

	req := GigahostDeployRequest{
		OrderID:        "ord_poll_transition",
		SSHPassword:    "Password123!",
		WaitReady:      true,
		WaitTimeoutSec: 5,
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("expected successful deploy after polling, got: %v", err)
	}
	if status.Status != DeployStatusReady {
		t.Errorf("expected status ready after polling, got: %s", status.Status)
	}
	if status.AssignedIP != "198.51.100.88" {
		t.Errorf("expected assigned IP 198.51.100.88, got: %s", status.AssignedIP)
	}
}

func TestGigahostDeploy_GetStatus_RefreshesFromUpstream(t *testing.T) {
	h, r, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()

	// Initial record in DB with deploying status
	_ = h.ensureGigahostDeploySchema(ctx)
	_ = h.updateDeployOrderStatus(ctx, "ord_refresh_status", DeployStatusDeploying, DeployStatusDeploying, "", 0, 0, "")

	// Upstream now reports ready
	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{
			OrderID:    orderID,
			ServerID:   9901,
			Status:     gigahost.StatusReady,
			AssignedIP: "198.51.100.99",
		}, nil
	}

	adminSession := &models.SessionData{UserID: "admin", Role: models.RoleAdmin}
	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/deploy/ord_refresh_status", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}
	var res map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	deploy := res["deploy"].(map[string]any)
	if deploy["status"] != DeployStatusReady {
		t.Errorf("expected refreshed status 'ready', got: %v", deploy["status"])
	}
	if deploy["assigned_ip"] != "198.51.100.99" {
		t.Errorf("expected refreshed assigned IP 198.51.100.99, got: %v", deploy["assigned_ip"])
	}

	// 6. Non-existent order returns 404
	req404 := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/deploy/non_existent_ord", nil)
	req404 = req404.WithContext(middleware.WithSession(req404.Context(), adminSession))
	w404 := httptest.NewRecorder()
	r.ServeHTTP(w404, req404)
	if w404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent order, got %d", w404.Code)
	}

	// 7. Status handler missing order_id returns 400
	reqNoID := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/deploy/", nil)
	reqNoID = reqNoID.WithContext(middleware.WithSession(reqNoID.Context(), adminSession))
	wNoID := httptest.NewRecorder()
	r.ServeHTTP(wNoID, reqNoID)
	if wNoID.Code != http.StatusNotFound && wNoID.Code != http.StatusBadRequest {
		t.Errorf("expected 400 or 404 for empty order_id in status, got %d", wNoID.Code)
	}

	// 8. Deploy handler with invalid JSON payload returns 400
	reqBadJSON := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/deploy", bytes.NewReader([]byte("{invalid-json")))
	reqBadJSON = reqBadJSON.WithContext(middleware.WithSession(reqBadJSON.Context(), adminSession))
	wBadJSON := httptest.NewRecorder()
	r.ServeHTTP(wBadJSON, reqBadJSON)
	if wBadJSON.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", wBadJSON.Code)
	}
}

func TestGigahostDeploy_ValidationAndMatchHelpers(t *testing.T) {
	// 1. Validate empty OrderID
	r1 := GigahostDeployRequest{SSHPassword: "pass"}
	if err := r1.Validate(); err == nil || !strings.Contains(err.Error(), "order_id is required") {
		t.Errorf("expected order_id required error, got %v", err)
	}

	// 2. Validate missing credentials
	r2 := GigahostDeployRequest{OrderID: "ord_1"}
	if err := r2.Validate(); err == nil || !strings.Contains(err.Error(), "ssh_password or ssh_key is required") {
		t.Errorf("expected credentials required error, got %v", err)
	}

	// 3. Validate unsupported protocol
	r3 := GigahostDeployRequest{OrderID: "ord_1", SSHPassword: "pass", Protocol: "openvpn"}
	if err := r3.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported protocol") {
		t.Errorf("expected unsupported protocol error, got %v", err)
	}

	// 4. Default ports
	rAWG := GigahostDeployRequest{Protocol: "awg"}
	if rAWG.GetEffectivePort() != "51820" {
		t.Errorf("expected 51820 for awg default, got %s", rAWG.GetEffectivePort())
	}
	rVLESS := GigahostDeployRequest{Protocol: "vless"}
	if rVLESS.GetEffectivePort() != "443" {
		t.Errorf("expected 443 for vless default, got %s", rVLESS.GetEffectivePort())
	}

	// 5. matchProviderServerID helper
	if !matchProviderServerID(int64(123), 123) {
		t.Error("matchProviderServerID int64 failed")
	}
	if !matchProviderServerID(int(123), 123) {
		t.Error("matchProviderServerID int failed")
	}
	if !matchProviderServerID(float64(123), 123) {
		t.Error("matchProviderServerID float64 failed")
	}
	if !matchProviderServerID("123", 123) {
		t.Error("matchProviderServerID string failed")
	}
	if matchProviderServerID(nil, 123) {
		t.Error("matchProviderServerID nil should be false")
	}
	if matchProviderServerID("wrong", 123) {
		t.Error("matchProviderServerID wrong string should be false")
	}
}

func TestGigahostDeploy_FallbackResolveServerInfo(t *testing.T) {
	h, _, mockClient := setupDeployTestEnv(t)
	ctx := context.Background()

	// DeployStatus returns ErrNotFound, but GetServers finds the server
	mockClient.getDeployStatusFn = func(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
		return nil, gigahost.ErrNotFound
	}
	mockClient.getServersFn = func(ctx context.Context) ([]gigahost.ServerInfo, error) {
		return []gigahost.ServerInfo{
			{
				ID:      7701,
				OrderID: "ord_fallback_info",
				IPv4:    "198.51.100.77",
				Status:  "ready",
			},
		}, nil
	}

	req := GigahostDeployRequest{
		OrderID:     "ord_fallback_info",
		SSHPassword: "Password123!",
		Protocol:    "awg",
	}

	status, err := h.DeployGigahostOrder(ctx, req)
	if err != nil {
		t.Fatalf("expected fallback resolve to succeed, got: %v", err)
	}
	if status.AssignedIP != "198.51.100.77" {
		t.Errorf("expected assigned IP 198.51.100.77 from fallback, got %s", status.AssignedIP)
	}
	if status.ProviderServerID != 7701 {
		t.Errorf("expected provider server ID 7701 from fallback, got %d", status.ProviderServerID)
	}
}

func TestGigahostDeploy_DefaultSSHDialer(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	h.SetSSHDialerForTest(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := h.dialDeploySSH(ctx, ssh.Config{
		Host:    "127.0.0.1",
		Port:    59998,
		Timeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected dialDeploySSH with invalid port to fail, got nil")
	}
}
