package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// TestAuditR5_NoEligibilityBeforeCanarySuccess reproduces and verifies the fix for Finding F8:
// Outer handshake success alone must NOT admit the backend as active in the load balancer pool.
// The backend must remain connecting (eligible=0) throughout canary qualification.
func TestAuditR5_NoEligibilityBeforeCanarySuccess(t *testing.T) {
	h, r, provider := setupDeployTestEnv(t)
	_, pub, host, port := rework5HandshakeOnlyServer(t, health.DefaultH1, health.DefaultH2, health.DefaultS1, health.DefaultS2)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{ServerID: 9011, Status: gigahost.StatusReady, AssignedIP: host}, nil
	}
	h.registry.Register(&mockProtocolManager{protocol: models.ProtocolAWG, installFn: func(_ context.Context, s *models.Server, _ map[string]any) error {
		s.Protocols["awg"] = map[string]any{
			"port":       strconv.Itoa(port),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"awg_params": map[string]any{
				"H1": strconv.FormatUint(uint64(health.DefaultH1), 10),
				"H2": strconv.FormatUint(uint64(health.DefaultH2), 10),
				"S1": strconv.Itoa(health.DefaultS1),
				"S2": strconv.Itoa(health.DefaultS2),
			},
		}
		return nil
	}})
	h.vpnSvc.SetProbeFunc(health.ProbeAWGEndpointRange)
	eligibleDuring := -1
	h.vpnSvc.SetCanaryProbeFunc(func(ctx context.Context, tun *models.BackendTunnel) error {
		backends, err := h.vpnSvc.GetBackends(ctx)
		if err != nil {
			return err
		}
		eligibleDuring = len(loadbalancer.FilterHealthy(backends, 0))
		current, err := h.vpnSvc.GetTunnel(tun.ServerID)
		if err != nil {
			return err
		}
		t.Logf("CANARY NOT YET SUCCEEDED: eligible=%d enabled=%v status=%s", eligibleDuring, current.Enabled, current.Status)
		return errors.New("fixture: data forwarding blackholed")
	})
	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/audit-r5-admission/setup", strings.NewReader(`{"ssh_password":"fixture-only"}`))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("FINAL: HTTP=%d eligible=%d", w.Code, len(loadbalancer.FilterHealthy(backends, 0)))
	if eligibleDuring != 0 {
		t.Fatalf("backend selectable before any successful data-plane canary: eligible=%d", eligibleDuring)
	}
}

// TestRework6_CanarySuccessPromotesConnectingToActive asserts that once the canary probe succeeds,
// the backend transitions from connecting to active and becomes eligible in the pool.
func TestRework6_CanarySuccessPromotesConnectingToActive(t *testing.T) {
	h, r, provider := setupDeployTestEnv(t)
	_, pub, host, port := rework5HandshakeOnlyServer(t, health.DefaultH1, health.DefaultH2, health.DefaultS1, health.DefaultS2)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{ServerID: 9012, Status: gigahost.StatusReady, AssignedIP: host}, nil
	}
	h.registry.Register(&mockProtocolManager{protocol: models.ProtocolAWG, installFn: func(_ context.Context, s *models.Server, _ map[string]any) error {
		s.Protocols["awg"] = map[string]any{
			"port":       strconv.Itoa(port),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"awg_params": map[string]any{
				"H1": strconv.FormatUint(uint64(health.DefaultH1), 10),
				"H2": strconv.FormatUint(uint64(health.DefaultH2), 10),
				"S1": strconv.Itoa(health.DefaultS1),
				"S2": strconv.Itoa(health.DefaultS2),
			},
		}
		return nil
	}})
	h.vpnSvc.SetProbeFunc(health.ProbeAWGEndpointRange)
	canaryInvoked := false
	h.vpnSvc.SetCanaryProbeFunc(func(ctx context.Context, tun *models.BackendTunnel) error {
		canaryInvoked = true
		backends, err := h.vpnSvc.GetBackends(ctx)
		if err != nil {
			return err
		}
		if eligible := len(loadbalancer.FilterHealthy(backends, 0)); eligible != 0 {
			t.Fatalf("expected eligible=0 during canary, got %d", eligible)
		}
		return nil
	})
	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/rework6-promote-active/setup", strings.NewReader(`{"ssh_password":"fixture-only"}`))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}
	if !canaryInvoked {
		t.Fatal("expected canary probe to be invoked")
	}
	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if eligible := len(loadbalancer.FilterHealthy(backends, 0)); eligible != 1 {
		t.Fatalf("expected eligible=1 after canary success, got %d", eligible)
	}
}

// TestRework6_BackgroundProbeCollisionDuringCanaryDoesNotAdmit verifies the regression oracle:
// If a background probe (ProbeTunnel or ProbeAll) executes while canary qualification is in-flight,
// the pending-enrollment guard prevents outer handshake success from committing active, keeping eligible=0.
func TestRework6_BackgroundProbeCollisionDuringCanaryDoesNotAdmit(t *testing.T) {
	h, r, provider := setupDeployTestEnv(t)
	_, pub, host, port := rework5HandshakeOnlyServer(t, health.DefaultH1, health.DefaultH2, health.DefaultS1, health.DefaultS2)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{ServerID: 9013, Status: gigahost.StatusReady, AssignedIP: host}, nil
	}
	h.registry.Register(&mockProtocolManager{protocol: models.ProtocolAWG, installFn: func(_ context.Context, s *models.Server, _ map[string]any) error {
		s.Protocols["awg"] = map[string]any{
			"port":       strconv.Itoa(port),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"awg_params": map[string]any{
				"H1": strconv.FormatUint(uint64(health.DefaultH1), 10),
				"H2": strconv.FormatUint(uint64(health.DefaultH2), 10),
				"S1": strconv.Itoa(health.DefaultS1),
				"S2": strconv.Itoa(health.DefaultS2),
			},
		}
		return nil
	}})
	h.vpnSvc.SetProbeFunc(health.ProbeAWGEndpointRange)
	collisionEligible := -1
	h.vpnSvc.SetCanaryProbeFunc(func(ctx context.Context, tun *models.BackendTunnel) error {
		// Simulate concurrent background ProbeTunnel while canary is in-flight
		_, _ = h.vpnSvc.ProbeTunnel(context.Background(), tun)

		backends, err := h.vpnSvc.GetBackends(ctx)
		if err != nil {
			return err
		}
		collisionEligible = len(loadbalancer.FilterHealthy(backends, 0))
		return errors.New("fixture: data forwarding blackholed")
	})
	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/rework6-collision/setup", strings.NewReader(`{"ssh_password":"fixture-only"}`))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if collisionEligible != 0 {
		t.Fatalf("background probe collision admitted connecting backend prematurely: eligible=%d", collisionEligible)
	}
	if w.Code != 502 {
		t.Fatalf("expected HTTP 502, got %d", w.Code)
	}
}
