package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// Restored verbatim from round 9 (evidence/dev-round-9/false-ready-red.log):
// a proxy that has not passed traffic qualification must not be reported ready.
// Round 10 rewrote this oracle instead of satisfying it; that was a requirement
// relaxation and is reverted here.
func TestProxyDeploymentDoesNotReportReadyWithoutTrafficQualification(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			_, router, _ := setupDeployTestEnv(t)
			req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/proxy-unqualified/setup", strings.NewReader(fmt.Sprintf(`{"ssh_password":"fixture-only","protocol":%q,"tls_domain":"proxy.example.com"}`, proto)))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code == http.StatusOK {
				t.Fatalf("unqualified proxy reported ready: %s", response.Body.String())
			}
		})
	}
}

// A background probe firing during enable must not admit the proxy early.
func TestProxyDeploymentQuarantinedBeforeEnableCompletes(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			h, router, _ := setupDeployTestEnv(t)
			h.vpnSvc.SetProxyProbeFuncsForTest(
				func(context.Context, string, models.VLESSRealityParams, time.Duration) (int64, error) { return 1, nil },
				func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) { return 1, nil },
			)
			called := false
			h.vpnSvc.SetEnableBackendPostAddTunnelHookForTest(func() {
				called = true
				backends, err := h.vpnSvc.GetBackends(context.Background())
				if err != nil || len(backends) != 1 {
					t.Fatalf("get backend during enable: %v", err)
				}
				_, _ = h.vpnSvc.ProbeTunnel(context.Background(), backends[0])
				backends, err = h.vpnSvc.GetBackends(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if n := len(loadbalancer.FilterHealthy(backends, 0)); n != 0 {
					t.Fatalf("unqualified proxy eligible during enable: %d", n)
				}
			})
			req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/proxy-quarantine/setup", strings.NewReader(fmt.Sprintf(`{"ssh_password":"fixture-only","protocol":%q,"tls_domain":"proxy.example.com"}`, proto)))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			router.ServeHTTP(httptest.NewRecorder(), req)
			if !called {
				t.Fatal("did not reach proxy enable")
			}
		})
	}
}

// A proxy that HAS passed an authentic application traffic qualification must be
// admitted and durable-cleared before readiness is reported.
func TestProxyDeploymentQualifiedBackendBecomesSelectable(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			h, router, _ := setupDeployTestEnv(t)
			h.vpnSvc.SetProxyTrafficProbeFuncForTest(
				func(context.Context, *models.BackendTunnel) (int64, error) { return 5, nil },
			)

			req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/proxy-qualified/setup",
				strings.NewReader(fmt.Sprintf(`{"ssh_password":"fixture-only","protocol":%q,"tls_domain":"proxy.example.com"}`, proto)))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("qualified proxy deployment: HTTP%d %s", response.Code, response.Body.String())
			}

			backends, err := h.vpnSvc.GetBackends(context.Background())
			if err != nil || len(backends) != 1 {
				t.Fatalf("backends=%d err=%v", len(backends), err)
			}
			serverID := backends[0].ServerID
			defer func() { _ = h.vpnSvc.DisableBackend(context.Background(), serverID) }()

			pending, err := h.db.GetBackendPendingEnrollments(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if pending[serverID] {
				t.Fatal("app-level qualified proxy kept its durable enrollment quarantine")
			}
			if n := len(loadbalancer.FilterHealthy(backends, 0)); n != 1 {
				t.Fatalf("qualified %s backend not selectable: eligible=%d", proto, n)
			}
		})
	}
}

// A failed application qualification must be reported truthfully and must leave
// the backend durably quarantined and ineligible.
func TestProxyDeploymentFailedQualificationKeepsQuarantine(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			h, router, _ := setupDeployTestEnv(t)
			h.vpnSvc.SetProxyTrafficProbeFuncForTest(
				func(context.Context, *models.BackendTunnel) (int64, error) {
					return 0, fmt.Errorf("application exchange unavailable")
				},
			)

			req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/proxy-fail-qualify/setup",
				strings.NewReader(fmt.Sprintf(`{"ssh_password":"fixture-only","protocol":%q,"tls_domain":"proxy.example.com"}`, proto)))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code == http.StatusOK {
				t.Fatalf("failed qualification reported ready: %s", response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "application exchange unavailable") {
				t.Fatalf("failure diagnostics not propagated: %s", response.Body.String())
			}

			backends, err := h.vpnSvc.GetBackends(context.Background())
			if err != nil || len(backends) != 1 {
				t.Fatalf("backends=%d err=%v", len(backends), err)
			}
			serverID := backends[0].ServerID
			defer func() { _ = h.vpnSvc.DisableBackend(context.Background(), serverID) }()

			pending, err := h.db.GetBackendPendingEnrollments(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !pending[serverID] {
				t.Fatal("failed qualification released the durable enrollment quarantine")
			}
			if n := len(loadbalancer.FilterHealthy(backends, 0)); n != 0 {
				t.Fatalf("failed-qualification %s proxy became eligible: %d", proto, n)
			}
		})
	}
}

// TestProxyReplacementAfterFailedDeploymentDoesNotInheritQuarantine pins the
// reinstall/replacement boundary (group B): when a backend is replaced on the
// same server, the failure of the FIRST deployment must not quarantine the
// replacement, while a genuinely unqualified replacement stays gated.
func TestProxyReplacementAfterFailedDeploymentDoesNotInheritQuarantine(t *testing.T) {
	h, router, _ := setupDeployTestEnv(t)
	h.vpnSvc.SetProxyTrafficProbeFuncForTest(
		func(context.Context, *models.BackendTunnel) (int64, error) {
			return 0, fmt.Errorf("first deployment application exchange unavailable")
		},
	)

	req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/proxy-replace/setup",
		strings.NewReader(fmt.Sprintf(`{"ssh_password":"fixture-only","protocol":%q,"tls_domain":"proxy.example.com"}`, models.ProtocolVLESS)))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code == http.StatusOK {
		t.Fatalf("failed first deployment reported ready: %s", response.Body.String())
	}

	backends, err := h.vpnSvc.GetBackends(context.Background())
	if err != nil || len(backends) != 1 {
		t.Fatalf("backends=%d err=%v", len(backends), err)
	}
	serverID := backends[0].ServerID
	t.Cleanup(func() { _ = h.vpnSvc.DisableBackend(context.Background(), serverID) })

	pending, err := h.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !pending[serverID] {
		t.Fatal("failed deployment released its own durable quarantine")
	}

	// Replace the backend on the same server: the retired tunnel's quarantine must
	// not survive into the replacement.
	if err := h.vpnSvc.DeleteBackend(context.Background(), serverID); err != nil {
		t.Fatalf("delete backend: %v", err)
	}
	if err := h.vpnSvc.EnableBackend(context.Background(), serverID); err != nil {
		t.Fatalf("re-enable replacement: %v", err)
	}
	after, err := h.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after[serverID] {
		t.Fatal("the replacement inherited the retired deployment's durable quarantine")
	}
	// The runtime owner must agree with the durable one: a stale in-memory marker
	// would keep the replacement non-routable until a process restart even though
	// the store is clean.
	cur, err := h.vpnSvc.GetTunnel(serverID)
	if err != nil || cur == nil {
		t.Fatalf("read replacement tunnel: %v", err)
	}
	if !cur.Enabled {
		t.Fatal("replacement is not administratively enabled")
	}
}
