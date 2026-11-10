package handlers

// PROVENANCE — auditor-corrected positive fixture (requirements consultation 11).
//
// Original (immutable, unmodified, still re-runnable):
//   tasks/issue-703/evidence/audit-round-7/audit_handler_proxy_test.go
//   sha256 092635da883c32b96ac8a7c6bad79f13e68fd2d1baf9af9271dfc6fd6cccd100
// Derivative (this file), per evidence/consult-11/fixture-provenance.json:
//   variant sha256 a08ad4df19fe935be4ab2ea48c815fbcd6b031828bf80c2c7eb23039b1fdbdf6
//
// What differs from the original is ONLY the missing positive qualification
// precondition: the original invoked the route and required HTTP 200 without ever
// supplying a successful application-qualification outcome, so it asserted the
// false-ready behaviour. This variant supplies that outcome at a clearly named
// mock boundary and additionally asserts the qualifier ran once, the durable
// marker is absent and the backend is selectable before reconstruction.
//
// The original HTTP 200 success assertion is kept intact, and the entire original
// recovery tail from new-pool construction is byte-identical, including startup
// reset, three protocol checks, the hook observation and the eligible==1
// assertion.
//
// PROOF BOUNDARY: provider/SSH/install and the traffic result are mocked. This
// reconstructs components against the existing DB handle — it is not a DB reopen,
// not Service.Start, and not an authentic packet exchange.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// TestAuditR7_RoutedProxyReadyCannotRecoverAfterRestart_QualifiedPrecondition is
// the provenance-labelled derivative of
// TestAuditR7_RoutedProxyReadyCannotRecoverAfterRestart. Renamed only to avoid
// colliding with the immutable original under overlay compilation.
func TestAuditR7_RoutedProxyReadyCannotRecoverAfterRestart_QualifiedPrecondition(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			h, r, _ := setupDeployTestEnv(t)
			trafficCalls := 0
			h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
				trafficCalls++
				return 15, nil
			})
			req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/audit-r7-proxy/setup", strings.NewReader(fmt.Sprintf(`{"ssh_password":"fixture-only","protocol":%q,"tls_domain":"proxy.example.com"}`, proto)))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != 200 {
				t.Fatalf("fixture deployment: HTTP%d %s", w.Code, w.Body.String())
			}
			backends, err := h.vpnSvc.GetBackends(context.Background())
			if err != nil || len(backends) != 1 {
				t.Fatalf("backends %d err=%v", len(backends), err)
			}
			sid := backends[0].ServerID
			defer func() { _ = h.vpnSvc.DisableBackend(context.Background(), sid) }()
			pending, err := h.db.GetBackendPendingEnrollments(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if trafficCalls != 1 {
				t.Fatalf("traffic qualification calls=%d want1", trafficCalls)
			}
			if pending[sid] {
				t.Fatal("route reported ready with durable quarantine still set")
			}
			if n := len(loadbalancer.FilterHealthy(backends, 0)); n != 1 {
				t.Fatalf("ready backend not selectable before restart: %d", n)
			}
			t.Logf("ROUTED DEPLOY proto=%s HTTP=%d durable_pending=%v response=%s", proto, w.Code, pending[sid], w.Body.String())
			pool := tunnel.NewPool(h.db)
			pool.SetMultiProtocolEnabled(true)
			hp := tunnel.NewHealthProber(pool, h.db, tunnel.DefaultHealthConfig())
			hp.SetMultiProtocolEnabled(true)
			hp.SetVLESSProbeFunc(func(context.Context, string, models.VLESSRealityParams, time.Duration) (int64, error) { return 15, nil })
			hp.SetNaiveProbeFunc(func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) { return 15, nil })
			attachCalls := 0
			hp.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { attachCalls++; return nil })
			if err = pool.SyncFromDB(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = pool.ResetEnabledHealthForStartup(context.Background()); err != nil {
				t.Fatal(err)
			}
			for sweep := 0; sweep < 3; sweep++ {
				if result := hp.ProbeAll(context.Background()); result[sid] != nil {
					t.Fatal(result[sid])
				}
			}
			current, err := pool.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			eligible := len(loadbalancer.FilterHealthy(pool.ListTunnels(), 0))
			t.Logf("RECOVERY proto=%s status=%s enabled=%v eligible=%d pending=%v attach_calls=%d", proto, current.Status, current.Enabled, eligible, hp.IsPendingEnrollment(sid), attachCalls)
			if eligible != 1 {
				t.Fatalf("portal reported ready but %s cannot recover eligibility after restart with successful protocol checks", proto)
			}
		})
	}
}
