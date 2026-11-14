package tunnel

// PROVENANCE — auditor-corrected positive fixture (requirements consultation 11).
//
// Original (immutable, unmodified, still re-runnable):
//   tasks/issue-703/evidence/audit-round-7/audit_proxy_test.go
//   sha256 ca2b934b8382496f7983209e9cc4d25a410cfa24b78bc123660d00f8758c8fbe
// Derivative (this file), per evidence/consult-11/fixture-provenance.json:
//   variant sha256 a5af29e31b3dbcf3a96219f9b4e29cece7d14be8fdaadbd34f069e364baa5160
//
// What differs from the original is ONLY the missing positive qualification
// precondition: the original went straight from AddTunnelWithConfig to a single
// protocol-result probe and required active-before-restart, which asserts
// handshake-only admission. This variant keeps the deploy marker pending, proves
// an ordinary probe success does NOT admit it, then exercises the real
// application-traffic qualification boundary plus the atomic promote/release.
//
// The entire original restart/recovery tail is byte-identical, including the real
// SQLite close/reopen, new pool/prober, startup reset, three sweeps, durable read
// and the original final active/selectability assertion. Ordinary non-deploy
// controls are unchanged.
//
// PROOF BOUNDARY: the traffic qualification, health outcome and attach callback
// are injected. This is component lifecycle evidence with a real SQLite reopen —
// NOT authentic packet exchange, and NOT an OS-process restart.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAuditR7_QualifiedProxySurvivesRestart_QualifiedPrecondition is the
// provenance-labelled derivative of TestAuditR7_QualifiedProxySurvivesRestart.
// Renamed only to avoid colliding with the immutable original when that file is
// compiled via overlay; every assertion is preserved.
func TestAuditR7_QualifiedProxySurvivesRestart_QualifiedPrecondition(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		for _, deploy := range []bool{false, true} {
			name := proto + "/ordinary"
			if deploy {
				name = proto + "/gigahost"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				path := filepath.Join(t.TempDir(), "proxy.db")
				const key = "test-secret-key-1234567890123456"
				db, err := database.Open(path, key)
				if err != nil {
					t.Fatal(err)
				}
				sid, err := db.CreateServer(ctx, &models.Server{Name: "Qualified proxy", Host: "192.0.2.52"})
				if err != nil {
					t.Fatal(err)
				}
				pool := NewPool(db)
				pool.SetMultiProtocolEnabled(true)
				// Production constructs hp before the administrator enrolls a VPS.
				hp := NewHealthProber(pool, db, DefaultHealthConfig())
				configure := func(h *HealthProber) {
					h.SetMultiProtocolEnabled(true)
					h.SetVLESSProbeFunc(func(context.Context, string, models.VLESSRealityParams, time.Duration) (int64, error) { return 15, nil })
					h.SetNaiveProbeFunc(func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) { return 15, nil })
					h.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { return nil })
				}
				configure(hp)
				enrollCtx := ctx
				if deploy {
					enrollCtx = context.WithValue(ctx, DeployEnrollmentKey, true)
					hp.SetPendingEnrollment(sid, true)
				}
				params := json.RawMessage(`{"uuid":"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d","port":443,"username":"fixture","password":"fixture","domain":"proxy.example.com"}`)
				tun, err := pool.AddTunnelWithConfig(enrollCtx, sid, "192.0.2.52:443", "", BackendTunnelOptions{Protocol: proto, ProtocolParams: params})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = hp.ProbeTunnel(ctx, tun); err != nil {
					t.Fatal(err)
				}
				if deploy {
					unqualified, err := pool.GetTunnel(sid)
					if err != nil {
						t.Fatal(err)
					}
					if unqualified.Status != models.TunnelStatusConnecting || len(pool.GetActiveTunnels()) != 0 {
						t.Fatal("handshake alone admitted pending enrollment")
					}
					trafficCalls := 0
					hp.SetProxyTrafficProbeFunc(func(context.Context, *models.BackendTunnel) (int64, error) {
						trafficCalls++
						return 15, nil
					})
					latency, err := hp.QualifyProxyTraffic(ctx, unqualified)
					if err != nil {
						t.Fatal(err)
					}
					if trafficCalls != 1 {
						t.Fatal("fixture did not invoke application-traffic qualification boundary")
					}
					if err = pool.PromoteTunnelWithEnrollmentRelease(ctx, sid, unqualified.ID, unqualified.StateVersion, models.TunnelStatusActive, latency); err != nil {
						t.Fatal(err)
					}
					hp.SetPendingEnrollment(sid, false)
					pending, err := db.GetBackendPendingEnrollments(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if pending[sid] {
						t.Fatal("qualified enrollment marker not cleared")
					}
				}
				before, _ := pool.GetTunnel(sid)
				pending, err := db.GetBackendPendingEnrollments(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("BEFORE RESTART proto=%s deploy=%v status=%s active=%d memory_pending=%v durable_pending=%v", proto, deploy, before.Status, len(pool.GetActiveTunnels()), hp.IsPendingEnrollment(sid), pending[sid])
				if before.Status != models.TunnelStatusActive {
					t.Fatal("fixture must be healthy before restart")
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
				db, err = database.Open(path, key)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				pool2 := NewPool(db)
				pool2.SetMultiProtocolEnabled(true)
				hp2 := NewHealthProber(pool2, db, DefaultHealthConfig())
				configure(hp2)
				if err = pool2.SyncFromDB(ctx); err != nil {
					t.Fatal(err)
				}
				if err = pool2.ResetEnabledHealthForStartup(ctx); err != nil {
					t.Fatal(err)
				}
				for sweep := 0; sweep < 3; sweep++ {
					if result := hp2.ProbeAll(ctx); result[sid] != nil {
						t.Fatal(result[sid])
					}
				}
				after, _ := pool2.GetTunnel(sid)
				durable, err := db.GetBackendTunnelByServerID(ctx, sid)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("AFTER RESTART proto=%s deploy=%v status=%s durable=%s active=%d pending=%v; three successful protocol sweeps", proto, deploy, after.Status, durable.Status, len(pool2.GetActiveTunnels()), hp2.IsPendingEnrollment(sid))
				if after.Status != models.TunnelStatusActive || len(pool2.GetActiveTunnels()) != 1 {
					t.Fatalf("previously healthy %s backend remains unselectable after restart despite successful protocol checks", proto)
				}
			})
		}
	}
}
