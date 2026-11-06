package tunnel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const releaseTestKey = "test-secret-key-1234567890123456"

// proxyParams returns protocol parameters that satisfy the tunnel's own
// validation for either proxy family.
func proxyParams(proto string) []byte {
	if proto == models.ProtocolVLESS {
		return []byte(`{"uuid":"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d","server_name":"proxy.example.com"}`)
	}
	return []byte(`{"username":"u","password":"p","domain":"proxy.example.com","port":443}`)
}

func newProxyFixture(t *testing.T, db *database.DB, proto string, host string) (*Pool, *HealthProber, int64, *models.BackendTunnel) {
	t.Helper()
	ctx := context.Background()
	pool := NewPool(db)
	pool.SetMultiProtocolEnabled(true)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "proxy " + proto, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnelWithConfig(context.WithValue(ctx, DeployEnrollmentKey, true), serverID, host+":443", "", BackendTunnelOptions{
		Protocol:       proto,
		ProtocolParams: proxyParams(proto),
	})
	if err != nil {
		t.Fatal(err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig())
	hp.SetMultiProtocolEnabled(true)
	// The health probe is a handshake/key-exchange check for both proxy
	// families; keep it successful so the ONLY question under test is which
	// probe releases the durable enrollment marker.
	hp.SetVLESSProbeFunc(func(context.Context, string, models.VLESSRealityParams, time.Duration) (int64, error) { return 15, nil })
	hp.SetNaiveProbeFunc(func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) { return 15, nil })
	hp.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { return nil })
	return pool, hp, serverID, tun
}

// Finding F10 / original work item 9: a proxy that has passed the explicit
// application-traffic qualification step must survive a real restart as an
// active, selectable backend.
//
// PROOF BOUNDARY (provenance): the traffic qualification, health outcome and
// device-attach callback are injected. This test establishes the COMPONENT
// LIFECYCLE with a real SQLite close/reopen and the real state machine. It does
// NOT prove an authenticated packet exchange and must not be cited as authentic
// traffic evidence (R12). The authentic request/reply coverage runs remotely:
// TestProbeVLESSTraffic_Success (real sing-vmess server) and
// TestCaddyIntegration_* (real Caddy + naive binary) in CI.
func TestQualifiedProxySurvivesRestartWithQualificationStep(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "qualified-proxy.db")

			db, err := database.Open(path, releaseTestKey)
			if err != nil {
				t.Fatal(err)
			}
			pool, hp, serverID, tun := newProxyFixture(t, db, proto, "192.0.2.80")

			pending, err := db.GetBackendPendingEnrollments(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !pending[serverID] {
				t.Fatal("fixture: enrollment marker was not written by pool enrollment")
			}

			// The protocol's own health check alone must NOT qualify.
			if _, err := hp.ProbeTunnel(ctx, tun); err != nil {
				t.Fatalf("health probe: %v", err)
			}
			current, err := pool.GetTunnel(serverID)
			if err != nil {
				t.Fatal(err)
			}
			pending, err = db.GetBackendPendingEnrollments(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !pending[serverID] {
				t.Fatal("handshake/key-exchange success released the durable enrollment marker")
			}
			if current.Status != models.TunnelStatusConnecting {
				t.Fatalf("handshake-only probe admitted the backend: status=%s", current.Status)
			}
			if n := len(pool.GetActiveTunnels()); n != 0 {
				t.Fatalf("handshake-only probe made the backend selectable: active=%d", n)
			}

			// Authentic application traffic qualification, then the atomic
			// promote+release that deployment performs. The traffic probe is a
			// distinct path from the health/handshake probe above; this fixture
			// only removes the real network dependency.
			trafficCalls := 0
			hp.SetProxyTrafficProbeFunc(func(context.Context, *models.BackendTunnel) (int64, error) {
				trafficCalls++
				return 12, nil
			})
			latencyMS, err := hp.QualifyProxyTraffic(ctx, current)
			if err != nil {
				t.Fatalf("application traffic qualification: %v", err)
			}
			if err := pool.PromoteTunnelWithEnrollmentRelease(ctx, serverID, current.ID, current.StateVersion, models.TunnelStatusActive, latencyMS); err != nil {
				t.Fatalf("promote+release: %v", err)
			}
			if trafficCalls != 1 {
				t.Fatalf("expected exactly one application traffic qualification, got %d", trafficCalls)
			}
			hp.SetPendingEnrollment(serverID, false)

			pending, err = db.GetBackendPendingEnrollments(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if pending[serverID] {
				t.Fatal("qualified backend kept its durable enrollment marker")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			// Real restart: new DB handle, new pool, new prober, startup reset.
			db2, err := database.Open(path, releaseTestKey)
			if err != nil {
				t.Fatal(err)
			}
			defer db2.Close()
			pool2 := NewPool(db2)
			pool2.SetMultiProtocolEnabled(true)
			hp2 := NewHealthProber(pool2, db2, DefaultHealthConfig())
			hp2.SetMultiProtocolEnabled(true)
			hp2.SetVLESSProbeFunc(func(context.Context, string, models.VLESSRealityParams, time.Duration) (int64, error) { return 15, nil })
			hp2.SetNaiveProbeFunc(func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) { return 15, nil })
			hp2.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { return nil })

			if err := pool2.SyncFromDB(ctx); err != nil {
				t.Fatal(err)
			}
			if err := pool2.ResetEnabledHealthForStartup(ctx); err != nil {
				t.Fatal(err)
			}
			for sweep := 0; sweep < 3; sweep++ {
				if result := hp2.ProbeAll(ctx); result[serverID] != nil {
					t.Fatalf("sweep %d: %v", sweep, result[serverID])
				}
			}

			after, err := pool2.GetTunnel(serverID)
			if err != nil {
				t.Fatal(err)
			}
			durable, err := db2.GetBackendTunnelByServerID(ctx, serverID)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("AFTER RESTART proto=%s status=%s durable=%s active=%d pending=%v",
				proto, after.Status, durable.Status, len(pool2.GetActiveTunnels()), hp2.IsPendingEnrollment(serverID))
			if after.Status != models.TunnelStatusActive {
				t.Fatalf("qualified %s backend did not recover after restart: status=%s", proto, after.Status)
			}
			if n := len(pool2.GetActiveTunnels()); n != 1 {
				t.Fatalf("qualified %s backend not selectable after restart: active=%d", proto, n)
			}
		})
	}
}

// TestProxyPromotionReleasesMarkerAtomically pins the durable write ordering:
// qualification and marker removal commit together, so no state exists where a
// qualified backend is still enrolled. Proof boundary: real pool/DB path; it does
// not simulate an arbitrary process crash or a commit-time fault injection.
func TestProxyPromotionReleasesMarkerAtomically(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)
			pool, hp, serverID, tun := newProxyFixture(t, db, proto, "192.0.2.81")

			// A refused promotion (stale generation) must leave the marker.
			if err := pool.PromoteTunnelWithEnrollmentRelease(ctx, serverID, tun.ID, tun.StateVersion+99, models.TunnelStatusActive, 5); err == nil {
				t.Fatal("expected stale-generation promotion to be refused")
			}
			pending, err := db.GetBackendPendingEnrollments(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !pending[serverID] {
				t.Fatal("refused promotion released the durable enrollment marker")
			}

			// A committed promotion releases it in the same transaction.
			if err := pool.PromoteTunnelWithEnrollmentRelease(ctx, serverID, tun.ID, tun.StateVersion, models.TunnelStatusActive, 5); err != nil {
				t.Fatalf("promotion: %v", err)
			}
			pending, err = db.GetBackendPendingEnrollments(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if pending[serverID] {
				t.Fatal("committed promotion left the durable enrollment marker")
			}
			current, err := pool.GetTunnel(serverID)
			if err != nil {
				t.Fatal(err)
			}
			if current.Status != models.TunnelStatusActive {
				t.Fatalf("expected active, got %s", current.Status)
			}
			_ = hp
		})
	}
}
