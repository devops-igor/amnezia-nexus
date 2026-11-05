package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestProbeTunnel_ConnectingTunnelQuarantinedUntilCanary verifies that outer handshake success
// does not promote a connecting tunnel to active. It must remain in connecting status so it
// is never eligible in the load balancer pool before data-plane canary qualification.
func TestProbeTunnel_ConnectingTunnelQuarantinedUntilCanary(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Connecting Host", Host: "192.0.2.1"})
	tun, err := pool.AddTunnelWithConfig(context.WithValue(ctx, DeployEnrollmentKey, true), sID, "192.0.2.1:51820", "pub-conn", BackendTunnelOptions{})
	if err != nil {
		t.Fatalf("AddTunnelWithConfig failed: %v", err)
	}
	if tun.Status != models.TunnelStatusConnecting {
		t.Fatalf("expected initial status %q, got %q", models.TunnelStatusConnecting, tun.Status)
	}

	prober := NewHealthProber(pool, db, DefaultHealthConfig(), func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	})
	prober.SetPendingEnrollment(sID, true)
	if !prober.IsPendingEnrollment(sID) {
		t.Fatal("expected IsPendingEnrollment to report true")
	}
	if thresh := prober.LatencyThresholdMS(); thresh <= 0 {
		t.Fatalf("expected positive LatencyThresholdMS, got %d", thresh)
	}
	prober.SetSubnetProvider(func() string { return "10.200.0.0/16" })
	if got := prober.GetSubnetCIDR(); got != "10.200.0.0/16" {
		t.Fatalf("expected 10.200.0.0/16 from dynamic provider, got %s", got)
	}

	lat, err := prober.ProbeTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("ProbeTunnel failed: %v", err)
	}
	if lat != 15 {
		t.Fatalf("expected latency 15ms, got %d", lat)
	}

	afterProbe, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if afterProbe.Status != models.TunnelStatusConnecting {
		t.Fatalf("handshake-only probe must preserve connecting status until canary qualification; got status %q", afterProbe.Status)
	}
	if afterProbe.LatencyMS != 15 {
		t.Fatalf("expected latency 15ms recorded, got %d", afterProbe.LatencyMS)
	}

	// Also verify that ProbeAll does not promote connecting tunnels to active
	results := prober.ProbeAll(ctx)
	if results[sID] != nil {
		t.Fatalf("ProbeAll unexpected error for server %d: %v", sID, results[sID])
	}
	afterProbeAll, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if afterProbeAll.Status != models.TunnelStatusConnecting {
		t.Fatalf("ProbeAll must preserve connecting status until canary qualification; got status %q", afterProbeAll.Status)
	}
}
