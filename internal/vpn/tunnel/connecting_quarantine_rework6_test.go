package tunnel

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
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

func testProbeSuccessHelper(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
	return 15 * time.Millisecond, nil
}

func TestPendingEnrollment_SurvivesRestartDurable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "quarantine-restart.db")
	const key = "test-secret-key-1234567890123456"
	db, err := database.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := db.CreateServer(ctx, &models.Server{Name: "Unqualified enrollment", Host: "192.0.2.50"})
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(db)
	enrollment := context.WithValue(ctx, DeployEnrollmentKey, true)
	tun, err := pool.AddTunnelWithConfig(enrollment, sid, "192.0.2.50:51820", "fixture-public-key", BackendTunnelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig(), testProbeSuccessHelper)
	hp.SetPendingEnrollment(sid, true)
	if _, err = hp.ProbeTunnel(enrollment, tun); err != nil {
		t.Fatal(err)
	}
	before, _ := pool.GetTunnel(sid)
	if before.Status != models.TunnelStatusConnecting {
		t.Fatal("fixture not quarantined")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	restarted := NewPool(db)
	if err = restarted.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err = restarted.ResetEnabledHealthForStartup(ctx); err != nil {
		t.Fatal(err)
	}
	hp2 := NewHealthProber(restarted, db, DefaultHealthConfig(), testProbeSuccessHelper)
	canaries := 0
	hp2.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		canaries++
		return errors.New("data forwarding unavailable")
	})
	results := hp2.ProbeAll(ctx)
	if results[sid] != nil {
		t.Fatal(results[sid])
	}
	after, _ := restarted.GetTunnel(sid)
	durable, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if !hp2.IsPendingEnrollment(sid) {
		t.Fatal("expected pending enrollment to survive restart")
	}
	if after.Status != models.TunnelStatusConnecting {
		t.Fatalf("expected quarantined status %s after restart, got %s", models.TunnelStatusConnecting, after.Status)
	}
	if durable.Status != models.TunnelStatusConnecting {
		t.Fatalf("expected durable status %s after restart, got %s", models.TunnelStatusConnecting, durable.Status)
	}
	if len(restarted.GetActiveTunnels()) != 0 {
		t.Fatalf("unqualified enrollment admitted after restart without a successful data canary")
	}
}

func TestPendingEnrollment_SurvivesProbeFailure(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "Pending qualification", Host: "192.0.2.51"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnelWithConfig(context.WithValue(ctx, DeployEnrollmentKey, true), sid, "192.0.2.51:51820", "fixture-key", BackendTunnelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig(), testProbeSuccessHelper)
	hp.SetPendingEnrollment(sid, true)
	hp.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("transient health UDP loss")
	})
	if _, err := hp.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("fixture probe must fail")
	}
	degraded, _ := pool.GetTunnel(sid)
	if degraded.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded after probe failure, got %s", degraded.Status)
	}
	hp.SetProbeFunc(testProbeSuccessHelper)
	if _, err := hp.ProbeTunnel(ctx, degraded); err != nil {
		t.Fatal(err)
	}
	current, _ := pool.GetTunnel(sid)
	if current.Status != models.TunnelStatusConnecting {
		t.Fatalf("expected quarantined status %s after subsequent probe success, got %s", models.TunnelStatusConnecting, current.Status)
	}
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatal("pending enrollment bypassed after normal failed/successful background probes")
	}
}
