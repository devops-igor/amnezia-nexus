package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestProbeTunnel_SetTunnelEndpoint_FencesInFlightSuccess verifies that:
//  1. A health probe starts against an old endpoint and measures latency.
//  2. An endpoint update occurs (via SetTunnelEndpoint), bumping StateVersion.
//  3. The probe completes its success path, but SetTunnelStatusIfCurrentWithVersion
//     rejects the update with ErrStaleStateVersion.
//  4. In-memory pool status and DB remain unchanged and unpolluted by the old probe.
func TestProbeTunnel_SetTunnelEndpoint_FencesInFlightSuccess(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Endpoint Fencing Server", Host: "198.51.100.30"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, serverID, "198.51.100.30:51820", "pubkey-fencing")
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultHealthConfig()
	cfg.LatencyThresholdMS = 200
	prober := NewHealthProber(pool, db, cfg, func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 300 * time.Millisecond, nil // measured latency > LatencyThresholdMS (would mark degraded)
	})

	reached := make(chan struct{})
	resume := make(chan struct{})
	prober.preStatusCommitHook = func() {
		close(reached)
		<-resume
	}

	done := make(chan error, 1)
	go func() {
		_, err := prober.ProbeTunnel(ctx, tun)
		done <- err
	}()

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		close(resume)
		t.Fatal("probe did not reach preStatusCommitHook")
	}

	// While probe is paused, endpoint is updated to a new host, advancing StateVersion to 2
	newEndpoint := "198.51.100.31:51820"
	if err := pool.SetTunnelEndpoint(ctx, tun.ID, newEndpoint); err != nil {
		close(resume)
		t.Fatal(err)
	}

	// Release probe
	close(resume)
	probeErr := <-done

	if !errors.Is(probeErr, ErrStaleStateVersion) {
		t.Errorf("expected ErrStaleStateVersion, got: %v", probeErr)
	}

	// Verify tunnel in pool was NOT marked degraded by the old probe
	curTun, err := pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if curTun.Status != "active" {
		t.Errorf("expected status 'active', got %q", curTun.Status)
	}
	if curTun.StateVersion != 2 {
		t.Errorf("expected StateVersion = 2, got %d", curTun.StateVersion)
	}
	if curTun.Endpoint != newEndpoint {
		t.Errorf("expected Endpoint = %q, got %q", newEndpoint, curTun.Endpoint)
	}
}
