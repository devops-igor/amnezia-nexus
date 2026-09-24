package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestProbeTunnel_DeletedTunnelIsTerminal(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Deleted Probe Host", Host: "192.0.2.12"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, serverID, "192.0.2.12:51820", "pub-deleted")
	if err != nil {
		t.Fatal(err)
	}
	probes := 0
	prober := NewHealthProber(pool, db, DefaultHealthConfig(), func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		probes++
		if err := pool.RemoveTunnel(ctx, serverID); err != nil {
			return 0, err
		}
		return 15 * time.Millisecond, nil
	})
	hookCalls := 0
	prober.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error {
		hookCalls++
		return nil
	})
	if _, err := prober.ProbeTunnel(ctx, tun); !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("probe after concurrent deletion: got %v, want ErrTunnelNotFound", err)
	}
	if hookCalls != 0 {
		t.Fatalf("deleted tunnel's active hook ran %d times", hookCalls)
	}
	if _, err := prober.ProbeTunnel(ctx, tun); !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("probe of previously deleted tunnel: got %v, want ErrTunnelNotFound", err)
	}
	if probes != 1 {
		t.Fatalf("deleted tunnel was probed again: probes=%d", probes)
	}
}

// Pause after the last successful identity check. A new tunnel for the same
// server must not inherit either result of the old tunnel's probe.
func TestProbeTunnel_ReplacementAfterIdentityCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		probeErr error
	}{
		{name: "success"},
		{name: "failure", probeErr: errors.New("old tunnel probe timed out")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)
			pool := NewPool(db)
			serverID, err := db.CreateServer(ctx, &models.Server{Name: "Replacement Host", Host: "192.0.2.13"})
			if err != nil {
				t.Fatal(err)
			}
			old, err := pool.AddTunnel(ctx, serverID, "192.0.2.13:51820", "old-key")
			if err != nil {
				t.Fatal(err)
			}
			cfg := DefaultHealthConfig()
			cfg.FailureThreshold = 3
			prober := NewHealthProber(pool, db, cfg, func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
				return time.Second, tc.probeErr
			})
			// A failure from A would reach the disable threshold if it could
			// modify B's server-keyed counters.
			if tc.probeErr != nil {
				prober.mu.Lock()
				prober.failCounts[serverID] = 2
				prober.healthGenerations[serverID] = old.ID
				prober.mu.Unlock()
			}

			reached := make(chan struct{})
			resume := make(chan struct{})
			pause := func() { close(reached); <-resume }
			if tc.probeErr == nil {
				prober.preStatusCommitHook = pause
			} else {
				prober.preFailureCommitHook = pause
			}
			done := make(chan error, 1)
			go func() { _, err := prober.ProbeTunnel(ctx, old); done <- err }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				close(resume)
				t.Fatal("probe did not reach commit boundary")
			}
			if err := pool.RemoveTunnel(ctx, serverID); err != nil {
				close(resume)
				t.Fatal(err)
			}
			replacement, err := pool.AddTunnel(ctx, serverID, "192.0.2.13:51821", "new-key")
			if err != nil {
				close(resume)
				t.Fatal(err)
			}
			if replacement.ID == old.ID {
				close(resume)
				t.Fatal("replacement did not receive a new tunnel ID")
			}
			prober.ResetFailCount(serverID)
			before, err := pool.GetTunnel(serverID)
			if err != nil {
				close(resume)
				t.Fatal(err)
			}
			close(resume)
			select {
			case err := <-done:
				if !errors.Is(err, ErrTunnelNotFound) {
					t.Fatalf("old probe returned %v, want ErrTunnelNotFound", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("old probe did not finish")
			}
			after, err := pool.GetTunnel(serverID)
			if err != nil {
				t.Fatal(err)
			}
			if after.ID != before.ID || after.Status != before.Status || after.DisableReason != before.DisableReason ||
				after.StateVersion != before.StateVersion || after.LatencyMS != before.LatencyMS {
				t.Fatalf("replacement changed after stale probe: before=%+v after=%+v", before, after)
			}
			prober.mu.RLock()
			failures, gen, autoDisabled, successes := prober.failCounts[serverID], prober.healthGenerations[serverID], prober.autoDisabled[serverID], prober.successCounts[serverID]
			prober.mu.RUnlock()
			if failures != 0 || gen != replacement.ID || autoDisabled || successes != 0 {
				t.Fatalf("replacement health state contaminated: failures=%d gen=%d autoDisabled=%v successes=%d", failures, gen, autoDisabled, successes)
			}
		})
	}
}

func TestThresholdReconcile_RejectsReplacedTunnel(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Recreated Host", Host: "192.0.2.14"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := pool.AddTunnel(ctx, serverID, "192.0.2.14:51820", "old-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.RemoveTunnel(ctx, serverID); err != nil {
		t.Fatal(err)
	}
	replacement, err := pool.AddTunnel(ctx, serverID, "192.0.2.14:51821", "new-key")
	if err != nil {
		t.Fatal(err)
	}
	before := *replacement
	prober := NewHealthProber(pool, db, DefaultHealthConfig())
	prober.ResetFailCount(serverID)
	prober.mu.Lock()
	prober.failCounts[serverID] = prober.cfg.FailureThreshold
	prober.mu.Unlock()

	reconciled, err := prober.reconcileThresholdAutoDisable(ctx, serverID, old.ID)
	if reconciled || !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("stale reconciliation: reconciled=%v err=%v, want false, ErrTunnelNotFound", reconciled, err)
	}
	after, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID || after.Status != before.Status || after.DisableReason != before.DisableReason ||
		after.StateVersion != before.StateVersion || after.LatencyMS != before.LatencyMS || prober.IsAutoDisabled(serverID) {
		t.Fatalf("stale reconciliation changed replacement: before=%+v after=%+v", before, after)
	}
	prober.mu.RLock()
	count, generation := prober.failCounts[serverID], prober.healthGenerations[serverID]
	prober.mu.RUnlock()
	if count != prober.cfg.FailureThreshold || generation != replacement.ID {
		t.Fatalf("stale reconciliation changed replacement health state: count=%d generation=%d", count, generation)
	}
}

// TestProbeTunnel_DisabledTunnelNotResurrected verifies that ProbeTunnel never
// changes the status of an administratively disabled tunnel (issues #28/#43):
// a successful handshake probe must not write "active"/"degraded" over the
// admin-disabled state, and ProbeAll must skip disabled tunnels entirely.
func TestProbeTunnel_DisabledTunnelNotResurrected(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Disabled Host", Host: "192.0.2.10"})
	tun, err := pool.AddTunnel(ctx, s1ID, "192.0.2.10:51820", "pub-disabled")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeCalls := 0
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probeCalls++
		return 15 * time.Millisecond, nil
	}

	cfg := DefaultHealthConfig()
	prober := NewHealthProber(pool, db, cfg, mockProbe)

	hookCalls := 0
	prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		hookCalls++
		return nil
	})

	// Administratively disable the tunnel (as DisableBackend does).
	if err := pool.SetTunnelStatus(ctx, s1ID, "disabled", 0); err != nil {
		t.Fatalf("SetTunnelStatus(disabled) failed: %v", err)
	}

	// A successful probe of a disabled tunnel must be rejected up front.
	lat, err := prober.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatalf("expected ProbeTunnel to refuse probing a disabled tunnel, got lat=%d err=nil", lat)
	}
	if probeCalls != 0 {
		t.Errorf("expected probe function not to be called for disabled tunnel, got %d calls", probeCalls)
	}
	if hookCalls != 0 {
		t.Errorf("expected onActiveHook not to be called for disabled tunnel, got %d calls", hookCalls)
	}

	st, _ := pool.GetTunnel(s1ID)
	if st.Status != "disabled" {
		t.Errorf("disabled tunnel status was changed by probe: got %q, want %q", st.Status, "disabled")
	}

	// ProbeAll must skip the disabled tunnel entirely.
	results := prober.ProbeAll(ctx)
	if len(results) != 0 {
		t.Errorf("expected ProbeAll to skip disabled tunnel, got %d results", len(results))
	}
	if probeCalls != 0 {
		t.Errorf("expected probe function not to be called via ProbeAll for disabled tunnel, got %d calls", probeCalls)
	}
	st, _ = pool.GetTunnel(s1ID)
	if st.Status != "disabled" {
		t.Errorf("disabled tunnel status was changed by ProbeAll: got %q, want %q", st.Status, "disabled")
	}
}

// TestCheckAndReconnect_DoesNotResurrectDisabledTunnel verifies that the
// reconnect manager only considers "degraded"/"connecting" tunnels as
// candidates and never probes or reactivates an administratively disabled one.
func TestCheckAndReconnect_DoesNotResurrectDisabledTunnel(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Disabled Reconnect Host", Host: "192.0.2.11"})
	if _, err := pool.AddTunnel(ctx, s1ID, "192.0.2.11:51820", "pub-reconnect"); err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeCalls := 0
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probeCalls++
		return 15 * time.Millisecond, nil
	}

	hCfg := DefaultHealthConfig()
	prober := NewHealthProber(pool, db, hCfg, mockProbe)

	rCfg := ReconnectConfig{
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		Multiplier:     2.0,
		MaxRetries:     3,
		CheckInterval:  20 * time.Millisecond,
	}
	reconnectMgr := NewReconnectManager(pool, prober, rCfg)

	// Administratively disable the tunnel.
	if err := pool.SetTunnelStatus(ctx, s1ID, "disabled", 0); err != nil {
		t.Fatalf("SetTunnelStatus(disabled) failed: %v", err)
	}

	reconnected := reconnectMgr.CheckAndReconnect(ctx)
	if reconnected != 0 {
		t.Errorf("expected 0 reconnected for disabled tunnel, got %d", reconnected)
	}
	if probeCalls != 0 {
		t.Errorf("expected no probe attempts for disabled tunnel, got %d", probeCalls)
	}

	st, _ := pool.GetTunnel(s1ID)
	if st.Status != "disabled" {
		t.Errorf("reconnect manager resurrected disabled tunnel: got %q, want %q", st.Status, "disabled")
	}

	retries, _, _ := reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 0 {
		t.Errorf("expected no retry state to accumulate for disabled tunnel, got retries=%d", retries)
	}
}
