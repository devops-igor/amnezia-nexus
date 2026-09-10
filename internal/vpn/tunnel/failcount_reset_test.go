package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// TestHealthProber_ResetFailCount verifies the issue #50 primitive: clearing a
// primed consecutive-failure counter restores the full FailureThreshold grace
// period. The behavioral contract is asserted in preference to inspecting the
// internal map: after a reset, one failed probe must leave the tunnel
// degraded (not disabled), and exactly FailureThreshold consecutive failures
// must disable it.
func TestHealthProber_ResetFailCount(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Reset FailCount", Host: "192.0.2.77"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sID, "192.0.2.77:51820", "pub-reset")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeShouldFail := true
	mockProbe := func(_ context.Context, _ string, _ string, _ string, _ string, _ string, _ uint32, _ uint32, _ int, _ int, _ time.Duration) (time.Duration, error) {
		if probeShouldFail {
			return 0, errors.New("simulated handshake timeout")
		}
		return 10 * time.Millisecond, nil
	}

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3
	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Prime the counter to threshold-1: two failures -> degraded.
	for i := 0; i < cfg.FailureThreshold-1; i++ {
		if _, err := prober.ProbeTunnel(ctx, tun); err == nil {
			t.Fatalf("priming failure %d: expected probe error", i+1)
		}
	}
	st, _ := pool.GetTunnel(sID)
	if st.Status != "degraded" {
		t.Fatalf("expected degraded after %d failures, got %q", cfg.FailureThreshold-1, st.Status)
	}
	prober.mu.RLock()
	primed := prober.failCounts[sID]
	prober.mu.RUnlock()
	if primed != cfg.FailureThreshold-1 {
		t.Fatalf("expected primed failCount=%d, got %d", cfg.FailureThreshold-1, primed)
	}

	// Reset mid-degradation: the very next single failure must NOT disable.
	prober.ResetFailCount(sID)
	prober.mu.RLock()
	afterReset := prober.failCounts[sID]
	prober.mu.RUnlock()
	if afterReset != 0 {
		t.Fatalf("expected failCount=0 after ResetFailCount, got %d", afterReset)
	}
	if _, err := prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe error after reset")
	}
	st, _ = pool.GetTunnel(sID)
	if st.Status != "degraded" {
		t.Fatalf("expected degraded after reset + 1 failure (grace restored), got %q", st.Status)
	}

	// Full grace semantics: exactly threshold-1 more failures until disabled.
	for i := 0; i < cfg.FailureThreshold-1; i++ {
		if _, err := prober.ProbeTunnel(ctx, tun); err == nil {
			t.Fatalf("post-reset failure %d: expected probe error", i+1)
		}
		st, _ = pool.GetTunnel(sID)
		want := "degraded"
		if i == cfg.FailureThreshold-2 {
			want = "disabled"
		}
		if st.Status != want {
			t.Fatalf("after reset + %d total failures: got %q, want %q", i+1, st.Status, want)
		}
	}

	// Nil-receiver safety: a nil prober makes ResetFailCount a no-op.
	var nilProber *HealthProber
	nilProber.ResetFailCount(sID)
}
