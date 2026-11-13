package tunnel

// Failure-category isolation for the health prober (issue #794, group A).
//
// An outer-handshake failure streak and a data-plane ATTACHMENT failure are
// different observations about different things. This file pins that they cannot
// accumulate into one another: neither may complete the other's consecutive
// threshold, because the resulting status write withdraws routing eligibility
// and moves established sessions.
//
// Fixture scope: the outer handshake outcome is injected through the existing
// ProbeFunc seam and the data-plane hook through the existing OnActiveHook seam
// (which is exactly what Service wires to ensureBackendDeviceAttached). No probe
// or canary verdict is stubbed beyond that.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// mixedCategoryFixture is one enabled backend with an established session count
// and no attached data-plane device, so the active hook has real work to do and
// can fail the way an unattachable device fails in production.
type mixedCategoryFixture struct {
	prober *HealthProber
	pool   *Pool
	tun    *models.BackendTunnel
}

func newMixedCategoryFixture(t *testing.T, activeConns int) *mixedCategoryFixture {
	t.Helper()
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sid, err := db.CreateServer(ctx, &models.Server{Name: "category-isolation", Host: "192.0.2.201"})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sid, "192.0.2.201:51820", "category-pubkey")
	if err != nil {
		t.Fatalf("add tunnel: %v", err)
	}
	if activeConns > 0 {
		// An established, admitted session: this is the resource the
		// preservation contract protects.
		pool.IncrementConnections(tun.ID)
	}

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3
	hp := NewHealthProber(pool, db, cfg, func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	return &mixedCategoryFixture{prober: hp, pool: pool, tun: tun}
}

// setOuter installs the outer handshake outcome for subsequent probes.
func (f *mixedCategoryFixture) setOuter(fails bool) {
	f.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		if fails {
			return 0, errors.New("outer handshake dropped")
		}
		return 20 * time.Millisecond, nil
	})
}

// setHookFails installs a data-plane hook that fails the way an unattachable
// device does, or succeeds.
func (f *mixedCategoryFixture) setHookFails(fails bool) {
	f.prober.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error {
		if fails {
			return errors.New("data-plane attach failed: no device")
		}
		return nil
	})
}

// probe runs one real probe cycle against the live pool row and returns the row.
func (f *mixedCategoryFixture) probe(t *testing.T) *models.BackendTunnel {
	t.Helper()
	live, err := f.pool.GetTunnel(f.tun.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if _, err := f.prober.ProbeTunnel(t.Context(), live); err != nil {
		t.Logf("probe returned %v", err)
	}
	cur, err := f.pool.GetTunnel(f.tun.ServerID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	return cur
}

// TestHookFailureCannotInheritOuterFailureStreak is the reproduction and the
// contract: a long outer-handshake outage followed by ONE attachment failure
// must not withdraw the backend. The attachment failure is its own category and
// needs its own consecutive threshold.
func TestHookFailureCannotInheritOuterFailureStreak(t *testing.T) {
	f := newMixedCategoryFixture(t, 1)
	threshold := f.prober.Config().FailureThreshold

	// The outer handshake has been failing for the whole streak.
	f.setOuter(true)
	f.setHookFails(false)
	for i := 0; i < threshold-1; i++ {
		cur := f.probe(t)
		if cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("outer failure %d: status = %q, want handshake_blocked preserved for a session-carrying backend", i+1, cur.Status)
		}
	}

	// The outer handshake comes back, but the data plane cannot be attached: the
	// FIRST attachment failure must not complete the outer streak's threshold.
	f.setOuter(false)
	f.setHookFails(true)
	cur := f.probe(t)
	if cur.Status == models.TunnelStatusDisabled {
		t.Fatalf("one attachment failure after %d outer failures health-disabled the backend immediately (state_version %d); "+
			"unrelated failure categories must not accumulate", threshold-1, cur.StateVersion)
	}
	if !cur.Enabled {
		t.Fatal("attachment failure cleared administrative eligibility")
	}
}

// TestSustainedHookFailureStillWithdraws pins the other half of the contract:
// separating the categories must not make a genuinely unattachable backend
// immortal. Its OWN consecutive threshold still withdraws it.
func TestSustainedHookFailureStillWithdraws(t *testing.T) {
	f := newMixedCategoryFixture(t, 1)
	threshold := f.prober.Config().FailureThreshold

	f.setOuter(false)
	f.setHookFails(true)
	var cur *models.BackendTunnel
	// First threshold-1 attachment failures: no withdrawal yet.
	for i := 0; i < threshold-1; i++ {
		cur = f.probe(t)
		if cur.Status == models.TunnelStatusDisabled {
			t.Fatalf("attachment failure %d of %d disabled the backend below its own threshold", i+1, threshold)
		}
	}
	// The threshold-crossing failure must withdraw it.
	for i := 0; i < 2; i++ {
		cur = f.probe(t)
		if cur.Status == models.TunnelStatusDisabled {
			break
		}
	}
	if cur.Status != models.TunnelStatusDisabled || cur.DisableReason != models.DisableReasonHealth {
		t.Fatalf("sustained attachment failures never withdrew the backend: status=%q reason=%q", cur.Status, cur.DisableReason)
	}
	if !cur.Enabled {
		t.Fatal("health withdrawal must not clear administrative eligibility")
	}
}

// TestFailureCategoriesResetTogether pins the other half of category isolation:
// an administrative disable and an explicit reset must clear BOTH streaks, so a
// stale attachment-failure streak cannot later combine with fresh outer failures
// (or vice versa) to withdraw a backend that never reached a threshold in either
// category.
func TestFailureCategoriesResetTogether(t *testing.T) {
	t.Run("administrative disable clears the attachment streak", func(t *testing.T) {
		f := newMixedCategoryFixture(t, 1)
		threshold := f.prober.Config().FailureThreshold

		// Build an attachment-failure streak just below the threshold.
		f.setOuter(false)
		f.setHookFails(true)
		for i := 0; i < threshold-1; i++ {
			if cur := f.probe(t); cur.Status == models.TunnelStatusDisabled {
				t.Fatalf("attachment failure %d of %d disabled below threshold", i+1, threshold)
			}
		}
		if got := f.prober.hookFailures(f.tun.ServerID); got != threshold-1 {
			t.Fatalf("fixture: attachment streak = %d, want %d", got, threshold-1)
		}

		// The administrator disables and re-enables the backend.
		f.prober.MarkAdminDisabled(f.tun.ServerID)
		if got := f.prober.hookFailures(f.tun.ServerID); got != 0 {
			t.Fatalf("administrative disable left the attachment streak at %d, want 0", got)
		}
		if err := f.pool.SetTunnelEnabled(t.Context(), f.tun.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("administrative disable: %v", err)
		}
		if err := f.pool.SetTunnelEnabled(t.Context(), f.tun.ServerID, true, models.DisableReasonNone); err != nil {
			t.Fatalf("administrative re-enable: %v", err)
		}

		// A fresh attachment failure after re-enable must start a new streak, not
		// complete the pre-disable one.
		cur := f.probe(t)
		if cur.Status == models.TunnelStatusDisabled {
			t.Fatal("a fresh attachment failure completed the pre-disable streak after re-enable")
		}
	})

	t.Run("ResetFailCount clears the attachment streak", func(t *testing.T) {
		f := newMixedCategoryFixture(t, 1)
		threshold := f.prober.Config().FailureThreshold

		f.setOuter(false)
		f.setHookFails(true)
		for i := 0; i < threshold-1; i++ {
			f.probe(t)
		}
		f.prober.ResetFailCount(f.tun.ServerID)
		if got := f.prober.hookFailures(f.tun.ServerID); got != 0 {
			t.Fatalf("ResetFailCount left the attachment streak at %d, want 0", got)
		}
		if got := f.prober.GetFailCount(f.tun.ServerID); got != 0 {
			t.Fatalf("ResetFailCount left the outer streak at %d, want 0", got)
		}
	})
}

// TestOuterStreakCannotInheritHookFailures is the mirror direction: a
// consecutive attachment-failure streak must not let a single outer failure
// complete its threshold either.
func TestOuterStreakCannotInheritHookFailures(t *testing.T) {
	f := newMixedCategoryFixture(t, 1)
	threshold := f.prober.Config().FailureThreshold

	f.setOuter(false)
	f.setHookFails(true)
	for i := 0; i < threshold-1; i++ {
		if cur := f.probe(t); cur.Status == models.TunnelStatusDisabled {
			t.Fatalf("attachment failure %d of %d disabled the backend below threshold", i+1, threshold)
		}
	}

	// Now the outer handshake fails once. On its own that is below threshold.
	f.setOuter(true)
	f.setHookFails(false)
	cur := f.probe(t)
	if cur.Status == models.TunnelStatusDisabled {
		t.Fatal("one outer failure completed an attachment-failure streak's threshold")
	}
}
