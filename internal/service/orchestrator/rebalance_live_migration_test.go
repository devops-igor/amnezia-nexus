package orchestrator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type mockSessionMigrator struct {
	mu         sync.Mutex
	migrations []struct {
		sessionID      string
		targetTunnelID int64
	}
	failSessionID string
	failErr       error
}

func (m *mockSessionMigrator) MigrateSession(ctx context.Context, sessionID string, targetTunnelID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failSessionID != "" && m.failSessionID == sessionID {
		if m.failErr != nil {
			return m.failErr
		}
		return errors.New("simulated migration failure")
	}

	m.migrations = append(m.migrations, struct {
		sessionID      string
		targetTunnelID int64
	}{
		sessionID:      sessionID,
		targetTunnelID: targetTunnelID,
	})
	return nil
}

func (m *mockSessionMigrator) getMigrations() []struct {
	sessionID      string
	targetTunnelID int64
} {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]struct {
		sessionID      string
		targetTunnelID int64
	}, len(m.migrations))
	copy(res, m.migrations)
	return res
}

// TestRebalanceVPNSessionsWithSessionMigrator verifies that RebalanceVPNSessions delegates
// session moves to the configured SessionMigrator (issue #289).
func TestRebalanceVPNSessionsWithSessionMigrator(t *testing.T) {
	f := setupRebalanceFixture(t)
	// Seed 9 sessions on t1 and 1 on t2 (total 10, average = 5.0, threshold = max(1, int(5.0*1.4)) = 7).
	// Excess on t1: 9 - 7 = 2 sessions to drain.
	for i := 1; i <= 9; i++ {
		f.session(t, fmtSessionID(i), f.t1, "connected")
	}
	f.session(t, fmtSessionID(10), f.t2, "connected")

	migrator := &mockSessionMigrator{}
	orch := New(f.db, nil, WithSessionMigrator(migrator))

	ctx := context.Background()
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	migrations := migrator.getMigrations()
	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(migrations))
	}

	for _, m := range migrations {
		if m.targetTunnelID != f.t2 {
			t.Errorf("migration target tunnel = %d, want %d (t2)", m.targetTunnelID, f.t2)
		}
	}
}

// TestRebalanceVPNSessionsSessionMigratorFailure verifies that a failing SessionMigrator
// is logged and skipped gracefully without failing the entire rebalance pass (issue #289).
func TestRebalanceVPNSessionsSessionMigratorFailure(t *testing.T) {
	f := setupRebalanceFixture(t)
	// Seed 9 sessions on t1 and 1 on t2. Excess is 2 sessions to drain.
	for i := 1; i <= 9; i++ {
		f.session(t, fmtSessionID(i), f.t1, "connected")
	}
	f.session(t, fmtSessionID(10), f.t2, "connected")

	migrator := &mockSessionMigrator{
		failSessionID: fmtSessionID(1),
		failErr:       errors.New("db disconnect during live migration"),
	}
	orch := New(f.db, nil)
	orch.SetSessionMigrator(migrator)

	ctx := context.Background()
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions should not return error on individual session migration failure: %v", err)
	}

	migrations := migrator.getMigrations()
	// Since session 1 failed, next session(s) should be processed until excess is met or list exhausted
	if len(migrations) == 0 {
		t.Fatalf("expected subsequent session to be migrated after session 1 failure")
	}
}

// TestRebalanceVPNSessionsFallbackWhenMigratorNil verifies backwards-compatible DB-only
// update behavior when no SessionMigrator is configured (issue #289).
func TestRebalanceVPNSessionsFallbackWhenMigratorNil(t *testing.T) {
	f := setupRebalanceFixture(t)
	for i := 1; i <= 9; i++ {
		f.session(t, fmtSessionID(i), f.t1, "connected")
	}
	f.session(t, fmtSessionID(10), f.t2, "connected")

	orch := New(f.db, nil) // no SessionMigrator configured

	ctx := context.Background()
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	all := f.allSessions(t)
	drainingCount := 0
	for _, s := range all {
		if s.Status == "draining" {
			drainingCount++
			if s.BackendTunnelID != f.t2 {
				t.Errorf("session %s backend = %d, want %d", s.ID, s.BackendTunnelID, f.t2)
			}
		}
	}
	if drainingCount != 2 {
		t.Fatalf("expected 2 draining sessions after fallback rebalance, got %d", drainingCount)
	}
}

func fmtSessionID(i int) string {
	return "sess-rebalance-" + string(rune('a'+i-1))
}

// TestCheckBackendTunnelHealth_UsesSessionMigrator verifies that CheckBackendTunnelHealth
// delegates degraded tunnel session migration to SessionMigrator (issue #289).
func TestCheckBackendTunnelHealth_UsesSessionMigrator(t *testing.T) {
	f := setupRebalanceFixture(t)
	// Seed session on t1
	f.session(t, "sess-health-mig-1", f.t1, "connected")

	migrator := &mockSessionMigrator{}
	orch := New(f.db, nil,
		WithSessionMigrator(migrator),
		WithProbeFailureThreshold(1),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			// Fail probe for t1 endpoint (55430)
			if strings.Contains(endpoint, "55430") {
				return 0, errors.New("simulated probe failure on t1")
			}
			return 10 * time.Millisecond, nil
		}),
	)

	ctx := context.Background()
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	migrations := migrator.getMigrations()
	if len(migrations) != 1 {
		t.Fatalf("expected 1 migration via SessionMigrator, got %d", len(migrations))
	}

	if migrations[0].sessionID != "sess-health-mig-1" {
		t.Errorf("migration session ID = %s, want sess-health-mig-1", migrations[0].sessionID)
	}
	if migrations[0].targetTunnelID != f.t2 {
		t.Errorf("migration target tunnel = %d, want %d (t2)", migrations[0].targetTunnelID, f.t2)
	}
}

// A target may be disabled after its probe succeeded but before migration starts.
func TestMigrateDegradedTunnelSessions_SkipsDisabledHealthySnapshot(t *testing.T) {
	for _, withMigrator := range []bool{false, true} {
		name := "database fallback"
		if withMigrator {
			name = "live migrator"
		}
		t.Run(name, func(t *testing.T) {
			f := setupRebalanceFixture(t)
			ctx := context.Background()
			f.session(t, "stale-target-session", f.t1, "connected")
			stale, err := f.db.GetBackendTunnel(ctx, f.t2)
			if err != nil || stale == nil {
				t.Fatalf("GetBackendTunnel failed: %v", err)
			}
			if err := f.db.UpdateBackendTunnelStatusWithReason(ctx, f.t2, "disabled", models.DisableReasonAdmin, 0); err != nil {
				t.Fatalf("disable target: %v", err)
			}

			migrator := &mockSessionMigrator{}
			orch := New(f.db, nil)
			if withMigrator {
				orch.SetSessionMigrator(migrator)
			}
			orch.migrateDegradedTunnelSessions(ctx, []int64{f.t1}, []*models.BackendTunnel{stale})

			session, err := f.db.GetVPNSessionByID(ctx, "stale-target-session")
			if err != nil || session == nil {
				t.Fatalf("GetVPNSessionByID failed: %v", err)
			}
			if session.BackendTunnelID != f.t1 || session.Status != "connected" {
				t.Fatalf("session moved to disabled tunnel: %+v", session)
			}
			if got := migrator.getMigrations(); len(got) != 0 {
				t.Fatalf("migrator called with disabled target: %+v", got)
			}
		})
	}
}

func TestMigrateDegradedTunnelSessions_UsesNextActiveTarget(t *testing.T) {
	f := setupRebalanceFixture(t)
	ctx := context.Background()
	f.session(t, "next-target-session", f.t1, "connected")
	stale, err := f.db.GetBackendTunnel(ctx, f.t2)
	if err != nil || stale == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	source, err := f.db.GetBackendTunnel(ctx, f.t1)
	if err != nil || source == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	thirdID, err := f.db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: source.ServerID, InterfaceName: "awg-extra", PublicKey: "reb-pub3", Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}
	active, err := f.db.GetBackendTunnel(ctx, thirdID)
	if err != nil || active == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if err := f.db.UpdateBackendTunnelStatusWithReason(ctx, f.t2, "disabled", models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("disable target: %v", err)
	}

	migrator := &mockSessionMigrator{}
	orch := New(f.db, nil, WithSessionMigrator(migrator))
	orch.migrateDegradedTunnelSessions(ctx, []int64{f.t1}, []*models.BackendTunnel{stale, active})
	got := migrator.getMigrations()
	if len(got) != 1 || got[0].targetTunnelID != thirdID || got[0].sessionID != "next-target-session" {
		t.Fatalf("migration did not skip disabled candidate: %+v", got)
	}
}
