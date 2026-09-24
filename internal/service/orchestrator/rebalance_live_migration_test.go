package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
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
