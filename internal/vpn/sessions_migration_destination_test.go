package vpn

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func disableHealthSource(t *testing.T, f *failoverFixture) *models.BackendTunnel {
	t.Helper()
	if err := f.svc.pool.SetTunnelStatusWithReason(t.Context(), f.source.ServerID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	source, err := f.svc.pool.GetTunnelByID(f.source.ID)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func assertMigrationPlacement(t *testing.T, f *failoverFixture, want *models.BackendTunnel) {
	t.Helper()
	row, err := f.svc.db.GetVPNSessionByID(t.Context(), f.sess.ID)
	if err != nil || row == nil || row.BackendTunnelID != want.ID || row.Status != "connected" {
		t.Errorf("durable placement: row=%+v error=%v, want %d", row, err, want.ID)
	}
	live, ok := f.svc.sessionMgr.GetSessionSnapshotByID(f.sess.ID)
	if !ok || live.BackendTunnelID != want.ID || live.Status != "connected" {
		t.Errorf("session placement: %+v/%t, want %d", live, ok, want.ID)
	}
	affinity, ok := f.svc.stickyMgr.GetPeerAffinity(f.peer.peerKey)
	if !ok || affinity != want.ID {
		t.Errorf("affinity=%d/%t, want %d", affinity, ok, want.ID)
	}
	f.assertRoutedTo(t, want, f.source, f.first, f.second)
	for _, candidate := range []*models.BackendTunnel{f.source, f.first, f.second} {
		live, err := f.svc.pool.GetTunnelByID(candidate.ID)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		if candidate.ID == want.ID {
			count = 1
		}
		if live.ActiveConnections != count {
			t.Errorf("backend %d counter=%d, want %d", candidate.ID, live.ActiveConnections, count)
		}
	}
}

func TestHealthFailoverCommitsEligibleAlternative(t *testing.T) {
	for _, mode := range []string{"unmarked", "earlier_mark", "late_mark", "retry_late_mark", "exhausted"} {
		t.Run(mode, func(t *testing.T) {
			f := newFailoverFixture(t)
			source := disableHealthSource(t, f)
			defer f.svc.clearHealthFailoverDebt(source.ID)
			if mode == "earlier_mark" {
				f.markAbsent(t, f.first)
			}
			if mode == "late_mark" || mode == "retry_late_mark" || mode == "exhausted" {
				f.svc.SetPreCommitMigrationHookForTest(func() {
					f.markAbsent(t, f.first)
					if mode == "exhausted" {
						f.markAbsent(t, f.second)
					}
					f.assertRoutedTo(t, f.source, f.first, f.second)
				})
			}
			if mode == "retry_late_mark" {
				f.svc.recordHealthFailoverDebt(source)
				if got := f.svc.RetryPendingHealthFailovers(t.Context()); got != 1 {
					t.Errorf("settled debt=%d, want 1", got)
				}
			} else if err := f.svc.BackendHealthDisabled(t.Context(), source); err != nil {
				t.Fatal(err)
			}
			want := f.second
			if mode == "unmarked" {
				want = f.first
			}
			if mode == "exhausted" {
				want = f.source
			}
			assertMigrationPlacement(t, f, want)
			if got := f.svc.hasPendingHealthFailover(source.ID); got != (mode == "exhausted") {
				t.Errorf("retry debt=%t, mode=%s", got, mode)
			}
		})
	}
}

func TestHealthFailoverLateMarkAtTopologyWait(t *testing.T) {
	f := newFailoverFixture(t)
	source := disableHealthSource(t, f)
	defer f.svc.clearHealthFailoverDebt(source.ID)
	f.svc.mu.Lock()
	locked := true
	defer func() {
		if locked {
			f.svc.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- f.svc.BackendHealthDisabled(t.Context(), source) }()
	waitMigrationFrame(t, "(*Service).MigrateSession(")
	f.markAbsent(t, f.first)
	f.assertRoutedTo(t, f.source, f.first)
	f.svc.mu.Unlock()
	locked = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("health failover did not complete")
	}
	assertMigrationPlacement(t, f, f.second)
}

func waitMigrationFrame(t *testing.T, frame string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		if n == len(buf) {
			t.Fatal("truncated migration stack")
		}
		for _, trace := range bytes.Split(buf[:n], []byte("\n\n")) {
			if bytes.Contains(trace, []byte(frame)) && bytes.Contains(trace, []byte("sync.(*Mutex).Lock(")) {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("migration never reached %s", frame)
}

func TestForwardMigrationPublishesBeforeCompetingMark(t *testing.T) {
	f := newFailoverFixture(t)
	done := make(chan error, 1)
	f.svc.stickyMgr.SetNowFunc(func() time.Time {
		// AssignPeerAffinity is the last publication inside the real commit.
		// A real inventory writer must still be waiting for that commit.
		go func() {
			done <- f.svc.db.SetServerProviderAbsence(t.Context(), f.first.ServerID, time.Now().UTC(), "fixture")
		}()
		waitMigrationFrame(t, "(*DB).SetServerProviderAbsence(")
		return time.Now().UTC()
	})
	if err := f.svc.MigrateSession(t.Context(), f.sess.ID, f.first.ID); err != nil {
		t.Fatal(err)
	}
	f.svc.stickyMgr.SetNowFunc(nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inventory writer did not finish after publication")
	}
	assertMigrationPlacement(t, f, f.first)
}

func TestForwardMigrationFailurePreservesMarkedSource(t *testing.T) {
	f := newFailoverFixture(t)
	f.svc.SetPreCommitMigrationHookForTest(func() {
		f.markAbsent(t, f.source)
		if _, err := f.svc.db.SQLDB().ExecContext(t.Context(), "DELETE FROM vpn_sessions WHERE id = ?", f.sess.ID); err != nil {
			t.Fatal(err)
		}
	})
	if err := f.svc.MigrateSession(t.Context(), f.sess.ID, f.first.ID); err == nil {
		t.Fatal("missing connected row was accepted")
	}
	f.assertRoutedTo(t, f.source, f.first)
	live, ok := f.svc.sessionMgr.GetSessionSnapshotByID(f.sess.ID)
	if !ok || live.BackendTunnelID != f.source.ID {
		t.Fatal("failed move changed session placement")
	}
	if got, _ := f.svc.stickyMgr.GetPeerAffinity(f.peer.peerKey); got != f.source.ID {
		t.Fatal("failed move published affinity")
	}
}
