package vpn

import (
	"bytes"
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// peerSyncWaitFrame is the frame the status caller must be blocked in while a
// reconciliation owns the peer synchronizer.
var peerSyncWaitFrame = []byte("(*peerSynchronizer).Status")

const (
	// peerSyncDumpInitial is the single-shot buffer this observation used before
	// it grew; it stays as the control that reproduces the blind observation.
	peerSyncDumpInitial = 1 << 18
	// peerSyncDumpMax bounds growth: a larger dump is an inconclusive
	// observation, never the absence of the waiter.
	peerSyncDumpMax = 1 << 26
)

// peerSyncParkedDump reports whether the dump holds the peer-sync wait frame and
// whether the whole dump was observed. runtime.Stack truncates silently at
// len(buf), so a cut dump cannot show a missing waiter; growth repeats the
// observation up to peerSyncDumpMax. fixedDump keeps the pre-growth buffer.
func peerSyncParkedDump(fixedDump bool) (parked, complete bool) {
	for size := peerSyncDumpInitial; ; size *= 2 {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Contains(buf[:n], peerSyncWaitFrame), true
		}
		if fixedDump || size >= peerSyncDumpMax {
			return false, false // cut dump: the waiter is unproven, not absent
		}
	}
}

// peerSyncLockOrderRun holds a real status caller against a real reconciliation
// owning the peer synchronizer. ballast is the parked-goroutine load, fixedDump
// the blind pre-growth observation, inverted the defective caller that holds
// Service.mu across the peer-sync wait.
func peerSyncLockOrderRun(t *testing.T, ballast int, fixedDump, inverted bool) (parked, complete, svcFree bool) {
	t.Helper()
	if ballast > 0 {
		// Load that pushes a whole-package dump past a fixed buffer. Every
		// goroutine is joined, so the load never outlives the test.
		park := make(chan struct{})
		var load sync.WaitGroup
		load.Add(ballast)
		for range ballast {
			go func() { defer load.Done(); <-park }()
		}
		t.Cleanup(func() { close(park); load.Wait() })
	}
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	engine, err := svc.NewIngressEngine(t.Context(), "diagnostic-lock-order", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.peerSync.portal = &orphanDiagnosticPortal{present: true}
	t.Cleanup(func() { _ = engine.Stop() })
	entered, release := make(chan struct{}), make(chan struct{})
	skipRevoke, revoked := false, false
	engine.peerSync.revokeSession = func(ctx context.Context, key string) error {
		close(entered)
		<-release
		if skipRevoke || inverted {
			return nil
		} // let defective arrangements fail without leaking workers
		err := svc.RevokeUpstreamPeerSession(ctx, key)
		revoked = err == nil
		return err
	}
	svc.ingressEngine, svc.running, engine.running = engine, true, true
	svc.cfg.PublicEndpoint = "nexus.invalid:51820"
	reconcileDone, statusDone := make(chan error, 1), make(chan error, 1)
	go func() { reconcileDone <- engine.peerSync.reconcileNow(t.Context()) }()
	<-entered // real reconciliation owns peerSynchronizer.mu
	go func() {
		if inverted {
			svc.mu.RLock()
			defer svc.mu.RUnlock()
			_ = engine.PeerSyncStatus()
			statusDone <- nil
			return
		}
		_, err := svc.GetStatus(t.Context())
		statusDone <- err
	}()
	parked, complete = false, true
	deadline := time.Now().Add(2 * time.Second)
	// Poll until the wait is seen, the deadline expires, or the observation is
	// cut: a cut dump cannot become complete by polling again.
	for time.Now().Before(deadline) && !parked && complete {
		parked, complete = peerSyncParkedDump(fixedDump)
		runtime.Gosched()
	}
	// Service.mu must be free while the caller waits. Probe it over a bounded
	// window instead of once: a healthy caller takes its own read lock early,
	// so a single sample can lose that race, while a real inversion holds the
	// lock for the whole contention and is never observed free.
	svcFree = false
	for probe := time.Now().Add(2 * time.Second); time.Now().Before(probe); {
		if svc.mu.TryLock() {
			svc.mu.Unlock()
			svcFree = true
			break
		}
		runtime.Gosched()
	}
	if !svcFree {
		skipRevoke = true
	}
	close(release)
	for _, done := range []chan error{reconcileDone, statusDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("status/reconcile lock cycle")
		}
	}
	if !inverted && !svcFree {
		t.Fatal("skipped the real revoke: cannot confirm it completes under contention")
	}
	if !inverted && svcFree && !revoked {
		t.Fatal("status/reconcile completed without running the real revoke")
	}
	return parked, complete, svcFree
}

// TestPeerSyncLockOrderObserverControls re-runs the lock-order oracle with the
// observation and the lock order as explicit knobs at controlled goroutine
// volume: it pins the truncation the growing observation removes, and proves the
// corrected observer still fails for Service.mu ownership.
func TestPeerSyncLockOrderObserverControls(t *testing.T) {
	for _, tc := range []struct {
		name              string
		ballast           int
		growing, inverted bool
		parked, complete  bool
		svcFree           bool
	}{
		// Real load, corrected observer: the waiter is found, Service.mu is
		// free, and the real revoke completed.
		{"grown sees the real waiter under load", 3000, true, false, true, true, true},
		// Same load and correct product lock order, blind observer: the 256 KiB
		// dump is always cut, so a missing waiter here proves nothing.
		{"fixed buffer leaves the waiter unproven", 3000, false, false, false, false, true},
		// The corrected observer must still fail for Service.mu ownership.
		{"inversion negative stays detected", 0, true, true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parked, complete, svcFree := peerSyncLockOrderRun(t, tc.ballast, !tc.growing, tc.inverted)
			if parked != tc.parked || complete != tc.complete || svcFree != tc.svcFree {
				t.Fatalf("observed parked=%v complete=%v svcMuFree=%v, want %v/%v/%v",
					parked, complete, svcFree, tc.parked, tc.complete, tc.svcFree)
			}
		})
	}
}
