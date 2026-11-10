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

// peerSyncParkedDump reports whether the goroutine dump holds the peer-sync wait
// frame and whether that dump was complete. runtime.Stack truncates silently at
// len(buf), and a finished package run parks thousands of goroutines, so a full
// buffer means the dump was cut, possibly before the goroutine just started.
// Growing repeats the observation instead of turning the cut into a missed
// waiter; fixedDump reproduces the pre-growth single-shot buffer.
func peerSyncParkedDump(fixedDump bool) (parked, complete bool) {
	for size := peerSyncDumpInitial; ; size *= 2 {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if bytes.Contains(buf[:n], peerSyncWaitFrame) {
			return true, true
		}
		if n < len(buf) {
			return false, true // whole dump examined: waiter really absent
		}
		if fixedDump || size >= peerSyncDumpMax {
			return false, false // truncated: nothing may be concluded
		}
	}
}

// peerSyncLockOrderRun holds a real status caller against a real reconciliation
// owning the peer synchronizer, and reports whether the observer saw the wait,
// whether its dump was complete, and whether Service.mu stayed free. ballast is
// the parked-goroutine load, fixedDump the blind single-shot observation, and
// inverted the defective caller that holds Service.mu across the peer-sync wait.
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
	for time.Now().Before(deadline) && !parked && complete {
		parked, complete = peerSyncParkedDump(fixedDump)
		runtime.Gosched()
	}
	svcFree = svc.mu.TryLock()
	if svcFree {
		svc.mu.Unlock()
	} else {
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
// volume: it pins the truncation defect the growing observation removes, and
// proves the corrected observer still fails for Service.mu ownership.
func TestPeerSyncLockOrderObserverControls(t *testing.T) {
	for _, tc := range []struct {
		name              string
		ballast           int
		growing, inverted bool
		parked, complete  bool
		svcFree           bool
	}{
		// Real load, corrected observer: waiter found, Service.mu free, real revoke done.
		{"grown sees the real waiter under load", 3000, true, false, true, true, true},
		// Same load and correct product lock order, blind observer misses the waiter.
		{"fixed buffer truncates under load", 3000, false, false, false, false, true},
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
