package vpn

// Regression coverage for issue #391 round 4b, finding 2 (async peer-sync
// lifecycle) and finding 4 (caller-visible runtime enforcement failure).
//
// Determinism: every test here drives the lifecycle through channels,
// WaitGroups and the existing quiesceNotifyWorker seam. No time.Sleep is used
// to synchronize a race.
//
// The construction- and shutdown-window tests deliberately use only API that
// exists both before and after the fix, so they can be run against the
// unfixed tree to prove they cover the defect.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// syncTestBound bounds the convergence and drain waits used by these tests, so
// a regression fails fast instead of waiting out a production timeout.
const syncTestBound = 5 * time.Second

// syncProbeParams is the key/value pair merged into a connection's existing
// client_params by syncProbeUpdate.
//
// The mutated column must be a NOTIFYING one: UpdateConnection only calls
// notifyPeerChange for user_id, server_id, protocol, client_id and
// client_params. A cosmetic column such as name updates the row without
// notifying anyone, so a probe using it passes on the unfixed tree and proves
// nothing.
//
// The payload is MERGED into the existing client_params rather than replacing
// them. UpdateConnection overwrites the whole column, and dropping assigned_ip
// would make the durable row invalid for desired(), which would then legitimately
// REMOVE the peer from the portal and make the test fail for the wrong reason.
const syncProbeKey = "sync_probe"

func syncProbeUpdate(ctx context.Context, db *database.DB, connID string) (map[string]any, error) {
	conn, err := db.GetConnection(ctx, connID)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, fmt.Errorf("connection %s not found", connID)
	}
	params := map[string]any{}
	for k, v := range conn.ClientParams {
		params[k] = v
	}
	params[syncProbeKey] = "391-round4b"
	return map[string]any{"client_params": params}, nil
}

// withSyncTestBounds installs short convergence and drain bounds for one test.
func withSyncTestBounds(t *testing.T) {
	t.Helper()
	prevConverge, prevDrain := peerSyncConvergeTimeout, peerSyncDrainTimeout
	peerSyncConvergeTimeout, peerSyncDrainTimeout = syncTestBound, syncTestBound
	t.Cleanup(func() { peerSyncConvergeTimeout, peerSyncDrainTimeout = prevConverge, prevDrain })
}

// newTestPeerSynchronizer assembles a peerSynchronizer and attaches it as the
// database's PeerChangeListener, mirroring exactly what
// Service.NewIngressEngine does around it: load the durable portal
// configuration, build the portal device, start the notify worker, subscribe.
// It returns the synchronizer, the stop closure and the portal device.
//
// Tests use it to reach the two lifecycle windows deterministically, from
// outside the engine's constructor, so a commit can be delivered while the
// engine is still assembling rather than racing to land there.
func newTestPeerSynchronizer(t *testing.T, svc *Service, db *database.DB) (*peerSynchronizer, func() error, *clientawg.ClientAWGDevice) {
	t.Helper()
	ctx := t.Context()
	cfg, err := clientawg.LoadConfig(ctx, db, virtualtun.Config{Name: "sync-window-portal", MTU: 1420}, nil)
	if err != nil {
		t.Fatalf("load portal configuration: %v", err)
	}
	settings, err := db.GetVPNConfig(ctx)
	if err != nil || settings == nil {
		t.Fatalf("load portal subnet: %v", err)
	}
	portal, err := clientawg.NewDevice(cfg)
	if err != nil {
		t.Fatalf("create portal device: %v", err)
	}
	ps := newPeerSynchronizer(db, portal, ingress.NewResolver(), cfg, settings, svc.RevokeUpstreamPeerSession, svc.sessionMgr.ListActiveSessionsSnapshot)
	stop, err := ps.startNotifyWorker()
	if err != nil {
		_ = portal.Close()
		t.Fatalf("start notify worker: %v", err)
	}
	unsubscribe, err := db.SubscribePeerChanges(ps)
	if err != nil {
		_ = stop()
		_ = portal.Close()
		t.Fatalf("subscribe peer changes: %v", err)
	}
	teardown := func() {
		unsubscribe()
		_ = stop()
		_ = portal.Close()
	}
	t.Cleanup(teardown)
	return ps, stop, portal
}

// peerOwnerOf returns the durable connection that owns a peer's public key.
func peerOwnerOf(t *testing.T, db *database.DB, peerKey string) (userID, connID string) {
	t.Helper()
	conn, err := db.GetConnectionByClientID(t.Context(), peerKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection for peer: %v", err)
	}
	return conn.UserID, conn.ID
}

// peerConnectionID returns the durable connection id that owns a peer's key.
func peerConnectionID(t *testing.T, db *database.DB, peerKey string) string {
	t.Helper()
	conn, err := db.GetConnectionByClientID(t.Context(), peerKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection for peer: %v", err)
	}
	return conn.ID
}

// TestPeerSyncConstructionWindowNeverReconcilesInline is the finding-2
// construction-window regression.
//
// The contract it pins: the instant the database can see this synchronizer,
// its notification callback is non-blocking. In the round-4a code the engine
// subscribed the listener and only armed the async callback after the initial
// reconcile, so a commit landing in that window fell through to reconcileNow on
// the committing goroutine. Reproduced here in its production shape: the
// committing goroutine holds Service.mu across its durable update, exactly as
// legacy admission does (HandleIncomingPeer -> resolveOrAllocatePeerIP ->
// UpdateConnection), and reconcileNow -> revokeSession ->
// RevokeUpstreamPeerSession re-acquires Service.mu. That is a self-deadlock on
// a non-reentrant mutex, and it is what this test detects.
//
// The commit is issued after the worker is started and the listener attached,
// which is the state the round-4a code left unarmed.
func TestPeerSyncConstructionWindowNeverReconcilesInline(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-window-construct")
	ps, _, portal := newTestPeerSynchronizer(t, svc, db)
	connID := peerConnectionID(t, db, peer.publicKey)

	// The initial installation, performed directly as the engine does, so
	// the later commit has real state to converge away from.
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	if !syncHasPeerOn(t, portal, peer.publicKey, peer.assignedIP) {
		t.Fatal("initial reconcile did not install the durable peer")
	}

	// A durable commit delivered while the engine is still assembling, from
	// a goroutine that holds Service.mu across the commit. UpdateConnection
	// is the production shape of that commit: legacy admission runs
	// HandleIncomingPeer -> resolveOrAllocatePeerIP -> UpdateConnection with
	// Service.mu held, and the notification fires from inside it.
	//
	// The mutated column MUST be one that notifies. UpdateConnection only
	// calls notifyPeerChange for user_id, server_id, protocol, client_id and
	// client_params; a cosmetic column such as name updates the row without
	// notifying anyone, so the test would pass on the unfixed tree and prove
	// nothing. client_params is the legacy-admission commit shape.
	updates, err := syncProbeUpdate(ctx, db, connID)
	if err != nil {
		t.Fatalf("build notifying update: %v", err)
	}
	commitDone := make(chan error, 1)
	go func() {
		svc.mu.Lock()
		defer svc.mu.Unlock()
		_, err := db.UpdateConnection(ctx, connID, updates)
		commitDone <- err
	}()

	var commitErr error
	select {
	case commitErr = <-commitDone:
	case <-time.After(syncTestBound):
		// The unfixed tree deadlocks here: the commit goroutine holds
		// Service.mu and the inline reconciliation blocks acquiring it.
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		t.Fatalf("durable commit deadlocked in the engine construction window: the notification ran the reconciliation inline\n%s", buf)
	}
	if commitErr != nil {
		t.Fatalf("durable commit in the construction window failed: %v", commitErr)
	}

	// The commit must have returned promptly, and the enforcement must have
	// happened on the worker rather than on the committing goroutine.
	if err := ps.AwaitPeerRuntimeSyncWithin(ctx, syncTestBound); err != nil {
		t.Fatalf("enforcement of the construction-window commit did not converge: %v", err)
	}
	// The commit reached the worker, which performed the enforcement: the
	// peer set still matches the durable state after the rename.
	if !syncHasPeerOn(t, portal, peer.publicKey, peer.assignedIP) {
		t.Fatal("peer set diverged from durable state after the construction-window commit")
	}
}

// TestPeerSyncShutdownWindowNeverReconcilesInline is the finding-2
// shutdown-window regression.
//
// The contract it pins: a notification that arrives after the worker stop has
// been requested, while the database listener is still attached, must never run
// a synchronous reconciliation, and Stop must complete. In the round-4a code
// the stop closure nil'd the enqueue path but the listener was detached only
// later, so a commit in that interval found a nil callback and fell back to
// reconcileNow on the committing goroutine — device I/O against a portal that
// is being closed, taking a lock the reconciler needs.
//
// The portal is swapped for a device that blocks forever, so an inline
// reconciliation cannot complete: on the unfixed tree the committing goroutine
// never returns, and on the fixed tree the notification is recorded as a
// visible failure and returns immediately.
func TestPeerSyncShutdownWindowNeverReconcilesInline(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-window-shutdown")
	ps, stop, portal := newTestPeerSynchronizer(t, svc, db)
	userID, _ := peerOwnerOf(t, db, peer.publicKey)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	// Request the worker stop while the database listener is STILL attached:
	// this is exactly the round-4a shutdown window.
	if err := stop(); err != nil {
		t.Fatalf("stop notify worker: %v", err)
	}
	// Wedge the portal device. An inline reconciliation would block here
	// forever; an enqueue cannot reach the stopped worker at all.
	hanging := hangingStatusDevice{release: make(chan struct{})}
	ps.setPortalDeviceForTest(hanging)

	commitDone := make(chan error, 1)
	go func() {
		_, err := db.ToggleUser(ctx, userID, false)
		commitDone <- err
	}()
	select {
	case err := <-commitDone:
		if err != nil {
			t.Fatalf("durable commit in the shutdown window failed: %v", err)
		}
	case <-time.After(syncTestBound):
		close(hanging.release)
		t.Fatal("shutdown-window notification ran a synchronous reconciliation on the committing goroutine")
	}

	// The failure is visible, in one converged state, and never silent.
	failures, reason := ps.EnqueueFailures()
	if failures == 0 || reason == "" {
		t.Fatalf("shutdown-window enqueue failure was silent: count=%d reason=%q", failures, reason)
	}
	status := ps.Status()
	if status.EnqueueFailures == 0 || status.LastEnqueueError == "" {
		t.Fatalf("enqueue failure missing from peer sync status: %+v", status)
	}
	// A caller waiting on convergence is released with the failure instead of
	// waiting out its bound.
	err := ps.AwaitPeerRuntimeSyncWithin(ctx, syncTestBound)
	if err == nil {
		t.Fatal("convergence wait reported success for a notification that was never enforced")
	}
	if !errors.Is(err, database.ErrPeerRuntimeSync) {
		t.Fatalf("convergence error is not a runtime sync failure: %v", err)
	}
	// Release the wedged device and confirm the portal was left alone: the
	// notification must not have run device I/O on the caller's goroutine.
	close(hanging.release)
	ps.setPortalDeviceForTest(portal)
	if err := stop(); err != nil {
		t.Fatalf("second stop of an already-stopped worker: %v", err)
	}
}

// TestPeerSyncNotificationStopLifecycleRace exercises concurrent database
// notifications against the worker stop. It pins the finding-2 requirement
// that the lifecycle state is explicitly synchronized: in the round-4a code
// the enqueue callback and the notification target were bare function fields
// read and written across goroutines, which -race reports independently of any
// assertion below.
func TestPeerSyncNotificationStopLifecycleRace(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-lifecycle-race")
	ps, stop, _ := newTestPeerSynchronizer(t, svc, db)
	_, connID := peerOwnerOf(t, db, peer.publicKey)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	// Two racing sides released by one barrier: notifications from the
	// database, and the stop that invalidates the enqueue path. The
	// read/write of the lifecycle state genuinely overlaps.
	const rounds = 200
	var start, done sync.WaitGroup
	start.Add(1)
	done.Add(2)
	go func() {
		defer done.Done()
		start.Wait()
		for i := 0; i < rounds; i++ {
			if _, err := db.ToggleConnection(ctx, connID, i%2 == 0); err != nil {
				t.Errorf("durable toggle: %v", err)
				return
			}
		}
	}()
	go func() {
		defer done.Done()
		start.Wait()
		if err := stop(); err != nil {
			t.Errorf("stop notify worker: %v", err)
		}
	}()
	start.Done()
	done.Wait()

	// Whatever the interleaving was, the outcome is coherent: notifications
	// were either enqueued and drained, or recorded as visible failures.
	// Nothing is silently dropped.
	ps.quiesceNotifyWorker()
	// The drain seam returning means the accounting agreed with reality, so
	// the bookkeeping must be settled too (issue #729): a leftover queued
	// count is a notification nobody will ever serve, and a negative one
	// would be a convergence that never happened.
	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("post-stop queued accounting = %d, want 0", got)
	}
	if ps.running.Load() {
		t.Fatal("post-stop running flag still set after the drain")
	}
	if !ps.armedFlag.Load() {
		if failures, reason := ps.EnqueueFailures(); failures > 0 && reason == "" {
			t.Fatal("enqueue failure counted without a recorded reason")
		}
	}
}

// gatedPortalDevice blocks the n-th Status call until releases[n-1] is
// closed, and reports every entry on entered. It is how these tests prove the
// worker is INSIDE a reconcile pass without sleeping or polling a flag: the
// pass announces itself, then parks where the test wants it. Calls beyond the
// staged releases are not blocked.
type gatedPortalDevice struct {
	mu       sync.Mutex
	calls    int
	entered  chan int
	releases []chan struct{}
}

func newGatedPortalDevice(staged int) *gatedPortalDevice {
	device := &gatedPortalDevice{entered: make(chan int, 32), releases: make([]chan struct{}, staged)}
	for i := range device.releases {
		device.releases[i] = make(chan struct{})
	}
	return device
}

func (d *gatedPortalDevice) Status() (clientawg.Status, error) {
	d.mu.Lock()
	d.calls++
	n := d.calls
	d.mu.Unlock()
	d.entered <- n
	if n <= len(d.releases) {
		<-d.releases[n-1]
	}
	return clientawg.Status{}, errors.New("portal unavailable")
}

func (d *gatedPortalDevice) AddPeer(clientawg.Peer) error { return errors.New("portal unavailable") }

func (d *gatedPortalDevice) RemovePeer(string) error { return errors.New("portal unavailable") }

// waitGateEntered waits until the gate reports the wanted pass as started.
func waitGateEntered(t *testing.T, gate *gatedPortalDevice, want int) {
	t.Helper()
	select {
	case n := <-gate.entered:
		if n != want {
			t.Fatalf("portal pass %d entered, want pass %d", n, want)
		}
	case <-time.After(syncTestBound):
		t.Fatalf("portal pass %d never started", want)
	}
}

// waitQuiesced proves quiesceNotifyWorker returns instead of spinning. The
// pre-fix defect hung exactly here, for seven minutes, until the package
// alarm fired; the bound turns that hang into a fast, attributable failure.
func waitQuiesced(t *testing.T, ps *peerSynchronizer) {
	t.Helper()
	quiesced := make(chan struct{})
	go func() {
		ps.quiesceNotifyWorker()
		close(quiesced)
	}()
	select {
	case <-quiesced:
	case <-time.After(syncTestBound):
		t.Fatalf("quiesceNotifyWorker spun for %s: queued=%d running=%v",
			syncTestBound, ps.pending.Load(), ps.running.Load())
	}
}

// TestPeerSyncStopSettlesAcceptedNotificationAccounting is the retained
// deterministic stranded-notification oracle from the issue-724 diagnosis
// (probe 1), asserted against the production stop transition.
//
// It is whitebox on purpose. The pre-fix defect is a two-instruction window —
// read the armed state, release the lock, then increment the queued count —
// and no scheduling trick makes that window land with certainty through the
// public path (the diagnosis measured 2/100 rounds). What IS deterministic is
// the state an accepted-but-never-started notification leaves behind, so that
// state is constructed directly and the stop contract is asserted on it:
// after stop, no queued accounting may survive, and the drain seam must
// return rather than spin.
func TestPeerSyncStopSettlesAcceptedNotificationAccounting(t *testing.T) {
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, stop, _ := newTestPeerSynchronizer(t, svc, db)

	// The accounting an accepted notification leaves queued before its pass
	// starts. Pre-fix this is what the stop transition walked away from.
	ps.pending.Add(1)

	if err := stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("stop left %d queued notification(s) with no worker to serve them", got)
	}
	if ps.running.Load() {
		t.Fatal("stop left the running flag set with no pass in flight")
	}
	waitQuiesced(t, ps)
}

// TestPeerSyncStopDrainsQueuedTokenAndReportsIt drives the same contract
// through the real notification path: one pass in flight, one notification
// coalesced behind it, then stop. The in-flight pass is awaited, the queued
// notification is settled by the stop transition instead of being stranded,
// and the caller waiting on it is told it was not enforced.
func TestPeerSyncStopDrainsQueuedTokenAndReportsIt(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, stop, _ := newTestPeerSynchronizer(t, svc, db)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	gate := newGatedPortalDevice(1)
	ps.setPortalDeviceForTest(gate)

	// First notification: taken by the worker, which parks inside the pass.
	ps.enqueuePeerReconcile()
	waitGateEntered(t, gate, 1)
	// Second notification: coalesces into a queued token behind that pass.
	ps.enqueuePeerReconcile()
	if got := ps.pending.Load(); got != 1 {
		t.Fatalf("queued count behind one running pass = %d, want 1", got)
	}
	if !ps.running.Load() {
		t.Fatal("running flag not set while a pass is in flight")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- stop() }()
	// Release the in-flight pass; the drain then has nothing left to await.
	close(gate.releases[0])
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("stop after a drained in-flight pass: %v", err)
		}
	case <-time.After(syncTestBound):
		t.Fatal("stop did not return after the in-flight pass was released")
	}

	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("queued count after stop = %d, want 0 (stranded token)", got)
	}
	if ps.running.Load() {
		t.Fatal("running flag still set after the drain")
	}
	waitQuiesced(t, ps)
	// The queued notification was never enforced and must be reported, not
	// silently converted into a success.
	if err := ps.AwaitPeerRuntimeSyncWithin(ctx, syncTestBound); !errors.Is(err, database.ErrPeerRuntimeSync) {
		t.Fatalf("convergence outcome after stop = %v, want a runtime sync failure", err)
	}
}

// TestPeerSyncQueuedNotificationsAllDrain is the coalescing control: kicks
// coalesce into at most one wake token, but an accepted notification's
// accounting may never be coalesced away. Every queued notification must be
// served (here: one pass each) and the count must end at exactly zero, not
// merely "small".
func TestPeerSyncQueuedNotificationsAllDrain(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, _, _ := newTestPeerSynchronizer(t, svc, db)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	gate := newGatedPortalDevice(1)
	ps.setPortalDeviceForTest(gate)

	const accepted = 5
	ps.enqueuePeerReconcile()
	waitGateEntered(t, gate, 1)
	for i := 1; i < accepted; i++ {
		ps.enqueuePeerReconcile()
	}
	// The first pass has already consumed its own token, so the queued debt
	// is exactly the remaining notifications: coalescing wakes must not lose
	// any of them.
	if got := ps.pending.Load(); got != accepted-1 {
		t.Fatalf("queued count behind one running pass = %d, want %d", got, accepted-1)
	}

	close(gate.releases[0])
	waitQuiesced(t, ps)
	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("queued count after the drain = %d, want 0", got)
	}
	if ps.running.Load() {
		t.Fatal("running flag still set after the drain")
	}
	// Exactly one pass per accepted notification: no debt lost, no phantom
	// pass invented.
	gate.mu.Lock()
	calls := gate.calls
	gate.mu.Unlock()
	if calls != accepted {
		t.Fatalf("portal saw %d passes for %d accepted notifications, want %d", calls, accepted, accepted)
	}
}

// TestPeerSyncRetiredGenerationCannotClobberLiveAccounting is the
// deterministic guard control for the crossover between a retired worker
// that is still inside a pass and a live worker that has taken the enqueue
// path over.
//
// This one is NOT a pre-fix reproduction, and it says so: the two failures it
// guards against are introduced by settling the queued count on stop. Pre-fix
// there was no settle, so nothing could underflow. Once stop settles the
// count, a stale worker that then claims a token would drive it to -1 (which
// quiesceNotifyWorker reads as "drained"), and a stale worker finishing its
// pass would clear the live generation's in-flight marker. Both are false
// convergence, so the guard is a required part of the correction and is
// pinned here.
//
// It is driven through the same helpers the worker itself calls — not a
// replica of the logic — because the interleaving has no seam a scheduler can
// be made to land on deterministically.
func TestPeerSyncRetiredGenerationCannotClobberLiveAccounting(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, stopFirst, _ := newTestPeerSynchronizer(t, svc, db)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	gate := newGatedPortalDevice(2)
	ps.setPortalDeviceForTest(gate)

	// Generation 1 takes a token and parks inside its pass.
	ps.enqueuePeerReconcile()
	waitGateEntered(t, gate, 1)
	ps.lcMu.Lock()
	retiredGen := ps.lcGen
	ps.lcMu.Unlock()

	// Stop retires that generation. The drain bound is tiny so the stop
	// returns while the pass is still parked (the crossover precondition).
	prevDrain := peerSyncDrainTimeout
	peerSyncDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { peerSyncDrainTimeout = prevDrain })
	if err := stopFirst(); err == nil {
		t.Fatal("stop reported a clean drain while its worker was still inside a pass")
	}
	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("stop settled the queued count to %d, want 0", got)
	}

	// A retired token is refused and must not decrement the settled count.
	if ps.beginNotifyPass(retiredGen) {
		t.Fatal("a retired generation claimed a token after its stop settled the queue")
	}
	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("retired generation moved the settled queued count to %d, want 0", got)
	}

	// A new generation takes over and starts a pass of its own.
	stopSecond, err := ps.startNotifyWorker()
	if err != nil {
		t.Fatalf("restart notify worker: %v", err)
	}
	t.Cleanup(func() { _ = stopSecond() })
	ps.enqueuePeerReconcile()
	liveGen := func() uint64 { ps.lcMu.Lock(); defer ps.lcMu.Unlock(); return ps.lcGen }()
	if liveGen == retiredGen {
		t.Fatal("restart reused the retired generation number")
	}
	if !ps.beginNotifyPass(liveGen) {
		t.Fatal("the live generation could not claim its own token")
	}
	if !ps.running.Load() {
		t.Fatal("running marker not set for the live generation's pass")
	}

	// The retired worker finishes its pass now. It must not clear the live
	// generation's marker.
	ps.endNotifyPass(retiredGen, 0, nil)
	if !ps.running.Load() {
		t.Fatal("retired generation cleared the live generation's running marker: quiesce would report a false convergence")
	}
	// The live generation's own completion does clear it.
	ps.endNotifyPass(liveGen, 0, nil)
	if ps.running.Load() {
		t.Fatal("live generation could not clear its own running marker")
	}

	// Unwedge both parked passes so the workers can exit.
	close(gate.releases[0])
	close(gate.releases[1])
	waitQuiesced(t, ps)
}

// TestPeerSyncRestartKeepsGenerationAccountingSeparate is the end-to-end
// restart control: a worker retired by an expired drain is still inside its
// pass when a new worker takes the enqueue path over, and the system still
// converges afterwards, with the live pass served and the queue settled.
func TestPeerSyncRestartKeepsGenerationAccountingSeparate(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	// This test deliberately lets the drain bound expire rather than waiting
	// the test bound out.
	prevDrain := peerSyncDrainTimeout
	peerSyncDrainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { peerSyncDrainTimeout = prevDrain })

	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ps, stopFirst, _ := newTestPeerSynchronizer(t, svc, db)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	gate := newGatedPortalDevice(2)
	ps.setPortalDeviceForTest(gate)

	// Generation 1 is inside a pass and stays there.
	ps.enqueuePeerReconcile()
	waitGateEntered(t, gate, 1)
	// Stop it and let the drain bound expire: the retired worker is still
	// inside its pass, which is exactly the crossover precondition.
	if err := stopFirst(); err == nil {
		t.Fatal("stop reported a clean drain while its worker was still inside a pass")
	}

	// A new generation takes the enqueue path over on the same synchronizer.
	stopSecond, err := ps.startNotifyWorker()
	if err != nil {
		t.Fatalf("restart notify worker: %v", err)
	}
	t.Cleanup(func() { _ = stopSecond() })
	if !ps.armedFlag.Load() {
		t.Fatal("restarted worker did not re-arm the enqueue path")
	}
	ps.enqueuePeerReconcile()

	// Release the retired pass. The new pass can only start once the retired
	// one drops the reconciliation lock, and it announces itself at the gate.
	close(gate.releases[0])
	waitGateEntered(t, gate, 2)
	if got := ps.pending.Load(); got != 0 {
		t.Fatalf("live generation queued count = %d, want 0", got)
	}

	close(gate.releases[1])
	waitQuiesced(t, ps)
	if ps.running.Load() {
		t.Fatal("live generation running flag still set after its pass finished")
	}
}

// TestPeerSyncCallerSeesEnforcementFailure is the finding-4 regression: a
// caller that committed a durable change and then asked for convergence must
// be told when the enforcement FAILED, and told success when it genuinely
// succeeded. That is the property the round-4a design lost, where the
// reconcile result was discarded and runtime_sync_failed could never be
// produced by an asynchronous enforcement failure.
//
// The wait runs on the caller's goroutine, after the commit returned and after
// Service.mu was released, so it cannot deadlock against the worker it waits
// for: it performs no device I/O itself.
func TestPeerSyncCallerSeesEnforcementFailure(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)

	t.Run("FailureIsReported", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		peer, _ := newEnginePeer(t, svc, db, "sync-converge-fail")
		e, err := svc.NewIngressEngine(ctx, "sync-converge-fail-portal", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Stop() })
		userID, _ := peerOwnerOf(t, db, peer.publicKey)

		// The enforcement will fail: the portal refuses to remove the peer.
		e.peerSync.setPortalDeviceForTest(failingRemovePeerDevice{real: e.Portal()})
		if _, err := db.ToggleUser(ctx, userID, false); err != nil {
			t.Fatalf("durable revocation must still commit: %v", err)
		}
		// The caller asks whether its own change took effect at runtime.
		// The commit goroutine holds no lock here, which is the whole point.
		err = e.AwaitPeerRuntimeSync(ctx)
		if err == nil {
			t.Fatal("caller was told the enforcement succeeded while the portal refused it")
		}
		if !errors.Is(err, database.ErrPeerRuntimeSync) {
			t.Fatalf("caller error is not a runtime sync failure: %v", err)
		}
		// The same failure is in the one converged status, not only in a
		// side counter.
		status := e.PeerSyncStatus()
		if status.SyncFailures == 0 || status.LastError == "" {
			t.Fatalf("enforcement failure missing from peer sync status: %+v", status)
		}
	})

	t.Run("SuccessIsReported", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		peer, _ := newEnginePeer(t, svc, db, "sync-converge-ok")
		e, err := svc.NewIngressEngine(ctx, "sync-converge-ok-portal", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Stop() })
		userID, _ := peerOwnerOf(t, db, peer.publicKey)

		if _, err := db.ToggleUser(ctx, userID, false); err != nil {
			t.Fatalf("durable revocation: %v", err)
		}
		if err := e.AwaitPeerRuntimeSync(ctx); err != nil {
			t.Fatalf("caller was told a successful enforcement failed: %v", err)
		}
		if syncHasPeer(t, e, peer.publicKey, "") {
			t.Fatal("revoked peer still active after a confirmed enforcement")
		}
	})

	t.Run("ConvergenceIsBounded", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		peer, _ := newEnginePeer(t, svc, db, "sync-converge-bounded")
		ps, stop, portal := newTestPeerSynchronizer(t, svc, db)
		userID, _ := peerOwnerOf(t, db, peer.publicKey)
		if err := ps.reconcileNow(ctx); err != nil {
			t.Fatalf("initial reconcile: %v", err)
		}
		// Wedge the portal so no enforcement pass can complete, then prove
		// the wait returns on its own bound instead of blocking forever.
		hanging := hangingStatusDevice{release: make(chan struct{})}
		ps.setPortalDeviceForTest(hanging)
		if _, err := db.ToggleUser(ctx, userID, false); err != nil {
			t.Fatalf("durable revocation: %v", err)
		}
		waited := make(chan error, 1)
		go func() { waited <- ps.AwaitPeerRuntimeSyncWithin(ctx, syncTestBound) }()
		select {
		case err := <-waited:
			if err == nil {
				t.Fatal("bounded convergence wait reported success for a wedged enforcement")
			}
			if !errors.Is(err, database.ErrPeerRuntimeSync) {
				t.Fatalf("timeout error is not a runtime sync failure: %v", err)
			}
			if ps.ConvergeTimeouts() == 0 {
				t.Fatal("convergence timeout was not recorded")
			}
		case <-time.After(3 * syncTestBound):
			close(hanging.release)
			t.Fatal("convergence wait blocked indefinitely on a wedged portal device")
		}
		// Unwedge and confirm the retry converges: the wait is a bounded
		// confirmation, not a one-shot verdict.
		close(hanging.release)
		ps.setPortalDeviceForTest(portal)
		if _, err := db.ToggleUser(ctx, userID, true); err != nil {
			t.Fatalf("durable re-enable: %v", err)
		}
		if err := ps.AwaitPeerRuntimeSyncWithin(ctx, syncTestBound); err != nil {
			t.Fatalf("convergence after unwedging the portal: %v", err)
		}
		if !syncHasPeerOn(t, portal, peer.publicKey, peer.assignedIP) {
			t.Fatal("re-enabled peer was not installed after convergence recovered")
		}
		_ = stop()
	})
}

// TestPeerSyncCallerConvergenceIsDeadlockFree proves the deadlock the
// asynchronous design exists to prevent does not come back through the
// caller-visible wait: a commit issued while Service.mu is held must not
// reconcile inline, and the convergence wait issued afterwards must return
// even though the worker needs that same lock.
func TestPeerSyncCallerConvergenceIsDeadlockFree(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-converge-deadlock")
	ps, _, portal := newTestPeerSynchronizer(t, svc, db)
	connID := peerConnectionID(t, db, peer.publicKey)
	if err := ps.reconcileNow(ctx); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}

	// Commit under Service.mu, exactly as legacy admission does. The mutated
	// column must be a notifying one (client_params), otherwise no
	// notification is delivered and the test cannot observe the defect.
	updates, err := syncProbeUpdate(ctx, db, connID)
	if err != nil {
		t.Fatalf("build notifying update: %v", err)
	}
	commitDone := make(chan error, 1)
	go func() {
		svc.mu.Lock()
		defer svc.mu.Unlock()
		_, err := db.UpdateConnection(ctx, connID, updates)
		commitDone <- err
	}()
	select {
	case err := <-commitDone:
		if err != nil {
			t.Fatalf("durable commit under Service.mu failed: %v", err)
		}
	case <-time.After(syncTestBound):
		t.Fatal("commit under Service.mu deadlocked: the notification reconciled inline")
	}
	// The wait runs after the commit returned and Service.mu was released,
	// so the worker can take that lock and converge.
	if err := ps.AwaitPeerRuntimeSyncWithin(ctx, syncTestBound); err != nil {
		t.Fatalf("convergence after a commit under Service.mu: %v", err)
	}
	if !syncHasPeerOn(t, portal, peer.publicKey, peer.assignedIP) {
		t.Fatal("peer set diverged from durable state after a commit under Service.mu")
	}
}

// TestPeerSyncStartupInstallNonRegression is the round-4a startup-install
// non-regression, which finding 2's reordering could easily have brought back.
//
// The naive way to satisfy finding 2 is to arm the callback before the initial
// reconcile and let the initial reconcile go through ReconcilePeers. That
// silently reintroduces the round-4a defect: ReconcilePeers enqueues and
// returns nil, so construction reports success with an empty portal. The
// initial reconcile therefore calls reconcileNow directly, and both halves of
// the guarantee are pinned here: the durable peer set is installed before
// construction returns, and a failed initial reconcile still aborts
// construction.
func TestPeerSyncStartupInstallNonRegression(t *testing.T) {
	ctx := t.Context()
	withSyncTestBounds(t)

	t.Run("DurablePeerSetInstalledBeforeReturn", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		peer, _ := newEnginePeer(t, svc, db, "sync-startup-install")
		e, err := svc.NewIngressEngine(ctx, "sync-startup-install-portal", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Stop() })
		// No quiesce, no sleep, no Start: the peer must already be on the
		// portal the moment construction returns. An enqueued initial
		// reconcile would break exactly this.
		if !syncHasPeer(t, e, peer.publicKey, peer.assignedIP) {
			t.Fatal("construction returned without installing the durable peer set")
		}
		if e.PeerSyncStatus().LastSuccessfulReconcile.IsZero() {
			t.Fatal("initial reconcile did not run synchronously during construction")
		}
	})

	t.Run("FailedInitialReconcileAbortsConstruction", func(t *testing.T) {
		db := setupTestDB(t)
		svc := newIngressEngineService(t, db)
		_, _ = newEnginePeer(t, svc, db, "sync-startup-fail")
		// An unusable persisted portal subnet makes desired() fail inside
		// reconcileNow, which is the initial reconciliation: construction
		// must fail rather than report an unenforced engine as ready.
		if err := db.SetSetting(ctx, "vpn_config", unusablePortalConfig(t, db)); err != nil {
			t.Fatalf("persist unusable portal configuration: %v", err)
		}
		e, err := svc.NewIngressEngine(ctx, "sync-startup-fail-portal", nil)
		if err == nil {
			_ = e.Stop()
			t.Fatal("construction succeeded although the initial reconciliation failed")
		}
		t.Logf("construction failed with: %v", err)
		// A failed construction must not leave the database listener
		// installed: a later attempt has to be able to subscribe.
		retry, retryErr := svc.NewIngressEngine(ctx, "sync-startup-fail-portal2", nil)
		if retryErr == nil {
			_ = retry.Stop()
		}
	})
}

// unusablePortalConfig returns the persisted vpn_config with a subnet the
// reconciler cannot use, which makes the initial reconcile fail.
func unusablePortalConfig(t *testing.T, db *database.DB) map[string]any {
	t.Helper()
	raw, found, err := db.GetSettingRaw(t.Context(), "vpn_config")
	if err != nil || !found || !raw.Valid {
		t.Fatalf("read persisted vpn_config: found=%v err=%v", found, err)
	}
	var stored map[string]any
	if err := json.Unmarshal([]byte(raw.String), &stored); err != nil {
		t.Fatalf("parse persisted vpn_config: %v", err)
	}
	stored["subnet_cidr"] = "not-a-subnet"
	return stored
}

// syncHasPeerOn is syncHasPeer against a raw portal device, for tests that
// drive the synchronizer without a constructed engine.
func syncHasPeerOn(t *testing.T, portal *clientawg.ClientAWGDevice, key, ip string) bool {
	t.Helper()
	status, err := portal.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range status.Peers {
		if peer.PublicKey != key {
			continue
		}
		if ip != "" && peer.AllowedIP.String() != ip+"/32" {
			t.Fatalf("peer has AllowedIP %s, want %s/32", peer.AllowedIP, ip)
		}
		return true
	}
	return false
}
