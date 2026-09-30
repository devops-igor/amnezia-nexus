package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// ErrIngressEngineStarted reports a Start on an already-running engine.
var ErrIngressEngineStarted = errors.New("ingress engine already started")

// ErrIngressEngineNotStarted reports a Stop on an engine that never started.
var ErrIngressEngineNotStarted = errors.New("ingress engine is not started")

// IngressEngine is the production integration seam for the upstream
// plaintext ingress path (issue #388): it owns the client-facing upstream
// device, the durable-ownership resolver, the router, and the receive loop
// that pumps ClientAWGDevice.ReceiveOutbound into ingress.Router.HandlePacket
// using PRODUCTION Nexus components — the service's real forwarder, the
// service's real admission primitive (EnsureBackendSessionForIngress), and
// the service's real session liveness.
//
// The engine also owns the upstream-mode idle reap driver (issue #390 part
// 1): reapLoop runs SessionManager.CheckTimeouts on the engine's reap
// cadence and hands each timed-out session to the service's provenance-
// selected reapSession (routing-only for ingress-admitted sessions). The
// custom listener's heartbeat keeps its own sweep — the two never run the
// same session twice (CheckTimeouts removes a session exactly once), and
// in the dormant-engine reality the listener remains the only sweeper. The
// sweep's idle threshold is the reapIdleTimeoutFn field (issue #390 part
// 2): it defaults to reapLoopIdleTimeout — the same 3-minute constant the
// listener config is built with — and tests override it per engine.
//
// The engine is DORMANT by default: nothing in the production startup path
// constructs or starts it. Engine ACTIVATION/canary/cutover/rollback is
// #393; this type exists so activation has a real, callable component to
// switch on instead of a test-only receive pump. The custom listener and its
// handshake path are untouched — the engine runs ALONGSIDE them, sharing the
// service's forwarder/sessions/pool with the same serialization regime.
//
// Shutdown is clean and idempotent: Stop terminates the receive loop first,
// then closes the upstream device (which unblocks a receiver parked in
// ReceiveOutbound through the engine-owned VirtualTUN closure), then waits
// for the loop goroutine to exit. A stopped engine leaks no goroutines.
type IngressEngine struct {
	svc                    *Service
	portal                 *clientawg.ClientAWGDevice
	peerSync               *peerSynchronizer
	unsubscribePeerChanges func()
	stopPeerSyncWorker     func() error
	resolver               *ingress.Resolver
	liveness               *ingress.SessionLiveness
	router                 *ingress.Router

	mu             sync.Mutex
	stopCh         chan struct{}
	stopped        chan struct{}
	reapStopCh     chan struct{}
	reapDoneCh     chan struct{}
	peerSyncStopCh chan struct{}
	peerSyncDoneCh chan struct{}
	closed         bool
	running        bool
	returnPath     *forwarder.ReturnPath
	returnCounters returnCounters

	// reapIdleTimeoutFn is the upstream sweep's idle threshold (issue #390
	// part 2 test seam). Production leaves it nil: sweepOnce then uses
	// reapLoopIdleTimeout — the same 3-minute constant the service's
	// listener config is built with. Tests assign it directly (same
	// package) BEFORE Start, so the reap loop's reads are ordered by
	// goroutine creation; the field is never written after Start.
	reapIdleTimeoutFn func(*Service) time.Duration

	// reapInterval is the upstream-mode idle reap ticker cadence (issue #390
	// part 2 test seam). Production leaves it 0: reapLoop then uses
	// reapLoopInterval — the same 30s cadence as the custom listener's
	// heartbeat. Like reapIdleTimeoutFn, tests assign it directly (same
	// package) BEFORE Start; reapLoop reads it once at loop entry, and the
	// field is never written after Start.
	reapInterval     time.Duration
	peerSyncInterval time.Duration
}

// reapLoopInterval is the upstream-mode idle reap cadence. It mirrors the
// custom listener's heartbeat interval (30s) so idle sessions are retired
// with the same latency the transport path has always had.
const reapLoopInterval = 30 * time.Second
const peerSyncLoopInterval = 30 * time.Second

// reapLoopIntervalFor is the loop's ticker cadence: the engine's test seam
// when assigned, the production 30s constant otherwise. Must be called
// before launching reapLoop (read-once-at-entry contract).
func (e *IngressEngine) reapLoopIntervalFor() time.Duration {
	if e.reapInterval > 0 {
		return e.reapInterval
	}
	return reapLoopInterval
}

// NewIngressEngine builds the production upstream ingress chain from durable
// state:
//
//	clientawg.LoadConfig (durable portal identity, fail-closed)
//	  -> clientawg.ClientAWGDevice (portal role, one VirtualTUN)
//	  -> ingress.LoadResolver (durable assigned-IP ownership, durable-only)
//	  -> Service liveness (throttled TouchSession) + Service admission
//	       (EnsureBackendSessionForIngress — clean, handshake-free)
//	  -> ingress.Router
//
// tunName labels the in-memory portal TUN. Peers is an optional compatibility
// assertion for callers that supplied a startup list before #391; durable DB
// connections now determine the actual peer set. The persisted listen port is
// reused; the custom listener must NOT be running when the engine activates (#393
// owns that cutover). Construction validates everything and closes owned
// resources on failure; a constructed engine is Start-able.
func (s *Service) NewIngressEngine(ctx context.Context, tunName string, peers []clientawg.Peer) (*IngressEngine, error) {
	if s == nil {
		return nil, errors.New("ingress engine: nil service")
	}
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return nil, errors.New("ingress engine: no configuration database")
	}

	// The portal device's plaintext boundary: same MTU the listener uses,
	// bounded queues from the virtualtun defaults.
	cfg, err := clientawg.LoadConfig(ctx, db, virtualtun.Config{Name: tunName, MTU: 1420}, nil)
	if err != nil {
		return nil, fmt.Errorf("ingress engine: load portal configuration: %w", err)
	}
	vpnCfg, err := db.GetVPNConfig(ctx)
	if err != nil || vpnCfg == nil {
		return nil, errors.New("ingress engine: cannot load portal subnet")
	}
	portal, err := clientawg.NewDevice(cfg)
	if err != nil {
		return nil, fmt.Errorf("ingress engine: create portal device: %w", err)
	}

	resolver := ingress.NewResolver()
	// The live-session snapshot is the live side of the Nexus routing cleanup
	// reconciliation (issue #391 round 4b, S1): a DELETED connection leaves no
	// user_connections row, so durable enumeration alone would never see its
	// session. It reads the SessionManager under its own RLock and never
	// mutates it.
	peerSync := newPeerSynchronizer(db, portal, resolver, cfg, vpnCfg, s.RevokeUpstreamPeerSession, s.sessionMgr.ListActiveSessionsSnapshot)
	// The async post-commit reconcile worker, and with it the non-blocking
	// enqueue path, must exist BEFORE the DB listener is attached: every
	// later notification is a non-blocking enqueue onto this worker (issue
	// #391 round 4a, finding 2; round 4b, finding 2). startNotifyWorker
	// starts the worker and arms the enqueue path in one critical section,
	// so there is no window in which the listener is visible but the enqueue
	// path is disarmed. The initial reconcile below stays synchronous and
	// calls reconcileNow DIRECTLY: it runs without Service.mu held, it
	// installs the durable peer set before construction returns, and its
	// failure aborts construction.
	stopPeerSyncWorker, err := peerSync.startNotifyWorker()
	if err != nil {
		_ = portal.Close()
		return nil, fmt.Errorf("ingress engine: start peer sync notify worker: %w", err)
	}
	// abortWorker stops the notify worker on a construction failure. The
	// drain is deadline-bounded, so a wedged portal device reports a timeout
	// instead of blocking construction; the construction error below is the
	// one that matters, so the drain result is logged, not returned.
	abortWorker := func() {
		if stopErr := stopPeerSyncWorker(); stopErr != nil {
			log.Printf("[vpn/ingress] peer sync worker drain during aborted construction: %v", stopErr)
		}
	}
	unsubscribe, err := db.SubscribePeerChanges(peerSync)
	if err != nil {
		abortWorker()
		_ = portal.Close()
		return nil, fmt.Errorf("ingress engine: subscribe peer changes: %w", err)
	}
	// The initial reconciliation runs DIRECTLY through reconcileNow, never
	// through the PeerChangeListener entry point: the enqueue path is armed
	// and the worker is running, so ReconcilePeers would only enqueue and
	// return nil, and construction would report success without the portal
	// ever receiving the durable peer set (the round-4a startup-install
	// defect). Running it here — after the worker is live, before the
	// listener is attached — installs the durable peer set synchronously
	// and keeps a failure fatal to construction.
	if err := peerSync.reconcileNow(ctx); err != nil {
		unsubscribe()
		abortWorker()
		_ = portal.Close()
		return nil, fmt.Errorf("ingress engine: initial peer reconciliation: %w", err)
	}
	if peers != nil {
		desired, _, err := peerSync.desired(ctx)
		if err != nil || len(desired) != len(peers) {
			unsubscribe()
			abortWorker()
			_ = portal.Close()
			return nil, errors.New("ingress engine: supplied peers differ from durable peer registry")
		}
		for _, peer := range peers {
			entry, ok := desired[peer.PublicKey]
			if !ok || entry.peer.AllowedIP != peer.AllowedIP {
				unsubscribe()
				abortWorker()
				_ = portal.Close()
				return nil, errors.New("ingress engine: supplied peers differ from durable peer registry")
			}
		}
	}

	// Accepted plaintext refreshes the backend routing session's LastSeen
	// through the same SessionManager the transport path touches, with the
	// same throttle window (issue #294 pattern).
	liveness := ingress.NewSessionLiveness(s.sessionMgr.TouchSession)

	e := &IngressEngine{svc: s, portal: portal, peerSync: peerSync, unsubscribePeerChanges: unsubscribe, stopPeerSyncWorker: stopPeerSyncWorker, resolver: resolver, liveness: liveness}
	e.returnPath = forwarder.NewReturnPath(e.writeReturnPacket)
	// Production classification (issue #389 rework 2): the forwarder's
	// backend-reader filters reject malformed/unrouted replies before the
	// write callback runs, so the engine folds those rejections into the
	// same counters here. Exactly one engine exists per service (dormant
	// until #393 activation); a second registration would re-target
	// subsequent classifications to the newer engine.
	s.forwarder.SetReturnRejectClassifier(e.classifyForwarderReject)
	e.router = ingress.NewRouterWithReturnPath(resolver, serviceIngressAdmission{svc: s, returnPath: e.returnPath}, s.forwarder, liveness, e.returnPath)
	return e, nil
}

// Start launches the receive loop: ClientAWGDevice.ReceiveOutbound ->
// ingress.Router.HandlePacket, forever, until Stop or portal closure.
// Drops are the router's classified, counted outcomes and never kill the
// loop; only a portal-device failure (ErrClosed after Stop/Close) ends it.
// Start also launches the upstream-mode idle reap driver (issue #390 part 1),
// which owns reaping for engine-admitted backend sessions. Start on a running
// engine reports ErrIngressEngineStarted.
func (e *IngressEngine) Start() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return forwarder.ErrReturnPathClosed
	}
	if e.running {
		e.mu.Unlock()
		return ErrIngressEngineStarted
	}
	e.running = true
	stopCh := make(chan struct{})
	stopped := make(chan struct{})
	e.stopCh, e.stopped = stopCh, stopped
	reapStop := make(chan struct{})
	reapDone := make(chan struct{})
	e.reapStopCh, e.reapDoneCh = reapStop, reapDone
	peerSyncStop := make(chan struct{})
	peerSyncDone := make(chan struct{})
	e.peerSyncStopCh, e.peerSyncDoneCh = peerSyncStop, peerSyncDone
	e.mu.Unlock()

	go e.reapLoop(reapStop, reapDone)
	go e.peerSyncLoop(peerSyncStop, peerSyncDone)

	go func() {
		defer close(stopped)
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			pkt, err := e.portal.ReceiveOutbound()
			if err != nil {
				// The portal is closed (Stop or external shutdown):
				// the loop's only exit besides stopCh.
				return
			}
			// ReceiveOutbound hands out the TUN's internal buffer view;
			// HandlePacket finishes with the packet before the next
			// receive (the loop is single-goroutine), so no copy is
			// needed — but one is taken anyway to keep the router's
			// contract independent of the device's buffer lifetime.
			_ = e.router.HandlePacket(append([]byte(nil), pkt...))
		}
	}()
	return nil
}

// reapLoop is the upstream-mode idle reap driver (issue #390 part 1):
// upstream-only operation has no listener heartbeat, so the engine sweeps
// SessionManager.CheckTimeouts on its own cadence and hands each timed-out
// session to the service's provenance-selected reapSession — routing-only
// teardown for ingress-admitted sessions, legacy teardown for anything the
// handshake-era admission created (rollback safety). CheckTimeouts removes a
// session from the live map exactly once, so the engine's sweep and the
// custom listener's (both live only during a #394-adjacent overlap) never
// reap the same session twice. The liveness throttle map is Forget-cleaned
// for each reaped peer so it does not retain dead peers.
func (e *IngressEngine) reapLoop(stopCh <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	// Read-once at loop entry: the cadence seam (like the threshold seam)
	// is assigned before Start and never written afterwards, so capturing
	// it here orders the read before the goroutine's first tick without
	// further synchronization.
	ticker := time.NewTicker(e.reapLoopIntervalFor())
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			e.sweepOnce(context.Background())
		}
	}
}

// peerSyncLoop retries post-commit failures and repairs device drift even when
// the backend-session reaper is delayed by unrelated routing work. It calls
// reconcileNow directly (never the enqueue-style notification entry point) and
// runs on its own goroutine without Service.mu held (issue #391 round 4a,
// finding 2).
func (e *IngressEngine) peerSyncLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	interval := e.peerSyncInterval
	if interval <= 0 {
		interval = peerSyncLoopInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			_ = e.peerSync.reconcileNow(context.Background())
		}
	}
}

// sweepOnce runs one upstream-mode idle sweep. Split from reapLoop so tests
// drive single deterministic sweeps instead of waiting on the cadence.
func (e *IngressEngine) sweepOnce(ctx context.Context) {
	if e.svc == nil || e.svc.sessionMgr == nil {
		return
	}
	timedOut, err := e.svc.sessionMgr.CheckTimeouts(ctx, e.reapIdleTimeout())
	if err != nil {
		log.Printf("[vpn/ingress] upstream idle sweep failed: %v", err)
		return
	}
	for _, sess := range timedOut {
		e.svc.reapSession(ctx, sess)
		if e.liveness != nil {
			e.liveness.Forget(sess.PeerPublicKey)
		}
	}
}

// reapIdleTimeout is the sweep's idle threshold: the engine's test seam when
// assigned, the production 3-minute constant otherwise.
func (e *IngressEngine) reapIdleTimeout() time.Duration {
	if e.reapIdleTimeoutFn != nil {
		return e.reapIdleTimeoutFn(e.svc)
	}
	return reapLoopIdleTimeout(e.svc)
}

// reapLoopIdleTimeout is the idle threshold for the upstream sweep. It uses
// the same constant the service's listener config is built with (vpn.go
// NewVPNService: IdleTimeout 3m), so engine mode and legacy mode reap at
// identical latency; tests shorten it per engine via the IngressEngine's
// reapIdleTimeoutFn field (issue #390 part 2).
func reapLoopIdleTimeout(*Service) time.Duration {
	return 3 * time.Minute
}

// Stop terminates the receive loop and closes the upstream device. Idempotent;
// stopping a never-started engine still closes the portal device (the engine
// owns it from construction) and reports ErrIngressEngineNotStarted.
func (e *IngressEngine) Stop() error {
	e.mu.Lock()
	e.closed = true
	wasRunning := e.running
	stopCh, stopped := e.stopCh, e.stopped
	reapStop, reapDone := e.reapStopCh, e.reapDoneCh
	peerSyncStop, peerSyncDone := e.peerSyncStopCh, e.peerSyncDoneCh
	e.running = false
	e.stopCh, e.stopped = nil, nil
	e.reapStopCh, e.reapDoneCh = nil, nil
	e.peerSyncStopCh, e.peerSyncDoneCh = nil, nil
	e.mu.Unlock()

	if e.returnPath != nil {
		e.returnPath.Close()
	}
	// Detach the DB listener FIRST, then invalidate the enqueue path, then
	// drain the worker (issue #391 round 4b, finding 2). Order matters:
	// the enqueue path is exactly what a database notification uses, so
	// stopping the worker while the listener is still attached leaves a
	// window in which a late commit finds the enqueue path disarmed. The
	// drain then waits for the in-flight reconcile, which holds peerSync.mu
	// and may be mid-upstream-call, so it must reach quiescence before the
	// portal closes underneath it.
	// The drain is deadline-bounded: a reconcile wedged on the portal
	// device must not hang Stop, so a timeout is reported and teardown
	// proceeds (issue #391 round 4a; the worker's ctx is Background by
	// design so a portal stall cannot mask its own failure).
	if e.unsubscribePeerChanges != nil {
		e.unsubscribePeerChanges()
	}
	if e.stopPeerSyncWorker != nil {
		if err := e.stopPeerSyncWorker(); err != nil {
			log.Printf("[vpn/ingress] peer sync worker drain timed out during stop: %v", err)
		}
	}
	if stopCh != nil {
		close(stopCh)
	}
	if reapStop != nil {
		close(reapStop)
	}
	if peerSyncStop != nil {
		close(peerSyncStop)
	}
	if peerSyncDone != nil {
		<-peerSyncDone
	}
	// Close the portal so a receiver parked in ReceiveOutbound wakes up
	// (virtualtun.ErrClosed); the loop then exits via the receive error
	// even without observing stopCh. Unconditional: without it the loop
	// never exits and Stop would block forever on <-stopped.
	_ = e.portal.Close()
	if stopped != nil {
		<-stopped
	}
	if reapDone != nil {
		<-reapDone
	}
	if !wasRunning {
		return ErrIngressEngineNotStarted
	}
	return nil
}

// Router exposes the engine's router for observability (StatsSnapshot) and
// for the production-shaped integration tests. Not a seam for injecting
// alternative components — the engine owns its wiring.
func (e *IngressEngine) Router() *ingress.Router { return e.router }

// Resolver exposes the engine's durable-ownership resolver so #391's
// event-driven sync (and tests) can apply lease updates to the LIVE engine
// rather than a detached copy.
func (e *IngressEngine) Resolver() *ingress.Resolver { return e.resolver }

// PeerSyncStatus reports desired versus upstream peer state and repair errors.
func (e *IngressEngine) PeerSyncStatus() PeerSyncStatus { return e.peerSync.Status() }

// ReconcilePeers repairs runtime drift on demand from durable state. It runs
// synchronously without Service.mu held: it is the operators' and tests' "do
// one full reconciliation now and report the outcome" entry point, distinct
// from the async post-commit notification path (notifyPeerChange ->
// peerSynchronizer.ReconcilePeers), which only enqueues onto the serialized
// worker (issue #391 round 4a, finding 2).
func (e *IngressEngine) ReconcilePeers(ctx context.Context) error {
	return e.peerSync.reconcileNow(ctx)
}

// AwaitPeerRuntimeSync confirms to a CALLER that the runtime enforcement of
// the durable change it just committed actually completed, and reports the
// outcome (issue #391 round 4b, finding 4). This is the caller-visible half
// of the asynchronous post-commit design: the commit path itself stays
// non-blocking and never runs device I/O (which is what keeps it deadlock-free
// under Service.mu), and the caller learns the truth here, on its own
// goroutine, after the commit and after releasing its locks.
//
// It is bounded by the request context and by an internal deadline, so it can
// never block indefinitely; an enforcement that does not confirm in time is
// reported as database.ErrPeerRuntimeSync, never as a silent success. Callers
// MUST NOT invoke it while holding Service.mu or peerSync.mu: the worker it
// waits for takes exactly those locks.
func (e *IngressEngine) AwaitPeerRuntimeSync(ctx context.Context) error {
	return e.peerSync.AwaitPeerRuntimeSyncWithin(ctx, 0)
}

// Portal exposes the engine's upstream device for identity (public key) and
// listener status inspection.
func (e *IngressEngine) Portal() *clientawg.ClientAWGDevice { return e.portal }

// Running reports whether the receive loop is active.
func (e *IngressEngine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}
