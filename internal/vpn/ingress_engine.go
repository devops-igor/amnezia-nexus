package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

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
	svc      *Service
	portal   *clientawg.ClientAWGDevice
	resolver *ingress.Resolver
	liveness *ingress.SessionLiveness
	router   *ingress.Router

	mu             sync.Mutex
	stopCh         chan struct{}
	stopped        chan struct{}
	running        bool
	closed         bool
	returnPath     *forwarder.ReturnPath
	returnCounters returnCounters
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
// tunName labels the in-memory portal TUN; peers authorizes the upstream
// client identities (each a /32 lease mirrored in the resolver's durable
// record). The listen port in the persisted configuration is reused; the
// custom listener must NOT be running on it when the engine activates (#393
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
	cfg, err := clientawg.LoadConfig(ctx, db, virtualtun.Config{Name: tunName, MTU: 1420}, peers)
	if err != nil {
		return nil, fmt.Errorf("ingress engine: load portal configuration: %w", err)
	}
	portal, err := clientawg.NewDevice(cfg)
	if err != nil {
		return nil, fmt.Errorf("ingress engine: create portal device: %w", err)
	}

	resolver, stats, err := ingress.LoadResolver(ctx, db)
	if err != nil {
		_ = portal.Close()
		return nil, fmt.Errorf("ingress engine: load ownership resolver: %w", err)
	}
	log.Printf("[vpn/ingress] resolver loaded: %d durable leases (skipped: legacy=%d no-ip=%d unparseable=%d)",
		stats.Loaded, stats.SkippedNeedsMigration, stats.SkippedWithoutDurableIP, stats.SkippedUnparseableIP)

	// Accepted plaintext refreshes the backend routing session's LastSeen
	// through the same SessionManager the transport path touches, with the
	// same throttle window (issue #294 pattern).
	liveness := ingress.NewSessionLiveness(s.sessionMgr.TouchSession)

	e := &IngressEngine{svc: s, portal: portal, resolver: resolver, liveness: liveness}
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
// Start on a running engine reports ErrIngressEngineStarted.
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
	e.mu.Unlock()

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

// Stop terminates the receive loop and closes the upstream device. Idempotent;
// stopping a never-started engine still closes the portal device (the engine
// owns it from construction) and reports ErrIngressEngineNotStarted.
func (e *IngressEngine) Stop() error {
	e.mu.Lock()
	e.closed = true
	wasRunning := e.running
	stopCh, stopped := e.stopCh, e.stopped
	e.running = false
	e.stopCh, e.stopped = nil, nil
	e.mu.Unlock()

	if e.returnPath != nil {
		e.returnPath.Close()
	}
	if stopCh != nil {
		close(stopCh)
	}
	// Close the portal so a receiver parked in ReceiveOutbound wakes up
	// (virtualtun.ErrClosed); the loop then exits via the receive error
	// even without observing stopCh.
	_ = e.portal.Close()
	if stopped != nil {
		<-stopped
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

// Portal exposes the engine's upstream device for identity (public key) and
// listener status inspection.
func (e *IngressEngine) Portal() *clientawg.ClientAWGDevice { return e.portal }

// Running reports whether the receive loop is active.
func (e *IngressEngine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}
