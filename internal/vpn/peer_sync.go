package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// PeerSyncStatus is operational state, never a peer/key registry. Counts and
// errors remain available after a failed post-commit synchronization.
type PeerSyncStatus struct {
	DesiredPeers                int       `json:"desired_peers"`
	ActualPeers                 int       `json:"actual_peers"`
	InvalidRows                 int       `json:"invalid_rows"`
	SyncFailures                uint64    `json:"sync_failures"`
	AddFailures                 uint64    `json:"add_failures"`
	RemoveFailures              uint64    `json:"remove_failures"`
	UpdateFailures              uint64    `json:"update_failures"`
	LastSuccessfulReconcile     time.Time `json:"last_successful_reconcile"`
	LastError                   string    `json:"last_error,omitempty"`
	PortalConfigRestartRequired bool      `json:"portal_config_restart_required"`
	// EnqueueFailures and LastEnqueueError fold the post-commit enqueue
	// telemetry into the SAME observable state as the reconciliation
	// telemetry (issue #391 round 4b, finding 4): a durable change whose
	// enforcement could not even be queued is a failure of that change's
	// enforcement, and it must never be a counter that only exists
	// outside the status a reader already consults.
	EnqueueFailures  uint64 `json:"enqueue_failures"`
	LastEnqueueError string `json:"last_enqueue_error,omitempty"`

	// SyncFailuresRecent and EnqueueFailuresRecent are the increases of the
	// cumulative counters above observed in the last diagnostics sampling
	// window. Issue #424 defines these as active conditions: the cumulative
	// values remain exposed as history, but only the deltas degrade current
	// health, so a recovered incident no longer pins the status.
	SyncFailuresRecent    uint64  `json:"sync_failures_recent"`
	EnqueueFailuresRecent uint64  `json:"enqueue_failures_recent"`
	FailuresWindowSec     float64 `json:"failures_window_sec"`
}

type portalPeerDevice interface {
	Status() (clientawg.Status, error)
	AddPeer(clientawg.Peer) error
	RemovePeer(string) error
}

type peerSynchronizer struct {
	mu            sync.Mutex
	db            *database.DB
	portal        portalPeerDevice
	resolver      *ingress.Resolver
	config        clientawg.Config
	subnet        string
	settings      models.VPNConfig
	status        PeerSyncStatus
	revokeSession func(ctx context.Context, peerKey string) error
	// listActiveSessions is the live-session side of the Nexus routing
	// cleanup reconciliation (issue #391 round 4b, S1). It snapshots the
	// SessionManager under its own RLock, so cleanup can compare live
	// sessions against the desired durable peers without enumerating
	// user_connections: a DELETED connection has no row left, and both the
	// durable enumeration and removeDriftedPeers (which walks the upstream
	// device) would miss its session. Nil when no session manager is
	// attached; cleanup then falls back to the durable enumeration alone.
	listActiveSessions func() []models.VPNSession

	// Async post-commit reconciliation (issue #391 round 4a, finding 2;
	// round 4b, findings 2 and 4).
	//
	// kick is the wake function of the serialized worker. It is written
	// once by startNotifyWorker and cleared by the stop closure, and read
	// by every database commit goroutine, so it is GUARDED BY lcMu (never
	// a bare function field: an unsynchronized read/write here is both a
	// data race and the round-4a lifecycle defect).
	//
	// armed records that the enqueue path is live. It is set by
	// armEnqueue and cleared by the stop closure, under lcMu, and read
	// through armedFlag. The engine arms the enqueue path BEFORE it makes
	// the PeerChangeListener visible to the database, so there is no
	// instant at which a durable commit can reach this synchronizer and
	// find the enqueue path unarmed.
	lcMu      sync.Mutex
	lcState   peerSyncLifecycle
	armedFlag atomic.Bool
	notifySeq atomic.Int64 // notifications accepted (armed or rejected)
	doneSeq   atomic.Int64 // notifications whose enforcement has finished
	// convergeErr is the outcome of the most recently completed
	// enforcement pass, published together with doneSeq under lcMu so a
	// convergence waiter never reads a sequence and an error from
	// different passes.
	convergeErr error
	// convergeCh is the convergence broadcast channel, guarded by lcMu.
	// Each publication closes it and installs a fresh one, so a waiter
	// always selects on a channel the next completion closes.
	convergeCh    chan struct{}
	stoppedFlag   atomic.Bool
	timeouts      atomic.Uint64
	pending       atomic.Int64 // queued-not-yet-started reconciles
	running       atomic.Bool  // worker currently inside reconcileNow
	enqueueFails  atomic.Uint64
	lastEnqueueEr atomic.Value // string
}

// peerSyncLifecycle is the enqueue path's mutable state, guarded by
// peerSynchronizer.lcMu.
type peerSyncLifecycle struct {
	kick  func()
	armed bool
}

func newPeerSynchronizer(db *database.DB, portal portalPeerDevice, resolver *ingress.Resolver, cfg clientawg.Config, settings *models.VPNConfig, revokeSession func(ctx context.Context, peerKey string) error, listActiveSessions func() []models.VPNSession) *peerSynchronizer {
	return &peerSynchronizer{
		db:                 db,
		portal:             portal,
		resolver:           resolver,
		config:             cfg,
		subnet:             settings.SubnetCIDR,
		settings:           *settings,
		revokeSession:      revokeSession,
		listActiveSessions: listActiveSessions,
	}
}

// startNotifyWorker launches the serialized post-commit reconcile worker and
// arms the non-blocking enqueue path in the same critical section
// (issue #391 round 4b, finding 2). Arming is not a separate step the engine
// performs later: worker and enqueue path become live together, so there is no
// instant at which the enqueue path exists but is disarmed, and no instant at
// which it is armed before the worker can serve it.
//
// The worker owns one reconcile at a time; a burst of commits coalesces into
// at most one queued reconcile. The returned stop function invalidates the
// enqueue path, wakes the worker, and waits for the current reconcile to
// finish, so no reconcile runs after the portal closes. The drain is
// deadline-bounded: a reconcile stuck on an unresponsive portal device must
// never make Stop unreturnable, so stop reports a drain-timeout error instead
// of waiting forever. Stop is idempotent: an engine that never started or
// already stopped the worker may still be asked to stop through the same
// teardown path.
//
// The engine MUST detach the database listener before calling stop (see
// IngressEngine.Stop): the enqueue path is what a database notification uses,
// and it must never be found disarmed while a notification can still arrive.
func (s *peerSynchronizer) startNotifyWorker() (stop func() error, err error) {
	s.lcMu.Lock()
	if s.lcState.kick != nil {
		s.lcMu.Unlock()
		return nil, errors.New("peer sync notify worker already started")
	}
	// wake is the capacity-1 coalescing token channel: kick's non-blocking
	// send queues at most one pending reconcile per burst and never blocks,
	// even when the worker is mid-reconcile. Shutdown uses a separate
	// stopCh that stop closes: the worker never ranges over a channel the
	// sender can rewrite or close, so the drain cannot hang on a nil or
	// closed-channel receive race (the round-4a Stop hang).
	wake := make(chan struct{}, 1)
	s.lcState = peerSyncLifecycle{
		kick: func() {
			select {
			case wake <- struct{}{}:
			default:
				// A reconcile is already queued or running: coalesced.
				// The queued run re-reads durable state afresh, so it
				// observes every commit that happened before it
				// started. Never blocks: safe from under Service.mu.
			}
		},
		armed: true,
	}
	s.armedFlag.Store(true)
	s.lcMu.Unlock()

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopCh:
				return
			case <-wake:
				// This run serves exactly one enqueued token; counts
				// whose kick coalesced into it are re-armed after the
				// run so the backlog always drains. The pass re-reads
				// durable state, so it covers every notification
				// accepted before it started: snapshot the sequence
				// here, before the pass, and publish that watermark
				// with the pass outcome below.
				covered := s.notifySeq.Load()
				s.running.Store(true)
				s.pending.Add(-1)
				err := s.reconcileNow(context.Background())
				s.running.Store(false)
				s.publishConvergence(covered, err)
				if s.pending.Load() > 0 {
					select {
					case wake <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	var stopOnce sync.Once
	return func() error {
		// Idempotent: teardown paths may stop an already-stopped worker.
		stopOnce.Do(func() {
			// Invalidate the enqueue path under lcMu, so a concurrent
			// notification either observed the armed state and enqueued
			// before this point, or observes the disarmed state and
			// records a visible enqueue failure. There is no unsynchronized
			// window in which kick is read half-written.
			s.lcMu.Lock()
			s.lcState = peerSyncLifecycle{}
			s.lcMu.Unlock()
			s.armedFlag.Store(false)
			s.stoppedFlag.Store(true)
			// Closing stopCh releases a parked worker immediately; an
			// in-flight reconcile is awaited below up to
			// peerSyncDrainTimeout so a portal device wedged in a
			// blocking call cannot hang Stop.
			close(stopCh)
			// Release any convergence waiter: no further pass will ever
			// cover the notifications still outstanding, so they must be
			// failed explicitly rather than waited out to a timeout.
			s.failOutstandingConvergence()
		})
		select {
		case <-done:
			return nil
		case <-time.After(peerSyncDrainTimeout):
			return fmt.Errorf("peer sync worker did not drain within %s; engine stop proceeds", peerSyncDrainTimeout)
		}
	}, nil
}

// peerSyncDrainTimeout bounds the stop-time wait for an in-flight reconcile.
// Production reconciles complete in far less; the bound exists so a portal
// device wedged in a blocking call cannot turn engine Stop into a hang
// (issue #391 round 4a). It is a variable so tests can shorten it.
var peerSyncDrainTimeout = 30 * time.Second

// peerSyncConvergeTimeout bounds the caller-visible convergence wait
// (issue #391 round 4b, finding 4). A handler asks the worker to confirm the
// enforcement of the change it just committed; the worker does the device
// I/O, so the handler only ever waits, and it waits for at most this long.
// Exceeding it is reported to the caller as an unconfirmed enforcement (the
// same runtime_sync_failed envelope a failed pass produces), never as a hang
// and never as a silent success.
var peerSyncConvergeTimeout = 10 * time.Second

// enqueuePeerReconcile is the PeerChangeListener notification
// implementation (issue #391 round 4a, finding 2; round 4b, findings 2 and
// 4): it only records the notification and wakes the serialized worker, then
// returns immediately, so the database commit goroutine — which may hold
// Service.mu during legacy admission (HandleIncomingPeer ->
// resolveOrAllocatePeerIP -> UpdateConnection) — never blocks on runtime
// device I/O and never re-enters a runtime lock.
//
// It NEVER falls back to reconciling inline. The round-4b invariant is
// absolute: while the database can see this synchronizer, the enqueue path is
// armed, so the fallback could only ever be reached from the shutdown window
// (listener still attached, worker already stopped), where running the
// reconciliation on the committing goroutine is exactly the deadlock and
// post-close device I/O this design exists to prevent. A disarmed enqueue is
// therefore recorded as a visible failure, both in the enqueue telemetry and
// as the outcome of a convergence wait, so a caller is told the truth.
func (s *peerSynchronizer) enqueuePeerReconcile() {
	seq := s.notifySeq.Add(1)
	s.lcMu.Lock()
	kick, armed := s.lcState.kick, s.lcState.armed
	s.lcMu.Unlock()
	if !armed || kick == nil {
		reason := "peer sync notify worker is not running"
		if s.stoppedFlag.Load() {
			reason = "peer sync notify worker stopped before enforcement"
		}
		s.recordEnqueueFailure(reason)
		// The notification is accounted for as FAILED, not merely
		// dropped: a convergence waiter must not block until its timeout
		// on a notification that will never be served.
		s.publishConvergence(seq, errPeerSyncNotEnqueued(reason))
		return
	}
	s.pending.Add(1)
	kick()
}

// errPeerSyncNotEnqueued marks a notification whose enforcement could not be
// queued at all (the worker is not running). It is a runtime enforcement
// failure of that durable change, exactly like a failed pass, so it reaches
// the caller through the same runtime_sync_failed envelope.
func errPeerSyncNotEnqueued(reason string) error {
	return fmt.Errorf("%w: %s", database.ErrPeerRuntimeSync, reason)
}

// publishConvergence records the outcome of one enforcement pass and wakes
// every convergence waiter. The sequence watermark and the error are published
// together under lcMu so a waiter can never observe a watermark from one pass
// with an error from another.
func (s *peerSynchronizer) publishConvergence(covered int64, err error) {
	s.lcMu.Lock()
	defer s.lcMu.Unlock()
	if covered > s.doneSeq.Load() {
		s.convergeErr = err
		s.doneSeq.Store(covered)
	}
	s.signalConvergenceLocked()
}

// failOutstandingConvergence fails every notification that no pass will ever
// cover, because the worker is stopping. Waiters are released immediately
// with the stop reason instead of waiting out their timeout.
func (s *peerSynchronizer) failOutstandingConvergence() {
	s.lcMu.Lock()
	defer s.lcMu.Unlock()
	if outstanding := s.notifySeq.Load(); outstanding > s.doneSeq.Load() {
		s.convergeErr = errPeerSyncNotEnqueued("peer sync notify worker stopped before enforcement completed")
		s.doneSeq.Store(outstanding)
	}
	s.signalConvergenceLocked()
}

// signalConvergenceLocked wakes blocked convergence waiters. The broadcast
// channel is closed and replaced under lcMu, so a waiter always selects on a
// channel that the next publication closes.
func (s *peerSynchronizer) signalConvergenceLocked() {
	if s.convergeCh == nil {
		return
	}
	close(s.convergeCh)
	s.convergeCh = make(chan struct{})
}

func (s *peerSynchronizer) recordEnqueueFailure(reason string) {
	s.enqueueFails.Add(1)
	s.lastEnqueueEr.Store(reason)
	log.Printf("[vpn/peer-sync] post-commit reconcile enqueue failed: %s", reason)
}

// setPortalDeviceForTest swaps the upstream device under s.mu. Tests must use
// this instead of assigning s.portal directly: the notify worker may be inside
// reconcileNow (which holds s.mu for the whole pass) at any moment, so a bare
// field write is a data race. The swap takes effect on the next reconcile.
func (s *peerSynchronizer) setPortalDeviceForTest(device portalPeerDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.portal = device
}

// EnqueueFailures reports how many post-commit reconcile requests could not
// be queued and the most recent reason. Never silently zero when nonzero.
// The same numbers are folded into PeerSyncStatus, which is the state an
// operator (and the caller-visible reporting of finding 4) reads.
func (s *peerSynchronizer) EnqueueFailures() (uint64, string) {
	reason, _ := s.lastEnqueueEr.Load().(string)
	return s.enqueueFails.Load(), reason
}

// quiesceNotifyWorker waits until every notification enqueued so far has
// been executed to completion: pending is drained and no reconcile is
// running. Pending counts queued-not-yet-started reconciles only; the
// running flag covers the in-flight one, so the conjunction is exact. It is
// a deterministic test seam for the asynchronous post-commit enforcement:
// call it after a durable change instead of sleeping. Never call it from a
// goroutine that holds peerSync.mu or Service.mu.
func (s *peerSynchronizer) quiesceNotifyWorker() {
	for s.pending.Load() > 0 || s.running.Load() {
		time.Sleep(time.Millisecond)
	}
}

func (s *peerSynchronizer) Status() PeerSyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.status
	// Enqueue telemetry converges into the same observable state as the
	// reconciliation telemetry (finding 4): one status, not a counter that
	// only a test can reach.
	status.EnqueueFailures = s.enqueueFails.Load()
	status.LastEnqueueError, _ = s.lastEnqueueEr.Load().(string)
	return status
}

// ReconcilePeers is the PeerChangeListener notification entry point
// (issue #391 round 4b, finding 2). It NEVER reconciles inline and NEVER
// blocks: it records the notification, wakes the serialized worker, and
// returns. A database notification can arrive on a commit goroutine that
// holds Service.mu (legacy admission) and during the construction and
// shutdown windows, so there is no arrangement of this method in which
// running the reconciliation on the caller's goroutine would be correct.
//
// It reports no error: the commit is already durable, and the outcome of the
// enforcement it requested is reported through AwaitPeerRuntimeSync, which
// the caller invokes AFTER releasing every lock (finding 4).
func (s *peerSynchronizer) ReconcilePeers(context.Context) error {
	s.enqueuePeerReconcile()
	return nil
}

// AwaitPeerRuntimeSync blocks until the enforcement of every notification
// accepted so far has completed, and reports its outcome
// (issue #391 round 4b, finding 4). It is the caller-visible half of the
// asynchronous design: the durable commit path stays non-blocking and
// lock-free, and the caller learns the truth from a path that runs on its own
// goroutine, after the commit and after any locks were released.
//
// The call performs NO runtime device I/O itself: the worker goroutine does,
// which is what keeps this deadlock-free. It is bounded by
// peerSyncConvergenceTimeout and by ctx, so it can never block
// indefinitely; a bound that is exceeded is reported as an unconfirmed
// enforcement (a database.ErrPeerRuntimeSync-wrapped error), never as a
// silent success.
//
// It MUST NOT be called while holding peerSync.mu or Service.mu: the worker
// it waits for takes exactly those locks.
// AwaitPeerRuntimeSync implements database.PeerRuntimeConvergence on the
// synchronizer itself (not only on the engine wrapper), so the database's
// convergence confirmation reaches the live worker through the very listener
// it already holds. See the method on IngressEngine for the caller contract.
func (s *peerSynchronizer) AwaitPeerRuntimeSync(ctx context.Context) error {
	return s.AwaitPeerRuntimeSyncWithin(ctx, 0)
}

// AwaitPeerRuntimeSyncWithin is AwaitPeerRuntimeSync with an explicit bound;
// a non-positive timeout selects peerSyncConvergeTimeout. It exists so the
// engine can delegate without re-deciding the deadline, and so tests can pin a
// short bound.
func (s *peerSynchronizer) AwaitPeerRuntimeSyncWithin(ctx context.Context, timeout time.Duration) error {
	if s == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = peerSyncConvergeTimeout
	}
	target := s.notifySeq.Load()
	// GLOBAL WATERMARK (reviewed and accepted for round 4b): the target is
	// every notification accepted so far, not strictly this caller's own.
	// A caller therefore confirms enforcement of all commits that preceded
	// its own call, and may be told about a CONCURRENT change's enforcement
	// failure as if it were its own. That is deliberate and conservative: it
	// can only ever cause a handler to report a failure that genuinely
	// happened, never to swallow one. A notification accepted after this
	// snapshot belongs to a later change and is not waited for.
	if s.doneSeq.Load() >= target {
		return s.convergenceOutcome()
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		s.lcMu.Lock()
		ch := s.convergeCh
		if ch == nil {
			ch = make(chan struct{})
			s.convergeCh = ch
		}
		done := s.doneSeq.Load()
		s.lcMu.Unlock()
		if done >= target {
			return s.convergenceOutcome()
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return fmt.Errorf("%w: convergence wait canceled: %v", database.ErrPeerRuntimeSync, ctx.Err())
		case <-deadline.C:
			s.timeouts.Add(1)
			log.Printf("[vpn/peer-sync] post-commit enforcement did not converge within %s", timeout)
			return fmt.Errorf("%w: post-commit enforcement did not converge within %s", database.ErrPeerRuntimeSync, timeout)
		}
	}
}

// convergenceOutcome reads the published outcome of the pass that covered the
// caller's notification.
func (s *peerSynchronizer) convergenceOutcome() error {
	s.lcMu.Lock()
	defer s.lcMu.Unlock()
	err := s.convergeErr
	if err == nil {
		return nil
	}
	if errors.Is(err, database.ErrPeerRuntimeSync) {
		return err
	}
	return fmt.Errorf("%w: %v", database.ErrPeerRuntimeSync, err)
}

// ConvergeTimeouts reports how many caller-visible convergence waits hit their
// bound without the enforcement completing. Never silently zero when nonzero.
func (s *peerSynchronizer) ConvergeTimeouts() uint64 { return s.timeouts.Load() }

// ValidatePortalConfig requires a controlled stop/restart for changes to
// upstream listener parameters. Ordinary LB and queue setting changes remain
// live. The guard runs before SaveVPNConfig commits, so callers cannot receive
// an apparent successful config update while the active device still uses old
// AWG parameters.
func (s *peerSynchronizer) ValidatePortalConfig(cfg *models.VPNConfig) error {
	if cfg == nil {
		return errors.New("nil VPN configuration")
	}
	p := s.settings
	if cfg.ServerPublicKey != p.ServerPublicKey || cfg.ListenPort != p.ListenPort ||
		cfg.SubnetCIDR != p.SubnetCIDR || cfg.H1.String() != p.H1.String() || cfg.H2.String() != p.H2.String() ||
		cfg.H3.String() != p.H3.String() || cfg.H4.String() != p.H4.String() || cfg.S1 != p.S1 || cfg.S2 != p.S2 ||
		cfg.S3 != p.S3 || cfg.S4 != p.S4 || cfg.HeaderProtectionKey != p.HeaderProtectionKey ||
		cfg.ContentPaddingAddition != p.ContentPaddingAddition ||
		cfg.RandomTrailers != p.RandomTrailers || cfg.DisableCookies != p.DisableCookies {
		return errors.New("portal AWG parameters require stopping the upstream listener before update and restarting it afterward")
	}
	return nil
}

type desiredPeer struct {
	peer  clientawg.Peer
	owner ingress.PeerOwnership
}

func (s *peerSynchronizer) desired(ctx context.Context) (map[string]desiredPeer, int, error) {
	users, err := s.db.GetAllUsers(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read users: %w", err)
	}
	connections, err := s.db.GetAllConnections(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read connections: %w", err)
	}
	block, err := netip.ParsePrefix(s.subnet)
	if err != nil || !block.Addr().Is4() {
		return nil, 0, errors.New("invalid persisted portal subnet")
	}
	block = block.Masked()
	userByID := make(map[string]models.User, len(users))
	for _, user := range users {
		userByID[user.ID] = user
	}
	result := make(map[string]desiredPeer)
	keyCount := make(map[string]int)
	ipCount := make(map[netip.Addr]int)
	invalid := 0
	now := time.Now()
	for _, c := range connections {
		if c.ServerID != 0 || models.NormalizeProtocol(c.Protocol) != "awg" {
			continue
		}
		u, exists := userByID[c.UserID]
		if !exists || !eligiblePeer(u, c, now) {
			continue
		}
		candidate, present, valid := s.peerFromConnection(c, block)
		// An entirely blank row is normal during config issuance. A
		// half-populated row is excluded and reported for repair.
		if !present {
			continue
		}
		if !valid {
			invalid++
			continue
		}
		keyCount[c.ClientID]++
		ipCount[candidate.owner.IP]++
		result[c.ID] = candidate
	}
	byKey := make(map[string]desiredPeer, len(result))
	for _, candidate := range result {
		if keyCount[candidate.peer.PublicKey] != 1 || ipCount[candidate.owner.IP] != 1 {
			invalid++
			continue
		}
		byKey[candidate.peer.PublicKey] = candidate
	}
	return byKey, invalid, nil
}

func eligiblePeer(u models.User, c models.UserConnection, now time.Time) bool {
	return u.Enabled &&
		(u.ExpiresAt == nil || u.ExpiresAt.IsZero() || !now.After(*u.ExpiresAt)) &&
		(u.ExpirationDate == nil || u.ExpirationDate.IsZero() || !now.After(*u.ExpirationDate)) &&
		(u.TrafficLimit <= 0 || u.TrafficUsed < u.TrafficLimit) &&
		c.ClientParams["disabled"] != true && c.ClientParams["config_regeneration_required"] != true &&
		c.ClientParams["quarantined_ip_collision"] == nil
}

func (s *peerSynchronizer) peerFromConnection(c models.UserConnection, block netip.Prefix) (desiredPeer, bool, bool) {
	ipText, _ := c.ClientParams["assigned_ip"].(string)
	if c.ClientID == "" && ipText == "" {
		return desiredPeer{}, false, false
	}
	if c.ClientID == "" || ipText == "" {
		return desiredPeer{}, true, false
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil || !ip.Is4() || !block.Contains(ip) || ip == block.Addr() ||
		ip == block.Addr().Next() || isIPv4Broadcast(block, ip) {
		return desiredPeer{}, true, false
	}
	peer := clientawg.Peer{PublicKey: c.ClientID, AllowedIP: netip.PrefixFrom(ip, 32)}
	if clientawg.ValidatePeer(peer, s.config.PublicKey) != nil {
		return desiredPeer{}, true, false
	}
	return desiredPeer{peer: peer, owner: ingress.PeerOwnership{
		PeerPublicKey: c.ClientID, ConnectionID: c.ID, UserID: c.UserID, IP: ip,
	}}, true, true
}

func isIPv4Broadcast(block netip.Prefix, ip netip.Addr) bool {
	bits := block.Bits()
	if bits >= 31 {
		return true
	}
	a := block.Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	mask := uint32(1)<<(32-bits) - 1
	b := ip.As4()
	w := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return w == v|mask
}

// reconcileNow runs one full reconciliation synchronously. It takes
// peerSync.mu and, through the revokeSession callback, Service.mu; it must
// therefore never run while Service.mu is held (issue #391 round 4a,
// finding 2).
//
// It derives desired state afresh and repairs the runtime to match it,
// fail-closed during identity transitions (issue #391 round 4a, finding 1):
// upstream peers that are retired, or whose AllowedIP is about to move, have
// their plaintext-route ownership withdrawn BEFORE the old key is torn down
// upstream, so an old peer's traffic can never be attributed to the
// replacement identity that keeps the same assigned IP. A failed transition
// leaves the affected IPs unauthorized (resolver lookups miss, packets drop)
// until a later reconcile installs and verifies the replacement. Stable
// untouched peers keep their ownership and upstream state (no flap for
// unaffected clients). On a failed durable read ownership is still fully
// withdrawn. The upstream device's Status is the only source used for actual
// peer state.
func (s *peerSynchronizer) reconcileNow(ctx context.Context) error {
	// The immutable collaborators are checked before locking; s.portal is
	// read only under s.mu, because setPortalDeviceForTest may swap it while
	// the notify worker is mid-reconcile.
	if s == nil || s.db == nil || s.resolver == nil {
		return errors.New("peer synchronizer is not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.portal == nil {
		return errors.New("peer synchronizer is not initialized")
	}
	configDrift := s.portalConfigDrift(ctx)
	s.status.PortalConfigRestartRequired = configDrift != nil
	desired, invalid, err := s.desired(ctx)
	if err != nil {
		// A failed durable read cannot justify keeping stale plaintext
		// ownership, especially just after a committed revocation.
		_ = s.resolver.Replace(nil)
		return s.fail(err)
	}
	if invalid > 0 && invalid != s.status.InvalidRows {
		log.Printf("[vpn/peer-sync] excluded %d invalid or conflicting durable portal peer rows", invalid)
	}
	s.status.DesiredPeers, s.status.InvalidRows = len(desired), invalid

	current, err := s.portal.Status()
	if err != nil {
		// Fail CLOSED (issue #391 round 4c, F2). The upstream peer set is
		// UNKNOWN here, so nothing about the device may be assumed or
		// mutated: no AddPeer, no RemovePeer, no verification. But the
		// DURABLE desired set is known, and it alone decides who is
		// authorized. Withdrawal of newly-ineligible authorization, and
		// retirement of the Nexus routing sessions that authorization
		// backed, therefore run BEFORE returning, so an upstream status
		// failure can never be the reason a peer the durable state has
		// stopped authorizing keeps passing traffic. Only the withdrawal
		// half runs here: the device converges on the next pass that can
		// actually read it.
		failures := s.failClosedWithoutStatus(ctx, desired)
		failures = append(failures, err)
		return s.fail(errors.Join(failures...))
	}
	actual := make(map[string]clientawg.PeerStatus, len(current.Peers))
	for _, peer := range current.Peers {
		actual[peer.PublicKey] = peer
	}
	s.status.ActualPeers = len(actual)

	// Classify actual upstream peers (finding 1, step 1):
	//   stable  - same key, same AllowedIP, present in desired
	//   handoff - same key, same AllowedIP, present in desired, but the
	//             durable OWNER moved (issue #391 round 4c, F1: a live
	//             connection reassigned to another user, or its durable row
	//             recreated under a new connection id). Key and AllowedIP
	//             are byte-identical across such a move, so an
	//             AllowedIP-only comparison cannot see it and the previous
	//             owner's live session looked stable. A handoff is NOT
	//             stable and NOT retired: the upstream peer is already
	//             exactly right, so it is neither removed nor re-added.
	//   retired - everything else: not desired at all, or desired with a
	//             different AllowedIP (a key-stable transition whose old
	//             assignment must be withdrawn before the new install).
	stableActual := make(map[string]clientawg.PeerStatus, len(actual))
	var retireKeys []string
	var handoffKeys []string
	for key, have := range actual {
		want, isDesired := desired[key]
		switch {
		case !isDesired || want.peer.AllowedIP != have.AllowedIP:
			retireKeys = append(retireKeys, key)
		case !s.ownershipUnchanged(want.owner):
			handoffKeys = append(handoffKeys, key)
		default:
			stableActual[key] = have
		}
	}
	sort.Strings(retireKeys)
	sort.Strings(handoffKeys)

	// Withdraw resolver ownership only for IPs involved in transitions
	// (finding 1, step 2): retired upstream keys and pending-new desired
	// peers whose IP an upstream entry may still occupy under a different
	// key or with a different assignment. Stable untouched peers keep
	// their ownership.
	transitionIPs := make(map[netip.Addr]struct{})
	removed := make([]string, 0, len(retireKeys))
	for _, key := range retireKeys {
		if ip, tracked := s.resolver.Remove(key); tracked {
			transitionIPs[ip] = struct{}{}
		}
		removed = append(removed, key)
	}
	pendingKeys := make([]string, 0, len(desired))
	for key := range desired {
		if _, isStable := stableActual[key]; isStable {
			continue
		}
		pendingKeys = append(pendingKeys, key)
	}
	sort.Strings(pendingKeys)
	for _, key := range pendingKeys {
		transitionIPs[desired[key].owner.IP] = struct{}{}
	}
	transitionAddrs := make([]netip.Addr, 0, len(transitionIPs))
	for ip := range transitionIPs {
		transitionAddrs = append(transitionAddrs, ip)
	}
	sort.Slice(transitionAddrs, func(i, j int) bool { return transitionAddrs[i].Less(transitionAddrs[j]) })
	for _, owner := range s.resolver.FilterIPs(transitionAddrs) {
		// The replacement key's own entry is absent until verification
		// publishes the desired map, so removing whatever currently maps
		// a transition IP cannot evict a verified owner.
		s.resolver.Remove(owner.PeerPublicKey)
	}

	// Retire the previous owner's routing session for every handoff, using
	// the same revokeSession callback the retirement path uses so the
	// session, its forwarder route and the backend gauge move exactly once
	// (F1). Their upstream peers are already correct, so nothing is removed
	// or re-added for them: the handoff costs one Nexus-side re-admission,
	// not an AWG protocol churn.
	failures := s.retireHandoffSessions(ctx, handoffKeys)
	failures = append(failures, s.removeDriftedPeers(ctx, actual, desired, stableActual)...)
	failures = append(failures, s.addMissingPeers(actual, desired)...)

	// Verify the upstream device against the desired set (finding 1,
	// steps 5-6): only after verification may ownership be published.
	failures = append(failures, s.verifyPeers(desired)...)

	// Desired-set-driven Nexus routing cleanup (finding 4): independent
	// of upstream peer presence. A missing upstream peer must never
	// suppress Nexus session/route/accounting cleanup.
	failures = append(failures, s.cleanupOrphanedRouting(ctx, desired, removed)...)

	if configDrift != nil {
		failures = append(failures, configDrift)
	}
	if len(failures) != 0 {
		return s.fail(errors.Join(failures...))
	}

	// Publish the full desired ownership map only now (finding 1, step 7):
	// every desired peer is installed upstream and verified, and no
	// retired key remains authorized or upstream-configured. Until this
	// line, transition IPs resolve to nothing and their packets drop.
	owners := make([]ingress.PeerOwnership, 0, len(desired))
	for _, entry := range desired {
		owners = append(owners, entry.owner)
	}
	if err := s.resolver.Replace(owners); err != nil {
		return s.fail(err)
	}
	s.status.LastSuccessfulReconcile = time.Now().UTC()
	s.status.LastError = ""
	return nil
}

// ownershipAgrees reports whether a resolver record and a desired owner are
// the SAME authorization: same peer, same connection, same user, and —
// critically — the same assigned address.
//
// The assigned address is part of the answer, not decoration. A record is
// looked up by the address it authorizes, so a record whose address the
// durable state has since given to a DIFFERENT peer is not agreement even when
// key, connection and user all match: leaving it installed would keep
// authorizing a source IP the durable state has reassigned to someone else.
//
// Both ownership decision sites (the F1 classification and the F2
// fail-closed withdrawal) go through this one predicate on purpose. When they
// were written separately the withdrawal path compared user and connection
// only, and a peer whose address merely MOVED kept its authorization under a
// status failure — the same cross-user attribution F1 exists to prevent.
func ownershipAgrees(published, want ingress.PeerOwnership) bool {
	return published.PeerPublicKey == want.PeerPublicKey &&
		published.UserID == want.UserID &&
		published.ConnectionID == want.ConnectionID &&
		published.IP == want.IP
}

// ownershipUnchanged reports whether the resolver's currently published
// record for this peer's desired address already is the desired ownership
// (issue #391 round 4c, F1). The upstream device says nothing about
// ownership — a peer key and its AllowedIP are byte-identical across a user
// reassignment and across a connection-row recreation — so the resolver is
// the only place the PREVIOUS owner is still observable.
//
// A peer the resolver does not track at all has no published owner and
// therefore nothing to transition away from: it is treated as unchanged, so
// the normal pending-install path (withdraw, install, verify, publish)
// handles it. That is the first-install and post-crash case, and it must
// not be mistaken for an ownership transition. "Unchanged" here therefore
// means "no previous owner to move away from", NOT "already verified".
func (s *peerSynchronizer) ownershipUnchanged(want ingress.PeerOwnership) bool {
	published, tracked := s.resolver.Lookup(want.IP)
	if !tracked {
		return true
	}
	// A record for this address under a DIFFERENT peer key fails the
	// comparison inside ownershipAgrees: the address now answers for
	// someone else.
	return ownershipAgrees(published, want)
}

// retireHandoffSessions revokes the routing session of every peer whose
// durable owner moved while its upstream identity stayed identical (F1).
// The keys arrive already sorted, so the teardown order is deterministic and
// two handoffs can never interleave.
//
// The withdrawal of the previous owner's authorization has already happened
// (the handoff's assigned IP is in transitionIPs), so at this point the old
// session can no longer admit or forward anything: revoking it is pure
// cleanup, and the next packet re-admits under the new owner once the
// verified desired map is published.
func (s *peerSynchronizer) retireHandoffSessions(ctx context.Context, keys []string) []error {
	if s.revokeSession == nil {
		return nil
	}
	var failures []error
	for _, key := range keys {
		if err := s.revokeSession(ctx, key); err != nil {
			failures = append(failures, fmt.Errorf("retire reassigned session %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

// failClosedWithoutStatus withdraws the authorization the durable state no
// longer supports, and retires the Nexus routing sessions that authorization
// backed, WITHOUT consulting the upstream device (issue #391 round 4c, F2).
// It is the fail-closed half of a pass whose Status read failed.
//
// Why this placement is fail-closed: the durable desired set is authoritative
// for WHO may be authorized, and it is available on this path — it is derived
// before the device is ever called. The upstream peer set is not available,
// and this function never guesses it: it makes no AddPeer, RemovePeer or
// verify call, so it cannot install, evict or mis-attribute anything it
// cannot see. Authorization is therefore narrowed to exactly what durable
// state still endorses, and every routing session belonging to a withdrawn or
// reassigned peer is revoked through the same revokeSession callback the
// success path uses (so accounting moves exactly once, under the same
// Service.mu discipline). Peers that remain durably eligible keep their
// ownership and their sessions: a status failure is not a reason to
// disconnect everyone.
//
// On the next successful pass the device converges normally: peers the
// durable state still desires are verified and republished, and the ones it
// no longer desires are removed upstream then. Nothing here needs undoing.
func (s *peerSynchronizer) failClosedWithoutStatus(ctx context.Context, desired map[string]desiredPeer) []error {
	// The installed set is exactly the set of peers that can still authorize
	// a source IP, and unlike the upstream peer set it is fully answerable
	// here. Every record in it that disagrees with the durable desired set is
	// authorization the durable state no longer endorses — either the peer is
	// not desired at all, or it is desired under a different owner — and both
	// are withdrawn.
	withdrawn := make([]string, 0)
	for _, published := range s.resolver.Snapshot() {
		want, stillDesired := desired[published.PeerPublicKey]
		// The SAME predicate the success path classifies with, so the two
		// can never disagree about who is authorized. The assigned address
		// is compared too: a record whose address the durable state has
		// given to another peer is not agreement.
		if stillDesired && ownershipAgrees(published, want.owner) {
			continue
		}
		withdrawn = append(withdrawn, published.PeerPublicKey)
	}
	sort.Strings(withdrawn)
	var failures []error
	for _, key := range withdrawn {
		if _, tracked := s.resolver.Remove(key); !tracked {
			continue
		}
		if s.revokeSession == nil {
			continue
		}
		if err := s.revokeSession(ctx, key); err != nil {
			failures = append(failures, fmt.Errorf("revoke session %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

// cleanupOrphanedRouting runs the routing-only teardown for live
// portal-scope routing sessions whose peer is no longer desired, exactly
// once per session lifecycle, through the same revokeSession callback the
// upstream removal path uses (issue #391 round 4a, finding 4). It runs
// regardless of upstream peer presence: a peer that already vanished from
// the upstream device must not keep its Nexus session, forwarder route,
// or backend accounting alive. Only portal-scope sessions are considered:
// sessions of regular server peers and legacy server tunnels are not this
// engine's domain.
//
// The reconciliation is between the LIVE sessions in the SessionManager and
// the desired durable peers, NOT between user_connections and the desired set
// (issue #391 round 4b, S1). A DELETED connection has no user_connections
// row left, so a durable-row-driven enumeration never saw its peer key, and
// with the upstream peer also gone removeDriftedPeers never saw it either:
// neither path revoked, so the session, its forwarder route and the backend
// ActiveConnections counter leaked while reconciliation reported success.
// A missing upstream peer AND a missing durable row must never suppress
// exactly-once Nexus-side teardown, so live sessions are enumerated in their
// own right here.
//
// Portal scope of a live session is resolved without the durable row when the
// row can no longer answer: an ingress-admitted session is by construction an
// ingress-engine peer, and a direct-admitted session is classified against
// its durable connection (server_id 0, awg) exactly as before. A direct
// session whose durable row is gone is NOT revoked here: it belongs to the
// post-commit revoke path, which captured the identity before the delete
// (issue #391 round 4b, finding 1).
func (s *peerSynchronizer) cleanupOrphanedRouting(ctx context.Context, desired map[string]desiredPeer, alreadyRevoked []string) []error {
	if s.revokeSession == nil {
		return nil
	}
	// The durable portal-key set still contributes: it covers a live session
	// whose peer is no longer desired while its row is still present (the
	// toggle-to-disabled case) and keeps the classification authoritative
	// for direct-admitted sessions.
	portalKeys := make(map[string]struct{})
	if s.db != nil {
		assignments, err := s.db.GetVPNClientIPAssignments(ctx)
		if err != nil {
			return []error{fmt.Errorf("enumerate portal client assignments: %w", err)}
		}
		for _, a := range assignments {
			if a.PeerKey == "" {
				continue
			}
			portalKeys[a.PeerKey] = struct{}{}
		}
	}
	// The live session set is the other side of the reconciliation and is
	// independent of the durable rows.
	liveKeys, err := s.livePortalSessionKeys(ctx, portalKeys)
	if err != nil {
		return []error{err}
	}
	for key := range liveKeys {
		portalKeys[key] = struct{}{}
	}
	revoked := make(map[string]struct{}, len(alreadyRevoked))
	for _, key := range alreadyRevoked {
		revoked[key] = struct{}{}
	}
	keys := make([]string, 0, len(portalKeys))
	for key := range portalKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var failures []error
	for _, key := range keys {
		if _, ok := desired[key]; ok {
			continue
		}
		if _, done := revoked[key]; done {
			continue
		}
		if err := s.revokeSession(ctx, key); err != nil {
			failures = append(failures, fmt.Errorf("revoke session %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

// livePortalSessionKeys returns the peer keys of the currently live sessions
// that are this engine's domain. It is the live-session side of
// cleanupOrphanedRouting's reconciliation (issue #391 round 4b, S1) and is
// what makes a DELETED connection's session visible to cleanup at all.
//
// A session is in scope when it is connected, has a peer key, and either
// already appears in known (a portal durable connection is present) or is
// ingress-admitted (the ingress engine only ever admits its own portal
// peers, so this needs no durable row). Every other session — a regular
// server peer, a legacy server tunnel, a direct session whose row is gone
// — is left to its own lifecycle.
func (s *peerSynchronizer) livePortalSessionKeys(ctx context.Context, known map[string]struct{}) (map[string]struct{}, error) {
	if s.listActiveSessions == nil {
		return nil, nil
	}
	keys := make(map[string]struct{})
	for _, sess := range s.listActiveSessions() {
		if sess.Status != "connected" || sess.PeerPublicKey == "" {
			continue
		}
		if _, ok := known[sess.PeerPublicKey]; ok {
			keys[sess.PeerPublicKey] = struct{}{}
			continue
		}
		if sess.AdmittedVia == models.SessionAdmissionIngress {
			keys[sess.PeerPublicKey] = struct{}{}
			continue
		}
		// Direct-admitted with no known portal row: classify against
		// durable state, which is still authoritative for rows that exist.
		if s.db == nil {
			continue
		}
		conn, err := s.db.GetConnectionByClientID(ctx, sess.PeerPublicKey, 0)
		if err != nil || conn == nil {
			continue
		}
		if conn.ServerID == 0 && models.NormalizeProtocol(conn.Protocol) == "awg" {
			keys[sess.PeerPublicKey] = struct{}{}
		}
	}
	return keys, nil
}

func (s *peerSynchronizer) portalConfigDrift(ctx context.Context) error {
	current, configErr := clientawg.LoadConfig(ctx, s.db, s.config.TUN, nil)
	stored, subnetErr := s.db.GetVPNConfig(ctx)
	if configErr != nil || subnetErr != nil || stored == nil ||
		current.PrivateKey != s.config.PrivateKey || current.PublicKey != s.config.PublicKey ||
		current.ListenPort != s.config.ListenPort || current.Parameters != s.config.Parameters ||
		(stored != nil && stored.SubnetCIDR != s.subnet) {
		return errors.New("persisted portal AWG parameters differ from the running device; controlled restart required")
	}
	return nil
}

// removeDriftedPeers retires actual upstream peers that are not stably
// desired: not in the desired set at all, or desired with a different
// AllowedIP (a key-stable transition; the old assignment was already
// withdrawn from the resolver and the replacement is installed after this
// pass). Stable peers (same key, same AllowedIP, desired) are untouched.
// For every retired key the Nexus routing session is revoked first, then
// the upstream peer is removed.
func (s *peerSynchronizer) removeDriftedPeers(ctx context.Context, actual map[string]clientawg.PeerStatus, desired map[string]desiredPeer, stableActual map[string]clientawg.PeerStatus) []error {
	var failures []error
	// Remove all stale and changed assignments before adding. This also
	// handles two peers swapping IPs without stealing either AllowedIP.
	keys := make([]string, 0, len(actual))
	for key := range actual {
		if _, stable := stableActual[key]; stable {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want, exists := desired[key]
		if exists && want.peer.AllowedIP == actual[key].AllowedIP {
			// Stable as of this pass's Status snapshot; already excluded
			// above via stableActual. Kept as defense against a key being
			// in both maps.
			continue
		}
		if s.revokeSession != nil {
			if err := s.revokeSession(ctx, key); err != nil {
				failures = append(failures, fmt.Errorf("revoke session %s: %w", ingress.RedactKey(key), err))
			}
		}
		if err := s.portal.RemovePeer(key); err != nil {
			if exists {
				s.status.UpdateFailures++
			} else {
				s.status.RemoveFailures++
			}
			failures = append(failures, fmt.Errorf("remove peer %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

func (s *peerSynchronizer) addMissingPeers(actual map[string]clientawg.PeerStatus, desired map[string]desiredPeer) []error {
	var failures []error
	keys := make([]string, 0, len(desired))
	for key := range desired {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want := desired[key]
		if have, exists := actual[key]; exists && have.AllowedIP == want.peer.AllowedIP {
			continue
		}
		if err := s.portal.AddPeer(want.peer); err != nil {
			if _, exists := actual[key]; exists {
				s.status.UpdateFailures++
			} else {
				s.status.AddFailures++
			}
			failures = append(failures, fmt.Errorf("add peer %s: %w", ingress.RedactKey(key), err))
		}
	}
	return failures
}

func (s *peerSynchronizer) verifyPeers(desired map[string]desiredPeer) []error {
	after, err := s.portal.Status()
	if err != nil {
		return []error{err}
	}
	s.status.ActualPeers = len(after.Peers)
	if len(after.Peers) != len(desired) {
		return []error{errors.New("upstream peer count differs from durable state")}
	}
	for _, peer := range after.Peers {
		want, ok := desired[peer.PublicKey]
		if !ok || want.peer.AllowedIP != peer.AllowedIP {
			return []error{errors.New("upstream peer assignment differs from durable state")}
		}
	}
	return nil
}

func (s *peerSynchronizer) fail(err error) error {
	s.status.SyncFailures++
	s.status.LastError = err.Error()
	log.Printf("[vpn/peer-sync] reconciliation failed: %v", err)
	return err
}
