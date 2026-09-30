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

	// Async post-commit reconciliation (issue #391 round 4a, finding 2).
	// notify wakes the serialized worker with coalescing semantics
	// (capacity 1: a burst of N commits triggers at most one pending
	// reconcile). notifyListener is the PeerChangeListener notification
	// target: once the engine arms it, DB notifications enqueue onto the
	// worker instead of reconciling on the committing goroutine. Before
	// arming (the construction window) the notification entry point falls
	// back to running the reconciliation directly.
	notify             chan struct{}
	kick               func()
	notifyListener     func()
	pending            atomic.Int64 // queued-not-yet-started reconciles
	running            atomic.Bool  // worker currently inside reconcileNow
	enqueueFailures    atomic.Uint64
	lastEnqueueFailure atomic.Value // string
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
// arms the non-blocking enqueue callback (issue #391 round 4a, finding 2).
// The worker owns one reconcile at a time; a burst of commits coalesces into
// at most one queued reconcile. The returned stop function detaches the
// enqueue path, wakes the worker, and waits for the current reconcile to
// finish, so no reconcile runs after the portal closes. The drain is
// deadline-bounded: a reconcile stuck on an unresponsive portal device must
// never make Stop unreturnable, so stop reports a drain-timeout error
// instead of waiting forever. Stop is idempotent: an engine that never armed
// or already stopped the worker may still be asked to stop through the same
// teardown path.
func (s *peerSynchronizer) startNotifyWorker() (stop func() error, err error) {
	defer func() {
		if err != nil {
			s.kick = nil
			s.notify = nil
		}
	}()
	if s.notify != nil || s.kick != nil {
		return nil, errors.New("peer sync notify worker already started")
	}
	// wake is the capacity-1 coalescing token channel: kick's non-blocking
	// send queues at most one pending reconcile per burst and never blocks,
	// even when the worker is mid-reconcile. Shutdown uses a separate
	// stopCh that stop closes: the worker never ranges over a channel the
	// sender can rewrite or close, so the drain cannot hang on a nil or
	// closed-channel receive race (the round-4a Stop hang).
	wake := make(chan struct{}, 1)
	s.notify = wake
	s.kick = func() {
		select {
		case wake <- struct{}{}:
		default:
			// A reconcile is already queued or running: coalesced. The
			// queued run re-reads durable state afresh, so it observes
			// every commit that happened before it started. Never
			// blocks: safe from under Service.mu.
		}
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopCh:
				return
			case <-wake:
				// This run serves exactly one enqueued notification;
				// counts whose kick coalesced into this token are
				// re-armed after the run so the backlog always drains.
				s.running.Store(true)
				s.pending.Add(-1)
				_ = s.reconcileNow(context.Background())
				s.running.Store(false)
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
			s.kick = nil
			s.notifyListener = nil
			// Closing stopCh releases a parked worker immediately; an
			// in-flight reconcile is awaited below up to
			// peerSyncDrainTimeout so a portal device wedged in a
			// blocking call cannot hang Stop.
			close(stopCh)
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

// enqueuePeerReconcile is the PeerChangeListener notification
// implementation (issue #391 round 4a, finding 2): it only enqueues the
// serialized reconcile worker and returns immediately, so the database
// commit goroutine, which may hold Service.mu during legacy admission,
// never blocks on runtime device I/O. It is called from database commit
// paths, including under Service.mu during legacy admission
// (HandleIncomingPeer -> resolveOrAllocatePeerIP -> UpdateConnection), so it
// only does a channel send and atomic counter updates; the worker goroutine
// performs the actual reconcile, taking peerSync.mu and then (via
// revokeSession) Service.mu. A failed enqueue is visible, never silent: it
// is counted and recorded even though the periodic 30s reconcile loop still
// retries the drift, which remains the retry path for any drift.
func (s *peerSynchronizer) enqueuePeerReconcile() {
	kick := s.kick
	if kick == nil {
		s.recordEnqueueFailure("no notify worker")
		return
	}
	s.pending.Add(1)
	kick()
}

func (s *peerSynchronizer) recordEnqueueFailure(reason string) {
	s.enqueueFailures.Add(1)
	s.lastEnqueueFailure.Store(reason)
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
func (s *peerSynchronizer) EnqueueFailures() (uint64, string) {
	reason, _ := s.lastEnqueueFailure.Load().(string)
	return s.enqueueFailures.Load(), reason
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
	return s.status
}

// ReconcilePeers is the PeerChangeListener notification entry point. Before
// the engine arms the async worker (the construction window) it runs the
// reconciliation directly; afterwards it only enqueues onto the serialized
// worker (issue #391 round 4a, finding 2). The construction-time initial
// reconcile and the periodic reconcile loop call reconcileNow directly, so
// they keep executing synchronously without Service.mu held.
func (s *peerSynchronizer) ReconcilePeers(ctx context.Context) error {
	if notify := s.notifyListener; notify != nil {
		notify()
		return nil
	}
	return s.reconcileNow(ctx)
}

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
		return s.fail(err)
	}
	actual := make(map[string]clientawg.PeerStatus, len(current.Peers))
	for _, peer := range current.Peers {
		actual[peer.PublicKey] = peer
	}
	s.status.ActualPeers = len(actual)

	// Classify actual upstream peers (finding 1, step 1):
	//   stable  - same key, same AllowedIP, present in desired
	//   retired - everything else: not desired at all, or desired with a
	//             different AllowedIP (a key-stable transition whose old
	//             assignment must be withdrawn before the new install).
	stableActual := make(map[string]clientawg.PeerStatus, len(actual))
	var retireKeys []string
	for key, have := range actual {
		want, isDesired := desired[key]
		if isDesired && want.peer.AllowedIP == have.AllowedIP {
			stableActual[key] = have
			continue
		}
		retireKeys = append(retireKeys, key)
	}
	sort.Strings(retireKeys)

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

	failures := s.removeDriftedPeers(ctx, actual, desired, stableActual)
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
// ingress-engine peer, and a handshake-admitted session is classified against
// its durable connection (server_id 0, awg) exactly as before. A handshake
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
	// for handshake-admitted sessions.
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
// server peer, a legacy server tunnel, a handshake session whose row is gone
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
		// Handshake-admitted with no known portal row: classify against
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
