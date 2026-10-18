package vpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/auth"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/identity"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// VPNStatusSchemaVersion identifies the intentionally versioned /api/vpn/status
// representation. Version 2 removes legacy custom-engine crypto telemetry and
// keys forwarder_route_queues by opaque peer fingerprints instead of raw keys.
const VPNStatusSchemaVersion = 2

// Status represents the overall runtime telemetry of the VPN endpoint and load balancing subsystem.
type Status struct {
	SchemaVersion              int    `json:"status_schema_version"`
	ConfiguredEngine           string `json:"configured_engine"`
	ActiveEngine               string `json:"active_engine"`
	EngineRunning              bool   `json:"engine_running"`
	ListenPort                 int    `json:"listen_port"`
	ReturnRouteOwner           string `json:"return_route_owner"`
	ListenerRunning            bool   `json:"listener_running"`
	ActiveTunnels              int    `json:"active_tunnels"`
	ConnectedSessions          int    `json:"connected_sessions"`
	RestartInvalidatedSessions int64  `json:"restart_invalidated_sessions"`
	FreshSessionRegistrations  int64  `json:"fresh_session_registrations"`
	RxBytes                    int64  `json:"rx_bytes"`
	TxBytes                    int64  `json:"tx_bytes"`
	DroppedPackets             uint64 `json:"dropped_packets"`
	// Legacy-compatible forwarder counters that still describe Nexus-owned
	// dataplane behavior are retained in schema v2. Custom client-engine
	// decrypt/handshake telemetry was removed with the upstream-only architecture.
	ForwarderAvailable             bool   `json:"forwarder_available"`
	ForwarderDropsQueueFull        uint64 `json:"forwarder_drops_queue_full"`
	ForwarderDropsNoRoute          uint64 `json:"forwarder_drops_no_route"`
	ForwarderDropsPacketTooLarge   uint64 `json:"forwarder_drops_packet_too_large"`
	ForwarderDropsTotal            uint64 `json:"forwarder_drops_total"`
	ForwarderQueueOccupancy        int    `json:"forwarder_queue_occupancy"`
	ForwarderQueueCapacity         int    `json:"forwarder_queue_capacity"`
	ForwarderQueueHighWater        int    `json:"forwarder_queue_high_water"`
	ForwarderDeviceWriteErrors     uint64 `json:"forwarder_device_write_errors"`
	ForwarderDeviceWriteDurationMS uint64 `json:"forwarder_device_write_duration_ms"`
	ForwarderDeviceWriteCount      uint64 `json:"forwarder_device_write_count"`
	ForwarderDeviceWritesInFlight  int    `json:"forwarder_device_writes_in_flight"`
	ForwarderDeviceWriteOldestMS   int64  `json:"forwarder_device_write_oldest_in_flight_ms"`
	ForwarderDeviceWriteMaxMS      int64  `json:"forwarder_device_write_max_duration_ms"`
	ForwarderDeviceWriteStalls     uint64 `json:"forwarder_device_write_stalls"`
	ForwarderDeviceWriteStallMS    int64  `json:"forwarder_device_write_stall_threshold_ms"`
	PublicEndpoint                 string `json:"public_endpoint,omitempty"`
	// Schema v2 map keys are ingress.PeerKeyFingerprint values; peer_key_display
	// carries the redacted operator-facing identifier.
	ForwarderRouteQueues map[string]forwarder.RouteQueueStats `json:"forwarder_route_queues,omitempty"`
	UpstreamDesiredPeers int                                  `json:"upstream_desired_peers,omitempty"`
	UpstreamActualPeers  int                                  `json:"upstream_actual_peers,omitempty"`
	PeerSync             *PeerSyncStatus                      `json:"peer_sync,omitempty"`

	// Issue #424: Redesigned forwarder health & operational diagnostics
	HealthAssessment   ForwarderHealthAssessment     `json:"health_assessment"`
	Rates              TrafficRates                  `json:"rates"`
	QueuePressure      QueuePressureDiagnostics      `json:"queue_pressure"`
	ForwardLatency     ForwardLatencyDiagnostics     `json:"forward_latency"`
	DropCategories     DropCategoryBreakdown         `json:"drop_categories"`
	VirtualTUN         VirtualTUNDiagnostics         `json:"virtual_tun"`
	RoutingConsistency RoutingConsistencyDiagnostics `json:"routing_consistency"`
	HandshakeFreshness HandshakeFreshnessDiagnostics `json:"handshake_freshness"`
	Backends           BackendsDiagnostics           `json:"backends"`
	ProblemRoutes      []ProblemRouteItem            `json:"problem_routes"`
	AllRoutes          []ProblemRouteItem            `json:"all_routes,omitempty"`
	RuntimeResources   RuntimeResources              `json:"runtime_resources"`
	HistoricalSeries   HistoricalSeries              `json:"historical_series"`
	CountersSince      string                        `json:"counters_since,omitempty"`
}

// UserVPNState represents the real-time VPN connection state for a specific user.
type UserVPNState struct {
	Connected       bool               `json:"connected"`
	Session         *models.VPNSession `json:"session,omitempty"`
	BackendServerID int64              `json:"backend_server_id,omitempty"`
	BackendEndpoint string             `json:"backend_endpoint,omitempty"`
	LatencyMS       int64              `json:"latency_ms,omitempty"`
}

// Client AWG engines. Upstream is the sole, permanent client-facing engine.
const (
	ClientAWGEngineUpstream = "upstream"
)

// BackendTunnelStatus type alias for backwards compatibility.
type BackendTunnelStatus = string

const (
	TunnelStatusConnecting = "connecting"
	TunnelStatusActive     = "active"
	TunnelStatusDegraded   = "degraded"
	TunnelStatusDisabled   = "disabled"
)

var (
	ErrAWGNotInstalled = errors.New("server has no AWG protocol installed")
	ErrServerNotFound  = errors.New("server not found")
	// ErrBackendTunnelNotFound re-exports tunnel.ErrTunnelNotFound so HTTP
	// callers can map a delete of an unknown backend to 404 without
	// importing the tunnel package.
	ErrBackendTunnelNotFound = tunnel.ErrTunnelNotFound
	// ErrTunnelDisabled re-exports tunnel.ErrTunnelDisabled.
	ErrTunnelDisabled    = tunnel.ErrTunnelDisabled
	ErrVPNRollbackFailed = errors.New("vpn rollback failed")
)

// BackendTunnel is an alias for models.BackendTunnel.
type BackendTunnel = models.BackendTunnel

// Session is an alias for models.VPNSession.
type Session = models.VPNSession

// LoadBalancer is an alias for loadbalancer.LoadBalancer.
type LoadBalancer = loadbalancer.LoadBalancer

// AWGStatusProvider defines an interface for querying live AWG status on a server.
type AWGStatusProvider interface {
	GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error)
}

// RoutingRemediator defines an interface for configuring return routes and NAT on backend servers.
type RoutingRemediator interface {
	EnsureBackendRoutingAndNAT(ctx context.Context, server *models.Server, subnet string) error
}

// BackendDevice represents a backend packet device attached to the VPN forwarder.
type BackendDevice interface {
	tunnel.PacketDevice
	LastHandshakeTime() time.Time
	CreatedAt() time.Time
	DroppedPackets() uint64
	IsClosed() bool
}

// Service orchestrates endpoint listener, backend tunnel pool, load balancing, and traffic forwarding.
//
// Capacity serialization invariant (issue #86): mu is the single mutex under
// which every production mutator of the pool's ActiveConnections gauge
// runs — HandleIncomingPeer's select+increment, disconnect decrements, and
// failover backend moves. The rekey ReplacementHook mutates the gauge under
// SessionManager.mu, but only transitively from HandleIncomingPeer's
// CreateSession call, so it runs nested under this mutex too (lock order
// mu → SessionManager.mu, never reversed). Keep it that way: the
// check-then-allocate capacity decision is only safe under this
// serialization. Full contract: tunnel.Pool.IncrementConnections.
type Service struct {
	retiredIngressLosses ingressLossTotals // guarded by mu
	mu                   sync.RWMutex
	assignmentMu         sync.Mutex // serialize durable lease creation and restart migration
	db                   *database.DB
	cfg                  *models.VPNConfig
	sessionMgr           *session.SessionManager
	ipam                 *ipam.IPAM
	auth                 *auth.DBAuthenticator
	pool                 *tunnel.Pool
	prober               *tunnel.HealthProber
	reconnectMgr         *tunnel.ReconnectManager
	balancer             loadbalancer.LoadBalancer
	stickyMgr            *loadbalancer.StickySessionManager
	forwarder            *forwarder.Forwarder
	accountant           *forwarder.TrafficAccountant
	running              bool
	startedAt            time.Time // baseline timestamp for cumulative metrics; guarded by mu
	portalPubKey         string
	portalPrivKey        string
	awgProvider          AWGStatusProvider
	ingressEngine        *IngressEngine
	// backendDevices holds the per-backend UDP devices created by EnableBackend.
	backendDevices         map[int64]BackendDevice
	backendDeviceEndpoints map[int64]string
	deletedServers         map[int64]struct{} // guarded by mu
	lastLoggedDrops        atomic.Uint64
	// retiredBackendDeviceDrops is the LIFETIME accumulator for backend
	// devices that have left backendDevices (issue #424 round 5, finding 1).
	//
	// It is direction- and reason-preserving, not a scalar: a retiring
	// device's real VirtualTUN breakdown is transferred into the matching
	// buckets, so a return-direction loss stays a return-direction loss after
	// the device is gone. The accumulator carries the SAME fields as a live
	// device's contribution, which is what lets a retired loss be published
	// under the same key a live one uses.
	//
	// guarded by mu
	retiredBackendDeviceDrops  backendDeviceDropStats
	restartInvalidatedSessions atomic.Int64
	freshSessionRegistrations  atomic.Int64
	publicIPMu                 sync.RWMutex
	detectedPublicIP           string
	// dropLogUntil throttles the backend read loop's queue-full drop log
	// (log-flood defense; issue #39 produced 7687 lines in 2 h). Shared
	// across the per-backend read loops: all accesses are atomic, so the
	// worst case is one log line per second in aggregate.
	dropLogUntil atomic.Int64

	lastReconcileTime                      time.Time
	lastReconcileByTunnel                  map[int64]time.Time
	reconcilePostSnapshotHook              func()
	reconcilePreApplyHook                  func()
	reconcilePreCommitHook                 func()
	ensureDevicePreLockHook                func()
	preCommitMigrationHookForTest          func()
	preAdoptHookForTest                    func(peerKey, sessionID string)
	preIngressRouteRegistrationHookForTest func()
	preRevokeCloseHookForTest              func(peerKey, sessionID string)
	postCommitRevokeHookForTest            func(kind database.PeerRevokeKind, userID string, clientID string)
	updateBackendServerHostPreLockHook     func()
	updateBackendServerHostErr             error
	deleteBackendErr                       error
	syncBackendForwarderHook               func() error
	enableBackendPreAddTunnelHook          func()
	enableBackendPostAddTunnelHook         func()
	reaperHook                             func(context.Context, *models.VPNSession)

	rollingHistory   *RollingHistory
	diagRatesMu      sync.Mutex
	diagRates        *diagRatesTracker
	historyDiagRates *diagRatesTracker
	problemOnset     *problemOnsetTracker
	// diagGeneration is the diagnostics generation (issue #429 review
	// blocker 1). It advances ONLY in Start, so every Start after Stop is an
	// explicit new generation: every cumulative diagnostics baseline below is
	// reset/re-primed instead of a restart being inferred from counters that
	// moved backwards.
	//
	// Atomic (issue #429 review round 4, blocker 1): diagnosticsInputsLocked
	// captures it as part of the observation, and that capture runs under
	// s.mu while resetDiagnosticsGeneration holds diagRatesMu and takes s.mu
	// for its priming capture — reading the field there under diagRatesMu
	// would invert the established lock order and deadlock. The atomic load
	// cannot straddle a lifecycle transition because resetDiagnosticsGeneration
	// bumps it BEFORE startRollingHistory publishes any new-generation
	// tracker work, while the writers of everything else in the snapshot
	// hold s.mu.
	diagGeneration atomic.Uint64
	// historyPrimedGen is the generation the history priming state was
	// recorded for. historyPrimed is true only while historyPrimedGen equals
	// the current generation, so a generation bump in Start automatically
	// un-primes history and the next history read re-primes into the new
	// generation (issue #429 review blocker 1). Both are guarded by
	// diagRatesMu.
	historyPrimedGen diagGeneration
	// historyPrimed records that the history baselines captured a first
	// sample for historyPrimedGen. It is deliberately NOT derived from any
	// timestamp being zero (issue #424 round 8, finding 2) and deliberately
	// NOT a sticky flag (issue #429 review blocker 1).
	historyPrimed bool
	// diagDeltas converts cumulative lifetime failure counters into windowed
	// deltas so a recovered incident stops pinning current health (issue #424
	// round 2, finding 5). Its zero value is usable.
	diagDeltas    diagDeltaTrackers
	historyStopCh chan struct{}
	historyDoneCh chan struct{}
}

// NewVPNService initializes the complete unified VPN subsystem.
// Server-side RejectAfterTime defaults to device.RejectAfterTime (180s WireGuard protocol standard),
// providing a stable transition window intentionally independent of client-configured timing ranges.
//
//nolint:gocyclo // initialization validates and wires each owned subsystem in order.
func NewVPNService(db *database.DB, cfg *models.VPNConfig) (*Service, error) {
	if cfg == nil {
		if db != nil {
			var err error
			cfg, err = db.GetVPNConfig(context.Background())
			if err != nil {
				return nil, fmt.Errorf("failed to load VPN config: %w", err)
			}
		} else {
			cfg = defaultVPNConfig()
		}
	} else {
		applyVPNConfigDefaults(cfg)
	}

	if err := forwarder.ValidateClientRouteLimit(cfg.MaxTotalPeers); err != nil {
		return nil, err
	}

	// Migrate legacy configs whose AWG obfuscation parameters are unset
	// (H/S all zero) before any subsystem consumes them: the endpoint
	// listener copies H/S into its config below and EnsureKeypair
	// loadOrCreate persists the VPNConfig. Applies to caller-supplied
	// configs too (callers pass nil today; the shim keeps non-nil
	// callers safe).
	if err := ensureObfuscationParams(context.Background(), db, cfg); err != nil {
		return nil, err
	}

	ipamMgr, err := ipam.NewIPAM(cfg.SubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to init IPAM: %w", err)
	}
	// Config generation is also available before Start. Load both persisted
	// client leases and legacy session-only leases before exposing this service.
	if db != nil {
		if err := reservePersistedClientIPs(context.Background(), db, ipamMgr); err != nil {
			return nil, fmt.Errorf("restore client IP assignments: %w", err)
		}
	}

	var dbAuth *auth.DBAuthenticator
	if db != nil {
		dbAuth = auth.NewDBAuthenticator(db)
	}

	sessionMgr := session.NewSessionManager(db, ipamMgr)

	serverKeys := identity.NewServerKeysManager(db)

	// Finding 3 (issue #391 round 4a): committed durable access revocations
	// tear down live sessions immediately, engine-aware, instead of waiting
	// for the reconciliation worker or the idle reaper. The dispatcher is
	// subscribed before the listener exists so no revocation commit can slip
	// past it during startup; it binds the real service below, once built.
	// It never runs under Service.mu (see revokeDispatcher).
	revokeDispatch := newRevokeDispatcher()
	if db != nil {
		db.SubscribePeerRevokes(revokeDispatch)
	}

	pool := tunnel.NewPool(db)

	healthCfg := tunnel.DefaultHealthConfig()
	healthCfg.LatencyThresholdMS = int64(cfg.HealthThresholdMS)
	prober := tunnel.NewHealthProber(pool, db, healthCfg)

	reconnectCfg := tunnel.DefaultReconnectConfig()
	reconnectMgr := tunnel.NewReconnectManager(pool, prober, reconnectCfg)

	caps := loadbalancer.CapacityConfig{
		MaxTotalPeers:      cfg.MaxTotalPeers,
		MaxPeersPerBackend: cfg.MaxPeersPerBackend,
		AffinityTTL:        time.Duration(cfg.AffinityTTLMinutes) * time.Minute,
	}

	lb, err := loadbalancer.NewLoadBalancer(cfg.Algorithm, cfg.Weights, caps)
	if err != nil {
		lb = loadbalancer.NewLeastConnectionsBalancer(caps)
	}

	stickyMgr := loadbalancer.NewStickySessionManager(db, lb, caps)

	accountant := forwarder.NewTrafficAccountant(db, 2*time.Second)
	queueSize := cfg.ClientQueueSize
	if queueSize <= 0 {
		queueSize = forwarder.DefaultClientQueueSize
	}
	maxActiveRoutes := cfg.MaxTotalPeers
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = 1000
	}
	maxQueue := forwarder.MaxClientQueuePacketsForRoutes(maxActiveRoutes)
	if queueSize > maxQueue {
		queueSize = maxQueue
	}
	cfg.ClientQueueSize = queueSize
	fwd, err := forwarder.NewForwarderWithLimits(accountant, cfg.SubnetCIDR, queueSize, maxActiveRoutes)
	if err != nil {
		return nil, err
	}

	pub, priv, _ := tunnel.GenerateCurve25519KeyPair()
	if serverKeys != nil {
		privArr, pubArr, err := serverKeys.EnsureKeypair(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to ensure portal keypair: %w", err)
		}
		pub = base64.StdEncoding.EncodeToString(pubArr[:])
		priv = base64.StdEncoding.EncodeToString(privArr[:])
		// Keep only the encrypted representation in the live config. The
		// decoded key is owned separately by the endpoint and portalPrivKey.
		cfg.ServerPrivateKey = ""
		if db != nil {
			stored, err := db.GetVPNConfig(context.Background())
			if err != nil {
				return nil, fmt.Errorf("reload portal key after initialization: %w", err)
			}
			cfg.ServerPrivateKey = stored.ServerPrivateKey
		}
		cfg.ServerPublicKey = pub
	}

	svc := &Service{
		db:                     db,
		cfg:                    cfg,
		sessionMgr:             sessionMgr,
		ipam:                   ipamMgr,
		auth:                   dbAuth,
		pool:                   pool,
		prober:                 prober,
		reconnectMgr:           reconnectMgr,
		balancer:               lb,
		stickyMgr:              stickyMgr,
		forwarder:              fwd,
		accountant:             accountant,
		portalPubKey:           pub,
		portalPrivKey:          priv,
		backendDeviceEndpoints: make(map[int64]string),
		deletedServers:         make(map[int64]struct{}),
		lastReconcileByTunnel:  make(map[int64]time.Time),
		rollingHistory:         NewRollingHistory(),
		diagRates:              newDiagRatesTracker(),
		problemOnset:           newProblemOnsetTracker(),
	}
	revokeDispatch.bind(svc)

	// Finding 3 (issue #391 round 4a): committed durable access revocations
	// tear down live sessions immediately, engine-aware, instead of waiting
	// for the reconciliation worker or the idle reaper. Service implements
	// database.PeerRevokeRecorder; the callback never runs under Service.mu.
	// Constructing a service without a database is a supported path (the
	// subscription is a no-op then): there are no durable access changes to
	// observe, so there is nothing for the dispatcher to revoke.
	if db != nil {
		db.SubscribePeerRevokes(svc)
	}
	// Issue #78: session replacement (client rekey/reconnect) must migrate the
	// pool connection counter off the old backend - without this every rekey
	// leaked +1 on the old backend's ActiveConnections gauge (the original
	// connect incremented it; the replacement path never decremented, and a
	// later DisconnectSession(oldID) found nothing because the SessionManager
	// had already dropped the old ID and closed the DB row).
	// The hook uses the same pool primitives as the clean-disconnect
	// mirror-decrement paths (DisconnectUser/DisconnectSession/ReleaseClient).
	// SessionManager owns the ordering: CreateSession removes the old session
	// (and closes its DB row) BEFORE persisting the new one, and fires this
	// hook only after the new session is fully registered. The hook runs while
	// SessionManager.mu is held, so it must only touch the pool counter and
	// forwarder/sticky state - it must never re-enter the session manager.
	// Capacity serialization note (issue #86): the hook's pool counter
	// migration therefore participates in the capacity invariant only
	// transitively - EnsureBackendSessionForIngress holds s.mu for the whole
	// select -> CreateSession -> increment sequence, so the hook runs nested
	// under BOTH locks (s.mu -> sm.mu; the reverse order is never taken).
	// Old and new backends may differ when the reconnect re-selected a backend.
	sessionMgr.SetReplacementHook(func(ctx context.Context, old, new *models.VPNSession) {
		if old == nil {
			return
		}
		if new == nil {
			// Replacement failed to persist: no counter migration happened,
			// so the +1 leak stays observable via the reconcile logs instead
			// of silently guessing a counter state that was never applied.
			log.Printf("[vpn] session replacement for peer %s failed before the new session was registered; pool counter for backend %d not migrated (watch periodic reconcile)",
				old.PeerPublicKey, old.BackendTunnelID)
			return
		}
		// Mirror admission increment on the same primitives used by
		// DisconnectUser/DisconnectSession/ReleaseClient for the decrement.
		svc.pool.DecrementConnections(old.BackendTunnelID)
		if new.BackendTunnelID != old.BackendTunnelID {
			svc.pool.IncrementConnections(new.BackendTunnelID)
		}
		if svc.forwarder != nil {
			if err := svc.forwarder.UpdateSessionBackend(old.PeerPublicKey, new.BackendTunnelID); err != nil && !errors.Is(err, forwarder.ErrSessionNotRegistered) {
				log.Printf("[vpn] session replacement route redirect for peer %s -> backend %d: %v", old.PeerPublicKey, new.BackendTunnelID, err)
			}
		}
		if svc.stickyMgr != nil {
			svc.stickyMgr.AssignPeerAffinity(old.PeerPublicKey, new.BackendTunnelID)
		}
	})

	svc.prober.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		// Issue #43 (session 8): the previous closure short-circuited here
		// whenever a data device was attached, synthesizing a fake 10ms
		// success (or a fake handshake timeout) from LastHandshakeTime alone
		// - without sending anything. The real Noise IK prober (the only
		// user of the dedicated probe key) was unreachable, so the backend's
		// probe peer never handshook. The prober now runs the real
		// health.ProbeAWGEndpoint on EVERY cycle regardless of data-device
		// handshake age; the 10s cadence is trivial load. If a fast path is
		// ever reintroduced it must still SEND the probe.
		// Issue #49: forwards through ProbeAWGEndpointRange, which accepts
		// full AWG 3.1 header ranges (models.HeaderRange) as well as uint32.
		return health.ProbeAWGEndpointRange(ctx, endpoint, serverPubKey, clientPrivKey, psk, hpKey, h1, h2, s1, s2, timeout)
	})

	svc.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		return svc.ensureBackendDeviceAttached(ctx, t)
	})
	svc.prober.SetOnSelfHealHook(func(ctx context.Context, t *models.BackendTunnel) error {
		return svc.EnableBackend(tunnel.ContextWithSelfHealing(ctx), t.ServerID)
	})

	return svc, nil
}

// SetProbeFunc sets the health probe function for testing or customized reachability probing.
func (s *Service) SetProbeFunc(fn tunnel.ProbeFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prober != nil {
		s.prober.SetProbeFunc(fn)
	}
}

// SetBackendDeviceForTest sets a backend device for testing.
func (s *Service) SetBackendDeviceForTest(tunID int64, dev BackendDevice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backendDevices == nil {
		s.backendDevices = make(map[int64]BackendDevice)
	}
	s.backendDevices[tunID] = dev
}

// SetBackendDeviceEndpointForTest sets the recorded endpoint for a backend device for testing.
func (s *Service) SetBackendDeviceEndpointForTest(tunID int64, endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backendDeviceEndpoints == nil {
		s.backendDeviceEndpoints = make(map[int64]string)
	}
	s.backendDeviceEndpoints[tunID] = endpoint
}

// SetReconcilePostSnapshotHook registers a test hook called immediately after
// reading the active session snapshot in reconcileConnectionCounts, before s.mu is acquired.
func (s *Service) SetReconcilePostSnapshotHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcilePostSnapshotHook = fn
}

// SetReconcilePreApplyHook registers a test hook called under s.mu before
// the tunnel reconciliation apply phase in reconcileConnectionCounts.
func (s *Service) SetReconcilePreApplyHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcilePreApplyHook = fn
}

// SetReconcilePreCommitHook registers a test hook called under s.mu and sm.LockLifecycle
// immediately before applying changes in reconcileConnectionCounts.
func (s *Service) SetReconcilePreCommitHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcilePreCommitHook = fn
}

// GetBackendDeviceForTest returns the backend device for a tunnel ID.
func (s *Service) GetBackendDeviceForTest(tunID int64) BackendDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendDevices == nil {
		return nil
	}
	return s.backendDevices[tunID]
}

// GetBackendDeviceEndpointForTest returns the recorded endpoint for a backend device for testing.
func (s *Service) GetBackendDeviceEndpointForTest(tunID int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendDeviceEndpoints == nil {
		return ""
	}
	return s.backendDeviceEndpoints[tunID]
}

// ProbeTunnel probes a tunnel using the service's health prober.
func (s *Service) ProbeTunnel(ctx context.Context, t *models.BackendTunnel) (int64, error) {
	if s.prober == nil {
		return 0, errors.New("health prober not initialized")
	}
	return s.prober.ProbeTunnel(ctx, t)
}

// SelfHealSweep sweeps auto-disabled backend tunnels and attempts to recover them.
func (s *Service) SelfHealSweep(ctx context.Context) int {
	s.mu.RLock()
	prober := s.prober
	s.mu.RUnlock()

	if prober == nil {
		return 0
	}
	return prober.SelfHealSweep(ctx)
}

// SetHealthProber sets a custom health prober instance.
func (s *Service) SetHealthProber(prober *tunnel.HealthProber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prober = prober
	if s.prober != nil {
		s.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
			return s.ensureBackendDeviceAttached(ctx, t)
		})
		s.prober.SetOnSelfHealHook(func(ctx context.Context, t *models.BackendTunnel) error {
			return s.EnableBackend(tunnel.ContextWithSelfHealing(ctx), t.ServerID)
		})
	}
}

// SetEnsureDevicePreLockHook sets a hook called immediately before acquiring s.mu in ensureBackendDeviceAttached.
func (s *Service) SetEnsureDevicePreLockHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureDevicePreLockHook = fn
}

// SetUpdateBackendServerHostPreLockHook sets a hook called immediately before acquiring s.mu in UpdateBackendServerHost.
func (s *Service) SetUpdateBackendServerHostPreLockHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateBackendServerHostPreLockHook = fn
}

// SetUpdateServerHostPreLockHook is an alias for SetUpdateBackendServerHostPreLockHook.
func (s *Service) SetUpdateServerHostPreLockHook(fn func()) {
	s.SetUpdateBackendServerHostPreLockHook(fn)
}

// SetUpdateBackendServerHostErrorForTest sets an error to be returned by UpdateBackendServerHost for testing.
func (s *Service) SetUpdateBackendServerHostErrorForTest(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateBackendServerHostErr = err
}

// SetDeleteBackendErrorForTest sets an error to be returned by DeleteBackend for testing.
func (s *Service) SetDeleteBackendErrorForTest(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteBackendErr = err
}

// SetEnableBackendPreAddTunnelHookForTest sets a hook called immediately before calling pool.AddTunnel in EnableBackend.
func (s *Service) SetEnableBackendPreAddTunnelHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableBackendPreAddTunnelHook = fn
}

// SetEnableBackendPostAddTunnelHookForTest sets a hook called immediately after calling pool.AddTunnel in EnableBackend.
func (s *Service) SetEnableBackendPostAddTunnelHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableBackendPostAddTunnelHook = fn
}

// SetSyncBackendForwarderHookForTest sets a test hook called inside syncBackendForwarderOnHostUpdateLocked.
func (s *Service) SetSyncBackendForwarderHookForTest(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncBackendForwarderHook = fn
}

// SetTunnelEndpointHookForTest sets a test hook for SetTunnelEndpoint on the pool.
func (s *Service) SetTunnelEndpointHookForTest(fn func(ctx context.Context, tunnelID int64, endpoint string) error) {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.SetSetTunnelEndpointHookForTest(fn)
}

func (s *Service) resolveServerAWGParams(ctx context.Context, serverID int64) (map[string]any, error) {
	if s.db == nil {
		return nil, errors.New("database not available")
	}
	srv, err := s.db.GetServerByID(ctx, serverID)
	if err != nil || srv == nil {
		return nil, fmt.Errorf("failed to load server %d: %w", serverID, err)
	}
	if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
		if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
			return p, nil
		} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
			return p, nil
		}
	}
	return nil, nil
}

// backendTunnelReady rejects a deleted, replaced, or disabled pool entry.
func (s *Service) backendTunnelReady(t *models.BackendTunnel) error {
	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}
	current, err := s.pool.GetTunnel(t.ServerID)
	if err != nil {
		return err
	}
	if current == nil || current.ID != t.ID {
		return tunnel.ErrTunnelNotFound
	}
	if !current.Enabled {
		return ErrTunnelDisabled
	}
	if t.StateVersion > 0 && current.StateVersion != t.StateVersion {
		return tunnel.ErrStaleStateVersion
	}
	if t.Endpoint != "" && current.Endpoint != t.Endpoint {
		return tunnel.ErrStaleStateVersion
	}
	return nil
}

// ensureBackendDeviceAttached verifies that a data-plane device is attached for the tunnel.
// If missing, it attempts to attach the device using persisted server AWG credentials.
func (s *Service) ensureBackendDeviceAttached(ctx context.Context, t *models.BackendTunnel) error {
	if t == nil {
		return nil
	}
	if err := s.backendTunnelReady(t); err != nil {
		return err
	}
	s.mu.RLock()
	hasDev := s.backendDevices != nil && s.backendDevices[t.ID] != nil
	s.mu.RUnlock()
	if hasDev {
		return nil
	}

	awgParams, loadErr := s.resolveServerAWGParams(ctx, t.ServerID)
	if loadErr != nil {
		log.Printf("[vpn] warning: tunnel %d (server %d) probe succeeded but failed to load server credentials: %v", t.ID, t.ServerID, loadErr)
		return loadErr
	}

	s.mu.RLock()
	hook := s.ensureDevicePreLockHook
	s.mu.RUnlock()
	if hook != nil {
		hook()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isServerDeletedLocked(t.ServerID) {
		return fmt.Errorf("server %d is deleted", t.ServerID)
	}

	if err := s.backendTunnelReady(t); err != nil {
		return err
	}
	if s.backendDevices != nil && s.backendDevices[t.ID] != nil {
		return nil
	}

	if attachErr := s.attachBackendForwarder(t, awgParams); attachErr != nil {
		log.Printf("[vpn] warning: tunnel %d (server %d) probe succeeded but failed to attach data plane: %v", t.ID, t.ServerID, attachErr)
		return attachErr
	}
	return nil
}

// SetAWGStatusProvider sets the provider used to query live AWG status on backend servers.
func (s *Service) SetAWGStatusProvider(provider AWGStatusProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.awgProvider = provider
}

// HasAWGStatusProvider reports whether an AWG status provider is configured on the service.
func (s *Service) HasAWGStatusProvider() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.awgProvider != nil
}

// IngressEngine returns the active IngressEngine when running in upstream mode.
func (s *Service) IngressEngine() *IngressEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ingressEngine
}

// SetIngressEngine sets an IngressEngine instance on the service before Start (e.g. for testing).
func (s *Service) SetIngressEngine(e *IngressEngine) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("cannot set ingress engine while service is running")
	}
	s.ingressEngine = e
	return nil
}

// IsRunning returns true if the VPN service is active.
func (s *Service) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// ReturnRouteOwner returns the actual forwarder return route owner ("upstream" or "none").
// If the service is not running or has no registered routes, it returns "none".
func (s *Service) ReturnRouteOwner() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.running || s.forwarder == nil {
		return "none"
	}
	return s.forwarder.ReturnRouteOwner()
}

// GetStatus returns the operational status and telemetry of the VPN subsystem.
func (s *Service) GetStatus(ctx context.Context) (*Status, error) {
	s.mu.RLock()
	inputs := s.diagnosticsInputsLocked()
	// Structural membership shares the Service administrative boundary.
	// These snapshot methods do no peer synchronization or external I/O.
	var routeSnapshot []forwarder.RouteInfo
	if inputs.forwarder != nil {
		routeSnapshot = inputs.forwarder.InspectRoutes()
	}
	running, db := s.running, s.db
	startedAt := s.startedAt
	var cfg *models.VPNConfig
	if s.cfg != nil {
		cfg = &models.VPNConfig{ListenPort: s.cfg.ListenPort, PublicEndpoint: s.cfg.PublicEndpoint}
	}
	s.mu.RUnlock()

	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	} else if db != nil {
		if dbCfg, err := db.GetVPNConfig(ctx); err == nil && dbCfg != nil && dbCfg.ListenPort > 0 {
			listenPort = dbCfg.ListenPort
		}
	}

	engineRunning := false
	var upstreamDesiredPeers, upstreamActualPeers int
	var peerSync *PeerSyncStatus

	if running {
		if inputs.ingressEngine != nil && inputs.ingressEngine.Running() {
			engineRunning = true
			syncStat := inputs.ingressEngine.PeerSyncStatus()
			upstreamDesiredPeers = syncStat.DesiredPeers
			upstreamActualPeers = syncStat.ActualPeers
			peerSync = &syncStat
		}
	}

	activeEngine := "none"
	if engineRunning {
		activeEngine = ClientAWGEngineUpstream
	}

	returnRouteOwner := "none"
	if engineRunning && inputs.forwarder != nil {
		returnRouteOwner = inputs.forwarder.ReturnRouteOwner()
	}

	status := &Status{
		SchemaVersion:              VPNStatusSchemaVersion,
		ConfiguredEngine:           ClientAWGEngineUpstream,
		ActiveEngine:               activeEngine,
		EngineRunning:              engineRunning,
		ListenPort:                 listenPort,
		ReturnRouteOwner:           returnRouteOwner,
		ListenerRunning:            engineRunning,
		RestartInvalidatedSessions: s.restartInvalidatedSessions.Load(),
		FreshSessionRegistrations:  s.freshSessionRegistrations.Load(),
		UpstreamDesiredPeers:       upstreamDesiredPeers,
		UpstreamActualPeers:        upstreamActualPeers,
		PeerSync:                   peerSync,
	}

	if !startedAt.IsZero() {
		status.CountersSince = startedAt.UTC().Format("2006-01-02 15:04 UTC")
	}

	for _, tun := range inputs.tunnels {
		if backendEligible(tun) {
			status.ActiveTunnels++
		}
	}
	if inputs.sessionMgr != nil {
		status.ConnectedSessions = len(inputs.sessions)
	}

	// Capture per-route telemetry exactly once for this status response.
	// Route pressure contains recency windows over monotonic counters, so a
	// second read later in the same request is not merely another snapshot:
	// it can advance the window and consume the incident. Both the legacy
	// route-queue map and the redesigned diagnostics reuse this value.
	populateForwarderStatusFromRoutes(status, inputs.forwarder, routeSnapshot)

	var totalDrops uint64
	for _, dev := range inputs.backendDevices {
		if dev != nil {
			totalDrops += dev.DroppedPackets()
		}
	}
	status.DroppedPackets = totalDrops

	if totalDrops > 0 {
		prev := s.lastLoggedDrops.Load()
		if prev == 0 || totalDrops-prev >= 100 {
			if s.lastLoggedDrops.CompareAndSwap(prev, totalDrops) {
				log.Printf("[vpn] warning: %d packets dropped across backend devices due to full queues", totalDrops)
			}
		}
	}

	status.PublicEndpoint = resolveClientEndpointInternal(ctx, s, cfg, listenPort)
	s.populateOperationalDiagnosticsFromInputs(status, routeSnapshot, inputs)

	return status, nil
}

// populateForwarderStatusFromRoutes preserves the legacy status keys while
// using the caller's coherent route snapshot. It must not call
// AllRouteQueueStats: that method samples the same recency counters again and
// can consume a just-observed pressure event before problem_routes is built.
func populateForwarderStatusFromRoutes(status *Status, f *forwarder.Forwarder, routes []forwarder.RouteInfo) {
	if f == nil {
		return
	}
	status.ForwarderAvailable = true
	rx, tx, _ := f.GetStats()
	status.RxBytes = rx
	status.TxBytes = tx
	status.ForwarderDropsQueueFull, status.ForwarderDropsNoRoute, status.ForwarderDropsTotal = f.DropStats()
	status.ForwarderDropsPacketTooLarge = f.DropsPacketTooLarge()
	status.ForwarderQueueOccupancy, status.ForwarderQueueCapacity, status.ForwarderQueueHighWater = f.AggregateQueueStats()

	if len(routes) > 0 {
		ordered := append([]forwarder.RouteInfo(nil), routes...)
		sort.Slice(ordered, func(i, j int) bool { return ordered[i].PeerKey < ordered[j].PeerKey })
		if len(ordered) > forwarder.MaxSupportedActiveRoutes {
			ordered = ordered[:forwarder.MaxSupportedActiveRoutes]
		}
		status.ForwarderRouteQueues = make(map[string]forwarder.RouteQueueStats, len(ordered))
		for _, route := range ordered {
			stats := route.Stats
			stats.PeerKeyDisplay = ingress.RedactKey(route.PeerKey)
			status.ForwarderRouteQueues[ingress.PeerKeyFingerprint(route.PeerKey)] = stats
		}
	}

	writes := f.DeviceWriteSnapshot()
	status.ForwarderDeviceWriteErrors = writes.Errors
	status.ForwarderDeviceWriteDurationMS = uint64(writes.TotalDuration.Milliseconds()) // #nosec G115 -- completed write durations are non-negative.
	status.ForwarderDeviceWriteCount = writes.Count
	status.ForwarderDeviceWritesInFlight = writes.InFlight
	status.ForwarderDeviceWriteOldestMS = writes.OldestInFlight.Milliseconds()
	status.ForwarderDeviceWriteMaxMS = writes.MaxDuration.Milliseconds()
	status.ForwarderDeviceWriteStalls = writes.Stalls
	status.ForwarderDeviceWriteStallMS = forwarder.DeviceWriteStallThreshold.Milliseconds()
}

// TotalDroppedPackets returns the sum of dropped packets across all active backend devices.
func (s *Service) TotalDroppedPackets() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total uint64
	for _, dev := range s.backendDevices {
		if dev != nil {
			total += dev.DroppedPackets()
		}
	}
	return total
}

// SessionsEnriched returns active sessions with identity joins and persisted
// traffic resolved from the database, plus the forwarder accountant's
// un-flushed buffered deltas on top: rx/tx are the last-flushed DB totals
// (production-live via the periodic Flush into UpdateVPNSessionTraffic)
// plus whatever RecordRx/RecordTx has buffered but not yet flushed.
// last_seen comes from the DB row only: it is the last accounted traffic
// activity visible via the accountant flush — not transport-level peer
// liveness (review-2 P2). Read-path only (issue #189).
//
// Row-set source is the DB. For the admin table that must agree with the
// active-sessions card by construction, use SessionsLive instead.
func (s *Service) SessionsEnriched(ctx context.Context) ([]models.EnrichedVPNSession, error) {
	if s.db == nil {
		return nil, errors.New("database not available")
	}

	sessions, err := s.db.GetEnrichedActiveVPNSessions(ctx)
	if err != nil {
		return nil, err
	}

	return s.applyBufferedAccountantDeltas(sessions), nil
}

// applyBufferedAccountantDeltas adds the forwarder accountant's un-flushed
// buffered rx/tx deltas onto each session's persisted counters. Exact, no
// double counting: Flush swaps each buffer to 0 when it persists the drained
// amount into the DB row. Shared by SessionsEnriched (DB truth) and
// SessionsLive (memory truth).
func (s *Service) applyBufferedAccountantDeltas(sessions []models.EnrichedVPNSession) []models.EnrichedVPNSession {
	s.mu.RLock()
	accountant := s.accountant
	s.mu.RUnlock()
	if accountant == nil {
		return sessions
	}
	for i := range sessions {
		if rx, tx := accountant.GetSessionTraffic(sessions[i].ID); rx != 0 || tx != 0 {
			sessions[i].RxBytes += rx
			sessions[i].TxBytes += tx
		}
	}
	return sessions
}

// SessionsLive is the memory-authoritative variant of SessionsEnriched
// (issue #189 improvement round): the SNAPSHOT (row membership) comes from
// the SessionManager's in-memory connected set, the same source the
// active-sessions card counts, so the card and the admin table can never
// disagree. Ghost DB rows (peers that vanished without a teardown) cannot
// appear, and a live session can never be missing from the table.
//
// Identity is resolved by PEER PUBLIC KEY (issue #213), not by vpn_sessions
// row survival: the peer key is the stable connection-config identity
// (user_connections.client_id, the same key DBAuthenticator authenticates),
// so a live session keeps its username and server identity even when its
// vpn_sessions row is displaced (e.g. the UNIQUE assigned_ip collision when
// another user's config legitimately reclaims the IP). The username comes
// from user_connections -> users, the server identity from the snapshot's
// backend tunnel -> servers. Identity fallbacks match the DB-enriched path:
// a peer key with no user_connections row (or a user row gone) renders
// 'unknown'; a tunnel missing from backend_tunnels renders
// 'Server #<tunnelID>' with server ID 0.
//
// Traffic counters and displayed last_seen are NOT memory-authoritative:
// while in-memory session liveness is kept fresh by TouchSession() in
// handleTransportData to prevent premature idle reaping (issue #294),
// displayed last_seen and rx/tx counters in SessionsLive reflect accounting
// activity telemetry persisted by TrafficAccountant.Flush rather than real-time
// per-packet transport timestamps. rx/tx/last_seen are seeded from the
// persisted vpn_sessions row by session ID (cumulative-since-connect totals,
// written incrementally by TrafficAccountant.Flush), and the accountant's
// un-flushed buffered deltas are added on top. The displayed value is
// therefore DB cumulative + buffered, continuous across flushes. A session
// with no DB row (brand-new session, displaced row, enrichment miss) keeps
// the snapshot's zeros and in-memory last_seen; the buffered deltas still
// apply to it either way.
//
// ConnectionName is the value captured at handshake from the authenticating
// user_connection; the manager always knows it, so no fallback is needed.
// Like the DB path, displayed last_seen is accounting activity telemetry
// (the last flush that moved counters), not transport-level liveness proof.
func (s *Service) SessionsLive(ctx context.Context) ([]models.EnrichedVPNSession, error) {
	if s.db == nil {
		return nil, errors.New("database not available")
	}
	if s.sessionMgr == nil {
		return nil, errors.New("session manager not initialized")
	}

	snapshot := s.sessionMgr.ListActiveSessionsSnapshot()

	out := make([]models.EnrichedVPNSession, 0, len(snapshot))
	for i := range snapshot {
		sess := snapshot[i]
		out = append(out, models.EnrichedVPNSession{
			ID:              sess.ID,
			UserID:          sess.UserID,
			Username:        "unknown",
			BackendTunnelID: sess.BackendTunnelID,
			ServerID:        0,
			ServerName:      fmt.Sprintf("Server #%d", sess.BackendTunnelID),
			PeerPublicKey:   sess.PeerPublicKey,
			AssignedIP:      sess.AssignedIP,
			ConnectedAt:     sess.ConnectedAt,
			LastSeen:        sess.LastSeen,
			RxBytes:         sess.RxBytes,
			TxBytes:         sess.TxBytes,
			Status:          sess.Status,
			ConnectionName:  sess.ConnectionName,
		})
	}
	if len(out) == 0 {
		return out, nil
	}

	// Traffic/last_seen seeding (issue #213: unchanged contract) — single
	// pass over vpn_sessions by session ID. QMARK placeholders
	// (modernc.org/sqlite).
	ids := make([]string, 0, len(out))
	seen := make(map[string]struct{}, len(out))
	for i := range out {
		if _, dup := seen[out[i].ID]; dup {
			continue
		}
		seen[out[i].ID] = struct{}{}
		ids = append(ids, out[i].ID)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	trafficQuery := `SELECT s.id,
		COALESCE(s.rx_bytes, 0) AS rx_bytes, COALESCE(s.tx_bytes, 0) AS tx_bytes,
		COALESCE(s.last_seen, '') AS last_seen
		FROM vpn_sessions s
		WHERE s.id IN (` + placeholders + `)`

	rows, err := s.db.QueryContext(ctx, trafficQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich live vpn session traffic: %w", err)
	}

	type liveTraffic struct {
		rxBytes  int64
		txBytes  int64
		lastSeen time.Time
	}
	byID := make(map[string]liveTraffic, len(ids))
	for rows.Next() {
		var id string
		var traffic liveTraffic
		var lastSeenStr string
		if err := rows.Scan(&id, &traffic.rxBytes, &traffic.txBytes, &lastSeenStr); err != nil {
			_ = rows.Close() // early close; error already superseding
			return nil, fmt.Errorf("failed to scan live vpn session traffic: %w", err)
		}
		if lastSeenStr != "" {
			if ts, err := time.Parse(time.RFC3339, lastSeenStr); err == nil {
				traffic.lastSeen = ts
			}
		}
		byID[id] = traffic
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // early close; error already superseding
		return nil, fmt.Errorf("failed to iterate live vpn session traffic: %w", err)
	}
	_ = rows.Close() // fully iterated; release before the identity queries

	// Identity resolution keyed by PEER PUBLIC KEY (issue #213): the peer
	// key is the stable connection-config identity, so the username
	// survives vpn_sessions row displacement. user_connections.client_id is
	// cryptographically unique by construction (Curve25519 public key;
	// enforced in practice by the auth path treating it as the identity
	// key, not by a schema constraint — same precedent as
	// DBAuthenticator.AuthenticatePeer). Duplicates, if data ever
	// degenerated, would map to an arbitrary-but-stable iteration winner
	// and must not fabricate traffic.
	peerIdentities, err := s.resolvePeerIdentitiesByPeerKey(ctx, out)
	if err != nil {
		return nil, err
	}

	// Server identity from the snapshot's backend tunnel (independent of
	// vpn_sessions): one small pass over backend_tunnels + servers, scoped
	// to the DISTINCT tunnels the live snapshot references (backend_tunnels
	// grows unboundedly; only snapshot tunnels are needed). A tunnel gone
	// from the table falls back to 'Server #<tunnelID>'.
	tunnelIDs := make([]int64, 0, len(out))
	tunnelSeen := make(map[int64]struct{}, len(out))
	for i := range out {
		if _, dup := tunnelSeen[out[i].BackendTunnelID]; dup {
			continue
		}
		tunnelSeen[out[i].BackendTunnelID] = struct{}{}
		tunnelIDs = append(tunnelIDs, out[i].BackendTunnelID)
	}
	byTunnel, err := s.resolveServerNamesByTunnel(ctx, tunnelIDs)
	if err != nil {
		return nil, err
	}

	// Merge. Identity (peer-key pass, authoritative) and server identity
	// (snapshot tunnel) are applied unconditionally; traffic/last_seen are
	// applied only when the vpn_sessions row exists. Misses keep the
	// fallbacks set above — same COALESCE semantics as the DB-enriched
	// read path. When the DB row exists it is authoritative for traffic
	// and last_seen: the persisted counters are cumulative (Flush adds
	// deltas via UpdateVPNSessionTraffic), and the snapshot's per-session
	// counters never move in production, so seeding from the DB is what
	// keeps the displayed total continuous across flushes. Rows without a
	// DB row keep the snapshot's zero counters and in-memory last_seen;
	// the buffered deltas are added below either way.
	for i := range out {
		if id, ok := peerIdentities[out[i].PeerPublicKey]; ok {
			out[i].Username = id.username
			out[i].ConnectionID = id.connectionID
		}
		if srv, ok := byTunnel[out[i].BackendTunnelID]; ok {
			out[i].ServerID = srv.serverID
			out[i].ServerName = srv.serverName
		}
		if traffic, ok := byID[out[i].ID]; ok {
			out[i].RxBytes = traffic.rxBytes
			out[i].TxBytes = traffic.txBytes
			if !traffic.lastSeen.IsZero() {
				out[i].LastSeen = traffic.lastSeen
			}
		}
	}

	return s.applyBufferedAccountantDeltas(out), nil
}

type livePeerIdentity struct {
	username     string
	connectionID string
}

// resolvePeerIdentitiesByPeerKey resolves session identity and connection ID by PEER PUBLIC KEY
// (issue #213, issue #447): user_connections.client_id is the stable connection-config
// identity, so the username and connection ID survive vpn_sessions row displacement.
func (s *Service) resolvePeerIdentitiesByPeerKey(ctx context.Context, sessions []models.EnrichedVPNSession) (map[string]livePeerIdentity, error) {
	peerKeys := make([]string, 0, len(sessions))
	peerSeen := make(map[string]struct{}, len(sessions))
	for i := range sessions {
		pk := sessions[i].PeerPublicKey
		if pk == "" {
			continue
		}
		if _, dup := peerSeen[pk]; dup {
			continue
		}
		peerSeen[pk] = struct{}{}
		peerKeys = append(peerKeys, pk)
	}
	identities := make(map[string]livePeerIdentity, len(peerKeys))
	if len(peerKeys) == 0 {
		return identities, nil
	}

	pkPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(peerKeys)), ",")
	pkArgs := make([]any, len(peerKeys))
	for i, pk := range peerKeys {
		pkArgs[i] = pk
	}
	identityQuery := `SELECT uc.client_id AS pk, COALESCE(u.username, 'unknown') AS username,
		COALESCE(uc.id, '') AS connection_id
		FROM user_connections uc
		LEFT JOIN users u ON u.id = uc.user_id
		WHERE uc.client_id IN (` + pkPlaceholders + `)`

	idRows, err := s.db.QueryContext(ctx, identityQuery, pkArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve live session identity by peer key: %w", err)
	}
	defer idRows.Close()
	for idRows.Next() {
		var pk, username, connID string
		if err := idRows.Scan(&pk, &username, &connID); err != nil {
			return nil, fmt.Errorf("failed to scan live session identity: %w", err)
		}
		identities[pk] = livePeerIdentity{
			username:     username,
			connectionID: connID,
		}
	}
	if err := idRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate live session identities: %w", err)
	}
	return identities, nil
}

// liveServerIdentity is one backend tunnel's resolved server identity.
type liveServerIdentity struct {
	serverID   int64
	serverName string
}

// resolveServerNamesByTunnel maps backend tunnel IDs to server identity
// (independent of vpn_sessions): backend_tunnels -> servers by tunnel ID,
// scoped to the caller-supplied DISTINCT tunnel IDs (the ones the live
// snapshot references). tunnelIDs empty -> empty map, no query. A tunnel
// missing from backend_tunnels simply has no entry; callers keep their
// fallback.
func (s *Service) resolveServerNamesByTunnel(ctx context.Context, tunnelIDs []int64) (map[int64]liveServerIdentity, error) {
	byTunnel := make(map[int64]liveServerIdentity)
	if len(tunnelIDs) == 0 {
		return byTunnel, nil
	}

	tPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(tunnelIDs)), ",")
	tArgs := make([]any, len(tunnelIDs))
	for i, id := range tunnelIDs {
		tArgs[i] = id
	}
	serverQuery := `SELECT t.id AS tunnel_id, COALESCE(t.server_id, 0) AS server_id,
		COALESCE(srv.name, 'Server #' || t.id) AS server_name
		FROM backend_tunnels t
		LEFT JOIN servers srv ON srv.id = t.server_id
		WHERE t.id IN (` + tPlaceholders + `)`

	srvRows, err := s.db.QueryContext(ctx, serverQuery, tArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve live session server identity: %w", err)
	}
	defer srvRows.Close()
	for srvRows.Next() {
		var tunnelID int64
		var srv liveServerIdentity
		if err := srvRows.Scan(&tunnelID, &srv.serverID, &srv.serverName); err != nil {
			return nil, fmt.Errorf("failed to scan live session server identity: %w", err)
		}
		byTunnel[tunnelID] = srv
	}
	if err := srvRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate live session server identities: %w", err)
	}
	return byTunnel, nil
}

// GetBackends returns all registered backend tunnels.
func (s *Service) GetBackends(ctx context.Context) ([]*models.BackendTunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.pool == nil {
		return nil, errors.New("tunnel pool not initialized")
	}
	return s.pool.ListTunnels(), nil
}

func parsePort(val any) int {
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		p, _ := strconv.Atoi(v)
		return p
	default:
		if v != nil {
			p, _ := strconv.Atoi(fmt.Sprint(v))
			return p
		}
		return 0
	}
}

// SetTunnelStatus updates the status and latency of a backend tunnel in the pool.
// Invariant (issue #289 rework): callers serialize under s.mu.Lock() against MigrateSession
// and DisableBackend to prevent check-to-commit races.
func (s *Service) SetTunnelStatus(ctx context.Context, serverID int64, status string, latencyMS int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		return tunnel.ErrTunnelNotFound
	}
	return s.pool.SetTunnelStatus(ctx, serverID, status, latencyMS)
}

// SetTunnelStatusWithVersion updates the status and latency of a backend tunnel in the pool
// if the expected tunnel ID and state version match.
func (s *Service) SetTunnelStatusWithVersion(ctx context.Context, serverID, expectedTunnelID, expectedVersion int64, status string, latencyMS int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pool == nil {
		return tunnel.ErrTunnelNotFound
	}
	return s.pool.SetTunnelStatusIfCurrentWithVersion(ctx, serverID, expectedTunnelID, expectedVersion, status, latencyMS)
}

// DisableBackend disables a backend server and initiates connection draining.
func (s *Service) DisableBackend(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.disableBackendLocked(ctx, serverID)
}

// disableBackendLocked applies DisableBackend semantics; the caller must hold
// s.mu (write). It disables the tunnel, detaches and closes the backend's
// forwarder device, and fails over active sessions (sticky affinities, DB
// rows, live forwarder routes, pool counters) onto healthy backends so
// traffic keeps flowing before any further mutation by the caller.
func (s *Service) disableBackendLocked(ctx context.Context, serverID int64) error {
	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}

	tunnel, err := s.pool.GetTunnel(serverID)
	if err != nil {
		return err
	}

	if err := s.pool.SetTunnelEnabled(ctx, serverID, false, models.DisableReasonAdmin); err != nil {
		return fmt.Errorf("failed to persist administrative backend disable: %w", err)
	}

	if s.prober != nil {
		s.prober.MarkAdminDisabled(serverID)
	}

	// Detach and stop the backend UDP device created by EnableBackend so the
	// forwarder stops routing client packets to a disabled backend.
	if s.forwarder != nil {
		s.forwarder.DetachBackendDevice(tunnel.ID)
	}
	if dev, ok := s.backendDevices[tunnel.ID]; ok {
		if dev != nil {
			_ = dev.Close()
		}
		if dev != nil {
			// The retirement TRANSFER: the device's direction x reason
			// breakdown moves into the lifetime buckets, so nothing is
			// double counted while it was live and nothing is reclassified
			// now that it is gone.
			s.retiredBackendDeviceDrops.addInto(snapshotBackendDeviceDrops(dev))
		}
		delete(s.backendDevices, tunnel.ID)
	}
	if s.backendDeviceEndpoints != nil {
		delete(s.backendDeviceEndpoints, tunnel.ID)
	}

	// Trigger failover for active sessions on this backend
	if s.stickyMgr != nil {
		activeTunnels := s.pool.GetActiveTunnels()
		// Issue #85: HandleFailover returns a result with successful
		// migrations AND explicitly reported skipped peers — every peer left
		// on the disabled backend is logged here so stranding is visible.
		failover, err := s.stickyMgr.HandleFailover(ctx, tunnel.ID, activeTunnels)
		if err != nil {
			log.Printf("[vpn] failover for backend %d found no healthy target: %v", serverID, err)
		}
		if failover != nil {
			for _, sk := range failover.Skipped {
				log.Printf("[vpn] failover for backend %d: peer %s (user %s) NOT migrated: %s", serverID, sk.PeerPublicKey, sk.UserID, sk.Reason)
			}
		}
		// Redirect live traffic: the detached backend's device is closed, so
		// any session still routed to it would silently drop packets. The
		// sticky maps alone do not move the forwarder's per-session route.
		var migrations []loadbalancer.FailoverMigration
		if failover != nil {
			migrations = failover.Migrations
		}
		for _, m := range migrations {
			if s.forwarder != nil {
				if err := s.forwarder.UpdateSessionBackend(m.PeerPublicKey, m.NewBackendTunnelID); err != nil {
					// ErrSessionNotRegistered = session has no live route
					// (already disconnected); nothing to redirect then.
					log.Printf("[vpn] failover route redirect for peer %s -> backend %d: %v", m.PeerPublicKey, m.NewBackendTunnelID, err)
				}
			}
			// Move the connection count with the session: the pool counter
			// tracks currently-connected peers per backend and feeds
			// least-connections and capacity filtering.
			s.pool.DecrementConnections(tunnel.ID)
			s.pool.IncrementConnections(m.NewBackendTunnelID)
		}
		if len(migrations) > 0 && s.sessionMgr != nil {
			s.sessionMgr.BumpLifecycleVersion()
		}
	}

	return nil
}

func (s *Service) resolveNewBackendEndpoint(ctx context.Context, serverID int64, currentEndpoint, newHost string) (string, error) {
	cleanHost := strings.Trim(strings.TrimSpace(newHost), "[]")
	if _, port, splitErr := net.SplitHostPort(currentEndpoint); splitErr == nil && port != "" {
		return net.JoinHostPort(cleanHost, port), nil
	}
	if s.db == nil {
		return "", fmt.Errorf("database not available to resolve server %d credentials", serverID)
	}
	srv, loadErr := s.db.GetServerByID(ctx, serverID)
	if loadErr != nil || srv == nil {
		return "", fmt.Errorf("failed to load server %d: %w", serverID, loadErr)
	}
	_, p, _, credErr := s.resolveBackendCredentials(ctx, serverID, srv)
	if credErr != nil {
		return "", fmt.Errorf("failed to resolve backend credentials for server %d: %w", serverID, credErr)
	}
	return net.JoinHostPort(cleanHost, strconv.Itoa(p)), nil
}

func (s *Service) syncBackendForwarderOnHostUpdateLocked(ctx context.Context, serverID, expectedTunnelID int64, awgParams map[string]any) error {
	if s.syncBackendForwarderHook != nil {
		if err := s.syncBackendForwarderHook(); err != nil {
			return err
		}
	}

	currentTun, err := s.pool.GetTunnel(serverID)
	if err != nil {
		if errors.Is(err, tunnel.ErrTunnelNotFound) {
			return nil
		}
		return err
	}
	if currentTun == nil || currentTun.ID != expectedTunnelID {
		return nil
	}

	if !currentTun.Enabled {
		return nil
	}

	if currentTun.Status == TunnelStatusActive || currentTun.Status == TunnelStatusDegraded ||
		currentTun.Status == models.TunnelStatusActive || currentTun.Status == models.TunnelStatusDegraded {
		attachErr := s.attachBackendForwarder(currentTun, awgParams)
		if attachErr != nil {
			log.Printf("[vpn] warning: failed to attach backend forwarder for server %d after host update: %v", serverID, attachErr)
			_ = s.pool.SetTunnelStatus(ctx, serverID, TunnelStatusDegraded, 0)
			return fmt.Errorf("failed to attach backend forwarder: %w", attachErr)
		}
	}

	if s.prober != nil {
		s.prober.ResetFailCount(serverID)
	}

	return nil
}

// UpdateBackendServerHost updates the endpoint of a server in the VPN backend pool.
func (s *Service) UpdateBackendServerHost(ctx context.Context, serverID int64, newHost string) error {
	if s == nil || s.pool == nil {
		return nil
	}

	s.mu.RLock()
	injectedErr := s.updateBackendServerHostErr
	s.mu.RUnlock()
	if injectedErr != nil {
		return injectedErr
	}

	tun, err := s.pool.GetTunnel(serverID)
	if err != nil {
		if errors.Is(err, tunnel.ErrTunnelNotFound) {
			return nil
		}
		return err
	}
	if tun == nil {
		return nil
	}

	newEndpoint, err := s.resolveNewBackendEndpoint(ctx, serverID, tun.Endpoint, newHost)
	if err != nil {
		return err
	}

	if tun.Endpoint == newEndpoint {
		s.mu.RLock()
		dev := s.backendDevices[tun.ID]
		var attachedEndpoint string
		if s.backendDeviceEndpoints != nil {
			attachedEndpoint = s.backendDeviceEndpoints[tun.ID]
		}
		s.mu.RUnlock()

		// Genuinely synchronized idempotent no-op: device exists, is open,
		// and its configured endpoint matches the requested endpoint.
		if dev != nil && !dev.IsClosed() && attachedEndpoint == newEndpoint {
			return nil
		}

		// Runtime device is missing, closed, or attached to a stale endpoint -> reconcile.
		awgParams, _ := s.resolveServerAWGParams(ctx, serverID)

		s.mu.RLock()
		hook := s.updateBackendServerHostPreLockHook
		s.mu.RUnlock()
		if hook != nil {
			hook()
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		return s.syncBackendForwarderOnHostUpdateLocked(ctx, serverID, tun.ID, awgParams)
	}

	oldEndpoint := tun.Endpoint
	if err := s.pool.SetTunnelEndpoint(ctx, tun.ID, newEndpoint); err != nil {
		return fmt.Errorf("failed to update backend tunnel endpoint in pool: %w", err)
	}
	tun.Endpoint = newEndpoint

	rollbackEndpoint := func(originalErr error) error {
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rbErr := s.pool.SetTunnelEndpoint(rbCtx, tun.ID, oldEndpoint); rbErr != nil {
			log.Printf("[vpn] warning: failed to rollback backend tunnel endpoint for server %d: %v", serverID, rbErr)
			return errors.Join(originalErr, fmt.Errorf("%w: failed to restore endpoint to %s: %v", ErrVPNRollbackFailed, oldEndpoint, rbErr))
		}
		return originalErr
	}

	awgParams, _ := s.resolveServerAWGParams(ctx, serverID)

	s.mu.RLock()
	hook := s.updateBackendServerHostPreLockHook
	s.mu.RUnlock()
	if hook != nil {
		hook()
	}

	if err := ctx.Err(); err != nil {
		return rollbackEndpoint(err)
	}

	s.mu.Lock()
	syncErr := s.syncBackendForwarderOnHostUpdateLocked(ctx, serverID, tun.ID, awgParams)
	s.mu.Unlock()

	if syncErr != nil {
		return rollbackEndpoint(syncErr)
	}

	return nil
}

type deleteServerContextKey struct{}

func withDeleteServer(ctx context.Context) context.Context {
	return context.WithValue(ctx, deleteServerContextKey{}, true)
}

func isDeleteServerContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	val, ok := ctx.Value(deleteServerContextKey{}).(bool)
	return ok && val
}

func (s *Service) isServerDeletedLocked(serverID int64) bool {
	if s.deletedServers == nil {
		return false
	}
	_, ok := s.deletedServers[serverID]
	return ok
}

// DeleteServer tombstones the server to prevent concurrent resurrection by EnableBackend
// or automated self-healing, tears down any associated VPN backend tunnel and drains sessions.
func (s *Service) DeleteServer(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	if s.deletedServers == nil {
		s.deletedServers = make(map[int64]struct{})
	}
	s.deletedServers[serverID] = struct{}{}
	if s.deleteBackendErr != nil {
		err := s.deleteBackendErr
		delete(s.deletedServers, serverID)
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	err := s.DeleteBackend(withDeleteServer(ctx), serverID)
	if err != nil {
		if errors.Is(err, ErrBackendTunnelNotFound) {
			return nil
		}
		s.mu.Lock()
		delete(s.deletedServers, serverID)
		s.mu.Unlock()
		return err
	}
	return nil
}

// ClearServerDeletedTombstone removes the deletion tombstone for a server ID,
// allowing subsequent additions or restores of that server ID to succeed.
func (s *Service) ClearServerDeletedTombstone(serverID int64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deletedServers != nil {
		delete(s.deletedServers, serverID)
	}
}

// DeleteBackend permanently removes a backend tunnel from the load-balancing
// pool (issue #29): the server itself and its AWG protocol configuration are
// untouched — only the backend_tunnels registration and the in-memory pool
// entry are dropped.
//
// Ordering matters: DisableBackend semantics run FIRST (status change,
// forwarder device detach, sticky failover of connected sessions) while the
// tunnel is still resolvable, so active sessions migrate to healthy backends
// and no vpn_sessions row is left referencing the deleted backend_tunnels
// row. Only then is the tunnel removed from the pool (which also deletes the
// persisted row) and a defensive DB sweep catches any leftover row the pool
// could not see (missing row is not an error: log and continue).
func (s *Service) DeleteBackend(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.deleteBackendErr != nil {
		return s.deleteBackendErr
	}

	if s.isServerDeletedLocked(serverID) && !isDeleteServerContext(ctx) {
		return ErrBackendTunnelNotFound
	}

	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}

	// Guard: unknown backend -> not-found, before any state mutation.
	tunnel, err := s.pool.GetTunnel(serverID)
	if err != nil {
		return err
	}

	// Phase 1 — drain: disable + failover while the tunnel is still in the
	// pool, so HandleFailover's session migration has healthy targets and
	// the caller's sessions never orphan onto a removed tunnel ID.
	if err := s.disableBackendLocked(ctx, serverID); err != nil {
		return err
	}

	// Phase 2 — removal: drops the pool entries and the persisted
	// backend_tunnels row.
	if err := s.pool.RemoveTunnel(ctx, serverID); err != nil {
		return fmt.Errorf("failed to remove tunnel for server %d: %w", serverID, err)
	}

	// Phase 3 — defensive sweep: RemoveTunnel only deletes the row matching
	// the in-memory tunnel ID. If the DB drifted (row recreated under a new
	// ID, pool re-synced from a stale snapshot), a leftover backend_tunnels
	// row for this server would keep serving stale lookups. The sweep
	// reassigns any connected sessions still on it to a surviving active
	// backend, deletes the leftover row, and never fails the delete: a
	// missing row is the expected path.
	//
	// DB calls run without s.mu held (db methods take their own locks) — the
	// disabled tunnel cannot re-enter the pool in between: pool mutations
	// all happen under s.mu, which we re-acquire immediately after.
	//
	// failoverTarget is a surviving ACTIVE pool tunnel (never the deleted
	// one): reassigning sessions onto the just-deleted row would only move
	// the orphan. Zero means no healthy target exists — HandleFailover
	// already hit the same terminal state and logged it.
	failoverTarget := int64(0)
	for _, tun := range s.pool.GetActiveTunnels() {
		if tun.ID != tunnel.ID {
			failoverTarget = tun.ID
			break
		}
	}

	s.mu.Unlock()
	leftover, dbErr := s.db.GetBackendTunnelByServerID(ctx, serverID)
	if dbErr != nil {
		leftover = nil
		log.Printf("[vpn] warning: delete backend %d: DB sweep lookup failed: %v", serverID, dbErr)
	}
	if leftover != nil {
		// Reassign connected sessions that lost the failover race onto the
		// leftover row, marking them draining (issue #29: no orphaned
		// vpn_sessions row may reference a deleted backend_tunnels row).
		//
		// GetActiveVPNSessions returns ONLY status='connected' rows, so the
		// sweep covers exactly those. Sessions already marked 'draining' are
		// intentionally NOT swept: draining is a terminal state per issue
		// #44 — such sessions are winding down and must never be migrated
		// again, even if their stale backend_tunnels row is deleted here.
		if sessions, sessErr := s.db.GetActiveVPNSessions(ctx); sessErr != nil {
			log.Printf("[vpn] warning: delete backend %d: orphan-session sweep lookup failed: %v", serverID, sessErr)
		} else {
			for i := range sessions {
				if sessions[i].BackendTunnelID != leftover.ID {
					continue
				}
				if failoverTarget == 0 {
					log.Printf("[vpn] warning: delete backend %d: no healthy backend left to reassign session %s (leftover row %d deleted, session left draining)", serverID, sessions[i].ID, leftover.ID)
					continue
				}
				if err := s.db.UpdateVPNSessionBackendTunnel(ctx, sessions[i].ID, failoverTarget); err != nil {
					log.Printf("[vpn] warning: delete backend %d: could not reassign session %s off leftover row %d: %v", serverID, sessions[i].ID, leftover.ID, err)
				} else {
					log.Printf("[vpn] delete backend %d: reassigned session %s off leftover backend_tunnels row %d onto backend %d (draining)", serverID, sessions[i].ID, leftover.ID, failoverTarget)
				}
			}
		}
		if err := s.db.DeleteBackendTunnel(ctx, leftover.ID); err != nil {
			log.Printf("[vpn] warning: delete backend %d: failed to delete leftover backend_tunnels row %d: %v", serverID, leftover.ID, err)
		}
	}
	s.mu.Lock()

	return nil
}

// GetTunnel retrieves a backend tunnel by server ID from the pool.
func (s *Service) GetTunnel(serverID int64) (*models.BackendTunnel, error) {
	if s.pool == nil {
		return nil, errors.New("tunnel pool not initialized")
	}
	return s.pool.GetTunnel(serverID)
}

// GetTunnels is an alias for GetBackends.
func (s *Service) GetTunnels(ctx context.Context) ([]*models.BackendTunnel, error) {
	return s.GetBackends(ctx)
}

// GetConfig returns the active VPN configuration.
func (s *Service) GetConfig(ctx context.Context) (*models.VPNConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cfg == nil {
		return nil, errors.New("vpn config is nil")
	}
	cfgCopy := *s.cfg
	return &cfgCopy, nil
}

// UpdateConfig updates the dynamic VPN configuration and reinitializes the load balancer.
//
//nolint:gocyclo // transactional validation, persistence, runtime apply, and rollback are intentionally centralized.
func (s *Service) UpdateConfig(ctx context.Context, cfg *models.VPNConfig) error {
	if cfg == nil {
		return errors.New("vpn config cannot be nil")
	}
	if err := forwarder.ValidateClientRouteLimit(cfg.MaxTotalPeers); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var previousCfg *models.VPNConfig
	if s.cfg != nil {
		cfgCopy := *s.cfg
		previousCfg = &cfgCopy
	}
	// Preserve obfuscation parameters the incoming config omits (zero
	// H1..H4 / S1..S4) so partial updates cannot silently clobber the
	// values already distributed to peers.
	if s.cfg != nil {
		preserveObfuscationParams(s.cfg, cfg)
		enforceMinSValues(cfg)
		if cfg.ClientQueueSize <= 0 {
			cfg.ClientQueueSize = s.cfg.ClientQueueSize
		}
		// The portal identity is immutable through ordinary config updates.
		if cfg.ServerPrivateKey != "" && cfg.ServerPrivateKey != s.cfg.ServerPrivateKey {
			return errors.New("portal private key cannot be changed by config update")
		}
		if cfg.ServerPublicKey != "" && cfg.ServerPublicKey != s.cfg.ServerPublicKey {
			return errors.New("portal public key cannot be changed by config update")
		}
		cfg.ServerPrivateKey = s.cfg.ServerPrivateKey
		cfg.ServerPublicKey = s.cfg.ServerPublicKey
	}

	listenerRunning := s.running || (s.ingressEngine != nil && s.ingressEngine.Running())
	obfuscationChanged := s.cfg != nil && obfuscationDiffers(s.cfg, cfg)
	if obfuscationChanged && listenerRunning {
		log.Printf("[vpn] rejecting config update: obfuscation parameters are immutable while listener is running")
		return errors.New("obfuscation parameters are immutable while listener is running")
	}

	listenPortChanged := s.cfg != nil && cfg.ListenPort > 0 && cfg.ListenPort != s.cfg.ListenPort
	if listenPortChanged && listenerRunning {
		log.Printf("[vpn] rejecting config update: listen_port cannot change from %d to %d while listener is running", s.cfg.ListenPort, cfg.ListenPort)
		return errors.New("listen_port cannot be changed while the VPN listener is running; restart the panel")
	}

	if cfg.ClientQueueSize <= 0 {
		cfg.ClientQueueSize = forwarder.DefaultClientQueueSize
	}
	maxActiveRoutes := cfg.MaxTotalPeers
	if maxActiveRoutes <= 0 {
		maxActiveRoutes = 1000
	}
	maxQueue := forwarder.MaxClientQueuePacketsForRoutes(maxActiveRoutes)
	if cfg.ClientQueueSize > maxQueue {
		cfg.ClientQueueSize = maxQueue
	}
	queueSizeChanged := false
	routeLimitChanged := false
	if s.cfg != nil && s.forwarder != nil {
		oldQueueSize := s.cfg.ClientQueueSize
		if oldQueueSize <= 0 {
			oldQueueSize = forwarder.DefaultClientQueueSize
		}
		oldMaxActiveRoutes := s.cfg.MaxTotalPeers
		if oldMaxActiveRoutes <= 0 {
			oldMaxActiveRoutes = 1000
		}
		queueSizeChanged = cfg.ClientQueueSize != oldQueueSize
		routeLimitChanged = maxActiveRoutes != oldMaxActiveRoutes
	}

	caps := loadbalancer.CapacityConfig{
		MaxTotalPeers:      cfg.MaxTotalPeers,
		MaxPeersPerBackend: cfg.MaxPeersPerBackend,
		AffinityTTL:        time.Duration(cfg.AffinityTTLMinutes) * time.Minute,
	}
	newLB, err := loadbalancer.NewLoadBalancer(cfg.Algorithm, cfg.Weights, caps)
	if err != nil {
		return fmt.Errorf("invalid load balancer configuration: %w", err)
	}

	if s.db != nil {
		if err := s.db.SaveVPNConfig(ctx, cfg); err != nil {
			return fmt.Errorf("failed to persist vpn config: %w", err)
		}
	}
	if queueSizeChanged || routeLimitChanged {
		if err := s.forwarder.ReconfigureClientQueueConfig(cfg.ClientQueueSize, maxActiveRoutes); err != nil {
			if s.db != nil && previousCfg != nil {
				if rollbackErr := s.db.SaveVPNConfig(ctx, previousCfg); rollbackErr != nil {
					return fmt.Errorf("cannot apply client queue size: %w; persistence rollback failed: %v", err, rollbackErr)
				}
			}
			return fmt.Errorf("cannot apply client queue size: %w", err)
		}
	}
	s.cfg = cfg

	s.balancer = newLB
	if s.stickyMgr != nil {
		s.stickyMgr = loadbalancer.NewStickySessionManager(s.db, newLB, caps)
	}

	return nil
}

// GetUserConnectionState retrieves current VPN connectivity state for a user.
func (s *Service) GetUserConnectionState(ctx context.Context, userID string) (*UserVPNState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sessionMgr == nil {
		return &UserVPNState{Connected: false}, nil
	}

	sessions := s.sessionMgr.GetSessionsByUserID(userID)
	if len(sessions) == 0 {
		return &UserVPNState{Connected: false}, nil
	}

	sess := sessions[0]
	state := &UserVPNState{
		Connected: true,
		Session:   sess,
	}

	if s.pool != nil {
		if t, err := s.pool.GetTunnelByID(sess.BackendTunnelID); err == nil && t != nil {
			state.BackendServerID = t.ServerID
			state.BackendEndpoint = t.Endpoint
			state.LatencyMS = t.LatencyMS
		}
	}

	return state, nil
}

// DisconnectUser disconnects all active VPN sessions for a user.
func (s *Service) DisconnectUser(ctx context.Context, userID string) error {
	var retirements []forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		for _, retirement := range retirements {
			retirement.Wait()
		}
	}()

	if s.sessionMgr == nil {
		return nil
	}

	sessions := s.sessionMgr.GetSessionsByUserID(userID)
	for _, sess := range sessions {
		_ = s.sessionMgr.CloseSession(ctx, sess.ID, "disconnected")
		if s.forwarder != nil {
			retirements = append(retirements, s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID))
		}
		if s.stickyMgr != nil {
			s.stickyMgr.ClearAffinity(userID)
			s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
		}
		// The counter feeds least-connections and capacity filtering; without
		// the decrement it becomes a lifetime cumulative count and backends
		// eventually look permanently full.
		s.pool.DecrementConnections(sess.BackendTunnelID)
	}

	return nil
}

// reapSession tears down an idle-timed-out session routing-only:
// forwarder route retirement and guarded pool decrement.
func (s *Service) reapSession(ctx context.Context, sess *models.VPNSession) {
	if sess == nil {
		return
	}
	s.reapIngressSession(sess)
}

// reapIngressSession performs the routing-only teardown of an idle upstream
// backend session (issue #390 part 1). It holds the same s.mu admission
// serialization regime reapSession always held, retires the forwarder route
// with the session-identity guard (a recreated session's route is never
// removed by an old reap — the forwarder's generation-bounded delete holds),
// and applies the same reconciliation-guarded pool decrement as the legacy
// path. It MUST NOT touch endpoint transport state or generation fences, and
// it never removes the configured upstream peer (durable user_connections /
// clientawg identity): the peer stays configured and idle after its backend
// routing session is retired; the peer's crypto state outlives any number of
// Nexus backend sessions.
//
// Liveness guard: CheckTimeouts removes the session it reaps, so a live
// session for the peer under s.mu means a concurrent admission raced this
// reap. Two sub-cases:
//
//   - Same ID still live: the admission's LastSeen-based reuse refreshed the
//     session (traffic won the race); it still owns its route and pool
//     count — this reap is a full no-op.
//   - Different live ID: the admission created a fresh session (CheckTimeouts
//     had already removed this one, so no replacement hook moved its count).
//     This reap still owns the OLD pool decrement, but must not touch the
//     route — the new session's registration owns it now.
//
// Without the same-ID no-op, a reused session's freshly re-validated route
// could be retired by the racing reap (route == "" while the session reports
// connected — every return packet lost; found by the reap/recreate race
// test). Without the different-ID decrement, the old session's count leaks
// (gauge sum 2 for one live session; found by the same test pair).
func (s *Service) reapIngressSession(sess *models.VPNSession) {
	var retirement forwarder.Retirement
	var reaped bool
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if reaped {
			log.Printf("[vpn/service] reaped idle upstream session (routing-only): id=%s peer=%s user=%s ip=%s tunnel_id=%d",
				sess.ID, sess.PeerPublicKey, sess.UserID, sess.AssignedIP, sess.BackendTunnelID)
		}
	}()

	skipRoute := false
	if live, exists := s.sessionMgr.GetSessionSnapshotByPeer(sess.PeerPublicKey); exists {
		if live.ID == sess.ID {
			// Refreshed/reuse won the race: still live, owns everything.
			log.Printf("[vpn/service] skip idle reap of upstream session id=%s peer=%s: session is live again",
				sess.ID, sess.PeerPublicKey)
			return
		}
		// Fresh-creation replacement won: skip route retirement, keep the
		// old session's pool decrement (no hook moved it).
		skipRoute = true
		log.Printf("[vpn/service] reap of upstream session id=%s peer=%s: peer already re-admitted as %s; retiring the old count only",
			sess.ID, sess.PeerPublicKey, live.ID)
	}

	reaped = true

	if !skipRoute && s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}

	if s.pool != nil {
		shouldDecrement := true
		var tunReconcileTime time.Time
		if s.lastReconcileByTunnel != nil {
			tunReconcileTime = s.lastReconcileByTunnel[sess.BackendTunnelID]
		}
		if !sess.TimedOutAt.IsZero() && !tunReconcileTime.IsZero() && tunReconcileTime.After(sess.TimedOutAt) {
			shouldDecrement = false
		}
		if shouldDecrement {
			s.pool.DecrementConnections(sess.BackendTunnelID)
		}
	}
}

// PruneExpiredAffinity scans and removes expired sticky affinity records
// from the load balancer. It acquires s.mu with RLock only long enough to
// retrieve stickyMgr, then executes pruning outside s.mu to eliminate
// lock contention during mass session reap sweeps.
func (s *Service) PruneExpiredAffinity() int {
	s.mu.RLock()
	sm := s.stickyMgr
	s.mu.RUnlock()
	if sm == nil {
		return 0
	}
	return sm.PruneExpired()
}

// DisconnectSession disconnects a specific VPN session by ID routing-only.
func (s *Service) DisconnectSession(ctx context.Context, sessionID string) error {
	var retirement forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
	}()

	if s.sessionMgr == nil {
		return nil
	}

	sess, ok := s.sessionMgr.GetSessionByID(sessionID)
	if !ok {
		return session.ErrSessionNotFound
	}

	_ = s.sessionMgr.CloseSession(ctx, sessionID, "disconnected")
	if s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}
	if s.stickyMgr != nil {
		s.stickyMgr.ClearAffinity(sess.UserID)
		s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
	}
	if s.pool != nil {
		s.pool.DecrementConnections(sess.BackendTunnelID)
	}

	return nil
}

// RevokeUpstreamPeerSession performs immediate routing-only teardown for an
// upstream peer whose durable connection was removed or disabled (issue #391).
// It closes the active session in SessionManager with reason "revoked", retires
// the forwarder route, clears sticky affinity, and decrements backend pool
// active connections. It does NOT advance endpoint peer generations, touch
// upstream transport keys, or release the peer's durable IP allocation.
func (s *Service) RevokeUpstreamPeerSession(ctx context.Context, peerKey string) error {
	if s == nil || s.sessionMgr == nil {
		return nil
	}
	var retirement forwarder.Retirement
	var reapedSess *models.VPNSession
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if reapedSess != nil {
			log.Printf("[vpn/service] revoked upstream peer session (routing-only): id=%s peer=%s user=%s ip=%s tunnel_id=%d",
				reapedSess.ID, reapedSess.PeerPublicKey, reapedSess.UserID, reapedSess.AssignedIP, reapedSess.BackendTunnelID)
		}
	}()

	sess, ok := s.sessionMgr.GetSession(peerKey)
	if !ok {
		return nil
	}
	if s.preRevokeCloseHookForTest != nil {
		s.preRevokeCloseHookForTest(sess.PeerPublicKey, sess.ID)
	}
	if err := s.sessionMgr.CloseSession(ctx, sess.ID, "revoked"); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			// The session was already evicted (e.g. by CheckTimeouts); the idle reaper owns teardown.
			return nil
		}
		return fmt.Errorf("close revoked session %s: %w", sess.ID, err)
	}
	reapedSess = sess
	if s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}
	if s.stickyMgr != nil {
		s.stickyMgr.ClearAffinity(sess.UserID)
		s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
	}
	if s.pool != nil {
		s.pool.DecrementConnections(sess.BackendTunnelID)
	}
	return nil
}

// SetPreRevokeCloseHookForTest sets a test hook called under s.mu in RevokeUpstreamPeerSession
// immediately after GetSession and before CloseSession to deterministically test eviction races.
func (s *Service) SetPreRevokeCloseHookForTest(fn func(peerKey, sessionID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preRevokeCloseHookForTest = fn
}

// SetPreAdoptHookForTest sets a test hook called under s.mu in ensureBackendSessionForIngress
// immediately before calling AdoptSessionForIngress (issue #390).
func (s *Service) SetPreAdoptHookForTest(fn func(peerKey, sessionID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preAdoptHookForTest = fn
}

// SetPreIngressRouteRegistrationHookForTest sets a test hook called under s.mu
// in ensureBackendSessionForIngress immediately before forwarder route registration.
func (s *Service) SetPreIngressRouteRegistrationHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preIngressRouteRegistrationHookForTest = fn
}

// SetPreCommitMigrationHookForTest sets a test hook called under s.mu in MigrateSession
// immediately before committing connection counters to the target tunnel (issue #289 rework).
func (s *Service) SetPreCommitMigrationHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preCommitMigrationHookForTest = fn
}

// validateMigrationTarget checks that targetTunnelID exists and is eligible for
// migration - administratively enabled AND runtime-active (issue #90) -
// returning its StateVersion. The eligibility preflight must run before any
// migration mutation so a disabled target is rejected without touching the
// forwarder route, SessionManager state, or the DB session row.
func (s *Service) validateMigrationTarget(targetTunnelID int64) (int64, error) {
	if s.pool == nil {
		return 0, nil
	}
	targetTun, err := s.pool.GetTunnelByID(targetTunnelID)
	if err != nil {
		return 0, fmt.Errorf("target backend tunnel %d not found in pool: %w", targetTunnelID, err)
	}
	if !targetTun.Enabled || !strings.EqualFold(targetTun.Status, models.TunnelStatusActive) {
		return 0, fmt.Errorf("target backend tunnel %d is not eligible (enabled=%t status=%s)",
			targetTunnelID, targetTun.Enabled, targetTun.Status)
	}
	return targetTun.StateVersion, nil
}

// rollbackMigration reverts mutations across DB, SessionManager, and Forwarder during a failed migration.
// The DB compensation executes under a non-cancelable bounded context derived from ctx to guarantee
// completion even if the request context was canceled (issue #289 rework round 3).
func (s *Service) rollbackMigration(ctx context.Context, sessionID, peerKey string, oldTunnelID int64, oldStatus string, forwarderMigrated, rollbackSessionMgr, rollbackDB bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	var rollbackErrs []error

	if rollbackDB && s.db != nil {
		if err := s.db.MigrateVPNSessionBackend(rollbackCtx, sessionID, oldTunnelID); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback db session %s to backend %d: %w", sessionID, oldTunnelID, err))
		}
	}
	if rollbackSessionMgr && s.sessionMgr != nil {
		if err := s.sessionMgr.RollbackSessionBackend(sessionID, oldTunnelID, oldStatus); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback session mgr %s to backend %d: %w", sessionID, oldTunnelID, err))
		}
	}
	if forwarderMigrated && s.forwarder != nil {
		if err := s.forwarder.UpdateSessionBackend(peerKey, oldTunnelID); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback forwarder peer %s to backend %d: %w", peerKey, oldTunnelID, err))
		}
	}

	return errors.Join(rollbackErrs...)
}

// MigrateSession migrates an active session to a target backend tunnel, updating
// the live forwarder route, in-memory session, database state, and pool counters atomically
// with full rollback across all subsystems if any step fails (issue #289, rework).
//
// Invariant (issue #86, #289): caller executes under s.mu.Lock(), maintaining the
// lock ordering s.mu -> SessionManager.mu (never reversed), and preserving serialization
// for pool connection counters and route transitions.
func (s *Service) MigrateSession(ctx context.Context, sessionID string, targetTunnelID int64) error {
	if s == nil {
		return errors.New("vpn service is nil")
	}
	if sessionID == "" {
		return errors.New("empty session id")
	}
	if targetTunnelID <= 0 {
		return errors.New("invalid target tunnel id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	expectedVersion, err := s.validateMigrationTarget(targetTunnelID)
	if err != nil {
		return err
	}

	if s.sessionMgr == nil {
		return errors.New("session manager is not initialized")
	}

	sess, ok := s.sessionMgr.GetSessionSnapshotByID(sessionID)
	if !ok {
		return session.ErrSessionNotFound
	}

	peerKey := sess.PeerPublicKey
	oldTunnelID := sess.BackendTunnelID
	oldStatus := sess.Status
	if oldStatus == "" {
		oldStatus = "connected"
	}

	if oldTunnelID == targetTunnelID {
		return nil
	}

	// Step 1: Live Forwarder Route Migration
	var forwarderMigrated bool
	if s.forwarder != nil {
		if err := s.forwarder.UpdateSessionBackend(peerKey, targetTunnelID); err != nil {
			if !errors.Is(err, forwarder.ErrSessionNotRegistered) {
				return fmt.Errorf("failed to update live forwarder route for session %s: %w", sessionID, err)
			}
		} else {
			forwarderMigrated = true
		}
	}

	// Step 2: In-Memory Session Update
	if _, _, _, err := s.sessionMgr.UpdateSessionBackend(sessionID, targetTunnelID, "connected"); err != nil {
		rbErr := s.rollbackMigration(ctx, sessionID, peerKey, oldTunnelID, oldStatus, forwarderMigrated, false, false)
		return errors.Join(fmt.Errorf("failed to update in-memory session %s: %w", sessionID, err), rbErr)
	}

	// Step 3: Database Persistence
	if s.db != nil {
		if err := s.db.MigrateVPNSessionBackend(ctx, sessionID, targetTunnelID); err != nil {
			rbErr := s.rollbackMigration(ctx, sessionID, peerKey, oldTunnelID, oldStatus, forwarderMigrated, true, false)
			return errors.Join(fmt.Errorf("failed to persist vpn session %s backend migration: %w", sessionID, err), rbErr)
		}
	}

	// Step 4.5: Pre-commit hook for testing check-to-commit races
	if s.preCommitMigrationHookForTest != nil {
		s.preCommitMigrationHookForTest()
	}

	// Step 5: Transfer Connection Counters
	if s.pool != nil {
		if err := s.pool.TransferConnectionsIfActive(oldTunnelID, targetTunnelID, expectedVersion); err != nil {
			rbErr := s.rollbackMigration(ctx, sessionID, peerKey, oldTunnelID, oldStatus, forwarderMigrated, true, true)
			return errors.Join(fmt.Errorf("failed to commit connection transfer to target tunnel %d: %w", targetTunnelID, err), rbErr)
		}
	}

	if s.stickyMgr != nil {
		s.stickyMgr.AssignPeerAffinity(peerKey, targetTunnelID)
	}
	s.sessionMgr.BumpLifecycleVersion()

	log.Printf("[vpn] migrated session %s (peer %s) from backend %d to backend %d (connected)",
		sessionID, peerKey, oldTunnelID, targetTunnelID)
	slog.Info("Migrated VPN session backend route",
		"session_id", sessionID,
		"peer_key", peerKey,
		"source_tunnel_id", oldTunnelID,
		"target_tunnel_id", targetTunnelID,
		"status", "connected",
	)

	return nil
}

// MigrateVPNSession is an alias for MigrateSession.
func (s *Service) MigrateVPNSession(ctx context.Context, sessionID string, targetTunnelID int64) error {
	return s.MigrateSession(ctx, sessionID, targetTunnelID)
}

// ReleaseClient releases IPAM allocations and disconnects any active sessions for the client.
func (s *Service) ReleaseClient(ctx context.Context, clientPub string) error {
	var retirement forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
	}()

	if s.sessionMgr != nil && clientPub != "" {
		if sess, ok := s.sessionMgr.GetSession(clientPub); ok {
			_ = s.sessionMgr.CloseSession(ctx, sess.ID, "client_deleted")
			if s.forwarder != nil {
				retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
			}
			if s.stickyMgr != nil {
				s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
			}
			if s.pool != nil {
				s.pool.DecrementConnections(sess.BackendTunnelID)
			}
		}
	}

	if s.ipam != nil && clientPub != "" {
		_ = s.ipam.Release(clientPub)
	}

	return nil
}

// SetSessionReaperHookForTest sets a test hook invoked by SweepTimedOutSessions for each reaped session.
func (s *Service) SetSessionReaperHookForTest(fn func(context.Context, *models.VPNSession)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reaperHook = fn
}

// SweepTimedOutSessions sweeps for idle-timed-out sessions and invokes reapSession
// (or the test reaper hook) for each timed-out session.
func (s *Service) SweepTimedOutSessions(ctx context.Context) ([]*models.VPNSession, error) {
	if s == nil || s.sessionMgr == nil {
		return nil, nil
	}
	timeout := 3 * time.Minute
	timedOut, err := s.sessionMgr.CheckTimeouts(ctx, timeout)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	hook := s.reaperHook
	s.mu.RUnlock()
	for _, sess := range timedOut {
		if hook != nil {
			hook(ctx, sess)
		} else {
			s.reapSession(ctx, sess)
		}
	}
	return timedOut, nil
}

func (s *Service) selectTunnelForPeer(ctx context.Context, req *loadbalancer.RoutingRequest) (*models.BackendTunnel, error) {
	if s.stickyMgr != nil {
		b, _, err := s.stickyMgr.GetOrAssignBackend(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("backend selection failed: %w", err)
		}
		return b, nil
	}
	if s.balancer != nil {
		b, err := s.balancer.SelectBackend(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("backend selection failed: %w", err)
		}
		return b, nil
	}
	return nil, loadbalancer.ErrNoActiveBackends
}

// SelectTunnel selects a backend tunnel using the configured load balancing algorithm.
func (s *Service) SelectTunnel(ctx context.Context, tunnels []*models.BackendTunnel) (*models.BackendTunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.balancer == nil {
		return nil, fmt.Errorf("load balancer not initialized")
	}

	req := &loadbalancer.RoutingRequest{
		AvailableTunnels: tunnels,
	}
	return s.balancer.SelectBackend(ctx, req)
}

// GenerateUserClientConfig is an alias for GenerateClientConfig for API clarity.
func (s *Service) GenerateUserClientConfig(ctx context.Context, userID string) (string, string, error) {
	return s.GenerateClientConfig(ctx, userID)
}

func resolveHeaderProtectionKey(ctx context.Context, db *database.DB, cfg *models.VPNConfig, awgParams *awg.AWGParams) {
	if awgParams.HeaderProtectionKey == "" {
		if cfg != nil && cfg.HeaderProtectionKey != "" {
			awgParams.HeaderProtectionKey = cfg.HeaderProtectionKey
		} else if db != nil {
			if vpnCfg, err := db.GetVPNConfig(ctx); err == nil && vpnCfg != nil && vpnCfg.HeaderProtectionKey != "" {
				awgParams.HeaderProtectionKey = vpnCfg.HeaderProtectionKey
			}
		}
	}
	if awgParams.HeaderProtectionKey != "" {
		ensureMinJunk := func(valStr *string, minVal int) {
			num, err := strconv.Atoi(*valStr)
			if err != nil || num < minVal {
				*valStr = strconv.Itoa(minVal)
			}
		}
		ensureMinJunk(&awgParams.InitPacketJunkSize, 12)
		ensureMinJunk(&awgParams.ResponsePacketJunkSize, 12)
		ensureMinJunk(&awgParams.CookieReplyPacketJunkSize, 12)
		ensureMinJunk(&awgParams.TransportPacketJunkSize, 12)
	}
}

func resolveContentPadding(ctx context.Context, db *database.DB, cfg *models.VPNConfig) (bool, string) {
	if cfg != nil && cfg.ContentPaddingAddition != "" && cfg.ContentPaddingAddition != "false" && cfg.ContentPaddingAddition != "0" {
		val := cfg.ContentPaddingAddition
		if val == "true" || val == "yes" || val == "1" {
			val = "16-64"
		}
		return true, val
	}
	if db == nil {
		return false, ""
	}
	srvs, err := db.GetAllServers(ctx)
	if err != nil {
		return false, ""
	}
	for _, srv := range srvs {
		if srv.Protocols == nil {
			continue
		}
		awgInfo, ok := srv.Protocols["awg"].(map[string]any)
		if !ok {
			continue
		}
		params, ok := awgInfo["awg_params"].(map[string]any)
		if !ok {
			continue
		}
		if cp, ok := params["awg_content_padding"]; ok {
			if b, _ := strconv.ParseBool(fmt.Sprint(cp)); b {
				return true, "16-64"
			}
		}
		if cp, ok := params["content_padding_addition"].(string); ok && cp != "" && cp != "false" {
			return true, cp
		}
	}
	return false, ""
}

type clientConfigParameters struct {
	clientPub  string
	clientPriv string
	rat        *awg.TimingRange
	rt         *awg.TimingRange
	rej        *awg.TimingRange
	kt         *awg.TimingRange
	mha        *awg.TimingRange
	pk         *awg.TimingRange
	cpAdd      *string
}

func resolveClientConfigParameters(awgConn *models.UserConnection, cpEnabled bool, cpVal string) (*clientConfigParameters, error) {
	res := &clientConfigParameters{}
	if awgConn != nil && len(awgConn.ClientParams) > 0 {
		res.rat = getTimingParam(awgConn.ClientParams, "rekey_after_time")
		res.rt = getTimingParam(awgConn.ClientParams, "rekey_timeout")
		res.rej = getTimingParam(awgConn.ClientParams, "reject_after_time")
		res.kt = getTimingParam(awgConn.ClientParams, "keepalive_timeout")
		res.mha = getTimingParam(awgConn.ClientParams, "max_handshake_attempts")
		res.pk = getTimingParam(awgConn.ClientParams, "persistent_keepalive")
		res.clientPriv = getStringParam(awgConn.ClientParams, "client_private_key")
		if res.clientPriv != "" && awgConn.ClientID != "" {
			res.clientPub = awgConn.ClientID
		}
		if s := getStringParam(awgConn.ClientParams, "content_padding_addition"); s != "" {
			res.cpAdd = &s
		}
	}

	rtBackfilled := (res.rt == nil)
	ratBackfilled := (res.rat == nil)

	if res.rat == nil {
		res.rat = awg.GenerateRekeyAfterTime()
	}
	if res.rt == nil {
		res.rt = awg.GenerateRekeyTimeout()
	}
	if res.rej == nil {
		res.rej = awg.GenerateRejectAfterTime()
	}
	if res.kt == nil {
		res.kt = awg.GenerateKeepaliveTimeout()
	}
	if res.mha == nil {
		res.mha = awg.GenerateMaxHandshakeAttempts()
	}
	if res.pk == nil {
		res.pk = awg.GeneratePersistentKeepalive()
	}

	if rtBackfilled && !ratBackfilled {
		if res.rt.Hi >= res.rat.Lo {
			res.rt.Hi = max(1, res.rat.Lo-1)
			if res.rt.Lo > res.rt.Hi {
				res.rt.Lo = res.rt.Hi
			}
		}
		// Clamp below any stored reject_after_time too: the regenerated rat may
		// extend past a stored rej (e.g. stored rt=110, rej=125, generated
		// rat=111-128). EnforceTimingOrdering is not called here because stored
		// values must not be mutated, so clamp the regenerated ranges instead.
		awg.EnforceTimingOrdering(nil, res.rat, res.rej)
	} else if ratBackfilled && !rtBackfilled {
		if res.rat.Lo <= res.rt.Hi {
			res.rat.Lo = res.rt.Hi + 1
			if res.rat.Hi < res.rat.Lo {
				res.rat.Hi = res.rat.Lo
			}
		}
		// Same: regenerated rat raised above stored rt.Hi may now collide with
		// a stored rej; re-check invariant 2 without touching stored values.
		awg.EnforceTimingOrdering(nil, res.rat, res.rej)
	} else {
		awg.EnforceTimingOrdering(res.rt, res.rat, res.rej)
	}

	if res.cpAdd == nil && cpEnabled {
		res.cpAdd = &cpVal
	}

	if res.clientPub == "" || res.clientPriv == "" {
		pub, priv, err := tunnel.GenerateCurve25519KeyPair()
		if err != nil {
			return nil, err
		}
		res.clientPub = pub
		res.clientPriv = priv
	}

	return res, nil
}

// GenerateClientConfigForConnection generates or retrieves client configuration for a specific connection ID.
func (s *Service) GenerateClientConfigForConnection(ctx context.Context, userID string, connectionID string) (string, string, error) {
	s.mu.RLock()
	db := s.db
	cfg := s.cfg
	portalPub := s.portalPubKey
	s.mu.RUnlock()

	if db == nil {
		return "", "", errors.New("database not available")
	}

	user, err := db.GetUser(ctx, userID)
	if err != nil || user == nil {
		return "", "", fmt.Errorf("user not found: %w", err)
	}

	conn, err := db.GetConnection(ctx, connectionID)
	if err != nil {
		return "", "", fmt.Errorf("failed to get connection: %w", err)
	}
	if conn == nil {
		return "", "", errors.New("connection not found")
	}
	if conn.UserID != userID {
		return "", "", errors.New("unauthorized: connection does not belong to user")
	}
	if conn.ServerID != 0 {
		return "", "", fmt.Errorf("connection %s is not a load balancer connection (server_id=%d)", connectionID, conn.ServerID)
	}
	if conn.Protocol != "" && models.NormalizeProtocol(conn.Protocol) != "awg" {
		return "", "", fmt.Errorf("unsupported protocol %q for load balancer connection", conn.Protocol)
	}

	return s.renderClientConfigForConnection(ctx, db, cfg, portalPub, user, conn, true)
}

// GenerateClientConfig builds an AWG client configuration for connecting to this portal VPN endpoint.
func (s *Service) GenerateClientConfig(ctx context.Context, userID string) (string, string, error) {
	s.mu.RLock()
	db := s.db
	cfg := s.cfg
	portalPub := s.portalPubKey
	s.mu.RUnlock()

	if db == nil {
		return "", "", errors.New("database not available")
	}

	user, err := db.GetUser(ctx, userID)
	if err != nil || user == nil {
		return "", "", fmt.Errorf("user not found: %w", err)
	}

	awgConn := findAWGConnection(ctx, db, user)
	return s.renderClientConfigForConnection(ctx, db, cfg, portalPub, user, awgConn, false)
}

func (s *Service) renderClientConfigForConnection(
	ctx context.Context,
	db *database.DB,
	cfg *models.VPNConfig,
	portalPub string,
	user *models.User,
	awgConn *models.UserConnection,
	isExplicit bool,
) (string, string, error) {
	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	}

	endpointStr := s.resolveClientEndpoint(ctx, cfg, listenPort)
	awgParams := awg.AWGParamsFromVPNConfig(cfg)
	resolveHeaderProtectionKey(ctx, db, cfg, awgParams)
	cpEnabled, cpVal := resolveContentPadding(ctx, db, cfg)

	p, err := resolveClientConfigParameters(awgConn, cpEnabled, cpVal)
	if err != nil {
		return "", "", err
	}

	s.assignmentMu.Lock()
	defer s.assignmentMu.Unlock()
	if err := reservePersistedClientIPs(ctx, db, s.ipam); err != nil {
		return "", "", fmt.Errorf("restore client IP assignments: %w", err)
	}
	clientParams := buildClientParams(awgConn, p)
	_, hadLease := s.ipam.GetAssignedIP(p.clientPub)
	assignedIP, err := s.resolveAssignedIP(clientParams, cfg, p.clientPub)
	if err != nil {
		return "", "", err
	}
	delete(clientParams, "config_regeneration_required")
	delete(clientParams, "quarantined_ip_collision")
	clientParams["assigned_ip"] = assignedIP

	if isExplicit && awgConn != nil {
		updates := map[string]any{
			"client_id":     p.clientPub,
			"client_params": clientParams,
		}
		updated, err := db.UpdateConnection(ctx, awgConn.ID, updates)
		if err != nil || !updated {
			if !hadLease {
				_ = s.ipam.Release(p.clientPub)
			}
			if err == nil {
				err = errors.New("connection was removed")
			}
			return "", "", fmt.Errorf("failed to update connection: %w", err)
		}
		awgConn.ClientID = p.clientPub
		awgConn.ClientParams = clientParams
	} else {
		if err := saveOrUpdateAWGConnection(ctx, db, user, awgConn, p.clientPub, clientParams); err != nil {
			if !hadLease {
				_ = s.ipam.Release(p.clientPub)
			}
			return "", "", fmt.Errorf("failed to persist client configuration: %w", err)
		}
		if awgConn != nil {
			awgConn.ClientID = p.clientPub
			awgConn.ClientParams = clientParams
		}
	}

	ud := &awg.AWGClientUserData{
		ClientName:             user.Username,
		ClientPrivateKey:       p.clientPriv,
		ClientIP:               assignedIP,
		Enabled:                true,
		RekeyAfterTime:         p.rat,
		RekeyTimeout:           p.rt,
		RejectAfterTime:        p.rej,
		KeepaliveTimeout:       p.kt,
		MaxHandshakeAttempts:   p.mha,
		PersistentKeepalive:    p.pk,
		ContentPaddingAddition: p.cpAdd,
	}

	clientMTU := "1280"
	if awgConn != nil && len(awgConn.ClientParams) > 0 {
		if m := getStringParam(awgConn.ClientParams, "mtu"); m != "" {
			clientMTU = m
		}
	}
	if clientMTU == "1280" && awgParams != nil && awgParams.MTU != "" {
		clientMTU = awgParams.MTU
	}

	configStr := awg.RenderClientConfig(
		p.clientPriv,
		assignedIP,
		portalPub,
		"", // psk
		endpointStr,
		awg.AWGDefaults["dns1"],
		awg.AWGDefaults["dns2"],
		clientMTU,
		awgParams,
		ud,
	)

	filename := fmt.Sprintf("amnezia-portal-%s.conf", user.Username)
	if isExplicit && awgConn != nil && awgConn.Name != "" {
		filename = fmt.Sprintf("%s.conf", awgConn.Name)
	}
	return configStr, filename, nil
}

func buildClientParams(awgConn *models.UserConnection, p *clientConfigParameters) map[string]any {
	clientParams := make(map[string]any)
	if awgConn != nil && awgConn.ClientParams != nil {
		for k, v := range awgConn.ClientParams {
			clientParams[k] = v
		}
	}
	updateTimingParam := func(key string, tr *awg.TimingRange) {
		if tr == nil {
			return
		}
		existingVal, exists := clientParams[key]
		if !exists || existingVal == nil {
			clientParams[key] = tr.String()
			return
		}
		parsedExisting, err := awg.ParseTimingRange(existingVal)
		if err != nil || parsedExisting == nil || parsedExisting.Lo != tr.Lo || parsedExisting.Hi != tr.Hi {
			clientParams[key] = tr.String()
		}
	}

	updateTimingParam("rekey_after_time", p.rat)
	updateTimingParam("rekey_timeout", p.rt)
	updateTimingParam("reject_after_time", p.rej)
	updateTimingParam("keepalive_timeout", p.kt)
	updateTimingParam("max_handshake_attempts", p.mha)
	updateTimingParam("persistent_keepalive", p.pk)
	clientParams["client_private_key"] = p.clientPriv
	if p.cpAdd != nil {
		clientParams["content_padding_addition"] = *p.cpAdd
	}
	return clientParams
}

func (s *Service) resolveAssignedIP(clientParams map[string]any, cfg *models.VPNConfig, clientPub string) (string, error) {
	regenerationRequired := false
	if req, ok := clientParams["config_regeneration_required"].(bool); ok && req {
		regenerationRequired = true
	}
	if q, ok := clientParams["quarantined_ip_collision"]; ok && q != nil && q != "" {
		regenerationRequired = true
	}

	if !regenerationRequired {
		if existingVal, ok := clientParams["assigned_ip"]; ok && existingVal != nil {
			if existingStr, ok := existingVal.(string); ok && existingStr != "" {
				parsedIP := net.ParseIP(existingStr)
				if parsedIP != nil && parsedIP.To4() != nil {
					valid := true
					if cfg != nil && cfg.SubnetCIDR != "" {
						if _, cidrNet, err := net.ParseCIDR(cfg.SubnetCIDR); err == nil {
							if !cidrNet.Contains(parsedIP) {
								valid = false
							}
						}
					}
					if valid {
						if s.ipam != nil {
							err := s.ipam.Reserve(parsedIP, clientPub)
							if err == nil {
								return existingStr, nil
							}
							if errors.Is(err, ipam.ErrIPAlreadyAllocated) {
								return "", fmt.Errorf("client %s persisted IP %s conflicts with another client: %w", clientPub, existingStr, err)
							}
						} else {
							return existingStr, nil
						}
					}
				}
			}
		}
	}

	if s.ipam != nil {
		if regenerationRequired {
			_ = s.ipam.Release(clientPub)
		}
		ip, err := s.ipam.Allocate(clientPub)
		if err != nil {
			return "", fmt.Errorf("allocate client IP: %w", err)
		}
		delete(clientParams, "config_regeneration_required")
		delete(clientParams, "quarantined_ip_collision")
		return ip.String(), nil
	}
	return "", errors.New("IP address manager is unavailable")
}

func findAWGConnection(ctx context.Context, db *database.DB, user *models.User) *models.UserConnection {
	conns, err := db.GetConnectionsByUserID(ctx, user.ID)
	if err != nil || len(conns) == 0 {
		return nil
	}

	// Priority 1: Match pending connection created with empty ClientID
	for i := range conns {
		if conns[i].ServerID == 0 && (conns[i].Protocol == "" || models.NormalizeProtocol(conns[i].Protocol) == "awg") && conns[i].ClientID == "" {
			return &conns[i]
		}
	}
	// Priority 2: Match default portal connection
	for i := range conns {
		if conns[i].ServerID == 0 && conns[i].Name == fmt.Sprintf("%s-awg", user.Username) {
			return &conns[i]
		}
	}
	// Priority 3: Pick the most recently created load balancer connection
	var latestLB *models.UserConnection
	for i := range conns {
		if conns[i].ServerID == 0 && (conns[i].Protocol == "" || models.NormalizeProtocol(conns[i].Protocol) == "awg") {
			if latestLB == nil || conns[i].CreatedAt.After(latestLB.CreatedAt) {
				latestLB = &conns[i]
			}
		}
	}
	if latestLB != nil {
		return latestLB
	}

	return nil
}

func saveOrUpdateAWGConnection(ctx context.Context, db *database.DB, user *models.User, awgConn *models.UserConnection, clientPub string, clientParams map[string]any) error {
	if awgConn != nil {
		updates := map[string]any{
			"client_id": clientPub,
		}
		if clientParams != nil {
			updates["client_params"] = clientParams
		}
		updated, err := db.UpdateConnection(ctx, awgConn.ID, updates)
		if err != nil {
			return err
		}
		if !updated {
			return errors.New("connection was removed")
		}
		return nil
	}

	conns, err := db.GetConnectionsByUserID(ctx, user.ID)
	if err != nil {
		return err
	}
	if len(conns) > 0 {
		// User already has connections; do not silently auto-create phantom <username>-awg connection.
		return errors.New("no load balancer connection exists for user with existing connections")
	}

	newConn := &models.UserConnection{
		UserID:       user.ID,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     clientPub,
		Name:         fmt.Sprintf("%s-awg", user.Username),
		AWGMimicry:   models.AWGMimicryAuto,
		ClientParams: clientParams,
	}
	_, err = db.CreateConnection(ctx, newConn)
	return err
}

func getTimingParam(m map[string]any, key string) *awg.TimingRange {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	tr, err := awg.ParseTimingRange(v)
	if err != nil || tr == nil {
		return nil
	}
	if tr.Lo <= 0 || tr.Hi <= 0 {
		return nil
	}
	return tr
}

func getStringParam(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

var externalIPDetector = detectExternalPublicIP

// outboundDial is the seam used by detectOutboundInterfaceIP; tests stub it
// to fake the container's local address without a real UDP dial.
var outboundDial = net.DialTimeout

// ipServiceEndpoints lists the public IP echo services consulted by
// detectExternalPublicIP (issue #71: ipify + icanhazip stay, no new
// external service dependencies).
var ipServiceEndpoints = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
}

// Detection retry budget (issue #71 requirement 2): up to ipServiceAttempts
// rounds over the endpoint list, 2s per-attempt timeout, short backoff
// between rounds. Worst case stays bounded (~13s) under the ~15s ceiling.
const (
	ipServiceAttempts     = 3
	ipServiceRetryBackoff = 300 * time.Millisecond
)

// Endpoint sources for observability (issue #71 requirement 4).
const (
	endpointSourceConfigured = "configured"
	endpointSourceEnv        = "env"
	endpointSourceIPService  = "detected(ip-service)"
	endpointSourceOutbound   = "detected(outbound-interface)"
	endpointSourceFallback   = "fallback(127.0.0.1)"
)

// sanitizeLogValue makes untrusted text safe for single-line logs: control
// characters (including CR/LF used to forge log lines) become visible
// escapes. Applied to response bodies and externally supplied endpoint
// values before they reach the log.
func sanitizeLogValue(s string) string {
	if s == "" {
		return s
	}
	replaced := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '\\'
		}
		return r
	}, s)
	if len(replaced) > 96 {
		replaced = replaced[:93] + "..."
	}
	return replaced
}

// vpnDebugf logs opt-in debug detail: emitted only when VPN_DEBUG is set.
// internal/vpn has no leveled logger; per-attempt detection noise stays
// behind this gate so default logs carry the single INFO source line.
func vpnDebugf(format string, args ...any) {
	if os.Getenv("VPN_DEBUG") == "" {
		return
	}
	// #nosec G706 -- format strings are compile-time constants inside this
	// file; variable arguments are validated IPs, fixed endpoint URLs, or
	// sanitized via sanitizeLogValue before reaching this wrapper.
	log.Printf(format, args...)
}

// logWriter returns the standard logger's current output writer so tests
// can capture endpoint-source log lines.
func logWriter() io.Writer {
	return log.Writer()
}

// detectPortalHostIPFallback runs the detection chain and reports which
// source produced the result (issue #71 observability). It returns "" with
// endpointSourceFallback when every stage fails; callers treat "" as
// failure and fall back to 127.0.0.1 without caching.
func detectPortalHostIPFallback(ctx context.Context) (string, string) {
	if externalIPDetector != nil {
		if ip := externalIPDetector(ctx); ip != "" {
			// Trust boundary: whatever the detector (or its test seam)
			// returns is only usable if it is a validated global-unicast
			// address; anything else counts as detection failure (issue #71).
			if isPublicIP(net.ParseIP(ip)) {
				return ip, endpointSourceIPService
			}
			vpnDebugf("[vpn] portal host detection: ip-service returned non-public %q; rejected", sanitizeLogValue(ip))
		}
	}
	if ip := detectOutboundInterfaceIP(); ip != "" {
		return ip, endpointSourceOutbound
	}
	return "", endpointSourceFallback
}

// isPublicIP reports whether ip is a validated global-unicast address:
// not loopback, unspecified, multicast/broadcast, link-local, private
// (RFC1918), or CGNAT 100.64.0.0/10 (issue #71 requirement 1).
func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return false
	}
	// net.IP.IsPrivate does not cover carrier-grade NAT 100.64.0.0/10;
	// the live incident showed container/network ranges in that space.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] < 128 {
		return false
	}
	return true
}

func detectExternalPublicIP(ctx context.Context) string {
	endpoints := ipServiceEndpoints

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Issue #71: the observed failure was both services failing once during
	// a boot window while egress came up seconds later. Retry the endpoint
	// list with a short backoff; total worst case stays bounded.
	for attempt := 1; attempt <= ipServiceAttempts; attempt++ {
		for _, ep := range endpoints {
			// Per-attempt timeout: 2s each, as before the retry loop.
			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			req, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, ep, nil)
			if err != nil {
				cancel()
				continue
			}
			// #nosec G107 -- fixed public IP detection endpoints
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				vpnDebugf("[vpn] public IP detection: %s attempt %d failed: %v", ep, attempt, err)
				continue
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			_ = resp.Body.Close()
			cancel()
			if err != nil {
				vpnDebugf("[vpn] public IP detection: %s attempt %d read failed: %v", ep, attempt, err)
				continue
			}
			ipStr := strings.TrimSpace(string(body))
			if parsed := net.ParseIP(ipStr); parsed != nil && isPublicIP(parsed) {
				return ipStr
			}
			vpnDebugf("[vpn] public IP detection: %s attempt %d returned unusable body %q", ep, attempt, sanitizeLogValue(ipStr))
		}
		if attempt < ipServiceAttempts {
			select {
			case <-ctx.Done():
				return ""
			case <-time.After(time.Duration(attempt) * ipServiceRetryBackoff):
			}
		}
	}
	return ""
}

func detectOutboundInterfaceIP() string {
	// Issue #71: the UDP dial to 8.8.8.8:80 returns the container's local
	// IP inside Docker (observed: 172.19.0.3). Only a validated global
	// unicast address may leave this function; anything else is treated
	// as detection failure.
	conn, err := outboundDial("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err != nil {
		vpnDebugf("[vpn] outbound interface detection: UDP dial failed: %v", err)
		return ""
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return ""
	}
	localIP := udpAddr.IP
	if !isPublicIP(localIP) {
		vpnDebugf("[vpn] outbound interface detection: rejected non-public local address %s", localIP)
		return ""
	}
	return localIP.String()
}

func formatEndpoint(val string, defaultPort int) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(val); err == nil {
		return val
	}
	return net.JoinHostPort(val, strconv.Itoa(defaultPort))
}

func resolveClientEndpointInternal(ctx context.Context, s *Service, cfg *models.VPNConfig, listenPort int) string {
	// 1. Configured cfg.PublicEndpoint
	if cfg != nil && strings.TrimSpace(cfg.PublicEndpoint) != "" {
		logEndpointSource(endpointSourceConfigured, cfg.PublicEndpoint)
		return formatEndpoint(cfg.PublicEndpoint, listenPort)
	}

	// 2. Environment variables: VPN_PUBLIC_ENDPOINT, PUBLIC_ENDPOINT, PUBLIC_IP
	for _, envKey := range []string{"VPN_PUBLIC_ENDPOINT", "PUBLIC_ENDPOINT", "PUBLIC_IP"} {
		if envVal := strings.TrimSpace(os.Getenv(envKey)); envVal != "" {
			logEndpointSource(endpointSourceEnv, envVal)
			return formatEndpoint(envVal, listenPort)
		}
	}

	// 3. Portal Host Auto-Detection (validated public IPs only; see #71)
	var hostIP, source string
	if s != nil {
		hostIP, source = s.detectPortalHostIP(ctx)
	} else {
		hostIP, source = detectPortalHostIPFallback(ctx)
	}
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	logEndpointSource(source, hostIP)
	return net.JoinHostPort(hostIP, strconv.Itoa(listenPort))
}

// lastEndpointSource/lastEndpointValue back the issue #71 observability
// line: log once per source change, not per resolve (cache hits must not
// spam). atomic.Pointer[string] is swap-only, so no ABA hazard.
var (
	lastEndpointSource atomic.Pointer[string]
	lastEndpointValue  atomic.Pointer[string]
)

// logEndpointSource emits the observability line required by issue #71:
// one INFO line whenever the resolved (source, value) pair changes, and a
// debug line (VPN_DEBUG-gated) otherwise, so cache hits and steady-state
// fallback resolves don't spam the log.
func logEndpointSource(source, value string) {
	prevSrc := lastEndpointSource.Swap(&source)
	prevVal := lastEndpointValue.Swap(&value)
	unchanged := prevSrc != nil && *prevSrc == source && prevVal != nil && *prevVal == value
	value = sanitizeLogValue(value)
	if unchanged {
		vpnDebugf("[vpn] client endpoint source: %s (%s) (unchanged)", source, value)
		return
	}
	// #nosec G706 -- source is a compile-time endpointSource* constant and
	// value passed through sanitizeLogValue above (control characters
	// including CR/LF replaced with escapes), so log lines cannot be forged.
	log.Printf("[vpn] client endpoint source: %s (%s)", source, value)
}

func (s *Service) detectPortalHostIP(ctx context.Context) (string, string) {
	if s != nil {
		s.publicIPMu.RLock()
		cached := s.detectedPublicIP
		s.publicIPMu.RUnlock()
		if cached != "" {
			return cached, endpointSourceIPService
		}
	}

	detected, source := detectPortalHostIPFallback(ctx)

	// Issue #71: only validated global-unicast results are cached; a failed
	// or non-public detection must return "" uncached so the next call
	// retries detection instead of pinning the bad value for the process
	// lifetime. The isPublicIP re-check is defense in depth: the detector
	// itself already validates, but this gate is what the no-cache
	// guarantee rests on.
	if s != nil && isPublicIP(net.ParseIP(detected)) {
		s.publicIPMu.Lock()
		s.detectedPublicIP = detected
		s.publicIPMu.Unlock()
	}
	return detected, source
}

func (s *Service) resolveClientEndpoint(ctx context.Context, cfg *models.VPNConfig, listenPort int) string {
	return resolveClientEndpointInternal(ctx, s, cfg, listenPort)
}

// ResolveClientEndpoint resolves the public endpoint for the Load Balancer entry point.
func (s *Service) ResolveClientEndpoint(ctx context.Context) string {
	s.mu.RLock()
	cfg := s.cfg
	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	}
	s.mu.RUnlock()
	return s.resolveClientEndpoint(ctx, cfg, listenPort)
}

// ExtractClientPublicKeyFromConfig parses a WireGuard/AWG config text to retrieve the client public key.
func ExtractClientPublicKeyFromConfig(configStr string) string {
	for _, line := range strings.Split(configStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				privKey := strings.TrimSpace(parts[1])
				pubKey, err := tunnel.DeriveClientPublicKey(privKey)
				if err == nil {
					return pubKey
				}
			}
		}
	}
	return ""
}
