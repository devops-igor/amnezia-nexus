package vpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
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
	backendDeviceSnapshots map[int64]*models.BackendTunnel
	deletedServers         map[int64]struct{} // guarded by mu
	adminDisableEpoch      map[int64]uint64   // guarded by mu
	lastLoggedDrops        atomic.Uint64
	// retiredBackendDeviceDrops is the LIFETIME accumulator for backend
	// devices that have left backendDevices (issue #424 round 5, finding 1).
	//
	// It is direction- and reason-preserving, not a scalar: a retiring
	// device's real VirtualTUN breakdown is transferred into the matching
	// buckets, so a return-direction loss stays a return-direction loss after
	// the device is gone. The accumulator carries the SAME fields as a live
	// device's contribution, which is what lets a retired loss be published
	// under the same key a live one uses. Guarded by mu.
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
	publicKeyUpdateSeams                   publicKeyUpdateSeams
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
	if err := cfg.ValidateDataPlaneI1Protocol(); err != nil {
		return nil, err
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
	if cfg != nil {
		if cfg.HealthThresholdMS > 0 {
			healthCfg.LatencyThresholdMS = int64(cfg.HealthThresholdMS)
		}
		if cfg.EnableMultiProtocolBackends {
			pool.SetMultiProtocolEnabled(true)
		}
	}

	prober := tunnel.NewHealthProber(pool, db, healthCfg)
	if cfg != nil && cfg.EnableMultiProtocolBackends {
		prober.SetMultiProtocolEnabled(true)
	}

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
		adminDisableEpoch:      make(map[int64]uint64),
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
	if err := cfg.ValidateDataPlaneI1Protocol(); err != nil {
		return err
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

	multiProtocolChanged := s.cfg != nil && cfg.EnableMultiProtocolBackends != s.cfg.EnableMultiProtocolBackends
	if multiProtocolChanged && listenerRunning {
		log.Printf("[vpn] rejecting config update: enable_multi_protocol_backends is immutable while listener is running")
		return errors.New("enable_multi_protocol_backends cannot be changed while the VPN listener is running; restart the panel")
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
	if s.pool != nil {
		s.pool.SetMultiProtocolEnabled(cfg.EnableMultiProtocolBackends)
	}
	if s.prober != nil {
		s.prober.SetMultiProtocolEnabled(cfg.EnableMultiProtocolBackends)
	}

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
