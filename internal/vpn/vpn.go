package vpn

import (
	"context"
	"crypto/rand"
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
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// Status represents the overall runtime telemetry of the VPN endpoint and load balancing subsystem.
type Status struct {
	ListenerRunning            bool   `json:"listener_running"`
	ActiveTunnels              int    `json:"active_tunnels"`
	ConnectedSessions          int    `json:"connected_sessions"`
	RestartInvalidatedSessions int64  `json:"restart_invalidated_sessions"`
	FreshSessionRegistrations  int64  `json:"fresh_session_registrations"`
	RxBytes                    int64  `json:"rx_bytes"`
	TxBytes                    int64  `json:"tx_bytes"`
	DroppedPackets             uint64 `json:"dropped_packets"`
	// Issue #39, #151 & #288 telemetry: return-path drops inside the forwarder (queue
	// full / no route / total) and rejected handshake initiations at the listener.
	// A rising forwarder_drops_total with stable traffic means a stalled
	// downstream path or unroutable backend returns; a rising handshake_rejections means
	// client initiations are failing cryptographic verification (issues #39, #288).
	ForwarderDropsQueueFull        uint64                               `json:"forwarder_drops_queue_full"`
	ForwarderDropsNoRoute          uint64                               `json:"forwarder_drops_no_route"`
	ForwarderDropsPacketTooLarge   uint64                               `json:"forwarder_drops_packet_too_large"`
	ForwarderDropsTotal            uint64                               `json:"forwarder_drops_total"`
	ForwarderQueueOccupancy        int                                  `json:"forwarder_queue_occupancy"`
	ForwarderQueueCapacity         int                                  `json:"forwarder_queue_capacity"`
	ForwarderQueueHighWater        int                                  `json:"forwarder_queue_high_water"`
	ForwarderDeviceWriteErrors     uint64                               `json:"forwarder_device_write_errors"`
	ForwarderDeviceWriteDurationMS uint64                               `json:"forwarder_device_write_duration_ms"`
	ForwarderDeviceWriteCount      uint64                               `json:"forwarder_device_write_count"`
	ForwarderDeviceWritesInFlight  int                                  `json:"forwarder_device_writes_in_flight"`
	ForwarderDeviceWriteOldestMS   int64                                `json:"forwarder_device_write_oldest_in_flight_ms"`
	ForwarderDeviceWriteMaxMS      int64                                `json:"forwarder_device_write_max_duration_ms"`
	ForwarderDeviceWriteStalls     uint64                               `json:"forwarder_device_write_stalls"`
	ForwarderDeviceWriteStallMS    int64                                `json:"forwarder_device_write_stall_threshold_ms"`
	TransportDecryptionFailures    uint64                               `json:"transport_decryption_failures"`
	HandshakeRejections            uint64                               `json:"handshake_rejections"`
	PublicEndpoint                 string                               `json:"public_endpoint,omitempty"`
	ForwarderRouteQueues           map[string]forwarder.RouteQueueStats `json:"forwarder_route_queues,omitempty"`
}

// UserVPNState represents the real-time VPN connection state for a specific user.
type UserVPNState struct {
	Connected       bool               `json:"connected"`
	Session         *models.VPNSession `json:"session,omitempty"`
	BackendServerID int64              `json:"backend_server_id,omitempty"`
	BackendEndpoint string             `json:"backend_endpoint,omitempty"`
	LatencyMS       int64              `json:"latency_ms,omitempty"`
}

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
	mu            sync.RWMutex
	assignmentMu  sync.Mutex // serialize durable lease creation and restart migration
	db            *database.DB
	cfg           *models.VPNConfig
	endpoint      *endpoint.Listener
	sessionMgr    *endpoint.SessionManager
	ipam          *endpoint.IPAM
	auth          *endpoint.DBAuthenticator
	pool          *tunnel.Pool
	prober        *tunnel.HealthProber
	reconnectMgr  *tunnel.ReconnectManager
	balancer      loadbalancer.LoadBalancer
	stickyMgr     *loadbalancer.StickySessionManager
	forwarder     *forwarder.Forwarder
	accountant    *forwarder.TrafficAccountant
	running       bool
	portalPubKey  string
	portalPrivKey string
	awgProvider   AWGStatusProvider
	// requireTun switches Start to the real Linux TUN data plane (production
	// mode; cmd opts in via RequireTunDevice when VPN_ENABLED). tunOpener is
	// the injectable device constructor used by tests to prove the
	// management-mode (TUN-unavailable) contract hermetically. tunDev is the
	// attached client-facing device; backendDevices holds the per-backend UDP
	// devices created by EnableBackend.
	requireTun                 bool
	tunOpener                  func() (endpoint.PacketDevice, error)
	tunDev                     endpoint.PacketDevice
	backendDevices             map[int64]BackendDevice
	backendDeviceEndpoints     map[int64]string
	lastLoggedDrops            atomic.Uint64
	restartInvalidatedSessions atomic.Int64
	freshSessionRegistrations  atomic.Int64
	publicIPMu                 sync.RWMutex
	detectedPublicIP           string
	// dropLogUntil throttles the backend read loop's queue-full drop log
	// (log-flood defense; issue #39 produced 7687 lines in 2 h). Shared
	// across the per-backend read loops: all accesses are atomic, so the
	// worst case is one log line per second in aggregate.
	dropLogUntil atomic.Int64

	lastReconcileTime                  time.Time
	lastReconcileByTunnel              map[int64]time.Time
	peerGenerations                    map[string]uint64
	reconcilePostSnapshotHook          func()
	reconcilePreApplyHook              func()
	reconcilePreCommitHook             func()
	ensureDevicePreLockHook            func()
	preCommitMigrationHookForTest      func()
	updateBackendServerHostPreLockHook func()
	updateBackendServerHostErr         error
	syncBackendForwarderHook           func() error
}

// obfuscationMigrationMu serializes first-read obfuscation migration
// across concurrent NewVPNService calls so racing first starts converge
// on one persisted parameter set instead of divergent ephemeral values
// that would desync the listener from rendered client configs.
var obfuscationMigrationMu sync.Mutex

// generatePortalHeaderProtectionKey generates a cryptographically random
// 32-byte header protection key encoded in base64.
func generatePortalHeaderProtectionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random header protection key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ensureObfuscationParams migrates a config whose H1..H4/S1..S4 or
// HeaderProtectionKey are unset (legacy rows written before those existed).
// Under the migration lock it re-reads the persisted config — a
// concurrent first start may have already persisted parameters, and
// the persisted values win over any in-memory guess — generates
// standard-profile parameters and portal HeaderProtectionKey when still unset,
// and persists them synchronously. Persistence failures are returned so
// startup fails loudly instead of running with divergent ephemeral values.
// The ListenPort is propagated through every save branch (R3): the
// migration must never persist a zeroed listen_port, which GetVPNConfig's
// fill-down would re-default to the default port and desync the running listener
// from rendered client configs. Ports <= 0 fall back to DefaultListenPort.
func enforceMinSValues(cfg *models.VPNConfig) bool {
	var changed bool
	if cfg.S1 < 12 {
		cfg.S1 = 12
		changed = true
	}
	if cfg.S2 < 12 {
		cfg.S2 = 12
		changed = true
	}
	if cfg.S3 < 12 {
		cfg.S3 = 12
		changed = true
	}
	if cfg.S4 < 12 {
		cfg.S4 = 12
		changed = true
	}
	return changed
}

func isObfuscationConfigComplete(cfg *models.VPNConfig) bool {
	if cfg == nil {
		return true
	}
	if cfg.HeaderProtectionKey == "" {
		return false
	}
	if cfg.S1 < 12 || cfg.S2 < 12 || cfg.S3 < 12 || cfg.S4 < 12 {
		return false
	}
	if awg.NeedsHeaderUpgrade(cfg.H1) || awg.NeedsHeaderUpgrade(cfg.H2) ||
		awg.NeedsHeaderUpgrade(cfg.H3) || awg.NeedsHeaderUpgrade(cfg.H4) {
		return false
	}
	if err := awg.ValidateQuadrantDisjointness(cfg.H1, cfg.H2, cfg.H3, cfg.H4); err != nil {
		return false
	}
	return true
}

func generateMissingObfuscation(cfg *models.VPNConfig) (bool, error) {
	var generated bool
	if cfg.H1.IsZero() && cfg.H2.IsZero() && cfg.H3.IsZero() && cfg.H4.IsZero() {
		h1, h2, h3, h4, s1, s2, s3, s4, err := awg.GenerateStandardObfuscationValues()
		if err != nil {
			return false, fmt.Errorf("failed to generate obfuscation params: %w", err)
		}
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = h1, h2, h3, h4
		cfg.S1, cfg.S2, cfg.S3, cfg.S4 = s1, s2, s3, s4
		generated = true
	} else if awg.NeedsHeaderUpgrade(cfg.H1) || awg.NeedsHeaderUpgrade(cfg.H2) ||
		awg.NeedsHeaderUpgrade(cfg.H3) || awg.NeedsHeaderUpgrade(cfg.H4) ||
		awg.ValidateQuadrantDisjointness(cfg.H1, cfg.H2, cfg.H3, cfg.H4) != nil {
		h1, h2, h3, h4, upgraded, err := awg.UpgradeDegenerateHeaders(cfg.H1, cfg.H2, cfg.H3, cfg.H4)
		if err != nil {
			return false, fmt.Errorf("failed to upgrade obfuscation headers: %w", err)
		}
		if upgraded {
			cfg.H1, cfg.H2, cfg.H3, cfg.H4 = h1, h2, h3, h4
			generated = true
		}
		if cfg.S1 == 0 && cfg.S2 == 0 && cfg.S3 == 0 && cfg.S4 == 0 {
			cfg.S1, cfg.S2, cfg.S3, cfg.S4 = 50, 70, 20, 15
			generated = true
		}
	}
	if cfg.HeaderProtectionKey == "" {
		hpk, err := generatePortalHeaderProtectionKey()
		if err != nil {
			return false, err
		}
		cfg.HeaderProtectionKey = hpk
		generated = true
	}
	return generated, nil
}

// ensureObfuscationParams migrates a VPNConfig that lacks AWG obfuscation
// values, contains legacy degenerate headers (lo == hi), or lacks HeaderProtectionKey.
// Checks the DB first under a mutex — a concurrent first start may have already
// persisted parameters, and the persisted values win over any in-memory guess — generates
// standard-profile parameters and portal HeaderProtectionKey when still unset,
// upgrades degenerate headers to ranges with span >= 1000, and persists them synchronously.
// Persistence failures are returned so startup fails loudly instead of running with
// divergent ephemeral values. The ListenPort is propagated through every save branch (R3):
// the migration must never persist a zeroed listen_port, which GetVPNConfig's
// fill-down would re-default to the default port and desync the running listener
// from rendered client configs. Ports <= 0 fall back to DefaultListenPort.
func ensureObfuscationParams(ctx context.Context, db *database.DB, cfg *models.VPNConfig) error {
	if cfg == nil {
		return nil
	}
	// If all obfuscation parameters (header ranges, min S values, and HeaderProtectionKey)
	// are already valid and complete, nothing to migrate.
	if isObfuscationConfigComplete(cfg) {
		return nil
	}

	if db == nil {
		if _, err := generateMissingObfuscation(cfg); err != nil {
			return err
		}
		enforceMinSValues(cfg)
		return nil
	}

	obfuscationMigrationMu.Lock()
	defer obfuscationMigrationMu.Unlock()

	persisted, err := db.GetVPNConfig(ctx)
	if err == nil && persisted != nil {
		if isObfuscationConfigComplete(persisted) {
			cfg.H1, cfg.H2, cfg.H3, cfg.H4 = persisted.H1, persisted.H2, persisted.H3, persisted.H4
			cfg.S1, cfg.S2, cfg.S3, cfg.S4 = persisted.S1, persisted.S2, persisted.S3, persisted.S4
			cfg.HeaderProtectionKey = persisted.HeaderProtectionKey
			return nil
		}
		if !persisted.H1.IsZero() && cfg.H1.IsZero() {
			cfg.H1, cfg.H2, cfg.H3, cfg.H4 = persisted.H1, persisted.H2, persisted.H3, persisted.H4
			cfg.S1, cfg.S2, cfg.S3, cfg.S4 = persisted.S1, persisted.S2, persisted.S3, persisted.S4
		}
		if persisted.HeaderProtectionKey != "" && cfg.HeaderProtectionKey == "" {
			cfg.HeaderProtectionKey = persisted.HeaderProtectionKey
		}
	}

	if isObfuscationConfigComplete(cfg) {
		return nil
	}

	needsSave, err := generateMissingObfuscation(cfg)
	if err != nil {
		return err
	}
	if enforceMinSValues(cfg) {
		needsSave = true
	}

	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}

	if needsSave {
		target := persisted
		if target == nil {
			target = cfg
		} else {
			target.H1, target.H2, target.H3, target.H4 = cfg.H1, cfg.H2, cfg.H3, cfg.H4
			target.S1, target.S2, target.S3, target.S4 = cfg.S1, cfg.S2, cfg.S3, cfg.S4
			target.HeaderProtectionKey = cfg.HeaderProtectionKey
			// R3: propagate the caller's (already validated) listen port so the
			// migration save cannot zero out a previously wired port.
			target.ListenPort = cfg.ListenPort
		}
		if err := db.SaveVPNConfig(ctx, target); err != nil {
			return fmt.Errorf("failed to persist obfuscation params: %w", err)
		}
	}
	return nil
}

// preserveObfuscationParams copies unset (zero) AWG obfuscation fields
// from the current config into an incoming config so partial updates
// cannot clobber the parameters already distributed to peers.
func preserveObfuscationParams(from, to *models.VPNConfig) {
	if to.H1.IsZero() {
		to.H1 = from.H1
	}
	if to.H2.IsZero() {
		to.H2 = from.H2
	}
	if to.H3.IsZero() {
		to.H3 = from.H3
	}
	if to.H4.IsZero() {
		to.H4 = from.H4
	}
	if to.S1 == 0 {
		to.S1 = from.S1
	}
	if to.S2 == 0 {
		to.S2 = from.S2
	}
	if to.S3 == 0 {
		to.S3 = from.S3
	}
	if to.S4 == 0 {
		to.S4 = from.S4
	}
	if to.HeaderProtectionKey == "" {
		to.HeaderProtectionKey = from.HeaderProtectionKey
	}
	if to.ContentPaddingAddition == "" {
		to.ContentPaddingAddition = from.ContentPaddingAddition
	}
}

// obfuscationDiffers reports whether two configs disagree on any AWG
// obfuscation parameter.
func obfuscationDiffers(a, b *models.VPNConfig) bool {
	return a.H1 != b.H1 || a.H2 != b.H2 || a.H3 != b.H3 || a.H4 != b.H4 ||
		a.S1 != b.S1 || a.S2 != b.S2 || a.S3 != b.S3 || a.S4 != b.S4 ||
		a.HeaderProtectionKey != b.HeaderProtectionKey || a.ContentPaddingAddition != b.ContentPaddingAddition
}

func defaultVPNConfig() *models.VPNConfig {
	return &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            make(map[int64]int),
	}
}

func applyVPNConfigDefaults(cfg *models.VPNConfig) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = models.LBLeastConnections
	}
	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = "10.100.0.0/16"
	}
	if cfg.HealthThresholdMS <= 0 {
		cfg.HealthThresholdMS = 500
	}
	if cfg.MaxTotalPeers <= 0 {
		cfg.MaxTotalPeers = 1000
	}
	if cfg.MaxPeersPerBackend <= 0 {
		cfg.MaxPeersPerBackend = 250
	}
	if cfg.ClientQueueSize > 0 {
		maxQueue := forwarder.MaxClientQueuePacketsForRoutes(cfg.MaxTotalPeers)
		if cfg.ClientQueueSize > maxQueue {
			cfg.ClientQueueSize = maxQueue
		}
	}
	if cfg.Weights == nil {
		cfg.Weights = make(map[int64]int)
	}
}

// NewVPNService initializes the complete unified VPN subsystem.
// Server-side RejectAfterTime defaults to device.RejectAfterTime (180s WireGuard protocol standard),
// providing a stable transition window intentionally independent of client-configured timing ranges.
func NewVPNService(db *database.DB, cfg *models.VPNConfig) (*Service, error) {
	if cfg == nil {
		if db != nil {
			var err error
			cfg, err = db.GetVPNConfig(context.Background())
			if err != nil {
				cfg = defaultVPNConfig()
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

	ipam, err := endpoint.NewIPAM(cfg.SubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to init IPAM: %w", err)
	}
	// Config generation is also available before Start. Load both persisted
	// client leases and legacy session-only leases before exposing this service.
	if db != nil {
		if err := reservePersistedClientIPs(context.Background(), db, ipam); err != nil {
			return nil, fmt.Errorf("restore client IP assignments: %w", err)
		}
	}

	var auth *endpoint.DBAuthenticator
	if db != nil {
		auth = endpoint.NewDBAuthenticator(db)
	}

	sessionMgr := endpoint.NewSessionManager(db, ipam)

	serverKeys := endpoint.NewServerKeysManager(db)

	listenerCfg := endpoint.ListenerConfig{
		ListenPort:  cfg.ListenPort,
		SubnetCIDR:  cfg.SubnetCIDR,
		MTU:         1420,
		IdleTimeout: 3 * time.Minute,
		// RejectAfterTime defaults to device.RejectAfterTime (180s WireGuard protocol standard)
		// when zero, providing a stable transition window intentionally independent of client-configured
		// timing ranges.
		HeaderProtectionKey: cfg.HeaderProtectionKey,
		H1:                  cfg.H1,
		S1:                  cfg.S1,
		H2:                  cfg.H2,
		S2:                  cfg.S2,
		H3:                  cfg.H3,
		S3:                  cfg.S3,
		H4:                  cfg.H4,
		S4:                  cfg.S4,
	}

	epListener, err := endpoint.NewListener(listenerCfg, db, auth, ipam, sessionMgr, serverKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to init endpoint listener: %w", err)
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
		// EnsureKeypair may have just created and persisted the portal
		// identity into the stored VPNConfig via its own copy. Refresh the
		// in-memory cfg identity fields so partial config updates copy the
		// real persisted identity instead of empty strings (which would
		// wipe the keypair on the next save and invalidate every rendered
		// client config).
		cfg.ServerPublicKey = pub
		cfg.ServerPrivateKey = priv
	}

	svc := &Service{
		db:                     db,
		cfg:                    cfg,
		endpoint:               epListener,
		sessionMgr:             sessionMgr,
		ipam:                   ipam,
		auth:                   auth,
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
		lastReconcileByTunnel:  make(map[int64]time.Time),
		peerGenerations:        make(map[string]uint64),
	}

	epListener.SetIncomingPeerHandler(svc.HandleIncomingPeer)
	epListener.SetClientPacketRouter(fwd.RouteClientToBackend)
	// Issue #78: session replacement (client rekey/reconnect) must migrate the
	// pool connection counter off the old backend - without this every rekey
	// leaked +1 on the old backend's ActiveConnections gauge (the original
	// connect incremented it in HandleIncomingPeer; the replacement path never
	// decremented, and a later DisconnectSession(oldID) found nothing because
	// the SessionManager had already dropped the old ID and closed the DB row).
	// The hook uses the same pool primitives as the clean-disconnect
	// mirror-decrement paths (DisconnectUser/DisconnectSession/ReleaseClient).
	// SessionManager owns the ordering: CreateSession removes the old session
	// (and closes its DB row) BEFORE persisting the new one, and fires this
	// hook only after the new session is fully registered. The hook runs while
	// SessionManager.mu is held, so it must only touch the pool counter and
	// forwarder/sticky state - it must never re-enter the session manager.
	// Capacity serialization note (issue #86): the hook's pool counter
	// migration therefore participates in the capacity invariant only
	// transitively - CreateSession's only production call site today is
	// HandleIncomingPeer, which holds s.mu for the whole select ->
	// CreateSession -> increment sequence, so the hook in fact runs nested
	// under BOTH locks (s.mu -> sm.mu; the reverse order is never taken).
	// If a CreateSession call site outside s.mu is ever added, the hook
	// escapes the capacity serialization regime and the contract on
	// tunnel.Pool.IncrementConnections must be re-evaluated.
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
		// Mirror HandleIncomingPeer's increment on the same primitives used by
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
	// Idle-timeout reaper: run teardown directly on the reaped session
	// (forwarder route, pool counter, sticky affinity). CheckTimeouts has
	// already closed and removed the session from sessionMgr, so we must not
	// call DisconnectSession (which looks up the session by ID and fails).
	epListener.SetSessionReaperHook(func(ctx context.Context, sess *models.VPNSession) {
		svc.reapSession(ctx, sess)
	})
	epListener.SetPostSweepHook(func(ctx context.Context) {
		svc.PruneExpiredAffinity()
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

// SetTunOpener overrides the TUN device opener for testing.
func (s *Service) SetTunOpener(fn func() (endpoint.PacketDevice, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunOpener = fn
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
	if current.Status == models.TunnelStatusDisabled || current.DisableReason == models.DisableReasonAdmin {
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

// RequireTunDevice switches Start to the real Linux TUN data plane: when the
// TUN device cannot be opened, Start fails with an error chain wrapping
// endpoint.ErrTunUnavailable so callers can degrade to management-only mode
// instead of silently running without the data plane.
func (s *Service) RequireTunDevice() {
	s.mu.Lock()
	s.requireTun = true
	s.tunOpener = defaultLinuxTunOpener
	s.mu.Unlock()
}

// defaultLinuxTunOpener opens the production client-facing Linux TUN device
// ("awg0", MTU 1420). Its errors wrap endpoint.ErrTunUnavailable.
func defaultLinuxTunOpener() (endpoint.PacketDevice, error) {
	return endpoint.OpenTunDevice("awg0", 1420)
}

// restoreBackendDevices restores data-plane devices for active and degraded tunnels loaded from DB.
func (s *Service) restoreBackendDevices(ctx context.Context) {
	for _, tun := range s.pool.ListTunnels() {
		if tun.DisableReason == models.DisableReasonAdmin {
			continue
		}
		if tun.Status != TunnelStatusActive && tun.Status != TunnelStatusDegraded {
			continue
		}
		var awgParams map[string]any
		var attachErr error
		if s.db != nil {
			srv, err := s.db.GetServerByID(ctx, tun.ServerID)
			if err != nil || srv == nil {
				attachErr = fmt.Errorf("failed to load server %d: %w", tun.ServerID, err)
			} else if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
				awgParams, _ = awgInfo["awg_params"].(map[string]any)
			}
		} else {
			attachErr = errors.New("database not available")
		}
		if attachErr == nil {
			s.mu.Lock()
			attachErr = s.attachBackendForwarder(tun, awgParams)
			s.mu.Unlock()
		}
		if attachErr != nil {
			log.Printf("[vpn] warning: failed to restore data plane for tunnel %d (server %d): %v", tun.ID, tun.ServerID, attachErr)
			_ = s.pool.SetTunnelStatus(ctx, tun.ServerID, TunnelStatusDegraded, 0)
		}
	}
}

// Start launches the complete VPN subsystem.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	// No client transport keys, endpoints, or forwarder routes survive a process
	// restart. Atomically discard persisted sessions and their pool gauges
	// before any backend device or packet pump can receive traffic. If cleanup
	// fails, do not start with a falsely connected data plane.
	if s.db != nil {
		s.assignmentMu.Lock()
		err := reservePersistedClientIPs(ctx, s.db, s.ipam)
		var invalidated int64
		if err == nil {
			invalidated, err = s.db.InvalidateVPNSessionsForRestart(ctx)
		}
		s.assignmentMu.Unlock()
		if err != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("failed to invalidate VPN sessions on restart: %w", err)
		}
		s.restartInvalidatedSessions.Store(invalidated)
		log.Printf("[vpn] restart reconciliation invalidated %d persisted connected session(s); awaiting fresh client handshakes", invalidated)
	}

	// 1. Sync tunnels from DB
	if s.pool != nil {
		if err := s.pool.SyncFromDB(ctx); err != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("failed to sync tunnels from DB: %w", err)
		}

		// Issue #43 startup migration: backfill dedicated probe keys for
		// legacy tunnels and (re-)register both portal peers on each backend
		// BEFORE data planes are restored, so devices and probes come up
		// with their correct identities. Best-effort; logs on failure.
		s.EnsureBackendProbeKeys(ctx)

		// Restore backend data-plane devices for active tunnels
		s.restoreBackendDevices(ctx)
	}

	// 2. Reconcile the active_connections gauge from the authoritative
	// session table (issue #54): the persisted counter drifts when older
	// deploys kill sessions without decrementing it, and the drift survives
	// restarts, distorting least-conn routing. Best-effort: startup must
	// not fail if reconciliation errors.
	s.reconcileConnectionCounts(ctx)

	// 3. Client-facing TUN device (production data plane). When required
	// (RequireTunDevice) and the TUN device cannot be opened, abort
	// data-plane startup and fail with an error chain wrapping
	// endpoint.ErrTunUnavailable -- the panel continues management-only.
	if s.requireTun && s.tunOpener != nil {
		dev, tunErr := s.tunOpener()
		if tunErr != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("failed to open tun device: %w", tunErr)
		}
		s.tunDev = dev
		if s.forwarder != nil {
			s.forwarder.AttachClientDevice(dev)
		}
	}

	// 4. Start forwarder & accountant
	if s.forwarder != nil {
		s.forwarder.Start(ctx)
		s.forwarder.StartPumps(ctx)
	}

	// 5. Start health prober & reconnect manager
	if s.prober != nil {
		s.prober.Start(ctx)
	}
	if s.reconnectMgr != nil {
		s.reconnectMgr.Start(ctx)
	}

	// 6. Start endpoint listener
	if s.endpoint != nil {
		s.endpoint.SetPostSweepHook(func(ctx context.Context) {
			s.PruneExpiredAffinity()
		})
		if err := s.endpoint.Start(ctx); err != nil {
			if s.prober != nil {
				s.prober.Stop()
			}
			if s.reconnectMgr != nil {
				s.reconnectMgr.Stop()
			}
			if s.forwarder != nil {
				_ = s.forwarder.Stop()
			}
			if s.tunDev != nil {
				_ = s.tunDev.Close()
				s.tunDev = nil
			}
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("failed to start endpoint listener: %w", err)
		}
	}

	// Issue #78: hourly periodic reconcile of the active_connections gauge.
	// Safety net for residual counter drift; gauge-only semantics — it never
	// touches sessions, so it cannot fight the idle-timeout reaper.
	s.StartGaugeReconciler(ctx)

	return nil
}

func quarantinePersistedAssignment(ctx context.Context, db *database.DB, claimant database.VPNClientIPAssignment, conflictingIP string) {
	if claimant.ClientParams == nil {
		claimant.ClientParams = make(map[string]any)
	}
	delete(claimant.ClientParams, "assigned_ip")
	claimant.ClientParams["quarantined_ip_collision"] = conflictingIP
	claimant.ClientParams["config_regeneration_required"] = true
	if db != nil && claimant.ConnectionID != "" {
		_, _ = db.UpdateConnection(ctx, claimant.ConnectionID, map[string]any{"client_params": claimant.ClientParams})
	}
	if claimant.NeedsMigration && claimant.PeerKey != "" && db != nil {
		if sess, err := db.GetVPNSessionByPeerKey(ctx, claimant.PeerKey); err == nil && sess != nil {
			_ = db.DeleteVPNSession(ctx, sess.ID)
		}
	}
}

func reserveSingleClaimant(ctx context.Context, db *database.DB, ipam *endpoint.IPAM, claimant database.VPNClientIPAssignment, ip net.IP, ipStr string) error {
	if current, ok := ipam.GetAssignedIP(claimant.PeerKey); ok && !current.Equal(ip) {
		quarantinePersistedAssignment(ctx, db, claimant, ipStr)
		log.Printf("[vpn] warning: connection %s (user %s, peer %s) has conflicting persisted address %s (already assigned %s); quarantined conflicting lease (requires config regeneration)", claimant.ConnectionID, claimant.UserID, claimant.PeerKey, ipStr, current)
		return nil
	}
	if err := ipam.Reserve(ip, claimant.PeerKey); err != nil {
		if errors.Is(err, endpoint.ErrIPNotInSubnet) || errors.Is(err, endpoint.ErrIPReserved) {
			return nil
		}
		if errors.Is(err, endpoint.ErrIPAlreadyAllocated) {
			quarantinePersistedAssignment(ctx, db, claimant, ipStr)
			log.Printf("[vpn] warning: startup IP collision on %s: connection %s (user %s, peer %s) address already allocated to another peer; quarantined conflicting lease (requires config regeneration)", ipStr, claimant.ConnectionID, claimant.UserID, claimant.PeerKey)
			return nil
		}
		return fmt.Errorf("connection %s peer %s address %s: %w", claimant.ConnectionID, claimant.PeerKey, claimant.AssignedIP, err)
	}
	return nil
}

func reconcileMultipleClaimants(ctx context.Context, db *database.DB, ipam *endpoint.IPAM, claimants []database.VPNClientIPAssignment, ip net.IP, ipStr string) error {
	// Multiple claimants sharing the same IP (len(claimants) > 1):
	// Select ONE winner deterministically:
	// 1) Durable lease (!claimant.NeedsMigration) beats legacy fallback (claimant.NeedsMigration).
	// 2) Oldest connection (CreatedAt earlier).
	// 3) Stable tie-breaker (claimant.ConnectionID).
	sort.SliceStable(claimants, func(i, j int) bool {
		if claimants[i].NeedsMigration != claimants[j].NeedsMigration {
			return !claimants[i].NeedsMigration
		}
		if !claimants[i].CreatedAt.Equal(claimants[j].CreatedAt) {
			return claimants[i].CreatedAt.Before(claimants[j].CreatedAt)
		}
		return claimants[i].ConnectionID < claimants[j].ConnectionID
	})

	winner := claimants[0]
	losers := claimants[1:]

	// Reserve winner in IPAM
	if current, ok := ipam.GetAssignedIP(winner.PeerKey); ok && !current.Equal(ip) {
		quarantinePersistedAssignment(ctx, db, winner, ipStr)
		log.Printf("[vpn] warning: connection %s (user %s, peer %s) has conflicting persisted address %s (already assigned %s); quarantined conflicting lease (requires config regeneration)", winner.ConnectionID, winner.UserID, winner.PeerKey, ipStr, current)
	} else {
		if err := ipam.Reserve(ip, winner.PeerKey); err != nil {
			if !errors.Is(err, endpoint.ErrIPNotInSubnet) && !errors.Is(err, endpoint.ErrIPReserved) {
				if errors.Is(err, endpoint.ErrIPAlreadyAllocated) {
					quarantinePersistedAssignment(ctx, db, winner, ipStr)
					log.Printf("[vpn] warning: startup IP collision on %s: connection %s (user %s, peer %s) address already allocated to another peer; quarantined conflicting lease (requires config regeneration)", ipStr, winner.ConnectionID, winner.UserID, winner.PeerKey)
				} else {
					return fmt.Errorf("connection %s peer %s address %s: %w", winner.ConnectionID, winner.PeerKey, winner.AssignedIP, err)
				}
			}
		}
	}

	// For every loser: clear/quarantine conflicting lease in SQLite, log warning
	for _, loser := range losers {
		if loser.NeedsMigration {
			loser.NeedsMigration = false
		}
		quarantinePersistedAssignment(ctx, db, loser, ipStr)
		log.Printf("[vpn] warning: startup IP collision on %s: connection %s (user %s, peer %s) conflicts with owner connection %s; quarantined/cleared conflicting lease (requires config regeneration)", ipStr, loser.ConnectionID, loser.UserID, loser.PeerKey, winner.ConnectionID)
	}
	return nil
}

func reservePersistedClientIPs(ctx context.Context, db *database.DB, ipam *endpoint.IPAM) error {
	if ipam == nil || db == nil {
		return nil
	}
	assignments, err := db.GetVPNClientIPAssignments(ctx)
	if err != nil {
		return err
	}

	byIP := make(map[string][]database.VPNClientIPAssignment)
	for _, a := range assignments {
		if a.AssignedIP != "" {
			byIP[a.AssignedIP] = append(byIP[a.AssignedIP], a)
		}
	}

	// Deterministic iteration order over IPs
	ips := make([]string, 0, len(byIP))
	for ipStr := range byIP {
		ips = append(ips, ipStr)
	}
	sort.Strings(ips)

	for _, ipStr := range ips {
		claimants := byIP[ipStr]
		ip := net.ParseIP(ipStr)
		if ip == nil || ip.To4() == nil {
			continue
		}

		if len(claimants) == 1 {
			if err := reserveSingleClaimant(ctx, db, ipam, claimants[0], ip, ipStr); err != nil {
				return err
			}
			continue
		}

		if err := reconcileMultipleClaimants(ctx, db, ipam, claimants, ip, ipStr); err != nil {
			return err
		}
	}
	return nil
}

// isLifecycleMutated returns true if the session manager exists and its
// lifecycle version has advanced beyond versionBefore.
func (s *Service) isLifecycleMutated(versionBefore uint64) bool {
	return s.sessionMgr != nil && s.sessionMgr.LifecycleVersion() != versionBefore
}

// reconcileConnectionCounts recomputes the active_connections gauge of every
// tunnel in the pool from the authoritative vpn_sessions table (issue #54).
// The gauge is a LIVE count of status='connected' sessions per backend
// tunnel; it drifts when historical deploys kill sessions without
// decrementing it, and since it is persisted in backend_tunnels the drift
// survives restarts and distorts least-conn balancing. It runs once during
// Start after restart cleanup and pool sync but BEFORE the forwarder and
// endpoint accept traffic, so this read-modify-write over pool snapshots is
// safe: no live IncrementConnections/DecrementConnections traffic can race
// it at that point. On any error it logs and returns so the panel still
// comes up.
func (s *Service) reconcileConnectionCounts(ctx context.Context) {
	if s.pool == nil || s.db == nil {
		return
	}

	var versionBefore uint64
	if s.sessionMgr != nil {
		versionBefore = s.sessionMgr.LifecycleVersion()
	}

	sessions, err := s.db.GetActiveVPNSessions(ctx)
	dbReadTime := time.Now().UTC()
	if err != nil {
		log.Printf("[vpn] warning: connection gauge reconciliation skipped, cannot read active sessions: %v", err)
		return
	}

	var postHook func()
	s.mu.RLock()
	postHook = s.reconcilePostSnapshotHook
	s.mu.RUnlock()
	if postHook != nil {
		postHook()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionMgr != nil {
		s.sessionMgr.LockLifecycle()
		defer s.sessionMgr.UnlockLifecycle()
	}

	if s.isLifecycleMutated(versionBefore) {
		log.Printf("[vpn] warning: connection gauge reconciliation skipped: session lifecycle mutated during DB snapshot (version %d -> %d)",
			versionBefore, s.sessionMgr.LifecycleVersion())
		return
	}

	if s.reconcilePreApplyHook != nil {
		s.reconcilePreApplyHook()
	}

	if s.isLifecycleMutated(versionBefore) {
		log.Printf("[vpn] warning: connection gauge reconciliation skipped: session lifecycle mutated during pre-apply hook (version %d -> %d)",
			versionBefore, s.sessionMgr.LifecycleVersion())
		return
	}

	desired := make(map[int64]int)
	for i := range sessions {
		desired[sessions[i].BackendTunnelID]++
	}

	tunnels := s.pool.ListTunnels()
	tunnelChanges := make(map[int64]int)
	stagedReconcile := make(map[int64]time.Time)
	for _, tun := range tunnels {
		want := desired[tun.ID]
		if tun.ActiveConnections == want {
			stagedReconcile[tun.ID] = dbReadTime
			continue
		}
		tunnelChanges[tun.ID] = want
		stagedReconcile[tun.ID] = dbReadTime
	}

	if s.reconcilePreCommitHook != nil {
		s.reconcilePreCommitHook()
	}

	if s.isLifecycleMutated(versionBefore) {
		log.Printf("[vpn] warning: connection gauge reconciliation aborted: session lifecycle mutated before commit (version %d -> %d)",
			versionBefore, s.sessionMgr.LifecycleVersion())
		return
	}

	anyDrift := len(tunnelChanges) > 0
	allSucceeded := true
	for _, tun := range tunnels {
		want, changed := tunnelChanges[tun.ID]
		if !changed {
			continue
		}
		if err := s.pool.SetConnectionCount(ctx, tun.ID, want); err != nil {
			allSucceeded = false
			delete(stagedReconcile, tun.ID)
			log.Printf("[vpn] warning: failed to reconcile active_connections for tunnel %d (server %d): %v", tun.ID, tun.ServerID, err)
			continue
		}
		log.Printf("[vpn] reconciled active_connections for tunnel %d (server %d): %d -> %d", tun.ID, tun.ServerID, tun.ActiveConnections, want)
	}

	if s.lastReconcileByTunnel == nil {
		s.lastReconcileByTunnel = make(map[int64]time.Time)
	}
	for tunID, ts := range stagedReconcile {
		s.lastReconcileByTunnel[tunID] = ts
	}

	if allSucceeded {
		s.lastReconcileTime = dbReadTime
	}

	// Sessions whose BackendTunnelID is not in the pool: count them as the
	// total minus everything accounted for by known tunnels.
	knownCount := 0
	for _, tun := range tunnels {
		knownCount += desired[tun.ID]
	}
	unknown := len(sessions) - knownCount
	if unknown > 0 {
		log.Printf("[vpn] warning: %d connected session(s) reference backend tunnels outside the pool; left for existing failover/sweeper logic", unknown)
	}

	if !anyDrift && unknown == 0 {
		log.Printf("[vpn] connection gauge reconciliation: no drift detected across %d tunnel(s)", len(tunnels))
	}
}

// ConnectionGaugeReconcileInterval is the cadence of the periodic gauge
// reconciliation (issue #78 decision: hourly - short enough that drift never
// lives longer than one interval, cheap enough to be a single indexed DB
// read over the vpn_sessions table per hour).
const ConnectionGaugeReconcileInterval = time.Hour

// StartGaugeReconciler launches the hourly periodic reconcile of the
// active_connections gauge (issue #78 short-term safety net). It reuses the
// existing, tested reconcileConnectionCounts primitive unchanged - no new
// counting logic - so the gauge is the ONLY thing it corrects: it never
// creates, closes, or resurrects sessions, and therefore cannot fight the
// session reaper. Reaper interaction: the reaper's teardown closes real
// session rows synchronously via DisconnectSession before the gauge can be
// stale; the reconcile simply recomputes the gauge FROM the (now-correct)
// session table, so ordering against reaper passes is irrelevant. The only
// race window is a session lifecycle event landing mid-reconcile, which is
// the same read-modify-write over pool snapshots Start already relies on and
// self-corrects on the next pass. Drift (before -> after per backend) is
// logged inside reconcileConnectionCounts, making the residual leak rate
// observable in production.
func (s *Service) StartGaugeReconciler(ctx context.Context) {
	if s.pool == nil || s.db == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(ConnectionGaugeReconcileInterval)
		defer ticker.Stop()
		log.Printf("[vpn] periodic connection-gauge reconciler started (interval %s)", ConnectionGaugeReconcileInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reconcileConnectionCounts(ctx)
				s.PruneExpiredAffinity()
			}
		}
	}()
}

// Stop gracefully shuts down the VPN subsystem.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	if s.endpoint != nil {
		_ = s.endpoint.Stop()
	}
	if s.prober != nil {
		s.prober.Stop()
	}
	if s.reconnectMgr != nil {
		s.reconnectMgr.Stop()
	}
	if s.forwarder != nil {
		_ = s.forwarder.Stop()
	}
	if s.pool != nil {
		_ = s.pool.Close()
	}

	s.mu.Lock()
	if s.backendDevices != nil {
		for id, dev := range s.backendDevices {
			if dev != nil {
				_ = dev.Close()
			}
			delete(s.backendDevices, id)
		}
	}
	if s.backendDeviceEndpoints != nil {
		for id := range s.backendDeviceEndpoints {
			delete(s.backendDeviceEndpoints, id)
		}
	}
	s.mu.Unlock()

	return nil
}

// IsRunning returns true if the VPN service is active.
func (s *Service) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetStatus returns the operational status and telemetry of the VPN subsystem.
func (s *Service) GetStatus(ctx context.Context) (*Status, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := &Status{
		ListenerRunning:            s.endpoint != nil && s.endpoint.IsRunning(),
		RestartInvalidatedSessions: s.restartInvalidatedSessions.Load(),
		FreshSessionRegistrations:  s.freshSessionRegistrations.Load(),
	}

	if s.pool != nil {
		status.ActiveTunnels = len(s.pool.GetActiveTunnels())
	}
	if s.sessionMgr != nil {
		status.ConnectedSessions = s.sessionMgr.ActiveCount()
	}
	if s.forwarder != nil {
		rx, tx, _ := s.forwarder.GetStats()
		status.RxBytes = rx
		status.TxBytes = tx
		status.ForwarderDropsQueueFull, status.ForwarderDropsNoRoute, status.ForwarderDropsTotal = s.forwarder.DropStats()
		status.ForwarderDropsPacketTooLarge = s.forwarder.DropsPacketTooLarge()
		status.ForwarderQueueOccupancy, status.ForwarderQueueCapacity, status.ForwarderQueueHighWater = s.forwarder.AggregateQueueStats()
		allRouteQueues := s.forwarder.AllRouteQueueStats()
		if len(allRouteQueues) > 0 {
			peers := make([]string, 0, len(allRouteQueues))
			for peerKey := range allRouteQueues {
				peers = append(peers, peerKey)
			}
			sort.Strings(peers)
			limit := len(peers)
			if limit > forwarder.MaxSupportedActiveRoutes {
				limit = forwarder.MaxSupportedActiveRoutes
			}
			status.ForwarderRouteQueues = make(map[string]forwarder.RouteQueueStats, limit)
			for _, peerKey := range peers[:limit] {
				status.ForwarderRouteQueues[peerKey] = allRouteQueues[peerKey]
			}
		}
		writes := s.forwarder.DeviceWriteSnapshot()
		status.ForwarderDeviceWriteErrors = writes.Errors
		status.ForwarderDeviceWriteDurationMS = uint64(writes.TotalDuration.Milliseconds()) // #nosec G115 -- completed write durations are non-negative.
		status.ForwarderDeviceWriteCount = writes.Count
		status.ForwarderDeviceWritesInFlight = writes.InFlight
		status.ForwarderDeviceWriteOldestMS = writes.OldestInFlight.Milliseconds()
		status.ForwarderDeviceWriteMaxMS = writes.MaxDuration.Milliseconds()
		status.ForwarderDeviceWriteStalls = writes.Stalls
		status.ForwarderDeviceWriteStallMS = forwarder.DeviceWriteStallThreshold.Milliseconds()
	}
	if s.endpoint != nil {
		status.HandshakeRejections = s.endpoint.HandshakeRejections()
		status.TransportDecryptionFailures = s.endpoint.TransportDecryptionFailures()
	}

	var totalDrops uint64
	for _, dev := range s.backendDevices {
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

	listenPort := 51820
	if s.cfg != nil && s.cfg.ListenPort > 0 {
		listenPort = s.cfg.ListenPort
	}
	status.PublicEndpoint = resolveClientEndpointInternal(ctx, s, s.cfg, listenPort)

	return status, nil
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
	usernames, err := s.resolveUsernamesByPeerKey(ctx, out)
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
		if username, ok := usernames[out[i].PeerPublicKey]; ok {
			out[i].Username = username
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

// resolveUsernamesByPeerKey resolves session identity by PEER PUBLIC KEY
// (issue #213): user_connections.client_id is the stable connection-config
// identity, so the username survives vpn_sessions row displacement.
// client_id is cryptographically unique by construction (Curve25519 public
// key; enforced in practice by the auth path treating it as the identity
// key, not by a schema constraint — same precedent as
// DBAuthenticator.AuthenticatePeer). Duplicates, if data ever degenerated,
// would map to an arbitrary-but-stable iteration winner.
func (s *Service) resolveUsernamesByPeerKey(ctx context.Context, sessions []models.EnrichedVPNSession) (map[string]string, error) {
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
	usernames := make(map[string]string, len(peerKeys))
	if len(peerKeys) == 0 {
		return usernames, nil
	}

	pkPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(peerKeys)), ",")
	pkArgs := make([]any, len(peerKeys))
	for i, pk := range peerKeys {
		pkArgs[i] = pk
	}
	identityQuery := `SELECT uc.client_id AS pk, COALESCE(u.username, 'unknown') AS username
		FROM user_connections uc
		LEFT JOIN users u ON u.id = uc.user_id
		WHERE uc.client_id IN (` + pkPlaceholders + `)`

	idRows, err := s.db.QueryContext(ctx, identityQuery, pkArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve live session identity by peer key: %w", err)
	}
	defer idRows.Close()
	for idRows.Next() {
		var pk, username string
		if err := idRows.Scan(&pk, &username); err != nil {
			return nil, fmt.Errorf("failed to scan live session identity: %w", err)
		}
		usernames[pk] = username
	}
	if err := idRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate live session identities: %w", err)
	}
	return usernames, nil
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

// EnableBackend enables a backend server for load balancing by loading its
// AWG protocol credentials from the database, registering (or refreshing) the
// tunnel in the pool, attaching a backend UDP packet device to the forwarder,
// and marking the tunnel active.
func (s *Service) EnableBackend(ctx context.Context, serverID int64) error {
	s.mu.RLock()
	pool := s.pool
	db := s.db
	awgProv := s.awgProvider
	s.mu.RUnlock()

	if pool == nil {
		return errors.New("tunnel pool not initialized")
	}
	if db == nil {
		return errors.New("database not available")
	}

	var (
		hasInitial     bool
		initialReason  string
		initialVersion int64
	)
	if initTun, err := pool.GetTunnel(serverID); err == nil && initTun != nil {
		hasInitial = true
		initialReason = initTun.DisableReason
		initialVersion = initTun.StateVersion
	}

	server, err := db.GetServerByID(ctx, serverID)
	if err != nil {
		return fmt.Errorf("failed to load server %d: %w", serverID, err)
	}
	if server == nil {
		return fmt.Errorf("%w: server %d", ErrServerNotFound, serverID)
	}

	pub, port, awgParams, err := s.resolveBackendCredentials(ctx, serverID, server)
	if err != nil {
		return err
	}

	endpoint := net.JoinHostPort(server.Host, strconv.Itoa(port))

	s.mu.Lock()
	tun, err := pool.AddTunnel(ctx, serverID, endpoint, pub)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to register backend tunnel for server %d: %w", serverID, err)
	}

	// Register the portal peers on the backend server (issue #43):
	//   - "Portal Data Device": identity = derive(tunnel.PrivateKey) — the DATA
	//     device key with AllowedIPs scoped to portal client subnet so the backend accepts data
	//     traffic from the portal subnet and routes replies to the data device (never 0.0.0.0/0).
	//   - "Portal Health Probe": identity = derive(tunnel.ProbePrivateKey) — a
	//     dedicated probe key so prober handshakes never roam the data peer's
	//     return endpoint (per-peer endpoint roaming: last sender wins).
	// AddClient is an idempotent upsert on the caller-supplied key, so repeat
	// registrations refresh in place; a legacy shared-key peer registered under
	// the data identity keeps its client_ip entry and is re-pointed at the
	// data-device identity.
	if awgProv != nil {
		if err := s.registerBackendPortalPeers(ctx, server, tun); err != nil {
			_ = pool.SetTunnelStatus(ctx, serverID, TunnelStatusDegraded, 0)
			return err
		}
	}

	// Ensure return routing and NAT masquerade for portal client subnet.
	// Run safely: log warning on failure so temporary SSH issues don't block enabling the backend.
	if err := s.remediateBackendRouting(ctx, serverID); err != nil {
		log.Printf("[vpn] warning: failed to ensure backend routing and NAT for server %d: %v", serverID, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	currTun, err := pool.GetTunnel(serverID)
	if err != nil {
		return err
	}
	if tunnel.IsSelfHealingContext(ctx) && currTun.DisableReason == models.DisableReasonAdmin {
		return errors.New("backend was administratively disabled; aborting enable")
	}
	if hasInitial {
		// If an administrator disabled this backend while enable was in-flight,
		// or if concurrent state mutation occurred, abort to respect the disable.
		if currTun.DisableReason == models.DisableReasonAdmin && initialReason != models.DisableReasonAdmin {
			return errors.New("backend was administratively disabled; aborting enable")
		}
		if currTun.StateVersion != initialVersion {
			return errors.New("backend state modified concurrently; aborting enable")
		}
	} else if currTun.DisableReason == models.DisableReasonAdmin {
		return errors.New("backend was administratively disabled; aborting enable")
	}

	if err := s.attachBackendForwarder(tun, awgParams); err != nil {
		return err
	}

	// Issue #50: clear the prober's consecutive-failure counter so the
	// re-enabled backend gets the full FailureThreshold grace period; without
	// this the first jittery probe after re-enable instantly re-disables it.
	//
	// Lock ordering: s.mu -> hp.mu is safe: the prober's own mutex is a leaf.
	// Every hp.mu holder (ProbeTunnel, Start/Stop, the Set* setters) touches
	// only prober fields plus pool (pool.mu); pool methods never call back
	// into Service; and the onActiveHook fires with hp.mu already released,
	// so no code path acquires hp.mu -> s.mu. This ordering already exists in
	// SetHealthProber and SetProbeFunc.
	if s.prober != nil {
		s.prober.ResetFailCount(serverID)
	}

	if tunnel.IsSelfHealingContext(ctx) {
		return nil
	}

	return pool.SetTunnelStatusWithReason(ctx, serverID, TunnelStatusActive, models.DisableReasonNone, 10)
}

// registerBackendPortalPeers registers the portal's two identities on the
// backend server (issue #43 key separation):
//
//  1. "Portal Data Plane" — the DATA device identity derive(tun.PrivateKey)
//     with AllowedIPs scoped to the portal client subnet (s.getPortalSubnet(),
//     e.g. 10.100.0.0/16), so the backend accepts data traffic from the
//     portal client subnet and routes replies to the data device. The portal
//     data plane peer must NEVER be granted 0.0.0.0/0 to prevent awg-quick from
//     creating a default route hijack on reboot. The legacy
//     name is kept deliberately: backends provisioned before the split already
//     hold a peer of this name keyed by the same data identity, so the
//     manager's upsert refreshes it in place instead of appending a duplicate
//     [Peer] (which amneziawg would reject).
//
//  2. "Portal Health Probe" — the dedicated probe identity
//     derive(tun.ProbePrivateKey) with NO allowed_ips key, so the manager's
//     peerSectionFor defaults it to clientIP/32. The probe peer must NEVER own
//     0.0.0.0/0: its only traffic is the prober's handshake/keepalive
//     exchange, and a wide AllowedIPs would let probe packets shadow the data
//     plane.
//
// The DATA peer is registered FIRST so a mid-way failure cannot leave a
// backend with a probe peer but no data peer. On any failure the error is
// wrapped with the server ID and the caller degrades the tunnel.
func (s *Service) registerBackendPortalPeers(ctx context.Context, server *models.Server, tun *models.BackendTunnel) error {
	s.mu.RLock()
	awgProv := s.awgProvider
	db := s.db
	s.mu.RUnlock()

	adder, ok := awgProv.(interface {
		AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error)
	})
	if !ok {
		// Provider without AddClient capability (e.g. status-only
		// implementations): there is no peer-registration path on this
		// backend, so skip silently — same semantics as before #43.
		return nil
	}

	dataPub, err := tunnel.DataDevicePublicKey(tun)
	if err != nil {
		return fmt.Errorf("failed to derive data device public key for server %d: %w", server.ID, err)
	}
	probePub, err := tunnel.ClientPublicKey(tun)
	if err != nil {
		return fmt.Errorf("failed to derive probe public key for server %d: %w", server.ID, err)
	}
	if tun.ProbePrivateKey == "" || probePub == dataPub {
		return fmt.Errorf("probe key for backend tunnel %d on server %d is missing or collides with the data key", tun.ID, server.ID)
	}

	portalSubnet := s.getPortalSubnet()
	dataParams := map[string]any{
		"clientName":        "Portal Data Plane",
		"name":              "Portal Data Plane",
		"public_key":        dataPub,
		"client_public_key": dataPub,
		"allowed_ips":       portalSubnet,
	}
	if _, err := adder.AddClient(ctx, server, dataParams); err != nil {
		return fmt.Errorf("failed to register portal data plane peer on backend server %d: %w", server.ID, err)
	}

	probeParams := map[string]any{
		"clientName":        "Portal Health Probe",
		"name":              "Portal Health Probe",
		"public_key":        probePub,
		"client_public_key": probePub,
		// No allowed_ips key: peerSectionFor defaults to clientIP/32. The
		// probe peer must never be granted 0.0.0.0/0.
	}
	if _, err := adder.AddClient(ctx, server, probeParams); err != nil {
		return fmt.Errorf("failed to register portal health probe peer on backend server %d: %w", server.ID, err)
	}

	// Persist the probe key so the identity is stable across restarts
	// (Fernet-encrypted at rest by the database layer).
	if db != nil {
		if err := db.UpdateBackendTunnel(ctx, tun.ID, map[string]any{"probe_private_key": tun.ProbePrivateKey}); err != nil {
			return fmt.Errorf("failed to persist probe private key for backend tunnel %d (server %d): %w", tun.ID, server.ID, err)
		}
	}
	return nil
}

// EnsureBackendProbeKeys is the issue-#43 startup migration: every tunnel in
// the pool must carry a dedicated probe key and have both portal peers
// registered on its backend server. Pool.SyncFromDB backfills keys missing
// from legacy rows in memory; this pass guarantees persistence and provisions
// the probe peer. Registration is idempotent (AddClient upserts by the
// caller-supplied public key), so running it on every boot for every
// non-disabled tunnel is safe and self-healing — it also re-points any legacy
// shared-key probe peer and drops stale PSK variants.
//
// Best-effort by design: an unreachable backend is logged and left as-is; the
// health prober and the next EnableBackend/startup pass retry later.
func (s *Service) EnsureBackendProbeKeys(ctx context.Context) {
	s.mu.RLock()
	pool := s.pool
	s.mu.RUnlock()
	if pool == nil {
		return
	}

	for _, tun := range pool.ListTunnels() {
		if tun.Status == TunnelStatusDisabled {
			continue
		}

		// SyncFromDB already backfills missing keys; this defensive second
		// pass keeps the migration correct if it ever runs against a pool
		// populated by another path.
		if tun.ProbePrivateKey == "" {
			_, sk, err := tunnel.GenerateCurve25519KeyPair()
			if err != nil {
				log.Printf("[vpn] warning: probe-key migration for tunnel %d (server %d): failed to generate keypair: %v", tun.ID, tun.ServerID, err)
				continue
			}
			tun.ProbePrivateKey = sk
			s.mu.RLock()
			db := s.db
			s.mu.RUnlock()
			if db != nil {
				if err := db.UpdateBackendTunnel(ctx, tun.ID, map[string]any{"probe_private_key": sk}); err != nil {
					log.Printf("[vpn] warning: probe-key migration for tunnel %d (server %d): persist failed: %v", tun.ID, tun.ServerID, err)
					continue
				}
			}
		}

		s.mu.RLock()
		awgProv := s.awgProvider
		db := s.db
		s.mu.RUnlock()
		if awgProv == nil || db == nil {
			continue
		}
		server, err := db.GetServerByID(ctx, tun.ServerID)
		if err != nil || server == nil {
			log.Printf("[vpn] warning: probe-peer migration for tunnel %d: server %d not loadable: %v", tun.ID, tun.ServerID, err)
			continue
		}
		regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := s.registerBackendPortalPeers(regCtx, server, tun); err != nil {
			log.Printf("[vpn] warning: probe-peer migration for tunnel %d (server %d) failed, leaving tunnel as-is: %v", tun.ID, tun.ServerID, err)
		}
		cancel()
	}
}

// resolveBackendCredentials retrieves AWG credentials for a backend, falling back to live discovery.
func (s *Service) resolveBackendCredentials(ctx context.Context, serverID int64, server *models.Server) (string, int, map[string]any, error) {
	var pub string
	var port int
	var awgParams map[string]any
	if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
		pub, _ = awgInfo["public_key"].(string)
		port = parsePort(awgInfo["port"])
		if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
			awgParams = p
		} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
			awgParams = p
		}
	}

	if (pub == "" || port <= 0) && s.awgProvider != nil {
		if livePub, livePort, ok := s.discoverLiveAWG(ctx, serverID, server); ok {
			pub = livePub
			port = livePort
			if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
				if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
					awgParams = p
				} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
					awgParams = p
				}
			}
		}
	}

	if pub == "" || port <= 0 {
		return "", 0, nil, ErrAWGNotInstalled
	}

	return pub, port, awgParams, nil
}

// discoverLiveAWG attempts to query the running AWG container and persists discovered configuration to DB.
func (s *Service) discoverLiveAWG(ctx context.Context, serverID int64, server *models.Server) (string, int, bool) {
	status, err := s.awgProvider.GetServerStatus(ctx, server)
	if err != nil || status == nil {
		return "", 0, false
	}
	if running, _ := status["container_running"].(bool); !running {
		return "", 0, false
	}
	livePub, _ := status["public_key"].(string)
	livePort := parsePort(status["port"])
	if livePub == "" || livePort <= 0 {
		return "", 0, false
	}

	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	protoMap, _ := server.Protocols["awg"].(map[string]any)
	if protoMap == nil {
		protoMap = make(map[string]any)
	}
	protoMap["installed"] = true
	protoMap["port"] = livePort
	protoMap["public_key"] = livePub
	if psk, ok := status["psk"].(string); ok && psk != "" {
		protoMap["psk"] = psk
	}
	if awgParams, ok := status["awg_params"]; ok && awgParams != nil {
		protoMap["awg_params"] = awgParams
	}
	if clientsCount, ok := status["clients_count"]; ok && clientsCount != nil {
		protoMap["clients_count"] = clientsCount
	}
	server.Protocols["awg"] = protoMap
	_ = s.db.UpdateServerProtocols(ctx, serverID, server.Protocols)

	return livePub, livePort, true
}

func (s *Service) attachBackendForwarder(tun *models.BackendTunnel, awgParams map[string]any) error {
	if tun == nil {
		return errors.New("backend tunnel is nil")
	}
	if s.forwarder == nil {
		return nil
	}

	// Detach and close previous device for this tunnel to prevent leaks
	if s.backendDevices != nil {
		if oldDev, ok := s.backendDevices[tun.ID]; ok {
			s.forwarder.DetachBackendDevice(tun.ID)
			if oldDev != nil {
				_ = oldDev.Close()
			}
			delete(s.backendDevices, tun.ID)
			if s.backendDeviceEndpoints != nil {
				delete(s.backendDeviceEndpoints, tun.ID)
			}
		}
	}

	beMTU := 1280
	if awgParams != nil {
		if mVal, ok := awgParams["mtu"].(string); ok && mVal != "" {
			if parsed, err := strconv.Atoi(mVal); err == nil && parsed > 0 {
				beMTU = parsed
			}
		} else if mInt, ok := awgParams["mtu"].(int); ok && mInt > 0 {
			beMTU = mInt
		}
	}

	dev, devErr := tunnel.NewAWGClientDevice(fmt.Sprintf("awg-be-%d", tun.ServerID), tun.Endpoint, tun.PrivateKey, tun.PublicKey, beMTU, awgParams)
	if devErr != nil {
		return fmt.Errorf("failed to create backend AWG device for server %d: %w", tun.ServerID, devErr)
	}
	s.forwarder.AttachBackendDevice(tun.ID, dev)
	if s.backendDevices == nil {
		s.backendDevices = make(map[int64]BackendDevice)
	}
	s.backendDevices[tun.ID] = dev
	if s.backendDeviceEndpoints == nil {
		s.backendDeviceEndpoints = make(map[int64]string)
	}
	s.backendDeviceEndpoints[tun.ID] = tun.Endpoint

	// Spawn backend read loop to route packets back to clients
	go func(backendID int64, serverID int64, device BackendDevice) {
		buf := make([]byte, 2048)
		for {
			n, err := device.Read(buf)
			if err != nil {
				return
			}
			if n >= 20 && (buf[0]>>4) == 4 { // IPv4
				destIP := net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()
				if err := s.forwarder.RouteBackendToClient(backendID, buf[:n], destIP); err != nil {
					// Throttle drop logs: a stalled route would otherwise
					// produce one log line per packet (issue #39: 7687
					// "packet queue is full" lines in 2 h). Counters are
					// exposed via Forwarder.DropStats / the stats API, so
					// rate-limiting the log loses no information.
					now := time.Now().Unix()
					if s.dropLogUntil.Load() <= now {
						s.dropLogUntil.Store(now + 1)
						log.Printf("[vpn/forwarder] dropped backend return packet to %s (backend_tunnel_id=%d server_id=%d): %v",
							destIP, backendID, serverID, err)
					}
				}
			}
		}
	}(tun.ID, tun.ServerID, dev)

	// Trigger backend routing and NAT remediation asynchronously in the background
	// so tunnel attachment and data-plane startup are never blocked by SSH latency.
	go s.triggerBackendRoutingRemediation(tun.ServerID)

	return nil
}

// getPortalSubnet returns the configured portal client subnet CIDR or defaults to "10.100.0.0/16".
func (s *Service) getPortalSubnet() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg != nil && s.cfg.SubnetCIDR != "" {
		return s.cfg.SubnetCIDR
	}
	return "10.100.0.0/16"
}

// remediateBackendRouting invokes EnsureBackendRoutingAndNAT on the configured AWG provider
// for the given server ID and portal subnet.
func (s *Service) remediateBackendRouting(ctx context.Context, serverID int64) error {
	s.mu.RLock()
	db := s.db
	awgProv := s.awgProvider
	s.mu.RUnlock()

	if db == nil {
		return errors.New("database not available")
	}
	if awgProv == nil {
		return errors.New("awg provider not available")
	}
	remediator, ok := awgProv.(RoutingRemediator)
	if !ok {
		return nil
	}

	server, err := db.GetServerByID(ctx, serverID)
	if err != nil {
		return fmt.Errorf("failed to load server %d: %w", serverID, err)
	}
	if server == nil {
		return fmt.Errorf("server %d not found", serverID)
	}

	subnet := s.getPortalSubnet()
	return remediator.EnsureBackendRoutingAndNAT(ctx, server, subnet)
}

// triggerBackendRoutingRemediation runs remediation in the background with a 30-second timeout.
// If the AWG provider or database is not yet ready at startup, it polls with a bounded retry.
func (s *Service) triggerBackendRoutingRemediation(serverID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bounded wait for awgProvider and db to become available during startup lifecycle
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(5 * time.Second)
	for {
		s.mu.RLock()
		ready := s.db != nil && s.awgProvider != nil
		s.mu.RUnlock()

		if ready {
			break
		}

		select {
		case <-ctx.Done():
			return
		case <-timeout:
			goto execute
		case <-ticker.C:
		}
	}

execute:
	if err := s.remediateBackendRouting(ctx, serverID); err != nil {
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "database is closed") {
			log.Printf("[vpn] warning: failed to ensure backend routing and NAT for server %d: %v", serverID, err)
		}
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

	if err := s.pool.SetTunnelStatusWithReason(ctx, serverID, TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
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

	if currentTun.DisableReason == models.DisableReasonAdmin || currentTun.Status == TunnelStatusDisabled || currentTun.Status == models.TunnelStatusDisabled {
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
		// Preserve portal identity the incoming config omits (empty key
		// fields): an update must never silently wipe the persisted
		// keypair that distributed client configs rely on.
		if cfg.ServerPrivateKey == "" {
			cfg.ServerPrivateKey = s.cfg.ServerPrivateKey
		}
		if cfg.ServerPublicKey == "" {
			cfg.ServerPublicKey = s.cfg.ServerPublicKey
		}
	}

	obfuscationChanged := s.cfg != nil && obfuscationDiffers(s.cfg, cfg)
	if obfuscationChanged && s.endpoint != nil && s.endpoint.IsRunning() {
		log.Printf("[vpn] rejecting config update: obfuscation parameters are immutable while listener is running")
		return errors.New("obfuscation parameters are immutable while listener is running")
	}

	listenPortChanged := s.cfg != nil && cfg.ListenPort > 0 && cfg.ListenPort != s.cfg.ListenPort
	if listenPortChanged && s.endpoint != nil && s.endpoint.IsRunning() {
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
	oldQueueSize := forwarder.DefaultClientQueueSize
	oldMaxActiveRoutes := 1000
	if s.cfg != nil && s.forwarder != nil {
		oldQueueSize = s.cfg.ClientQueueSize
		if oldQueueSize <= 0 {
			oldQueueSize = forwarder.DefaultClientQueueSize
		}
		oldMaxActiveRoutes = s.cfg.MaxTotalPeers
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
	rollback := func(cause error) error {
		var rollbackErrs []error
		if s.endpoint != nil && previousCfg != nil {
			if obfuscationChanged {
				if err := s.endpoint.UpdateObfuscation(previousCfg.H1, previousCfg.H2, previousCfg.H3, previousCfg.H4, previousCfg.S1, previousCfg.S2, previousCfg.S3, previousCfg.S4); err != nil {
					rollbackErrs = append(rollbackErrs, err)
				}
				if err := s.endpoint.UpdateHeaderProtectionKey(previousCfg.HeaderProtectionKey); err != nil {
					rollbackErrs = append(rollbackErrs, err)
				}
			}
			if listenPortChanged {
				s.endpoint.UpdateListenPort(previousCfg.ListenPort)
			}
		}
		if queueSizeChanged || routeLimitChanged {
			if err := s.forwarder.ReconfigureClientQueueConfig(oldQueueSize, oldMaxActiveRoutes); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		if s.db != nil && previousCfg != nil {
			if err := s.db.SaveVPNConfig(ctx, previousCfg); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		if len(rollbackErrs) > 0 {
			return fmt.Errorf("%w; rollback failed: %v", cause, errors.Join(rollbackErrs...))
		}
		return cause
	}
	if s.endpoint != nil && obfuscationChanged {
		if err := s.endpoint.UpdateObfuscation(cfg.H1, cfg.H2, cfg.H3, cfg.H4, cfg.S1, cfg.S2, cfg.S3, cfg.S4); err != nil {
			return rollback(err)
		}
		if err := s.endpoint.UpdateHeaderProtectionKey(cfg.HeaderProtectionKey); err != nil {
			return rollback(err)
		}
		log.Printf("[vpn] propagated obfuscation parameter change to idle listener")
	}
	if s.endpoint != nil && listenPortChanged {
		s.endpoint.UpdateListenPort(cfg.ListenPort)
		log.Printf("[vpn] propagated listen port change (%d) to idle listener", cfg.ListenPort)
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
	type pendingPrune struct {
		peer, sessionID string
		generation      uint64
	}
	var prunes []pendingPrune
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		for _, retirement := range retirements {
			retirement.Wait()
		}
		if s.endpoint != nil {
			for _, prune := range prunes {
				s.endpoint.PrunePeerTransportStateIfSession(prune.peer, prune.sessionID, prune.generation)
			}
		}
	}()

	if s.sessionMgr == nil {
		return nil
	}

	sessions := s.sessionMgr.GetSessionsByUserID(userID)
	for _, sess := range sessions {
		if s.peerGenerations == nil {
			s.peerGenerations = make(map[string]uint64)
		}
		s.peerGenerations[sess.PeerPublicKey]++
		fenceGen := s.peerGenerations[sess.PeerPublicKey]
		if s.endpoint != nil {
			s.endpoint.FencePeerGeneration(sess.PeerPublicKey, fenceGen)
		}
		_ = s.sessionMgr.CloseSession(ctx, sess.ID, "disconnected")
		if s.forwarder != nil {
			retirements = append(retirements, s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID))
		}
		prunes = append(prunes, pendingPrune{sess.PeerPublicKey, sess.ID, fenceGen})
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

// reapSession tears down forwarder routes and pool counters for an idle-timeout
// reaped session. Sticky affinity is preserved within AffinityTTL to prevent
// backend/IP thrashing upon client reconnect (issue #294). Pool connection counter
// decrement is skipped if periodic reconciliation already re-synchronized the gauge from the database.
// Note: sticky affinity pruning is intentionally not executed here to prevent O(K*N)
// lock contention under Service.mu during mass timeouts; it is amortized post-sweep
// and during periodic maintenance via PruneExpiredAffinity.
func (s *Service) reapSession(ctx context.Context, sess *models.VPNSession) {
	if sess == nil {
		return
	}
	var retirement forwarder.Retirement
	var fenceGen uint64
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if fenceGen != 0 {
			s.mu.Lock()
			// A reconnect may have installed a new session while the old
			// route's admitted writes were finishing. Check under Service.mu
			// so a new session cannot be created between this check and prune.
			current, exists := s.sessionMgr.GetSession(sess.PeerPublicKey)
			if !exists || current.ID == sess.ID {
				s.endpoint.PrunePeerTransportState(sess.PeerPublicKey, fenceGen)
			}
			s.mu.Unlock()
		}
		log.Printf("[vpn/service] reaped idle session: id=%s peer=%s user=%s ip=%s tunnel_id=%d",
			sess.ID, sess.PeerPublicKey, sess.UserID, sess.AssignedIP, sess.BackendTunnelID)
	}()

	if s.endpoint != nil && s.sessionMgr != nil && s.peerGenerations[sess.PeerPublicKey] <= sess.Generation {
		// CheckTimeouts has already removed this session. Reserve the next
		// generation before unlocking, so a fresh handshake receives a
		// generation beyond this fence while an old handshake is rejected.
		if current, exists := s.sessionMgr.GetSession(sess.PeerPublicKey); !exists || current.ID == sess.ID {
			fenceGen = sess.Generation + 1
			if s.peerGenerations == nil {
				s.peerGenerations = make(map[string]uint64)
			}
			s.peerGenerations[sess.PeerPublicKey] = fenceGen
			s.endpoint.FencePeerGeneration(sess.PeerPublicKey, fenceGen)
		}
	}

	if s.forwarder != nil {
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

// DisconnectSession disconnects a specific VPN session by ID.
func (s *Service) DisconnectSession(ctx context.Context, sessionID string) error {
	var retirement forwarder.Retirement
	var prunePeer, pruneSession string
	var fenceGen uint64
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if prunePeer != "" && s.endpoint != nil {
			s.endpoint.PrunePeerTransportStateIfSession(prunePeer, pruneSession, fenceGen)
		}
	}()

	if s.sessionMgr == nil {
		return nil
	}

	sess, ok := s.sessionMgr.GetSessionByID(sessionID)
	if !ok {
		return endpoint.ErrSessionNotFound
	}

	if s.peerGenerations == nil {
		s.peerGenerations = make(map[string]uint64)
	}
	s.peerGenerations[sess.PeerPublicKey]++
	fenceGen = s.peerGenerations[sess.PeerPublicKey]
	prunePeer, pruneSession = sess.PeerPublicKey, sess.ID
	if s.endpoint != nil {
		s.endpoint.FencePeerGeneration(prunePeer, fenceGen)
	}

	_ = s.sessionMgr.CloseSession(ctx, sessionID, "disconnected")
	if s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}
	if s.stickyMgr != nil {
		s.stickyMgr.ClearAffinity(sess.UserID)
		s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
	}
	// Mirror IncrementConnections from HandleIncomingPeer; see
	// DisconnectUser for why the decrement must happen on every path.
	s.pool.DecrementConnections(sess.BackendTunnelID)

	return nil
}

// SetPreCommitMigrationHookForTest sets a test hook called under s.mu in MigrateSession
// immediately before committing connection counters to the target tunnel (issue #289 rework).
func (s *Service) SetPreCommitMigrationHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preCommitMigrationHookForTest = fn
}

// validateMigrationTarget checks that targetTunnelID exists and is active, returning its StateVersion.
func (s *Service) validateMigrationTarget(targetTunnelID int64) (int64, error) {
	if s.pool == nil {
		return 0, nil
	}
	targetTun, err := s.pool.GetTunnelByID(targetTunnelID)
	if err != nil {
		return 0, fmt.Errorf("target backend tunnel %d not found in pool: %w", targetTunnelID, err)
	}
	if !strings.EqualFold(targetTun.Status, "active") {
		return 0, fmt.Errorf("target backend tunnel %d is not active (status=%s)", targetTunnelID, targetTun.Status)
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
		return endpoint.ErrSessionNotFound
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
	var pruneSession string
	var pruneAfterRetirement bool
	var fenceGen uint64
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if pruneAfterRetirement && s.endpoint != nil {
			s.endpoint.PrunePeerTransportStateIfSession(clientPub, pruneSession, fenceGen)
		}
	}()

	if s.sessionMgr != nil && clientPub != "" {
		if sess, ok := s.sessionMgr.GetSession(clientPub); ok {
			if s.peerGenerations == nil {
				s.peerGenerations = make(map[string]uint64)
			}
			// ReleaseClient used to advance the generation once for the
			// session and once for the client. Reserve both before removing
			// the route so an in-flight handshake cannot commit during Wait.
			s.peerGenerations[sess.PeerPublicKey] += 2
			fenceGen = s.peerGenerations[sess.PeerPublicKey]
			if s.endpoint != nil {
				s.endpoint.FencePeerGeneration(clientPub, fenceGen)
			}
			pruneSession = sess.ID
			pruneAfterRetirement = true
			_ = s.sessionMgr.CloseSession(ctx, sess.ID, "client_deleted")
			if s.forwarder != nil {
				retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
			}
			if s.stickyMgr != nil {
				s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
			}
			// Mirror IncrementConnections from HandleIncomingPeer; see
			// DisconnectUser for why the decrement must happen on every path.
			s.pool.DecrementConnections(sess.BackendTunnelID)
		}
	}

	if clientPub != "" && !pruneAfterRetirement {
		if s.peerGenerations == nil {
			s.peerGenerations = make(map[string]uint64)
		}
		s.peerGenerations[clientPub]++
		fenceGen = s.peerGenerations[clientPub]
		if s.endpoint != nil {
			// No route to retire: keep the existing in-lock cleanup for a
			// client whose transport state outlived its session.
			s.endpoint.PrunePeerTransportStateIfSession(clientPub, "", fenceGen)
		}
	}

	if s.ipam != nil && clientPub != "" {
		_ = s.ipam.Release(clientPub)
	}

	return nil
}

// SetPreTransportCommitHookForTest sets the pre-transport-commit hook on the endpoint listener for testing.
func (s *Service) SetPreTransportCommitHookForTest(fn func(peerKey string, sessID string)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.endpoint != nil {
		s.endpoint.SetPreTransportCommitHookForTest(fn)
	}
}

// HasTransportStateForPeer reports whether the endpoint holds any transport state for peerKey.
func (s *Service) HasTransportStateForPeer(peerKey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.endpoint == nil {
		return false
	}
	return s.endpoint.HasTransportStateForPeer(peerKey)
}

// HandleIncomingPeer authenticates a peer. A healthy live session keeps its
// backend and route through cryptographic rekeys; only admission/reconnect or
// an unusable assignment goes through backend selection and route registration.
//
// Capacity serialization contract (issue #86): s.mu is held for the ENTIRE
// select → CreateSession → IncrementConnections sequence below, making the
// check-then-allocate capacity decision (GetActiveTunnels snapshot →
// selectTunnelForPeer/FilterHealthy → IncrementConnections) atomic. This is
// the invariant that keeps ActiveConnections from exceeding
// MaxPeersPerBackend: the gauge itself is only pool-mutex-atomic, so any
// future caller that mutates pool counters outside s.mu (or outside the
// rekey hook's nested sm.mu regime — the hook's only production call site
// today is the CreateSession call here, so it runs nested under s.mu too;
// full contract on tunnel.Pool.IncrementConnections) reopens the race.
// A replaced route's device writes are joined only after releasing s.mu;
// admission, session bookkeeping, and pool counters remain serialized above it.
func (s *Service) HandleIncomingPeer(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
	var retirement forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
	}()

	if s.auth == nil || s.ipam == nil || s.sessionMgr == nil || s.pool == nil {
		return nil, nil, errors.New("subsystems not initialized")
	}

	user, conn, err := s.auth.AuthenticatePeer(ctx, peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("peer authentication failed: %w", err)
	}

	if s.peerGenerations == nil {
		s.peerGenerations = make(map[string]uint64)
	}
	if live, ok := s.sessionMgr.GetSessionSnapshotByPeer(peerPublicKey); ok && live.UserID == user.ID && live.Status == "connected" {
		backend, backendErr := s.pool.GetTunnelByID(live.BackendTunnelID)
		if backendErr == nil && backend.Status == "active" &&
			(s.forwarder == nil || s.forwarder.HasSessionRoute(peerPublicKey, live.ID, conn.ID, live.AssignedIP, backend.ID)) {
			gen := max(s.peerGenerations[peerPublicKey], live.Generation) + 1
			if sess, advanced := s.sessionMgr.AdvanceLiveSessionGeneration(peerPublicKey, live.ID, user.ID, gen); advanced {
				s.peerGenerations[peerPublicKey] = gen
				if s.stickyMgr != nil {
					s.stickyMgr.AssignPeerAffinity(peerPublicKey, backend.ID)
				}
				return sess, backend, nil
			}
		}
	}

	activeTunnels := s.pool.GetActiveTunnels()
	if len(activeTunnels) == 0 {
		return nil, nil, loadbalancer.ErrNoActiveBackends
	}

	req := &loadbalancer.RoutingRequest{
		UserID:           user.ID,
		PeerPublicKey:    peerPublicKey,
		AvailableTunnels: activeTunnels,
	}

	backend, err := s.selectTunnelForPeer(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	s.assignmentMu.Lock()
	if s.db != nil {
		err = reservePersistedClientIPs(ctx, s.db, s.ipam)
	}
	var assignedIP net.IP
	if err == nil {
		assignedIP, err = s.resolveOrAllocatePeerIP(ctx, conn, peerPublicKey)
	}
	s.assignmentMu.Unlock()
	if err != nil {
		return nil, nil, err
	}

	s.peerGenerations[peerPublicKey]++
	peerGen := s.peerGenerations[peerPublicKey]

	sess, err := s.sessionMgr.CreateSession(ctx, user.ID, peerPublicKey, assignedIP.String(), backend.ID, conn.Name, peerGen)
	if err != nil {
		return nil, nil, fmt.Errorf("session creation failed: %w", err)
	}

	s.pool.IncrementConnections(backend.ID)

	if s.forwarder != nil {
		retirement = s.forwarder.BeginRegisterSessionWithLimit(sess.ID, conn.ID, peerPublicKey, assignedIP.String(), backend.ID, 0, 0)
		s.forwarder.AttachPeerDevice(peerPublicKey, &peerVirtualDevice{
			peerKey:  peerPublicKey,
			endpoint: s.endpoint,
		})
	}
	s.freshSessionRegistrations.Add(1)

	return sess, backend, nil
}

// PeerGeneration returns the latest assigned generation for a peer under s.mu.
func (s *Service) PeerGeneration(peerKey string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.peerGenerations == nil {
		return 0
	}
	return s.peerGenerations[peerKey]
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

func (s *Service) resolveOrAllocatePeerIP(ctx context.Context, conn *models.UserConnection, peerPublicKey string) (net.IP, error) {
	if conn != nil && conn.ClientParams != nil {
		if req, ok := conn.ClientParams["config_regeneration_required"].(bool); ok && req {
			return nil, fmt.Errorf("peer %s IP was quarantined due to conflict with another client: %w (config regeneration required)", peerPublicKey, endpoint.ErrIPAlreadyAllocated)
		}
		if qIP, ok := conn.ClientParams["quarantined_ip_collision"]; ok && qIP != nil && qIP != "" {
			return nil, fmt.Errorf("peer %s IP was quarantined due to conflict with another client: %w (config regeneration required)", peerPublicKey, endpoint.ErrIPAlreadyAllocated)
		}
		if rawIP, ok := conn.ClientParams["assigned_ip"]; ok && rawIP != nil {
			if strIP, ok := rawIP.(string); ok && strIP != "" {
				targetIP := net.ParseIP(strIP)
				if targetIP != nil && targetIP.To4() != nil {
					err := s.ipam.Reserve(targetIP, peerPublicKey)
					if err == nil {
						return targetIP, nil
					}
					if errors.Is(err, endpoint.ErrIPAlreadyAllocated) {
						return nil, fmt.Errorf("peer %s persisted IP %s conflicts with another client: %w", peerPublicKey, strIP, err)
					}
				}
			}
		}
	}

	ip, err := s.ipam.Allocate(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ip allocation failed: %w", err)
	}
	if conn != nil {
		params := make(map[string]any, len(conn.ClientParams)+1)
		for key, value := range conn.ClientParams {
			params[key] = value
		}
		delete(params, "config_regeneration_required")
		delete(params, "quarantined_ip_collision")
		params["assigned_ip"] = ip.String()
		if s.db != nil && conn.ID != "" {
			updated, err := s.db.UpdateConnection(ctx, conn.ID, map[string]any{
				"client_params": params,
			})
			if err != nil || !updated {
				_ = s.ipam.Release(peerPublicKey)
				if err == nil {
					err = errors.New("connection was removed")
				}
				return nil, fmt.Errorf("persist assigned IP for peer %s (updated=%t): %w", peerPublicKey, updated, err)
			}
		}
		conn.ClientParams = params
	}
	return ip, nil
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
							if errors.Is(err, endpoint.ErrIPAlreadyAllocated) {
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

type peerVirtualDevice struct {
	peerKey  string
	endpoint *endpoint.Listener
}

func (p *peerVirtualDevice) Write(pkt []byte) (int, error) {
	err := p.endpoint.SendToPeer(p.peerKey, pkt)
	if err != nil {
		return 0, err
	}
	return len(pkt), nil
}
func (p *peerVirtualDevice) Read(pkt []byte) (int, error) { return 0, errors.New("not implemented") }
func (p *peerVirtualDevice) Close() error                 { return nil }
func (p *peerVirtualDevice) Name() string                 { return "virtual-" + p.peerKey }
func (p *peerVirtualDevice) MTU() int                     { return 1280 }
