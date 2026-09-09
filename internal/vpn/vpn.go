package vpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/endpoint"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/tunnel"
)

// Status represents the overall runtime telemetry of the VPN endpoint and load balancing subsystem.
type Status struct {
	ListenerRunning   bool   `json:"listener_running"`
	ActiveTunnels     int    `json:"active_tunnels"`
	ConnectedSessions int    `json:"connected_sessions"`
	RxBytes           int64  `json:"rx_bytes"`
	TxBytes           int64  `json:"tx_bytes"`
	DroppedPackets    uint64 `json:"dropped_packets"`
	PublicEndpoint    string `json:"public_endpoint,omitempty"`
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
)

// BackendTunnel is an alias for models.BackendTunnel.
type BackendTunnel = models.BackendTunnel

// Session is an alias for models.VPNSession.
type Session = models.VPNSession

// LoadBalancer is an alias for loadbalancer.LoadBalancer.
type LoadBalancer = loadbalancer.LoadBalancer

// LeastConnectionsLoadBalancer is an alias for loadbalancer.LeastConnectionsBalancer.
type LeastConnectionsLoadBalancer = loadbalancer.LeastConnectionsBalancer

// NewLeastConnectionsLoadBalancer creates a least connections load balancer.
func NewLeastConnectionsLoadBalancer() *loadbalancer.LeastConnectionsBalancer {
	return loadbalancer.NewLeastConnectionsBalancer(loadbalancer.CapacityConfig{})
}

// AWGStatusProvider defines an interface for querying live AWG status on a server.
type AWGStatusProvider interface {
	GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error)
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
type Service struct {
	mu            sync.RWMutex
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
	requireTun       bool
	tunOpener        func() (endpoint.PacketDevice, error)
	tunDev           endpoint.PacketDevice
	backendDevices   map[int64]BackendDevice
	lastLoggedDrops  atomic.Uint64
	publicIPMu       sync.RWMutex
	detectedPublicIP string
}

// obfuscationMigrationMu serializes first-read obfuscation migration
// across concurrent NewVPNService calls so racing first starts converge
// on one persisted parameter set instead of divergent ephemeral values
// that would desync the listener from rendered client configs.
var obfuscationMigrationMu sync.Mutex

// ensureObfuscationParams migrates a config whose H1..H4/S1..S4 are
// unset (legacy rows written before obfuscation parameters existed).
// Under the migration lock it re-reads the persisted config — a
// concurrent first start may have already persisted parameters, and
// the persisted values win over any in-memory guess — generates
// standard-profile parameters when still unset, and persists them
// synchronously. Persistence failures are returned so startup fails
// loudly instead of running with divergent ephemeral values.
// The ListenPort is propagated through every save branch (R3): the
// migration must never persist a zeroed listen_port, which GetVPNConfig's
// fill-down would re-default to the default port and desync the running listener
// from rendered client configs. Ports <= 0 fall back to DefaultListenPort.
func ensureObfuscationParams(ctx context.Context, db *database.DB, cfg *models.VPNConfig) error {
	if db == nil || cfg == nil || cfg.H1 != 0 {
		return nil
	}

	obfuscationMigrationMu.Lock()
	defer obfuscationMigrationMu.Unlock()

	persisted, err := db.GetVPNConfig(ctx)
	if err == nil && persisted != nil && persisted.H1 != 0 {
		cfg.H1 = persisted.H1
		cfg.H2 = persisted.H2
		cfg.H3 = persisted.H3
		cfg.H4 = persisted.H4
		cfg.S1 = persisted.S1
		cfg.S2 = persisted.S2
		cfg.S3 = persisted.S3
		cfg.S4 = persisted.S4
		return nil
	}

	h1, h2, h3, h4, s1, s2, s3, s4, err := awg.GenerateStandardObfuscationValues()
	if err != nil {
		return fmt.Errorf("failed to generate obfuscation params: %w", err)
	}
	cfg.H1, cfg.H2, cfg.H3, cfg.H4 = h1, h2, h3, h4
	cfg.S1, cfg.S2, cfg.S3, cfg.S4 = s1, s2, s3, s4

	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}

	if persisted != nil {
		persisted.H1, persisted.H2, persisted.H3, persisted.H4 = h1, h2, h3, h4
		persisted.S1, persisted.S2, persisted.S3, persisted.S4 = s1, s2, s3, s4
		// R3: propagate the caller's (already validated) listen port so the
		// migration save cannot zero out a previously wired port.
		persisted.ListenPort = cfg.ListenPort
		if err := db.SaveVPNConfig(ctx, persisted); err != nil {
			return fmt.Errorf("failed to persist obfuscation params: %w", err)
		}
	} else if err := db.SaveVPNConfig(ctx, cfg); err != nil {
		return fmt.Errorf("failed to persist obfuscation params: %w", err)
	}
	return nil
}

// preserveObfuscationParams copies unset (zero) AWG obfuscation fields
// from the current config into an incoming config so partial updates
// cannot clobber the parameters already distributed to peers.
func preserveObfuscationParams(from, to *models.VPNConfig) {
	if to.H1 == 0 {
		to.H1 = from.H1
	}
	if to.H2 == 0 {
		to.H2 = from.H2
	}
	if to.H3 == 0 {
		to.H3 = from.H3
	}
	if to.H4 == 0 {
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

// NewVPNService initializes the complete unified VPN subsystem.
func NewVPNService(db *database.DB, cfg *models.VPNConfig) (*Service, error) {
	if cfg == nil {
		if db != nil {
			var err error
			cfg, err = db.GetVPNConfig(context.Background())
			if err != nil {
				cfg = &models.VPNConfig{
					Algorithm:          models.LBLeastConnections,
					ListenPort:         51820,
					SubnetCIDR:         "10.100.0.0/16",
					HealthThresholdMS:  500,
					MaxTotalPeers:      1000,
					MaxPeersPerBackend: 250,
					Weights:            make(map[int64]int),
				}
			}
		} else {
			cfg = &models.VPNConfig{
				Algorithm:          models.LBLeastConnections,
				ListenPort:         51820,
				SubnetCIDR:         "10.100.0.0/16",
				HealthThresholdMS:  500,
				MaxTotalPeers:      1000,
				MaxPeersPerBackend: 250,
				Weights:            make(map[int64]int),
			}
		}
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
		H1:          int(cfg.H1),
		S1:          cfg.S1,
		H2:          int(cfg.H2),
		S2:          cfg.S2,
		H3:          int(cfg.H3),
		S3:          cfg.S3,
		H4:          int(cfg.H4),
		S4:          cfg.S4,
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
	}

	lb, err := loadbalancer.NewLoadBalancer(cfg.Algorithm, cfg.Weights, caps)
	if err != nil {
		lb = loadbalancer.NewLeastConnectionsBalancer(caps)
	}

	stickyMgr := loadbalancer.NewStickySessionManager(db, lb, caps)

	accountant := forwarder.NewTrafficAccountant(db, 2*time.Second)
	fwd := forwarder.NewForwarder(accountant, 512)

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
		if db != nil {
			if fresh, ferr := db.GetVPNConfig(context.Background()); ferr == nil && fresh != nil {
				cfg.ServerPrivateKey = fresh.ServerPrivateKey
				cfg.ServerPublicKey = fresh.ServerPublicKey
			}
		}
	}

	svc := &Service{
		db:            db,
		cfg:           cfg,
		endpoint:      epListener,
		sessionMgr:    sessionMgr,
		ipam:          ipam,
		auth:          auth,
		pool:          pool,
		prober:        prober,
		reconnectMgr:  reconnectMgr,
		balancer:      lb,
		stickyMgr:     stickyMgr,
		forwarder:     fwd,
		accountant:    accountant,
		portalPubKey:  pub,
		portalPrivKey: priv,
	}

	epListener.SetIncomingPeerHandler(svc.HandleIncomingPeer)
	epListener.SetClientPacketRouter(fwd.RouteClientToBackend)
	// Idle-timeout reaper: run the same teardown as an explicit disconnect
	// (forwarder route, pool counter, sticky affinity) for each reaped
	// session. Without this, idle timeouts leak all three (the reaper used
	// to discard CheckTimeouts' return value).
	epListener.SetSessionReaperHook(func(ctx context.Context, sess *models.VPNSession) {
		if sess == nil {
			return
		}
		_ = svc.DisconnectSession(ctx, sess.ID)
	})

	svc.prober.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		svc.mu.RLock()
		var tunID int64
		for _, t := range svc.pool.ListTunnels() {
			if t.PublicKey == serverPubKey {
				tunID = t.ID
				break
			}
		}
		var dev BackendDevice
		if tunID > 0 && svc.backendDevices != nil {
			dev = svc.backendDevices[tunID]
		}
		svc.mu.RUnlock()

		if dev != nil {
			last := dev.LastHandshakeTime()
			if !last.IsZero() && time.Since(last) < 3*time.Minute {
				return 10 * time.Millisecond, nil
			} else if !last.IsZero() && time.Since(last) >= 3*time.Minute {
				return 0, errors.New("amneziawg-go handshake timeout")
			}
			// If LastHandshakeTime is zero, check startup grace period (90s cutoff).
			// If within grace period: amneziawg-go requires a manual trigger packet to initiate the first handshake.
			// Send a dummy IPv4 packet to 0.0.0.0 to trigger it and report success.
			// If past grace period: report handshake timeout.
			if time.Since(dev.CreatedAt()) >= 90*time.Second {
				return 0, fmt.Errorf("amneziawg-go handshake timeout: initial handshake not completed within %v", 90*time.Second)
			}
			dummyPacket := []byte{
				0x45, 0x00, 0x00, 0x14, // Version/IHL, ToS, Total Length
				0x00, 0x00, 0x40, 0x00, // Identification, Flags/Fragment Offset
				0x40, 0x01, 0x00, 0x00, // TTL, Protocol (ICMP), Header Checksum
				0x00, 0x00, 0x00, 0x00, // Source IP (0.0.0.0)
				0x00, 0x00, 0x00, 0x00, // Dest IP (0.0.0.0)
			}
			_, _ = dev.Write(dummyPacket)
			return 10 * time.Millisecond, nil
		}

		return health.ProbeAWGEndpoint(ctx, endpoint, serverPubKey, clientPrivKey, psk, hpKey, h1, h2, s1, s2, timeout)
	})

	svc.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		return svc.ensureBackendDeviceAttached(ctx, t)
	})

	return svc, nil
}

// NewService creates a new VPNService with a specific algorithm (backwards compatibility).
func NewService(algo models.LoadBalancingAlgorithm) *Service {
	cfg := &models.VPNConfig{
		Algorithm:          algo,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            make(map[int64]int),
	}
	svc, _ := NewVPNService(nil, cfg)
	return svc
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

// GetBackendDeviceForTest returns the backend device for a tunnel ID.
func (s *Service) GetBackendDeviceForTest(tunID int64) BackendDevice {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendDevices == nil {
		return nil
	}
	return s.backendDevices[tunID]
}

// ProbeTunnel probes a tunnel using the service's health prober.
func (s *Service) ProbeTunnel(ctx context.Context, t *models.BackendTunnel) (int64, error) {
	if s.prober == nil {
		return 0, errors.New("health prober not initialized")
	}
	return s.prober.ProbeTunnel(ctx, t)
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
	}
}

// ensureBackendDeviceAttached verifies that a data-plane device is attached for the tunnel.
// If missing, it attempts to attach the device using persisted server AWG credentials.
func (s *Service) ensureBackendDeviceAttached(ctx context.Context, t *models.BackendTunnel) error {
	if t == nil {
		return nil
	}
	s.mu.RLock()
	hasDev := s.backendDevices != nil && s.backendDevices[t.ID] != nil
	s.mu.RUnlock()
	if hasDev {
		return nil
	}

	var awgParams map[string]any
	var attachErr error
	if s.db != nil {
		srv, err := s.db.GetServerByID(ctx, t.ServerID)
		if err != nil || srv == nil {
			attachErr = fmt.Errorf("failed to load server %d: %w", t.ServerID, err)
		} else if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
			if p, ok := awgInfo["awg_params"].(map[string]any); ok && p != nil {
				awgParams = p
			} else if p, ok := awgInfo["params"].(map[string]any); ok && p != nil {
				awgParams = p
			}
		}
	} else {
		attachErr = errors.New("database not available")
	}

	if attachErr == nil {
		s.mu.Lock()
		attachErr = s.attachBackendForwarder(t, awgParams)
		s.mu.Unlock()
	}

	if attachErr != nil {
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

	// 1. Sync tunnels from DB
	if s.pool != nil {
		if err := s.pool.SyncFromDB(ctx); err != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("failed to sync tunnels from DB: %w", err)
		}

		// Restore backend data-plane devices for active tunnels
		s.restoreBackendDevices(ctx)
	}

	// 2. Sync sessions from DB
	if s.sessionMgr != nil {
		_ = s.sessionMgr.SyncFromDB(ctx)
	}

	// 3. Start forwarder & accountant
	if s.forwarder != nil {
		s.forwarder.Start(ctx)
		s.forwarder.StartPumps(ctx)
	}

	// 4. Start health prober & reconnect manager
	if s.prober != nil {
		s.prober.Start(ctx)
	}
	if s.reconnectMgr != nil {
		s.reconnectMgr.Start(ctx)
	}

	// 5. Start endpoint listener
	if s.endpoint != nil {
		if err := s.endpoint.Start(ctx); err != nil {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
			return fmt.Errorf("failed to start endpoint listener: %w", err)
		}
	}

	// 6. Client-facing TUN device (production data plane). When required
	// (RequireTunDevice) and the TUN device cannot be opened, quiesce
	// everything Start brought up and fail with an error chain wrapping
	// endpoint.ErrTunUnavailable — the panel continues management-only.
	if s.requireTun && s.tunOpener != nil {
		dev, tunErr := s.tunOpener()
		if tunErr != nil {
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

	return nil
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
		ListenerRunning: s.endpoint != nil && s.endpoint.IsRunning(),
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

	// Register the prober client peer on the backend server so amneziawg-go accepts probe handshakes
	// We also use allowed_ips=0.0.0.0/0 so the portal can route arbitrary traffic.
	if awgProv != nil {
		type clientAdder interface {
			AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error)
		}
		if adder, ok := awgProv.(clientAdder); ok {
			proberPub, err := health.ComputePublicKeyFromPrivate(tun.PrivateKey)
			if err != nil {
				_ = pool.SetTunnelStatus(ctx, serverID, TunnelStatusDegraded, 0)
				return fmt.Errorf("failed to compute prober client public key for server %d: %w", serverID, err)
			}
			clientParams := map[string]any{
				"clientName":        "Portal Data Plane",
				"name":              "Portal Data Plane",
				"public_key":        proberPub,
				"client_public_key": proberPub,
				"allowed_ips":       "0.0.0.0/0",
			}
			if _, err := adder.AddClient(ctx, server, clientParams); err != nil {
				_ = pool.SetTunnelStatus(ctx, serverID, TunnelStatusDegraded, 0)
				return fmt.Errorf("failed to register portal data plane peer on backend server %d: %w", serverID, err)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.attachBackendForwarder(tun, awgParams); err != nil {
		return err
	}

	return pool.SetTunnelStatus(ctx, serverID, TunnelStatusActive, 10)
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
		}
	}

	dev, devErr := tunnel.NewAWGClientDevice(fmt.Sprintf("awg-be-%d", tun.ServerID), tun.Endpoint, tun.PrivateKey, tun.PublicKey, 1340, awgParams)
	if devErr != nil {
		return fmt.Errorf("failed to create backend AWG device for server %d: %w", tun.ServerID, devErr)
	}
	s.forwarder.AttachBackendDevice(tun.ID, dev)
	if s.backendDevices == nil {
		s.backendDevices = make(map[int64]BackendDevice)
	}
	s.backendDevices[tun.ID] = dev

	// Spawn backend read loop to route packets back to clients
	go func(backendID int64, device BackendDevice) {
		buf := make([]byte, 2048)
		for {
			n, err := device.Read(buf)
			if err != nil {
				return
			}
			if n >= 20 && (buf[0]>>4) == 4 { // IPv4
				destIP := net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()
				_ = s.forwarder.RouteBackendToClient(backendID, buf[:n], destIP)
			}
		}
	}(tun.ID, dev)
	return nil
}

// DisableBackend disables a backend server and initiates connection draining.
func (s *Service) DisableBackend(ctx context.Context, serverID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}

	tunnel, err := s.pool.GetTunnel(serverID)
	if err != nil {
		return err
	}

	_ = s.pool.SetTunnelStatus(ctx, serverID, TunnelStatusDisabled, 0)

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

	// Trigger failover for active sessions on this backend
	if s.stickyMgr != nil {
		activeTunnels := s.pool.GetActiveTunnels()
		migrations, err := s.stickyMgr.HandleFailover(ctx, tunnel.ID, activeTunnels)
		if err != nil {
			log.Printf("[vpn] failover for backend %d found no healthy target: %v", serverID, err)
		}
		// Redirect live traffic: the detached backend's device is closed, so
		// any session still routed to it would silently drop packets. The
		// sticky maps alone do not move the forwarder's per-session route.
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
	}

	return nil
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
func (s *Service) UpdateConfig(ctx context.Context, cfg *models.VPNConfig) error {
	if cfg == nil {
		return errors.New("vpn config cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Preserve obfuscation parameters the incoming config omits (zero
	// H1..H4 / S1..S4) so partial updates cannot silently clobber the
	// values already distributed to peers.
	if s.cfg != nil {
		preserveObfuscationParams(s.cfg, cfg)
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

	// Any remaining difference is an explicit obfuscation change. An
	// idle listener can be re-parameterized safely; a running listener
	// cannot (its packet-processing paths read config fields without
	// holding the listener lock), so reject the change explicitly
	// instead of letting config and listener diverge silently.
	if s.cfg != nil && obfuscationDiffers(s.cfg, cfg) {
		if s.endpoint != nil && s.endpoint.IsRunning() {
			log.Printf("[vpn] rejecting config update: obfuscation parameters are immutable while listener is running")
			return errors.New("obfuscation parameters are immutable while listener is running")
		}
		if s.endpoint != nil {
			s.endpoint.UpdateObfuscation(cfg.H1, cfg.H2, cfg.H3, cfg.H4, cfg.S1, cfg.S2, cfg.S3, cfg.S4)
			log.Printf("[vpn] propagated obfuscation parameter change to idle listener")
		}
	}

	// A listen-port change on a RUNNING listener cannot take effect: the
	// UDP socket is already bound to the old port, so the bound socket and
	// the persisted config would silently diverge (Issue #16). Mirror the
	// obfuscation rejection above. The env wiring path in cmd/*/main.go
	// runs BEFORE service Start, so it never hits this rejection.
	if s.cfg != nil && cfg.ListenPort > 0 && cfg.ListenPort != s.cfg.ListenPort {
		if s.endpoint != nil && s.endpoint.IsRunning() {
			log.Printf("[vpn] rejecting config update: listen_port cannot change from %d to %d while listener is running", s.cfg.ListenPort, cfg.ListenPort)
			return errors.New("listen_port cannot be changed while the VPN listener is running; restart the panel")
		}
		if s.endpoint != nil {
			s.endpoint.UpdateListenPort(cfg.ListenPort)
			log.Printf("[vpn] propagated listen port change (%d) to idle listener", cfg.ListenPort)
		}
	}

	s.cfg = cfg
	if s.db != nil {
		if err := s.db.SaveVPNConfig(ctx, cfg); err != nil {
			return fmt.Errorf("failed to persist vpn config: %w", err)
		}
	}

	caps := loadbalancer.CapacityConfig{
		MaxTotalPeers:      cfg.MaxTotalPeers,
		MaxPeersPerBackend: cfg.MaxPeersPerBackend,
	}

	lb, err := loadbalancer.NewLoadBalancer(cfg.Algorithm, cfg.Weights, caps)
	if err == nil {
		s.balancer = lb
		if s.stickyMgr != nil {
			s.stickyMgr = loadbalancer.NewStickySessionManager(s.db, lb, caps)
		}
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionMgr == nil {
		return nil
	}

	sessions := s.sessionMgr.GetSessionsByUserID(userID)
	for _, sess := range sessions {
		_ = s.sessionMgr.CloseSession(ctx, sess.ID, "disconnected")
		if s.forwarder != nil {
			s.forwarder.UnregisterSession(sess.PeerPublicKey)
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

// DisconnectSession disconnects a specific VPN session by ID.
func (s *Service) DisconnectSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionMgr == nil {
		return nil
	}

	sess, ok := s.sessionMgr.GetSessionByID(sessionID)
	if !ok {
		return endpoint.ErrSessionNotFound
	}

	_ = s.sessionMgr.CloseSession(ctx, sessionID, "disconnected")
	if s.forwarder != nil {
		s.forwarder.UnregisterSession(sess.PeerPublicKey)
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

// ReleaseClient releases IPAM allocations and disconnects any active sessions for the client.
func (s *Service) ReleaseClient(ctx context.Context, clientPub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionMgr != nil && clientPub != "" {
		if sess, ok := s.sessionMgr.GetSession(clientPub); ok {
			_ = s.sessionMgr.CloseSession(ctx, sess.ID, "client_deleted")
			if s.forwarder != nil {
				s.forwarder.UnregisterSession(sess.PeerPublicKey)
			}
			if s.stickyMgr != nil {
				s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
			}
			// Mirror IncrementConnections from HandleIncomingPeer; see
			// DisconnectUser for why the decrement must happen on every path.
			s.pool.DecrementConnections(sess.BackendTunnelID)
		}
	}

	if s.ipam != nil && clientPub != "" {
		_ = s.ipam.Release(clientPub)
	}

	return nil
}

// HandleIncomingPeer authenticates a connecting peer, selects a backend tunnel, and registers forwarding routes.
func (s *Service) HandleIncomingPeer(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.auth == nil || s.ipam == nil || s.sessionMgr == nil || s.pool == nil {
		return nil, nil, errors.New("subsystems not initialized")
	}

	user, conn, err := s.auth.AuthenticatePeer(ctx, peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("peer authentication failed: %w", err)
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

	var backend *models.BackendTunnel
	if s.stickyMgr != nil {
		b, _, err := s.stickyMgr.GetOrAssignBackend(ctx, req)
		if err != nil {
			return nil, nil, fmt.Errorf("backend selection failed: %w", err)
		}
		backend = b
	} else if s.balancer != nil {
		b, err := s.balancer.SelectBackend(ctx, req)
		if err != nil {
			return nil, nil, fmt.Errorf("backend selection failed: %w", err)
		}
		backend = b
	}

	assignedIP, err := s.ipam.Allocate(peerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ip allocation failed: %w", err)
	}

	sess, err := s.sessionMgr.CreateSession(ctx, user.ID, peerPublicKey, assignedIP.String(), backend.ID)
	if err != nil {
		_ = s.ipam.Release(peerPublicKey)
		return nil, nil, fmt.Errorf("session creation failed: %w", err)
	}

	s.pool.IncrementConnections(backend.ID)

	if s.forwarder != nil {
		s.forwarder.RegisterSession(sess.ID, conn.ID, peerPublicKey, assignedIP.String(), backend.ID)
		s.forwarder.AttachPeerDevice(peerPublicKey, &peerVirtualDevice{
			peerKey:  peerPublicKey,
			endpoint: s.endpoint,
		})
	}

	return sess, backend, nil
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

func resolveHeaderProtectionKey(ctx context.Context, db *database.DB, awgParams *awg.AWGParams) {
	if awgParams.HeaderProtectionKey == "" && db != nil {
		if srvs, err := db.GetAllServers(ctx); err == nil {
			for _, srv := range srvs {
				if srv.Protocols != nil {
					if awgInfo, ok := srv.Protocols["awg"].(map[string]any); ok {
						if params, ok := awgInfo["awg_params"].(map[string]any); ok {
							if hpk := health.ExtractHeaderProtectionKey(params); hpk != "" {
								awgParams.HeaderProtectionKey = hpk
								break
							}
						}
					}
				}
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
	rat        *int
	rt         *int
	rej        *int
	kt         *int
	mha        *int
	pk         *int
	cpAdd      *string
}

func resolveClientConfigParameters(awgConn *models.UserConnection, cpEnabled bool, cpVal string) (*clientConfigParameters, error) {
	res := &clientConfigParameters{}
	if awgConn != nil && len(awgConn.ClientParams) > 0 {
		res.rat = getIntParam(awgConn.ClientParams, "rekey_after_time")
		res.rt = getIntParam(awgConn.ClientParams, "rekey_timeout")
		res.rej = getIntParam(awgConn.ClientParams, "reject_after_time")
		res.kt = getIntParam(awgConn.ClientParams, "keepalive_timeout")
		res.mha = getIntParam(awgConn.ClientParams, "max_handshake_attempts")
		res.pk = getIntParam(awgConn.ClientParams, "persistent_keepalive")
		res.clientPriv = getStringParam(awgConn.ClientParams, "client_private_key")
		if res.clientPriv != "" && awgConn.ClientID != "" {
			res.clientPub = awgConn.ClientID
		}
		if s := getStringParam(awgConn.ClientParams, "content_padding_addition"); s != "" {
			res.cpAdd = &s
		}
	}

	if res.rat == nil || res.rt == nil || res.rej == nil || res.kt == nil || res.mha == nil || res.pk == nil {
		rat, rt, rej, kt, mha, pk := awg.GenerateClientTimingParams()
		if *rt >= *rat {
			adj := *rat - 1
			rt = &adj
		}
		res.rat = rat
		res.rt = rt
		res.rej = rej
		res.kt = kt
		res.mha = mha
		res.pk = pk
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

	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	}

	endpointStr := s.resolveClientEndpoint(ctx, cfg, listenPort)
	awgParams := awg.AWGParamsFromVPNConfig(cfg)
	resolveHeaderProtectionKey(ctx, db, awgParams)
	cpEnabled, cpVal := resolveContentPadding(ctx, db, cfg)

	awgConn := findAWGConnection(ctx, db, user)
	p, err := resolveClientConfigParameters(awgConn, cpEnabled, cpVal)
	if err != nil {
		return "", "", err
	}

	clientParams := make(map[string]any)
	if awgConn != nil && awgConn.ClientParams != nil {
		for k, v := range awgConn.ClientParams {
			clientParams[k] = v
		}
	}
	clientParams["rekey_after_time"] = *p.rat
	clientParams["rekey_timeout"] = *p.rt
	clientParams["reject_after_time"] = *p.rej
	clientParams["keepalive_timeout"] = *p.kt
	clientParams["max_handshake_attempts"] = *p.mha
	clientParams["persistent_keepalive"] = *p.pk
	clientParams["client_private_key"] = p.clientPriv
	if p.cpAdd != nil {
		clientParams["content_padding_addition"] = *p.cpAdd
	}

	saveOrUpdateAWGConnection(ctx, db, user, awgConn, p.clientPub, clientParams)

	assignedIP := "10.100.0.2"
	if s.ipam != nil {
		if ip, err := s.ipam.Allocate(p.clientPub); err == nil {
			assignedIP = ip.String()
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

	configStr := awg.RenderClientConfig(
		p.clientPriv,
		assignedIP,
		portalPub,
		"", // psk
		endpointStr,
		"1.1.1.1",
		"1.0.0.1",
		"1420",
		awgParams,
		ud,
	)

	filename := fmt.Sprintf("amnezia-portal-%s.conf", user.Username)
	return configStr, filename, nil
}

func findAWGConnection(ctx context.Context, db *database.DB, user *models.User) *models.UserConnection {
	conns, err := db.GetConnectionsByUserID(ctx, user.ID)
	if err != nil || len(conns) == 0 {
		return nil
	}

	// Priority 1: Match pending connection created with empty ClientID
	for i := range conns {
		if models.NormalizeProtocol(conns[i].Protocol) == "awg" && conns[i].ClientID == "" {
			return &conns[i]
		}
	}
	// Priority 2: Match default portal connection
	for i := range conns {
		if conns[i].ServerID == 0 && conns[i].Name == fmt.Sprintf("%s-awg", user.Username) {
			return &conns[i]
		}
	}
	// Priority 3: Fallback for single-connection tests / legacy mode
	if len(conns) == 1 && models.NormalizeProtocol(conns[0].Protocol) == "awg" {
		return &conns[0]
	}
	return nil
}

func saveOrUpdateAWGConnection(ctx context.Context, db *database.DB, user *models.User, awgConn *models.UserConnection, clientPub string, clientParams map[string]any) {
	if awgConn != nil {
		updates := map[string]any{
			"client_id": clientPub,
		}
		if clientParams != nil {
			updates["client_params"] = clientParams
		}
		_, _ = db.UpdateConnection(ctx, awgConn.ID, updates)
	} else {
		newConn := &models.UserConnection{
			UserID:       user.ID,
			ServerID:     0,
			Protocol:     "awg",
			ClientID:     clientPub,
			Name:         fmt.Sprintf("%s-awg", user.Username),
			AWGMimicry:   models.AWGMimicryAuto,
			ClientParams: clientParams,
		}
		_, _ = db.CreateConnection(ctx, newConn)
	}
}

func getIntParam(m map[string]any, key string) *int {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case int:
		return &val
	case int64:
		i := int(val)
		return &i
	case float64:
		i := int(val)
		return &i
	case string:
		if i, err := strconv.Atoi(val); err == nil {
			return &i
		}
	}
	return nil
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

func detectPortalHostIPFallback(ctx context.Context) string {
	if externalIPDetector != nil {
		if ip := externalIPDetector(ctx); ip != "" {
			return ip
		}
	}
	if ip := detectOutboundInterfaceIP(); ip != "" {
		return ip
	}
	return "127.0.0.1"
}

func detectExternalPublicIP(ctx context.Context) string {
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	endpoints := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		// #nosec G107 -- fixed public IP detection endpoints
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		ipStr := strings.TrimSpace(string(body))
		if parsed := net.ParseIP(ipStr); parsed != nil {
			return ipStr
		}
	}
	return ""
}

func detectOutboundInterfaceIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err == nil {
		defer conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil {
			return udpAddr.IP.String()
		}
	}
	return ""
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
		return formatEndpoint(cfg.PublicEndpoint, listenPort)
	}

	// 2. Environment variables: VPN_PUBLIC_ENDPOINT, PUBLIC_ENDPOINT, PUBLIC_IP
	for _, envKey := range []string{"VPN_PUBLIC_ENDPOINT", "PUBLIC_ENDPOINT", "PUBLIC_IP"} {
		if envVal := strings.TrimSpace(os.Getenv(envKey)); envVal != "" {
			return formatEndpoint(envVal, listenPort)
		}
	}

	// 3. Portal Host Auto-Detection (cached in memory on VPNService)
	var hostIP string
	if s != nil {
		hostIP = s.detectPortalHostIP(ctx)
	} else {
		hostIP = detectPortalHostIPFallback(ctx)
	}
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	return net.JoinHostPort(hostIP, strconv.Itoa(listenPort))
}

func (s *Service) detectPortalHostIP(ctx context.Context) string {
	if s != nil {
		s.publicIPMu.RLock()
		cached := s.detectedPublicIP
		s.publicIPMu.RUnlock()
		if cached != "" {
			return cached
		}
	}

	detected := detectPortalHostIPFallback(ctx)

	if s != nil && detected != "" {
		s.publicIPMu.Lock()
		s.detectedPublicIP = detected
		s.publicIPMu.Unlock()
	}
	return detected
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
func (p *peerVirtualDevice) MTU() int                     { return 1420 }
