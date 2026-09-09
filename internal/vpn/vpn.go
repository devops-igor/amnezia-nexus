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
	backendDevices   map[int64]*tunnel.AWGClientDevice
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
}

// obfuscationDiffers reports whether two configs disagree on any AWG
// obfuscation parameter.
func obfuscationDiffers(a, b *models.VPNConfig) bool {
	return a.H1 != b.H1 || a.H2 != b.H2 || a.H3 != b.H3 || a.H4 != b.H4 ||
		a.S1 != b.S1 || a.S2 != b.S2 || a.S3 != b.S3 || a.S4 != b.S4
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

// SetHealthProber sets a custom health prober instance.
func (s *Service) SetHealthProber(prober *tunnel.HealthProber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prober = prober
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
	}

	// 2. Sync sessions from DB
	if s.sessionMgr != nil {
		_ = s.sessionMgr.SyncFromDB(ctx)
	}

	// 3. Start forwarder & accountant
	if s.forwarder != nil {
		s.forwarder.Start(ctx)
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

	listenPort := 51820
	if s.cfg != nil && s.cfg.ListenPort > 0 {
		listenPort = s.cfg.ListenPort
	}
	status.PublicEndpoint = resolveClientEndpointInternal(ctx, s, s.cfg, listenPort)

	return status, nil
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}
	if s.db == nil {
		return errors.New("database not available")
	}

	server, err := s.db.GetServerByID(ctx, serverID)
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

	tun, err := s.pool.AddTunnel(ctx, serverID, endpoint, pub)
	if err != nil {
		return fmt.Errorf("failed to register backend tunnel for server %d: %w", serverID, err)
	}

	// Register the prober client peer on the backend server so amneziawg-go accepts probe handshakes
	// We also use allowed_ips=0.0.0.0/0 so the portal can route arbitrary traffic.
	if proberPub, err := health.ComputePublicKeyFromPrivate(tun.PrivateKey); err != nil {
		log.Printf("[vpn] warning: failed to compute prober client public key for server %d: %v", serverID, err)
	} else if s.awgProvider != nil {
		type clientAdder interface {
			AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error)
		}
		if adder, ok := s.awgProvider.(clientAdder); ok {
			clientParams := map[string]any{
				"clientName":        "Portal Data Plane",
				"name":              "Portal Data Plane",
				"public_key":        proberPub,
				"client_public_key": proberPub,
				"allowed_ips":       "0.0.0.0/0",
			}
			if _, err := adder.AddClient(ctx, server, clientParams); err != nil {
				log.Printf("[vpn] warning: failed to register portal data plane peer on backend server %d: %v", serverID, err)
			}
		}
	}

	if err := s.attachBackendForwarder(tun, awgParams); err != nil {
		return err
	}

	return s.pool.SetTunnelStatus(ctx, serverID, TunnelStatusActive, 10)
}

// resolveBackendCredentials retrieves AWG credentials for a backend, falling back to live discovery.
func (s *Service) resolveBackendCredentials(ctx context.Context, serverID int64, server *models.Server) (string, int, map[string]any, error) {
	var pub string
	var port int
	var awgParams map[string]any
	if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
		pub, _ = awgInfo["public_key"].(string)
		port = parsePort(awgInfo["port"])
		awgParams, _ = awgInfo["awg_params"].(map[string]any)
	}

	if (pub == "" || port <= 0) && s.awgProvider != nil {
		if livePub, livePort, ok := s.discoverLiveAWG(ctx, serverID, server); ok {
			pub = livePub
			port = livePort
			if awgInfo, ok := server.Protocols["awg"].(map[string]any); ok {
				awgParams, _ = awgInfo["awg_params"].(map[string]any)
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
	dev, devErr := tunnel.NewAWGClientDevice(fmt.Sprintf("awg-be-%d", tun.ServerID), tun.Endpoint, tun.PrivateKey, tun.PublicKey, 1340, awgParams)
	if devErr != nil {
		return fmt.Errorf("failed to create backend AWG device for server %d: %w", tun.ServerID, devErr)
	}
	s.forwarder.AttachBackendDevice(tun.ID, dev)
	if s.backendDevices == nil {
		s.backendDevices = make(map[int64]*tunnel.AWGClientDevice)
	}
	s.backendDevices[tun.ID] = dev

	// Spawn backend read loop to route packets back to clients
	go func(backendID int64, device *tunnel.AWGClientDevice) {
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
		_, _ = s.stickyMgr.HandleFailover(ctx, tunnel.ID, activeTunnels)
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

	// Generate client keypair
	clientPub, clientPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		return "", "", err
	}

	// Persist / update client connection in database so peer authentication succeeds
	matchOrCreateAWGConnection(ctx, db, user, clientPub)

	assignedIP := "10.100.0.2"
	if s.ipam != nil {
		if ip, err := s.ipam.Allocate(clientPub); err == nil {
			assignedIP = ip.String()
		}
	}

	listenPort := 51820
	if cfg != nil && cfg.ListenPort > 0 {
		listenPort = cfg.ListenPort
	}

	endpointStr := s.resolveClientEndpoint(ctx, cfg, listenPort)

	// Use real AWG obfuscation parameters from stored VPNConfig
	awgParams := awg.AWGParamsFromVPNConfig(cfg)

	configStr := awg.RenderClientConfig(
		clientPriv,
		assignedIP,
		portalPub,
		"", // psk
		endpointStr,
		"1.1.1.1",
		"1.0.0.1",
		"1420",
		awgParams, nil,
	)

	filename := fmt.Sprintf("amnezia-portal-%s.conf", user.Username)
	return configStr, filename, nil
}

func matchOrCreateAWGConnection(ctx context.Context, db *database.DB, user *models.User, clientPub string) {
	conns, err := db.GetConnectionsByUserID(ctx, user.ID)
	var awgConn *models.UserConnection
	if err == nil {
		// Priority 1: Match pending connection created with empty ClientID
		for i := range conns {
			if models.NormalizeProtocol(conns[i].Protocol) == "awg" && conns[i].ClientID == "" {
				awgConn = &conns[i]
				break
			}
		}
		// Priority 2: Match default portal connection
		if awgConn == nil {
			for i := range conns {
				if conns[i].ServerID == 0 && conns[i].Name == fmt.Sprintf("%s-awg", user.Username) {
					awgConn = &conns[i]
					break
				}
			}
		}
		// Priority 3: Fallback for single-connection tests / legacy mode
		if awgConn == nil && len(conns) == 1 && models.NormalizeProtocol(conns[0].Protocol) == "awg" {
			awgConn = &conns[0]
		}
	}

	if awgConn != nil {
		_, _ = db.UpdateConnection(ctx, awgConn.ID, map[string]any{
			"client_id": clientPub,
		})
	} else {
		newConn := &models.UserConnection{
			UserID:     user.ID,
			ServerID:   0,
			Protocol:   "awg",
			ClientID:   clientPub,
			Name:       fmt.Sprintf("%s-awg", user.Username),
			AWGMimicry: models.AWGMimicryAuto,
		}
		_, _ = db.CreateConnection(ctx, newConn)
	}
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
