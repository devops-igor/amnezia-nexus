package vpn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// returnStackDevice models the plaintext boundary of a decrypted backend
// tunnel. Both application endpoints use real userspace TCP/UDP stacks;
// the portal's production backend reader and queue pumps move their packets.
// This does not model encryption between Nexus and the backend VPN server.
type returnStackDevice struct {
	tun  tun.Device
	once sync.Once
}

func (d *returnStackDevice) Read(p []byte) (int, error) {
	sizes := []int{0}
	n, err := d.tun.Read([][]byte{p}, sizes, 0)
	if err != nil || n == 0 {
		return 0, err
	}
	return sizes[0], nil
}

func (d *returnStackDevice) Write(p []byte) (int, error) {
	_, err := d.tun.Write([][]byte{p}, 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *returnStackDevice) Close() (err error) {
	d.once.Do(func() { err = d.tun.Close() })
	return err
}

// QualificationSubjectConfig holds settings for the upstream qualification subject.
type QualificationSubjectConfig struct {
	DBPath           string `json:"db_path"`
	FrozenConfigPath string `json:"frozen_config_path"`
	ReadyPath        string `json:"ready_path"`
	ListenPort       int    `json:"listen_port"`
	EchoPort         uint16 `json:"echo_port"`
	UnderlayHostIP   string `json:"underlay_host_ip"`
	DestinationIP    string `json:"destination_ip"`
	Engine           string `json:"engine"`
	ReuseDB          bool   `json:"reuse_db"`
}

// QualificationSubject manages an isolated upstream qualification subject instance.
type QualificationSubject struct {
	cfg          QualificationSubjectConfig
	db           *database.DB
	svc          *Service
	engine       *IngressEngine
	backendVT    tun.Device
	backendStack *netstack.Net
	adapter      *returnStackDevice
	tcpListeners []net.Listener
	udpConns     []net.PacketConn
	backendDone  chan struct{}
	stopOnce     sync.Once
	stopErr      error
}

// NewQualificationSubject constructs and starts the upstream qualification subject helper.
// It initializes an isolated test DB, real portal identity, test user and connection,
// freezes the rendered client configuration before engine startup, starts backend TCP/UDP
// echo services, constructs Service.NewIngressEngine, and starts the real dataplane path.
func normalizeSubjectConfig(cfg QualificationSubjectConfig) (QualificationSubjectConfig, error) {
	if cfg.Engine == "" {
		cfg.Engine = "upstream"
	}
	if cfg.Engine != "upstream" {
		return cfg, fmt.Errorf("invalid subject engine %q: upstream is the only runtime engine", cfg.Engine)
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "test-artifacts/runtime/panel_test.db"
	}
	if cfg.FrozenConfigPath == "" {
		cfg.FrozenConfigPath = "test-artifacts/runtime/frozen-client.conf"
	}
	if cfg.ReadyPath == "" {
		cfg.ReadyPath = "test-artifacts/runtime/subject.ready"
	}
	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}
	if cfg.EchoPort == 0 {
		cfg.EchoPort = 40001
	}
	if cfg.UnderlayHostIP == "" {
		cfg.UnderlayHostIP = "10.254.250.1"
	}
	if cfg.DestinationIP == "" {
		cfg.DestinationIP = "10.100.0.1"
	}

	for _, p := range []string{cfg.DBPath, cfg.FrozenConfigPath, cfg.ReadyPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return cfg, fmt.Errorf("create directory for %s: %w", p, err)
		}
	}
	if !cfg.ReuseDB {
		_ = os.Remove(cfg.DBPath)
		_ = os.Remove(cfg.DBPath + "-shm")
		_ = os.Remove(cfg.DBPath + "-wal")
		_ = os.Remove(cfg.FrozenConfigPath)
	}
	_ = os.Remove(cfg.ReadyPath)
	return cfg, nil
}

func initSubjectPortal(ctx context.Context, cfg QualificationSubjectConfig) (*database.DB, *Service, int64, int64, clientawg.Peer, error) {
	if cfg.ReuseDB {
		return loadReusedSubjectPortal(ctx, cfg)
	}
	return createFreshSubjectPortal(ctx, cfg)
}

func loadReusedSubjectPortal(ctx context.Context, cfg QualificationSubjectConfig) (*database.DB, *Service, int64, int64, clientawg.Peer, error) {
	db, err := database.Open(cfg.DBPath, "test-secret-key-1234567890123456")
	if err != nil {
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("open qualification database: %w", err)
	}

	servers, err := db.GetAllServers(ctx)
	if err != nil || len(servers) == 0 {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("retrieve qualification servers: %w", err)
	}
	sID := servers[0].ID

	tunnels, err := db.GetAllBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("retrieve qualification tunnels: %w", err)
	}
	tunnelID := tunnels[0].ID

	svc, err := NewVPNService(db, nil)
	if err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("initialize vpn service with reused db: %w", err)
	}

	users, err := db.GetAllUsers(ctx)
	if err != nil || len(users) == 0 {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("retrieve qualification users: %w", err)
	}
	uID := users[0].ID

	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("retrieve qualification connection: %w", err)
	}
	clientPubKey := conns[0].ClientID
	assignedIPStr, ok := conns[0].ClientParams["assigned_ip"].(string)
	if !ok || assignedIPStr == "" {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, errors.New("missing assigned IP in qualification connection")
	}
	assignedIP := netip.MustParseAddr(assignedIPStr)
	clientPeer := clientawg.Peer{
		PublicKey: clientPubKey,
		AllowedIP: netip.PrefixFrom(assignedIP, 32),
	}

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("sync backend pool: %w", err)
	}

	if _, err := os.Stat(cfg.FrozenConfigPath); err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("frozen client config missing: %w", err)
	}

	return db, svc, sID, tunnelID, clientPeer, nil
}

func createFreshSubjectPortal(ctx context.Context, cfg QualificationSubjectConfig) (*database.DB, *Service, int64, int64, clientawg.Peer, error) {
	db, err := database.Open(cfg.DBPath, "test-secret-key-1234567890123456")
	if err != nil {
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("open qualification database: %w", err)
	}

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Server 1",
		Host: "198.51.100.1",
		Protocols: map[string]any{
			"awg": map[string]any{"public_key": "backend-test-public-key", "port": 51820},
		},
	})
	if err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("create backend server: %w", err)
	}

	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "backend-test-public-key",
		PrivateKey:    "backend-test-private-key",
		Endpoint:      "198.51.100.1:51820",
		Status:        models.TunnelStatusActive,
		LatencyMS:     10,
	})
	if err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("create backend tunnel: %w", err)
	}

	hpBytes := make([]byte, 32)
	for i := range hpBytes {
		hpBytes[i] = byte(i + 1)
	}
	endpointStr := fmt.Sprintf("%s:%d", cfg.UnderlayHostIP, cfg.ListenPort)
	vpnCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          cfg.ListenPort,
		PublicEndpoint:      endpointStr,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       500,
		MaxPeersPerBackend:  100,
		H1:                  models.DegenerateHeaderRange(1020325451),
		H2:                  models.DegenerateHeaderRange(3288052141),
		H3:                  models.DegenerateHeaderRange(2528465083),
		H4:                  models.DegenerateHeaderRange(1766607858),
		S1:                  50,
		S2:                  100,
		S3:                  150,
		S4:                  200,
		HeaderProtectionKey: base64.StdEncoding.EncodeToString(hpBytes),
	}

	svc, err := NewVPNService(db, vpnCfg)
	if err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("initialize vpn service: %w", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "qual-client",
		Role:     "user",
		Enabled:  true,
	})
	if err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("create qualification user: %w", err)
	}

	rawConfig, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("generate client config: %w", err)
	}

	if err := os.WriteFile(cfg.FrozenConfigPath, []byte(rawConfig), 0600); err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("write frozen client config: %w", err)
	}

	conns, err := db.GetConnectionsByUserID(ctx, uID)
	if err != nil || len(conns) == 0 {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("retrieve qualification connection: %w", err)
	}
	clientPubKey := conns[0].ClientID
	assignedIPStr, ok := conns[0].ClientParams["assigned_ip"].(string)
	if !ok || assignedIPStr == "" {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, errors.New("missing assigned IP in qualification connection")
	}
	assignedIP := netip.MustParseAddr(assignedIPStr)
	clientPeer := clientawg.Peer{
		PublicKey: clientPubKey,
		AllowedIP: netip.PrefixFrom(assignedIP, 32),
	}

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		_ = db.Close()
		return nil, nil, 0, 0, clientawg.Peer{}, fmt.Errorf("sync backend pool: %w", err)
	}

	return db, svc, sID, tunnelID, clientPeer, nil
}

func setupEchoStack(destinationIP string, echoPort uint16) (tun.Device, *netstack.Net, []net.Listener, []net.PacketConn, error) {
	destAddrs := []netip.Addr{netip.MustParseAddr(destinationIP)}
	if destinationIP != "198.51.100.99" {
		destAddrs = append(destAddrs, netip.MustParseAddr("198.51.100.99"))
	}
	backendVT, backendStack, err := netstack.CreateNetTUN(destAddrs, nil, 1280)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create backend tun: %w", err)
	}

	var tcpListeners []net.Listener
	var udpConns []net.PacketConn
	cleanup := func() {
		for _, l := range tcpListeners {
			_ = l.Close()
		}
		for _, c := range udpConns {
			_ = c.Close()
		}
		_ = backendVT.Close()
	}

	for _, addr := range destAddrs {
		tcpL, err := backendStack.ListenTCPAddrPort(netip.AddrPortFrom(addr, echoPort))
		if err != nil {
			cleanup()
			return nil, nil, nil, nil, fmt.Errorf("listen backend tcp on %s:%d: %w", addr, echoPort, err)
		}
		udpC, err := backendStack.ListenUDPAddrPort(netip.AddrPortFrom(addr, echoPort))
		if err != nil {
			_ = tcpL.Close()
			cleanup()
			return nil, nil, nil, nil, fmt.Errorf("listen backend udp on %s:%d: %w", addr, echoPort, err)
		}
		tcpListeners = append(tcpListeners, tcpL)
		udpConns = append(udpConns, udpC)

		go runEchoTCP(tcpL)
		go runEchoUDP(udpC)
	}

	return backendVT, backendStack, tcpListeners, udpConns, nil
}

func writeSubjectReadiness(cfg QualificationSubjectConfig) error {
	readyData := map[string]any{
		"status":         "ready",
		"engine":         cfg.Engine,
		"listen_port":    cfg.ListenPort,
		"echo_port":      cfg.EchoPort,
		"underlay_ip":    cfg.UnderlayHostIP,
		"destination_ip": cfg.DestinationIP,
		"pid":            os.Getpid(),
		"ready_at":       time.Now().UTC().Format(time.RFC3339),
	}
	readyBytes, err := json.MarshalIndent(readyData, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal readiness data: %w", err)
	}
	if err := os.WriteFile(cfg.ReadyPath, readyBytes, 0600); err != nil {
		return fmt.Errorf("write readiness file: %w", err)
	}
	return nil
}

// NewQualificationSubject constructs and starts the upstream qualification subject helper.
// It initializes an isolated test DB, real portal identity, test user and connection,
// freezes the rendered client configuration before engine startup, starts backend TCP/UDP
// echo services, constructs Service.NewIngressEngine, and starts the real dataplane path.
func NewQualificationSubject(cfg QualificationSubjectConfig) (*QualificationSubject, error) {
	normCfg, err := normalizeSubjectConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	db, svc, sID, tunnelID, clientPeer, err := initSubjectPortal(ctx, normCfg)
	if err != nil {
		return nil, err
	}

	sub := &QualificationSubject{
		cfg: normCfg,
		db:  db,
		svc: svc,
	}

	// Mock probe function so Service startup/sweeps do not block or fail on mock backend
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	}
	sub.svc.SetProbeFunc(mockProbe)

	backendVT, backendStack, tcpListeners, udpConns, err := setupEchoStack(normCfg.DestinationIP, normCfg.EchoPort)
	if err != nil {
		_ = sub.Stop()
		return nil, err
	}
	sub.backendVT = backendVT
	sub.backendStack = backendStack
	sub.tcpListeners = tcpListeners
	sub.udpConns = udpConns

	sub.adapter = &returnStackDevice{tun: backendVT}
	sub.svc.forwarder.AttachBackendDevice(tunnelID, sub.adapter)

	sub.backendDone = make(chan struct{})
	go func() {
		defer close(sub.backendDone)
		sub.svc.pumpBackendReturns(tunnelID, sID, sub.adapter)
	}()
	sub.svc.forwarder.StartPumps(ctx)

	engine, err := sub.svc.NewIngressEngine(ctx, "nexus-subject", []clientawg.Peer{clientPeer})
	if err != nil {
		_ = sub.Stop()
		return nil, fmt.Errorf("construct ingress engine: %w", err)
	}
	sub.engine = engine

	if err := sub.engine.Start(); err != nil {
		_ = sub.Stop()
		return nil, fmt.Errorf("start ingress engine: %w", err)
	}
	sub.svc.stickyMgr.AssignPeerAffinity(clientPeer.PublicKey, tunnelID)

	if err := writeSubjectReadiness(normCfg); err != nil {
		_ = sub.Stop()
		return nil, err
	}

	return sub, nil
}

func runEchoTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}(c)
	}
}

func runEchoUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		_, _ = pc.WriteTo(pkt, remote)
	}
}

// Stop cleanly shuts down the qualification subject and tears down all resources.
func (s *QualificationSubject) Stop() error {
	s.stopOnce.Do(func() {
		var errs []error
		if s.cfg.ReadyPath != "" {
			_ = os.Remove(s.cfg.ReadyPath)
		}
		if s.engine != nil {
			if err := s.engine.Stop(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.svc != nil {
			if s.cfg.Engine == "custom" {
				if err := s.svc.Stop(); err != nil {
					errs = append(errs, err)
				}
			} else if s.svc.forwarder != nil {
				s.svc.forwarder.StopPumps()
			}
		}
		if s.adapter != nil {
			_ = s.adapter.Close()
			if s.backendDone != nil {
				<-s.backendDone
			}
		}
		for _, l := range s.tcpListeners {
			if err := l.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		for _, c := range s.udpConns {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if s.db != nil {
			if err := s.db.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		s.stopErr = errors.Join(errs...)
	})
	return s.stopErr
}

// DB returns the underlying isolated database instance.
func (s *QualificationSubject) DB() *database.DB {
	return s.db
}

// Service returns the underlying VPN service instance.
func (s *QualificationSubject) Service() *Service {
	return s.svc
}

// Engine returns the underlying IngressEngine instance.
func (s *QualificationSubject) Engine() *IngressEngine {
	return s.engine
}

// Config returns the configuration used to start the subject.
func (s *QualificationSubject) Config() QualificationSubjectConfig {
	return s.cfg
}
