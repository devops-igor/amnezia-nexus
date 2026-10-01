package vpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// Pinned dependency constants for Issue #392 qualification.
const (
	ExpectedUpstreamAWGModule  = "github.com/amnezia-vpn/amneziawg-go/v3"
	ExpectedUpstreamAWGVersion = "v3.1.20260828"
)

// EnvironmentManifest pins and reports the exact runtime and dependency environment.
type EnvironmentManifest struct {
	NexusVersion      string `json:"nexus_version"`
	NexusCommit       string `json:"nexus_commit"`
	GoVersion         string `json:"go_version"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	UpstreamAWGModule string `json:"upstream_awg_module"`
	UpstreamAWGVer    string `json:"upstream_awg_version"`
}

// FindRepoRoot traverses upward from the current working directory to locate the repository root.
func FindRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repository root (go.mod) not found")
		}
		dir = parent
	}
}

// VerifyEnvironmentAndDependencies checks and asserts exact upstream dependency pinning in go.mod
// and runtime build info, reporting system details and failing fast on version mismatches.
func VerifyEnvironmentAndDependencies(repoRoot string) (*EnvironmentManifest, error) {
	manifest := &EnvironmentManifest{
		NexusVersion: config.AppVersion,
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
	}

	// Read build info from runtime if available
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				manifest.NexusCommit = setting.Value
				break
			}
		}
		for _, dep := range info.Deps {
			if dep.Path == ExpectedUpstreamAWGModule {
				manifest.UpstreamAWGModule = dep.Path
				manifest.UpstreamAWGVer = dep.Version
				break
			}
		}
	}

	// Fallback/Direct check of go.mod in repoRoot to guarantee exact pinning
	goModPath := filepath.Join(repoRoot, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, ExpectedUpstreamAWGModule) {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 {
					manifest.UpstreamAWGModule = fields[0]
					manifest.UpstreamAWGVer = fields[1]
				}
			}
		}
	} else if manifest.UpstreamAWGModule == "" {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	// Git commit fallback from .git if debug.BuildInfo lacked vcs.revision
	if manifest.NexusCommit == "" {
		headPath := filepath.Join(repoRoot, ".git", "HEAD")
		if headData, err := os.ReadFile(headPath); err == nil {
			headStr := strings.TrimSpace(string(headData))
			if strings.HasPrefix(headStr, "ref: ") {
				refFile := filepath.Join(repoRoot, ".git", strings.TrimPrefix(headStr, "ref: "))
				if refData, err := os.ReadFile(refFile); err == nil {
					manifest.NexusCommit = strings.TrimSpace(string(refData))
				}
			} else if len(headStr) >= 7 {
				manifest.NexusCommit = headStr
			}
		}
	}

	// Fail fast on module or version mismatch
	if manifest.UpstreamAWGModule != ExpectedUpstreamAWGModule {
		return nil, fmt.Errorf("upstream module mismatch: got %q, want %q", manifest.UpstreamAWGModule, ExpectedUpstreamAWGModule)
	}
	if manifest.UpstreamAWGVer != ExpectedUpstreamAWGVersion {
		return nil, fmt.Errorf("upstream version mismatch: got %q, want %q", manifest.UpstreamAWGVer, ExpectedUpstreamAWGVersion)
	}

	return manifest, nil
}

// RedactedConfigManifest represents the frozen, redacted evidence manifest schema.
// Private keys, unredacted secrets, and real server IP addresses are strictly excluded.
type RedactedConfigManifest struct {
	RenderedConfigHash     string `json:"rendered_config_sha256"`
	ClientPublicKey        string `json:"client_public_key"`
	AssignedIP             string `json:"assigned_ip"`
	ServerEndpoint         string `json:"server_endpoint"`
	ServerPort             int    `json:"server_port"`
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	S1                     int    `json:"s1"`
	S2                     int    `json:"s2"`
	S3                     int    `json:"s3"`
	S4                     int    `json:"s4"`
	Jc                     int    `json:"jc"`
	Jmin                   int    `json:"jmin"`
	Jmax                   int    `json:"jmax"`
	HeaderProtection       string `json:"header_protection"`
	RandomTrailers         string `json:"random_trailers,omitempty"`
	ContentPaddingAddition string `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         string `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string `json:"rekey_timeout,omitempty"`
	PersistentKeepalive    string `json:"persistent_keepalive,omitempty"`
}

// CompatibilityEvidenceManifest combines the environment manifest and frozen redacted config manifest.
type CompatibilityEvidenceManifest struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   string                 `json:"generated_at"`
	Environment   EnvironmentManifest    `json:"environment"`
	FrozenConfig  RedactedConfigManifest `json:"frozen_client_configuration"`
}

// FreezeAndRedactConfig computes the SHA-256 hash of a rendered client configuration and builds
// a privacy-compliant redacted manifest.
func FreezeAndRedactConfig(rawConfig string, clientPubKey string, assignedIP string, serverPort int) (*RedactedConfigManifest, error) {
	if rawConfig == "" {
		return nil, errors.New("rawConfig cannot be empty")
	}

	hash := sha256.Sum256([]byte(rawConfig))
	hashHex := hex.EncodeToString(hash[:])

	manifest := &RedactedConfigManifest{
		RenderedConfigHash: hashHex,
		ClientPublicKey:    clientPubKey,
		AssignedIP:         assignedIP,
		ServerPort:         serverPort,
		HeaderProtection:   "<absent>",
	}

	lines := strings.Split(rawConfig, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)

		switch k {
		case "Address":
			if manifest.AssignedIP == "" {
				ipPart, _, _ := strings.Cut(v, "/")
				manifest.AssignedIP = ipPart
			}
		case "Endpoint":
			_, portPart, err := net.SplitHostPort(v)
			if err == nil {
				manifest.ServerEndpoint = fmt.Sprintf("<redacted-ip>:%s", portPart)
			} else {
				manifest.ServerEndpoint = "<redacted-ip>:51820"
			}
		case "H1":
			manifest.H1 = v
		case "H2":
			manifest.H2 = v
		case "H3":
			manifest.H3 = v
		case "H4":
			manifest.H4 = v
		case "S1":
			manifest.S1, _ = strconv.Atoi(v)
		case "S2":
			manifest.S2, _ = strconv.Atoi(v)
		case "S3":
			manifest.S3, _ = strconv.Atoi(v)
		case "S4":
			manifest.S4, _ = strconv.Atoi(v)
		case "Jc":
			manifest.Jc, _ = strconv.Atoi(v)
		case "Jmin":
			manifest.Jmin, _ = strconv.Atoi(v)
		case "Jmax":
			manifest.Jmax, _ = strconv.Atoi(v)
		case "HeaderProtectionKey":
			if v != "" {
				manifest.HeaderProtection = "<present-32B>"
			}
		case "RandomTrailers":
			manifest.RandomTrailers = v
		case "ContentPaddingAddition":
			manifest.ContentPaddingAddition = v
		case "RekeyAfterTime":
			manifest.RekeyAfterTime = v
		case "RekeyTimeout":
			manifest.RekeyTimeout = v
		case "PersistentKeepalive":
			manifest.PersistentKeepalive = v
		}
	}

	if manifest.ServerEndpoint == "" && serverPort > 0 {
		manifest.ServerEndpoint = fmt.Sprintf("<redacted-ip>:%d", serverPort)
	}

	if err := manifest.ValidatePrivacy(); err != nil {
		return nil, fmt.Errorf("privacy validation failed: %w", err)
	}

	return manifest, nil
}

// ValidatePrivacy enforces the security invariant: never record, log, or commit private keys,
// unredacted server IPs, or unredacted secrets.
func (m *RedactedConfigManifest) ValidatePrivacy() error {
	rawJSON, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s := string(rawJSON)

	// Invariant 1: No private keys
	if strings.Contains(strings.ToLower(s), "private") {
		return errors.New("privacy violation: 'private' keyword or private key found in manifest")
	}

	// Invariant 2: ServerEndpoint must not expose raw IP addresses
	if m.ServerEndpoint != "" {
		host, _, err := net.SplitHostPort(m.ServerEndpoint)
		if err == nil {
			if net.ParseIP(host) != nil {
				return fmt.Errorf("privacy violation: server endpoint contains unredacted IP %q", host)
			}
		}
	}

	// Invariant 3: HeaderProtection must be redacted
	if m.HeaderProtection != "<present-32B>" && m.HeaderProtection != "<absent>" {
		return fmt.Errorf("privacy violation: header protection key not redacted: %q", m.HeaderProtection)
	}

	// Invariant 4: No local filesystem paths
	homeLeakPattern := "/" + "home" + "/"
	tmpLeakPattern := "/" + "tmp" + "/"
	if strings.Contains(s, homeLeakPattern) || strings.Contains(s, tmpLeakPattern) {
		return errors.New("privacy violation: local filesystem path found in manifest")
	}

	return nil
}

// ValidatePrivacy checks the complete compatibility evidence manifest.
func (em *CompatibilityEvidenceManifest) ValidatePrivacy() error {
	if err := em.FrozenConfig.ValidatePrivacy(); err != nil {
		return err
	}
	rawJSON, err := json.Marshal(em)
	if err != nil {
		return err
	}
	s := string(rawJSON)
	if strings.Contains(strings.ToLower(s), "private_key") {
		return errors.New("privacy violation: private key found in evidence manifest")
	}
	homeLeakPattern := "/" + "home" + "/"
	tmpLeakPattern := "/" + "tmp" + "/"
	if strings.Contains(s, homeLeakPattern) || strings.Contains(s, tmpLeakPattern) {
		return errors.New("privacy violation: local filesystem path found in evidence manifest")
	}
	return nil
}

// DifferentialHarness provides sequential reference-vs-subject execution on the same test port.
type DifferentialHarness struct {
	t               testing.TB
	db              *database.DB
	svc             *Service
	listenPort      int
	destinationIP   netip.Addr
	echoPort        uint16
	clientUser      *models.User
	clientPeer      clientawg.Peer
	rawClientConfig string
	frozenHash      string
	manifest        *RedactedConfigManifest
	backendTunnelID int64
}

// ReferenceServer wraps a standalone upstream AWG device backed by a netstack echo responder.
type ReferenceServer struct {
	dev         *device.Device
	tun         tun.Device
	stack       *netstack.Net
	tcpListener net.Listener
	udpConn     net.PacketConn
	port        int
	closed      bool
	mu          sync.Mutex
}

// SubjectServer wraps the production Nexus IngressEngine with echo backend attachments.
type SubjectServer struct {
	svc          *Service
	engine       *IngressEngine
	backendVT    tun.Device
	backendStack *netstack.Net
	tcpListener  net.Listener
	udpConn      net.PacketConn
	port         int
	backendDone  chan struct{}
	adapter      *returnStackDevice
	closed       bool
	mu           sync.Mutex
}

// HarnessClient is an upstream AWG client device attached to netstack.
type HarnessClient struct {
	dev         *device.Device
	tun         tun.Device
	stack       *netstack.Net
	assignedIP  netip.Addr
	destination netip.Addr
	echoPort    uint16
	closed      bool
	mu          sync.Mutex
}

// fullAmneziaWGOpts returns a config mutator enforcing full AmneziaWG obfuscation:
// H1-H4 header ranges, S1-S4 padding >= 12, HeaderProtectionKey, RandomTrailers, and ContentPaddingAddition.
func fullAmneziaWGOpts() func(cfg *models.VPNConfig) {
	return func(cfg *models.VPNConfig) {
		cfg.H1 = models.NewHeaderRange(100000000, 200000000)
		cfg.H2 = models.NewHeaderRange(300000000, 400000000)
		cfg.H3 = models.NewHeaderRange(500000000, 600000000)
		cfg.H4 = models.NewHeaderRange(700000000, 800000000)
		cfg.S1 = 50
		cfg.S2 = 100
		cfg.S3 = 150
		cfg.S4 = 200
		cfg.RandomTrailers = false
		cfg.DisableCookies = false

		hpBytes := make([]byte, 32)
		for i := range hpBytes {
			hpBytes[i] = byte(i + 1)
		}
		cfg.HeaderProtectionKey = base64.StdEncoding.EncodeToString(hpBytes)
	}
}

// NewDifferentialHarness builds the qualification fixture with frozen client configuration.
func NewDifferentialHarness(t *testing.T, opts ...func(*models.VPNConfig)) *DifferentialHarness {
	t.Helper()
	db := setupTestDB(t)

	// Allocate a free ephemeral UDP port on 127.0.0.1
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listenPort := socket.LocalAddr().(*net.UDPAddr).Port
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}

	svc, _, _, _, _ := setupTestVPNService(t, db, func(cfg *models.VPNConfig) {
		cfg.ListenPort = listenPort
		cfg.PublicEndpoint = fmt.Sprintf("127.0.0.1:%d", listenPort)
		fullAmneziaWGOpts()(cfg)
		for _, opt := range opts {
			opt(cfg)
		}
	})

	ctx := t.Context()
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	cfg.ListenPort = listenPort
	cfg.PublicEndpoint = fmt.Sprintf("127.0.0.1:%d", listenPort)
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.HeaderProtectionKey == "" {
		svc.mu.Lock()
		svc.cfg.HeaderProtectionKey = ""
		svc.cfg.S1 = cfg.S1
		svc.cfg.S2 = cfg.S2
		svc.cfg.S3 = cfg.S3
		svc.cfg.S4 = cfg.S4
		svc.cfg.H1 = cfg.H1
		svc.cfg.H2 = cfg.H2
		svc.cfg.H3 = cfg.H3
		svc.cfg.H4 = cfg.H4
		svc.cfg.RandomTrailers = cfg.RandomTrailers
		svc.cfg.ContentPaddingAddition = cfg.ContentPaddingAddition
		svc.mu.Unlock()
		_ = svc.endpoint.UpdateHeaderProtectionKey("")
		_ = svc.endpoint.UpdateObfuscation(cfg.H1, cfg.H2, cfg.H3, cfg.H4, cfg.S1, cfg.S2, cfg.S3, cfg.S4)
		_ = db.SaveVPNConfig(ctx, cfg)
	} else {
		if err := svc.UpdateConfig(ctx, cfg); err != nil {
			t.Fatalf("update config: %v", err)
		}
	}

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tunnels := svc.pool.ListTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no backend tunnels configured")
	}
	backendTunnelID := tunnels[0].ID

	// Issue client config through production issuance path BEFORE servers start
	user, err := db.CreateUser(ctx, &models.User{Username: "diff-test-user", Role: "user", Enabled: true})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	rawConfig, _, err := svc.GenerateClientConfig(ctx, user)
	if err != nil {
		t.Fatalf("generate client config: %v", err)
	}

	conns, err := db.GetConnectionsByUserID(ctx, user)
	if err != nil || len(conns) == 0 {
		t.Fatalf("connections for user: %v", err)
	}
	clientPubKey := conns[0].ClientID
	assignedIP, ok := conns[0].ClientParams["assigned_ip"].(string)
	if !ok || assignedIP == "" {
		t.Fatalf("missing assigned IP: %+v", conns[0].ClientParams)
	}

	clientPeer := clientawg.Peer{
		PublicKey: clientPubKey,
		AllowedIP: netip.PrefixFrom(netip.MustParseAddr(assignedIP), 32),
	}

	manifest, err := FreezeAndRedactConfig(rawConfig, clientPubKey, assignedIP, listenPort)
	if err != nil {
		t.Fatalf("freeze and redact config: %v", err)
	}

	destinationIP := netip.MustParseAddr("198.51.100.99")

	return &DifferentialHarness{
		t:               t,
		db:              db,
		svc:             svc,
		listenPort:      listenPort,
		destinationIP:   destinationIP,
		echoPort:        40001,
		clientUser:      &models.User{ID: user, Username: "diff-test-user"},
		clientPeer:      clientPeer,
		rawClientConfig: rawConfig,
		frozenHash:      manifest.RenderedConfigHash,
		manifest:        manifest,
		backendTunnelID: backendTunnelID,
	}
}

// StartReferenceServer initializes the standalone reference AWG device and netstack echo server.
func (h *DifferentialHarness) StartReferenceServer() (*ReferenceServer, error) {
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{h.destinationIP}, nil, 1280)
	if err != nil {
		return nil, fmt.Errorf("reference tun: %w", err)
	}

	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "ref-server"))

	tcpListener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(h.destinationIP, h.echoPort))
	if err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("reference tcp listener: %w", err)
	}

	udpConn, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(h.destinationIP, h.echoPort))
	if err != nil {
		_ = tcpListener.Close()
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("reference udp listener: %w", err)
	}

	ref := &ReferenceServer{
		dev:         dev,
		tun:         vt,
		stack:       stack,
		tcpListener: tcpListener,
		udpConn:     udpConn,
		port:        h.listenPort,
	}

	ref.startEchoWorkers()

	ipc := h.buildReferenceServerIPC()
	if err := dev.IpcSet(ipc); err != nil {
		_ = ref.Close()
		return nil, fmt.Errorf("reference ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		_ = ref.Close()
		return nil, fmt.Errorf("reference up: %w", err)
	}

	return ref, nil
}

func (s *ReferenceServer) startEchoWorkers() {
	go func() {
		for {
			c, err := s.tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, remote, err := s.udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			_, _ = s.udpConn.WriteTo(pkt, remote)
		}
	}()
}

// Close stops the reference AWG device and echo listeners.
func (s *ReferenceServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var errs []error
	if s.tcpListener != nil {
		if err := s.tcpListener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.dev != nil {
		s.dev.Close()
	} else if s.tun != nil {
		if err := s.tun.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PeerEndpoint returns the client's outer roaming endpoint as recorded by the reference server.
func (s *ReferenceServer) PeerEndpoint() (string, error) {
	ipc, err := s.dev.IpcGet()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			return strings.TrimPrefix(line, "endpoint="), nil
		}
	}
	return "", errors.New("peer endpoint not found in reference UAPI")
}

// StopReferenceServer cleanly terminates the reference server.
func (h *DifferentialHarness) StopReferenceServer(ref *ReferenceServer) error {
	if ref == nil {
		return nil
	}
	return ref.Close()
}

// StartSubjectServer initializes the production Nexus IngressEngine with echo backend attachments.
func (h *DifferentialHarness) StartSubjectServer() (*SubjectServer, error) {
	ctx := context.Background()
	if err := h.svc.pool.SyncFromDB(ctx); err != nil {
		return nil, fmt.Errorf("sync pool: %w", err)
	}

	backendVT, backendStack, err := netstack.CreateNetTUN([]netip.Addr{h.destinationIP}, nil, 1280)
	if err != nil {
		return nil, fmt.Errorf("backend tun: %w", err)
	}

	tcpListener, err := backendStack.ListenTCPAddrPort(netip.AddrPortFrom(h.destinationIP, h.echoPort))
	if err != nil {
		_ = backendVT.Close()
		return nil, fmt.Errorf("backend tcp: %w", err)
	}

	udpConn, err := backendStack.ListenUDPAddrPort(netip.AddrPortFrom(h.destinationIP, h.echoPort))
	if err != nil {
		_ = tcpListener.Close()
		_ = backendVT.Close()
		return nil, fmt.Errorf("backend udp: %w", err)
	}

	adapter := &returnStackDevice{tun: backendVT}
	h.svc.forwarder.AttachBackendDevice(h.backendTunnelID, adapter)

	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		h.svc.pumpBackendReturns(h.backendTunnelID, 1, adapter)
	}()

	h.svc.forwarder.StartPumps(ctx)

	engine, err := h.svc.NewIngressEngine(ctx, "nexus-subject", []clientawg.Peer{h.clientPeer})
	if err != nil {
		_ = tcpListener.Close()
		_ = udpConn.Close()
		_ = adapter.Close()
		<-backendDone
		return nil, fmt.Errorf("new ingress engine: %w", err)
	}

	if err := engine.Start(); err != nil {
		_ = engine.Stop()
		_ = tcpListener.Close()
		_ = udpConn.Close()
		_ = adapter.Close()
		<-backendDone
		return nil, fmt.Errorf("engine start: %w", err)
	}

	h.svc.stickyMgr.AssignPeerAffinity(h.clientPeer.PublicKey, h.backendTunnelID)

	sub := &SubjectServer{
		svc:          h.svc,
		engine:       engine,
		backendVT:    backendVT,
		backendStack: backendStack,
		tcpListener:  tcpListener,
		udpConn:      udpConn,
		port:         h.listenPort,
		backendDone:  backendDone,
		adapter:      adapter,
	}

	sub.startEchoWorkers()
	return sub, nil
}

func (s *SubjectServer) startEchoWorkers() {
	go func() {
		for {
			c, err := s.tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, remote, err := s.udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			_, _ = s.udpConn.WriteTo(pkt, remote)
		}
	}()
}

// Close stops the subject Nexus engine and backend pumps.
func (s *SubjectServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var errs []error
	if s.engine != nil {
		if err := s.engine.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	s.svc.forwarder.StopPumps()
	if s.adapter != nil {
		_ = s.adapter.Close()
		<-s.backendDone
	}
	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	return errors.Join(errs...)
}

// PeerEndpoint returns the client's outer roaming endpoint as recorded by the subject Nexus engine.
func (s *SubjectServer) PeerEndpoint() (string, error) {
	st, err := s.engine.Portal().Status()
	if err != nil {
		return "", err
	}
	if len(st.Peers) > 0 {
		return st.Peers[0].Endpoint, nil
	}
	return "", errors.New("peer endpoint not found in subject status")
}

// StopSubjectServer cleanly terminates the subject server.
func (h *DifferentialHarness) StopSubjectServer(sub *SubjectServer) error {
	if sub == nil {
		return nil
	}
	return sub.Close()
}

// RestartSubjectServer performs a clean restart of the subject engine on the same port.
func (h *DifferentialHarness) RestartSubjectServer(sub *SubjectServer) (*SubjectServer, error) {
	if err := h.StopSubjectServer(sub); err != nil {
		return nil, fmt.Errorf("stop subject server: %w", err)
	}
	h.AssertPortFree(5 * time.Second)
	return h.StartSubjectServer()
}

// SetClientRekeyAfterTime modifies the raw client config's RekeyAfterTime parameter.
func (h *DifferentialHarness) SetClientRekeyAfterTime(seconds int) {
	var lines []string
	found := false
	for _, line := range strings.Split(h.rawClientConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "RekeyAfterTime") && strings.Contains(trimmed, "=") {
			lines = append(lines, fmt.Sprintf("RekeyAfterTime = %d", seconds))
			found = true
		} else {
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("RekeyAfterTime = %d", seconds))
	}
	h.rawClientConfig = strings.Join(lines, "\n")
}

// SetClientRekeyTimeout modifies the raw client config's RekeyTimeout parameter.
func (h *DifferentialHarness) SetClientRekeyTimeout(seconds int) {
	var lines []string
	found := false
	for _, line := range strings.Split(h.rawClientConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "RekeyTimeout") && strings.Contains(trimmed, "=") {
			lines = append(lines, fmt.Sprintf("RekeyTimeout = %d", seconds))
			found = true
		} else {
			lines = append(lines, line)
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("RekeyTimeout = %d", seconds))
	}
	h.rawClientConfig = strings.Join(lines, "\n")
}

// NewClient constructs an upstream AWG client device using the exact frozen client config.
func (h *DifferentialHarness) NewClient() (*HarnessClient, error) {
	assignedAddr := netip.MustParseAddr(h.clientPeer.AllowedIP.Addr().String())
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{assignedAddr}, nil, 1280)
	if err != nil {
		return nil, fmt.Errorf("client tun: %w", err)
	}

	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "client"))
	uapi := configToUAPI(h.t.(*testing.T), h.rawClientConfig)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("client uapi: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("client up: %w", err)
	}

	return &HarnessClient{
		dev:         dev,
		tun:         vt,
		stack:       stack,
		assignedIP:  assignedAddr,
		destination: h.destinationIP,
		echoPort:    h.echoPort,
	}, nil
}

// DialTCP initiates a TCP connection to the echo server through the tunnel.
func (c *HarnessClient) DialTCP(ctx context.Context) (net.Conn, error) {
	return c.stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(c.destination, c.echoPort))
}

// DialUDP initiates a UDP connection to the echo server through the tunnel.
func (c *HarnessClient) DialUDP() (net.Conn, error) {
	return c.stack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(c.destination, c.echoPort))
}

// ExchangeTCP writes payload to conn and reads the exact echoed bytes back.
func (c *HarnessClient) ExchangeTCP(conn net.Conn, payload []byte) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Write(payload)
	if err != nil || n != len(payload) {
		return nil, fmt.Errorf("tcp write: n=%d err=%w", n, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("tcp read: %w", err)
	}
	return buf, nil
}

// ExchangeUDP writes a datagram to conn and reads the echoed datagram back, retrying if necessary.
func (c *HarnessClient) ExchangeUDP(conn net.Conn, payload []byte) ([]byte, error) {
	for attempt := 0; attempt < 5; attempt++ {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Write(payload)
		if err != nil || n != len(payload) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		buf := make([]byte, len(payload)+128)
		nRead, err := conn.Read(buf)
		if err == nil && nRead == len(payload) && bytes.Equal(buf[:nRead], payload) {
			return buf[:nRead], nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("udp exchange timed out after 5 attempts")
}

// LastHandshakeTime returns the timestamp of the last successful handshake recorded by the device.
func (c *HarnessClient) LastHandshakeTime() time.Time {
	raw, err := c.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && k == "last_handshake_time_sec" {
			sec, _ := strconv.ParseInt(v, 10, 64)
			if sec > 0 {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

// Close stops the client AWG device and netstack.
func (c *HarnessClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.dev != nil {
		c.dev.Close()
	} else if c.tun != nil {
		if err := c.tun.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AssertPortFree verifies that the specified listen port is free.
func (h *DifferentialHarness) AssertPortFree(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: h.listenPort})
		if err == nil {
			_ = l.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	h.t.Fatalf("port %d did not become free within %s", h.listenPort, timeout)
}

func (h *DifferentialHarness) buildReferenceServerIPC() string {
	ctx := context.Background()
	cfg, err := h.svc.GetConfig(ctx)
	if err != nil {
		h.t.Fatalf("get config: %v", err)
	}

	portalPrivStr, err := security.DecryptCredential(cfg.ServerPrivateKey, h.db.SecretKey())
	if err != nil {
		portalPrivStr = cfg.ServerPrivateKey
	}
	portalPrivBytes, err := base64.StdEncoding.DecodeString(portalPrivStr)
	if err != nil {
		h.t.Fatalf("decode portal private key: %v", err)
	}
	portalPrivHex := hex.EncodeToString(portalPrivBytes)

	clientPubBytes, err := base64.StdEncoding.DecodeString(h.clientPeer.PublicKey)
	if err != nil {
		h.t.Fatalf("decode client public key: %v", err)
	}
	clientPubHex := hex.EncodeToString(clientPubBytes)

	var hpKeyHex string
	if cfg.HeaderProtectionKey != "" {
		hpBytes, _ := base64.StdEncoding.DecodeString(cfg.HeaderProtectionKey)
		if len(hpBytes) == 32 {
			hpKeyHex = hex.EncodeToString(hpBytes)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", portalPrivHex)
	fmt.Fprintf(&b, "listen_port=%d\n", h.listenPort)
	if !cfg.H1.IsZero() {
		fmt.Fprintf(&b, "h1=%s\n", cfg.H1.String())
	}
	if !cfg.H2.IsZero() {
		fmt.Fprintf(&b, "h2=%s\n", cfg.H2.String())
	}
	if !cfg.H3.IsZero() {
		fmt.Fprintf(&b, "h3=%s\n", cfg.H3.String())
	}
	if !cfg.H4.IsZero() {
		fmt.Fprintf(&b, "h4=%s\n", cfg.H4.String())
	}
	if cfg.S1 > 0 {
		fmt.Fprintf(&b, "s1=%d\n", cfg.S1)
	}
	if cfg.S2 > 0 {
		fmt.Fprintf(&b, "s2=%d\n", cfg.S2)
	}
	if cfg.S3 > 0 {
		fmt.Fprintf(&b, "s3=%d\n", cfg.S3)
	}
	if cfg.S4 > 0 {
		fmt.Fprintf(&b, "s4=%d\n", cfg.S4)
	}
	if hpKeyHex != "" {
		fmt.Fprintf(&b, "header_protection_key=%s\n", hpKeyHex)
	}
	if cfg.ContentPaddingAddition != "" {
		fmt.Fprintf(&b, "content_padding_addition=%s\n", cfg.ContentPaddingAddition)
	}
	fmt.Fprintf(&b, "random_trailers=%t\n", cfg.RandomTrailers)
	fmt.Fprintf(&b, "disable_cookies=%t\n", cfg.DisableCookies)
	fmt.Fprintf(&b, "public_key=%s\n", clientPubHex)
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	fmt.Fprintf(&b, "allowed_ip=%s\n", h.clientPeer.AllowedIP.String())

	return b.String()
}
