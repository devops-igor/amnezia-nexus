package endpoint

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	randv2 "math/rand/v2"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/chacha20poly1305"
)

// PacketDevice abstracts physical Linux TUN devices and in-memory test devices.
type PacketDevice interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
	Name() string
	MTU() int
}

// ChannelPacketDevice is an in-memory PacketDevice implementation using Go channels.
type ChannelPacketDevice struct {
	name   string
	mtu    int
	in     chan []byte
	out    chan []byte
	closed atomic.Bool
	stopCh chan struct{}
}

// NewChannelPacketDevice creates a new in-memory channel packet device.
func NewChannelPacketDevice(name string, mtu int, bufSize int) *ChannelPacketDevice {
	if mtu <= 0 {
		mtu = 1420
	}
	if bufSize <= 0 {
		bufSize = 256
	}
	return &ChannelPacketDevice{
		name:   name,
		mtu:    mtu,
		in:     make(chan []byte, bufSize),
		out:    make(chan []byte, bufSize),
		stopCh: make(chan struct{}),
	}
}

func (c *ChannelPacketDevice) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, errors.New("device closed")
	}
	select {
	case <-c.stopCh:
		return 0, errors.New("device closed")
	case pkt, ok := <-c.in:
		if !ok {
			return 0, errors.New("device closed")
		}
		n := copy(p, pkt)
		return n, nil
	}
}

func (c *ChannelPacketDevice) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, errors.New("device closed")
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case <-c.stopCh:
		return 0, errors.New("device closed")
	case c.out <- buf:
		return len(p), nil
	default:
		return 0, errors.New("channel buffer full")
	}
}

func (c *ChannelPacketDevice) InjectPacket(p []byte) error {
	if c.closed.Load() {
		return errors.New("device closed")
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.in <- buf:
		return nil
	default:
		return errors.New("inbound queue full")
	}
}

func (c *ChannelPacketDevice) ReceivePacket() ([]byte, error) {
	if c.closed.Load() {
		return nil, errors.New("device closed")
	}
	select {
	case pkt, ok := <-c.out:
		if !ok {
			return nil, errors.New("device closed")
		}
		return pkt, nil
	case <-c.stopCh:
		return nil, errors.New("device closed")
	}
}

func (c *ChannelPacketDevice) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.stopCh)
	}
	return nil
}

func (c *ChannelPacketDevice) Name() string { return c.name }
func (c *ChannelPacketDevice) MTU() int     { return c.mtu }

// ListenerConfig defines settings for the AWG endpoint listener.
type ListenerConfig struct {
	ListenPort  int
	SubnetCIDR  string
	MTU         int
	PrivateKey  string
	PublicKey   string
	IdleTimeout time.Duration
	// RejectAfterTime is the cryptographic validity lifetime of a transport keypair (default 180s).
	RejectAfterTime time.Duration
	// HeaderProtectionKey is the AWG 3.x header protection key (hex or base64).
	HeaderProtectionKey string
	// H1 is the AWG handshake initiation message type range; zero/empty selects
	// health.DefaultH1. Must match the AWG client parameters (JunkPacket
	// message type) distributed to registered peers.
	H1 models.HeaderRange
	// S1 is the junk prefix length before the initiation payload; 0 selects
	// health.DefaultS1.
	S1 int
	// H2 is the AWG handshake response message type range; zero/empty selects
	// health.DefaultH2.
	H2 models.HeaderRange
	// S2 is the junk prefix length before the response payload; 0 selects
	// health.DefaultS2.
	S2 int
	// H3 is the AWG underload / cookie reply message type range; zero/empty selects
	// health.DefaultH3.
	H3 models.HeaderRange
	// S3 is the junk prefix length for cookie reply packets; 0 selects
	// health.DefaultS3.
	S3 int
	// H4 is the AWG transport-data message type range; zero/empty selects
	// health.DefaultH4.
	H4 models.HeaderRange
	// S4 is the junk padding length before the transport encrypted payload; 0 selects
	// health.DefaultS4.
	S4 int
	// NumWorkers is the number of worker goroutines for datagram processing (issue #160).
	// If <= 0, defaults to runtime.NumCPU() (minimum 4).
	NumWorkers int
	// WorkerQueueSize is the capacity of the inbound packet dispatch queue (issue #160).
	// If <= 0, defaults to 2048.
	WorkerQueueSize int
	// HeartbeatInterval is the interval between idle-timeout sweeps in heartbeatLoop.
	// If <= 0, defaults to 30 seconds.
	HeartbeatInterval time.Duration
}

// BackendSelector resolves the backend tunnel a newly authenticated peer's
// session should be pinned to. It is the listener's integration point for
// load-balancer-aware backend selection (sticky sessions / least-connections
// / weighted round-robin); when unset the listener falls back to the static
// DB lookup keyed by the peer's connection server ID.
// IncomingPeerHandler handles the handshake accept path.
type IncomingPeerHandler func(ctx context.Context, peerPublicKey string) (*models.VPNSession, *models.BackendTunnel, error)

// ClientPacketRouter routes a decrypted client→backend transport packet for
// a peer (the VPN service wires it to forwarder.RouteClientToBackend).
type ClientPacketRouter func(peerKey string, packet []byte) error

// activePeerState tracks a peer's most recent UDP endpoint so late transport
// datagrams and server→client sends can find the right socket address.
type activePeerState struct {
	peerKey         string
	udpAddr         *net.UDPAddr // cached pre-parsed UDP endpoint (avoids per-packet string resolution, issue #151)
	receiverIdx     atomic.Uint32
	lastSeen        atomic.Int64 // unix nanos
	lastTouchSec    atomic.Int64 // unix seconds (issue #294: throttles TouchSession calls)
	decryptLogUntil atomic.Int64 // unix seconds (issue #148 rate limiting)
}

// packetJob holds an inbound UDP datagram dispatched from the read loop to the worker pool (issue #160).
type packetJob struct {
	data   []byte
	sender *net.UDPAddr
}

// peerKeypairs tracks the active and previous transport keypair generations for a peer (Issue #295).
type peerKeypairs struct {
	peerKey        string
	nextGeneration uint64
	current        *TransportKeys
	previous       *TransportKeys
	prevLogUntil   atomic.Int64
}

// keypairEntry maps a local receiver index to its owning peer and transport keyset.
type keypairEntry struct {
	peerKey string
	keys    *TransportKeys
}

// Listener manages the AWG endpoint UDP listener and peer lifecycle.
type Listener struct {
	mu                  sync.RWMutex
	config              ListenerConfig
	hpKey               []byte
	db                  *database.DB
	auth                Authenticator
	ipam                *IPAM
	sessionMgr          *SessionManager
	serverKeys          *ServerKeysManager
	serverPriv          []byte
	noiseKeys           map[string]*TransportKeys
	peerKeypairs        map[string]*peerKeypairs
	indexTable          map[uint32]*keypairEntry
	rejectAfterTime     time.Duration
	peersByAddr         map[string]*activePeerState // sender UDP addr string -> peer state
	peerGenerations     map[string]uint64           // peerKey -> highest committed generation
	udpConn             *net.UDPConn
	tunDev              PacketDevice
	packetQueue         chan packetJob
	packetQueueDrops    atomic.Uint64
	running             bool
	draining            bool
	stopCh              chan struct{}
	wg                  sync.WaitGroup
	rxBytes             atomic.Int64
	txBytes             atomic.Int64
	incomingPeerHandler IncomingPeerHandler

	router ClientPacketRouter
	// reaperHook runs on the heartbeat goroutine for each idle-timed-out
	// session (see SessionReaperHook); guarded by mu, set before Start.
	reaperHook SessionReaperHook
	// postSweepHook runs on the heartbeat goroutine after each idle-timeout sweep cycle; guarded by mu.
	postSweepHook func(ctx context.Context)

	// rejectLogUntil throttles handshake-rejection log lines (log-flood
	// defense against a garbage-packet source that fails MAC1): at most one
	// rejection log per second. Read/written only by the single read-loop
	// goroutine.
	rejectLogUntil atomic.Int64

	// handshakeRejects counts inbound datagrams that were genuine handshake
	// initiations but failed cryptographic verification (e.g., MAC1 failure,
	// static key / timestamp decryption failure, or stale timestamp).
	// Unroutable transport data and non-initiation datagrams are excluded (issue #288).
	handshakeRejects atomic.Uint64
	// transportDecryptFailures counts established-peer transport datagrams that
	// failed AEAD decryption; these are distinct from handshake rejections.
	transportDecryptFailures atomic.Uint64
	// staleHandshakes counts handshake completions dropped by the commit fence
	// because a newer handshake for the same peer already completed.
	staleHandshakes atomic.Uint64
	// staleResponseDrops counts handshake responses suppressed at the per-peer send
	// gate because a newer generation committed before response transmission.
	staleResponseDrops atomic.Uint64

	peerSendLocksMu sync.Mutex
	peerSendLocks   map[string]*sync.Mutex

	postCommitHook func(peerKey string, gen uint64)

	// preTransportCommitHook runs in handleDatagram after response and transport keys
	// are built, but before transport state is committed; used for deterministic testing.
	preTransportCommitHook func(peerKey string, sessID string)

	// preSweepPruneHook runs in SweepTimedOutSessions after a timed-out session is found
	// but before PrunePeerTransportStateForGeneration executes; used for deterministic testing.
	preSweepPruneHook func(peerKey string, timedOutGen uint64)
}

// applyListenerConfigDefaults applies fallback defaults to zero-valued config fields.
func applyListenerConfigDefaults(cfg *ListenerConfig) {
	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = "10.100.0.0/16"
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1420
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 3 * time.Minute
	}
	if cfg.RejectAfterTime <= 0 {
		cfg.RejectAfterTime = device.RejectAfterTime
	}
	if cfg.H1.IsZero() {
		cfg.H1 = models.DegenerateHeaderRange(health.DefaultH1)
	}
	if cfg.S1 == 0 {
		cfg.S1 = health.DefaultS1
	}
	if cfg.H2.IsZero() {
		cfg.H2 = models.DegenerateHeaderRange(health.DefaultH2)
	}
	if cfg.S2 == 0 {
		cfg.S2 = health.DefaultS2
	}
	if cfg.H3.IsZero() {
		cfg.H3 = models.DegenerateHeaderRange(health.DefaultH3)
	}
	if cfg.S3 == 0 {
		cfg.S3 = health.DefaultS3
	}
	if cfg.H4.IsZero() {
		cfg.H4 = models.DegenerateHeaderRange(health.DefaultH4)
	}
	if cfg.S4 == 0 {
		cfg.S4 = health.DefaultS4
	}
	if cfg.NumWorkers <= 0 {
		cfg.NumWorkers = runtime.NumCPU()
		if cfg.NumWorkers < 4 {
			cfg.NumWorkers = 4
		}
	}
	if cfg.WorkerQueueSize <= 0 {
		cfg.WorkerQueueSize = 2048
	}
}

// NewListener initializes a new AWG endpoint listener. serverKeys provides the
// endpoint's persistent Noise server keypair (see ServerKeysManager); when nil
// one is created from db (ephemeral when db is also nil).
func NewListener(cfg ListenerConfig, db *database.DB, auth Authenticator, ipam *IPAM, sessionMgr *SessionManager, serverKeys *ServerKeysManager) (*Listener, error) {
	applyListenerConfigDefaults(&cfg)

	if auth == nil && db != nil {
		auth = NewDBAuthenticator(db)
	}

	if serverKeys == nil {
		serverKeys = NewServerKeysManager(db)
	}

	if ipam == nil {
		var err error
		ipam, err = NewIPAM(cfg.SubnetCIDR)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize IPAM: %w", err)
		}
	}

	if sessionMgr == nil {
		sessionMgr = NewSessionManager(db, ipam)
	}

	if cfg.HeaderProtectionKey != "" {
		for i, s := range []*int{&cfg.S1, &cfg.S2, &cfg.S3, &cfg.S4} {
			if *s < health.HeaderCipherNonceSize {
				// Mirrors upstream uapi.go:852-857: header protection is
				// unusable with S<N below the cipher nonce size: HP clients
				// would be silently rejected with no distinguishing log.
				return nil, fmt.Errorf("S%d must be >= %d to use headerProtection", i+1, health.HeaderCipherNonceSize)
			}
		}
	}

	var hpKeyBytes []byte
	if cfg.HeaderProtectionKey != "" {
		var err error
		hpKeyBytes, err = health.DecodeKey(cfg.HeaderProtectionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode header protection key: %w", err)
		}
	}

	rejectAfterTime := cfg.RejectAfterTime
	if rejectAfterTime <= 0 {
		rejectAfterTime = device.RejectAfterTime
	}

	return &Listener{
		config:          cfg,
		hpKey:           hpKeyBytes,
		db:              db,
		auth:            auth,
		ipam:            ipam,
		sessionMgr:      sessionMgr,
		serverKeys:      serverKeys,
		noiseKeys:       make(map[string]*TransportKeys),
		peerKeypairs:    make(map[string]*peerKeypairs),
		indexTable:      make(map[uint32]*keypairEntry),
		rejectAfterTime: rejectAfterTime,
		peersByAddr:     make(map[string]*activePeerState),
		peerGenerations: make(map[string]uint64),
		peerSendLocks:   make(map[string]*sync.Mutex),
		tunDev:          NewChannelPacketDevice("awg0", cfg.MTU, 512),
		stopCh:          make(chan struct{}),
	}, nil
}

// SetIncomingPeerHandler registers the handler for incoming peer handshakes.
func (el *Listener) SetIncomingPeerHandler(fn IncomingPeerHandler) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.incomingPeerHandler = fn
}

// SetClientPacketRouter installs the router used to forward decrypted
// client→backend transport packets (nil drops them instead).
func (el *Listener) SetClientPacketRouter(fn ClientPacketRouter) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.router = fn
}

// SetPacketDevice overrides the default packet device (e.g. Linux TUN interface).
func (el *Listener) SetPacketDevice(dev PacketDevice) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.tunDev = dev
}

// UpdateObfuscation swaps the AWG obfuscation parameters (H1..H4, S1..S4)
// in the listener configuration. Callers must only invoke it while the
// listener is stopped: the UDP read, handshake, and transport paths read
// config fields without holding mu, so mutating a running listener would
// race with packet processing. The VPN service enforces that contract by
// propagating parameter changes to idle listeners and rejecting them while
// the listener runs.
func (el *Listener) UpdateObfuscation(h1, h2, h3, h4 any, s1, s2, s3, s4 int) error {
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.running {
		return errors.New("cannot update obfuscation parameters while listener is running")
	}

	hr1, err := models.ParseHeaderRange(h1)
	if err != nil {
		return fmt.Errorf("invalid H1: %w", err)
	}
	hr2, err := models.ParseHeaderRange(h2)
	if err != nil {
		return fmt.Errorf("invalid H2: %w", err)
	}
	hr3, err := models.ParseHeaderRange(h3)
	if err != nil {
		return fmt.Errorf("invalid H3: %w", err)
	}
	hr4, err := models.ParseHeaderRange(h4)
	if err != nil {
		return fmt.Errorf("invalid H4: %w", err)
	}

	if hr1.IsZero() {
		hr1 = models.DegenerateHeaderRange(health.DefaultH1)
	}
	if hr2.IsZero() {
		hr2 = models.DegenerateHeaderRange(health.DefaultH2)
	}
	if hr3.IsZero() {
		hr3 = models.DegenerateHeaderRange(health.DefaultH3)
	}
	if hr4.IsZero() {
		hr4 = models.DegenerateHeaderRange(health.DefaultH4)
	}

	// Clamp S values to at least 12 when HP is active
	if len(el.hpKey) == 32 {
		if s1 < health.HeaderCipherNonceSize {
			s1 = health.HeaderCipherNonceSize
		}
		if s2 < health.HeaderCipherNonceSize {
			s2 = health.HeaderCipherNonceSize
		}
		if s3 < health.HeaderCipherNonceSize {
			s3 = health.HeaderCipherNonceSize
		}
		if s4 < health.HeaderCipherNonceSize {
			s4 = health.HeaderCipherNonceSize
		}
	}

	el.config.H1 = hr1
	el.config.H2 = hr2
	el.config.H3 = hr3
	el.config.H4 = hr4
	el.config.S1 = s1
	el.config.S2 = s2
	el.config.S3 = s3
	el.config.S4 = s4
	return nil
}

// UpdateHeaderProtectionKey updates the AWG header protection key in the
// listener configuration. Callers must only invoke it while the listener is stopped.
func (el *Listener) UpdateHeaderProtectionKey(hpKey string) error {
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.running {
		return errors.New("cannot update header protection key while listener is running")
	}
	el.config.HeaderProtectionKey = hpKey
	if hpKey == "" {
		el.hpKey = nil
		return nil
	}
	keyBytes, err := health.DecodeKey(hpKey)
	if err != nil {
		return fmt.Errorf("failed to decode header protection key: %w", err)
	}
	el.hpKey = keyBytes
	// Clamp S values to at least 12 when HP is active
	if el.config.S1 < health.HeaderCipherNonceSize {
		el.config.S1 = health.HeaderCipherNonceSize
	}
	if el.config.S2 < health.HeaderCipherNonceSize {
		el.config.S2 = health.HeaderCipherNonceSize
	}
	if el.config.S3 < health.HeaderCipherNonceSize {
		el.config.S3 = health.HeaderCipherNonceSize
	}
	if el.config.S4 < health.HeaderCipherNonceSize {
		el.config.S4 = health.HeaderCipherNonceSize
	}
	return nil
}

func (el *Listener) headerProtectionKey() []byte {
	el.mu.RLock()
	defer el.mu.RUnlock()
	return el.hpKey
}

// UpdateListenPort sets the UDP port the listener will bind at its next
// Start. Callers must only invoke it while the listener is stopped - a
// running listener is already bound to its current port, and Start
// (like UpdateObfuscation) refuses to run twice - so the VPN service
// propagates port changes only to idle listeners and rejects them while
// the listener runs.
func (el *Listener) UpdateListenPort(port int) {
	el.mu.Lock()
	defer el.mu.Unlock()
	if port <= 0 {
		return
	}
	el.config.ListenPort = port
}

// ListenerConfigSnapshot returns a copy of the current listener
// configuration so callers (and tests) can verify the listener agrees
// with the persisted VPN configuration.
func (el *Listener) ListenerConfigSnapshot() ListenerConfig {
	el.mu.RLock()
	defer el.mu.RUnlock()
	return el.config
}

// DefaultUDPSocketBufferSize is the default SO_RCVBUF and SO_SNDBUF buffer size (4 MB)
// configured on the endpoint listener's UDP socket to prevent kernel-level packet drops
// and socket backpressure during downstream traffic bursts (issue #151).
const DefaultUDPSocketBufferSize = 4 * 1024 * 1024

// Start binds the UDP port and starts the background loops.
func (el *Listener) Start(ctx context.Context) error {
	el.mu.Lock()
	if el.running {
		el.mu.Unlock()
		return errors.New("endpoint listener is already running")
	}

	addr := &net.UDPAddr{Port: el.config.ListenPort}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		el.mu.Unlock()
		return fmt.Errorf("failed to bind UDP port %d: %w", el.config.ListenPort, err)
	}

	if err := conn.SetReadBuffer(DefaultUDPSocketBufferSize); err != nil {
		log.Printf("[vpn/endpoint] warning: failed to set SO_RCVBUF to %d: %v", DefaultUDPSocketBufferSize, err)
	}
	if err := conn.SetWriteBuffer(DefaultUDPSocketBufferSize); err != nil {
		log.Printf("[vpn/endpoint] warning: failed to set SO_SNDBUF to %d: %v", DefaultUDPSocketBufferSize, err)
	}

	el.udpConn = conn
	if el.tunDev == nil {
		el.tunDev = NewChannelPacketDevice("awg0", el.config.MTU, 512)
	} else if chDev, ok := el.tunDev.(*ChannelPacketDevice); ok && chDev.closed.Load() {
		el.tunDev = NewChannelPacketDevice(chDev.Name(), chDev.MTU(), 512)
	}
	el.running = true
	el.draining = false
	el.stopCh = make(chan struct{})

	numWorkers := el.config.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
		if numWorkers < 4 {
			numWorkers = 4
		}
	}
	queueSize := el.config.WorkerQueueSize
	if queueSize <= 0 {
		queueSize = 2048
	}
	el.packetQueue = make(chan packetJob, queueSize)
	el.mu.Unlock()

	el.wg.Add(2 + numWorkers)
	go el.udpReadLoop(ctx)
	go el.heartbeatLoop(ctx)
	for i := 0; i < numWorkers; i++ {
		go el.workerLoop(ctx)
	}

	return nil
}

// Stop gracefully stops the UDP listener and worker loops.
func (el *Listener) Stop() error {
	el.mu.Lock()
	if !el.running {
		el.mu.Unlock()
		return nil
	}
	el.running = false
	close(el.stopCh)
	if el.udpConn != nil {
		_ = el.udpConn.Close()
	}
	if el.tunDev != nil {
		_ = el.tunDev.Close()
	}
	el.mu.Unlock()

	el.wg.Wait()
	return nil
}

// Drain marks listener as draining and prepares active sessions for graceful disconnection.
func (el *Listener) Drain(ctx context.Context, timeout time.Duration) error {
	el.mu.Lock()
	el.draining = true
	el.mu.Unlock()

	if el.sessionMgr != nil {
		return el.sessionMgr.Drain(ctx, timeout)
	}
	return nil
}

// AuthenticateAndRegisterPeer authenticates peer credentials, leases an internal IP, and creates an active session.
func (el *Listener) AuthenticateAndRegisterPeer(ctx context.Context, peerPublicKey string, backendTunnelID int64) (*models.VPNSession, error) {
	el.mu.RLock()
	if el.draining {
		el.mu.RUnlock()
		return nil, errors.New("listener is draining: new connections rejected")
	}
	auth := el.auth
	ipam := el.ipam
	sm := el.sessionMgr
	el.mu.RUnlock()

	if auth == nil || ipam == nil || sm == nil {
		return nil, errors.New("endpoint listener subsystem not initialized")
	}

	user, conn, err := auth.AuthenticatePeer(ctx, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("peer authentication failed: %w", err)
	}

	assignedIP, err := ipam.Allocate(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ip allocation failed: %w", err)
	}

	el.mu.Lock()
	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}
	el.peerGenerations[peerPublicKey]++
	peerGen := el.peerGenerations[peerPublicKey]
	el.mu.Unlock()

	sess, err := sm.CreateSession(ctx, user.ID, peerPublicKey, assignedIP.String(), backendTunnelID, conn.Name, peerGen)
	if err != nil {
		_ = ipam.Release(peerPublicKey)
		return nil, fmt.Errorf("session creation failed: %w", err)
	}

	return sess, nil
}

// peerSendLock returns the dedicated send mutex for serializing handshake responses per peer.
func (el *Listener) peerSendLock(peerKey string) *sync.Mutex {
	el.peerSendLocksMu.Lock()
	defer el.peerSendLocksMu.Unlock()
	if el.peerSendLocks == nil {
		el.peerSendLocks = make(map[string]*sync.Mutex)
	}
	mu, ok := el.peerSendLocks[peerKey]
	if !ok {
		mu = &sync.Mutex{}
		el.peerSendLocks[peerKey] = mu
	}
	return mu
}

// DisconnectPeer disconnects a peer and closes their session.
func (el *Listener) DisconnectPeer(ctx context.Context, peerPublicKey string) error {
	el.mu.RLock()
	sm := el.sessionMgr
	el.mu.RUnlock()

	if sm == nil {
		return nil
	}

	sess, ok := sm.GetSession(peerPublicKey)
	if !ok {
		return ErrPeerNotFound
	}

	err := sm.CloseSession(ctx, sess.ID, "disconnected")

	el.mu.Lock()
	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}
	fenceGen := sess.Generation + 1
	if fenceGen <= el.peerGenerations[peerPublicKey] {
		fenceGen = el.peerGenerations[peerPublicKey] + 1
	}
	el.peerGenerations[peerPublicKey] = fenceGen
	el.mu.Unlock()

	el.PrunePeerTransportState(peerPublicKey, fenceGen)
	return err
}

// DisconnectSession disconnects a specific session by ID and prunes its transport state.
func (el *Listener) DisconnectSession(ctx context.Context, sessionID string) error {
	el.mu.RLock()
	sm := el.sessionMgr
	el.mu.RUnlock()

	if sm == nil {
		return nil
	}

	sess, ok := sm.GetSessionByID(sessionID)
	if !ok {
		return ErrSessionNotFound
	}

	err := sm.CloseSession(ctx, sessionID, "disconnected")

	el.mu.Lock()
	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}
	fenceGen := sess.Generation + 1
	if fenceGen <= el.peerGenerations[sess.PeerPublicKey] {
		fenceGen = el.peerGenerations[sess.PeerPublicKey] + 1
	}
	el.peerGenerations[sess.PeerPublicKey] = fenceGen
	el.mu.Unlock()

	el.PrunePeerTransportState(sess.PeerPublicKey, fenceGen)
	return err
}

// GetListenAddr returns the bound UDP address or nil.
func (el *Listener) GetListenAddr() net.Addr {
	el.mu.RLock()
	defer el.mu.RUnlock()
	if el.udpConn != nil {
		return el.udpConn.LocalAddr()
	}
	return nil
}

// IsRunning returns true if the endpoint listener is active.
func (el *Listener) IsRunning() bool {
	el.mu.RLock()
	defer el.mu.RUnlock()
	return el.running
}

// IsDraining returns true if the listener is in draining mode.
func (el *Listener) IsDraining() bool {
	el.mu.RLock()
	defer el.mu.RUnlock()
	return el.draining
}

// HandshakeRejections returns the number of inbound datagrams failing
// cryptographic handshake initiation verification (MAC1 failure, static key /
// timestamp decryption failure, or stale timestamp). Unroutable transport data
// and non-initiation datagrams are excluded (issues #39, #288, #290). Nil
// receiver is safe and returns 0.
func (el *Listener) HandshakeRejections() uint64 {
	if el == nil {
		return 0
	}
	return el.handshakeRejects.Load()
}

// TransportDecryptionFailures returns established-peer transport datagrams
// dropped after AEAD decryption failed. It excludes handshake rejections.
func (el *Listener) TransportDecryptionFailures() uint64 {
	if el == nil {
		return 0
	}
	return el.transportDecryptFailures.Load()
}

// PacketQueueDrops returns the number of inbound datagrams dropped due to a full
// worker dispatch queue. Nil receiver is safe and returns 0 (issue #160).
func (el *Listener) PacketQueueDrops() uint64 {
	if el == nil {
		return 0
	}
	return el.packetQueueDrops.Load()
}

// StaleHandshakeDrops returns the number of handshake completions dropped
// by the monotonic generation commit fence because a newer handshake for the
// same peer had already completed. Nil receiver is safe and returns 0.
func (el *Listener) StaleHandshakeDrops() uint64 {
	if el == nil {
		return 0
	}
	return el.staleHandshakes.Load()
}

// StaleResponseDrops returns the number of handshake responses suppressed at the
// per-peer send gate because a newer generation committed before response transmission.
// Nil receiver is safe and returns 0.
func (el *Listener) StaleResponseDrops() uint64 {
	if el == nil {
		return 0
	}
	return el.staleResponseDrops.Load()
}

// SetPostCommitHookForTest sets a hook invoked immediately after CommitHandshake commits
// before entering the per-peer send gate.
func (el *Listener) SetPostCommitHookForTest(fn func(peerKey string, gen uint64)) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.postCommitHook = fn
}

// PeerGeneration returns the highest committed generation for a peer under el.mu.
func (el *Listener) PeerGeneration(peerKey string) uint64 {
	el.mu.RLock()
	defer el.mu.RUnlock()
	if el.peerGenerations == nil {
		return 0
	}
	return el.peerGenerations[peerKey]
}

// PeerEndpoint returns the most recently seen UDP endpoint for a peer.
func (el *Listener) PeerEndpoint(peerKey string) *net.UDPAddr {
	el.mu.RLock()
	defer el.mu.RUnlock()
	var newest int64 = -1
	var ep *net.UDPAddr
	for _, cand := range el.peersByAddr {
		if cand.peerKey != peerKey {
			continue
		}
		if ls := cand.lastSeen.Load(); ls > newest {
			newest = ls
			ep = cand.udpAddr
		}
	}
	return ep
}

// HandleDatagramForTest processes a single datagram through the handshake/transport
// pipeline synchronously for testing.
func (el *Listener) HandleDatagramForTest(ctx context.Context, datagram []byte, sender *net.UDPAddr) {
	el.handleDatagram(ctx, datagram, sender)
}

// WorkerPoolStats returns the configured worker count, current queue length,
// and queue capacity (issue #160).
func (el *Listener) WorkerPoolStats() (workers int, queueLen int, queueCap int) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	workers = el.config.NumWorkers
	queueCap = el.config.WorkerQueueSize
	if el.packetQueue != nil {
		queueLen = len(el.packetQueue)
		queueCap = cap(el.packetQueue)
	}
	return
}

// GetStats returns current traffic bytes and active session counts.
func (el *Listener) GetStats() (rx int64, tx int64, active int) {
	rx = el.rxBytes.Load()
	tx = el.txBytes.Load()
	if el.sessionMgr != nil {
		active = el.sessionMgr.ActiveCount()
	}
	return
}

// RecordTraffic records raw packet ingress/egress bytes.
func (el *Listener) RecordTraffic(rx, tx int64) {
	if rx > 0 {
		el.rxBytes.Add(rx)
	}
	if tx > 0 {
		el.txBytes.Add(tx)
	}
}

// SessionManager returns the underlying session manager.
func (el *Listener) SessionManager() *SessionManager {
	return el.sessionMgr
}

// IPAM returns the underlying IP address manager.
func (el *Listener) IPAM() *IPAM {
	return el.ipam
}

// TransportKeysFor returns the Noise transport keys derived for a peer's most
// recent successful handshake, if any. Data-plane forwarding (Batch 2) uses
// these keys to decrypt/encrypt transport data.
func (el *Listener) TransportKeysFor(peerKey string) (*TransportKeys, bool) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	keys, ok := el.noiseKeys[peerKey]
	return keys, ok
}

func (el *Listener) getRejectAfterTime() time.Duration {
	if el.rejectAfterTime > 0 {
		return el.rejectAfterTime
	}
	if el.config.RejectAfterTime > 0 {
		return el.config.RejectAfterTime
	}
	return device.RejectAfterTime
}

// storeTransportKeys records the transport keys derived for a peer's active
// handshake, rotating any previous current keys to previous and registering the
// keypair in indexTable.
func (el *Listener) storeTransportKeys(peerKey string, keys *TransportKeys, sessionIDs ...string) {
	if keys != nil {
		_ = keys.InitCiphers()
	}
	el.mu.Lock()
	defer el.mu.Unlock()
	el.storeTransportKeysLocked(peerKey, keys)
}

func (el *Listener) storeTransportKeysLocked(peerKey string, newKeys *TransportKeys) {
	if el.noiseKeys == nil {
		el.noiseKeys = make(map[string]*TransportKeys)
	}
	if el.peerKeypairs == nil {
		el.peerKeypairs = make(map[string]*peerKeypairs)
	}
	if el.indexTable == nil {
		el.indexTable = make(map[uint32]*keypairEntry)
	}

	if newKeys == nil {
		el.noiseKeys[peerKey] = nil
		return
	}

	pkp, ok := el.peerKeypairs[peerKey]
	if !ok {
		pkp = &peerKeypairs{
			peerKey: peerKey,
		}
		el.peerKeypairs[peerKey] = pkp
	}
	if pkp.nextGeneration == 0 {
		pkp.nextGeneration = 1
	}

	if newKeys.Generation == 0 {
		newKeys.Generation = pkp.nextGeneration
		pkp.nextGeneration++
	}

	if newKeys.CreatedAt.IsZero() {
		newKeys.CreatedAt = time.Now()
	}
	if newKeys.ExpiresAt.IsZero() {
		newKeys.ExpiresAt = newKeys.CreatedAt.Add(el.getRejectAfterTime())
	}

	if pkp.previous != nil && pkp.previous.LocalIndex != 0 {
		delete(el.indexTable, pkp.previous.LocalIndex)
	}
	if pkp.current != nil {
		pkp.previous = pkp.current
	}
	pkp.current = newKeys

	if newKeys.LocalIndex != 0 {
		el.indexTable[newKeys.LocalIndex] = &keypairEntry{
			peerKey: peerKey,
			keys:    newKeys,
		}
	}
	el.noiseKeys[peerKey] = newKeys

	log.Printf("[vpn/endpoint] stored transport keys for peer %s: gen=%d local_idx=%d remote_idx=%d expires_in=%s",
		peerKey, newKeys.Generation, newKeys.LocalIndex, newKeys.RemoteIndex, time.Until(newKeys.ExpiresAt).Round(time.Second))
}

// allocateReceiverIndex generates an unused, non-zero 32-bit receiver index that
// does not collide with any active keypair entry in el.indexTable, and reserves
// the slot in indexTable to avoid races between concurrent handshakes.
func (el *Listener) allocateReceiverIndex(peerKey string) uint32 {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.indexTable == nil {
		el.indexTable = make(map[uint32]*keypairEntry)
	}

	var idxBuf [4]byte
	for {
		if _, err := rand.Read(idxBuf[:]); err != nil {
			// #nosec G404 -- fallback in rare crypto/rand failure
			val := randv2.Uint32()
			binary.LittleEndian.PutUint32(idxBuf[:], val)
		}
		idx := binary.LittleEndian.Uint32(idxBuf[:])
		if idx == 0 {
			continue
		}
		if _, exists := el.indexTable[idx]; !exists {
			el.indexTable[idx] = &keypairEntry{peerKey: peerKey, keys: nil}
			return idx
		}
	}
}

// releaseReceiverIndex frees a reserved indexTable slot if keys were never committed.
func (el *Listener) releaseReceiverIndex(idx uint32) {
	if idx == 0 {
		return
	}
	el.mu.Lock()
	defer el.mu.Unlock()
	el.releaseReceiverIndexLocked(idx)
}

func (el *Listener) releaseReceiverIndexLocked(idx uint32) {
	if idx == 0 {
		return
	}
	if entry, ok := el.indexTable[idx]; ok && entry.keys == nil {
		delete(el.indexTable, idx)
	}
}

func (el *Listener) lookupKeypairByIndex(receiverIdx uint32) (*keypairEntry, bool) {
	if receiverIdx == 0 {
		return nil, false
	}
	el.mu.RLock()
	defer el.mu.RUnlock()
	entry, ok := el.indexTable[receiverIdx]
	return entry, ok
}

// PeerKeypairsForTest returns the current and previous transport keys for a peer.
func (el *Listener) PeerKeypairsForTest(peerKey string) (current *TransportKeys, previous *TransportKeys) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	if pkp, ok := el.peerKeypairs[peerKey]; ok {
		return pkp.current, pkp.previous
	}
	return nil, nil
}

// IndexTableCountForTest returns the number of entries in indexTable.
func (el *Listener) IndexTableCountForTest() int {
	el.mu.RLock()
	defer el.mu.RUnlock()
	return len(el.indexTable)
}

func (el *Listener) keypairStatus(peerKey string, keys *TransportKeys) string {
	if keys == nil {
		return "unknown"
	}
	if keys.IsExpired() {
		return "expired"
	}
	el.mu.RLock()
	defer el.mu.RUnlock()
	if pkp, ok := el.peerKeypairs[peerKey]; ok {
		if pkp.previous == keys {
			return "previous"
		}
		if pkp.current == keys {
			return "current"
		}
	}
	return "current"
}

// StoreTransportKeysForTest exposes storeTransportKeys for integration tests.
func (el *Listener) StoreTransportKeysForTest(peerKey string, keys *TransportKeys, sessionIDs ...string) {
	el.storeTransportKeys(peerKey, keys)
}

// SetPeerSessionIDForTest is preserved for test compatibility.
func (el *Listener) SetPeerSessionIDForTest(peerKey, sessionID string) {
}

// PeerSessionIDForTest returns the active session ID from sessionMgr if present.
func (el *Listener) PeerSessionIDForTest(peerKey string) string {
	if el.sessionMgr != nil {
		if s, ok := el.sessionMgr.GetSession(peerKey); ok && s != nil {
			return s.ID
		}
	}
	return ""
}

// SetPreTransportCommitHookForTest registers a hook invoked before committing handshake transport state.
func (el *Listener) SetPreTransportCommitHookForTest(fn func(peerKey string, sessID string)) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.preTransportCommitHook = fn
}

// SetPreSweepPruneHookForTest registers a hook invoked in SweepTimedOutSessions
// after discovering a timed-out session, but before invoking PrunePeerTransportStateForGeneration.
func (el *Listener) SetPreSweepPruneHookForTest(fn func(peerKey string, timedOutGen uint64)) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.preSweepPruneHook = fn
}

// CommitHandshakeTransportStateForTest exposes commitHandshakeTransportState for tests.
func (el *Listener) CommitHandshakeTransportStateForTest(peerKey string, sessID string, transportKeys *TransportKeys, allocatedIdx uint32, sender *net.UDPAddr, remoteIdx uint32) bool {
	if el.sessionMgr != nil && sessID != "" {
		active, ok := el.sessionMgr.GetSession(peerKey)
		if !ok || active == nil || active.ID != sessID || active.Status != "connected" {
			el.releaseReceiverIndex(allocatedIdx)
			return false
		}
		return el.CommitHandshake(peerKey, active.Generation, transportKeys, sender, remoteIdx)
	}
	return el.CommitHandshake(peerKey, 0, transportKeys, sender, remoteIdx)
}

// LookupKeypairByIndexForTest returns the transport keys registered for receiverIdx.
func (el *Listener) LookupKeypairByIndexForTest(receiverIdx uint32) (*TransportKeys, bool) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	entry, ok := el.indexTable[receiverIdx]
	if !ok || entry == nil {
		return nil, false
	}
	return entry.keys, true
}

// HasPeerAddrForTest reports whether any peersByAddr mapping exists for peerKey.
func (el *Listener) HasPeerAddrForTest(peerKey string) bool {
	el.mu.RLock()
	defer el.mu.RUnlock()
	for _, st := range el.peersByAddr {
		if st != nil && st.peerKey == peerKey {
			return true
		}
	}
	return false
}

// HasTransportStateForPeer reports whether any transport state (keypairs, noiseKeys,
// indexTable entries, or peersByAddr mappings) currently exists for peerKey.
func (el *Listener) HasTransportStateForPeer(peerKey string) bool {
	el.mu.RLock()
	defer el.mu.RUnlock()

	if pkp, ok := el.peerKeypairs[peerKey]; ok && pkp != nil {
		return true
	}
	if k, ok := el.noiseKeys[peerKey]; ok && k != nil {
		return true
	}
	for _, entry := range el.indexTable {
		if entry != nil && entry.peerKey == peerKey {
			return true
		}
	}
	for _, st := range el.peersByAddr {
		if st != nil && st.peerKey == peerKey {
			return true
		}
	}
	return false
}

// PrunePeerKeypairsForTest removes keypairs for peerKey.
func (el *Listener) PrunePeerKeypairsForTest(peerKey string) {
	el.PrunePeerTransportState(peerKey)
}

// RememberPeerForTest exposes rememberPeer for integration tests.
func (el *Listener) RememberPeerForTest(sender *net.UDPAddr, peerKey string, receiverIdx uint32) {
	el.rememberPeer(sender, peerKey, receiverIdx)
}

// serverPrivateKey resolves the endpoint's persistent Noise server private
// key, loading or creating it via the ServerKeysManager on first use. It
// returns nil when no keypair is available, in which case handshake
// processing is skipped.
func (el *Listener) serverPrivateKey(ctx context.Context) []byte {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.serverPriv != nil {
		return el.serverPriv
	}
	if el.serverKeys == nil {
		return nil
	}
	priv, _, err := el.serverKeys.EnsureKeypair(ctx)
	if err != nil {
		log.Printf("[vpn/endpoint] failed to load server keypair: %v", err)
		return nil
	}
	privCopy := make([]byte, len(priv))
	copy(privCopy, priv[:])
	el.serverPriv = privCopy
	return el.serverPriv
}

// handleDatagram classifies an inbound UDP datagram. Valid AWG handshake
// initiations are authenticated against registered peers (peer identity is
// the base64 client static public key), routed to a backend tunnel (via the
// installed BackendSelector when present, otherwise the static DB lookup
// keyed by the connection's server ID), given a session, and answered with a
// Noise handshake response. Datagrams that fail initiation parsing are
// treated as transport data: when they come from a sender address with a
// recently completed handshake they are decrypted with the stored transport
// keys and handed to the installed ClientPacketRouter; anything else is
// dropped.
func (el *Listener) handleDatagram(ctx context.Context, datagram []byte, sender *net.UDPAddr) {
	if len(datagram) < 4 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	serverPriv := el.serverPrivateKey(ctx)
	if serverPriv == nil {
		return
	}

	info, err := ParseInitiation(serverPriv, datagram, el.config.H1, el.config.S1, el.hpKey)
	if err != nil {
		// Not a valid handshake initiation for this endpoint (or a transport packet
		// whose ciphertext at offset S1 happens to collide with H1, causing MAC1 failure).
		// First, check if this datagram is recognized transport data for an established session.
		if el.handleTransportData(datagram, sender) {
			// The datagram was recognized as transport data (either successfully decrypted
			// and routed, or dropped due to AEAD decrypt failure). It must not be counted
			// as a handshake rejection.
			return
		}

		// The datagram was NOT recognized as transport data for an established session.
		// If ParseInitiation failed because it was not an initiation message (ErrNotInitiation,
		// e.g. unknown sender transport data or foreign noise) or too short (ErrDatagramTooShort),
		// drop it silently without polluting metrics or logging.
		if errors.Is(err, ErrNotInitiation) || errors.Is(err, ErrDatagramTooShort) {
			return
		}

		// The datagram was NOT transport data AND was an initiation message that failed
		// genuine cryptographic verification (e.g. ErrMAC1Failed, ErrDecryptStatic,
		// ErrDecryptTimestamp, ErrTimestampStale). Increment rejection metric and emit throttled log.
		el.handshakeRejects.Add(1)
		now := time.Now().Unix()
		until := el.rejectLogUntil.Load()
		if now >= until && el.rejectLogUntil.CompareAndSwap(until, now+1) {
			log.Printf("[vpn/endpoint] rejected handshake initiation from %s: %v", sender, err)
		}
		return
	}

	if el.IsDraining() {
		log.Printf("[vpn/endpoint] dropping handshake from %s: listener is draining", sender)
		return
	}

	peerKey := base64.StdEncoding.EncodeToString(info.ClientStaticPub)

	el.mu.RLock()
	handler := el.incomingPeerHandler
	el.mu.RUnlock()

	if handler == nil {
		log.Printf("[vpn/endpoint] dropping handshake from %s: no incoming peer handler installed", sender)
		return
	}

	sess, _, err := handler(ctx, peerKey)
	if err != nil {
		log.Printf("[vpn/endpoint] handshake processing failed for peer %s from %s: %v", peerKey, sender, err)
		return
	}

	allocatedIdx := el.allocateReceiverIndex(peerKey)
	resp, transportKeys, err := BuildResponse(serverPriv, info, el.config.H2, el.config.S2, el.hpKey, allocatedIdx)
	if err != nil {
		el.releaseReceiverIndex(allocatedIdx)
		log.Printf("[vpn/endpoint] failed to build handshake response for peer %s: %v", peerKey, err)
		return
	}

	var gen uint64
	var sessID string
	if sess != nil {
		gen = sess.Generation
		sessID = sess.ID
	}

	el.mu.RLock()
	preCommitHook := el.preTransportCommitHook
	el.mu.RUnlock()
	if preCommitHook != nil {
		preCommitHook(peerKey, sessID)
	}

	if !el.CommitHandshake(peerKey, gen, transportKeys, sender, info.SenderIndex) {
		log.Printf("[vpn/endpoint] dropping stale handshake completion for peer %s (gen %d < current %d)", peerKey, gen, el.PeerGeneration(peerKey))
		return
	}

	el.mu.RLock()
	hook := el.postCommitHook
	el.mu.RUnlock()
	if hook != nil {
		hook(peerKey, gen)
	}

	// Per-peer send gate:
	sendMu := el.peerSendLock(peerKey)
	sendMu.Lock()
	defer sendMu.Unlock()

	if gen < el.PeerGeneration(peerKey) {
		el.staleResponseDrops.Add(1)
		log.Printf("[vpn/endpoint] suppressing stale handshake response for peer %s (gen %d < current %d)",
			peerKey, gen, el.PeerGeneration(peerKey))
		return
	}

	el.mu.RLock()
	udpConn := el.udpConn
	el.mu.RUnlock()
	if udpConn == nil {
		return
	}
	if _, err := udpConn.WriteToUDP(resp, sender); err != nil {
		log.Printf("[vpn/endpoint] failed to write handshake response to %s: %v", sender, err)
		return
	}
	el.txBytes.Add(int64(len(resp)))
}

// CommitHandshake atomically commits the handshake transport keys and peer endpoint
// if gen >= el.peerGenerations[peerKey]. If gen is older than the current generation,
// it discards the keys, releases any preallocated receiver index, leaves the endpoint
// and lastSeen untouched, increments staleHandshakes, and returns false.
func (el *Listener) CommitHandshake(peerKey string, gen uint64, transportKeys *TransportKeys, sender *net.UDPAddr, receiverIdx uint32) bool {
	if transportKeys != nil {
		_ = transportKeys.InitCiphers()
	}
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}

	if gen < el.peerGenerations[peerKey] {
		if transportKeys != nil && transportKeys.LocalIndex != 0 {
			el.releaseReceiverIndexLocked(transportKeys.LocalIndex)
		}
		el.staleHandshakes.Add(1)
		return false
	}

	el.peerGenerations[peerKey] = gen

	if transportKeys != nil {
		transportKeys.Generation = gen
		el.storeTransportKeysLocked(peerKey, transportKeys)
	}

	if sender != nil {
		el.rememberPeerLocked(sender, peerKey, receiverIdx)
	}

	return true
}

func (el *Listener) rememberPeerLocked(sender *net.UDPAddr, peerKey string, receiverIdx uint32) {
	if sender == nil {
		return
	}
	if el.peersByAddr == nil {
		el.peersByAddr = make(map[string]*activePeerState)
	}
	senderCopy := &net.UDPAddr{
		IP:   append(net.IP(nil), sender.IP...),
		Port: sender.Port,
		Zone: sender.Zone,
	}
	st, ok := el.peersByAddr[sender.String()]
	if !ok {
		st = &activePeerState{
			peerKey: peerKey,
			udpAddr: senderCopy,
		}
		st.receiverIdx.Store(receiverIdx)
		el.peersByAddr[sender.String()] = st
	} else {
		st.peerKey = peerKey
		st.udpAddr = senderCopy
		st.receiverIdx.Store(receiverIdx)
	}
	st.lastSeen.Store(time.Now().UnixNano())
}

// rememberPeer records the sender address and client index of a peer that just completed a
// handshake (single udpReadLoop caller; map writes guarded by mu).
func (el *Listener) rememberPeer(sender *net.UDPAddr, peerKey string, receiverIdx uint32) {
	if sender == nil {
		return
	}
	el.mu.Lock()
	defer el.mu.Unlock()
	el.rememberPeerLocked(sender, peerKey, receiverIdx)
}

// peerByAddr looks up the peer state recorded for a sender address.
func (el *Listener) peerByAddr(addr string) (*activePeerState, bool) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	st, ok := el.peersByAddr[addr]
	return st, ok
}

// decryptLogThrottleSeconds is the interval in seconds between transport decryption
// failure logs for a given peer (issue #148).
const decryptLogThrottleSeconds = 5

// touchSessionThrottleSeconds is the minimum interval in seconds between TouchSession
// invocations for an active peer to minimize SessionManager mutex contention under high throughput (issue #294).
const touchSessionThrottleSeconds = 2

// touchPeerSession updates session liveness in SessionManager with rate limiting
// to prevent mutex contention on SessionManager under high packet throughput (issue #294).
func (el *Listener) touchPeerSession(peerKey string, st *activePeerState) {
	if el.sessionMgr == nil || st == nil {
		return
	}
	nowSec := time.Now().Unix()
	last := st.lastTouchSec.Load()
	if (nowSec-last >= touchSessionThrottleSeconds || nowSec < last) && st.lastTouchSec.CompareAndSwap(last, nowSec) {
		el.sessionMgr.TouchSession(peerKey)
	}
}

func (el *Listener) logThrottledDecryptionFailure(sender *net.UDPAddr, peerKey string, keys *TransportKeys, status string, err error) {
	el.transportDecryptFailures.Add(1)
	var st *activePeerState
	if sender != nil {
		st, _ = el.peerByAddr(sender.String())
	}
	now := time.Now().Unix()
	canLog := false
	if st != nil {
		until := st.decryptLogUntil.Load()
		if now >= until && st.decryptLogUntil.CompareAndSwap(until, now+decryptLogThrottleSeconds) {
			canLog = true
		}
	} else {
		canLog = true
	}
	if canLog {
		idx := uint32(0)
		gen := uint64(0)
		if keys != nil {
			idx = keys.LocalIndex
			gen = keys.Generation
		}
		log.Printf("[vpn/endpoint] transport data decryption failed for peer %s (index=%d, gen=%d, status=%s): %v",
			peerKey, idx, gen, status, err)
	}
}

// logThrottledReplayRejection logs a transport anti-replay rejection.
func (el *Listener) logThrottledReplayRejection(sender *net.UDPAddr, peerKey string, keys *TransportKeys, counter uint64) {
	var st *activePeerState
	if sender != nil {
		st, _ = el.peerByAddr(sender.String())
	}
	now := time.Now().Unix()
	canLog := false
	if st != nil {
		until := st.decryptLogUntil.Load()
		if now >= until && st.decryptLogUntil.CompareAndSwap(until, now+decryptLogThrottleSeconds) {
			canLog = true
		}
	} else {
		canLog = true
	}
	if canLog {
		idx := uint32(0)
		gen := uint64(0)
		if keys != nil {
			idx = keys.LocalIndex
			gen = keys.Generation
		}
		log.Printf("[vpn/endpoint] transport data replay rejected for peer %s (index=%d, gen=%d, counter=%d)",
			peerKey, idx, gen, counter)
	}
}

func (el *Listener) deliverToRouter(peerKey string, packet []byte) {
	el.mu.RLock()
	router := el.router
	el.mu.RUnlock()
	if router == nil {
		return
	}
	if err := router(peerKey, packet); err != nil {
		log.Printf("[vpn/endpoint] client packet routing failed for peer %s: %v", peerKey, err)
	}
}

func (el *Listener) logPreviousKeyAccepted(peerKey string, keys *TransportKeys) {
	el.mu.RLock()
	pkp := el.peerKeypairs[peerKey]
	el.mu.RUnlock()
	if pkp != nil {
		now := time.Now().Unix()
		until := pkp.prevLogUntil.Load()
		if now < until || !pkp.prevLogUntil.CompareAndSwap(until, now+1) {
			return
		}
	}
	log.Printf("[vpn/endpoint] accepted transport packet with previous keypair for peer %s: gen=%d index=%d",
		peerKey, keys.Generation, keys.LocalIndex)
}

func (el *Listener) updatePeerEndpointAfterDecryption(sender *net.UDPAddr, peerKey string, remoteIdx uint32, isCurrent bool) *activePeerState {
	if sender == nil {
		return nil
	}
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.peersByAddr == nil {
		el.peersByAddr = make(map[string]*activePeerState)
	}
	st, ok := el.peersByAddr[sender.String()]
	if !ok {
		st = &activePeerState{
			peerKey: peerKey,
			udpAddr: &net.UDPAddr{
				IP:   append(net.IP(nil), sender.IP...),
				Port: sender.Port,
				Zone: sender.Zone,
			},
		}
		if isCurrent && remoteIdx != 0 {
			st.receiverIdx.Store(remoteIdx)
		}
		el.peersByAddr[sender.String()] = st
	} else {
		if st.peerKey != peerKey {
			st.peerKey = peerKey
		}
		if st.udpAddr == nil {
			st.udpAddr = &net.UDPAddr{
				IP:   append(net.IP(nil), sender.IP...),
				Port: sender.Port,
				Zone: sender.Zone,
			}
		}
		if isCurrent && remoteIdx != 0 {
			st.receiverIdx.Store(remoteIdx)
		}
	}
	return st
}

// transportDataHeaderLen is the AWG/WireGuard transport-data header:
// 4-byte message type + 4-byte receiver index + 8-byte counter, followed by
// the ChaCha20Poly1305-encrypted packet (>= 16-byte auth tag).
const transportDataHeaderLen = 16

// parseTransportHeader unmasks the 16-byte AWG transport header and returns receiverIdx and counter.
func parseTransportHeader(datagram, payload, hpKey []byte, s4 int, h4 models.HeaderRange) (receiverIdx uint32, counter uint64, isHP bool, ok bool) {
	if len(payload) < transportDataHeaderLen {
		return 0, 0, false, false
	}

	plainMsgType := binary.LittleEndian.Uint32(payload[0:4])

	// 1. If HP key is 32 bytes and s4 >= 12, attempt to unmask the 16-byte header:
	// [msgType 4B][receiverIdx 4B][counter 8B] using ChaCha20 keyed by hpKey with nonce = datagram[:12].
	if len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, datagram[:health.HeaderCipherNonceSize])
		if cip != nil {
			var hdr [transportDataHeaderLen]byte
			copy(hdr[:], payload[:transportDataHeaderLen])
			cip.XORKeyStream(hdr[:], hdr[:])
			obfMsgType := binary.LittleEndian.Uint32(hdr[0:4])

			if h4.Contains(obfMsgType) {
				receiverIdx = binary.LittleEndian.Uint32(hdr[4:8])
				counter = binary.LittleEndian.Uint64(hdr[8:16])
				return receiverIdx, counter, true, true
			}
			if h4.Contains(plainMsgType) {
				// Obfuscated header did not match H4, but plaintext header does: backward-compat plaintext peer.
				receiverIdx = binary.LittleEndian.Uint32(payload[4:8])
				counter = binary.LittleEndian.Uint64(payload[8:16])
				return receiverIdx, counter, false, true
			}
			return 0, 0, false, false
		}
	}

	// 2. Plaintext path (HP disabled or s4 < 12).
	if h4.Contains(plainMsgType) {
		receiverIdx = binary.LittleEndian.Uint32(payload[4:8])
		counter = binary.LittleEndian.Uint64(payload[8:16])
		return receiverIdx, counter, false, true
	}

	return 0, 0, false, false
}

// decryptPayload decrypts the transport payload with dual-mode HP fallback.
func decryptPayload(aead cipher.AEAD, payload []byte, counter uint64, isHP bool, h4 models.HeaderRange) ([]byte, uint64, error) {
	if len(payload) < transportDataHeaderLen {
		return nil, counter, errors.New("transport payload too short")
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)
	packet, err := aead.Open(nil, nonce[:], payload[transportDataHeaderLen:], nil)
	if err == nil {
		return packet, counter, nil
	}
	// Dual-mode fallback: if HP header unmasking decrypt failed, check if plaintext header also matched H4.
	if isHP {
		plainMsgType := binary.LittleEndian.Uint32(payload[0:4])
		if h4.Contains(plainMsgType) {
			plainCounter := binary.LittleEndian.Uint64(payload[8:16])
			var plainNonce [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(plainNonce[4:12], plainCounter)
			if p, err2 := aead.Open(nil, plainNonce[:], payload[transportDataHeaderLen:], nil); err2 == nil {
				return p, plainCounter, nil
			}
		}
	}
	return nil, counter, err
}

// trimIPPacketPadding strips trailing content padding by inspecting the IPv4 Total Length
// or IPv6 Payload Length header fields.
func trimIPPacketPadding(packet []byte) []byte {
	if len(packet) == 0 {
		return packet
	}
	version := packet[0] >> 4
	if version == 4 && len(packet) >= 20 {
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLen >= 20 && len(packet) > totalLen {
			return packet[:totalLen]
		}
	} else if version == 6 && len(packet) >= 40 {
		payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
		totalLen := payloadLen + 40
		if totalLen >= 40 && len(packet) > totalLen {
			return packet[:totalLen]
		}
	}
	return packet
}

// handleTransportData processes a datagram that failed handshake-initiation
// parsing (or a transport datagram whose ciphertext caused an initiation parse failure).
// Inbound packets are resolved by receiver index into the active or previous keypair,
// or via bounded compatibility fallback for synthetic test sessions.
func (el *Listener) handleTransportData(datagram []byte, sender *net.UDPAddr) bool {
	s4 := el.config.S4
	if s4 < 0 {
		s4 = 0
	}
	h4 := el.config.H4
	if h4.IsZero() {
		h4 = models.DegenerateHeaderRange(health.DefaultH4)
	}

	if sender == nil || len(datagram) < s4+transportDataHeaderLen+chacha20poly1305.Overhead {
		return false
	}

	hpKey := el.headerProtectionKey()
	payload := datagram[s4:]

	receiverIdx, counter, isHP, isTransport := parseTransportHeader(datagram, payload, hpKey, s4, h4)
	if !isTransport {
		return false
	}

	// 1. Primary Keypair Lookup (Index-Aware)
	if el.handleTransportByIndex(sender, payload, receiverIdx, counter, isHP, h4) {
		return true
	}

	// 2. Bounded Compatibility Fallback
	return el.handleTransportFallback(sender, payload, counter, isHP, h4)
}

func (el *Listener) handleTransportByIndex(sender *net.UDPAddr, payload []byte, receiverIdx uint32, counter uint64, isHP bool, h4 models.HeaderRange) bool {
	entry, found := el.lookupKeypairByIndex(receiverIdx)
	if !found || entry == nil || entry.keys == nil {
		return false
	}
	peerKey := entry.peerKey
	keys := entry.keys

	if keys.IsExpired() {
		el.logThrottledDecryptionFailure(sender, peerKey, keys, "expired", errors.New("key expired"))
		return true
	}

	aead, err := keys.RecvCipher()
	if err != nil {
		el.logThrottledDecryptionFailure(sender, peerKey, keys, el.keypairStatus(peerKey, keys), err)
		return true
	}

	packet, usedCounter, decErr := decryptPayload(aead, payload, counter, isHP, h4)
	if decErr != nil {
		el.logThrottledDecryptionFailure(sender, peerKey, keys, el.keypairStatus(peerKey, keys), decErr)
		return true
	}

	if !keys.ValidateCounter(usedCounter) {
		el.logThrottledReplayRejection(sender, peerKey, keys, usedCounter)
		return true
	}

	status := el.keypairStatus(peerKey, keys)
	if status == "previous" {
		el.logPreviousKeyAccepted(peerKey, keys)
	}

	isCurrent := (status == "current")
	var remoteIdxToUpdate uint32
	if isCurrent {
		remoteIdxToUpdate = keys.RemoteIndex
	}
	st := el.updatePeerEndpointAfterDecryption(sender, peerKey, remoteIdxToUpdate, isCurrent)
	if st != nil {
		st.lastSeen.Store(time.Now().UnixNano())
		el.touchPeerSession(peerKey, st)
	}

	packet = trimIPPacketPadding(packet)
	el.deliverToRouter(peerKey, packet)
	return true
}

// candidateFallbackKeys snapshots the candidate transport keys (current and previous)
// for a peer under el.mu.RLock to prevent data races with concurrent keypair rotation
// in storeTransportKeys. Decryption is performed outside the lock.
func (el *Listener) candidateFallbackKeys(peerKey string) []*TransportKeys {
	el.mu.RLock()
	defer el.mu.RUnlock()

	var candidates []*TransportKeys
	if pkp := el.peerKeypairs[peerKey]; pkp != nil {
		if pkp.current != nil && !pkp.current.IsExpired() {
			candidates = append(candidates, pkp.current)
		}
		if pkp.previous != nil && !pkp.previous.IsExpired() {
			candidates = append(candidates, pkp.previous)
		}
	}
	if len(candidates) == 0 {
		if k := el.noiseKeys[peerKey]; k != nil && !k.IsExpired() {
			candidates = append(candidates, k)
		}
	}
	return candidates
}

func (el *Listener) handleTransportFallback(sender *net.UDPAddr, payload []byte, counter uint64, isHP bool, h4 models.HeaderRange) bool {
	st, ok := el.peerByAddr(sender.String())
	if !ok {
		return false
	}
	if st.udpAddr == nil {
		el.mu.Lock()
		if st.udpAddr == nil {
			st.udpAddr = &net.UDPAddr{
				IP:   append(net.IP(nil), sender.IP...),
				Port: sender.Port,
				Zone: sender.Zone,
			}
		}
		el.mu.Unlock()
	}

	peerKey := st.peerKey
	candidates := el.candidateFallbackKeys(peerKey)

	var decryptedPacket []byte
	var successfulKeys *TransportKeys
	var lastDecErr error

	for _, keys := range candidates {
		aead, err := keys.RecvCipher()
		if err != nil {
			lastDecErr = err
			continue
		}
		p, usedCounter, err := decryptPayload(aead, payload, counter, isHP, h4)
		if err == nil {
			if !keys.ValidateCounter(usedCounter) {
				el.logThrottledReplayRejection(sender, peerKey, keys, usedCounter)
				return true
			}
			decryptedPacket = p
			successfulKeys = keys
			break
		}
		lastDecErr = err
	}

	if decryptedPacket == nil {
		var keysToLog *TransportKeys
		status := "current"
		if len(candidates) > 0 {
			keysToLog = candidates[0]
			status = el.keypairStatus(peerKey, keysToLog)
		} else if k, ok := el.TransportKeysFor(peerKey); ok {
			keysToLog = k
			status = el.keypairStatus(peerKey, keysToLog)
		}
		if lastDecErr == nil {
			lastDecErr = errors.New("chacha20poly1305: message authentication failed")
		}
		el.logThrottledDecryptionFailure(sender, peerKey, keysToLog, status, lastDecErr)
		return true
	}

	if el.keypairStatus(peerKey, successfulKeys) == "previous" {
		el.logPreviousKeyAccepted(peerKey, successfulKeys)
	}

	isCurrent := (el.keypairStatus(peerKey, successfulKeys) == "current")
	var remoteIdxToUpdate uint32
	if isCurrent {
		remoteIdxToUpdate = successfulKeys.RemoteIndex
	}
	updatedSt := el.updatePeerEndpointAfterDecryption(sender, peerKey, remoteIdxToUpdate, isCurrent)
	if updatedSt != nil {
		updatedSt.lastSeen.Store(time.Now().UnixNano())
		el.touchPeerSession(peerKey, updatedSt)
	}

	decryptedPacket = trimIPPacketPadding(decryptedPacket)
	el.deliverToRouter(peerKey, decryptedPacket)
	return true
}

// SendToPeer encrypts an IP packet for a peer with the stored transport
// SendKey and writes it to the peer's last recorded UDP address using AWG
// transport framing (S4 padding + H4 magic header). The send counter is a fresh
// monotonic value per transport key generation.
func (el *Listener) SendToPeer(peerKey string, packet []byte) error {
	keys, ok := el.TransportKeysFor(peerKey)
	if !ok || keys == nil || keys.SendKey == nil {
		return fmt.Errorf("no transport keys for peer %s", peerKey)
	}

	// Find the peer's most-recently-seen UDP address. A peer that rehandshakes
	// from a new socket port leaves its older entry in peersByAddr; map
	// iteration order must not decide which address receives traffic
	// (issue #43: replies vanished when the stale entry won the pick).
	addrStr := ""
	var st *activePeerState
	var newest int64 = -1
	el.mu.RLock()
	for a, cand := range el.peersByAddr {
		if cand.peerKey != peerKey {
			continue
		}
		if ls := cand.lastSeen.Load(); ls > newest {
			newest = ls
			addrStr = a
			st = cand
		}
	}
	udpConn := el.udpConn
	hpKey := el.hpKey
	var addr *net.UDPAddr
	if st != nil {
		addr = st.udpAddr
	}
	el.mu.RUnlock()
	if st == nil || udpConn == nil {
		return fmt.Errorf("no recorded address for peer %s", peerKey)
	}
	if addr == nil {
		var err error
		addr, err = net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			return fmt.Errorf("failed to resolve peer address %s: %w", addrStr, err)
		}
	}

	counter := keys.NextSendCounter()
	aead, err := keys.SendCipher()
	if err != nil {
		return fmt.Errorf("failed to get transport send cipher: %w", err)
	}
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:12], counter)

	s4 := el.config.S4
	if s4 < 0 {
		s4 = 0
	}
	h4Val := el.config.H4.PickOne()
	if h4Val == 0 {
		h4Val = health.DefaultH4
	}

	msg := make([]byte, s4, s4+transportDataHeaderLen+len(packet)+chacha20poly1305.Overhead)
	for i := 0; i < s4; i += 8 {
		// #nosec G404 -- non-cryptographic obfuscation junk padding
		val := randv2.Uint64()
		rem := s4 - i
		if rem > 8 {
			rem = 8
		}
		for b := 0; b < rem; b++ {
			msg[i+b] = byte(val)
			val >>= 8
		}
	}

	receiverIdx := keys.RemoteIndex
	if receiverIdx == 0 && st != nil {
		receiverIdx = st.receiverIdx.Load()
	}

	var hdr [transportDataHeaderLen]byte
	binary.LittleEndian.PutUint32(hdr[0:4], h4Val) // AWG H4 transport data
	binary.LittleEndian.PutUint32(hdr[4:8], receiverIdx)
	binary.LittleEndian.PutUint64(hdr[8:16], counter)
	msg = append(msg, hdr[:]...)
	msg = aead.Seal(msg, nonce[:], packet, nil)

	// If HP key is 32 bytes and s4 >= 12, apply ChaCha20 cipher (key hpKey, nonce msg[:12])
	// to mask the 16-byte header msg[s4 : s4+16] in-place.
	if len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, msg[:health.HeaderCipherNonceSize])
		if cip != nil {
			cip.XORKeyStream(msg[s4:s4+transportDataHeaderLen], msg[s4:s4+transportDataHeaderLen])
		}
	}

	if _, err := udpConn.WriteToUDP(msg, addr); err != nil {
		return fmt.Errorf("failed to write transport data to %s: %w", addr, err)
	}
	el.txBytes.Add(int64(len(msg)))
	return nil
}

func (el *Listener) udpReadLoop(ctx context.Context) {
	defer el.wg.Done()
	buf := make([]byte, 2048)

	for {
		if el.udpConn == nil {
			return
		}

		n, addr, err := el.udpConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-el.stopCh:
				return
			default:
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				continue
			}
		}

		if n > 0 {
			el.rxBytes.Add(int64(n))
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				data := make([]byte, n)
				copy(data, buf[:n])
				job := packetJob{
					data:   data,
					sender: udpAddr,
				}
				select {
				case <-el.stopCh:
					return
				case el.packetQueue <- job:
				default:
					el.packetQueueDrops.Add(1)
				}
			}
		}
	}
}

func (el *Listener) workerLoop(ctx context.Context) {
	defer el.wg.Done()
	for {
		select {
		case <-el.stopCh:
			return
		case job, ok := <-el.packetQueue:
			if !ok {
				return
			}
			el.handleDatagram(ctx, job.data, job.sender)
		}
	}
}

// SessionReaperHook is invoked by heartbeatLoop with each session it reaps
// for idleness, so the VPN service can release forwarder routes, tunnel pool
// connection counts, and sticky affinity (the same cleanup an explicit
// DisconnectSession performs). Without it, every idle timeout leaks those.
type SessionReaperHook func(ctx context.Context, sess *models.VPNSession)

// SetSessionReaperHook registers the idle-timeout cleanup callback. Must be
// called before Start; the hook runs on the heartbeat goroutine.
func (el *Listener) SetSessionReaperHook(fn SessionReaperHook) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.reaperHook = fn
}

// SetPostSweepHook registers a callback invoked after each idle-timeout sweep cycle.
// The hook runs on the heartbeat goroutine outside the session manager mutex.
func (el *Listener) SetPostSweepHook(fn func(ctx context.Context)) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.postSweepHook = fn
}

func (el *Listener) invokePostSweepHook(ctx context.Context) {
	el.mu.RLock()
	hook := el.postSweepHook
	el.mu.RUnlock()
	if hook != nil {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[vpn] recovered from post-sweep hook panic: %v", r)
			}
		}()
		hook(ctx)
	}
}

func (el *Listener) sweepExpiredKeypairs() {
	el.mu.Lock()
	defer el.mu.Unlock()
	for _, pkp := range el.peerKeypairs {
		if pkp.previous != nil && pkp.previous.IsExpired() {
			if pkp.previous.LocalIndex != 0 {
				delete(el.indexTable, pkp.previous.LocalIndex)
			}
			pkp.previous = nil
		}
	}
}

func (el *Listener) prunePeerTransportStateLocked(peerKey string) {
	if pkp, ok := el.peerKeypairs[peerKey]; ok && pkp != nil {
		if pkp.current != nil && pkp.current.LocalIndex != 0 {
			delete(el.indexTable, pkp.current.LocalIndex)
		}
		if pkp.previous != nil && pkp.previous.LocalIndex != 0 {
			delete(el.indexTable, pkp.previous.LocalIndex)
		}
		delete(el.peerKeypairs, peerKey)
	}

	for idx, entry := range el.indexTable {
		if entry != nil && entry.peerKey == peerKey {
			delete(el.indexTable, idx)
		}
	}

	delete(el.noiseKeys, peerKey)

	for addr, st := range el.peersByAddr {
		if st != nil && st.peerKey == peerKey {
			delete(el.peersByAddr, addr)
		}
	}
}

// FencePeerGeneration rejects pending handshakes from older generations while
// leaving transport keys and addresses intact for already-admitted return
// writes. The caller can prune those resources after route retirement.
func (el *Listener) FencePeerGeneration(peerKey string, fenceGen uint64) {
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}
	if fenceGen > el.peerGenerations[peerKey] {
		el.peerGenerations[peerKey] = fenceGen
	}
}

// PrunePeerTransportState removes all transport keys, index table entries, and peer endpoints
// for peerKey, and advances the peer's generation fence to fenceGen (if provided) so that any
// in-flight handshakes with older generations are rejected.
func (el *Listener) PrunePeerTransportState(peerKey string, fenceGen ...uint64) bool {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}

	if len(fenceGen) > 0 && fenceGen[0] > 0 {
		if fenceGen[0] < el.peerGenerations[peerKey] {
			return false
		}
		el.peerGenerations[peerKey] = fenceGen[0]
	} else {
		el.peerGenerations[peerKey]++
	}

	el.prunePeerTransportStateLocked(peerKey)
	return true
}

// PrunePeerTransportStateForGeneration atomically prunes transport state for peerKey
// under el.mu if the peer's current generation has not advanced past timedOutGen.
// If currentGen > timedOutGen: a newer generation has already committed, so it
// leaves the transport state untouched and returns false.
// Otherwise: it prunes the transport state, advances the generation fence to at
// least timedOutGen + 1, and returns true.
func (el *Listener) PrunePeerTransportStateForGeneration(peerKey string, timedOutGen uint64) bool {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.peerGenerations == nil {
		el.peerGenerations = make(map[string]uint64)
	}

	currentGen := el.peerGenerations[peerKey]
	if currentGen > timedOutGen {
		return false
	}

	fence := timedOutGen + 1
	if el.peerGenerations[peerKey] < fence {
		el.peerGenerations[peerKey] = fence
	} else {
		el.peerGenerations[peerKey]++
	}

	el.prunePeerTransportStateLocked(peerKey)
	return true
}

// PrunePeerTransportStateIfSession removes endpoint transport state for a peer if the current session
// matches expectedSessionID, or unconditionally if expectedSessionID is empty.
func (el *Listener) PrunePeerTransportStateIfSession(peerKey string, sessionID string, fenceGen ...uint64) bool {
	if sessionID != "" && el.sessionMgr != nil {
		if s, ok := el.sessionMgr.GetSession(peerKey); ok && s != nil && s.ID != sessionID {
			return false
		}
	}
	return el.PrunePeerTransportState(peerKey, fenceGen...)
}

func (el *Listener) prunePeerKeypairsIfMatch(peerKey string, expectedSessionID string) bool {
	return el.PrunePeerTransportStateIfSession(peerKey, expectedSessionID)
}

// SweepTimedOutSessions sweeps for idle-timed-out sessions and invokes the registered
// SessionReaperHook for each reaped session.
func (el *Listener) SweepTimedOutSessions(ctx context.Context) ([]*models.VPNSession, error) {
	el.sweepExpiredKeypairs()

	if el.sessionMgr == nil {
		return nil, nil
	}
	timedOut, err := el.sessionMgr.CheckTimeouts(ctx, el.config.IdleTimeout)
	if err != nil {
		return nil, err
	}
	if len(timedOut) == 0 {
		return nil, nil
	}
	el.mu.RLock()
	hook := el.reaperHook
	el.mu.RUnlock()
	for _, sess := range timedOut {
		el.mu.RLock()
		prePruneHook := el.preSweepPruneHook
		el.mu.RUnlock()
		if prePruneHook != nil {
			prePruneHook(sess.PeerPublicKey, sess.Generation)
		}

		log.Printf("[vpn/endpoint] idle session timed out: id=%s peer=%s user=%s last_seen=%s (idle threshold=%s)",
			sess.ID, sess.PeerPublicKey, sess.UserID, sess.LastSeen.Format(time.RFC3339), el.config.IdleTimeout)
		if hook != nil {
			func() {
				defer func() {
					// A panicking hook must not kill the sweep.
					if r := recover(); r != nil {
						log.Printf("[vpn] recovered from session reaper hook panic: %v", r)
					}
				}()
				hook(ctx, sess)
			}()
		}
		// The service hook retires the route and waits for admitted writes.
		// Keep transport keys alive until those writes have finished. The
		// generation guard preserves keys installed by a concurrent reconnect.
		if !el.PrunePeerTransportStateForGeneration(sess.PeerPublicKey, sess.Generation) && el.HasTransportStateForPeer(sess.PeerPublicKey) {
			log.Printf("[vpn/endpoint] skipping keypair pruning for timed-out session %s (gen %d): newer endpoint generation exists for peer %s",
				sess.ID, sess.Generation, sess.PeerPublicKey)
		}
	}
	return timedOut, nil
}

func (el *Listener) heartbeatLoop(ctx context.Context) {
	defer el.wg.Done()
	interval := 30 * time.Second
	if el.config.HeartbeatInterval > 0 {
		interval = el.config.HeartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-el.stopCh:
			return
		case <-ticker.C:
			if _, err := el.SweepTimedOutSessions(ctx); err != nil {
				log.Printf("[vpn] idle-timeout sweep failed: %v", err)
			}
			el.invokePostSweepHook(ctx)
		}
	}
}
