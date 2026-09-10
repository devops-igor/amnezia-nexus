package endpoint

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	randv2 "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
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

// activePeerState tracks a peer's most recent UDP endpoint and transport
// send counter so late transport datagrams and server→client sends can find
// the right socket address.
type activePeerState struct {
	peerKey     string
	receiverIdx atomic.Uint32
	sendCount   atomic.Uint64
	lastSeen    atomic.Int64 // unix nanos
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
	peersByAddr         map[string]*activePeerState // sender UDP addr string -> peer state
	udpConn             *net.UDPConn
	tunDev              PacketDevice
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

	// rejectLogUntil throttles handshake-rejection log lines (log-flood
	// defense against a garbage-packet source that fails MAC1): at most one
	// rejection log per second. Read/written only by the single read-loop
	// goroutine.
	rejectLogUntil atomic.Int64

	// handshakeRejects counts inbound datagrams that failed handshake-
	// initiation parsing AND were not transport data for an established
	// session (handleDatagram's rejection branch). Exposed via
	// HandshakeRejections so silent rekey rejections (issue #39 defect 2:
	// legit rekeys rejected as "not an AWG handshake initiation") become
	// observable in stats instead of only in throttled logs.
	handshakeRejects atomic.Uint64
}

// NewListener initializes a new AWG endpoint listener. serverKeys provides the
// endpoint's persistent Noise server keypair (see ServerKeysManager); when nil
// one is created from db (ephemeral when db is also nil).
func NewListener(cfg ListenerConfig, db *database.DB, auth Authenticator, ipam *IPAM, sessionMgr *SessionManager, serverKeys *ServerKeysManager) (*Listener, error) {
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
				// unusable with S<N below the cipher nonce size — HP clients
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

	return &Listener{
		config:      cfg,
		hpKey:       hpKeyBytes,
		db:          db,
		auth:        auth,
		ipam:        ipam,
		sessionMgr:  sessionMgr,
		serverKeys:  serverKeys,
		noiseKeys:   make(map[string]*TransportKeys),
		peersByAddr: make(map[string]*activePeerState),
		tunDev:      NewChannelPacketDevice("awg0", cfg.MTU, 512),
		stopCh:      make(chan struct{}),
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
// Start. Callers must only invoke it while the listener is stopped — a
// running listener is already bound to its current port, and Start
// (like UpdateObfuscation) refuses to run twice — so the VPN service
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

	el.udpConn = conn
	if el.tunDev == nil {
		el.tunDev = NewChannelPacketDevice("awg0", el.config.MTU, 512)
	} else if chDev, ok := el.tunDev.(*ChannelPacketDevice); ok && chDev.closed.Load() {
		el.tunDev = NewChannelPacketDevice(chDev.Name(), chDev.MTU(), 512)
	}
	el.running = true
	el.draining = false
	el.stopCh = make(chan struct{})
	el.mu.Unlock()

	el.wg.Add(2)
	go el.udpReadLoop(ctx)
	go el.heartbeatLoop(ctx)

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

	user, _, err := auth.AuthenticatePeer(ctx, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("peer authentication failed: %w", err)
	}

	assignedIP, err := ipam.Allocate(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ip allocation failed: %w", err)
	}

	sess, err := sm.CreateSession(ctx, user.ID, peerPublicKey, assignedIP.String(), backendTunnelID)
	if err != nil {
		_ = ipam.Release(peerPublicKey)
		return nil, fmt.Errorf("session creation failed: %w", err)
	}

	return sess, nil
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

	return sm.CloseSession(ctx, sess.ID, "disconnected")
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

// HandshakeRejections returns the number of inbound datagrams rejected by
// handshake-initiation parsing and not consumed as transport data. It is the
// observability signal for issue #39 defect 2: a rising count means legit
// client (rekey) initiations are being classified as not-a-handshake. Nil
// receiver is safe and returns 0.
func (el *Listener) HandshakeRejections() uint64 {
	if el == nil {
		return 0
	}
	return el.handshakeRejects.Load()
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

// storeTransportKeys records the transport keys derived for a peer's active
// handshake, replacing any previous keys from an earlier handshake.
func (el *Listener) storeTransportKeys(peerKey string, keys *TransportKeys) {
	el.mu.Lock()
	defer el.mu.Unlock()
	if el.noiseKeys == nil {
		el.noiseKeys = make(map[string]*TransportKeys)
	}
	el.noiseKeys[peerKey] = keys
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
		// Not a valid handshake initiation for this endpoint: transport data
		// for an established session (or garbage). Try the transport path.
		if !el.handleTransportData(datagram, sender) {
			// Count every rejection that is not transport data — including
			// too-short datagrams — so the counter reflects the true
			// rejection volume seen on the wire (issue #39 defect 2).
			el.handshakeRejects.Add(1)
			if !errors.Is(err, ErrDatagramTooShort) {
				// Throttle rejection logs: a garbage flood that fails MAC1
				// would otherwise produce one log line per packet.
				// (Read-loop goroutine only: plain read/put is safe.)
				now := time.Now().Unix()
				if el.rejectLogUntil.Load() <= now {
					el.rejectLogUntil.Store(now + 1)
					log.Printf("[vpn/endpoint] rejected handshake initiation from %s: %v", sender, err)
				}
			}
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

	_, _, err = handler(ctx, peerKey)
	if err != nil {
		log.Printf("[vpn/endpoint] handshake processing failed for peer %s from %s: %v", peerKey, sender, err)
		return
	}

	resp, transportKeys, err := BuildResponse(serverPriv, info, el.config.H2, el.config.S2, el.hpKey)
	if err != nil {
		log.Printf("[vpn/endpoint] failed to build handshake response for peer %s: %v", peerKey, err)
		return
	}

	if transportKeys != nil {
		el.storeTransportKeys(peerKey, transportKeys)
	}

	// Remember the peer's UDP endpoint so subsequent transport-data
	// datagrams from the same address can be decrypted and routed, and so
	// SendToPeer can address them.
	el.rememberPeer(sender, peerKey, info.SenderIndex)

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

// rememberPeer records the sender address and client index of a peer that just completed a
// handshake (single udpReadLoop caller; map writes guarded by mu).
func (el *Listener) rememberPeer(sender *net.UDPAddr, peerKey string, receiverIdx uint32) {
	if sender == nil {
		return
	}
	el.mu.Lock()
	if el.peersByAddr == nil {
		el.peersByAddr = make(map[string]*activePeerState)
	}
	st, ok := el.peersByAddr[sender.String()]
	if !ok {
		st = &activePeerState{peerKey: peerKey}
		st.receiverIdx.Store(receiverIdx)
		el.peersByAddr[sender.String()] = st
	} else {
		st.peerKey = peerKey
		st.receiverIdx.Store(receiverIdx)
	}
	st.lastSeen.Store(time.Now().UnixNano())
	el.mu.Unlock()
}

// peerByAddr looks up the peer state recorded for a sender address.
func (el *Listener) peerByAddr(addr string) (*activePeerState, bool) {
	el.mu.RLock()
	defer el.mu.RUnlock()
	st, ok := el.peersByAddr[addr]
	return st, ok
}

// transportDataHeaderLen is the AWG/WireGuard transport-data header:
// 4-byte message type + 4-byte receiver index + 8-byte counter, followed by
// the ChaCha20Poly1305-encrypted packet (>= 16-byte auth tag).
const transportDataHeaderLen = 16

// handleTransportData processes a datagram that failed handshake-initiation
// parsing: if the sender address belongs to a peer with an established
// session and stored transport keys, decrypt the AWG transport-data message
// and hand the inner IP packet to the installed client packet router.
// Anything else (unknown sender, garbage, keepalive from a stale address) is
// silently dropped.
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
	st, ok := el.peerByAddr(sender.String())
	if !ok {
		return false
	}
	keys, ok := el.TransportKeysFor(st.peerKey)
	if !ok || keys == nil || keys.RecvKey == nil {
		return false
	}

	aead, err := chacha20poly1305.New(keys.RecvKey)
	if err != nil {
		return false
	}

	payload := datagram[s4:]
	hpKey := el.headerProtectionKey()

	packet, decErr := decryptTransportPayload(aead, datagram, payload, hpKey, s4, h4)
	if packet == nil {
		if decErr != nil {
			log.Printf("[vpn/endpoint] transport data decryption failed for peer %s: %v", st.peerKey, decErr)
		}
		return false
	}
	st.lastSeen.Store(time.Now().UnixNano())

	packet = trimIPPacketPadding(packet)

	el.mu.RLock()
	router := el.router
	el.mu.RUnlock()
	if router == nil {
		return true
	}
	if err := router(st.peerKey, packet); err != nil {
		// Congestion/backpressure is expected under load: drop silently at
		// debug priority; anything else is a routing inconsistency worth a log.
		log.Printf("[vpn/endpoint] client packet routing failed for peer %s: %v", st.peerKey, err)
	}
	return true
}

// decryptTransportPayload attempts Header Protection unmasking and AEAD decryption,
// falling back to plaintext H4 matching if HP unmasking does not match or fails.
func decryptTransportPayload(aead cipher.AEAD, datagram, payload, hpKey []byte, s4 int, h4 models.HeaderRange) ([]byte, error) {
	var packet []byte
	var decErr error

	// 1. If HP key is 32 bytes and s4 >= 12, attempt to unmask the 16-byte header:
	// [msgType 4B][receiverIdx 4B][counter 8B] using ChaCha20 keyed by el.hpKey with nonce = datagram[:12].
	if len(hpKey) == 32 && s4 >= health.HeaderCipherNonceSize {
		cip := health.NewHeaderProtectionCipher(hpKey, datagram[:health.HeaderCipherNonceSize])
		if cip != nil {
			var hdr [transportDataHeaderLen]byte
			copy(hdr[:], payload[:transportDataHeaderLen])
			cip.XORKeyStream(hdr[:], hdr[:])
			if h4.Contains(binary.LittleEndian.Uint32(hdr[0:4])) {
				counter := binary.LittleEndian.Uint64(hdr[8:16])
				var nonce [chacha20poly1305.NonceSize]byte
				binary.LittleEndian.PutUint64(nonce[4:12], counter)
				packet, decErr = aead.Open(nil, nonce[:], payload[transportDataHeaderLen:], nil)
			}
		}
	}

	// 2. Dual-mode fallback: if HP unmasking was not applicable, unmasked header did not match H4,
	// or unmasked AEAD decryption failed, check if plaintext header matches H4.
	if packet == nil {
		plainMsgType := binary.LittleEndian.Uint32(payload[0:4])
		if h4.Contains(plainMsgType) {
			counter := binary.LittleEndian.Uint64(payload[8:16])
			var nonce [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(nonce[4:12], counter)
			packet, decErr = aead.Open(nil, nonce[:], payload[transportDataHeaderLen:], nil)
		}
	}

	return packet, decErr
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

// SendToPeer encrypts an IP packet for a peer with the stored transport
// SendKey and writes it to the peer's last recorded UDP address using AWG
// transport framing (S4 padding + H4 magic header). The send counter is a fresh
// monotonic value per peer.
func (el *Listener) SendToPeer(peerKey string, packet []byte) error {
	keys, ok := el.TransportKeysFor(peerKey)
	if !ok || keys == nil || keys.SendKey == nil {
		return fmt.Errorf("no transport keys for peer %s", peerKey)
	}

	// Find the peer's last-seen UDP address.
	addrStr := ""
	var st *activePeerState
	el.mu.RLock()
	for a, cand := range el.peersByAddr {
		if cand.peerKey == peerKey {
			addrStr = a
			st = cand
		}
	}
	udpConn := el.udpConn
	hpKey := el.hpKey
	el.mu.RUnlock()
	if st == nil || udpConn == nil {
		return fmt.Errorf("no recorded address for peer %s", peerKey)
	}
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return fmt.Errorf("failed to resolve peer address %s: %w", addrStr, err)
	}

	counter := st.sendCount.Add(1) - 1
	aead, err := chacha20poly1305.New(keys.SendKey)
	if err != nil {
		return fmt.Errorf("failed to create transport AEAD: %w", err)
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

	receiverIdx := st.receiverIdx.Load()

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
		select {
		case <-el.stopCh:
			return
		default:
		}

		if el.udpConn == nil {
			return
		}

		_ = el.udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, addr, err := el.udpConn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-el.stopCh:
				return
			default:
				continue
			}
		}

		if n > 0 {
			el.rxBytes.Add(int64(n))
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				el.handleDatagram(ctx, buf[:n], udpAddr)
			}
		}
	}
}

// SessionReaperHook is invoked by heartbeatLoop with each session it reaps
// for idleness, so the VPN service can release forwarder routes, tunnel pool
// connection counts, and sticky affinity — the same cleanup an explicit
// DisconnectSession performs. Without it, every idle timeout leaks those.
type SessionReaperHook func(ctx context.Context, sess *models.VPNSession)

// SetSessionReaperHook registers the idle-timeout cleanup callback. Must be
// called before Start; the hook runs on the heartbeat goroutine.
func (el *Listener) SetSessionReaperHook(fn SessionReaperHook) {
	el.mu.Lock()
	defer el.mu.Unlock()
	el.reaperHook = fn
}

func (el *Listener) heartbeatLoop(ctx context.Context) {
	defer el.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-el.stopCh:
			return
		case <-ticker.C:
			if el.sessionMgr != nil {
				timedOut, err := el.sessionMgr.CheckTimeouts(ctx, el.config.IdleTimeout)
				if err != nil {
					log.Printf("[vpn] idle-timeout sweep failed: %v", err)
					continue
				}
				if len(timedOut) == 0 {
					continue
				}
				el.mu.RLock()
				hook := el.reaperHook
				el.mu.RUnlock()
				for _, sess := range timedOut {
					if hook != nil {
						func() {
							defer func() {
								// A panicking hook must not kill the heartbeat loop.
								if r := recover(); r != nil {
									log.Printf("[vpn] recovered from session reaper hook panic: %v", r)
								}
							}()
							hook(ctx, sess)
						}()
					}
				}
			}
		}
	}
}
