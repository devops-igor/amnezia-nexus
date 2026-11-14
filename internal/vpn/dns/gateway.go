package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// ReplyWriter sends packet frames back towards the authenticated VPN client.
type ReplyWriter interface {
	WritePacket(scope policy.Scope, packet []byte) error
}

// RouteObserver records DNS response observations into an active route cache.
type RouteObserver interface {
	ObserveDNSResponse(sessionID string, req, resp *mdns.Msg) error
}

// ScopeHandle represents an active authenticated DNS session capability.
type ScopeHandle struct {
	Scope        policy.Scope
	SessionCache *policy.SessionCache
	ReplyWriter  ReplyWriter
	ctx          context.Context
	cancel       context.CancelFunc
	retired      atomic.Bool
}

// NewScopeHandle constructs a new ScopeHandle tied to the parent context.
func NewScopeHandle(parent context.Context, scope policy.Scope, sc *policy.SessionCache, writer ReplyWriter) *ScopeHandle {
	ctx, cancel := context.WithCancel(parent)
	return &ScopeHandle{
		Scope:        scope,
		SessionCache: sc,
		ReplyWriter:  writer,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Retire permanently marks the scope handle as retired, cancels its context,
// and invalidates its session cache. Synchronous, memory-only, and idempotent.
func (h *ScopeHandle) Retire() {
	if h == nil {
		return
	}
	if h.retired.CompareAndSwap(false, true) {
		h.cancel()
		if h.SessionCache != nil {
			h.SessionCache.Invalidate()
		}
	}
}

// IsRetired returns true if the scope handle has been retired.
func (h *ScopeHandle) IsRetired() bool {
	if h == nil {
		return true
	}
	return h.retired.Load()
}

// Context returns the context for this scope handle.
func (h *ScopeHandle) Context() context.Context {
	if h == nil {
		return context.Background()
	}
	return h.ctx
}

// Retirement tracks synchronous invalidation of an expired or revoked scope.
type Retirement struct {
	Scope policy.Scope
}

// GatewayConfig configures the Gateway transport adapter.
type GatewayConfig struct {
	Gateway       netip.AddrPort
	RouteObserver RouteObserver
}

type gatewayTCPTransport struct {
	scope     policy.Scope
	vt        tun.Device
	mu        sync.Mutex
	closed    atomic.Bool
	cancel    context.CancelFunc
	serveDone chan struct{}
}

// Close tears the transport down in producer order: the Serve loop is stopped
// and joined first, and only then is the netstack device closed.
//
// Serve closes the listener itself (listener teardown emits packets through the
// device) and joins the goroutines it started, so closing the device before
// Serve returns would race its packet channel with a live notification send.
// The transport mutex additionally serializes the close against any TrySubmit
// packet injection that is still writing into the device.
func (tr *gatewayTCPTransport) Close() {
	if !tr.closed.CompareAndSwap(false, true) {
		return
	}
	if tr.cancel != nil {
		tr.cancel()
	}
	if tr.serveDone != nil {
		<-tr.serveDone
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.vt != nil {
		_ = tr.vt.Close()
	}
}

// Gateway intercepts and processes DNS queries addressed to the gateway on port 53.
type Gateway struct {
	cfg        GatewayConfig
	server     *Server
	mu         sync.Mutex
	transports map[policy.Scope]*gatewayTCPTransport
}

// NewGateway constructs a new Gateway transport adapter.
func NewGateway(cfg GatewayConfig, server *Server) (*Gateway, error) {
	if !cfg.Gateway.IsValid() || !cfg.Gateway.Addr().Is4() || cfg.Gateway.Port() != 53 {
		return nil, errors.New("gateway must have valid IPv4 and port 53")
	}
	if server == nil {
		return nil, errors.New("server cannot be nil")
	}
	if cfg.RouteObserver != nil {
		server.SetObserver(cfg.RouteObserver)
	}
	return &Gateway{
		cfg:        cfg,
		server:     server,
		transports: make(map[policy.Scope]*gatewayTCPTransport),
	}, nil
}

// SetObserver updates the active route observer.
func (g *Gateway) SetObserver(obs RouteObserver) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cfg.RouteObserver = obs
	if g.server != nil {
		g.server.SetObserver(obs)
	}
}

func (g *Gateway) getOrCreateTransport(scope *ScopeHandle) (*gatewayTCPTransport, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if scope == nil || scope.IsRetired() {
		return nil, errors.New("scope is nil or retired")
	}

	if tr, ok := g.transports[scope.Scope]; ok {
		return tr, nil
	}

	vt, tnet, err := netstack.CreateNetTUN([]netip.Addr{g.cfg.Gateway.Addr()}, nil, 1500)
	if err != nil {
		return nil, err
	}

	tcpL, err := tnet.ListenTCPAddrPort(g.cfg.Gateway)
	if err != nil {
		_ = vt.Close()
		return nil, err
	}

	// The transport owns its Serve lifetime so Close can join it before
	// tearing down the device the listener writes into.
	serveCtx, serveCancel := context.WithCancel(scope.ctx)

	tr := &gatewayTCPTransport{
		scope:     scope.Scope,
		vt:        vt,
		cancel:    serveCancel,
		serveDone: make(chan struct{}),
	}
	g.transports[scope.Scope] = tr

	// Background reader: forward outbound IP packets from netstack to client reply writer.
	go func() {
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 65535)
		sizes := make([]int, 1)
		for {
			n, err := vt.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				if !scope.IsRetired() && scope.ReplyWriter != nil {
					if err := scope.ReplyWriter.WritePacket(scope.Scope, pkt); err != nil {
						scope.Retire()
						go g.BeginRetire(scope)
					}
				}
			}
		}
	}()

	// Serve TCP DNS queries over this listener bounded by the transport context.
	// Closing the transport joins this goroutine, so the listener teardown it
	// performs (which emits packets through the device) cannot overlap the
	// device close.
	go func() {
		defer close(tr.serveDone)
		_ = g.server.Serve(serveCtx, scope, nil, tcpL)
	}()

	// Clean up transport when scope context is done.
	go func() {
		<-scope.ctx.Done()
		g.server.RetireScope(scope.Scope)
		g.mu.Lock()
		var toClose *gatewayTCPTransport
		if g.transports[scope.Scope] == tr {
			delete(g.transports, scope.Scope)
			toClose = tr
		}
		g.mu.Unlock()
		if toClose != nil {
			toClose.Close()
		}
	}()

	return tr, nil
}

func (g *Gateway) handleUDP(scope *ScopeHandle, ipv4Packet []byte, ihl int, dstIP netip.Addr) (bool, error) {
	if len(ipv4Packet) < ihl+8 {
		return false, nil
	}
	dstPort := binary.BigEndian.Uint16(ipv4Packet[ihl+2 : ihl+4])
	if dstPort != 53 {
		return false, nil
	}

	fragOffset := binary.BigEndian.Uint16(ipv4Packet[6:8]) & 0x1fff
	moreFrags := (ipv4Packet[6] & 0x20) != 0
	if fragOffset != 0 || moreFrags {
		return true, nil // Drop fragmented UDP packets.
	}

	srcIP := netip.AddrFrom4([4]byte{ipv4Packet[12], ipv4Packet[13], ipv4Packet[14], ipv4Packet[15]})
	srcPort := binary.BigEndian.Uint16(ipv4Packet[ihl : ihl+2])
	udpLen := int(binary.BigEndian.Uint16(ipv4Packet[ihl+4 : ihl+6]))
	if udpLen < 8 || ihl+udpLen > len(ipv4Packet) {
		return true, nil
	}

	udpPayload := ipv4Packet[ihl+8 : ihl+udpLen]
	reqMsg := new(mdns.Msg)
	if err := reqMsg.Unpack(udpPayload); err != nil {
		return true, nil // Malformed DNS query dropped.
	}

	recvTime := time.Now()
	respMsg, err := g.server.ServeDNSMessage(scope.ctx, scope.Scope, reqMsg, false)
	if err != nil || respMsg == nil {
		return true, nil
	}

	respBytes, err := respMsg.Pack()
	if err != nil {
		return true, nil
	}

	// Enqueue reply back to authenticated client if scope remains active.
	if !scope.IsRetired() && scope.ReplyWriter != nil {
		replyPkt := buildIPv4UDPPacket(dstIP, 53, srcIP, srcPort, respBytes)
		if replyPkt != nil {
			if err := scope.ReplyWriter.WritePacket(scope.Scope, replyPkt); err == nil {
				g.server.ObserveResponseWithSessionID(reqMsg, respMsg, scope.SessionCache, scope.Scope.SessionID, recvTime)
			}
		}
	}
	return true, nil
}

// TrySubmit inspects incoming IPv4 packets from authenticated ingress.
// If addressed to the gateway IPv4 on port 53 (UDP or TCP), the packet is handled by the DNS service.
func (g *Gateway) TrySubmit(scope *ScopeHandle, ipv4Packet []byte) (handled bool, err error) {
	if scope == nil || scope.IsRetired() {
		return false, nil
	}
	if len(ipv4Packet) < 20 {
		return false, nil
	}

	// Verify IPv4 version.
	if (ipv4Packet[0] >> 4) != 4 {
		return false, nil
	}
	ihl := int(ipv4Packet[0]&0x0f) * 4
	if len(ipv4Packet) < ihl {
		return false, nil
	}

	// Verify destination IP matches gateway IP.
	dstIP := netip.AddrFrom4([4]byte{ipv4Packet[16], ipv4Packet[17], ipv4Packet[18], ipv4Packet[19]})
	if dstIP != g.cfg.Gateway.Addr() {
		return false, nil
	}

	proto := ipv4Packet[9]
	switch proto {
	case 17: // UDP
		return g.handleUDP(scope, ipv4Packet, ihl, dstIP)

	case 6: // TCP
		if len(ipv4Packet) < ihl+20 {
			return false, nil
		}
		dstPort := binary.BigEndian.Uint16(ipv4Packet[ihl+2 : ihl+4])
		if dstPort != 53 {
			return false, nil
		}
		tr, err := g.getOrCreateTransport(scope)
		if err != nil {
			return true, nil
		}
		tr.mu.Lock()
		if tr.closed.Load() {
			// Transport teardown already started; the device must not be
			// touched after its close.
			tr.mu.Unlock()
			return true, nil
		}
		_, _ = tr.vt.Write([][]byte{ipv4Packet}, 0)
		tr.mu.Unlock()
		return true, nil

	default:
		return false, nil
	}
}

// RetireScope releases the per-scope limiter bookkeeping immediately instead of
// waiting for the scope-context watcher. It is memory-only and never blocks, so
// a session-lifecycle owner may call it from a lock-protected retirement path;
// the scope's transport is still torn down by the watcher that owns it once the
// scope context is canceled.
func (g *Gateway) RetireScope(scope policy.Scope) {
	if g == nil || g.server == nil {
		return
	}
	g.server.RetireScope(scope)
}

// ActiveTransports returns the number of live per-scope gateway TCP transports.
func (g *Gateway) ActiveTransports() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.transports)
}

// ActiveSessionLimiters returns the number of live per-scope limiter entries.
func (g *Gateway) ActiveSessionLimiters() int {
	if g == nil || g.server == nil {
		return 0
	}
	return g.server.ActiveSessionLimiters()
}

// BeginRetire permanently retires scope handle, cancels query contexts, and invalidates session cache.
// Synchronous, memory-only, and idempotent.
func (g *Gateway) BeginRetire(scope *ScopeHandle) Retirement {
	if scope != nil {
		scope.Retire()
		g.server.RetireScope(scope.Scope)
		g.mu.Lock()
		var toClose *gatewayTCPTransport
		if tr, ok := g.transports[scope.Scope]; ok {
			delete(g.transports, scope.Scope)
			toClose = tr
		}
		g.mu.Unlock()
		if toClose != nil {
			toClose.Close()
		}
		return Retirement{Scope: scope.Scope}
	}
	return Retirement{}
}

// Close permanently closes all active gateway TCP transports.
func (g *Gateway) Close() error {
	g.mu.Lock()
	transports := make([]*gatewayTCPTransport, 0, len(g.transports))
	for scope, tr := range g.transports {
		delete(g.transports, scope)
		g.server.RetireScope(scope)
		transports = append(transports, tr)
	}
	g.mu.Unlock()
	for _, tr := range transports {
		tr.Close()
	}
	return nil
}

func buildIPv4UDPPacket(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, payload []byte) []byte {
	if len(payload) > 65507 {
		return nil
	}
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	// #nosec G115 -- totalLen is bounded by 20+8+65507 <= 65535
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF flag
	pkt[8] = 64                                  // TTL
	pkt[9] = 17                                  // Protocol UDP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	ipChecksum := calculateChecksum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	// UDP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	// #nosec G115 -- 8+len(payload) is bounded by 8+65507 <= 65535
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(pkt[26:28], 0) // Checksum optional
	copy(pkt[28:], payload)

	return pkt
}

func calculateChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
