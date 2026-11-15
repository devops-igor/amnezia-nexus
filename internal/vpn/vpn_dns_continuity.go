package vpn

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// DNS continuity for configurations issued while policy routing was active.
//
// A generated client configuration that names the tunnel gateway as its only
// resolver keeps that address after policy routing is disabled. The policy
// resolver is a gateway-address-only responder that outlives the classifier and
// direct-egress lifetime: it answers queries addressed to the gateway DNS
// address over UDP and TCP, it never intercepts external port 53, and it writes
// no routing evidence, so it can never grant DIRECT authority.
//
// Newly generated configurations while policy routing is inactive keep the
// legacy external defaults; continuity only serves profiles that already name
// the gateway.

// defaultPolicyUpstreams returns the plain-DNS upstreams used by the policy
// resolver and by the continuity responder, in failover order. The pair matches
// the addresses client configurations push, so an active profile and a
// continuity profile resolve through the same provider.
func defaultPolicyUpstreams() []netip.AddrPort {
	return []netip.AddrPort{
		netip.MustParseAddrPort("94.140.14.14:53"),
		netip.MustParseAddrPort("94.140.15.15:53"),
	}
}

// newDNSContinuityResolver builds the upstream resolver of the continuity
// responder. Tests substitute it to keep resolution deterministic without
// network access, exactly like newProductionWANDevice.
var newDNSContinuityResolver = func(cfg gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
	return gatewaydns.NewUpstreamResolver(cfg)
}

// dnsContinuityService owns the responder that survives policy-routing
// disablement. Guarded by Service.mu.
type dnsContinuityService struct {
	gateway *gatewaydns.Gateway
	addr    netip.Addr
	handler *dnsContinuityHandler
}

func (c *dnsContinuityService) close() {
	if c == nil {
		return
	}
	if c.handler != nil {
		_ = c.handler.Close()
		c.handler = nil
	}
	if c.gateway != nil {
		_ = c.gateway.Close()
		c.gateway = nil
	}
}

// newContinuityDNSGateway builds a gateway-address-only responder. It is
// constructed without a policy source and without a route observer, so answers
// can never be classified into routing evidence.
func newContinuityDNSGateway(addr netip.Addr) *gatewaydns.Gateway {
	if !validGatewayDNSAddr(addr) {
		return nil
	}
	resolver, err := newDNSContinuityResolver(gatewaydns.ResolverConfig{Upstreams: defaultPolicyUpstreams()})
	if err != nil || resolver == nil {
		return nil
	}
	gwAddr := netip.AddrPortFrom(addr, 53)
	srv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{Gateway: gwAddr}, resolver, nil)
	if err != nil {
		return nil
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{Gateway: gwAddr}, srv)
	if err != nil {
		return nil
	}
	return gw
}

func validGatewayDNSAddr(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4() && !addr.IsUnspecified() && !addr.IsLoopback() && !addr.IsMulticast()
}

const (
	dnsContinuityWorkerCount = 4
	dnsContinuityQueueCap    = 128
	// dnsContinuityMaxSessions bounds the per-session reply authority the
	// continuity responder retains. It mirrors the intercepted-DNS handler's
	// bounded state instead of growing with every session that ever queried.
	dnsContinuityMaxSessions = 256
)

// dnsContinuityHandler answers gateway-addressed plain DNS while policy routing
// is inactive. It reuses the intercepted-DNS worker pattern (bounded queue,
// fixed workers started on first use) but is deliberately independent of the
// route cache: it resolves no session scope and records no observation.
type dnsContinuityHandler struct {
	gw          *gatewaydns.Gateway
	sessionLive func(sessionID string) bool
	queue       chan dnsJob
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	startOnce   sync.Once
	closed      atomic.Bool
	dropped     atomic.Uint64

	mu       sync.Mutex
	sessions map[string]*dnsContinuitySession
}

type dnsContinuitySession struct {
	runtime  *dnsSessionRuntime
	lastUsed time.Time
}

func newDNSContinuityHandler(gw *gatewaydns.Gateway, sessionLive func(sessionID string) bool) *dnsContinuityHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &dnsContinuityHandler{
		gw:          gw,
		sessionLive: sessionLive,
		queue:       make(chan dnsJob, dnsContinuityQueueCap),
		ctx:         ctx,
		cancel:      cancel,
		sessions:    make(map[string]*dnsContinuitySession),
	}
}

func (h *dnsContinuityHandler) Close() error {
	if h == nil {
		return nil
	}
	if h.closed.CompareAndSwap(false, true) {
		h.cancel()
		h.mu.Lock()
		sessions := make([]*dnsContinuitySession, 0, len(h.sessions))
		for sessionID, sess := range h.sessions {
			delete(h.sessions, sessionID)
			sessions = append(sessions, sess)
		}
		h.mu.Unlock()
		for _, sess := range sessions {
			h.retireRuntime(sess.runtime)
		}
		h.wg.Wait()
	}
	return nil
}

// HandleDNSPacket admits a gateway-addressed plain DNS packet into the bounded
// continuity queue. Non-DNS or non-IP packets are refused so the caller can keep
// its existing routing.
func (h *dnsContinuityHandler) HandleDNSPacket(sessionID, peerKey, assignedIP string, path *forwarder.ReturnPath, packet []byte) (bool, error) {
	if h == nil || h.gw == nil || h.closed.Load() {
		return false, nil
	}
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return false, nil
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 {
		return false, nil
	}
	proto := packet[9]
	if proto != 17 && proto != 6 {
		return false, nil
	}
	if binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) != 53 {
		return false, nil
	}

	h.startWorkers()
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)
	select {
	case h.queue <- dnsJob{
		sessionID:  sessionID,
		peerKey:    peerKey,
		assignedIP: assignedIP,
		path:       path,
		packet:     pktCopy,
	}:
		return true, nil
	default:
		h.dropped.Add(1)
		return true, nil
	}
}

// startWorkers launches the fixed worker set on first use, so a service whose
// policy routing is disabled and whose clients never query retains no
// goroutines.
func (h *dnsContinuityHandler) startWorkers() {
	h.startOnce.Do(func() {
		h.wg.Add(dnsContinuityWorkerCount)
		for i := 0; i < dnsContinuityWorkerCount; i++ {
			go h.worker()
		}
	})
}

func (h *dnsContinuityHandler) worker() {
	defer h.wg.Done()
	for {
		select {
		case <-h.ctx.Done():
			return
		case job := <-h.queue:
			h.processJob(job)
		}
	}
}

func (h *dnsContinuityHandler) processJob(job dnsJob) {
	if h.gw == nil || h.closed.Load() {
		return
	}
	if h.sessionLive != nil && !h.sessionLive(job.sessionID) {
		h.retireSession(job.sessionID)
		return
	}
	rt := h.runtime(job)
	if rt == nil {
		return
	}
	// A session may have retired while its authority was being replaced. Never
	// answer for a session that no longer owns a route.
	if h.sessionLive != nil && !h.sessionLive(job.sessionID) {
		h.retireSession(job.sessionID)
		return
	}
	_, _ = h.gw.TrySubmit(rt.handle, job.packet)
}

// authorityUsable reports whether a cached continuity authority can still answer
// for its session: it has not been retired and its context is not canceled.
// The gateway retires the handle when a reply cannot be delivered (for example
// one recoverable return-queue failure) while the session itself stays live.
func authorityUsable(handle *gatewaydns.ScopeHandle) bool {
	return handle != nil && !handle.IsRetired() && handle.Context().Err() == nil
}

// runtime returns the reply authority of one session, creating it on first use
// and replacing one the gateway retired while the session stayed live. The scope
// handle carries no session cache, so the responder cannot record routing
// evidence even though it shares the gateway transport.
func (h *dnsContinuityHandler) runtime(job dnsJob) *dnsSessionRuntime {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed.Load() {
		return nil
	}
	if sess := h.sessions[job.sessionID]; sess != nil {
		if authorityUsable(sess.runtime.handle) {
			sess.lastUsed = now
			sess.runtime.writer.setTarget(job)
			return sess.runtime
		}
		// The gateway retired this authority while the session remained live.
		// Retire it synchronously so its canceled transport cannot be reused by
		// the replacement (the transport is keyed by the session scope), then
		// publish fresh authority for the same session.
		h.retireRuntime(sess.runtime)
		delete(h.sessions, job.sessionID)
	} else if len(h.sessions) >= dnsContinuityMaxSessions {
		h.evictOldestLocked()
	}
	writer := &pbrReplyWriter{}
	writer.setTarget(job)
	handle := gatewaydns.NewScopeHandle(h.ctx, policy.Scope{SessionID: job.sessionID, OwnershipEpoch: 1}, nil, writer)
	writer.handle.Store(handle)
	rt := &dnsSessionRuntime{handle: handle, writer: writer}
	h.sessions[job.sessionID] = &dnsContinuitySession{runtime: rt, lastUsed: now}
	return rt
}

// evictOldestLocked drops the least recently used session authority so the map
// stays bounded. The caller holds h.mu, and no live session is evicted before a
// longer-idle one.
func (h *dnsContinuityHandler) evictOldestLocked() {
	var oldestID string
	var oldestAt time.Time
	for sessionID, sess := range h.sessions {
		if oldestAt.IsZero() || sess.lastUsed.Before(oldestAt) {
			oldestID, oldestAt = sessionID, sess.lastUsed
		}
	}
	if oldestID == "" {
		return
	}
	sess := h.sessions[oldestID]
	delete(h.sessions, oldestID)
	// Retiring cancels the scope context, so the gateway transport owned by it
	// is torn down by its watcher; doing it under h.mu keeps only memory-only
	// bookkeeping here. Retirement is idempotent.
	h.retireRuntime(sess.runtime)
}

func (h *dnsContinuityHandler) retireSession(sessionID string) {
	h.mu.Lock()
	sess := h.sessions[sessionID]
	if sess == nil {
		h.mu.Unlock()
		return
	}
	delete(h.sessions, sessionID)
	h.mu.Unlock()
	h.retireRuntime(sess.runtime)
}

func (h *dnsContinuityHandler) retireRuntime(rt *dnsSessionRuntime) {
	if rt == nil {
		return
	}
	if h.gw != nil {
		// BeginRetire is synchronous: it retires the handle, releases the
		// server scope and closes the gateway transport owned by that scope, so
		// no canceled authority or transport outlives its replacement.
		h.gw.BeginRetire(rt.handle)
		return
	}
	rt.handle.Retire()
}

// installDNSContinuity installs the gateway-address-only responder that serves
// configurations issued while policy routing was active. Idempotent.
func (s *Service) installDNSContinuity() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.installDNSContinuityLocked(s.deriveGatewayDNSIPLocked())
}

// installDNSContinuityLocked installs the continuity responder and makes it the
// forwarder's DNS handler, closing the handler it replaces. The caller holds
// s.mu. A responder already serving the same address keeps its handler, so a
// repeated disable cannot drop queries in flight.
func (s *Service) installDNSContinuityLocked(addr netip.Addr) {
	if s == nil || s.forwarder == nil || !validGatewayDNSAddr(addr) {
		return
	}
	continuity := s.dnsContinuity
	if continuity == nil || continuity.addr != addr {
		if continuity != nil {
			continuity.close()
		}
		gw := newContinuityDNSGateway(addr)
		if gw == nil {
			s.dnsContinuity = nil
			return
		}
		continuity = &dnsContinuityService{gateway: gw, addr: addr}
		s.dnsContinuity = continuity
	}
	s.forwarder.SetGatewayDNSIP(addr)
	if installed, ok := s.forwarder.DNSHandler().(*dnsContinuityHandler); ok && installed == continuity.handler {
		return
	}
	if old := s.forwarder.DNSHandler(); old != nil {
		if closer, ok := old.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	continuity.handler = newDNSContinuityHandler(continuity.gateway, s.forwarder.HasLiveSession)
	s.forwarder.SetDNSHandler(continuity.handler)
}

// closeDNSContinuity releases the continuity responder on service shutdown,
// including the handler installed on the forwarder.
func (s *Service) closeDNSContinuity() {
	if s == nil {
		return
	}
	s.mu.Lock()
	continuity := s.dnsContinuity
	s.dnsContinuity = nil
	if s.forwarder != nil && continuity != nil && continuity.handler != nil {
		if installed, ok := s.forwarder.DNSHandler().(*dnsContinuityHandler); ok && installed == continuity.handler {
			s.forwarder.SetDNSHandler(nil)
		}
	}
	s.mu.Unlock()
	continuity.close()
}
