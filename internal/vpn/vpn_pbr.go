package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

var (
	// ErrPBRMissingHostWAN indicates PBR cannot be enabled without a valid host WAN IPv4 address.
	ErrPBRMissingHostWAN = errors.New("vpn: pbr direct egress requires a valid host WAN IP")
	// ErrPBRMissingWANDevice indicates PBR cannot be enabled without an attached WAN packet device.
	ErrPBRMissingWANDevice = errors.New("vpn: pbr direct egress requires an attached WAN packet device")
	// ErrPBRMissingRouteCache indicates PBR cannot be enabled without a route cache decision source.
	ErrPBRMissingRouteCache = errors.New("vpn: pbr direct egress requires a route cache")
	// ErrPBRMissingPolicy indicates PBR cannot be enabled without a compiled policy matcher.
	ErrPBRMissingPolicy = errors.New("vpn: pbr direct egress requires a policy matcher")
)

// PBRConfig holds Policy-Based Routing direct egress configuration for Service.
type PBRConfig struct {
	Enabled       bool
	HostWANIP     netip.Addr
	GatewayDNSIP  netip.Addr
	WANDevice     forwarder.PacketDevice
	RouteCache    forwarder.RouteCache
	PolicyMatcher *policy.Matcher
	DNSGateway    *gatewaydns.Gateway
}

// ValidatePBRPrerequisites checks that all required direct egress components are present
// before PBR can be safely enabled. Fails closed if any prerequisite is missing.
func ValidatePBRPrerequisites(cfg PBRConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if !cfg.HostWANIP.IsValid() || !cfg.HostWANIP.Is4() || cfg.HostWANIP.IsUnspecified() || cfg.HostWANIP.IsLoopback() {
		return ErrPBRMissingHostWAN
	}
	if cfg.WANDevice == nil {
		return ErrPBRMissingWANDevice
	}
	if cfg.RouteCache == nil {
		return ErrPBRMissingRouteCache
	}
	if cfg.PolicyMatcher == nil {
		return ErrPBRMissingPolicy
	}
	return nil
}

// DeriveHostWANIP derives the real host WAN IPv4 address from the system routing table
// or network interfaces. It never falls back to hardcoded test addresses.
func DeriveHostWANIP() (netip.Addr, error) {
	// 1. Query outbound interface IP via UDP connect probe (does not send packets over the wire)
	conn, err := net.Dial("udp4", "1.1.1.1:80")
	if err == nil {
		defer conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil {
			if ip, ok := netip.AddrFromSlice(udpAddr.IP.To4()); ok && ip.IsValid() && ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip, nil
			}
		}
	}

	// 2. Fall back to inspecting system network interfaces
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil {
					continue
				}
				ip4 := ip.To4()
				if ip4 == nil {
					continue
				}
				if parsed, ok := netip.AddrFromSlice(ip4); ok && parsed.IsValid() && !parsed.IsLoopback() && !parsed.IsUnspecified() {
					return parsed, nil
				}
			}
		}
	}

	return netip.Addr{}, ErrPBRMissingHostWAN
}

// ConfigurePBR validates prerequisites and configures direct egress and policy-based routing on the service.
// Defaults to disabled (Enabled == false). Fails closed if enabled but prerequisites fail.
func (s *Service) ConfigurePBR(cfg PBRConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.forwarder == nil {
		return errors.New("vpn: forwarder unavailable")
	}

	// Default to disabled
	if !cfg.Enabled {
		s.forwarder.SetPBREnabled(false)
		if dem := s.forwarder.DirectEgress(); dem != nil {
			_ = dem.Close()
			s.forwarder.SetDirectEgress(nil)
		}
		return nil
	}

	// Validate prerequisites before enabling PBR
	if err := ValidatePBRPrerequisites(cfg); err != nil {
		s.forwarder.SetPBREnabled(false)
		return fmt.Errorf("pbr prerequisites: %w", err)
	}

	if mem, ok := cfg.RouteCache.(*MemoryRouteCache); ok {
		mem.AttachMatcher(cfg.PolicyMatcher)
	}

	dem := forwarder.NewDirectEgressManager(forwarder.DirectEgressConfig{
		HostWANIP:    cfg.HostWANIP,
		GatewayDNSIP: cfg.GatewayDNSIP,
		WANDevice:    cfg.WANDevice,
	}, s.forwarder)

	dem.AttachWANDevice(cfg.WANDevice)
	s.forwarder.SetDirectEgress(dem)
	s.forwarder.SetRouteCache(cfg.RouteCache)
	s.forwarder.SetPolicyMatcher(cfg.PolicyMatcher)
	if cfg.GatewayDNSIP.IsValid() {
		s.forwarder.SetGatewayDNSIP(cfg.GatewayDNSIP)
	}

	if cfg.DNSGateway != nil {
		if obs, ok := cfg.RouteCache.(gatewaydns.RouteObserver); ok {
			cfg.DNSGateway.SetObserver(obs)
		}
		if oldH := s.forwarder.DNSHandler(); oldH != nil {
			if closer, ok := oldH.(io.Closer); ok {
				_ = closer.Close()
			}
		}
		s.forwarder.SetDNSHandler(newPBRDNSHandler(cfg.DNSGateway, cfg.RouteCache))
	}

	servicePBRConfigsMu.Lock()
	servicePBRConfigs[s] = &cfg
	servicePBRConfigsMu.Unlock()

	s.forwarder.SetPBREnabled(true)
	return nil
}

// DNSGateway returns the DNS gateway configured on the service, if any.
func (s *Service) DNSGateway() *gatewaydns.Gateway {
	pbrCfg := s.getPBRConfig()
	if pbrCfg != nil {
		return pbrCfg.DNSGateway
	}
	return nil
}

type dnsJob struct {
	sessionID  string
	peerKey    string
	assignedIP string
	path       *forwarder.ReturnPath
	packet     []byte
}

type pbrDNSHandler struct {
	gw      *gatewaydns.Gateway
	rc      forwarder.RouteCache
	queue   chan dnsJob
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closed  atomic.Bool
	dropped atomic.Uint64
}

const (
	defaultDNSWorkerCount = 8
	defaultDNSQueueCap    = 256
)

func newPBRDNSHandler(gw *gatewaydns.Gateway, rc forwarder.RouteCache) *pbrDNSHandler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &pbrDNSHandler{
		gw:     gw,
		rc:     rc,
		queue:  make(chan dnsJob, defaultDNSQueueCap),
		ctx:    ctx,
		cancel: cancel,
	}
	h.wg.Add(defaultDNSWorkerCount)
	for i := 0; i < defaultDNSWorkerCount; i++ {
		go h.worker()
	}
	return h
}

func (h *pbrDNSHandler) Close() error {
	if h == nil {
		return nil
	}
	if h.closed.CompareAndSwap(false, true) {
		h.cancel()
		h.wg.Wait()
	}
	return nil
}

func (h *pbrDNSHandler) worker() {
	defer h.wg.Done()
	for {
		select {
		case <-h.ctx.Done():
			return
		case job, ok := <-h.queue:
			if !ok {
				return
			}
			h.processJob(job)
		}
	}
}

func (h *pbrDNSHandler) processJob(job dnsJob) {
	if h.gw == nil {
		return
	}
	writer := &pbrReplyWriter{
		path:       job.path,
		peerKey:    job.peerKey,
		assignedIP: job.assignedIP,
	}
	var sc *policy.SessionCache
	if opener, ok := h.rc.(interface{ Open(policy.Scope) (*policy.SessionCache, error) }); ok {
		sc, _ = opener.Open(policy.Scope{SessionID: job.sessionID, OwnershipEpoch: 1})
	}
	scope := gatewaydns.NewScopeHandle(
		h.ctx,
		policy.Scope{SessionID: job.sessionID, OwnershipEpoch: 1},
		sc,
		writer,
	)
	_, _ = h.gw.TrySubmit(scope, job.packet)
}

func (h *pbrDNSHandler) HandleDNSPacket(sessionID, peerKey, assignedIP string, path *forwarder.ReturnPath, packet []byte) (bool, error) {
	if h == nil || h.gw == nil || h.closed.Load() {
		return false, nil
	}
	if len(packet) < 20 {
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
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	if dstPort != 53 {
		return false, nil
	}

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	job := dnsJob{
		sessionID:  sessionID,
		peerKey:    peerKey,
		assignedIP: assignedIP,
		path:       path,
		packet:     pktCopy,
	}

	select {
	case h.queue <- job:
		return true, nil
	default:
		h.dropped.Add(1)
		return true, nil
	}
}

type pbrReplyWriter struct {
	path       *forwarder.ReturnPath
	peerKey    string
	assignedIP string
}

func (w *pbrReplyWriter) WritePacket(_ policy.Scope, packet []byte) error {
	if w.path == nil {
		return forwarder.ErrReturnPathClosed
	}
	_, err := w.path.Write(w.peerKey, w.assignedIP, packet)
	return err
}

// PBREnabled reports whether policy-based routing is active on the service.
func (s *Service) PBREnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwarder != nil && s.forwarder.PBREnabled()
}

// DirectEgress returns the DirectEgressManager configured on the forwarder, if any.
func (s *Service) DirectEgress() *forwarder.DirectEgressManager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.forwarder == nil {
		return nil
	}
	return s.forwarder.DirectEgress()
}

var (
	servicePBRConfigsMu sync.RWMutex
	servicePBRConfigs   = make(map[*Service]*PBRConfig)
)

// SetPBRConfig registers an explicit PBR configuration for service startup.
func (s *Service) SetPBRConfig(cfg PBRConfig) {
	servicePBRConfigsMu.Lock()
	defer servicePBRConfigsMu.Unlock()
	servicePBRConfigs[s] = &cfg
}

func (s *Service) getPBRConfig() *PBRConfig {
	servicePBRConfigsMu.RLock()
	defer servicePBRConfigsMu.RUnlock()
	return servicePBRConfigs[s]
}

// MemoryRouteCache provides an in-memory implementation of forwarder.RouteCache
// backed by authentic policy.RouteCache with PROXY-wins, CNAME, TTL, and generation invalidation.
type MemoryRouteCache struct {
	mu      sync.RWMutex
	rc      *policy.RouteCache
	matcher *policy.Matcher
	gen     string
}

// NewMemoryRouteCache creates an in-memory RouteCache backed by authentic policy.RouteCache.
func NewMemoryRouteCache() *MemoryRouteCache {
	rc, _ := policy.NewRouteCache(policy.CacheConfig{})
	const initialGen = "gen-initial"
	rc.SetPolicyGeneration(initialGen)
	m := policy.NewMatcher()
	initSrc := policy.NewMemorySource("default", policy.ParsedRules{})
	if snap, err := policy.CompileSnapshot(1, initialGen, []policy.SourceParsedRules{initSrc.ToSourceParsedRules()}); err == nil {
		m.Publish(snap)
	}
	return &MemoryRouteCache{
		rc:      rc,
		matcher: m,
		gen:     initialGen,
	}
}

// AttachMatcher connects the active policy matcher to the route cache for evaluating DNS observations.
func (c *MemoryRouteCache) AttachMatcher(m *policy.Matcher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matcher = m
	if m != nil {
		if snap := m.Current(); snap != nil && snap.Generation() != "" {
			c.gen = snap.Generation()
			c.rc.SetPolicyGeneration(c.gen)
		}
	}
}

// PolicyMatcher returns the attached policy matcher.
func (c *MemoryRouteCache) PolicyMatcher() *policy.Matcher {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.matcher
}

// Lookup queries the routing decision for a destination IP in the session scope.
func (c *MemoryRouteCache) Lookup(sessionID string, ip netip.Addr) policy.Decision {
	if c == nil || sessionID == "" || !ip.IsValid() || !ip.Is4() {
		return policy.Unknown
	}
	c.mu.Lock()
	if c.matcher != nil {
		if snap := c.matcher.Current(); snap != nil && snap.Generation() != "" && snap.Generation() != c.gen {
			c.gen = snap.Generation()
			c.rc.SetPolicyGeneration(c.gen)
		}
	}
	gen := c.gen
	sc, err := c.rc.Open(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
	c.mu.Unlock()

	if err != nil || sc == nil {
		return policy.Unknown
	}
	return sc.Lookup(ip, gen, time.Now())
}

// Set stores a routing decision for an IP in the session scope.
func (c *MemoryRouteCache) Set(sessionID string, ip netip.Addr, d policy.Decision) {
	if c == nil || sessionID == "" || !ip.IsValid() || !ip.Is4() {
		return
	}
	c.mu.Lock()
	gen := c.gen
	sc, err := c.rc.Open(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
	c.mu.Unlock()
	if err != nil || sc == nil {
		return
	}
	if d == policy.Direct || d == policy.Proxy {
		_ = sc.Observe(gen, []policy.Observation{
			{
				IP:        ip,
				Decision:  d,
				ExpiresAt: time.Now().Add(time.Hour),
			},
		}, time.Now())
	}
}

// Observe records a routing decision for an IP in the session scope.
func (c *MemoryRouteCache) Observe(sessionID string, ip netip.Addr, d policy.Decision) {
	c.Set(sessionID, ip, d)
}

// ObserveDNSResponse evaluates a DNS query and response pair against the policy matcher
// and feeds client-scoped route evidence directly into the route cache (Direct or Proxy).
func (c *MemoryRouteCache) ObserveDNSResponse(sessionID string, req, resp *mdns.Msg) error {
	if c == nil || req == nil || resp == nil || sessionID == "" {
		return nil
	}
	c.mu.Lock()
	if c.matcher != nil {
		if snap := c.matcher.Current(); snap != nil && snap.Generation() != "" && snap.Generation() != c.gen {
			c.gen = snap.Generation()
			c.rc.SetPolicyGeneration(c.gen)
		}
	}
	matcher := c.matcher
	sc, err := c.rc.Open(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
	c.mu.Unlock()
	if err != nil || sc == nil {
		return err
	}
	var snap *policy.Snapshot
	if matcher != nil {
		snap = matcher.Current()
	}
	if snap == nil {
		return nil
	}
	_, err = gatewaydns.ObserveResponse(req, resp, snap, sc, time.Now(), 3600*time.Second)
	return err
}

// Open opens or retrieves the session cache for the given scope.
func (c *MemoryRouteCache) Open(scope policy.Scope) (*policy.SessionCache, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rc.Open(scope)
}

// RouteCache returns the underlying authentic policy.RouteCache.
func (c *MemoryRouteCache) RouteCache() *policy.RouteCache {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rc
}

// SetPolicyGeneration updates the active policy generation string on the route cache.
func (c *MemoryRouteCache) SetPolicyGeneration(generation string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen = generation
	c.rc.SetPolicyGeneration(generation)
}

// ObserveDNSResponse records client DNS observations into the active route cache used by the forwarder.
func (s *Service) ObserveDNSResponse(sessionID string, req, resp *mdns.Msg) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.forwarder == nil {
		return nil
	}
	rc := s.forwarder.RouteCache()
	if rc == nil {
		return nil
	}
	if mem, ok := rc.(*MemoryRouteCache); ok {
		return mem.ObserveDNSResponse(sessionID, req, resp)
	}
	return nil
}

// ObserveDNSObservation records a direct route decision observation into the active route cache.
func (s *Service) ObserveDNSObservation(sessionID string, ip netip.Addr, decision policy.Decision) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.forwarder == nil {
		return
	}
	rc := s.forwarder.RouteCache()
	if rc == nil {
		return
	}
	if mem, ok := rc.(*MemoryRouteCache); ok {
		mem.Set(sessionID, ip, decision)
	}
}

func (s *Service) deriveDefaultGatewayDNSIP() netip.Addr {
	s.mu.RLock()
	subnet := ""
	if s.cfg != nil {
		subnet = s.cfg.SubnetCIDR
	}
	s.mu.RUnlock()
	if subnet != "" {
		if prefix, err := netip.ParsePrefix(subnet); err == nil {
			addr := prefix.Addr()
			b := addr.As4()
			b[3] = 1
			return netip.AddrFrom4(b)
		}
	}
	return netip.MustParseAddr("10.100.0.1")
}

func initDefaultDNSGateway(gwDNS netip.Addr, matcher *policy.Matcher, rc forwarder.RouteCache) *gatewaydns.Gateway {
	upstreams := []netip.AddrPort{
		netip.MustParseAddrPort("1.1.1.1:53"),
		netip.MustParseAddrPort("8.8.8.8:53"),
	}
	resolver, err := gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{
		Upstreams: upstreams,
	})
	if err != nil {
		return nil
	}
	dnsSrv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{
		Gateway: netip.AddrPortFrom(gwDNS, 53),
	}, resolver, matcher)
	if err != nil {
		return nil
	}
	var obs gatewaydns.RouteObserver
	if ro, ok := rc.(gatewaydns.RouteObserver); ok {
		obs = ro
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{
		Gateway:       netip.AddrPortFrom(gwDNS, 53),
		RouteObserver: obs,
	}, dnsSrv)
	if err != nil {
		return nil
	}
	return gw
}

// initPBR initializes and configures policy-based routing on the service during startup.
// It instantiates concrete WAN transport, route cache, and policy matcher if not already configured.
// It fails closed if prerequisites or initialization fails.
func (s *Service) initPBR(ctx context.Context) error {
	pbrCfg := s.getPBRConfig()
	var cfg PBRConfig
	if pbrCfg != nil {
		cfg = *pbrCfg
	}
	cfg.Enabled = true

	// 1. Host WAN IP: derive if not set (in default production startup)
	if !cfg.HostWANIP.IsValid() {
		if pbrCfg == nil {
			derived, err := DeriveHostWANIP()
			if err != nil {
				return fmt.Errorf("derive host wan ip: %w", err)
			}
			cfg.HostWANIP = derived
		}
	}

	// 2. Gateway DNS IP: derive if not set
	if !cfg.GatewayDNSIP.IsValid() {
		cfg.GatewayDNSIP = s.deriveDefaultGatewayDNSIP()
	}

	// 3. WAN PacketDevice: instantiate production TUN device if not already provided
	if cfg.WANDevice == nil {
		wanDev, err := NewProductionWANDevice("nexus-wan0")
		if err != nil {
			return fmt.Errorf("create production wan device: %w", err)
		}
		if dev, ok := wanDev.(interface{ SetHostWANIP(netip.Addr) }); ok && cfg.HostWANIP.IsValid() {
			dev.SetHostWANIP(cfg.HostWANIP)
		}
		cfg.WANDevice = wanDev
	}

	// 4. Policy Matcher: instantiate and compile initial snapshot with valid sources if not provided
	if cfg.PolicyMatcher == nil {
		matcher := policy.NewMatcher()
		initialSrc := policy.NewMemorySource("default-production-policy", policy.ParsedRules{})
		snap, err := policy.CompileSnapshot(1, "gen-initial", []policy.SourceParsedRules{initialSrc.ToSourceParsedRules()})
		if err != nil {
			if cfg.WANDevice != nil {
				_ = cfg.WANDevice.Close()
			}
			return fmt.Errorf("compile initial policy snapshot: %w", err)
		}
		matcher.Publish(snap)
		cfg.PolicyMatcher = matcher
	}

	// 5. Route Cache: instantiate in-memory route cache if not provided and connect to matcher
	if cfg.RouteCache == nil {
		memCache := NewMemoryRouteCache()
		memCache.AttachMatcher(cfg.PolicyMatcher)
		cfg.RouteCache = memCache
	} else if mem, ok := cfg.RouteCache.(*MemoryRouteCache); ok {
		mem.AttachMatcher(cfg.PolicyMatcher)
	}

	// 5b. DNS Gateway: instantiate DNS gateway if not provided and connect RouteCache observer
	if cfg.DNSGateway == nil && cfg.GatewayDNSIP.IsValid() {
		cfg.DNSGateway = initDefaultDNSGateway(cfg.GatewayDNSIP, cfg.PolicyMatcher, cfg.RouteCache)
	}

	// 6. Configure PBR on Service (fails closed if prerequisite validation fails)
	if err := s.ConfigurePBR(cfg); err != nil {
		if cfg.WANDevice != nil {
			_ = cfg.WANDevice.Close()
		}
		return fmt.Errorf("configure pbr: %w", err)
	}

	return nil
}

// TeardownPBR disables PBR and cleanly closes the DirectEgressManager.
func (s *Service) TeardownPBR() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	servicePBRConfigsMu.Lock()
	delete(servicePBRConfigs, s)
	servicePBRConfigsMu.Unlock()

	if s.forwarder == nil {
		return nil
	}
	if oldH := s.forwarder.DNSHandler(); oldH != nil {
		if closer, ok := oldH.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	s.forwarder.SetDNSHandler(nil)
	s.forwarder.SetPBREnabled(false)
	if dem := s.forwarder.DirectEgress(); dem != nil {
		_ = dem.Close()
		s.forwarder.SetDirectEgress(nil)
	}
	return nil
}
