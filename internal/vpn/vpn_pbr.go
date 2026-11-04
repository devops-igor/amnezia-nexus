package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
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

	s.forwarder.SetPBREnabled(true)
	return nil
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

// MemoryRouteCache provides an in-memory implementation of forwarder.RouteCache.
type MemoryRouteCache struct {
	mu        sync.RWMutex
	decisions map[string]map[netip.Addr]policy.Decision
	matcher   *policy.Matcher
}

// NewMemoryRouteCache creates an in-memory RouteCache.
func NewMemoryRouteCache() *MemoryRouteCache {
	return &MemoryRouteCache{
		decisions: make(map[string]map[netip.Addr]policy.Decision),
	}
}

// AttachMatcher connects the active policy matcher to the route cache for evaluating DNS observations.
func (c *MemoryRouteCache) AttachMatcher(m *policy.Matcher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matcher = m
}

// PolicyMatcher returns the attached policy matcher.
func (c *MemoryRouteCache) PolicyMatcher() *policy.Matcher {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.matcher
}

// Lookup queries the routing decision for a destination IP in the session scope.
func (c *MemoryRouteCache) Lookup(sessionID string, ip netip.Addr) policy.Decision {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if sess, ok := c.decisions[sessionID]; ok {
		if d, ok := sess[ip]; ok {
			return d
		}
	}
	return policy.Unknown
}

// Set stores a routing decision for an IP in the session scope.
func (c *MemoryRouteCache) Set(sessionID string, ip netip.Addr, d policy.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decisions[sessionID] == nil {
		c.decisions[sessionID] = make(map[netip.Addr]policy.Decision)
	}
	c.decisions[sessionID][ip] = d
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
	c.mu.RLock()
	matcher := c.matcher
	c.mu.RUnlock()

	var snap *policy.Snapshot
	if matcher != nil {
		snap = matcher.Current()
	}

	qName := ""
	if len(req.Question) > 0 {
		qName = req.Question[0].Name
	}

	requiresProxy := false
	if snap != nil && qName != "" {
		requiresProxy = snap.MatchDomain(qName)
	}

	for _, ans := range resp.Answer {
		if aRec, ok := ans.(*mdns.A); ok {
			ip, ok := netip.AddrFromSlice(aRec.A)
			if !ok || !ip.IsValid() || !ip.Is4() {
				continue
			}
			decision := policy.Direct
			if requiresProxy || (snap != nil && snap.MatchIPv4(ip)) {
				decision = policy.Proxy
			}
			c.Set(sessionID, ip, decision)
		}
	}
	return nil
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
		s.mu.RLock()
		subnet := ""
		if s.cfg != nil {
			subnet = s.cfg.SubnetCIDR
		}
		s.mu.RUnlock()
		if subnet != "" {
			if prefix, err := netip.ParsePrefix(subnet); err == nil {
				// Gateway is standard first host in client subnet (.1)
				addr := prefix.Addr()
				b := addr.As4()
				b[3] = 1
				cfg.GatewayDNSIP = netip.AddrFrom4(b)
			}
		}
		if !cfg.GatewayDNSIP.IsValid() {
			cfg.GatewayDNSIP = netip.MustParseAddr("10.100.0.1")
		}
	}

	// 3. WAN PacketDevice: instantiate production TUN device if not already provided
	if cfg.WANDevice == nil {
		wanDev, err := NewProductionWANDevice("nexus-wan0")
		if err != nil {
			return fmt.Errorf("create production wan device: %w", err)
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
	s.forwarder.SetPBREnabled(false)
	if dem := s.forwarder.DirectEgress(); dem != nil {
		_ = dem.Close()
		s.forwarder.SetDirectEgress(nil)
	}
	return nil
}
