package vpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
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

	// If HostWANIP is not set, derive from host interfaces
	if !cfg.HostWANIP.IsValid() {
		derived, err := DeriveHostWANIP()
		if err != nil {
			s.forwarder.SetPBREnabled(false)
			return fmt.Errorf("derive host wan ip: %w", err)
		}
		cfg.HostWANIP = derived
	}

	// Validate prerequisites before enabling PBR
	if err := ValidatePBRPrerequisites(cfg); err != nil {
		s.forwarder.SetPBREnabled(false)
		return fmt.Errorf("pbr prerequisites: %w", err)
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

// TeardownPBR disables PBR and cleanly closes the DirectEgressManager.
func (s *Service) TeardownPBR() error {
	s.mu.Lock()
	defer s.mu.Unlock()

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
