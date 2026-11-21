package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

var (
	// ErrPBRMissingHostWAN indicates PBR cannot be enabled without a valid host WAN IPv4 address.
	ErrPBRMissingHostWAN = errors.New("vpn: pbr direct egress requires a valid host WAN IP")
	// ErrPBRMissingWANDevice indicates PBR cannot be enabled without an attached WAN packet device.
	ErrPBRMissingWANDevice = errors.New("vpn: pbr direct egress requires an attached WAN packet device")
	// ErrPBRMissingPolicy indicates PBR cannot be enabled without a compiled policy matcher.
	ErrPBRMissingPolicy = errors.New("vpn: pbr direct egress requires a policy matcher")
	// ErrPBREmptyPolicy indicates PBR cannot be enabled with an empty or uncompiled policy snapshot.
	ErrPBREmptyPolicy = errors.New("vpn: pbr direct egress requires a non-empty policy snapshot")
)

// PBRConfig holds Policy-Based Routing direct egress configuration for Service.
type PBRConfig struct {
	Enabled       bool
	HostWANIP     netip.Addr
	WANDevice     forwarder.PacketDevice
	PolicyMatcher *policy.Matcher
	PolicySources []policy.SourceParsedRules
	// UpstreamDNS is the validated upstream list the resolver is dialed with.
	// Empty means the effective defaults (policy.DefaultUpstreams()).
	UpstreamDNS []policy.Upstream
	// DNSResolver holds the configured upstream resolver. It is kept here so the
	// policy status can report the last upstream outcome, and so a live settings
	// change can swap the upstream list. The panel serves no client DNS, so the
	// resolver answers no query of its own; it carries the configured list.
	DNSResolver *gatewaydns.UpstreamResolver
	// InventoryOverride is the accepted operator override the classifier applies
	// on top of the committed allocation inventory. Nil keeps the shipped set as
	// the only authority, which is the behavior when no override is configured.
	InventoryOverride *policy.InventoryOverride
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
	if cfg.PolicyMatcher == nil {
		return ErrPBRMissingPolicy
	}
	snap := cfg.PolicyMatcher.Current()
	if snap == nil || (snap.DomainCount() == 0 && snap.CIDRCount() == 0) {
		return ErrPBREmptyPolicy
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

	// Default to disabled. The classifier and direct egress belong to the data
	// path that routes on them, so a disabled configuration installs neither and
	// no stale classification survives into the next activation.
	if !cfg.Enabled {
		s.forwarder.SetPBREnabled(false)
		// The classifier belongs to the data path that routes on it: with policy
		// routing off, no packet consults it and no stale classification survives
		// into the next activation.
		s.forwarder.SetDestinationClassifier(nil)
		if dem := s.forwarder.DirectEgress(); dem != nil {
			_ = dem.Close()
			s.forwarder.SetDirectEgress(nil)
		}
		return nil
	}

	// Validate prerequisites before enabling PBR
	if err := ValidatePBRPrerequisites(cfg); err != nil {
		// A refused activation is a transition to disabled.
		s.forwarder.SetPBREnabled(false)
		return fmt.Errorf("pbr prerequisites: %w", err)
	}

	dem := forwarder.NewDirectEgressManager(forwarder.DirectEgressConfig{
		HostWANIP: cfg.HostWANIP,
		WANDevice: cfg.WANDevice,
	}, s.forwarder)

	s.forwarder.SetDirectEgress(dem)
	s.forwarder.SetPolicyMatcher(cfg.PolicyMatcher)
	s.forwarder.SetDestinationClassifier(newDestinationClassifier(cfg.InventoryOverride))
	// The recorded override and the installed classifier are written together:
	// the status then describes the set the packet path is actually consulting,
	// including while a later save is still being applied.
	s.inventoryOverride = cfg.InventoryOverride

	servicePBRConfigsMu.Lock()
	servicePBRConfigs[s] = &cfg
	servicePBRConfigsMu.Unlock()

	// The resolver built for this activation is the authority for what is
	// configured, so the owned list is taken from it rather than from the
	// activation input: every later consumer (live change, a later activation)
	// reads this one field.
	if cfg.DNSResolver != nil {
		s.dnsUpstreams = cfg.DNSResolver.Upstreams()
	}

	s.forwarder.SetPBREnabled(true)
	return nil
}

// publishPBRUpstreamsLocked records upstreams as the registered activation input
// and on the service, replacing the previous value rather than mutating it, so a
// concurrent reader of either sees one coherent list and never the value the
// activation started with. The caller holds s.mu.
func (s *Service) publishPBRUpstreamsLocked(upstreams []policy.Upstream) {
	s.dnsUpstreams = upstreams
	servicePBRConfigsMu.Lock()
	defer servicePBRConfigsMu.Unlock()
	cfg := servicePBRConfigs[s]
	if cfg == nil {
		return
	}
	next := *cfg
	next.UpstreamDNS = upstreams
	servicePBRConfigs[s] = &next
}

// EffectiveDNSUpstreams returns the effective upstream list this service has
// accepted for its policy resolver. An empty result means nothing has been
// accepted yet, which the consumers treat as the effective defaults. The
// slice is a copy.
func (s *Service) EffectiveDNSUpstreams() []policy.Upstream {
	if s == nil {
		return policy.DefaultUpstreams()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.dnsUpstreams) == 0 {
		return policy.DefaultUpstreams()
	}
	out := make([]policy.Upstream, len(s.dnsUpstreams))
	copy(out, s.dnsUpstreams)
	return out
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

// newPolicyUpstreamResolver builds the upstream resolver from the configured
// list, falling back to the effective defaults when no list is configured.
// A list that cannot be dialed safely is returned as an error rather than
// silently leaving the resolver unset: policy routing without a working
// resolver produces no evidence at all, which is the failure this configuration
// exists to remove.
//
// It is a package-level variable so a test can substitute a constructor for the
// same reason newDNSContinuityResolver is one: the production resolver validates
// loopback upstreams away, and an encrypted local fixture can only be reached
// through a wrapper that calls NewUpstreamResolver on the configuration this
// function actually receives. Production always runs the value below.
var newPolicyUpstreamResolver = func(configured []policy.Upstream) (*gatewaydns.UpstreamResolver, error) {
	upstreams := configured
	if len(upstreams) == 0 {
		upstreams = policy.DefaultUpstreams()
	}
	resolver, err := gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{Upstreams: upstreams})
	if err != nil {
		return nil, fmt.Errorf("upstream dns configuration: %w", err)
	}
	return resolver, nil
}

// newProductionWANDevice is the substitution point for the production WAN device
// constructor. Production always uses NewProductionWANDevice; tests swap it to
// model the kernel's device-name lifetime (one owner per name) without a TUN
// capability. Same pattern as defaultIPTablesRunner in wan_device_linux.go.
var newProductionWANDevice = NewProductionWANDevice

func initPBRWANDevice(cfg *PBRConfig) error {
	if cfg.WANDevice == nil {
		wanDev, err := newProductionWANDevice("nexus-wan0")
		if err != nil {
			return fmt.Errorf("create production wan device: %w", err)
		}
		cfg.WANDevice = wanDev
	}
	if dev, ok := cfg.WANDevice.(interface{ SetHostWANIP(netip.Addr) error }); ok && cfg.HostWANIP.IsValid() {
		if err := dev.SetHostWANIP(cfg.HostWANIP); err != nil {
			_ = cfg.WANDevice.Close()
			return fmt.Errorf("configure wan device host wan ip: %w", err)
		}
	}
	return nil
}

func initPBRPolicyMatcher(cfg *PBRConfig) error {
	if cfg.PolicyMatcher == nil {
		sources := cfg.PolicySources
		if len(sources) == 0 {
			if cfg.WANDevice != nil {
				_ = cfg.WANDevice.Close()
			}
			return ErrPBREmptyPolicy
		}
		matcher := policy.NewMatcher()
		snap, err := policy.CompileSnapshot(1, "gen-initial", sources)
		if err != nil {
			if cfg.WANDevice != nil {
				_ = cfg.WANDevice.Close()
			}
			return fmt.Errorf("compile initial policy snapshot: %w", err)
		}
		if snap.DomainCount() == 0 && snap.CIDRCount() == 0 {
			if cfg.WANDevice != nil {
				_ = cfg.WANDevice.Close()
			}
			return ErrPBREmptyPolicy
		}
		matcher.Publish(snap)
		cfg.PolicyMatcher = matcher
		return nil
	}
	snap := cfg.PolicyMatcher.Current()
	if snap == nil || (snap.DomainCount() == 0 && snap.CIDRCount() == 0) {
		if cfg.WANDevice != nil {
			_ = cfg.WANDevice.Close()
		}
		return ErrPBREmptyPolicy
	}
	return nil
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
	if !cfg.HostWANIP.IsValid() && pbrCfg == nil {
		derived, err := DeriveHostWANIP()
		if err != nil {
			return fmt.Errorf("derive host wan ip: %w", err)
		}
		cfg.HostWANIP = derived
	}

	// 2. WAN PacketDevice: instantiate production TUN device if not already provided
	if err := initPBRWANDevice(&cfg); err != nil {
		return err
	}

	// 3. Policy Matcher: instantiate and compile initial snapshot with valid configured sources if not provided
	if err := initPBRPolicyMatcher(&cfg); err != nil {
		return err
	}

	// 4. Upstream resolver: build it from the configured upstream list (the
	// persisted policy settings, when this activation came from them) so a
	// blocked provider is a settings change rather than a code change. The panel
	// serves no client DNS, so this resolver answers no query of its own; it
	// carries the configured list and its last outcome for the operator surface.
	if cfg.DNSResolver == nil {
		resolver, err := newPolicyUpstreamResolver(cfg.UpstreamDNS)
		if err != nil {
			if cfg.WANDevice != nil {
				_ = cfg.WANDevice.Close()
			}
			return err
		}
		cfg.DNSResolver = resolver
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
	pbrCfg := servicePBRConfigs[s]
	delete(servicePBRConfigs, s)
	servicePBRConfigsMu.Unlock()

	if pbrCfg != nil && pbrCfg.WANDevice != nil {
		_ = pbrCfg.WANDevice.Close()
	}

	if s.forwarder == nil {
		return nil
	}
	// A teardown removes what the data path installed, so a disabled router
	// leaves no stale classification and no direct-egress manager behind.
	s.forwarder.SetPBREnabled(false)
	s.forwarder.SetDestinationClassifier(nil)
	if dem := s.forwarder.DirectEgress(); dem != nil {
		_ = dem.Close()
		s.forwarder.SetDirectEgress(nil)
	}
	return nil
}

// newDestinationClassifier joins the two committed inputs the routing contract
// needs for a destination address (issue #918): the allocation inventory
// answers "inside the Russian allocation" and the embedded ASN table answers
// "known multi-region CDN".
//
// The override is the operator's accepted correction of the allocation set
// (issue #920). It is applied as a layer over the shipped inventory rather than
// replacing it, so an address it does not name keeps the committed answer.
//
// Both are compiled into the binary, so building this costs no I/O and no
// network. A failure leaves the classifier uninstalled, and the contract then
// answers uncovered for every destination: nothing routes DIRECT and every
// packet keeps the fail-safe proxy default. The refusal is logged rather than
// swallowed, and the inventory's own status field already reports a broken
// artifact to the operator — "the artifact is broken" and "no address is
// Russian" must never look the same.
func newDestinationClassifier(override *policy.InventoryOverride) forwarder.DestinationClassifier {
	inventory, err := policy.ShippedInventory()
	if err != nil {
		slog.Warn("Address classifier unavailable: committed allocation inventory is unusable", "err", err)
		return nil
	}
	geo, err := geodb.DefaultGeoDB()
	if err != nil {
		slog.Warn("Address classifier unavailable: embedded ASN table is unusable", "err", err)
		return nil
	}
	classifier, err := policy.NewAddressClassifier(inventory.WithOverride(override), geo)
	if err != nil {
		slog.Warn("Address classifier unavailable", "err", err)
		return nil
	}
	return classifier
}

// UpdatePolicySnapshot compiles and atomically publishes new policy sources.
// If compilation or validation fails, it preserves the last valid compiled snapshot (HIGH 3).
func (s *Service) UpdatePolicySnapshot(version uint64, genID string, sources []policy.SourceParsedRules) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pbrCfg := s.getPBRConfig()
	if pbrCfg == nil || pbrCfg.PolicyMatcher == nil {
		return errors.New("vpn: policy matcher not initialized")
	}
	if len(sources) == 0 {
		return errors.New("vpn: cannot update policy with zero sources")
	}
	newSnap, err := policy.CompileSnapshot(version, genID, sources)
	if err != nil {
		return fmt.Errorf("compile policy snapshot: %w (retaining existing snapshot)", err)
	}
	if newSnap.DomainCount() == 0 && newSnap.CIDRCount() == 0 {
		return errors.New("vpn: compiled snapshot contains no rules (retaining existing snapshot)")
	}
	pbrCfg.PolicyMatcher.Publish(newSnap)
	return nil
}
