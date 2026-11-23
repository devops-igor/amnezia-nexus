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
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

var (
	// ErrPBRMissingHostWAN indicates PBR cannot be enabled without a valid host WAN IPv4 address.
	ErrPBRMissingHostWAN = errors.New("vpn: pbr direct egress requires a valid host WAN IP")
	// ErrPBRMissingWANDevice indicates PBR cannot be enabled without an attached WAN packet device.
	ErrPBRMissingWANDevice = errors.New("vpn: pbr direct egress requires an attached WAN packet device")
	// ErrPBRMissingPolicy indicates PBR cannot be enabled without a compiled policy matcher.
	ErrPBRMissingPolicy = errors.New("vpn: pbr direct egress requires a policy matcher")
	// ErrPBRMissingClassifier indicates PBR cannot be enabled without the
	// destination classifier that decides every destination the operator's
	// exception list does not override. It is the routing authority: without it no
	// destination can be classified as allocation-member, so nothing routes DIRECT
	// and the operator's policy would be inert while the panel reported it on.
	ErrPBRMissingClassifier = errors.New("vpn: pbr direct egress requires an installed destination classifier")
	// ErrPBREmptyPolicy indicates PBR was asked to compile a snapshot from source
	// rules that produced none. It is retained for the source-compiling startup
	// path; activation from the operator record no longer depends on the rule
	// count, because a zero-rule snapshot is a valid override-free policy.
	ErrPBREmptyPolicy = errors.New("vpn: pbr direct egress requires a non-empty policy snapshot")
)

// PBRConfig holds Policy-Based Routing direct egress configuration for Service.
type PBRConfig struct {
	Enabled       bool
	HostWANIP     netip.Addr
	WANDevice     forwarder.PacketDevice
	PolicyMatcher *policy.Matcher
	PolicySources []policy.SourceParsedRules
	// InventoryOverride is the accepted operator override the classifier applies
	// on top of the committed allocation inventory. Nil keeps the shipped set as
	// the only authority, which is the behavior when no override is configured.
	InventoryOverride *policy.InventoryOverride
	// DestinationClassifier is the address classifier activation installs: the
	// routing authority that answers every destination the operator's exception
	// list does not override (forwarder/routing_decision.go, rows 3 to 5).
	//
	// It is a field rather than something ConfigurePBR derives on its own so the
	// prerequisite check can confirm the authority is present before anything is
	// installed. Nil means no routing authority, which is a different state from
	// "the operator configured no overrides" and is the only one that may refuse
	// activation.
	DestinationClassifier forwarder.DestinationClassifier
}

// ValidatePBRPrerequisites checks that all required direct egress components are
// present before PBR can be safely enabled. Fails closed if any prerequisite is
// missing.
//
// The last prerequisite is the routing authority, and it is deliberately NOT the
// operator's rule count. The exception list is an override layer over the
// destination classifier (forwarder/routing_decision.go), so a published snapshot
// with zero rules is a valid configuration: rows 3 to 5 decide every destination
// from the classifier. What must never activate is a data path with no
// classifier: every destination then answers "uncovered", so the fail-safe proxy
// default (row 5) takes all traffic, nothing can ever route DIRECT, and the policy
// the operator enabled would be inert while the panel reported it as on. The
// classifier is also what proves the committed inventory and ASN table are
// readable, so its absence is the one state in which "activated" would not mean
// "routing".
//
// So the matcher must be installed (a nil matcher means the snapshot was never
// wired at all), and the classifier must be present. The rule count is not
// consulted.
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
	if cfg.DestinationClassifier == nil {
		return ErrPBRMissingClassifier
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

	// The routing authority is built from the committed artifacts, so "is it
	// present" is a fact about this build rather than about the operator's
	// exception list. Callers that already built one from the operator record
	// (StartPolicyRouting) supply it; otherwise it is built here from the
	// registered inventory override. A nil result means the committed inventory or
	// ASN table is unusable, which the prerequisite check below refuses.
	if cfg.DestinationClassifier == nil {
		cfg.DestinationClassifier = newDestinationClassifier(cfg.InventoryOverride)
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
	// Install exactly the classifier the prerequisite check just confirmed. An
	// operator override is applied when the classifier is built, so configuration
	// and installed authority cannot disagree.
	s.forwarder.SetDestinationClassifier(cfg.DestinationClassifier)
	// The recorded override and the installed classifier are written together:
	// the status then describes the set the packet path is actually consulting,
	// including while a later save is still being applied.
	s.inventoryOverride = cfg.InventoryOverride

	servicePBRConfigsMu.Lock()
	servicePBRConfigs[s] = &cfg
	servicePBRConfigsMu.Unlock()

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
		matcher.Publish(snap)
		cfg.PolicyMatcher = matcher
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

	// 4. Configure PBR on Service (fails closed if prerequisite validation fails)
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

// buildDestinationClassifier joins the two committed inputs the routing contract
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
func buildDestinationClassifier(override *policy.InventoryOverride) forwarder.DestinationClassifier {
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

// newDestinationClassifier is the production classifier constructor, and the
// substitution point tests use to model an unavailable committed artifact.
//
// Activation must refuse when this returns nil, so the refusal is only provable
// against a classifier that is genuinely absent rather than one that failed a
// check the test could satisfy. Same pattern as newProductionWANDevice.
var newDestinationClassifier = buildDestinationClassifier

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
	if newSnap.CIDRCount() == 0 {
		return errors.New("vpn: compiled snapshot contains no rules (retaining existing snapshot)")
	}
	pbrCfg.PolicyMatcher.Publish(newSnap)
	return nil
}
