package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
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
	// ErrPBREmptyPolicy indicates PBR cannot be enabled with an empty or uncompiled policy snapshot.
	ErrPBREmptyPolicy = errors.New("vpn: pbr direct egress requires a non-empty policy snapshot")
)

// PBRConfig holds Policy-Based Routing direct egress configuration for Service.
type PBRConfig struct {
	Enabled       bool
	HostWANIP     netip.Addr
	GatewayDNSIP  netip.Addr
	WANDevice     forwarder.PacketDevice
	RouteCache    forwarder.RouteCache
	PolicyMatcher *policy.Matcher
	PolicySources []policy.SourceParsedRules
	DNSGateway    *gatewaydns.Gateway
	// UpstreamDNS is the validated upstream list the policy resolver dials.
	// Empty means the effective defaults (policy.DefaultUpstreams()).
	UpstreamDNS []policy.Upstream
	// DNSResolver is the resolver installed with DNSGateway. It is kept here so
	// the policy status can report the last upstream outcome, and so a live
	// settings change can swap the upstream list without rebuilding the data
	// path.
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
	if cfg.RouteCache == nil {
		return ErrPBRMissingRouteCache
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

	// Default to disabled. A configuration issued while policy routing was
	// active keeps naming the gateway, so the resolver that answered it is
	// removed with the data path: no profile is served by the panel once the
	// classifier is off.
	if !cfg.Enabled {
		s.clearDNSHandlerLocked()
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
		// A refused activation is a transition to disabled: remove the resolver
		// with the data path it belongs to.
		s.clearDNSHandlerLocked()
		s.forwarder.SetPBREnabled(false)
		return fmt.Errorf("pbr prerequisites: %w", err)
	}

	if mem, ok := cfg.RouteCache.(*MemoryRouteCache); ok {
		mem.AttachMatcher(cfg.PolicyMatcher)
		// Bind each stored DNS observation to the route generation registered for
		// its session at observation time.
		fwd := s.forwarder
		mem.SetIncarnationSource(func(sessionID string) (uint64, bool) {
			return fwd.SessionRouteGeneration(sessionID)
		})
	}

	dem := forwarder.NewDirectEgressManager(forwarder.DirectEgressConfig{
		HostWANIP:    cfg.HostWANIP,
		GatewayDNSIP: cfg.GatewayDNSIP,
		WANDevice:    cfg.WANDevice,
	}, s.forwarder)

	s.forwarder.SetDirectEgress(dem)
	s.forwarder.SetRouteCache(cfg.RouteCache)
	s.forwarder.SetPolicyMatcher(cfg.PolicyMatcher)
	s.forwarder.SetDestinationClassifier(newDestinationClassifier(cfg.InventoryOverride))
	// The recorded override and the installed classifier are written together:
	// the status then describes the set the packet path is actually consulting,
	// including while a later save is still being applied.
	s.inventoryOverride = cfg.InventoryOverride
	if cfg.GatewayDNSIP.IsValid() {
		s.forwarder.SetGatewayDNSIP(cfg.GatewayDNSIP)
	}

	s.installPBRDNSHandlerLocked(cfg)

	servicePBRConfigsMu.Lock()
	servicePBRConfigs[s] = &cfg
	servicePBRConfigsMu.Unlock()

	// The resolver installed above is the authority for what is dialed, so the
	// owned list is taken from it rather than from the activation input: every
	// later consumer (live change, a later activation) reads this one field.
	if cfg.DNSResolver != nil {
		s.dnsUpstreams = cfg.DNSResolver.Upstreams()
	}

	s.forwarder.SetPBREnabled(true)
	return nil
}

// clearDNSHandlerLocked closes and removes the forwarder's ingress DNS handler.
// The caller holds s.mu.
//
// It is the disable transition. With policy routing inactive no resolver answers
// gateway-addressed DNS, so a client profile that still names the gateway address
// receives no answer from the panel and must be replaced. The handler is removed
// before it is closed, so no packet is admitted into a closing responder, and a
// repeated call is a no-op.
func (s *Service) clearDNSHandlerLocked() {
	if s == nil || s.forwarder == nil {
		return
	}
	handler := s.forwarder.DNSHandler()
	if handler == nil {
		return
	}
	s.forwarder.SetDNSHandler(nil)
	if closer, ok := handler.(io.Closer); ok {
		_ = closer.Close()
	}
}

// installPBRDNSHandlerLocked makes the policy resolver the forwarder's DNS
// handler, replacing and closing the handler it supersedes. A configuration
// without a gateway has no resolver to install, which is the pre-existing
// fail-open behavior for that impossible case. The caller holds s.mu.
func (s *Service) installPBRDNSHandlerLocked(cfg PBRConfig) {
	if cfg.DNSGateway == nil {
		return
	}
	if obs, ok := cfg.RouteCache.(gatewaydns.RouteObserver); ok {
		cfg.DNSGateway.SetObserver(obs)
	}
	if oldH := s.forwarder.DNSHandler(); oldH != nil {
		if closer, ok := oldH.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	s.forwarder.SetDNSHandler(newPBRDNSHandler(cfg.DNSGateway, cfg.RouteCache, s.forwarder.HasLiveSession))
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

// DNSGateway returns the DNS gateway configured on the service, if any.
func (s *Service) DNSGateway() *gatewaydns.Gateway {
	pbrCfg := s.getPBRConfig()
	if pbrCfg != nil {
		return pbrCfg.DNSGateway
	}
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

// MemoryRouteCache provides an in-memory implementation of forwarder.RouteCache
// backed by authentic policy.RouteCache with PROXY-wins, CNAME, TTL, and generation invalidation.
type MemoryRouteCache struct {
	mu      sync.RWMutex
	rc      *policy.RouteCache
	matcher *policy.Matcher
	gen     string
	// runtime is the intercepted-DNS authority whose per-session state is
	// retired together with the session's cache scope. The cache retains no
	// DNS state of its own; it is the session-scope authority every
	// route-removal path already retires through, so releasing a scope also
	// releases the work that scope authorized.
	runtime *pbrDNSHandler
	// dnsRecords is the bounded in-memory record of the answers this observer
	// actually wrote (issue #861). It is not the route cache: an entry here
	// survives the evidence expiring and is dropped only by age, capacity or
	// session retirement. Guarded by dnsRecordsMu, never by mu.
	dnsRecordsMu sync.RWMutex
	dnsRecords   *dnsledger.Ledger
	// historyLifetimes names the sessions whose DNS history lifetime is open and, for
	// each, the earliest receipt generation that lifetime admitted (zero when the first
	// receipt carried no incarnation). A lifetime opens at query receipt for a live
	// session and closes in RetireSessionScope, in the same critical section that erases
	// the rows, so a publication from a query whose session already retired cannot
	// recreate it. A closed lifetime leaves no entry, so the registry is bounded by the
	// sessions that currently own history, and a receipt of a re-admitted session opens
	// a fresh lifetime with its own generation.
	historyLifetimes map[string]uint64
	// incarnation resolves which registered route generation owns a session at
	// observation time, so a record can state its incarnation instead of
	// guessing one. nil means "not established", never "the current one".
	incarnation func(sessionID string) (uint64, bool)
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
		rc:               rc,
		matcher:          m,
		gen:              initialGen,
		dnsRecords:       dnsledger.New(),
		historyLifetimes: make(map[string]uint64),
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
//
// The read never allocates a scope: a session without retained evidence answers
// Unknown, which is the same answer an empty scope would give, but without
// permanently consuming capacity for a session that may already be retired.
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
	sc := c.rc.Get(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
	c.mu.Unlock()

	if sc == nil {
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
//
// The receipt is the session lifetime the query was received under. The observation is
// recorded as history under that receipt, never under the generation registered when this
// write finally runs: a delayed answer must not be credited to a session id's successor.
func (c *MemoryRouteCache) ObserveDNSResponse(sessionID string, receipt gatewaydns.QueryReceipt, req, resp *mdns.Msg) error {
	return c.observeDNSResponse(sessionID, &receipt, req, resp)
}

// ObserveDNSResponseEvidence evaluates the same answer for route evidence and records no
// history at all. It exists for callers that have no query receipt — an entrypoint
// without lifetime authority must not be able to stamp history with a generation it did
// not receive, so this one writes none rather than guessing one.
func (c *MemoryRouteCache) ObserveDNSResponseEvidence(sessionID string, req, resp *mdns.Msg) error {
	return c.observeDNSResponse(sessionID, nil, req, resp)
}

// observeDNSResponse writes the route evidence for one answer and, when a receipt is
// present, its history row under that receipt.
func (c *MemoryRouteCache) observeDNSResponse(sessionID string, receipt *gatewaydns.QueryReceipt, req, resp *mdns.Msg) error {
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
	// One instant for both the evidence deadline and the stored observation, so a
	// record cannot claim a different time than the decision it describes.
	observedAt := time.Now()
	observed, err := gatewaydns.ObserveResponseResult(req, resp, snap, sc, observedAt, 3600*time.Second)
	// The record is written whether or not the cache accepted the evidence: an
	// answer the observation path rejected is exactly what an administrator needs
	// to see, and it is stored with that verdict rather than as trusted evidence.
	if receipt != nil {
		c.recordDNSObservation(sessionID, *receipt, observed)
	}
	return err
}

// DNSTransportNotRecorded is the token an answer carries where the transport
// would go. The observer boundary this build records at does not see it; only the
// DNS server, which this slice does not modify, does.
const DNSTransportNotRecorded = "not_recorded"

// recordDNSObservation stores one observed answer in the bounded DNS ledger,
// bound to the session and to the route generation registered for it at the time
// of the observation.
func (c *MemoryRouteCache) recordDNSObservation(sessionID string, receipt gatewaydns.QueryReceipt, observed gatewaydns.ObservedAnswer) {
	if c.DNSLedger() == nil || sessionID == "" {
		return
	}
	answer := observed.Classification
	name := dnsledger.CanonicalName(observed.QName)
	aliases := []string{}
	if len(answer.Names) > 0 {
		name = dnsledger.CanonicalName(answer.Names[0])
		for _, alias := range answer.Names[1:] {
			aliases = append(aliases, dnsledger.CanonicalName(alias))
		}
	}
	if name == "" {
		return
	}
	addresses := make([]dnsledger.AddressDecision, 0, len(observed.Observations))
	for _, observation := range observed.Observations {
		addresses = append(addresses, dnsledger.AddressDecision{
			Address:  observation.IP,
			Decision: observation.Decision.String(),
		})
	}
	// The row is labeled with the lifetime the query was received under, and the same
	// receipt decides admission below. Resolving a generation here instead would label a
	// delayed answer with whatever owns the session id now.
	generation, generationKnown := receipt.Generation, receipt.Known
	policyGeneration := answerSnapshotGeneration(c)
	c.dnsRecordsMu.Lock()
	defer c.dnsRecordsMu.Unlock()
	// The answer record is written after the reply was delivered, so — like the terminal
	// event — it can run after the session retired, or after the session id was
	// re-admitted. It is admitted only while the lifetime this query was received under is
	// open, in the same critical section as the append, so retirement cannot interleave
	// between the decision and the write and a receipt from an ended lifetime is refused
	// even though the session id exists again.
	if !c.historyWriteAllowedLocked(sessionID, generation, generationKnown) {
		return
	}
	c.dnsRecords.Record(dnsledger.Input{
		SessionID:            sessionID,
		RouteGeneration:      generation,
		RouteGenerationKnown: generationKnown,
		Name:                 name,
		Aliases:              aliases,
		QType:                observed.QType,
		RCode:                observed.RCode,
		ObservedAt:           observed.RecvTime,
		ExpiresAt:            observed.ExpiresAt,
		PolicyGeneration:     policyGeneration,
		ClassificationValid:  answer.Valid,
		ClassificationReason: answer.Reason,
		Addresses:            addresses,
		ResolvedAddressCount: len(answer.ResolvedAddresses),
		CacheVerdict:         cacheVerdictToken(observed.CacheErr),
	}, observed.RecvTime)
}

// ObserveDNSQueryEvent stores one terminal client DNS query (issue #861, R9): a
// refused admission, a failed upstream exchange, NXDOMAIN, a truncated reply, a
// non-A type, or a reply the client never received.
//
// It is diagnostic history only. It writes no route evidence, so a failed or
// truncated answer cannot become trusted because it was recorded here, and it runs
// after the delivery attempt, outside every lock.
// BindQueryIncarnation reports the route generation registered for a session when a
// query arrives. It is the receipt-time half of the terminal-event contract: the
// event is emitted after the reply, and resolving the incarnation then could credit
// a successor that reused the session id.
//
// It is also where a session's DNS history lifetime opens. The receipt is the last
// moment the session is known to be live for this query, and the publication that
// follows it may run after the client disconnected, so the lifetime it belongs to has
// to be recorded here rather than inferred at publication time.
func (c *MemoryRouteCache) BindQueryIncarnation(sessionID string) (uint64, bool) {
	generation, known := c.observedIncarnation(sessionID)
	c.openHistoryLifetime(sessionID, generation, known)
	return generation, known
}

func (c *MemoryRouteCache) ObserveDNSQueryEvent(event gatewaydns.QueryEvent) {
	if c == nil || event.SessionID == "" {
		return
	}
	// Read before the history lock: the matcher has its own lock, and the history lock is
	// never held while acquiring another component's lock.
	policyGeneration := answerSnapshotGeneration(c)
	c.dnsRecordsMu.Lock()
	defer c.dnsRecordsMu.Unlock()
	// The terminal event is the last write of a query whose reply was already delivered,
	// so it can run after the session retired. The lifetime the query was received under
	// is the authority here: once it is closed, this row is dropped rather than
	// recreating history for a session that no longer exists.
	if !c.historyWriteAllowedLocked(event.SessionID, event.RouteGeneration, event.IncarnationKnown) {
		return
	}
	c.dnsRecords.RecordEvent(dnsledger.InputEvent{
		SessionID:            event.SessionID,
		RouteGeneration:      event.RouteGeneration,
		RouteGenerationKnown: event.IncarnationKnown,
		Transport:            event.Transport,
		Name:                 event.Name,
		QType:                event.QType,
		RCode:                event.RCode,
		Kind:                 event.Kind,
		UpstreamError:        event.UpstreamError,
		Truncated:            event.Truncated,
		Delivered:            event.Delivered,
		ReceivedAt:           event.ReceivedAt,
		AnsweredAt:           event.AnsweredAt,
		PolicyGeneration:     policyGeneration,
	}, event.ReceivedAt)
}

// observedIncarnation reports the route generation registered for the session at
// observation time. It never substitutes the current generation for an unknown
// one: a DNS answer can arrive while the session owns no route, and inventing a
// mapping would attribute one incarnation's query to another's.
func (c *MemoryRouteCache) observedIncarnation(sessionID string) (uint64, bool) {
	c.mu.RLock()
	resolver := c.incarnation
	c.mu.RUnlock()
	if resolver == nil {
		return 0, false
	}
	return resolver(sessionID)
}

// answerSnapshotGeneration reports the policy generation the answer was evaluated
// against, so a record can state it.
func answerSnapshotGeneration(c *MemoryRouteCache) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen
}

// cacheVerdictToken names the route cache's answer to an evidence write.
func cacheVerdictToken(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, policy.ErrSessionRetired):
		return "session_retired"
	case errors.Is(err, policy.ErrGenerationMismatch):
		return "generation_mismatch"
	case errors.Is(err, policy.ErrCapacityExceeded):
		return "quarantined"
	default:
		return "error"
	}
}

// DNSLedger returns the bounded DNS observation store, or nil when this cache has
// none. It is the only reader the per-client diagnosis uses.
func (c *MemoryRouteCache) DNSLedger() *dnsledger.Ledger {
	if c == nil {
		return nil
	}
	c.dnsRecordsMu.RLock()
	defer c.dnsRecordsMu.RUnlock()
	return c.dnsRecords
}

// SetIncarnationSource installs the route authority that binds a DNS observation
// to the incarnation that produced it. The resolver is read-only and must not
// call back into the cache: the forwarder lock sits above the cache lock.
func (c *MemoryRouteCache) SetIncarnationSource(resolve func(sessionID string) (uint64, bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.incarnation = resolve
}

// Open opens or retrieves the session cache for the given scope.
func (c *MemoryRouteCache) Open(scope policy.Scope) (*policy.SessionCache, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rc.Open(scope)
}

// SessionScope returns the scope that sessionID already owns, without creating
// one. A nil result means the session retains no evidence: it has never observed
// DNS, or its scope was released when its route retired.
func (c *MemoryRouteCache) SessionScope(sessionID string) *policy.SessionCache {
	if c == nil || sessionID == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rc.Get(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
}

// SessionScopeForLiveSession returns the session scope, creating it only while
// live reports the authenticated session as still owning a route.
//
// Delayed work (a queued DNS job, an in-flight observation) may run after its
// session retired, and retirement deletes the entry — so "no entry" cannot by
// itself distinguish a session that never observed anything from one whose scope
// was released. Allocation is therefore fenced by the session lifecycle, whose
// route table is the authoritative retirement record: the predicate is consulted
// without holding the cache lock (the cache never acquires the owner lock under
// its own lock) and re-checked after allocation, so a retirement that
// interleaves with the creation invalidates the new scope instead of leaving a
// released scope behind.
func (c *MemoryRouteCache) SessionScopeForLiveSession(sessionID string, live func(sessionID string) bool) *policy.SessionCache {
	if c == nil || sessionID == "" {
		return nil
	}
	if sc := c.SessionScope(sessionID); sc != nil {
		return sc
	}
	if live != nil && !live(sessionID) {
		return nil
	}
	sc, err := c.Open(policy.Scope{SessionID: sessionID, OwnershipEpoch: 1})
	if err != nil || sc == nil {
		return nil
	}
	if live != nil && !live(sessionID) {
		sc.Invalidate()
		return nil
	}
	return sc
}

// RetireSessionScope releases the cache scope owned by a retired authenticated
// session so its capacity returns to the bounded cache. It is idempotent and
// records no tombstone: a released scope is simply absent, and re-admission of
// the same session creates a fresh one.
//
// The released scope is the session's whole authority, not only its retained
// evidence: the intercepted-DNS runtime attached to this cache is retired in the
// same call, so a query that is still resolving cannot outlive the session that
// authorized it. The runtime is retired outside the cache lock because retiring
// a handle invalidates this cache.
func (c *MemoryRouteCache) RetireSessionScope(sessionID string) {
	if sc := c.SessionScope(sessionID); sc != nil {
		sc.Invalidate()
	}
	// The observation history is released in the same critical section that closes the
	// session's history lifetime. A publication still in flight therefore either finds
	// the lifetime already closed and drops its row, or appended before this point and is
	// erased here; either ordering leaves no history behind. A closed lifetime keeps no
	// entry, so this records no tombstone and re-admission opens a fresh lifetime.
	c.dnsRecordsMu.Lock()
	c.closeHistoryLifetimeLocked(sessionID)
	c.dnsRecordsMu.Unlock()
	if runtime := c.sessionRuntime(); runtime != nil {
		runtime.RetireSessionRuntime(sessionID)
	}
}

// setSessionRuntime attaches the intercepted-DNS runtime authority that must be
// retired with each released session scope.
func (c *MemoryRouteCache) setSessionRuntime(h *pbrDNSHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runtime = h
}

// clearSessionRuntime detaches h, leaving a newer handler's attachment intact.
func (c *MemoryRouteCache) clearSessionRuntime(h *pbrDNSHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runtime == h {
		c.runtime = nil
	}
}

func (c *MemoryRouteCache) sessionRuntime() *pbrDNSHandler {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.runtime
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

// ObserveDNSResponse records client DNS observations into the active route cache used by
// the forwarder. It carries no query receipt, so it writes route evidence only and no
// history: history is written by the DNS observer with the receipt the query arrived
// under.
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
		return mem.ObserveDNSResponseEvidence(sessionID, req, resp)
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
	defer s.mu.RUnlock()
	return s.deriveGatewayDNSIPLocked()
}

// deriveGatewayDNSIPLocked derives the gateway DNS address from the service
// subnet. The caller holds s.mu for reading or writing.
func (s *Service) deriveGatewayDNSIPLocked() netip.Addr {
	subnet := ""
	if s != nil && s.cfg != nil {
		subnet = s.cfg.SubnetCIDR
	}
	if subnet != "" {
		if prefix, err := netip.ParsePrefix(subnet); err == nil && prefix.Addr().Is4() {
			b := prefix.Addr().As4()
			b[3] = 1
			return netip.AddrFrom4(b)
		}
	}
	return netip.MustParseAddr("10.100.0.1")
}

// initDNSGateway builds the policy DNS gateway over an upstream resolver that
// was already constructed from the configured upstream list. The resolver is
// passed in rather than rebuilt here so the gateway, the status surface and the
// live settings path all share one resolver instance.
func initDNSGateway(gwDNS netip.Addr, matcher *policy.Matcher, rc forwarder.RouteCache, resolver gatewaydns.Resolver) *gatewaydns.Gateway {
	if resolver == nil {
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
		Gateway:                  netip.AddrPortFrom(gwDNS, 53),
		RouteObserver:            obs,
		InterceptAllDestinations: true,
	}, dnsSrv)
	if err != nil {
		return nil
	}
	return gw
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

	// 2. Gateway DNS IP: derive if not set
	if !cfg.GatewayDNSIP.IsValid() {
		cfg.GatewayDNSIP = s.deriveDefaultGatewayDNSIP()
	}

	// 3. WAN PacketDevice: instantiate production TUN device if not already provided
	if err := initPBRWANDevice(&cfg); err != nil {
		return err
	}

	// 4. Policy Matcher: instantiate and compile initial snapshot with valid configured sources if not provided
	if err := initPBRPolicyMatcher(&cfg); err != nil {
		return err
	}

	// 5. Route Cache: instantiate in-memory route cache if not provided and connect to matcher
	if cfg.RouteCache == nil {
		memCache := NewMemoryRouteCache()
		memCache.AttachMatcher(cfg.PolicyMatcher)
		cfg.RouteCache = memCache
	} else if mem, ok := cfg.RouteCache.(*MemoryRouteCache); ok {
		mem.AttachMatcher(cfg.PolicyMatcher)
	}

	// 5b. DNS Gateway: instantiate DNS gateway if not provided and connect RouteCache observer.
	// The resolver is built from the configured upstream list (the persisted
	// policy settings, when this activation came from them) so a blocked
	// provider is a settings change rather than a code change.
	if cfg.DNSGateway == nil && cfg.GatewayDNSIP.IsValid() {
		resolver, err := newPolicyUpstreamResolver(cfg.UpstreamDNS)
		if err != nil {
			if cfg.WANDevice != nil {
				_ = cfg.WANDevice.Close()
			}
			return err
		}
		cfg.DNSResolver = resolver
		cfg.DNSGateway = initDNSGateway(cfg.GatewayDNSIP, cfg.PolicyMatcher, cfg.RouteCache, resolver)
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
	// A configuration issued while policy routing was active names the gateway as
	// its only resolver. The resolver that answered it belongs to the policy data
	// path, so it is removed here with the classifier and direct egress: the panel
	// stops answering that address and an issued profile loses DNS until it is
	// replaced.
	s.clearDNSHandlerLocked()
	s.forwarder.SetPBREnabled(false)
	// The classifier belongs to the data path that consults it; a teardown leaves
	// no stale classification installed behind a disabled router.
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
// network. A failure leaves the classifier uninstalled, which keeps the previous
// decision path rather than a new one: the retained-DNS-evidence row still
// decides, and a destination with no usable evidence keeps the fail-safe proxy
// default. The refusal is logged rather than swallowed, and the
// inventory's own status field already reports a broken artifact to the
// operator — "the artifact is broken" and "no address is Russian" must never
// look the same.
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
