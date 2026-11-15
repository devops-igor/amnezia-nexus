package vpn

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// This file is the read-only policy dry run of issue #825: it answers "would
// this destination go direct or through the proxy, and why?" for one name or
// address without sending client traffic.
//
// Read-only is guaranteed by what this file does NOT call, not by a flag:
//
//   - No route-cache insertion. The only cache entry points used are
//     MemoryRouteCache.SessionScope (which delegates to RouteCache.Get, whose
//     contract is that it never creates a scope) and SessionCache.Inspect (one
//     atomic view load plus a map read). Open, Observe, Set, Invalidate, Sweep
//     and SetPolicyGeneration are not reachable from here, so no entry, session
//     or generation can change.
//   - No evidence recorded. Evidence is written only by SessionCache.Observe,
//     called from gatewaydns.ObserveResponse through the DNS handler. This file
//     never calls the observation path: the ad-hoc answer below is classified
//     locally and discarded.
//   - No DNS interception. Interception happens on the packet path
//     (Forwarder.routeClientPBR → dnsHandler.HandleDNSPacket). No packet is
//     parsed and no handler is invoked here; the lookup is an ordinary query the
//     resolver sends *out* to the configured upstreams.
//   - No flow created. Flows are installed by DirectEgressManager.RecordFlow and
//     the forwarder's send paths, none of which are called here.
//   - No counter movement. Every counter is a forwarder atomic incremented next
//     to a send, a drop or an observation; this path performs none of them.
//
// The one thing it does beyond reading is the bounded ad-hoc lookup, which is
// explicitly excluded from the evidence path and bounded by
// DefaultPolicyExplainResolveTimeout (or the caller's shorter deadline).

const (
	// DefaultPolicyExplainResolveTimeout bounds the ad-hoc name lookup. It is
	// shorter than the policy resolver's 4s query budget because this lookup is
	// an operator convenience, not a client answer.
	DefaultPolicyExplainResolveTimeout = 2 * time.Second
	// policyExplainMaxCNAMEHops matches the observation path's traversal bound.
	policyExplainMaxCNAMEHops = 16

	// Resolution methods reported to the operator.
	policyExplainMethodConfiguredResolver = "configured_resolver"
	policyExplainMethodCallerSupplied     = "caller_supplied"
	policyExplainMethodNotAttempted       = "not_attempted"
	policyExplainMethodUnavailable        = "unavailable"

	// policyExplainEvidenceSource names where route evidence comes from. In
	// production the only writer is gatewaydns.ObserveResponse, fed by
	// intercepted plain DNS, so the value says exactly that.
	policyExplainEvidenceSource = "intercepted_plain_dns"
)

// Limitations an answer always or conditionally carries. They are tokens, not
// sentences: the UI translates them, and a value that has no translation is
// shown as received rather than guessed.
const (
	PolicyLimitEncryptedDNS    = "encrypted_dns_not_observed"
	PolicyLimitAdHocResolution = "ad_hoc_resolution_is_not_evidence"
	PolicyLimitNoSession       = "evidence_requires_a_selected_session"
	PolicyLimitNoSessionData   = "session_has_no_cached_evidence"
	PolicyLimitNoName          = "domain_rules_require_a_name"
	PolicyLimitIPv6            = "ipv6_not_supported"
)

// PolicyExplainRequest is one validated dry-run request.
type PolicyExplainRequest struct {
	// Value is the input as the operator typed it, echoed back unchanged.
	Value string
	// Name is the canonical domain to explain. Empty when the caller supplied
	// only addresses.
	Name string
	// Addresses are caller-supplied addresses, evaluated instead of resolving.
	// Empty means "resolve Name".
	Addresses []netip.Addr
	// SessionID selects the session whose evidence is read. Empty means no
	// session was selected, so no evidence is consulted.
	SessionID string
	// ResolveTimeout bounds the ad-hoc lookup. Zero uses the default.
	ResolveTimeout time.Duration
}

// policyExplainDeps holds every live object one explanation reads. It is a
// struct rather than a parameter list so a test can drive the real decision
// table through the real matcher, a real seeded route cache and a fake resolver
// without constructing a data path.
type policyExplainDeps struct {
	Enabled      bool
	Snapshot     *policy.Snapshot
	SessionScope *policy.SessionCache
	Resolver     gatewaydns.Resolver
	Upstreams    []policy.Upstream
	Now          time.Time
}

// ExplainPolicy explains the routing decision for one destination.
func (s *Service) ExplainPolicy(ctx context.Context, req PolicyExplainRequest) (PolicyExplanation, error) {
	if s == nil {
		return PolicyExplanation{}, errors.New("vpn: policy explain requires a service")
	}
	deps := policyExplainDeps{Enabled: s.PBREnabled(), Now: time.Now()}
	if matcher := s.PolicyMatcher(); matcher != nil {
		deps.Snapshot = matcher.Current()
	}
	if cfg := s.getPBRConfig(); cfg != nil {
		if cfg.DNSResolver != nil {
			deps.Resolver = cfg.DNSResolver
			deps.Upstreams = cfg.DNSResolver.Upstreams()
		}
		if mem, ok := cfg.RouteCache.(*MemoryRouteCache); ok && mem != nil && req.SessionID != "" {
			// SessionScope reads the scope the session already owns. It never
			// allocates one, so explaining cannot consume a cache slot.
			deps.SessionScope = mem.SessionScope(req.SessionID)
		}
	}
	return explainPolicy(ctx, deps, req)
}

// explainPolicy builds the answer from already-resolved dependencies.
func explainPolicy(ctx context.Context, deps policyExplainDeps, req PolicyExplainRequest) (PolicyExplanation, error) {
	if req.Name == "" && len(req.Addresses) == 0 {
		return PolicyExplanation{}, errors.New("vpn: policy explain requires a name or an address")
	}

	out := PolicyExplanation{
		Input:       PolicyExplainInput{Value: req.Value, Kind: "address", Normalized: req.Name, Session: req.SessionID},
		Policy:      policyExplainState(deps),
		Addresses:   []PolicyExplainAddress{},
		Resolution:  PolicyExplainResolution{Method: policyExplainMethodNotAttempted, Addresses: []string{}},
		Limitations: policyExplainLimitations(req, deps),
		ReadOnly:    true,
	}
	if req.Name != "" {
		out.Input.Kind = "domain"
	}
	// A caller that supplied its own addresses needs no lookup, so the answer can
	// say so even when policy routing is disabled and nothing is evaluated.
	if len(req.Addresses) > 0 {
		out.Resolution = PolicyExplainResolution{
			Method:    policyExplainMethodCallerSupplied,
			Addresses: policyExplainAddrStrings(req.Addresses),
		}
	}

	// Disabled policy routing answers with the legacy route before any lookup:
	// there is nothing to explain beyond "everything is proxied", and skipping
	// the lookup keeps a dry run from sending DNS traffic it cannot need.
	if !deps.Enabled {
		out.Decision = string(policy.ActionProxy)
		out.Reason = string(policy.CausePolicyDisabled)
		out.Summary = string(policy.SummaryNone)
		return out, nil
	}

	names, addresses, resolution := policyExplainTargets(ctx, deps, req)
	out.Resolution = resolution

	verdict := policy.ExplainDestination(policy.ExplainDestinationInput{
		Enabled:     true,
		Snapshot:    deps.Snapshot,
		Names:       names,
		Addresses:   addresses,
		Resolved:    resolution.Error == "" || len(req.Addresses) > 0,
		EvidenceFor: policyExplainEvidenceReader(deps),
		Prohibited:  forwarder.IsProhibitedIPv4Destination,
	})
	policyExplainApply(&out, verdict, deps)
	return out, nil
}

// policyExplainTargets decides what to evaluate: the caller's own addresses, or
// a bounded ad-hoc lookup of the requested name.
func policyExplainTargets(ctx context.Context, deps policyExplainDeps, req PolicyExplainRequest) ([]string, []netip.Addr, PolicyExplainResolution) {
	if len(req.Addresses) > 0 {
		res := PolicyExplainResolution{
			Method:    policyExplainMethodCallerSupplied,
			Addresses: policyExplainAddrStrings(req.Addresses),
		}
		var names []string
		if req.Name != "" {
			names = []string{req.Name}
		}
		return names, req.Addresses, res
	}
	return resolvePolicyExplainName(ctx, deps, req)
}

// resolvePolicyExplainName performs the bounded lookup and reports exactly how
// it was made: which method, which upstreams the resolver dials, the deadline,
// the names the answer traversed and the addresses it produced.
func resolvePolicyExplainName(ctx context.Context, deps policyExplainDeps, req PolicyExplainRequest) ([]string, []netip.Addr, PolicyExplainResolution) {
	timeout := req.ResolveTimeout
	if timeout <= 0 {
		timeout = DefaultPolicyExplainResolveTimeout
	}
	res := PolicyExplainResolution{
		Method:      policyExplainMethodConfiguredResolver,
		Nameservers: policyUpstreamStrings(deps.Upstreams),
		TimeoutMS:   timeout.Milliseconds(),
		Addresses:   []string{},
	}
	if deps.Resolver == nil {
		res.Method = policyExplainMethodUnavailable
		res.Error = "no policy resolver is installed"
		return []string{req.Name}, nil, res
	}

	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(req.Name), mdns.TypeA)
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := deps.Resolver.Exchange(lookupCtx, query)
	if err != nil {
		res.Error = err.Error()
		return []string{req.Name}, nil, res
	}

	names, addresses, note := classifyPolicyExplainAnswer(resp, req.Name)
	res.Names = names
	res.Addresses = policyExplainAddrStrings(addresses)
	res.Note = note
	if len(addresses) == 0 && res.Error == "" {
		res.Error = "the answer contains no usable IPv4 address"
	}
	return names, addresses, res
}

// classifyPolicyExplainAnswer walks the CNAME chain the way the observation path
// does and returns the traversed names plus the terminal A records.
//
// A name that cannot be normalized is dropped from the rule evaluation: the
// observation path discards the whole answer in that case, so matching a
// canonical part of a chain it would have ignored would over-report a rule.
func classifyPolicyExplainAnswer(resp *mdns.Msg, queried string) ([]string, []netip.Addr, string) {
	if resp == nil {
		return nil, nil, ""
	}
	current := mdns.Fqdn(queried)
	names := make([]string, 0, 4)
	visited := make(map[string]struct{}, policyExplainMaxCNAMEHops)
	note := ""
	for hop := 0; hop < policyExplainMaxCNAMEHops; hop++ {
		key := strings.ToLower(current)
		if _, seen := visited[key]; seen {
			break
		}
		visited[key] = struct{}{}
		if canon, err := policy.NormalizeDomain(key); err == nil {
			names = append(names, canon)
		} else if note == "" {
			note = "a name in the answer does not normalize, so it cannot match a rule"
		}
		next := policyExplainCNAMETarget(resp, current)
		if next == "" {
			break
		}
		current = next
	}
	return names, policyExplainARecords(resp, current), note
}

// policyExplainCNAMETarget returns the single CNAME target of name, or "".
func policyExplainCNAMETarget(resp *mdns.Msg, name string) string {
	target := ""
	for _, rr := range resp.Answer {
		cname, ok := rr.(*mdns.CNAME)
		if !ok || !strings.EqualFold(cname.Hdr.Name, name) {
			continue
		}
		if target != "" && !strings.EqualFold(target, cname.Target) {
			// Ambiguous chain: production refuses it, so stop here and let the
			// caller see no further names.
			return ""
		}
		target = cname.Target
	}
	return target
}

// policyExplainARecords returns the deduplicated IPv4 A records of terminal.
func policyExplainARecords(resp *mdns.Msg, terminal string) []netip.Addr {
	out := make([]netip.Addr, 0, 4)
	seen := make(map[netip.Addr]struct{}, 4)
	for _, rr := range resp.Answer {
		rec, ok := rr.(*mdns.A)
		if !ok || !strings.EqualFold(rec.Hdr.Name, terminal) {
			continue
		}
		addr, ok := netip.AddrFromSlice(rec.A)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsValid() || !addr.Is4() {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

// policyExplainEvidenceReader returns the evidence lookup for the selected
// session, or nil when no session (or no cache scope) is available. The reader
// only ever calls Inspect.
func policyExplainEvidenceReader(deps policyExplainDeps) func(netip.Addr) *policy.Evidence {
	if deps.SessionScope == nil {
		return nil
	}
	generation := ""
	if deps.Snapshot != nil {
		generation = deps.Snapshot.Generation()
	}
	return func(addr netip.Addr) *policy.Evidence {
		evidence := deps.SessionScope.Inspect(addr, generation, deps.Now)
		return &evidence
	}
}

// policyExplainLimitations lists the caveats that apply to this answer.
func policyExplainLimitations(req PolicyExplainRequest, deps policyExplainDeps) []string {
	limits := []string{PolicyLimitEncryptedDNS, PolicyLimitAdHocResolution, PolicyLimitIPv6}
	switch {
	case req.SessionID == "":
		limits = append(limits, PolicyLimitNoSession)
	case deps.SessionScope == nil:
		// The session was selected but owns no cache scope: it has not observed
		// DNS yet, or its scope was released when its route retired. That is
		// different from "no session was asked about", so it says so.
		limits = append(limits, PolicyLimitNoSessionData)
	}
	if req.Name == "" {
		limits = append(limits, PolicyLimitNoName)
	}
	return limits
}

// policyExplainState reports the policy context the answer was computed in.
func policyExplainState(deps policyExplainDeps) PolicyExplainState {
	state := PolicyExplainState{Enabled: deps.Enabled}
	if deps.Snapshot != nil {
		state.GenerationID = deps.Snapshot.Generation()
		state.Version = deps.Snapshot.Version()
		state.DomainRules = deps.Snapshot.DomainCount()
		state.CIDRRules = deps.Snapshot.CIDRCount()
	}
	return state
}

// policyExplainApply copies a verdict into the wire shape.
func policyExplainApply(out *PolicyExplanation, verdict policy.DestinationExplanation, deps policyExplainDeps) {
	out.Decision = string(verdict.Decision)
	out.Reason = string(verdict.Reason)
	out.Summary = string(verdict.Summary)
	out.Rule = policyExplainRule(verdict)
	out.Prefix = policyExplainPrefix(verdict.Prefix)
	out.Evidence = policyExplainEvidence(verdict.Evidence, deps.Now)
	for _, v := range verdict.Addresses {
		out.Addresses = append(out.Addresses, PolicyExplainAddress{
			Address:  v.Address.String(),
			Decision: string(v.Decision),
			Reason:   string(v.Reason),
			Prefix:   policyExplainPrefix(v.Prefix),
			Evidence: policyExplainEvidence(v.Evidence, deps.Now),
		})
	}
}

func policyExplainRule(verdict policy.DestinationExplanation) *PolicyExplainRule {
	if verdict.Rule == nil {
		return nil
	}
	return &PolicyExplainRule{
		Base:        verdict.Rule.Base,
		Shape:       string(verdict.Rule.Shape),
		Sources:     policyExplainSources(verdict.Rule.Sources),
		SourceKind:  policyExplainSourceKind(verdict.Rule.Sources),
		MatchedName: verdict.RuleName,
	}
}

func policyExplainPrefix(match *policy.CIDRRuleMatch) *PolicyExplainPrefix {
	if match == nil {
		return nil
	}
	return &PolicyExplainPrefix{
		Prefix:     match.Prefix.String(),
		Sources:    policyExplainSources(match.Sources),
		SourceKind: policyExplainSourceKind(match.Sources),
	}
}

// policyExplainSourceKind classifies the lists that supplied a rule: a built-in
// preset, operator-supplied custom lists, or a mixture (which a snapshot merges
// only when several sources supply the same rule). An unknown identifier is
// reported as a custom list, because a preset identifier is a closed catalog.
func policyExplainSourceKind(sources []string) string {
	if len(sources) == 0 {
		return ""
	}
	custom := 0
	for _, id := range sources {
		if strings.HasPrefix(id, "custom-") {
			custom++
		}
	}
	switch {
	case custom == len(sources):
		return "custom"
	case custom == 0:
		return "preset"
	default:
		return "mixed"
	}
}

func policyExplainEvidence(evidence *policy.Evidence, now time.Time) *PolicyExplainEvidence {
	if evidence == nil {
		return nil
	}
	state := PolicyExplainEvidence{
		State:            string(evidence.State),
		Generation:       evidence.Generation,
		ExpiresInSeconds: int64(evidence.Remaining(now) / time.Second),
	}
	// Only a stored entry has an observation behind it. An absent, quarantined or
	// retired state means the cache holds nothing, so claiming the observation
	// source there would imply evidence that does not exist.
	if evidence.State == policy.EvidenceFresh || evidence.State == policy.EvidenceExpired {
		state.Source = policyExplainEvidenceSource
	}
	if evidence.Decision == policy.Direct || evidence.Decision == policy.Proxy {
		state.Decision = evidence.Decision.String()
	}
	return &state
}

// policyExplainSources reports a rule's sources, or an empty array so the JSON
// shape does not change between an attributed and an unattributed snapshot.
func policyExplainSources(sources []string) []string {
	if sources == nil {
		return []string{}
	}
	return sources
}

func policyExplainAddrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

// policyUpstreamStrings renders the resolver list the lookup dials, so the
// answer states which path resolved the name.
func policyUpstreamStrings(upstreams []policy.Upstream) []string {
	if len(upstreams) == 0 {
		upstreams = policy.DefaultUpstreams()
	}
	out := make([]string, 0, len(upstreams))
	for _, up := range upstreams {
		out = append(out, up.String())
	}
	return out
}
