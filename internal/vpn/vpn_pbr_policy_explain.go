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
// DefaultPolicyExplainResolveTimeout (or the caller's shorter deadline). That
// lookup does send an ordinary DNS query to the configured upstreams when a name
// is submitted without addresses, so this is not a zero-network operation: the
// client traffic, routing evidence and counters stay untouched, while the query
// itself leaves the panel. The answer reports its method so the operator can see
// that.
//
// Two facts are reported separately and must not be read as one: the CURRENT
// ACTION for the evaluated addresses (prohibited/CIDR/cache precedence, exactly
// what the packet path does) and the PROSPECTIVE rule classification of the
// submitted name (a rule match, which becomes the destination's route only once
// the client's own answer for that name is observed). A dry-run name never acts
// as an observation. See policy.ExplainDestination for the packet-path ordering.

const (
	// DefaultPolicyExplainResolveTimeout bounds the ad-hoc name lookup. It is
	// shorter than the policy resolver's 4s query budget because this lookup is
	// an operator convenience, not a client answer.
	DefaultPolicyExplainResolveTimeout = 2 * time.Second
	// policyExplainAnswerMaxTTL is the TTL ceiling handed to the observation
	// path's classifier. Classification uses it only as the starting minimum TTL;
	// this endpoint publishes remaining evidence TTL and elapsed age from the
	// cache, never this.
	policyExplainAnswerMaxTTL = time.Hour

	// Resolution methods reported to the operator.
	policyExplainMethodConfiguredResolver = "configured_resolver"
	policyExplainMethodCallerSupplied     = "caller_supplied"
	policyExplainMethodNotAttempted       = "not_attempted"
	policyExplainMethodUnavailable        = "unavailable"

	// policyExplainEvidenceSource names where route evidence comes from. In
	// production the only writer is gatewaydns.ObserveResponse, fed by
	// intercepted plain DNS, so the value says exactly that.
	policyExplainEvidenceSource = "intercepted_plain_dns"

	// policyExplainIgnoredAnswerPrefix introduces the resolution error shown when
	// the observation path would discard the whole answer. It is a named value so
	// the parity test can distinguish "answer rejected" from "answer valid but
	// carried no usable address" without matching an arbitrary sentence.
	policyExplainIgnoredAnswerPrefix = "the observation path would ignore this answer"
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
	// PolicyLimitNoEvidenceAge is added only when fresh evidence in the answer was
	// stored without an observation instant, so its age cannot be stated. It
	// states the limitation once for the whole answer; each affected evidence
	// object carries the same cause in age_unavailable_reason. Age is never
	// derived from the deadline.
	PolicyLimitNoEvidenceAge = "evidence_age_not_recorded"
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
	// Resolver is the read-only exchange entry point: same budgets and failover as
	// the live resolver, without its health-status write.
	Resolver  gatewaydns.ReadOnlyResolver
	Upstreams []policy.Upstream
	// Clock is the evaluation clock. It is sampled ONCE per answer, after the
	// blocking lookup, and that one instant is used both for reading the session
	// evidence and for serializing its remaining TTL. nil means time.Now.
	Clock func() time.Time
}

// policyExplainNow samples the evaluation clock.
func policyExplainNow(deps policyExplainDeps) time.Time {
	if deps.Clock != nil {
		return deps.Clock()
	}
	return time.Now()
}

// ExplainPolicy explains the routing decision for one destination.
func (s *Service) ExplainPolicy(ctx context.Context, req PolicyExplainRequest) (PolicyExplanation, error) {
	if s == nil {
		return PolicyExplanation{}, errors.New("vpn: policy explain requires a service")
	}
	deps := policyExplainDeps{Enabled: s.PBREnabled(), Clock: time.Now}
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
		// Nothing was looked up and no evidence was read, so the evaluation
		// instant is the moment of the answer itself.
		out.EvaluatedAt = policyExplainNow(deps).UTC().Format(time.RFC3339)
		return out, nil
	}

	names, addresses, resolution := policyExplainTargets(ctx, deps, req)
	out.Resolution = resolution

	// Sample the evaluation clock AFTER the blocking lookup and use this single
	// instant for both the evidence read and the TTL we serialize. The packet
	// path looks evidence up at the current time, so evaluating with a clock
	// sampled before a slow resolution would report an already-expired direct
	// authorization as fresh (F825-02). The lookup deadline itself is unchanged.
	evaluatedAt := policyExplainNow(deps)
	out.EvaluatedAt = evaluatedAt.UTC().Format(time.RFC3339)

	verdict := policy.ExplainDestination(policy.ExplainDestinationInput{
		Enabled:     true,
		Snapshot:    deps.Snapshot,
		Names:       names,
		Addresses:   addresses,
		Resolved:    resolution.Error == "" || len(req.Addresses) > 0,
		EvidenceFor: policyExplainEvidenceReader(deps, evaluatedAt),
		Prohibited:  forwarder.IsProhibitedIPv4Destination,
	})
	policyExplainApply(&out, verdict, evaluatedAt)
	policyExplainAgeLimitation(&out)
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

	// ExchangeReadOnly runs the production exchange with the production budgets
	// and failover, and deliberately does not publish the outcome to the live
	// resolver's health status (review finding HIGH-01): a dry run must not clear
	// or invent an operator-visible upstream failure.
	resp, err := deps.Resolver.ExchangeReadOnly(lookupCtx, query)
	if err != nil {
		res.Error = err.Error()
		return []string{req.Name}, nil, res
	}

	// The answer is classified by the observation path's own code (review finding
	// HIGH-03). A second traversal here would let this endpoint explain a
	// destination from an answer that can never become trusted evidence.
	answer := gatewaydns.ClassifyAnswer(query, resp, policyExplainAnswerMaxTTL)
	if !answer.Valid {
		res.Error = policyExplainIgnoredAnswerPrefix + ": " + answer.Reason
		return []string{req.Name}, nil, res
	}
	// The explainer evaluates every destination the answer resolves to, not the
	// subset eligible to become evidence (owner review HIGH-01): an address the
	// data path drops, such as 10.0.0.5, is exactly what an operator needs to see
	// reported with the decision production would give it. Production's evidence
	// set (answer.EvidenceAddresses) is deliberately not used here.
	res.Names = answer.Names
	res.Addresses = policyExplainAddrStrings(answer.ResolvedAddresses)
	if len(answer.ResolvedAddresses) == 0 {
		// The names are still returned: an answer without an address does not
		// erase the submitted name, so a rule match stays reportable.
		res.Error = "the answer contains no usable IPv4 address"
	}
	return answer.Names, answer.ResolvedAddresses, res
}

// policyExplainEvidenceReader returns the evidence lookup for the selected
// session, or nil when no session (or no cache scope) is available. The reader
// only ever calls Inspect.
func policyExplainEvidenceReader(deps policyExplainDeps, evaluatedAt time.Time) func(netip.Addr) *policy.Evidence {
	if deps.SessionScope == nil {
		return nil
	}
	generation := ""
	if deps.Snapshot != nil {
		generation = deps.Snapshot.Generation()
	}
	return func(addr netip.Addr) *policy.Evidence {
		evidence := deps.SessionScope.Inspect(addr, generation, evaluatedAt)
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
func policyExplainApply(out *PolicyExplanation, verdict policy.DestinationExplanation, evaluatedAt time.Time) {
	out.Decision = string(verdict.Decision)
	out.Reason = string(verdict.Reason)
	out.Summary = string(verdict.Summary)
	out.Prospective = policyExplainProspective(verdict.Prospective)
	out.Prefix = policyExplainPrefix(verdict.Prefix)
	out.Evidence = policyExplainEvidence(verdict.Evidence, evaluatedAt)
	for _, v := range verdict.Addresses {
		out.Addresses = append(out.Addresses, PolicyExplainAddress{
			Address:  v.Address.String(),
			Decision: string(v.Decision),
			Reason:   string(v.Reason),
			Prefix:   policyExplainPrefix(v.Prefix),
			Evidence: policyExplainEvidence(v.Evidence, evaluatedAt),
		})
	}
}

// policyExplainProspective copies the rule classification into the wire shape.
// It is returned as its own object so a caller cannot read the classification as
// the current action.
func policyExplainProspective(prospective *policy.ProspectiveRule) *PolicyExplainProspective {
	out := &PolicyExplainProspective{Matched: prospective != nil}
	if prospective == nil {
		return out
	}
	out.Decision = string(prospective.Decision)
	out.Reason = string(prospective.Basis)
	out.Rule = policyExplainRuleMatch(prospective.Rule)
	out.MatchedName = prospective.MatchedName
	out.RequiresObservedAnswer = true
	return out
}

func policyExplainRuleMatch(match *policy.DomainRuleMatch) *PolicyExplainRule {
	if match == nil {
		return nil
	}
	return &PolicyExplainRule{
		Base:         match.Base,
		Shape:        string(match.Shape),
		Contributors: policyExplainSources(match.Contributors),
		SourceKind:   policyExplainSourceKind(match.Contributors),
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
	policyExplainAge(&state, evidence, now)
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

// policyExplainAge states the elapsed age of fresh evidence, or why none can be
// stated. The age comes from the instant the observation was recorded and is
// never computed from the deadline or the TTL, so remaining lifetime cannot be
// presented as age.
func policyExplainAge(state *PolicyExplainEvidence, evidence *policy.Evidence, now time.Time) {
	age, reason := evidence.Age(now)
	if reason != policy.AgeReported {
		state.AgeUnavailableReason = string(reason)
		return
	}
	seconds := int64(age / time.Second)
	state.AgeSeconds = &seconds
}

// policyExplainAgeLimitation adds the answer-level caveat when any reported
// evidence is fresh but carries no recorded observation instant.
func policyExplainAgeLimitation(out *PolicyExplanation) {
	unrecorded := func(e *PolicyExplainEvidence) bool {
		return e != nil && e.AgeUnavailableReason == string(policy.AgeInstantNotRecorded)
	}
	found := unrecorded(out.Evidence)
	for _, a := range out.Addresses {
		found = found || unrecorded(a.Evidence)
	}
	if found {
		out.Limitations = append(out.Limitations, PolicyLimitNoEvidenceAge)
	}
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
