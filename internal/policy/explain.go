package policy

import (
	"net/netip"
)

// This file composes what the data path does with one destination and names the
// cause (issue #825). It is pure: every input is passed in, nothing is recorded,
// and no cache, matcher or resolver is touched.
//
// Two different questions are answered, and they must not be confused:
//
//  1. The CURRENT ACTION for the evaluated addresses. This has to follow the
//     packet path exactly (Forwarder.routeClientPBR), which has no name check at
//     all: after the prohibited-destination guard it tests the snapshot CIDR and
//     the session's cached PROXY decision, then the session's cached DIRECT
//     decision, and finally falls back to PROXY.
//
//    	prohibited destination        → DROP
//    	proxy-required CIDR           → PROXY (the prefix, and its lists)
//    	fresh cached PROXY evidence   → PROXY (the cache keeps PROXY over DIRECT)
//    	fresh cached DIRECT evidence  → DIRECT
//    	expired / quarantined / stale → PROXY, and which of the three it is
//    	no trusted observation        → PROXY (the safe default, never DIRECT)
//
//  2. The PROSPECTIVE rule classification for the submitted name (and its CNAME
//     chain). A matched domain rule is a real fact about the policy, but it is
//     NOT the current route: the data path only ever sees the address, and the
//     rule becomes that address's route after the client's own answer for the
//     name is observed under the current policy. A dry run that treats the
//     submitted name as such an observation reports the opposite of the real
//     eligibility for a listed name sharing an address the session already
//     routes direct. The classification is therefore returned separately and
//     labeled prospective; it never decides the current action.
//
// A name that cannot be resolved is never given an invented verdict: with no
// address there is no destination to route, so the answer is UNKNOWN with
// CauseNameUnresolved even when a rule matches, and the rule is still reported
// as the prospective classification.

// Action is what production does with a packet for a destination.
type Action string

const (
	// ActionDirect means the packet egresses directly over the WAN.
	ActionDirect Action = "DIRECT"
	// ActionProxy means the packet is sent to the client's proxy backend.
	ActionProxy Action = "PROXY"
	// ActionDrop means the packet is dropped by the prohibited-destination guard.
	ActionDrop Action = "DROP"
	// ActionUnknown means the inputs were not sufficient to decide.
	ActionUnknown Action = "UNKNOWN"
)

// Cause is the machine-readable reason a current action was reached, or the
// basis of a prospective rule classification. Each value names one specific
// cause, never a generic verdict.
type Cause string

const (
	// CausePolicyDisabled: policy routing is off, so every destination takes the
	// legacy proxy route. Nothing else is evaluated.
	CausePolicyDisabled Cause = "policy_disabled"
	// CauseNoPolicySnapshot: policy routing reports itself active but no snapshot
	// is published, so no rule can be evaluated. Fail closed.
	CauseNoPolicySnapshot Cause = "no_policy_snapshot"
	// CauseProhibitedDestination: the address is loopback, private, link-local,
	// CGNAT, multicast, reserved or a test range, so the data path drops it.
	CauseProhibitedDestination Cause = "prohibited_destination"
	// CauseDomainRule is the basis of a prospective classification: the submitted
	// name matches a proxy-required domain rule. It is not a current action.
	CauseDomainRule Cause = "domain_rule"
	// CauseCNAMERule is the basis of a prospective classification: a name in the
	// submitted name's CNAME chain matches a proxy-required domain rule.
	CauseCNAMERule Cause = "cname_rule"
	// CauseCIDRRule: an address matches a proxy-required CIDR prefix.
	CauseCIDRRule Cause = "cidr_rule"
	// CauseCachedProxyEvidence: the session's cache holds a fresh PROXY decision
	// for the address, and the cache keeps PROXY over DIRECT. The cache stores a
	// decision and a deadline only, so this states what the entry is, not which
	// name produced it.
	CauseCachedProxyEvidence Cause = "cached_proxy_evidence"
	// CauseFreshEvidenceDirect: fresh, trusted DNS evidence from the session says
	// the destination is not policy-routed.
	CauseFreshEvidenceDirect Cause = "fresh_evidence_direct"
	// CauseExpiredEvidence: the session holds evidence for the address but its
	// deadline has passed, so it no longer authorizes the direct path.
	CauseExpiredEvidence Cause = "expired_evidence"
	// CauseEvictedEvidence: the session's cache overflowed and was quarantined,
	// which dropped its entries. This is the only eviction that leaves a
	// quarantine marker; an ordinary entry evicted for capacity is reported as
	// absent, which is what the cache retains.
	CauseEvictedEvidence Cause = "evicted_evidence"
	// CauseStaleEvidence: the session's evidence belongs to a previous policy
	// generation and was discarded when the policy was refreshed.
	CauseStaleEvidence Cause = "stale_evidence_generation"
	// CauseNoEvidence: the session holds no trusted observation for the address
	// (or no session was selected): the safe default, PROXY, never DIRECT.
	CauseNoEvidence Cause = "no_trusted_evidence"
	// CauseNoUsableAddress: the name resolved, but to no address this path can
	// evaluate (no A record, or only addresses that are not usable IPv4).
	CauseNoUsableAddress Cause = "no_usable_address"
	// CauseNameUnresolved: the name could not be resolved, so there is no
	// destination to route and no truthful current action to give.
	CauseNameUnresolved Cause = "name_unresolved"
)

// Summary names how the per-address verdicts produced the headline decision.
type Summary string

const (
	// SummaryNone means there was nothing to aggregate (disabled policy, or no
	// evaluable address).
	SummaryNone Summary = "none"
	// SummarySingle means exactly one address was evaluated, so the headline is
	// that verdict.
	SummarySingle Summary = "single"
	// SummaryUnanimous means every evaluated address reached the same verdict.
	SummaryUnanimous Summary = "unanimous"
	// SummaryMostRestrictive means the addresses disagreed and the headline is
	// the most restrictive verdict among them (DROP > PROXY > UNKNOWN > DIRECT),
	// so the answer never looks safer than the worst address.
	SummaryMostRestrictive Summary = "most_restrictive"
)

// actionSeverity orders actions from least to most restrictive. It is what
// SummaryMostRestrictive maximizes.
func actionSeverity(a Action) int {
	switch a {
	case ActionDrop:
		return 3
	case ActionProxy:
		return 2
	case ActionUnknown:
		return 1
	case ActionDirect:
		return 0
	default:
		return 2
	}
}

// ProspectiveRule is the rule classification for the submitted name and its
// CNAME chain. It is deliberately a separate object from the current action:
// production never evaluates a name while forwarding a packet, so this
// classification only becomes the destination's route once the client's own
// answer for the name is observed under the current policy.
type ProspectiveRule struct {
	// Decision is the action this name would take when observed: PROXY.
	Decision Action
	// Basis says whether the queried name or a CNAME target matched.
	Basis Cause
	// Rule is the matched rule, its shape and the lists that contributed it.
	Rule *DomainRuleMatch
	// MatchedName is the name in the traversal that matched: the queried name
	// itself, or a CNAME target.
	MatchedName string
}

// AddressExplanation is the verdict for one destination address.
type AddressExplanation struct {
	Address  netip.Addr
	Decision Action
	Reason   Cause
	// Prefix is the matching CIDR when Reason is CauseCIDRRule.
	Prefix *CIDRRuleMatch
	// Evidence is the session evidence this verdict rests on, when it rests on
	// evidence at all.
	Evidence *Evidence
}

// DestinationExplanation is the explanation for one destination.
type DestinationExplanation struct {
	// Decision and Reason describe the CURRENT action for the evaluated
	// addresses, following the packet path's precedence.
	Decision Action
	Reason   Cause
	// Prospective is the rule classification of the submitted names. nil when no
	// rule matched. It never participates in Decision.
	Prospective *ProspectiveRule
	// Addresses carries one verdict per evaluated address, in input order.
	Addresses []AddressExplanation
	// Summary names how Addresses produced Decision.
	Summary Summary
	// Prefix and Evidence are the prefix and evidence of the verdict that
	// produced the headline decision, for convenience.
	Prefix   *CIDRRuleMatch
	Evidence *Evidence
}

// ExplainDestinationInput is everything one explanation needs. Each dependency
// is passed in so this file stays pure and a test can drive it with the real
// matcher and the real route cache without a data path.
type ExplainDestinationInput struct {
	// Enabled reports whether policy routing is active. When false the answer is
	// the legacy proxy route and nothing else is evaluated.
	Enabled bool
	// Snapshot is the live policy snapshot. nil is treated as "no rules".
	Snapshot *Snapshot
	// Names are canonical names in the order production traverses them: the
	// queried name first, then each CNAME target. They are used only for the
	// prospective classification.
	Names []string
	// Addresses are the addresses to evaluate: the caller's own addresses, or
	// the terminal A records of the resolution.
	Addresses []netip.Addr
	// Resolved reports whether Names and Addresses came from a successful
	// lookup. A caller that supplied its own addresses sets it to true.
	Resolved bool
	// EvidenceFor returns the session evidence for an address, or nil when the
	// session holds none. It must be read-only; nil means no session was
	// selected, which the caller reports separately.
	EvidenceFor func(netip.Addr) *Evidence
	// Prohibited reports whether production would drop the address. It is
	// injected because the classification lives in the forwarder, which imports
	// this package and not the other way round.
	Prohibited func(netip.Addr) bool
}

// ExplainDestination composes the current action for the evaluated addresses and
// the prospective rule classification for the submitted names.
func ExplainDestination(in ExplainDestinationInput) DestinationExplanation {
	if !in.Enabled {
		return DestinationExplanation{Decision: ActionProxy, Reason: CausePolicyDisabled, Summary: SummaryNone}
	}
	if in.Snapshot == nil {
		// Policy routing reports itself active but published nothing. Do not
		// invent a rule verdict: fail closed and say why.
		return DestinationExplanation{Decision: ActionProxy, Reason: CauseNoPolicySnapshot, Summary: SummaryNone}
	}

	out := DestinationExplanation{
		Prospective: prospectiveRule(in.Snapshot, in.Names),
		Addresses:   make([]AddressExplanation, 0, len(in.Addresses)),
	}
	for _, addr := range in.Addresses {
		out.Addresses = append(out.Addresses, explainAddress(in, addr))
	}
	if len(out.Addresses) == 0 {
		// No destination means no current action. The prospective classification,
		// when there is one, still describes what this name would do once it
		// resolves and is observed.
		out.Decision, out.Summary = ActionUnknown, SummaryNone
		if in.Resolved {
			out.Reason = CauseNoUsableAddress
		} else {
			out.Reason = CauseNameUnresolved
		}
		return out
	}

	out.Decision, out.Summary = summariseActions(out.Addresses)
	out.Reason = explainDecisiveReason(out)
	// The prefix and evidence shown at the top level belong to the address that
	// produced the headline decision, so the two levels cannot disagree.
	for i := range out.Addresses {
		if out.Addresses[i].Decision != out.Decision {
			continue
		}
		out.Prefix = out.Addresses[i].Prefix
		out.Evidence = out.Addresses[i].Evidence
		break
	}
	return out
}

// prospectiveRule classifies the submitted names against the snapshot without
// touching the current action. The queried name is preferred over a CNAME
// target, which keeps the answer specific; production marks the whole answer
// proxy-required when any traversed name matches.
func prospectiveRule(snap *Snapshot, names []string) *ProspectiveRule {
	if snap == nil {
		return nil
	}
	for i, name := range names {
		match, ok := snap.ExplainCanonicalDomain(name)
		if !ok {
			continue
		}
		basis := CauseDomainRule
		if i > 0 {
			basis = CauseCNAMERule
		}
		return &ProspectiveRule{
			Decision:    ActionProxy,
			Basis:       basis,
			Rule:        &match,
			MatchedName: name,
		}
	}
	return nil
}

// explainAddress is one address's current action, in the order the data path
// applies. It deliberately does not look at domain names: the packet path never
// does.
func explainAddress(in ExplainDestinationInput, addr netip.Addr) AddressExplanation {
	v := AddressExplanation{Address: addr}

	if in.Prohibited != nil && in.Prohibited(addr) {
		v.Decision, v.Reason = ActionDrop, CauseProhibitedDestination
		return v
	}
	if match, ok := in.Snapshot.ExplainIPv4(addr); ok {
		v.Decision, v.Reason, v.Prefix = ActionProxy, CauseCIDRRule, &match
		return v
	}

	if in.EvidenceFor == nil {
		v.Decision, v.Reason = ActionProxy, CauseNoEvidence
		return v
	}
	evidence := in.EvidenceFor(addr)
	v.Decision, v.Reason = evidenceVerdict(evidence)
	v.Evidence = evidence
	return v
}

// evidenceVerdict maps the state of a session's evidence to the action the data
// path takes and the cause to report. It is the only place the evidence states
// become decisions, so the mapping cannot drift between the headline and the
// per-address verdicts.
func evidenceVerdict(evidence *Evidence) (Action, Cause) {
	if evidence == nil {
		return ActionProxy, CauseNoEvidence
	}
	switch evidence.State {
	case EvidenceFresh:
		if evidence.Decision == Direct {
			return ActionDirect, CauseFreshEvidenceDirect
		}
		// The cache keeps PROXY over DIRECT, so a fresh PROXY entry means this
		// address is proxy-required for the session. The entry does not record
		// which name produced it.
		return ActionProxy, CauseCachedProxyEvidence
	case EvidenceExpired:
		return ActionProxy, CauseExpiredEvidence
	case EvidenceQuarantined:
		return ActionProxy, CauseEvictedEvidence
	case EvidenceStaleGeneration:
		return ActionProxy, CauseStaleEvidence
	default:
		return ActionProxy, CauseNoEvidence
	}
}

// summariseActions reduces the per-address verdicts to one headline decision.
//
// The rule is the whole contract of the summary, so it is deliberately simple:
// agreeing addresses give that verdict (SummaryUnanimous), and disagreeing
// addresses give the most restrictive one (SummaryMostRestrictive) so a name is
// never reported as safer than its worst address.
func summariseActions(verdicts []AddressExplanation) (Action, Summary) {
	if len(verdicts) == 0 {
		return ActionUnknown, SummaryNone
	}
	if len(verdicts) == 1 {
		return verdicts[0].Decision, SummarySingle
	}
	unanimous := true
	decision := verdicts[0].Decision
	for _, v := range verdicts[1:] {
		if v.Decision != decision {
			unanimous = false
		}
		if actionSeverity(v.Decision) > actionSeverity(decision) {
			decision = v.Decision
		}
	}
	if unanimous {
		return decision, SummaryUnanimous
	}
	return decision, SummaryMostRestrictive
}

// explainDecisiveReason returns the reason of the verdict that produced the
// headline decision, so the top-level reason always describes the top-level
// decision.
func explainDecisiveReason(out DestinationExplanation) Cause {
	for _, v := range out.Addresses {
		if v.Decision == out.Decision {
			return v.Reason
		}
	}
	return CauseNoEvidence
}
