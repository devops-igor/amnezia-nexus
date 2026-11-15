package policy

import (
	"net/netip"
)

// This file composes the decision a packet would take for one destination and
// names its cause (issue #825). It is pure: every input is passed in, nothing is
// recorded, and no cache, matcher or resolver is touched.
//
// The order of the checks is the order the data path applies them in
// (Forwarder.routeClientPBR):
//
//	1. policy routing disabled        → the legacy route, PROXY for everything
//	2. prohibited destination         → DROP
//	3. proxy-required domain rule     → PROXY (the rule, and the list, named)
//	4. proxy-required CIDR            → PROXY (the prefix, and the list, named)
//	5. fresh Direct evidence          → DIRECT
//	6. fresh Proxy evidence           → PROXY (another name shares this address)
//	7. expired / quarantined / stale  → PROXY, and which of the three it is
//	8. no trusted observation at all   → PROXY (the safe default, never DIRECT)
//
// A name that cannot be resolved is never given an invented verdict: with no
// rule it is UNKNOWN with CauseNameUnresolved, and with a rule it is PROXY with
// that rule as the cause, because the rule does not depend on the answer.

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

// Cause is the machine-readable reason a decision was reached. It is the field
// an operator acts on: each value names one specific cause, never a generic
// verdict.
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
	// CauseDomainRule: the queried name matches a proxy-required domain rule.
	CauseDomainRule Cause = "domain_rule"
	// CauseCNAMERule: the queried name itself matches nothing, but a name in its
	// CNAME chain matches a proxy-required domain rule.
	CauseCNAMERule Cause = "cname_rule"
	// CauseCIDRRule: an address matches a proxy-required CIDR prefix.
	CauseCIDRRule Cause = "cidr_rule"
	// CauseSharedIPConflict: no rule matches, but the session holds a fresh PROXY
	// observation for the address, which the cache keeps over DIRECT because
	// PROXY wins. Another name sharing this address is proxy-required.
	CauseSharedIPConflict Cause = "shared_ip_conflict"
	// CauseFreshEvidenceDirect: no rule matches and fresh, trusted DNS evidence
	// from the session says the destination is not policy-routed.
	CauseFreshEvidenceDirect Cause = "fresh_evidence_direct"
	// CauseExpiredEvidence: the session holds evidence for the address but its
	// deadline has passed, so it no longer authorizes the direct path.
	CauseExpiredEvidence Cause = "expired_evidence"
	// CauseEvictedEvidence: the session's cache overflowed and was quarantined,
	// which dropped its entries. This is the only eviction the cache performs.
	CauseEvictedEvidence Cause = "evicted_evidence"
	// CauseStaleEvidence: the session's evidence belongs to a previous policy
	// generation and was discarded when the policy was refreshed.
	CauseStaleEvidence Cause = "stale_evidence_generation"
	// CauseNoEvidence: the session holds no trusted observation for the address,
	// which is the safe default: PROXY, never DIRECT.
	CauseNoEvidence Cause = "no_trusted_evidence"
	// CauseNoUsableAddress: the name resolved, but to no address this path can
	// evaluate (no A record, or only addresses that are not usable IPv4).
	CauseNoUsableAddress Cause = "no_usable_address"
	// CauseNameUnresolved: the name could not be resolved, and no rule matches
	// it, so there is no truthful verdict to give.
	CauseNameUnresolved Cause = "name_unresolved"
)

// Summary names how the per-address verdicts produced the headline decision.
type Summary string

const (
	// SummaryNone means there was nothing to aggregate (disabled policy, or an
	// unresolved name with no rule).
	SummaryNone Summary = "none"
	// SummarySingle means zero or one address was evaluated, so the headline is
	// that verdict.
	SummarySingle Summary = "single"
	// SummaryUnanimous means every evaluated address reached the same verdict.
	SummaryUnanimous Summary = "unanimous"
	// SummaryRuleOnly means a rule matched the name without any address being
	// evaluated, because the name did not resolve.
	SummaryRuleOnly Summary = "rule_only"
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
	Decision Action
	Reason   Cause
	// Rule is the domain rule that decided the whole name, when one did. It is
	// set for CauseDomainRule and CauseCNAMERule.
	Rule *DomainRuleMatch
	// RuleName is the name in the traversal that matched the rule: the queried
	// name itself, or a CNAME target for CauseCNAMERule.
	RuleName string
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
	// queried name first, then each CNAME target.
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

// ExplainDestination composes the decision and its cause for one destination.
func ExplainDestination(in ExplainDestinationInput) DestinationExplanation {
	if !in.Enabled {
		return DestinationExplanation{Decision: ActionProxy, Reason: CausePolicyDisabled, Summary: SummaryNone}
	}
	if in.Snapshot == nil {
		// Policy routing reports itself active but published nothing. Do not
		// invent a rule verdict: fail closed and say why.
		return DestinationExplanation{Decision: ActionProxy, Reason: CauseNoPolicySnapshot, Summary: SummaryNone}
	}

	rule, ruleName, ruleCause := explainDomainRule(in.Snapshot, in.Names)

	if len(in.Addresses) == 0 {
		switch {
		case rule != nil:
			// A rule does not depend on the answer, so it is a truthful verdict
			// even when the name does not resolve.
			return DestinationExplanation{
				Decision: ActionProxy, Reason: ruleCause, Rule: rule, RuleName: ruleName, Summary: SummaryRuleOnly,
			}
		case !in.Resolved:
			return DestinationExplanation{Decision: ActionUnknown, Reason: CauseNameUnresolved, Summary: SummaryNone}
		default:
			return DestinationExplanation{Decision: ActionUnknown, Reason: CauseNoUsableAddress, Summary: SummaryNone}
		}
	}

	out := DestinationExplanation{
		Rule:      rule,
		RuleName:  ruleName,
		Addresses: make([]AddressExplanation, 0, len(in.Addresses)),
	}
	for _, addr := range in.Addresses {
		out.Addresses = append(out.Addresses, explainAddress(in, addr, rule, ruleCause))
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

// explainDomainRule returns the first rule match in traversal order: the queried
// name is preferred, then each CNAME target. That is also what production's
// observation code decides — it marks the answer proxy-required when any
// traversed name matches — but naming the first match keeps the answer specific.
func explainDomainRule(snap *Snapshot, names []string) (*DomainRuleMatch, string, Cause) {
	if snap == nil {
		return nil, "", ""
	}
	for i, name := range names {
		if match, ok := snap.ExplainCanonicalDomain(name); ok {
			if i == 0 {
				return &match, name, CauseDomainRule
			}
			return &match, name, CauseCNAMERule
		}
	}
	return nil, "", ""
}

// explainAddress is one address's verdict, in the order the data path applies.
func explainAddress(in ExplainDestinationInput, addr netip.Addr, rule *DomainRuleMatch, ruleCause Cause) AddressExplanation {
	v := AddressExplanation{Address: addr}

	if in.Prohibited != nil && in.Prohibited(addr) {
		v.Decision, v.Reason = ActionDrop, CauseProhibitedDestination
		return v
	}
	if rule != nil {
		v.Decision, v.Reason = ActionProxy, ruleCause
		return v
	}
	if match, ok := in.Snapshot.ExplainIPv4(addr); ok {
		v.Decision, v.Reason, v.Prefix = ActionProxy, CauseCIDRRule, &match
		return v
	}

	var evidence *Evidence
	if in.EvidenceFor != nil {
		evidence = in.EvidenceFor(addr)
	}
	if evidence == nil {
		v.Decision, v.Reason = ActionProxy, CauseNoEvidence
		return v
	}
	v.Evidence = evidence

	switch evidence.State {
	case EvidenceFresh:
		if evidence.Decision == Direct {
			v.Decision, v.Reason = ActionDirect, CauseFreshEvidenceDirect
			return v
		}
		// A fresh PROXY observation with no matching rule means another name that
		// resolves to this shared address is proxy-required, and PROXY wins in the
		// cache.
		v.Decision, v.Reason = ActionProxy, CauseSharedIPConflict
	case EvidenceExpired:
		v.Decision, v.Reason = ActionProxy, CauseExpiredEvidence
	case EvidenceQuarantined:
		v.Decision, v.Reason = ActionProxy, CauseEvictedEvidence
	case EvidenceStaleGeneration:
		v.Decision, v.Reason = ActionProxy, CauseStaleEvidence
	default:
		v.Decision, v.Reason = ActionProxy, CauseNoEvidence
	}
	return v
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
