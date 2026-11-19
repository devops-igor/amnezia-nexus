package forwarder

import (
	"net/netip"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The routing contract for a policy-routed packet, in one place (issue #918).
//
// This file is the SPECIFICATION of which rule wins and which rule a flow's
// record names. It is deliberately side-effect free: the caller owns recording
// the decision and dispatching the packet, so the contract can be read and
// tested without the packet plumbing.
//
// The accepted contract, in order:
//
//	1. invalid, prohibited or internal destination        -> DROP
//	2. explicit operator PROXY override                   -> PROXY
//	3. inside the Russian allocation AND a known
//	   multi-region CDN                                   -> PROXY
//	4. inside the Russian allocation, no CDN exclusion    -> DIRECT
//	5. unknown or uncovered destination                   -> PROXY
//	6. required egress unavailable                        -> DROP, no switch
//
// Row 6 is realized where the availability is known rather than here: the
// DIRECT dispatch returns the refusal (routeDirectDecision/sendToDirectEgress)
// and the packet path records it in the DROP ledger with the producer's reason
// instead of re-deciding the packet as PROXY. Every other row is decided here.
//
// While the DNS evidence subsystem exists, one MIGRATION row is inserted between
// rows 2 and 3. It is the block marked TEMPORARY below, it is the only place
// that reads evidence, and deleting it yields the final contract without
// touching another row.

// DestinationClassifier answers what is known about one destination address.
// policy.AddressClassifier is the production implementation; a nil classifier
// means no classification input is installed, and the contract then keeps its
// fail-safe default, which is today's behavior.
type DestinationClassifier interface {
	Classify(addr netip.Addr) policy.DestinationClassification
}

// egressInput is every fact the contract is decided from. All of it is read
// once by the caller, so a decision and the metadata recorded with it describe
// the same instant.
type egressInput struct {
	// prohibitedErr is the address-side prohibited/internal verdict for this
	// destination, from the same ValidateDirectDestination the dispatch path
	// applies; nil means permitted. An operator DIRECT input cannot bypass it:
	// it is row 1, above every input that could ask for DIRECT.
	prohibitedErr error
	// proxyOverride reports an explicit PROXY match from the published policy
	// snapshot, which today means an operator-supplied address range.
	proxyOverride bool
	// migrationEvidence is the client-scoped DNS evidence of the migration
	// contract. policy.Unknown means "no usable evidence" and leaves the
	// address classifier to decide.
	//
	// TEMPORARY: this field and the block that reads it are the migration row.
	migrationEvidence policy.Decision
	// classification is the address classifier's answer for this destination.
	// The zero value means uncovered, which proxies.
	classification policy.DestinationClassification
}

// egressDecision is the contract's answer for one packet.
type egressDecision struct {
	// choice is EgressChoiceDirect or EgressChoiceProxy. EgressChoiceNone means
	// DROP: the packet must not leave through either path.
	choice EgressChoice
	// reason is the branch that decided, recorded on the flow for a routed
	// packet. Empty for a DROP, which has no flow to attribute.
	reason EgressReason
	// dropReason is the DROP ledger token naming the producer that refused the
	// packet. Empty unless the decision is a DROP.
	dropReason string
	// dropErr is the refusal a DROP returns to its caller, so a dropped packet
	// is never reported as accepted. Empty unless the decision is a DROP.
	dropErr error
}

// dropped reports whether the decision refuses the packet.
func (d egressDecision) dropped() bool {
	return d.choice == EgressChoiceNone
}

// decideEgress applies the contract. It reads nothing global and has no side
// effects; the caller supplies every input.
func decideEgress(in egressInput) egressDecision {
	// Row 1 — DROP. Prohibited, internal and invalid destinations are refused
	// for an address-based DIRECT rule exactly as they are for the proxy path,
	// and before any input that could route them.
	if in.prohibitedErr != nil {
		return egressDecision{
			choice:     EgressChoiceNone,
			dropReason: DropReasonProhibitedDestination,
			dropErr:    in.prohibitedErr,
		}
	}

	// Row 2 — PROXY from an explicit operator override. This is the published
	// policy's address rule, and it wins over the classifier so an operator can
	// always take a destination off the direct path.
	if in.proxyOverride {
		return egressDecision{choice: EgressChoiceProxy, reason: EgressReasonProxyCIDRRule}
	}

	// MIGRATION ROW — TEMPORARY. While the DNS evidence subsystem exists, the
	// session's retained evidence sits between the explicit override and the
	// address classifier: observed PROXY keeps a shared address proxied, and
	// observed DIRECT still routes direct. Removing this block (and the
	// migrationEvidence field above) yields the final contract and changes no
	// other row.
	switch in.migrationEvidence {
	case policy.Direct:
		return egressDecision{choice: EgressChoiceDirect, reason: EgressReasonEvidenceDirect}
	case policy.Proxy:
		return egressDecision{choice: EgressChoiceProxy, reason: EgressReasonProxyCachedEvidence}
	}

	// Row 3 — PROXY: inside the Russian allocation, but the range belongs to a
	// multi-region CDN. A CDN address serves foreign services whatever the
	// allocation says, so it stays proxied.
	if in.classification.InAllocation && in.classification.CDNProvider != "" {
		return egressDecision{choice: EgressChoiceProxy, reason: EgressReasonAllocationCDNExcluded}
	}

	// Row 4 — DIRECT from allocation membership with no CDN exclusion. The
	// recorded reason says allocation-matched, never that the service is hosted
	// in Russia: membership is an approximation and reachability is unproven.
	if in.classification.AllocationRoutesDirect() {
		return egressDecision{choice: EgressChoiceDirect, reason: EgressReasonAllocationDirect}
	}

	// Row 5 — PROXY: unknown or uncovered, the fail-safe default.
	return egressDecision{choice: EgressChoiceProxy, reason: EgressReasonNoTrustedEvidence}
}
