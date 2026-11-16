package vpn

// This file holds the wire shape of the read-only policy dry run (issue #825):
// the answer the admin endpoint returns and the tokens inside it. The behavior
// lives in vpn_pbr_policy_explain.go; keeping the shape separate keeps each file
// inside the repository's size budget.

// PolicyExplainInput echoes what was explained.
type PolicyExplainInput struct {
	Value      string `json:"value"`
	Kind       string `json:"kind"`
	Normalized string `json:"normalized,omitempty"`
	Session    string `json:"session,omitempty"`
}

// PolicyExplainState is the policy state the answer was computed against.
type PolicyExplainState struct {
	Enabled      bool   `json:"enabled"`
	GenerationID string `json:"generation_id,omitempty"`
	Version      uint64 `json:"version"`
	DomainRules  int    `json:"domain_rules"`
	CIDRRules    int    `json:"cidr_rules"`
}

// PolicyExplainRule names a matched domain rule.
//
// Contributors lists the lists that contributed to the rule's BASE ENTRY. A base
// entry merges the shapes its sources supplied, so a contributor may supply only
// a shape this name does not use; it is a base-entry contributor list, not a
// proven supplier of the matched shape.
type PolicyExplainRule struct {
	Base         string   `json:"base"`
	Shape        string   `json:"shape"`
	Contributors []string `json:"contributors"`
	SourceKind   string   `json:"source_kind,omitempty"`
}

// PolicyExplainPrefix names the CIDR prefix that caused a proxy decision.
type PolicyExplainPrefix struct {
	Prefix     string   `json:"prefix"`
	Sources    []string `json:"sources"`
	SourceKind string   `json:"source_kind,omitempty"`
}

// PolicyExplainProspective is the rule classification for the submitted name and
// its CNAME chain. It is explicitly NOT the current action: the packet path
// never evaluates a name, so this classification only becomes the destination's
// route once the client's own answer for the name is observed under the current
// policy.
type PolicyExplainProspective struct {
	// Matched reports whether any submitted or CNAME name matches a rule.
	Matched bool `json:"matched"`
	// Decision is "PROXY" when matched, empty otherwise.
	Decision string `json:"decision,omitempty"`
	// Reason is "domain_rule" or "cname_rule" when matched.
	Reason string `json:"reason,omitempty"`
	// Rule carries the matched rule, its shape and its base contributors.
	Rule *PolicyExplainRule `json:"rule,omitempty"`
	// MatchedName is the queried name or the CNAME target that matched.
	MatchedName string `json:"matched_name,omitempty"`
	// RequiresObservedAnswer is always true for a match: the current route
	// changes only when a client answer for that name is observed.
	RequiresObservedAnswer bool `json:"requires_observed_answer,omitempty"`
}

// PolicyExplainEvidence is the session evidence a verdict rests on.
type PolicyExplainEvidence struct {
	State            string `json:"state"`
	Decision         string `json:"decision,omitempty"`
	Generation       string `json:"generation,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
	Source           string `json:"source"`
}

// PolicyExplainAddress is one address's current-action verdict.
type PolicyExplainAddress struct {
	Address  string                 `json:"address"`
	Decision string                 `json:"decision"`
	Reason   string                 `json:"reason"`
	Prefix   *PolicyExplainPrefix   `json:"prefix,omitempty"`
	Evidence *PolicyExplainEvidence `json:"evidence,omitempty"`
}

// PolicyExplainResolution states how the name was resolved.
type PolicyExplainResolution struct {
	Method      string   `json:"method"`
	Nameservers []string `json:"nameservers,omitempty"`
	TimeoutMS   int64    `json:"timeout_ms,omitempty"`
	Names       []string `json:"names,omitempty"`
	Addresses   []string `json:"addresses"`
	Error       string   `json:"error,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// PolicyExplanation is the operator-facing answer. It carries no client DNS
// history: the resolved name is the one the operator asked about.
//
// Decision and Reason describe the current action for the evaluated addresses.
// Prospective, when present, is the rule classification of the submitted names
// and never participates in that action.
type PolicyExplanation struct {
	Input       PolicyExplainInput        `json:"input"`
	Policy      PolicyExplainState        `json:"policy"`
	Decision    string                    `json:"decision"`
	Reason      string                    `json:"reason"`
	Summary     string                    `json:"summary"`
	Prospective *PolicyExplainProspective `json:"prospective,omitempty"`
	Prefix      *PolicyExplainPrefix      `json:"prefix,omitempty"`
	Addresses   []PolicyExplainAddress    `json:"addresses"`
	Evidence    *PolicyExplainEvidence    `json:"evidence,omitempty"`
	Resolution  PolicyExplainResolution   `json:"resolution"`
	// EvaluatedAt is the instant the evidence was evaluated at, sampled after the
	// optional blocking lookup: the answer's freshness claim is as of this time.
	EvaluatedAt string   `json:"evaluated_at"`
	Limitations []string `json:"limitations"`
	ReadOnly    bool     `json:"read_only"`
}
