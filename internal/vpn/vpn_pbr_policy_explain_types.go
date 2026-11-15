package vpn

// This file holds the wire shape of the read-only policy dry run (issue #825):
// the answer the admin endpoint returns and the tokens inside it. The behaviour
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

// PolicyExplainRule names the domain rule that caused a proxy decision.
type PolicyExplainRule struct {
	Base        string   `json:"base"`
	Shape       string   `json:"shape"`
	Sources     []string `json:"sources"`
	MatchedName string   `json:"matched_name,omitempty"`
}

// PolicyExplainPrefix names the CIDR prefix that caused a proxy decision.
type PolicyExplainPrefix struct {
	Prefix  string   `json:"prefix"`
	Sources []string `json:"sources"`
}

// PolicyExplainEvidence is the session evidence a verdict rests on.
type PolicyExplainEvidence struct {
	State            string `json:"state"`
	Decision         string `json:"decision,omitempty"`
	Generation       string `json:"generation,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
	Source           string `json:"source"`
}

// PolicyExplainAddress is one address's verdict.
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
type PolicyExplanation struct {
	Input       PolicyExplainInput      `json:"input"`
	Policy      PolicyExplainState      `json:"policy"`
	Decision    string                  `json:"decision"`
	Reason      string                  `json:"reason"`
	Summary     string                  `json:"summary"`
	Rule        *PolicyExplainRule      `json:"rule,omitempty"`
	Prefix      *PolicyExplainPrefix    `json:"prefix,omitempty"`
	Addresses   []PolicyExplainAddress  `json:"addresses"`
	Evidence    *PolicyExplainEvidence  `json:"evidence,omitempty"`
	Resolution  PolicyExplainResolution `json:"resolution"`
	Limitations []string                `json:"limitations"`
	ReadOnly    bool                    `json:"read_only"`
}
