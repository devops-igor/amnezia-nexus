package policy

import (
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// Snapshot represents an immutable policy matching state published atomically.
// It provides O(1) expected domain matching and O(log N) IPv4 CIDR matching
// with zero reader lock contention.
type Snapshot struct {
	version      uint64
	generationID string
	createdAt    time.Time
	domainCount  int
	cidrCount    int
	sourceIDs    []string
	domains      map[string]domainFlags
	ipv4         ipv4Index
}

// Version returns the sequential version number of this snapshot.
func (s *Snapshot) Version() uint64 {
	if s == nil {
		return 0
	}
	return s.version
}

// Generation returns the unique generation identifier of this snapshot.
func (s *Snapshot) Generation() string {
	if s == nil {
		return ""
	}
	return s.generationID
}

// CreatedAt returns the timestamp when this snapshot was compiled.
func (s *Snapshot) CreatedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.createdAt
}

// DomainCount returns the number of distinct domain rules in this snapshot.
func (s *Snapshot) DomainCount() int {
	if s == nil {
		return 0
	}
	return s.domainCount
}

// CIDRCount returns the number of IPv4 prefixes/ranges in this snapshot.
func (s *Snapshot) CIDRCount() int {
	if s == nil {
		return 0
	}
	return s.cidrCount
}

// SourceIDs returns the list of source identifiers included in this snapshot.
func (s *Snapshot) SourceIDs() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.sourceIDs))
	copy(out, s.sourceIDs)
	return out
}

// MatchCanonicalDomain checks if a canonical domain (ASCII lowercase, no trailing dot)
// matches any exact, inclusive suffix, or descendant rule in the snapshot.
// The search walks dot boundaries without string allocations.
func (s *Snapshot) MatchCanonicalDomain(name string) bool {
	if s == nil || len(s.domains) == 0 || name == "" {
		return false
	}

	orig := true
	q := name
	for {
		if f, ok := s.domains[q]; ok {
			if f&domainInclusiveSuffix != 0 || (orig && f&domainExact != 0) || (!orig && f&domainDescendants != 0) {
				return true
			}
		}
		i := strings.IndexByte(q, '.')
		if i < 0 {
			return false
		}
		q = q[i+1:]
		orig = false
	}
}

// MatchDomain normalizes name and checks if it matches any rule in the snapshot.
// If normalization fails, MatchDomain returns false (which downstream treats as UNKNOWN/PROXY).
func (s *Snapshot) MatchDomain(name string) bool {
	if s == nil {
		return false
	}
	canon, err := NormalizeDomain(name)
	if err != nil {
		return false
	}
	return s.MatchCanonicalDomain(canon)
}

// MatchIPv4 checks whether addr falls within any IPv4 CIDR range in the snapshot.
func (s *Snapshot) MatchIPv4(addr netip.Addr) bool {
	if s == nil {
		return false
	}
	return s.ipv4.match(addr)
}

// SourceParsedRules bundles parsed rules for a specific source for compilation.
type SourceParsedRules struct {
	SourceID string
	Rules    ParsedRules
}

// MemorySource provides an in-memory rule source for snapshot compilation.
type MemorySource struct {
	SourceID string
	Rules    ParsedRules
}

// NewMemorySource creates a MemorySource with the given ID and rules.
func NewMemorySource(id string, rules ParsedRules) MemorySource {
	if id == "" {
		id = "memory-default"
	}
	if rules.Domains == nil {
		rules.Domains = make(map[string]domainFlags)
	}
	return MemorySource{
		SourceID: id,
		Rules:    rules,
	}
}

// ToSourceParsedRules converts MemorySource to SourceParsedRules.
func (m MemorySource) ToSourceParsedRules() SourceParsedRules {
	return SourceParsedRules{
		SourceID: m.SourceID,
		Rules:    m.Rules,
	}
}

// CompileSnapshot creates a new immutable Snapshot from source parsed rules.
func CompileSnapshot(version uint64, generationID string, sources []SourceParsedRules) (*Snapshot, error) {
	if len(sources) == 0 {
		return nil, errors.New("cannot compile snapshot with zero sources")
	}

	mergedDomains := make(map[string]domainFlags)
	var allCIDRs []netip.Prefix
	seenCIDRs := make(map[netip.Prefix]struct{})
	sourceIDs := make([]string, 0, len(sources))

	for _, src := range sources {
		sourceIDs = append(sourceIDs, src.SourceID)
		for base, flags := range src.Rules.Domains {
			mergedDomains[base] |= flags
		}
		for _, prefix := range src.Rules.CIDRs {
			canon := prefix.Masked()
			if _, exists := seenCIDRs[canon]; !exists {
				seenCIDRs[canon] = struct{}{}
				allCIDRs = append(allCIDRs, canon)
			}
		}
	}

	idx := newIPv4Index(allCIDRs)

	return &Snapshot{
		version:      version,
		generationID: generationID,
		createdAt:    time.Now().UTC(),
		domainCount:  len(mergedDomains),
		cidrCount:    len(allCIDRs),
		sourceIDs:    sourceIDs,
		domains:      mergedDomains,
		ipv4:         idx,
	}, nil
}

// Matcher provides lock-free, concurrent-safe access to the current active policy Snapshot.
type Matcher struct {
	current atomic.Pointer[Snapshot]
}

// NewMatcher constructs an empty Matcher.
func NewMatcher() *Matcher {
	return &Matcher{}
}

// Current returns the currently active Snapshot, or nil if no snapshot has been published yet.
// Callers can safely retain this pointer for the duration of a transaction (e.g. DNS observation).
func (m *Matcher) Current() *Snapshot {
	return m.current.Load()
}

// Publish atomically updates the active Snapshot.
func (m *Matcher) Publish(s *Snapshot) {
	m.current.Store(s)
}
