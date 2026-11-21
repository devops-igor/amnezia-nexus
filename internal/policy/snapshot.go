package policy

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"time"
)

// Snapshot represents an immutable policy matching state published atomically.
// It provides O(log N) IPv4 CIDR matching with zero reader lock contention.
//
// The snapshot holds IPv4 prefixes only. The routing authority for a destination
// is its address, so there is no domain index: a name-based rule never decided a
// packet's route.
type Snapshot struct {
	version      uint64
	generationID string
	createdAt    time.Time
	cidrCount    int
	sourceIDs    []string
	ipv4         ipv4Index
	// cidrRules keeps every distinct prefix with the sources that supplied it.
	// The merged ipv4Index answers "does this address match"; it cannot answer
	// "which prefix, from which source" because it merges adjacent ranges. This
	// list is what an explanation reads. It costs one prefix plus one provenance
	// byte per distinct prefix and changes no match result.
	cidrRules []cidrRule
}

const (
	// maxSnapshotSources bounds the compiled provenance encoding: one bit per
	// source, packed into the high bits of the per-prefix provenance word. A
	// snapshot compiled from more sources records no provenance at all rather
	// than a wrong one.
	maxSnapshotSources = 25
	// provenanceShift is the position of the first provenance bit.
	provenanceShift = 0
)

// cidrRule is one compiled IPv4 prefix with the provenance bits of the sources
// that supplied it.
type cidrRule struct {
	prefix  netip.Prefix
	sources uint32
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
//
// Provenance: each prefix records which sources supplied it, packed into the bits
// of domainFlags above the match bits, so an explanation can name the prefix AND
// the list it came from without a second per-rule index in memory.
func CompileSnapshot(version uint64, generationID string, sources []SourceParsedRules) (*Snapshot, error) {
	if len(sources) == 0 {
		return nil, errors.New("cannot compile snapshot with zero sources")
	}

	cidrRules := make([]cidrRule, 0, len(sources))
	cidrIndex := make(map[netip.Prefix]int)
	sourceIDs := make([]string, 0, len(sources))

	for i, src := range sources {
		sourceIDs = append(sourceIDs, src.SourceID)
		provenance := provenanceBit(i, len(sources))
		for _, prefix := range src.Rules.CIDRs {
			canon := prefix.Masked()
			if at, exists := cidrIndex[canon]; exists {
				cidrRules[at].sources |= provenance
				continue
			}
			cidrIndex[canon] = len(cidrRules)
			cidrRules = append(cidrRules, cidrRule{prefix: canon, sources: provenance})
		}
	}

	prefixes := make([]netip.Prefix, len(cidrRules))
	for i := range cidrRules {
		prefixes[i] = cidrRules[i].prefix
	}

	return &Snapshot{
		version:      version,
		generationID: generationID,
		createdAt:    time.Now().UTC(),
		cidrCount:    len(cidrRules),
		sourceIDs:    sourceIDs,
		ipv4:         newIPv4Index(prefixes),
		cidrRules:    cidrRules,
	}, nil
}

// provenanceBit returns the provenance bit for the source at index i, or zero
// when the snapshot has more sources than the encoding holds. Recording nothing
// for such a snapshot is the honest answer: an explanation then names the prefix
// without naming a source, instead of naming a partial or wrong set.
func provenanceBit(i, total int) uint32 {
	if total > maxSnapshotSources || i < 0 || i >= maxSnapshotSources {
		return 0
	}
	return uint32(1<<uint(i)) << provenanceShift
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
// Callers can safely retain this pointer for the duration of a transaction.
func (m *Matcher) Current() *Snapshot {
	return m.current.Load()
}

// Publish atomically updates the active Snapshot.
func (m *Matcher) Publish(s *Snapshot) {
	m.current.Store(s)
}
