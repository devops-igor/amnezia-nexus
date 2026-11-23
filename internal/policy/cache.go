package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SchemaVersion defines the serialization layout version for cached policy generations.
//
// The schema stays 1 across the retirement of domain rules, and that is correct
// rather than sloppy: a durable generation is a compiled snapshot of what was
// published, and a predecessor generation is still exactly that. What changed is
// the hash grammar — the predecessor digested its domain entries as well as its
// prefixes, so its stored digest covers content this build no longer carries.
// Bumping the version would turn "an upgrade cannot read its own last-known-good
// policy" into a differently worded error, so the reader below recognizes the
// predecessor representation and verifies it against the predecessor grammar
// instead. See legacyContentHash.
const SchemaVersion = 1

const cacheFileName = "policy_lkg.json"

// SourceMeta stores HTTP conditional validation state and source statistics.
type SourceMeta struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	ETag         string    `json:"etag"`
	LastModified string    `json:"last_modified"`
	ContentHash  string    `json:"content_hash"`
	CheckedAt    time.Time `json:"checked_at"`
	RuleCount    int       `json:"rule_count"`
}

// Generation contains the complete durable representation of a published policy rule set.
type Generation struct {
	SchemaVersion int       `json:"schema_version"`
	GenerationID  string    `json:"generation_id"`
	Version       uint64    `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	ConfigHash    string    `json:"config_hash"`
	// AttributionHash is the canonical digest of the per-source rule sets this
	// generation was compiled from (see provenance.go). It is what lets a refresh
	// that knows only durable state tell a content-equivalent cycle from one that
	// moved a rule between lists. Generations written before this field existed
	// leave it empty, and such a generation is compared the older way rather than
	// being treated as a change (equivalence.go).
	AttributionHash string                `json:"attribution_hash,omitempty"`
	SourcesMeta     map[string]SourceMeta `json:"sources_meta"`
	// LegacyDomains is the domain half of a generation written by an earlier
	// build. This build routes on IPv4 only and never compiles or publishes these
	// entries; the field exists so the loader can verify such a generation
	// against the digest its own writer produced, and so reading one is a
	// migration rather than a corruption report. It is never written back.
	LegacyDomains map[string]uint32 `json:"domains,omitempty"`
	CIDRs         []string          `json:"cidrs"`
	CIDRCount     int               `json:"cidr_count"`
	ContentHash   string            `json:"content_hash"`
}

// ComputeContentHash computes a deterministic SHA-256 digest over normalized rules.
func ComputeContentHash(cidrs []string) string {
	h := sha256.New()

	// Hash sorted CIDR entries
	sortedCIDRs := make([]string, len(cidrs))
	copy(sortedCIDRs, cidrs)
	sort.Strings(sortedCIDRs)
	for _, c := range sortedCIDRs {
		_, _ = fmt.Fprintf(h, "C:%s\n", c)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// legacyContentHash recomputes the digest an earlier build's writer produced for
// the same file: its domain entries first, then its prefixes, under the same
// "D:<name>:<flags>" and "C:<prefix>" line grammar.
//
// It exists only to verify bytes this build must still be able to read. A
// predecessor generation was a valid, published last-known-good policy, so
// refusing it would take a working installation's own cache away on upgrade and
// leave PBR unable to activate — a migration failure reported as corruption. The
// result is never used to accept a file the current grammar cannot account for:
// Load tries the current digest first and falls back here only when the record
// actually carries legacy domain entries.
func legacyContentHash(domains map[string]uint32, cidrs []string) string {
	h := sha256.New()

	domainKeys := make([]string, 0, len(domains))
	for k := range domains {
		domainKeys = append(domainKeys, k)
	}
	sort.Strings(domainKeys)
	for _, k := range domainKeys {
		_, _ = fmt.Fprintf(h, "D:%s:%d\n", k, domains[k])
	}

	sortedCIDRs := make([]string, len(cidrs))
	copy(sortedCIDRs, cidrs)
	sort.Strings(sortedCIDRs)
	for _, c := range sortedCIDRs {
		_, _ = fmt.Fprintf(h, "C:%s\n", c)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// Store provides atomic persistence and retrieval for the last-known-good Generation.
type Store interface {
	Load(ctx context.Context) (*Generation, error)
	Commit(ctx context.Context, gen *Generation) error
}

// FileStore implements durable filesystem persistence with atomic rename and directory sync.
type FileStore struct {
	dir string
}

// NewFileStore initializes a FileStore writing to dir.
func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
}

// Commit atomically commits a candidate generation to disk with mode 0600.
func (s *FileStore) Commit(ctx context.Context, gen *Generation) error {
	if gen == nil {
		return errors.New("cannot commit nil generation")
	}
	if gen.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported generation schema version %d", gen.SchemaVersion)
	}

	// A predecessor generation read by Load has had its retired domain entries
	// cleared already; this makes the guarantee unconditional, so no path can write
	// content back into a record whose digest would then cover rules nothing
	// applies.
	gen.LegacyDomains = nil
	gen.ContentHash = ComputeContentHash(gen.CIDRs)
	gen.CIDRCount = len(gen.CIDRs)

	data, err := json.MarshalIndent(gen, "", "  ")
	if err != nil {
		return fmt.Errorf("failed serializing generation: %w", err)
	}

	return s.writeAtomically(data)
}

// writeAtomically replaces the cache file with data: a same-directory temporary
// file with mode 0600, written and synced, then renamed into place followed by a
// best-effort directory sync.
//
// It is one function because it is one contract — a reader must never observe a
// partially written cache, and a crash must leave either the previous file or the
// new one. Splitting the steps across a caller makes that guarantee depend on the
// caller remembering the ordering.
func (s *FileStore) writeAtomically(data []byte) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("failed creating cache directory: %w", err)
	}

	tmpPath, err := s.writeDurableTempFile(data)
	if err != nil {
		return err
	}
	// Cleaned up when the rename below does not happen. After a successful rename
	// the path no longer exists, so this is a no-op.
	defer func() { _ = os.Remove(tmpPath) }()

	targetPath := filepath.Join(s.dir, cacheFileName)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	// Sync parent directory to ensure directory entry durability
	if df, err := os.Open(s.dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}

	return nil
}

// writeDurableTempFile writes data to a mode-0600 temporary file in the cache
// directory and returns its path, with the contents already flushed to the
// filesystem.
//
// The flush is the point: a rename publishes whatever the file holds, so the bytes
// must reach the device before the rename makes them the live policy. A returned
// error always leaves the caller with the previous file untouched, because nothing
// has replaced it yet.
func (s *FileStore) writeDurableTempFile(data []byte) (string, error) {
	tmpFile, err := os.CreateTemp(s.dir, "policy_lkg.*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed creating temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Every failure below discards the partial candidate and reports why; none of
	// them touches the live cache file.
	fail := func(step string, cause error) (string, error) {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed %s cache file: %w", step, cause)
	}

	if err := tmpFile.Chmod(0600); err != nil {
		return fail("setting temp file permissions", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		return fail("writing", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fail("syncing", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed closing cache file: %w", err)
	}

	return tmpPath, nil
}

// Load loads and verifies the last-known-good generation from disk.
// If the cache file does not exist, os.ErrNotExist is returned.
func (s *FileStore) Load(ctx context.Context) (*Generation, error) {
	targetPath := filepath.Clean(filepath.Join(s.dir, cacheFileName))
	// #nosec G304 -- targetPath is bounded by internal cache directory and constant cacheFileName
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}

	gen, retiredDomains, err := verifyStoredGeneration(data)
	if err != nil {
		return nil, err
	}

	// The record is usable, but it is not what this build writes. Handing it back
	// unchanged would make the next commit silently rewrite the operator's durable
	// policy in the current shape without saying so, so the migration is recorded
	// in the same way a retired settings key is: derived from the bytes, reported
	// once, and never invented.
	if retiredDomains > 0 {
		s.recordLoadedPredecessor(gen, retiredDomains)
	}

	return gen, nil
}

// verifyStoredGeneration decodes and verifies one durable generation. A positive
// retiredDomains count reports that the bytes describe the predecessor
// representation and how many domain entries it carried that this build cannot
// apply.
//
// Verification is the one place that decides "these bytes are a usable
// last-known-good policy". Both hash grammars are tried in a fixed order so the
// answer does not depend on which one happens to match first, and a record that
// matches neither is still refused as corrupt.
func verifyStoredGeneration(data []byte) (*Generation, int, error) {
	var gen Generation
	if err := json.Unmarshal(data, &gen); err != nil {
		return nil, 0, fmt.Errorf("failed parsing cache JSON: %w", err)
	}

	if gen.SchemaVersion != SchemaVersion {
		return nil, 0, fmt.Errorf("incompatible schema version %d (expected %d)", gen.SchemaVersion, SchemaVersion)
	}

	if gen.Version == 0 || gen.GenerationID == "" {
		return nil, 0, errors.New("invalid cache generation metadata: zero version or empty ID")
	}

	// A predecessor generation carries domain entries beside its prefixes, and its
	// writer digested both. Recognizing it is what makes an upgrade activate from
	// the operator's own rules instead of reporting corruption.
	if len(gen.LegacyDomains) > 0 {
		if gen.ContentHash == legacyContentHash(gen.LegacyDomains, gen.CIDRs) {
			// The domain half is dropped from the in-memory record: this build
			// publishes prefixes only, and retaining entries nothing can apply
			// would let them be mistaken for live rules.
			retired := len(gen.LegacyDomains)
			gen.LegacyDomains = nil
			return &gen, retired, nil
		}
	}

	expectedHash := ComputeContentHash(gen.CIDRs)
	if gen.ContentHash != expectedHash {
		return nil, 0, fmt.Errorf("corrupted cache: content hash mismatch (stored=%s, calculated=%s)", gen.ContentHash, expectedHash)
	}

	return &gen, 0, nil
}

// recordLoadedPredecessor notes that the durable policy was read from an earlier
// build's representation and will be rewritten in the current one by the next
// commit.
func (s *FileStore) recordLoadedPredecessor(gen *Generation, retiredDomains int) {
	slog.Info("Policy last-known-good cache was written by an earlier build; "+
		"verified against its own digest, so its prefixes stay usable and the next "+
		"commit rewrites it in the current form",
		"generation_id", gen.GenerationID, "version", gen.Version,
		"retired_domain_entries", retiredDomains)
}

// GenerationToSnapshot converts a durable Generation into an in-memory Snapshot.
func GenerationToSnapshot(gen *Generation) (*Snapshot, error) {
	if gen == nil {
		return nil, errors.New("nil generation")
	}

	prefixes := make([]netip.Prefix, 0, len(gen.CIDRs))
	for _, c := range gen.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("failed parsing cached prefix %q: %w", c, err)
		}
		prefixes = append(prefixes, p.Masked())
	}

	idx := newIPv4Index(prefixes)

	// A durable generation stores merged rules only, so it carries no per-rule
	// source attribution. The prefixes are still retained individually so an
	// explanation can name the prefix that matched.
	cidrRules := make([]cidrRule, len(prefixes))
	for i := range prefixes {
		cidrRules[i] = cidrRule{prefix: prefixes[i]}
	}

	sourceIDs := make([]string, 0, len(gen.SourcesMeta))
	for id := range gen.SourcesMeta {
		sourceIDs = append(sourceIDs, id)
	}
	sort.Strings(sourceIDs)

	return &Snapshot{
		version:      gen.Version,
		generationID: gen.GenerationID,
		createdAt:    gen.CreatedAt,
		cidrCount:    len(prefixes),
		sourceIDs:    sourceIDs,
		ipv4:         idx,
		cidrRules:    cidrRules,
	}, nil
}
