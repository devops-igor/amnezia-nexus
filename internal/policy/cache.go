package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SchemaVersion defines the serialization layout version for cached policy generations.
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
	SchemaVersion int                   `json:"schema_version"`
	GenerationID  string                `json:"generation_id"`
	Version       uint64                `json:"version"`
	CreatedAt     time.Time             `json:"created_at"`
	ConfigHash    string                `json:"config_hash"`
	SourcesMeta   map[string]SourceMeta `json:"sources_meta"`
	Domains       map[string]uint8      `json:"domains"`
	CIDRs         []string              `json:"cidrs"`
	DomainCount   int                   `json:"domain_count"`
	CIDRCount     int                   `json:"cidr_count"`
	ContentHash   string                `json:"content_hash"`
}

// ComputeContentHash computes a deterministic SHA-256 digest over normalized rules.
func ComputeContentHash(domains map[string]uint8, cidrs []string) string {
	h := sha256.New()

	// Hash sorted domain entries
	domainKeys := make([]string, 0, len(domains))
	for k := range domains {
		domainKeys = append(domainKeys, k)
	}
	sort.Strings(domainKeys)
	for _, k := range domainKeys {
		_, _ = fmt.Fprintf(h, "D:%s:%d\n", k, domains[k])
	}

	// Hash sorted CIDR entries
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

	gen.ContentHash = ComputeContentHash(gen.Domains, gen.CIDRs)
	gen.DomainCount = len(gen.Domains)
	gen.CIDRCount = len(gen.CIDRs)

	data, err := json.MarshalIndent(gen, "", "  ")
	if err != nil {
		return fmt.Errorf("failed serializing generation: %w", err)
	}

	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("failed creating cache directory: %w", err)
	}

	// Create temporary file on the same filesystem
	tmpFile, err := os.CreateTemp(s.dir, "policy_lkg.*.tmp")
	if err != nil {
		return fmt.Errorf("failed creating temp cache file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath) // cleaned up if rename didn't occur
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed setting temp file permissions: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed writing cache file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed syncing cache file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed closing cache file: %w", err)
	}

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

// Load loads and verifies the last-known-good generation from disk.
// If the cache file does not exist, os.ErrNotExist is returned.
func (s *FileStore) Load(ctx context.Context) (*Generation, error) {
	targetPath := filepath.Clean(filepath.Join(s.dir, cacheFileName))
	// #nosec G304 -- targetPath is bounded by internal cache directory and constant cacheFileName
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}

	var gen Generation
	if err := json.Unmarshal(data, &gen); err != nil {
		return nil, fmt.Errorf("failed parsing cache JSON: %w", err)
	}

	if gen.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("incompatible schema version %d (expected %d)", gen.SchemaVersion, SchemaVersion)
	}

	if gen.Version == 0 || gen.GenerationID == "" {
		return nil, errors.New("invalid cache generation metadata: zero version or empty ID")
	}

	expectedHash := ComputeContentHash(gen.Domains, gen.CIDRs)
	if gen.ContentHash != expectedHash {
		return nil, fmt.Errorf("corrupted cache: content hash mismatch (stored=%s, calculated=%s)", gen.ContentHash, expectedHash)
	}

	return &gen, nil
}

// GenerationToSnapshot converts a durable Generation into an in-memory Snapshot.
func GenerationToSnapshot(gen *Generation) (*Snapshot, error) {
	if gen == nil {
		return nil, errors.New("nil generation")
	}

	domains := make(map[string]domainFlags, len(gen.Domains))
	for k, v := range gen.Domains {
		domains[k] = domainFlags(v)
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

	sourceIDs := make([]string, 0, len(gen.SourcesMeta))
	for id := range gen.SourcesMeta {
		sourceIDs = append(sourceIDs, id)
	}
	sort.Strings(sourceIDs)

	return &Snapshot{
		version:      gen.Version,
		generationID: gen.GenerationID,
		createdAt:    gen.CreatedAt,
		domainCount:  len(domains),
		cidrCount:    len(prefixes),
		sourceIDs:    sourceIDs,
		domains:      domains,
		ipv4:         idx,
	}, nil
}
