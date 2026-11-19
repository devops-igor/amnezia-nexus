package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// This file owns the maintenance entry point for the committed Russian
// inventory (issue #919). It is not used at runtime.
//
// Two rules live here, and both answer the same class of failure — a feed that
// is well formed but wrong:
//
//   - Ordering: a body is fully validated, its provenance rendered and its size
//     compared against the artifact it would replace BEFORE any file is touched,
//     so a rejected update — a captive portal response, a truncated download, a
//     body with one bad line — leaves the previously committed artifact exactly
//     as it was.
//   - Each file is then replaced atomically on its own. The two renames are
//     separate, so a run that dies between them leaves a mixed pair, which the
//     loader refuses rather than serving; WriteInventoryArtifact states that
//     contract and the recovery.
//
// A written artifact is re-verified by the loader (count, digest and notice are
// all derived from the bytes that ship), which is why this file does not need its
// own verification pass: a mismatch is refused when the artifact is loaded rather
// than trusted here.

// Bounds and names for the size comparison.
const (
	// MaxInventoryReductionPercent is the largest drop in prefix count an update
	// may make without an explicit maintenance decision.
	//
	// The absolute floor in inventory.go cannot catch this failure: a feed that
	// is truncated mid-download but still well formed can hold a few thousand
	// well-formed prefixes and pass a 1,024-prefix floor while removing most of
	// the Russian allocation from classification. Comparing against the count of
	// the artifact being replaced is what catches it. Fifty percent matches the
	// shrink guard the policy syncer already applies to downloaded rule sets, so
	// the repository has one reduction rule rather than two.
	MaxInventoryReductionPercent = 50

	// InventoryLargeReductionFlag is the maintenance flag that accepts a
	// deliberate large reduction. It is named here so that the rejection message
	// and the flag the command registers cannot drift apart.
	InventoryLargeReductionFlag = "allow-large-reduction"
)

// InventoryUpdateOptions carries the maintenance decisions for one regeneration.
type InventoryUpdateOptions struct {
	// PreviousPrefixCount is the prefix count of the committed artifact this
	// update replaces, from PreviousInventoryCount. Zero means there is no
	// previous artifact, so only the absolute floor applies.
	PreviousPrefixCount int
	// AllowLargeReduction accepts a body that would keep fewer than
	// MaxInventoryReductionPercent of those prefixes. It is the explicit
	// maintenance decision for a genuine change, not a way to skip validation.
	AllowLargeReduction bool
}

// ValidateInventoryUpdate validates body as the committed zone and returns the
// complete provenance record with its committed JSON rendering. It writes
// nothing, which is what a dry run reports.
//
// prov supplies the descriptive fields (source, source URL, retrieval date,
// license, notes); the prefix count, data digest and notice digest are always
// derived, so a caller cannot record metadata that disagrees with what ships.
func ValidateInventoryUpdate(body []byte, prov InventoryProvenance, opts InventoryUpdateOptions) (InventoryProvenance, []byte, error) {
	inv, err := InventoryFromBody(body)
	if err != nil {
		return InventoryProvenance{}, nil, err
	}
	if err := checkInventoryReduction(inv.PrefixCount(), opts); err != nil {
		return InventoryProvenance{}, nil, err
	}

	record := inv.Provenance()
	record.SchemaVersion = InventorySchemaVersion
	record.Kind = InventoryKind
	record.Source = prov.Source
	record.SourceURL = prov.SourceURL
	record.RetrievedAt = prov.RetrievedAt
	record.NoticeFile = ShippedInventoryNoticeFile
	record.NoticeSHA256 = NoticeDigest()
	record.License = prov.License
	record.Notes = prov.Notes
	if err := record.validateForWrite(); err != nil {
		return InventoryProvenance{}, nil, err
	}

	meta, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return InventoryProvenance{}, nil, fmt.Errorf("render inventory provenance: %w", err)
	}
	return record, append(meta, '\n'), nil
}

// validateForWrite checks that a record describes an artifact that can be
// committed: a named source, a real retrieval date, and the copyright notice
// this build actually ships.
func (p InventoryProvenance) validateForWrite() error {
	if p.Source == "" || p.SourceURL == "" {
		return errors.New("inventory provenance requires a source name and source URL")
	}
	if _, err := p.retrievedTime(); err != nil {
		return err
	}
	if p.NoticeSHA256 == "" || p.NoticeSHA256 != NoticeDigest() {
		return errors.New("inventory provenance must record the shipped copyright notice")
	}
	return nil
}

// checkInventoryReduction refuses a body that would drop too much of the
// committed set unless the operator asked for that. The message names both
// counts and the flag, because an operator who sees only one number cannot tell
// which side is wrong.
func checkInventoryReduction(count int, opts InventoryUpdateOptions) error {
	if opts.AllowLargeReduction || opts.PreviousPrefixCount <= 0 {
		return nil
	}
	if count*100 >= opts.PreviousPrefixCount*MaxInventoryReductionPercent {
		return nil
	}
	return fmt.Errorf("%w: body holds %d prefixes, the committed artifact holds %d; keeping fewer than %d%% is refused as a truncated feed unless -%s is passed",
		ErrInventoryLargeReduction, count, opts.PreviousPrefixCount, MaxInventoryReductionPercent, InventoryLargeReductionFlag)
}

// PreviousInventoryCount returns the prefix count an update would be reducing
// from: the count recorded by the artifact in dir, or — when dir holds no
// readable record — the count of the committed artifact this build ships.
//
// The artifact on disk is preferred because it is the file the update would
// replace. The embedded count is the fallback for a first run or a damaged
// record, so the comparison is against the committed set rather than silently
// becoming "no baseline" exactly when the tree is in an unusual state.
func PreviousInventoryCount(dir string) int {
	if meta, err := os.ReadFile(InventoryMetaPath(dir)); err == nil {
		var prov InventoryProvenance
		if err := json.Unmarshal(meta, &prov); err == nil && prov.PrefixCount > 0 {
			return prov.PrefixCount
		}
	}
	if shipped, err := ShippedInventory(); err == nil {
		return shipped.PrefixCount()
	}
	return 0
}

// WriteInventoryArtifact replaces the committed data and provenance files in dir
// with body and meta.
//
// Each file is individually atomic: it is written to a temporary in dir and
// renamed into place, so no reader ever sees a half-written file. The two
// renames are separate, so a reader that runs between them observes a mixed
// pair — new data with the previous provenance record, or the reverse. That pair
// is not served: LoadInventory re-derives the prefix count and digest from the
// data and refuses the artifact when the record disagrees, so an interrupted
// update cannot present a smaller or inconsistent set as the current one.
// Recovery is to re-run the tool: one invocation rewrites both files from one
// matching generation, after which the pair is coherent again. No journal, lock
// or two-phase commit is involved, and none is needed — the inconsistent pair
// fails loudly and re-running is idempotent.
//
// It does not validate body: callers use ValidateInventoryUpdate first, which is
// the single place the acceptance rule lives.
func WriteInventoryArtifact(dir string, body, meta []byte) error {
	if err := writeFileAtomic(InventoryDataPath(dir), body); err != nil {
		return fmt.Errorf("write inventory data: %w", err)
	}
	if err := writeFileAtomic(InventoryMetaPath(dir), meta); err != nil {
		return fmt.Errorf("write inventory provenance: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory and renames it into place, removing the temporary on failure.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = writeAndSync(tmp, data); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// writeAndSync writes data and flushes it to disk, closing the file whatever
// happens. It exists so the atomic write above reads as three steps rather than
// five error branches.
func writeAndSync(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}
