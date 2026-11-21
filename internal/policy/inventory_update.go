package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
//     as it was. That comparison measures the committed data file; the count in
//     the provenance record is never trusted for it, because an interrupted
//     update can leave the record describing the other generation.
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
	// update replaces, from PreviousInventoryCount. Zero means the caller
	// established that there is no committed artifact to compare against — not
	// that the baseline could not be read, which PreviousInventoryCount reports
	// as an error. A negative value is refused.
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
//
// A zero baseline means the caller established that there is no committed
// artifact to compare against. It is not a way to skip the comparison when the
// baseline read failed: PreviousInventoryCount returns an error in that case
// rather than zero, so a failed read cannot arrive here as "no previous
// artifact". A negative baseline is a caller error and is refused.
func checkInventoryReduction(count int, opts InventoryUpdateOptions) error {
	if opts.AllowLargeReduction {
		return nil
	}
	if opts.PreviousPrefixCount < 0 {
		return fmt.Errorf("inventory update received a negative previous prefix count (%d)", opts.PreviousPrefixCount)
	}
	if opts.PreviousPrefixCount == 0 {
		return nil
	}
	if count*100 >= opts.PreviousPrefixCount*MaxInventoryReductionPercent {
		return nil
	}
	return fmt.Errorf("%w: body holds %d prefixes, the committed artifact holds %d; keeping fewer than %d%% is refused as a truncated feed unless -%s is passed",
		ErrInventoryLargeReduction, count, opts.PreviousPrefixCount, MaxInventoryReductionPercent, InventoryLargeReductionFlag)
}

// PreviousInventoryCount returns the authoritative prefix count an update would
// be reducing from.
//
// The committed data file is measured whenever it exists, and that measurement is
// the baseline. It is the payload the update would replace; the recorded count is
// metadata that an interrupted update can leave describing the other generation,
// because the two files are renamed separately. A record claiming a smaller count
// than the data actually holds would otherwise let a feed truncated to exactly
// that number look like no reduction at all, so the record is never consulted
// here — see RecordedInventoryCount for the reporting use of it.
//
// Only when the directory holds no data file at all does the count come from the
// committed set this build ships. A data file that exists but cannot be measured,
// or an absent data file with an unusable shipped set, is an error: the caller
// must leave the artifact untouched, and zero is never a substitute for a count.
func PreviousInventoryCount(dir string) (int, error) {
	return previousInventoryCount(dir, shippedInventoryCount)
}

// previousInventoryCount is PreviousInventoryCount with the shipped-set reader
// injected, so a test can reproduce a build whose embedded artifact is unusable.
func previousInventoryCount(dir string, shipped func() (int, error)) (int, error) {
	measured, err := countCommittedDataFile(dir)
	switch {
	case err == nil:
		return measured, nil
	case errors.Is(err, fs.ErrNotExist):
		count, shippedErr := shipped()
		if shippedErr != nil {
			return 0, fmt.Errorf("%w: %s holds no data file and the shipped inventory is unusable: %v",
				ErrInventoryBaselineUnavailable, dir, shippedErr)
		}
		return count, nil
	default:
		return 0, err
	}
}

// RecordedInventoryCount returns the prefix count the provenance record in dir
// claims, or 0 when there is no readable record.
//
// It exists so the command can tell an operator that a record disagrees with the
// data beside it, which is the state an interrupted update leaves behind. It never
// influences the baseline: a disagreement is reported, not acted on, because
// repairing that pair is exactly what the update is for.
func RecordedInventoryCount(dir string) int {
	meta, err := os.ReadFile(InventoryMetaPath(dir))
	if err != nil {
		return 0
	}
	var prov InventoryProvenance
	if err := json.Unmarshal(meta, &prov); err != nil || prov.PrefixCount <= 0 {
		return 0
	}
	return prov.PrefixCount
}

// shippedInventoryCount returns the prefix count of the committed artifact this
// build ships.
func shippedInventoryCount() (int, error) {
	shipped, err := ShippedInventory()
	if err != nil {
		return 0, err
	}
	return shipped.PrefixCount(), nil
}

// countCommittedDataFile measures the data file in dir.
//
// It returns fs.ErrNotExist when the directory holds no data file, so the caller
// can tell "there is nothing here" from "there is something here I cannot read".
// A file that exists but cannot be read or measured is a wrapped
// ErrInventoryBaselineUnavailable: that is the fail-closed case, because the
// payload the update would replace is unknown.
func countCommittedDataFile(dir string) (int, error) {
	body, err := os.ReadFile(InventoryDataPath(dir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, fs.ErrNotExist
		}
		return 0, fmt.Errorf("%w: the committed data file in %s cannot be read: %v",
			ErrInventoryBaselineUnavailable, dir, err)
	}
	count, err := countInventoryPrefixes(body)
	if err != nil {
		return 0, fmt.Errorf("%w: the committed data file in %s cannot be measured: %v",
			ErrInventoryBaselineUnavailable, dir, err)
	}
	return count, nil
}

// countInventoryPrefixes counts the distinct prefixes of a data body without
// applying the update-path acceptance rules. A baseline measures the committed
// file as it stands; it is not a candidate for acceptance, so the absolute floor
// and the canonical-form and markup rules do not apply to it.
func countInventoryPrefixes(body []byte) (int, error) {
	parsed, _, err := Parse(context.Background(), bytes.NewReader(body), DefaultParseLimits())
	if err != nil {
		return 0, err
	}
	return len(distinctMaskedPrefixes(parsed.CIDRs)), nil
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
