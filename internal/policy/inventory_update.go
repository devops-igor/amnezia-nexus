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
// The ordering is the guarantee: a body is fully validated and its provenance
// record rendered BEFORE any file is touched, so a rejected update — a captive
// portal response, a truncated download, a body with one bad line — leaves the
// previously committed artifact exactly as it was. Writes then go through a
// temporary file in the destination directory and a rename, so an interrupted
// update cannot leave a half-written zone that the loader would parse as a
// smaller set.
//
// A written artifact is re-verified by the loader (count and digest are derived
// from the bytes), which is why this file does not need its own verification
// pass: a mismatch is refused at startup rather than trusted here.

// ValidateInventoryUpdate validates body as the committed zone and returns the
// complete provenance record with its committed JSON rendering. It writes
// nothing, which is what a dry run reports.
//
// prov supplies the descriptive fields (source, source URL, retrieval date,
// license, notes); the prefix count and digest are always derived from body, so
// a caller cannot record metadata that disagrees with the data it commits.
func ValidateInventoryUpdate(body []byte, prov InventoryProvenance) (InventoryProvenance, []byte, error) {
	inv, err := InventoryFromBody(body)
	if err != nil {
		return InventoryProvenance{}, nil, err
	}

	record := inv.Provenance()
	record.SchemaVersion = InventorySchemaVersion
	record.Kind = InventoryKind
	record.Source = prov.Source
	record.SourceURL = prov.SourceURL
	record.RetrievedAt = prov.RetrievedAt
	record.License = prov.License
	record.Notes = prov.Notes

	if record.Source == "" || record.SourceURL == "" {
		return InventoryProvenance{}, nil, errors.New("inventory provenance requires a source name and source URL")
	}
	if _, err := record.retrievedTime(); err != nil {
		return InventoryProvenance{}, nil, err
	}

	meta, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return InventoryProvenance{}, nil, fmt.Errorf("render inventory provenance: %w", err)
	}
	return record, append(meta, '\n'), nil
}

// WriteInventoryArtifact replaces the committed data and provenance files in dir
// with body and meta. Both files are written to temporaries in dir first and then
// renamed, so a reader never observes a partially written artifact.
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
