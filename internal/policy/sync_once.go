package policy

import "context"

// This file exposes a synchronous single-shot sync for callers that need a
// policy snapshot available *before* they can accept traffic, namely production
// startup activation (#678).
//
// The scheduling loop (Run) performs its initial update asynchronously with
// respect to the caller, so startup cannot use it to decide whether PBR may be
// enabled. SyncOnce runs exactly one fetch/parse/shrink-guard/commit/publish
// cycle through the same executeUpdate path the loop uses, so every existing
// guard still applies: a malformed download, an empty rule set, or a suspicious
// shrink fails the call and leaves the previously published snapshot (the
// last-known-good policy) untouched in the matcher.
//
// SyncOnce is intentionally not a second implementation of the sync semantics.

// SyncOnce performs one complete policy sync synchronously and returns its
// result. It returns ErrSyncInProgress if another update is already running, and
// ErrSyncerClosed after the syncer has shut down.
func (s *Syncer) SyncOnce(ctx context.Context) (SyncResult, error) {
	if s == nil {
		return SyncResult{}, ErrSyncerClosed
	}
	if s.closed.Load() {
		return SyncResult{}, ErrSyncerClosed
	}
	return s.executeUpdate(ctx)
}
