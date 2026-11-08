package policy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
)

// This file owns the last-known-good baseline that a syncer establishes before it
// evaluates its first candidate replacement.
//
// It is separate from sync.go (the scheduling loop and the update cycle) because
// the baseline has its own contract and its own failure modes, and because two
// different entry points depend on it: the long-running loop in Run and the
// synchronous activation path in internal/vpn (#678 F678-03).
//
// The reason it must exist at all: the shrink guard compares a candidate rule
// count against "the previous count", which it reads from the matcher. A matcher
// that was never initialized therefore has no previous count and accepts any
// candidate, including a complete-but-shortened list that the guard is explicitly
// designed to reject.

// BaselineStatus reports how a syncer established its last-known-good baseline
// before evaluating a candidate replacement.
type BaselineStatus int

const (
	// BaselineAbsent means there is no durable generation to compare against:
	// a genuinely fresh install, or an operator-supplied source with no prior
	// snapshot. The first sync establishes the baseline.
	BaselineAbsent BaselineStatus = iota
	// BaselinePrimed means a source/config-matching durable generation was
	// published into the matcher and adopted as the comparison baseline.
	BaselinePrimed
	// BaselineForeign means a durable generation exists but describes a
	// different source configuration, so it is not a valid baseline for this
	// one. It is reported so the caller can say so explicitly instead of
	// treating it as an ordinary fresh start.
	BaselineForeign
)

// PrimeBaseline publishes the durable last-known-good generation into the
// matcher and adopts it as the comparison baseline, but only when it matches the
// configured sources.
//
// Every path that evaluates a first candidate must call this first, so it lives
// here rather than being restated per caller.
//
// A returned error is reserved for a durable generation that exists but cannot
// be used: unreadable, corrupt, wrong schema, or self-inconsistent. Callers must
// treat that as explicit rather than as "no baseline", because silently syncing
// over an unreadable good generation is how the last recoverable copy is lost.
func (s *Syncer) PrimeBaseline(ctx context.Context) (BaselineStatus, error) {
	if s.store == nil {
		return BaselineAbsent, nil
	}
	gen, err := s.store.Load(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return BaselineAbsent, nil
		}
		return BaselineAbsent, fmt.Errorf("stored policy generation is unreadable: %w", err)
	}
	if gen == nil {
		return BaselineAbsent, nil
	}
	if gen.ConfigHash != s.computeConfigHash() {
		return BaselineForeign, nil
	}
	snap, snapErr := GenerationToSnapshot(gen)
	if snapErr != nil {
		return BaselineAbsent, fmt.Errorf("stored policy generation cannot be compiled: %w", snapErr)
	}
	if snap.DomainCount() == 0 && snap.CIDRCount() == 0 {
		return BaselineAbsent, fmt.Errorf("stored policy generation contains no rules")
	}
	s.matcher.Publish(snap)
	s.cachedGen = gen
	s.statusMu.Lock()
	s.status.Ready = true
	s.status.Version = gen.Version
	s.status.GenerationID = gen.GenerationID
	s.status.LastSuccess = gen.CreatedAt
	s.status.DomainCount = snap.DomainCount()
	s.status.CIDRCount = snap.CIDRCount()
	s.statusMu.Unlock()
	return BaselinePrimed, nil
}
