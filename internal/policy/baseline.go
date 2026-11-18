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

// AdoptBaseline records the durable last-known-good generation as this syncer's
// comparison baseline without publishing it.
//
// A live-policy replacement (#864) builds a new syncer for an operator save whose
// effective rules may be unchanged: the upstream resolver list and the refresh
// interval are settings the snapshot does not carry, so the save is content
// equivalent even though it is a real change to the runtime. The new syncer has no
// record of what is already published, and without one every such save would mint a
// new generation — which is what the forwarder's route caches key a client's DNS
// evidence on, so the evidence would be discarded and new flows would fall back to
// the fail-closed PROXY path.
//
// Adoption is a read: it never publishes and never commits, so it cannot take write
// ownership from the runtime the save is replacing, and a save whose fetch is then
// refused leaves the incumbent runtime still able to publish. Whether a cycle keeps
// the adopted identity is decided where it always was — by the config-hash,
// content and attribution comparison in executeUpdate — so a source change, a rule
// change or an unreadable store all publish.
func (s *Syncer) AdoptBaseline(ctx context.Context) (BaselineStatus, error) {
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
	// A durable generation records what an older build published, not what the
	// current guard permits. Adopting one that contains a guarded name would let
	// the replacement syncer treat those rules as the live baseline; the guard
	// version is part of neither the generative identity nor the config hash, so
	// the content itself has to be checked.
	if violations := GenerationNeverProxyViolations(gen); len(violations) > 0 {
		return BaselineForeign, nil
	}
	s.cachedGen = gen
	return BaselinePrimed, nil
}

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
// A publication refused by the write-ownership boundary (this runtime was
// superseded or retired while the generation was being prepared) is reported the
// same way: the preparation succeeded but must not reach the live policy.
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
	snap, status, snapErr := s.prepareBaselineSnapshot(gen)
	if snapErr != nil || status != BaselinePrimed {
		return status, snapErr
	}
	// Everything above is read-only preparation (load, hash, guard revalidation,
	// compile) and may run outside the boundary. Publishing the baseline and
	// advertising it in the status are a policy write, so they go through the same
	// ownership decision as executeUpdate's commit and publication (#678 F678-06).
	//
	// Run primes the baseline asynchronously, after activation already published the
	// same generation. A Run whose runtime has since been replaced must not republish
	// its old rules over the accepted one — the delivered snapshot would then disagree
	// with the durable store, the runtime status and the registered preset — and must
	// not advertise that generation in the status either. A canceled scheduler or an
	// early cancellation check cannot recall work that already read the generation;
	// only the final publication can be refused, which is what this fence does.
	if writeErr := s.owner.Write(s.ticket, func() error {
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
		return nil
	}); writeErr != nil {
		return BaselineAbsent, fmt.Errorf("baseline publication refused: %w", writeErr)
	}
	return BaselinePrimed, nil
}

// prepareBaselineSnapshot validates a durable generation against this syncer's
// configuration and the current never-proxy guard, then compiles it.
//
// BaselineForeign means the generation is not rules for this configuration; the
// caller may fetch a fresh baseline. An error is reserved for a generation that
// matches the configuration but cannot be used.
func (s *Syncer) prepareBaselineSnapshot(gen *Generation) (*Snapshot, BaselineStatus, error) {
	if gen.ConfigHash != s.computeConfigHash() {
		return nil, BaselineForeign, nil
	}
	// A durable generation records what an older build published, not what the
	// current guard permits. Publishing a snapshot with a guarded name would
	// proxy protected infrastructure exactly when the upstream fetch also fails.
	if violations := GenerationNeverProxyViolations(gen); len(violations) > 0 {
		return nil, BaselineForeign, nil
	}
	snap, err := GenerationToSnapshot(gen)
	if err != nil {
		return nil, BaselineAbsent, fmt.Errorf("stored policy generation cannot be compiled: %w", err)
	}
	if snap.DomainCount() == 0 && snap.CIDRCount() == 0 {
		return nil, BaselineAbsent, errors.New("stored policy generation contains no rules")
	}
	return snap, BaselinePrimed, nil
}
