package vpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file owns the snapshot ordering that makes policy activation fail closed:
// what the matcher must hold before the first network sync runs, what a failed or
// refused first sync means, and how the durable last-known-good generation is
// published.
//
// It is separate from vpn_pbr_policy_lifecycle.go (the runtime registry, the
// scheduling loop and the admin-facing status) because the activation handshake
// has its own contract and its own guard interactions, and because the ordering
// here is the substance of #678 F678-03.

// ensureInitialSnapshot guarantees the matcher holds a non-empty policy snapshot
// before activation proceeds.
//
// Ordering is what makes this correct (#678 F678-03). The durable last-known-good
// baseline is published into the matcher *first*, so the synchronous sync that
// follows is evaluated against the previous rule count. Without that, a fresh
// matcher has no previous count, the shrink guard has nothing to compare against,
// and a complete-but-shortened upstream list is accepted as the first-ever
// snapshot — overwriting both the live policy and the durable generation while
// every other guard (transport, content-type, empty list) reports success.
//
// So the sequence is: prime baseline → one synchronous sync → settle → require
// rules.
//   - baseline primed and the sync succeeds: the new generation was accepted
//     against a real previous count, which is the ordinary refresh path.
//   - baseline primed and the sync fails or is refused by a guard: the primed
//     last-known-good snapshot is already live, so the previous policy stays in
//     effect; nothing durable was overwritten because a refused sync commits
//     nothing.
//   - no baseline at all (genuinely fresh install, or an operator-selected new
//     source): the first sync legitimately establishes it.
//   - a durable generation that exists but cannot be used: refused explicitly
//     rather than synced over, because that would destroy the last recoverable
//     copy.
//
// If no rules are live at the end, activation is refused with an error an
// operator can act on.
func ensureInitialSnapshot(ctx context.Context, syncer *policy.Syncer, store policy.Store, matcher *policy.Matcher) error {
	baseline, baselineErr := syncer.PrimeBaseline(ctx)
	if baselineErr != nil {
		// A stored generation that cannot be used is a distinct, actionable state:
		// proceeding would sync over the only recoverable copy of the last good
		// policy, and refusing leaves PBR disabled, which is the safe outcome.
		return fmt.Errorf("%w: %v", ErrPolicyActivationNoRules, baselineErr)
	}
	if baseline == policy.BaselineForeign {
		slog.Warn("Stored policy generation belongs to a different source configuration; " +
			"fetching a fresh snapshot without a last-known-good baseline")
	}

	syncCtx, cancelSync := context.WithTimeout(ctx, policyActivationTimeout)
	syncRes, syncErr := syncer.SyncOnce(syncCtx)
	cancelSync()

	if err := settleInitialSync(ctx, store, matcher, baseline, syncRes, syncErr); err != nil {
		return err
	}

	snap := matcher.Current()
	if snap == nil || (snap.DomainCount() == 0 && snap.CIDRCount() == 0) {
		return ErrPolicyActivationNoRules
	}
	return nil
}

// settleInitialSync decides what the first synchronous sync's outcome means for
// activation, given what baseline was available before it ran.
//
// It is a separate step because "interpret the first sync" is a coherent decision
// with its own contract, and keeping it separate leaves the activation ordering in
// ensureInitialSnapshot readable as prime → sync → settle → require rules.
func settleInitialSync(
	ctx context.Context,
	store policy.Store,
	matcher *policy.Matcher,
	baseline policy.BaselineStatus,
	syncRes policy.SyncResult,
	syncErr error,
) error {
	switch {
	case syncErr != nil && baseline == policy.BaselinePrimed:
		// The candidate was refused (transport failure, shrink guard, malformed or
		// empty list) and the verified last-known-good snapshot is already the live
		// policy. That is exactly the "preserve a valid active policy on failure"
		// contract, so activation proceeds on the preserved policy.
		slog.Warn("Policy sync failed at startup; activated last-known-good policy instead", "err", syncErr)
		return nil
	case syncErr != nil:
		if loadErr := loadLastKnownGood(ctx, store, matcher); loadErr != nil {
			return fmt.Errorf("%w: initial sync failed (%v) and no usable last-known-good policy was found: %w",
				ErrPolicyActivationNoRules, syncErr, loadErr)
		}
		slog.Warn("Policy sync failed at startup; activated last-known-good policy instead", "err", syncErr)
		return nil
	case !syncRes.Published:
		return fmt.Errorf("%w: sync did not publish a snapshot", ErrPolicyActivationNoRules)
	}
	return nil
}

// loadLastKnownGood publishes the durable last-known-good generation, if any.
func loadLastKnownGood(ctx context.Context, store policy.Store, matcher *policy.Matcher) error {
	gen, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if gen == nil {
		return errors.New("no last-known-good policy generation stored")
	}
	snap, err := policy.GenerationToSnapshot(gen)
	if err != nil {
		return err
	}
	if snap.DomainCount() == 0 && snap.CIDRCount() == 0 {
		return errors.New("stored policy generation contains no rules")
	}
	matcher.Publish(snap)
	return nil
}
