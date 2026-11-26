package orchestrator

// Provider absence as a destination authority for the scheduled rebalance.
//
// The ingress path and the immediate failover paths already refuse to place work on a server
// the provider's inventory has confirmed deleted. The rebalance is a separate destination
// source: it enumerates DURABLE tunnels (`GetBackendTunnels`) rather than the pool snapshot,
// so the filter applied to that snapshot can never see its candidates. This file is what
// makes the durable source honor the same rule, once, for both of the rebalance's write
// paths (the live migrator and the DB-only fallback).
//
// Nothing here converts the mark into state: no tunnel is disabled, no probe is fabricated,
// no row is deleted. A session already being moved keeps moving; the rule decides
// destinations only.

import (
	"context"
	"log/slog"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// rebalanceAbsenceReadTimeout bounds the one read a rebalance pass performs, so a slow or
// locked store cannot stall the cycle.
const rebalanceAbsenceReadTimeout = 2 * time.Second

// providerAbsentServers reads the servers the provider has confirmed absent.
//
// A failed read is reported and treated as "nothing confirmed absent", matching every other
// absence consumer: refusing the whole rebalance because the store was momentarily
// unreadable would be a larger outage than the window it would close, and the rule is about
// CONFIRMED absence.
func (o *Orchestrator) providerAbsentServers(ctx context.Context) models.AbsentServerSet {
	if o == nil || o.db == nil {
		return nil
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rebalanceAbsenceReadTimeout)
	defer cancel()
	ids, err := o.db.ListProviderAbsentServerIDs(readCtx)
	if err != nil {
		slog.Warn("cannot read provider-absence marks; rebalance destinations are unchanged for this pass", "err", err)
		return nil
	}
	return models.NewAbsentServerSet(ids)
}

// dbTargetEligible reports whether the DB-only fallback may move a session onto
// targetTunnelID.
//
// It re-reads both facts immediately before the write instead of trusting the pass's
// snapshot: the target's own row (administrative changes) and the absence marks (a mark
// recorded while this pass was draining earlier sessions). A read failure refuses the move,
// because this path can then no longer prove the destination is still eligible and writing
// blind is exactly the defect this replaces; the next scheduled pass retries with fresh
// state.
func (o *Orchestrator) dbTargetEligible(ctx context.Context, targetTunnelID int64, absent models.AbsentServerSet) bool {
	if targetTunnelID <= 0 {
		return false
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rebalanceAbsenceReadTimeout)
	defer cancel()

	target, err := o.db.GetBackendTunnel(readCtx, targetTunnelID)
	if err != nil || target == nil {
		slog.Warn("rebalance destination could not be revalidated before the move; skipping",
			"target_tunnel_id", targetTunnelID, "err", err)
		return false
	}
	absentNow, known := o.currentAbsentServers(readCtx)
	if !known {
		// UNKNOWN, not "nothing is absent": the move is refused rather than allowed on the
		// pass snapshot, which may predate a mark. The next scheduled pass retries with
		// fresh state, and the durable write carries its own predicate as a second fence.
		return false
	}
	if len(absent) > 0 {
		merged := make(models.AbsentServerSet, len(absent)+len(absentNow))
		for id := range absent {
			merged[id] = struct{}{}
		}
		for id := range absentNow {
			merged[id] = struct{}{}
		}
		absentNow = merged
	}
	return models.TunnelDestinationAllowed(target, absentNow)
}

// currentAbsentServers reads the marks immediately before a durable move.
//
// The second return value is false when the read failed. That is UNKNOWN, and the caller must
// refuse the move: falling back to the pass snapshot would allow exactly the window this
// function exists to close, because the snapshot predates the decision. Returning "unknown"
// is also not the same as returning an empty set - an empty set means the provider confirmed
// nothing is absent, and the two must never be conflated.
func (o *Orchestrator) currentAbsentServers(ctx context.Context) (models.AbsentServerSet, bool) {
	ids, err := o.db.ListProviderAbsentServerIDs(ctx)
	if err != nil {
		slog.Warn("cannot re-read provider-absence marks before a rebalance move; refusing the move", "err", err)
		return nil, false
	}
	return models.NewAbsentServerSet(ids), true
}
