package loadbalancer

// Destination eligibility at the moment of choice.
//
// The candidate list a failover receives is a snapshot its caller built before taking its own
// service lock. Provider absence is written by an independent inventory cycle that takes the
// database lock, not the service lock, so a mark can commit between the snapshot and the
// choice. A destination decision made from the snapshot alone therefore commits a peer onto a
// backend the provider has already deleted - the peer keeps a route to a machine that is gone.
//
// These helpers make the decision authoritative where it is actually made: one bounded re-read
// immediately before selection, applied with the same predicate every other consumer uses
// (models.TunnelDestinationAllowed), and an UNKNOWN state that refuses the move instead of
// silently allowing it on stale information.

import (
	"context"
	"log"
	"sort"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// failoverAbsenceReadTimeout bounds the re-read, so a slow or locked store cannot stall a
// disable.
const failoverAbsenceReadTimeout = 2 * time.Second

// SetCandidateSnapshotHookForTest runs between the candidate snapshot and the destination
// re-read. It exists so a test can commit a mark at exactly that boundary deterministically,
// instead of racing two goroutines and hoping to hit the window.
func (sm *StickySessionManager) SetCandidateSnapshotHookForTest(fn func()) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.candidateHookForTest = fn
}

// SetAbsentReadFailureForTest makes the destination re-read fail, so a test can assert the
// refusal path without a second goroutine racing the store.
func (sm *StickySessionManager) SetAbsentReadFailureForTest(err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.absentReadErrForTest = err
}

// snapshotPeers returns the degraded peers of a snapshot sorted the way the result reports
// them, so a refusal is reported deterministically.
func (sm *StickySessionManager) snapshotPeers(snap failoverSnapshot) []stickyPeerTarget {
	peers := make([]stickyPeerTarget, len(snap.degradedPeers))
	copy(peers, snap.degradedPeers)
	sort.Slice(peers, func(i, j int) bool { return peers[i].peerKey < peers[j].peerKey })
	return peers
}

// revalidateDestinations re-reads the provider-absence marks and returns the candidates that
// may still receive the move.
//
// The second return value is false when the marks could not be read at all: the caller must
// then refuse the move rather than treat the snapshot as still valid. A store that is present
// but has no durable inventory writer (a test or embedded service built without a database)
// reports "nothing confirmed absent", which is the truth for it: no writer exists to record a
// deletion there.
func (sm *StickySessionManager) revalidateDestinations(ctx context.Context, candidates []*models.BackendTunnel) ([]*models.BackendTunnel, bool) {
	if sm.absentReadErrForTest != nil {
		log.Printf("[vpn] sticky failover: cannot re-read provider absence, refusing to choose a destination from a stale snapshot: %v", sm.absentReadErrForTest)
		return nil, false
	}
	if sm.db == nil {
		return candidates, true
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failoverAbsenceReadTimeout)
	defer cancel()

	ids, err := sm.db.ListProviderAbsentServerIDs(readCtx)
	if err != nil {
		// Unknown, not empty. Logged so the refusal below is explainable.
		log.Printf("[vpn] sticky failover: cannot re-read provider absence, refusing to choose a destination from a stale snapshot: %v", err)
		return nil, false
	}
	absent := models.NewAbsentServerSet(ids)
	if len(absent) == 0 {
		return candidates, true
	}
	eligible := make([]*models.BackendTunnel, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == nil || absent.Contains(candidate.ServerID) {
			continue
		}
		eligible = append(eligible, candidate)
	}
	return eligible, true
}
