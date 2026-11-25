package vpn

// Provider absence as an admission and destination authority.
//
// A durable absence mark is a statement about the provider's inventory, and the panel
// already honors it on every path that dials a server: probes, SSH acquisition, channels
// and commands are refused before dispatch. It was NOT honored where a *new* session is
// placed, so an enabled, still-"active" backend the provider had deleted could keep winning
// the least-loaded/latency tie and receive fresh client sessions, and it could equally be
// chosen as a failover or migration destination.
//
// The mark is preserved rather than converted into a status: nothing here disables a
// tunnel, fabricates a failed probe, or deletes a row, because the panel's own health
// history and administrative state are separate facts and already-admitted work must keep
// running. A recovered listing clears the mark and the backend becomes eligible again with
// no other action.
//
// Locking: these helpers perform one bounded database read, so callers read the set BEFORE
// taking Service.mu and pass it to the locked helpers explicitly. Making the set a
// parameter is deliberate - a new destination consumer cannot silently omit it, because the
// selection helpers take it as an argument and the guard in
// provider_absence_admission_guard_test.go fails on any GetActiveTunnels consumer that does
// not filter.

import (
	"context"
	"log"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// providerAbsenceReadTimeout bounds the one read a selection path performs, so a slow or
// locked store cannot stall admission.
const providerAbsenceReadTimeout = 2 * time.Second

// providerAbsentServerIDs reads the servers the provider has confirmed absent.
//
// A failed read is reported and treated as "nothing confirmed absent": refusing every new
// session because the store was momentarily unreadable would be a larger outage than the
// narrow window it would close, and the requirement is about CONFIRMED absence. The
// failure is logged, never silent.
func (s *Service) providerAbsentServerIDs(ctx context.Context) map[int64]struct{} {
	if s == nil || s.db == nil {
		return nil
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerAbsenceReadTimeout)
	defer cancel()
	ids, err := s.db.ListProviderAbsentServerIDs(readCtx)
	if err != nil {
		log.Printf("[vpn] warning: cannot read provider-absence marks, selection is unchanged for this request: %v", err)
		return nil
	}
	if len(ids) == 0 {
		return nil
	}
	absent := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		absent[id] = struct{}{}
	}
	return absent
}

// withoutProviderAbsent returns the tunnels that may receive NEW work.
//
// It is the single filter for every selection path: a tunnel whose server the provider has
// confirmed absent is not an assignment or migration destination, independently of its last
// health sample. Tunnels the provider still lists pass through unchanged, and an empty set
// (or a failed read) leaves the list exactly as it was.
func withoutProviderAbsent(tunnels []*models.BackendTunnel, absent map[int64]struct{}) []*models.BackendTunnel {
	if len(absent) == 0 || len(tunnels) == 0 {
		return tunnels
	}
	kept := make([]*models.BackendTunnel, 0, len(tunnels))
	for _, tun := range tunnels {
		if tun == nil {
			continue
		}
		if _, isAbsent := absent[tun.ServerID]; isAbsent {
			continue
		}
		kept = append(kept, tun)
	}
	return kept
}
