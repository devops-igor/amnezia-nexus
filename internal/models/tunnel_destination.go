package models

import "strings"

// Destination eligibility for a new session, a failover or a rebalance move.
//
// One decision, in one place, because the defect it replaces was not a wrong predicate: it
// was the same question answered in some callers and never asked in others. Any code that
// may place a session on a backend calls EligibleTunnelDestination; anything that only
// ENUMERATES tunnels (health sweeps, status pages, operator listings) does not, because the
// rule governs destinations, never work in flight or a server's recorded state.

// AbsentServerSet is the set of server ids the provider's own inventory has confirmed
// absent. A nil or empty set means "nothing confirmed absent", which is also the answer a
// caller must use when it could not read the marks: absence is a positive observation.
type AbsentServerSet map[int64]struct{}

// NewAbsentServerSet indexes a list of absent server ids. Nil in, nil out.
func NewAbsentServerSet(serverIDs []int64) AbsentServerSet {
	if len(serverIDs) == 0 {
		return nil
	}
	set := make(AbsentServerSet, len(serverIDs))
	for _, id := range serverIDs {
		set[id] = struct{}{}
	}
	return set
}

// Contains reports whether the provider has confirmed this server absent.
func (s AbsentServerSet) Contains(serverID int64) bool {
	if len(s) == 0 {
		return false
	}
	_, absent := s[serverID]
	return absent
}

// TunnelDestinationAllowed reports whether a tunnel may receive new work.
//
// Three independent facts decide it, and each is refused on its own: the backend must be
// administratively enabled, its last runtime status must be adoptable, and the provider must
// not have confirmed the server deleted. Provider absence is checked here rather than
// converted into a status because a mark is an inventory observation, not a health verdict:
// converting it would fabricate a failed probe, hide the real status and change what an
// operator sees.
func TunnelDestinationAllowed(tunnel *BackendTunnel, absent AbsentServerSet) bool {
	if tunnel == nil || !tunnel.Enabled {
		return false
	}
	if !TunnelStatusAdmitsNewWork(tunnel.Status) {
		return false
	}
	return !absent.Contains(tunnel.ServerID)
}

// TunnelStatusAdmitsNewWork reports whether a recorded status may receive new work.
//
// "active" is the ordinary case. "handshake-blocked" is admitted by the ingress path only
// when it carries its own fresh inner-canary evidence, which that caller checks; a caller
// that has no such evidence must pass the tunnel's own admission test for itself, so this
// shared rule accepts the two adoptable statuses and leaves the evidence to the owner.
func TunnelStatusAdmitsNewWork(status string) bool {
	switch NormalizeStatus(status) {
	case TunnelStatusActive, TunnelStatusHandshakeBlocked:
		return true
	}
	return false
}

// NormalizeStatus lower-cases and trims a tunnel status for comparison.
func NormalizeStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

// EligibleTunnelDestinations returns the tunnels that may receive new work, preserving the
// caller's order. It returns the input unchanged when nothing is disqualified, so a caller
// cannot accidentally treat an empty result as "no candidates".
func EligibleTunnelDestinations(tunnels []*BackendTunnel, absent AbsentServerSet) []*BackendTunnel {
	if len(tunnels) == 0 {
		return tunnels
	}
	eligible := make([]*BackendTunnel, 0, len(tunnels))
	for _, tunnel := range tunnels {
		if tunnel == nil || !TunnelDestinationAllowed(tunnel, absent) {
			continue
		}
		eligible = append(eligible, tunnel)
	}
	return eligible
}

// EligibleTunnelDestinationValues is EligibleTunnelDestinations for value slices, which is
// the shape the orchestrator's durable rebalance query returns.
func EligibleTunnelDestinationValues(tunnels []BackendTunnel, absent AbsentServerSet) []BackendTunnel {
	if len(tunnels) == 0 {
		return tunnels
	}
	eligible := make([]BackendTunnel, 0, len(tunnels))
	for i := range tunnels {
		if !TunnelDestinationAllowed(&tunnels[i], absent) {
			continue
		}
		eligible = append(eligible, tunnels[i])
	}
	return eligible
}
