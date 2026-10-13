package vpn

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// checkRoutingInvariants verifies integrity across active sessions, forwarder routes, and return paths.
//
// clientOwnershipMismatch is the CLIENT-direction (client -> backend) ownership
// mismatch cumulative counter. It is a parameter rather than being read from
// the engine here because the caller already resolved it through
// addIngressLosses, which folds in losses retained across an engine restart;
// re-reading the engine's own counter here would silently exclude exactly the
// retained losses the retention machinery exists to preserve (issue #424
// review round 9, blocker 3).
func checkRoutingInvariants(s *Service, routes []forwarder.RouteInfo, retStats ReturnStatsSnapshot, clientOwnershipMismatch uint64) RoutingConsistencyDiagnostics {
	return checkRoutingInvariantsWithInputs(s, s.captureDiagnosticsInputs(), routes, retStats, clientOwnershipMismatch)
}

func checkRoutingInvariantsWithInputs(s *Service, inputs diagnosticsInputs, routes []forwarder.RouteInfo, retStats ReturnStatsSnapshot, clientOwnershipMismatch uint64) RoutingConsistencyDiagnostics {
	activeSessions := inputs.sessions
	diag := auditRoutingConsistencyDetails(routes, activeSessions)
	diag.OwnershipMismatchDrops = retStats.OwnershipMismatchDrops
	diag.ClientOwnershipMismatchDrops = clientOwnershipMismatch

	if s != nil {
		now := time.Now()
		returnSnapshot := s.diagDeltas.sampleOwnershipMismatch(inputs.generation, now, retStats.OwnershipMismatchDrops)
		clientMismatchRate := s.diagDeltas.sampleClientOwnershipMismatch(inputs.generation, now, clientOwnershipMismatch)
		diag.OwnershipMismatchDropsRecent = returnSnapshot.delta
		diag.ClientOwnershipMismatchDropsRecent = clientMismatchRate.delta
		diag.OwnershipMismatchWindowSec = math.Max(returnSnapshot.windowSeconds, clientMismatchRate.windowSeconds)
		diag.ReturnOwnershipMismatchWindowSec = returnSnapshot.windowSeconds
		diag.ClientOwnershipMismatchWindowSec = clientMismatchRate.windowSeconds
		diag.ReturnOwnershipMismatchConsecutiveHighRateWindows = returnSnapshot.consecutiveHighRateWindows

		if diag.OwnershipMismatchRecentTotal() > 0 {
			diag.IsConsistent = false
			diag.InconsistencyDetails = append(diag.InconsistencyDetails,
				describeOwnershipMismatchRecent(&diag))
		} else if diag.OwnershipMismatchDrops > 0 || diag.ClientOwnershipMismatchDrops > 0 {
			diag.HistoricalDetails = append(diag.HistoricalDetails,
				describeOwnershipMismatchHistorical(&diag))
		}
	}

	return diag
}

func auditRoutingConsistencyDetails(routes []forwarder.RouteInfo, activeSessions []Session) RoutingConsistencyDiagnostics {
	diag := RoutingConsistencyDiagnostics{
		ActiveSessionsCount:  len(activeSessions),
		ActiveRoutesCount:    len(routes),
		IsConsistent:         true,
		SessionsWithoutRoute: []string{},
		RoutesWithoutSession: []string{},
		RoutesWithoutReturn:  []string{},
		DuplicateIPs:         []string{},
		HistoricalDetails:    []string{},
	}

	sessionByPeer := make(map[string]Session, len(activeSessions))
	ipSessions := make(map[string][]string)

	for _, sess := range activeSessions {
		sessionByPeer[sess.PeerPublicKey] = sess
		if sess.AssignedIP != "" {
			ipSessions[sess.AssignedIP] = append(ipSessions[sess.AssignedIP], sess.PeerPublicKey)
		}
	}

	routesByPeer := make(map[string]forwarder.RouteInfo, len(routes))
	ipRoutes := make(map[string][]string)

	for _, r := range routes {
		routesByPeer[r.PeerKey] = r
		if r.AssignedIP != "" {
			ipRoutes[r.AssignedIP] = append(ipRoutes[r.AssignedIP], r.PeerKey)
		}
		if r.BackendTunnelID > 0 && r.HasReturnPath && !r.ReturnPathClosed {
			diag.ReturnOwnersCount++
		}
	}

	diag.SessionsWithoutRoute, diag.RoutesWithoutSession = auditUnpairedRoutesAndSessions(sessionByPeer, routesByPeer)
	diag.RoutesWithoutReturn = auditRoutesWithoutReturn(routesByPeer)
	diag.DuplicateIPs = findDuplicateIPs(ipSessions, ipRoutes)

	// Sort FIRST, redact SECOND (issue #424 round 5, item 1a).
	sort.Strings(diag.SessionsWithoutRoute)
	sort.Strings(diag.RoutesWithoutSession)
	sort.Strings(diag.RoutesWithoutReturn)
	redactKeySlice(diag.SessionsWithoutRoute)
	redactKeySlice(diag.RoutesWithoutSession)
	redactKeySlice(diag.RoutesWithoutReturn)

	finalizeRoutingConsistencyIssues(&diag)

	return diag
}

func auditUnpairedRoutesAndSessions(sessionByPeer map[string]Session, routesByPeer map[string]forwarder.RouteInfo) ([]string, []string) {
	var sessionsWithoutRoute []string
	for peerKey, sess := range sessionByPeer {
		r, ok := routesByPeer[peerKey]
		if !ok || (r.SessionID != "" && sess.ID != "" && r.SessionID != sess.ID) {
			sessionsWithoutRoute = append(sessionsWithoutRoute, peerKey)
		}
	}

	var routesWithoutSession []string
	for peerKey, r := range routesByPeer {
		sess, ok := sessionByPeer[peerKey]
		if !ok || (r.SessionID != "" && sess.ID != "" && r.SessionID != sess.ID) {
			routesWithoutSession = append(routesWithoutSession, peerKey)
		}
	}

	return sessionsWithoutRoute, routesWithoutSession
}

func auditRoutesWithoutReturn(routesByPeer map[string]forwarder.RouteInfo) []string {
	var routesWithoutReturn []string
	for peerKey, r := range routesByPeer {
		if r.BackendTunnelID <= 0 || !r.HasReturnPath || r.ReturnPathClosed {
			routesWithoutReturn = append(routesWithoutReturn, peerKey)
		}
	}
	return routesWithoutReturn
}

func finalizeRoutingConsistencyIssues(diag *RoutingConsistencyDiagnostics) {
	if len(diag.SessionsWithoutRoute) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d active session(s) lack a forwarder route", len(diag.SessionsWithoutRoute)))
	}
	if len(diag.RoutesWithoutSession) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d forwarder route(s) have no corresponding active session", len(diag.RoutesWithoutSession)))
	}
	if len(diag.RoutesWithoutReturn) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d route(s) lack an assigned return owner/backend", len(diag.RoutesWithoutReturn)))
	}
	if len(diag.DuplicateIPs) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d duplicate IP address(es) detected across active routes: %s",
				len(diag.DuplicateIPs), strings.Join(diag.DuplicateIPs, ", ")))
	}
}

// redactKeySlice replaces every element of keys with its ingress.RedactKey
// rendering, in place. It exists because several diagnostics fields are built
// by iterating maps keyed by the raw peer public key: redacting only at one
// call site is what left the rest of the surface disclosing full keys in
// issue #424 round 5. ingress.RedactKey is the single redaction convention in
// this codebase, so this helper deliberately delegates to it rather than
// introducing a second scheme.
func redactKeySlice(keys []string) {
	for i, k := range keys {
		keys[i] = ingress.RedactKey(k)
	}
}

func findDuplicateIPs(ipSessions, ipRoutes map[string][]string) []string {
	dupIPSet := make(map[string]struct{})
	for ip, peers := range ipSessions {
		if len(peers) > 1 {
			dupIPSet[ip] = struct{}{}
		}
	}
	for ip, peers := range ipRoutes {
		if len(peers) > 1 {
			dupIPSet[ip] = struct{}{}
		}
	}
	dups := make([]string, 0, len(dupIPSet))
	for ip := range dupIPSet {
		dups = append(dups, ip)
	}
	sort.Strings(dups)
	return dups
}

// describeOwnershipMismatchRecent renders the current-window ownership-mismatch
// note. Each direction that is contributing is named with its own count, so a
// reader can tell a client-only incident from a return-only one from both, and
// a direction that is quiet is simply absent rather than reported as zero
// (issue #424 review round 9, blocker 3).
func describeOwnershipMismatchRecent(diag *RoutingConsistencyDiagnostics) string {
	parts := make([]string, 0, 2)
	if n := diag.ClientOwnershipMismatchDropsRecent; n > 0 {
		parts = append(parts, fmt.Sprintf("%d client-direction", n))
	}
	if n := diag.OwnershipMismatchDropsRecent; n > 0 {
		parts = append(parts, fmt.Sprintf("%d return-direction", n))
	}
	return fmt.Sprintf("%s ownership mismatch drop(s) in the last %.1fs",
		strings.Join(parts, " and "), diag.OwnershipMismatchWindowSec)
}

// describeOwnershipMismatchHistorical renders the recovered-incident note. It
// names the cumulative total across both directions, and stays a HISTORICAL
// detail: a lifetime counter must not degrade current health (issue #424 round
// 2, finding 5, extended to the client direction in round 9).
func describeOwnershipMismatchHistorical(diag *RoutingConsistencyDiagnostics) string {
	return fmt.Sprintf("%d ownership mismatch drop(s) observed historically (%d client, %d return), none in the last %.1fs",
		diag.ClientOwnershipMismatchDrops+diag.OwnershipMismatchDrops,
		diag.ClientOwnershipMismatchDrops, diag.OwnershipMismatchDrops,
		diag.OwnershipMismatchWindowSec)
}
