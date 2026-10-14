package vpn

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// problemOnsetTracker retains the original onset timestamp of active actionable problems
// across polling ticks, clearing resolved problems when they recover.
type problemOnsetTracker struct {
	mu     sync.Mutex
	onsets map[string]time.Time
}

// ProblemOnsetTracker is the exported alias for problemOnsetTracker.
type ProblemOnsetTracker = problemOnsetTracker

func newProblemOnsetTracker() *problemOnsetTracker {
	return &problemOnsetTracker{
		onsets: make(map[string]time.Time),
	}
}

// NewProblemOnsetTracker creates a new persistent problem onset tracker.
func NewProblemOnsetTracker() *ProblemOnsetTracker {
	return newProblemOnsetTracker()
}

func (s *Service) getProblemOnsetTracker() *problemOnsetTracker {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.problemOnset == nil {
		s.problemOnset = newProblemOnsetTracker()
	}
	return s.problemOnset
}

// SynthesizeActionableProblems derives per-session/route actionable problem records
// by correlating active routes, route pressure, and active VPN sessions.
func SynthesizeActionableProblems(routes []forwarder.RouteInfo, sessions []Session) []ActionableProblem {
	return SynthesizeActionableProblemsAt(routes, sessions, time.Now().UTC())
}

// SynthesizeActionableProblemsWithTracker derives per-session/route actionable problem records
// using a persistent onset tracker to retain onset across polling ticks.
func SynthesizeActionableProblemsWithTracker(routes []forwarder.RouteInfo, sessions []Session, observedAt time.Time, tracker *ProblemOnsetTracker) []ActionableProblem {
	return SynthesizeActionableProblemsAt(routes, sessions, observedAt, tracker)
}

// SynthesizeActionableProblemsWithHandshakes derives per-session/route actionable problem records
// by correlating active routes, route pressure, active VPN sessions, and peer handshakes.
func SynthesizeActionableProblemsWithHandshakes(routes []forwarder.RouteInfo, sessions []Session, peerHandshakes map[string]time.Time, observedAt time.Time, tracker ...*problemOnsetTracker) []ActionableProblem {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	problems := synthesizeUnroutableSessionProblems(routes, sessions, observedAt)
	for _, r := range routes {
		sess, hasSess := findSessionForRoute(r, sessions)
		problems = append(problems, synthesizeRoutePressureProblems(r, sess, hasSess, observedAt)...)
	}
	problems = append(problems, synthesizeStaleHandshakeProblems(sessions, peerHandshakes, observedAt)...)

	var tr *problemOnsetTracker
	if len(tracker) > 0 && tracker[0] != nil {
		tr = tracker[0]
	}

	if tr != nil {
		activeKeys := make(map[string]struct{}, len(problems))
		tr.mu.Lock()
		for i := range problems {
			p := &problems[i]
			sessID := p.SessionID
			if sessID == "" {
				sessID = p.AssignedIP
			}
			msgKey := p.MessageKey
			if msgKey == "" {
				msgKey = p.Category
			}
			key := fmt.Sprintf("%s:%s:%s:%s:%d", p.Category, msgKey, sessID, p.ConnectionID, p.BackendID)
			activeKeys[key] = struct{}{}
			if existing, ok := tr.onsets[key]; ok && !existing.IsZero() {
				p.FirstObserved = existing
			} else {
				tr.onsets[key] = p.FirstObserved
			}
		}
		for k := range tr.onsets {
			if _, active := activeKeys[k]; !active {
				delete(tr.onsets, k)
			}
		}
		tr.mu.Unlock()
	}

	sortActionableProblems(problems)
	return problems
}

// SynthesizeActionableProblemsAt derives per-session/route actionable problem records
// relative to an explicit observation timestamp, optionally persisting onset via a tracker.
func SynthesizeActionableProblemsAt(routes []forwarder.RouteInfo, sessions []Session, observedAt time.Time, tracker ...*problemOnsetTracker) []ActionableProblem {
	return SynthesizeActionableProblemsWithHandshakes(routes, sessions, nil, observedAt, tracker...)
}

func findSessionForRoute(r forwarder.RouteInfo, sessions []Session) (Session, bool) {
	// Priority 1: Exact Session ID match
	if r.SessionID != "" {
		for _, s := range sessions {
			if s.ID == r.SessionID {
				return s, true
			}
		}
	}

	// Priority 2: Peer key fallback
	// Permitted ONLY when session ID is absent on one/both sides (r.SessionID == "" || s.ID == "").
	// If both provide a session ID and they differ, s is strictly disqualified from matching r.
	if r.PeerKey != "" {
		for _, s := range sessions {
			if s.PeerPublicKey == r.PeerKey {
				if r.SessionID != "" && s.ID != "" && r.SessionID != s.ID {
					continue
				}
				return s, true
			}
		}
	}

	// Priority 3: IP fallback
	// Permitted ONLY when both session ID and peer key are absent on one/both sides.
	// If session IDs contradict, or if peer keys contradict, fallback is strictly forbidden.
	if r.AssignedIP != "" {
		for _, s := range sessions {
			if s.AssignedIP == r.AssignedIP {
				if r.SessionID != "" && s.ID != "" && r.SessionID != s.ID {
					continue
				}
				if r.PeerKey != "" && s.PeerPublicKey != "" && r.PeerKey != s.PeerPublicKey {
					continue
				}
				rAbsent := r.SessionID == "" && r.PeerKey == ""
				sAbsent := s.ID == "" && s.PeerPublicKey == ""
				if rAbsent || sAbsent {
					return s, true
				}
			}
		}
	}
	return Session{}, false
}

func synthesizeUnroutableSessionProblems(routes []forwarder.RouteInfo, sessions []Session, observedAt time.Time) []ActionableProblem {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	routesByPeerWithoutSession := make(map[string]struct{}, len(routes))
	routesBySessionID := make(map[string]struct{}, len(routes))
	untaggedRoutesByIP := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		if r.SessionID != "" {
			routesBySessionID[r.SessionID] = struct{}{}
		} else if r.PeerKey != "" {
			routesByPeerWithoutSession[r.PeerKey] = struct{}{}
		}
		if r.SessionID == "" && r.PeerKey == "" && r.AssignedIP != "" {
			untaggedRoutesByIP[r.AssignedIP] = struct{}{}
		}
	}

	var problems []ActionableProblem
	for _, sess := range sessions {
		if sess.Status != "" && sess.Status != "connected" {
			continue
		}
		hasSess := false
		if sess.ID != "" {
			_, hasSess = routesBySessionID[sess.ID]
		}
		hasPeer := false
		if sess.PeerPublicKey != "" {
			_, hasPeer = routesByPeerWithoutSession[sess.PeerPublicKey]
		}
		hasUntaggedIP := false
		if sess.AssignedIP != "" {
			_, hasUntaggedIP = untaggedRoutesByIP[sess.AssignedIP]
		}
		if !hasSess && !hasPeer && !hasUntaggedIP {
			problems = append(problems, ActionableProblem{
				Severity:       "CRITICAL",
				Category:       "routing",
				Message:        fmt.Sprintf("Active session %s has no forwarder route", sess.ID),
				MessageKey:     "vpn_problem_session_without_route",
				UserID:         sess.UserID,
				SessionID:      sess.ID,
				ConnectionName: sess.ConnectionName,
				AssignedIP:     sess.AssignedIP,
				BackendID:      sess.BackendTunnelID,
				FirstObserved:  observedAt,
			})
		}
	}
	return problems
}

func synthesizeStaleHandshakeProblems(sessions []Session, peerHandshakes map[string]time.Time, observedAt time.Time) []ActionableProblem {
	if peerHandshakes == nil {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	var problems []ActionableProblem
	for _, sess := range sessions {
		if sess.PeerPublicKey == "" {
			continue
		}
		hs, ok := peerHandshakes[sess.PeerPublicKey]
		if !ok || hs.IsZero() || observedAt.Sub(hs) > DefaultHealthThresholds.HandshakeStaleAge {
			problems = append(problems, ActionableProblem{
				Severity:       "WARNING",
				Category:       "sessions",
				Message:        fmt.Sprintf("Upstream handshake stale (> %s)", DefaultHealthThresholds.HandshakeStaleAge),
				MessageKey:     "vpn_problem_stale_handshake",
				SessionID:      sess.ID,
				UserID:         sess.UserID,
				Username:       sess.Username,
				ConnectionID:   sess.ConnectionID,
				ConnectionName: sess.ConnectionName,
				AssignedIP:     sess.AssignedIP,
				BackendID:      sess.BackendTunnelID,
				FirstObserved:  observedAt,
			})
		}
	}
	return problems
}

func synthesizeRoutePressureProblems(r forwarder.RouteInfo, sess Session, hasSess bool, observedAt time.Time) []ActionableProblem {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	var problems []ActionableProblem
	var userID, connName string
	if hasSess {
		userID = sess.UserID
		connName = sess.ConnectionName
	}
	sessionID := r.SessionID
	if sessionID == "" && hasSess {
		sessionID = sess.ID
	}
	connID := r.ConnectionID
	firstObserved := observedAt

	if r.Stats.QueueFullDropsRecent > 0 || r.Stats.QueueFullDropRatePPS > 0 {
		var rate string
		if r.Stats.QueueFullDropRatePPS > 0 {
			rate = fmt.Sprintf("%.1f drops/s", r.Stats.QueueFullDropRatePPS)
		} else if r.Stats.QueueFullDropsRecent > 0 {
			rate = fmt.Sprintf("%d drops/window", r.Stats.QueueFullDropsRecent)
		}
		problems = append(problems, ActionableProblem{
			Severity:       "DEGRADED",
			Category:       "dataplane",
			Message:        fmt.Sprintf("Return queue full drops (%d recent) for %s", r.Stats.QueueFullDropsRecent, r.AssignedIP),
			MessageKey:     "vpn_problem_route_queue_drops",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   rate,
			FirstObserved:  firstObserved,
		})
	}

	if r.Stats.WriteStallsRecent > 0 || r.Stats.OldestWriteMS >= 100 {
		sev := "WARNING"
		if r.Stats.OldestWriteMS >= 2000 {
			sev = "CRITICAL"
		} else if r.Stats.OldestWriteMS >= 500 || r.Stats.WriteStallsRecent > 0 {
			sev = "DEGRADED"
		}
		msg := fmt.Sprintf("Device write stall (%dms) for %s", r.Stats.OldestWriteMS, r.AssignedIP)
		rate := fmt.Sprintf("%dms stall", r.Stats.OldestWriteMS)
		if r.Stats.OldestWriteMS == 0 && r.Stats.WriteStallsRecent > 0 {
			msg = fmt.Sprintf("Device write stalls (%d recent) for %s", r.Stats.WriteStallsRecent, r.AssignedIP)
			rate = fmt.Sprintf("%d stalls", r.Stats.WriteStallsRecent)
		}
		stallFirstObserved := firstObserved
		if r.Stats.OldestWriteMS > 0 {
			stallFirstObserved = firstObserved.Add(-time.Duration(r.Stats.OldestWriteMS) * time.Millisecond)
		}
		if stallFirstObserved.After(firstObserved) {
			stallFirstObserved = firstObserved
		}
		problems = append(problems, ActionableProblem{
			Severity:       sev,
			Category:       "dataplane",
			Message:        msg,
			MessageKey:     "vpn_problem_write_stall",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   rate,
			FirstObserved:  stallFirstObserved,
		})
	}

	if r.Stats.WriteErrorsRecent > 0 {
		problems = append(problems, ActionableProblem{
			Severity:       "DEGRADED",
			Category:       "dataplane",
			Message:        fmt.Sprintf("Device write errors (%d recent) for %s", r.Stats.WriteErrorsRecent, r.AssignedIP),
			MessageKey:     "vpn_problem_write_errors",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   fmt.Sprintf("%d errors", r.Stats.WriteErrorsRecent),
			FirstObserved:  firstObserved,
		})
	}

	if r.HasPressure && r.Stats.QueueFullDropsRecent == 0 && r.Stats.WriteStallsRecent == 0 && r.Stats.WriteErrorsRecent == 0 && r.Stats.OldestWriteMS < 100 {
		pct := 0.0
		if r.Stats.Capacity > 0 {
			pct = float64(r.Stats.Occupancy) / float64(r.Stats.Capacity) * 100
		}
		problems = append(problems, ActionableProblem{
			Severity:       "WARNING",
			Category:       "queue_pressure",
			Message:        fmt.Sprintf("Route queue pressure (%d/%d queued) for %s", r.Stats.Occupancy, r.Stats.Capacity, r.AssignedIP),
			MessageKey:     "vpn_problem_route_queue_pressure",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   fmt.Sprintf("%d/%d queued (%0.0f%%)", r.Stats.Occupancy, r.Stats.Capacity, pct),
			FirstObserved:  firstObserved,
		})
	}

	return problems
}

func sortActionableProblems(problems []ActionableProblem) {
	problemSeverityRank := func(sev string) int {
		switch strings.ToUpper(sev) {
		case "CRITICAL":
			return 1
		case "DEGRADED":
			return 2
		case "WARNING":
			return 3
		default:
			return 4
		}
	}
	sort.SliceStable(problems, func(i, j int) bool {
		ri, rj := problemSeverityRank(problems[i].Severity), problemSeverityRank(problems[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if problems[i].AssignedIP != problems[j].AssignedIP {
			return problems[i].AssignedIP < problems[j].AssignedIP
		}
		return problems[i].Category < problems[j].Category
	})
}

func (s *Service) fetchPeerIdentityMappings(ctx context.Context, peerKeys []string) (map[string]string, map[string]string) {
	connByPeer := make(map[string]string)
	userByPeer := make(map[string]string)
	if len(peerKeys) == 0 || s == nil || s.db == nil {
		return connByPeer, userByPeer
	}

	pkPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(peerKeys)), ",")
	pkArgs := make([]any, len(peerKeys))
	for i, pk := range peerKeys {
		pkArgs[i] = pk
	}
	query := `SELECT uc.client_id, uc.id, COALESCE(u.username, '')
		FROM user_connections uc
		LEFT JOIN users u ON u.id = uc.user_id
		WHERE uc.client_id IN (` + pkPlaceholders + `)`
	rows, err := s.db.QueryContext(ctx, query, pkArgs...)
	if err != nil {
		return connByPeer, userByPeer
	}
	defer rows.Close()
	for rows.Next() {
		var pk, connID, username string
		if err := rows.Scan(&pk, &connID, &username); err == nil {
			connByPeer[pk] = connID
			userByPeer[pk] = username
		}
	}
	return connByPeer, userByPeer
}

func (s *Service) synthesizeActionableProblems(routes []forwarder.RouteInfo, sessions []Session, peerHandshakes map[string]time.Time) []ActionableProblem {
	var tracker *problemOnsetTracker
	if s != nil {
		tracker = s.getProblemOnsetTracker()
	}
	problems := SynthesizeActionableProblemsWithHandshakes(routes, sessions, peerHandshakes, time.Now().UTC(), tracker)
	if len(problems) == 0 || s == nil || s.db == nil {
		return problems
	}

	return s.enrichActionableProblemsWithDatabase(problems, sessions)
}

func (s *Service) enrichActionableProblemsWithDatabase(problems []ActionableProblem, sessions []Session) []ActionableProblem {
	if len(problems) == 0 || s == nil || s.db == nil {
		return problems
	}

	peerKeys := make([]string, 0, len(sessions))
	for _, sess := range sessions {
		if sess.PeerPublicKey != "" {
			peerKeys = append(peerKeys, sess.PeerPublicKey)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connByPeer, userByPeer := s.fetchPeerIdentityMappings(ctx, peerKeys)

	for i := range problems {
		enrichSingleProblem(&problems[i], sessions, connByPeer, userByPeer)
	}

	return problems
}

func enrichSingleProblem(p *ActionableProblem, sessions []Session, connByPeer, userByPeer map[string]string) {
	if p.Username != "" && p.ConnectionID != "" {
		return
	}

	if p.SessionID != "" {
		if enrichBySessionID(p, sessions, connByPeer, userByPeer) {
			return
		}
	}

	if p.UserID != "" {
		enrichByUserID(p, sessions, connByPeer, userByPeer)
	}
}

func enrichBySessionID(p *ActionableProblem, sessions []Session, connByPeer, userByPeer map[string]string) bool {
	for _, sess := range sessions {
		if sess.ID == p.SessionID {
			if p.Username == "" {
				p.Username = userByPeer[sess.PeerPublicKey]
			}
			if p.ConnectionID == "" {
				p.ConnectionID = connByPeer[sess.PeerPublicKey]
			}
			if p.ConnectionName == "" {
				p.ConnectionName = sess.ConnectionName
			}
			return true
		}
	}
	return false
}

func enrichByUserID(p *ActionableProblem, sessions []Session, connByPeer, userByPeer map[string]string) {
	var matching []Session
	for _, sess := range sessions {
		if sess.UserID == p.UserID {
			matching = append(matching, sess)
		}
	}
	if len(matching) == 1 {
		sess := matching[0]
		if p.Username == "" {
			p.Username = userByPeer[sess.PeerPublicKey]
		}
		if p.ConnectionID == "" {
			p.ConnectionID = connByPeer[sess.PeerPublicKey]
		}
		if p.ConnectionName == "" {
			p.ConnectionName = sess.ConnectionName
		}
	} else if len(matching) > 1 {
		if p.Username == "" {
			for _, sess := range matching {
				if u := userByPeer[sess.PeerPublicKey]; u != "" {
					p.Username = u
					return
				}
			}
		}
	}
}

// collectProblemRoutes converts forwarder RouteInfo slices into ProblemRouteItem diagnostics.
func collectProblemRoutes(routes []forwarder.RouteInfo) []ProblemRouteItem {
	items := make([]ProblemRouteItem, len(routes))
	for i, r := range routes {
		var note string
		if r.HasPressure {
			switch {
			case r.Stats.QueueFullDropsRecent > 0:
				note = fmt.Sprintf("Recent queue drops: %d", r.Stats.QueueFullDropsRecent)
			case r.Stats.Capacity > 0 && float64(r.Stats.Occupancy)/float64(r.Stats.Capacity) >= thresholds.RoutePressureUtilization():
				note = fmt.Sprintf("Queue pressure: %d/%d queued", r.Stats.Occupancy, r.Stats.Capacity)
			case r.Stats.WriteErrorsRecent > 0:
				note = fmt.Sprintf("Recent write errors: %d", r.Stats.WriteErrorsRecent)
			case r.Stats.WriteStallsRecent > 0:
				note = fmt.Sprintf("Recent write stalls: %d", r.Stats.WriteStallsRecent)
			case r.Stats.OldestWriteMS >= forwarder.DeviceWriteStallThreshold.Milliseconds():
				note = fmt.Sprintf("Write in flight: %dms", r.Stats.OldestWriteMS)
			}
		}

		var utilization, highWaterPct float64
		if r.Stats.Capacity > 0 {
			utilization = float64(r.Stats.Occupancy) / float64(r.Stats.Capacity) * 100
			highWaterPct = float64(r.Stats.HighWater) / float64(r.Stats.Capacity) * 100
		}
		var reservoir *RouteReservoirItem
		if r.Stats.P95WriteSamples > 0 || r.Stats.MaxWriteDurationMS > 0 || r.Stats.P95WriteMS > 0 {
			reservoir = &RouteReservoirItem{
				P95MS:   float64(r.Stats.P95WriteMS),
				Samples: r.Stats.P95WriteSamples,
				MaxMS:   float64(r.Stats.MaxWriteDurationMS),
			}
		}
		dropRatePPS := r.Stats.QueueFullDropRatePPS
		items[i] = ProblemRouteItem{
			SessionID:            r.SessionID,
			ConnectionID:         r.ConnectionID,
			Reservoir:            reservoir,
			UtilizationPct:       utilization,
			HighWaterPct:         highWaterPct,
			WriteCount:           r.Stats.WriteCount,
			WriteErrors:          r.Stats.WriteErrors,
			WriteStalls:          r.Stats.WriteStalls,
			WritesInFlight:       r.Stats.WritesInFlight,
			OldestWriteMS:        r.Stats.OldestWriteMS,
			MaxWriteMS:           r.Stats.MaxWriteDurationMS,
			P95WriteSamples:      r.Stats.P95WriteSamples,
			QueueFullDropsRecent: r.Stats.QueueFullDropsRecent,
			QueueFullDropRatePPS: dropRatePPS,
			WriteErrorsRecent:    r.Stats.WriteErrorsRecent,
			WriteStallsRecent:    r.Stats.WriteStallsRecent,
			Traffic:              r.Traffic,
			SessionAgeSec:        r.SessionAgeSec,
			LastTrafficAgeSec:    r.LastTrafficAgeSec,
			// Redacted at the API boundary, not in the UI (issue #424 round 4,
			// item E). The JSON payload IS the disclosure surface: a raw peer
			// public key shipped to a browser, a log shipper or a support
			// bundle is already disclosed even if every template masks it. The
			// value uses ingress.RedactKey, the redaction convention the rest of
			// the system already uses for peer keys, so the diagnostics surface
			// renders keys identically to ingress errors and counters. The key
			// name, presence and non-emptiness are unchanged: an admin still
			// sees a stable per-route identifier.
			PeerKey:      ingress.RedactKey(r.PeerKey),
			AssignedIP:   r.AssignedIP,
			BackendID:    r.BackendTunnelID,
			Occupancy:    r.Stats.Occupancy,
			Capacity:     r.Stats.Capacity,
			HighWater:    r.Stats.HighWater,
			Drops:        r.Stats.QueueFullDrops,
			P95WriteMS:   float64(r.Stats.P95WriteMS),
			HasPressure:  r.HasPressure,
			PressureNote: note,
		}
	}
	return items
}
