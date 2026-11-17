package vpn

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
)

// This file is the read-only per-client diagnosis of issue #861, slice 1: an
// administrator selects one exact session incarnation and receives the evidence
// the data plane already retains for it.
//
// Read-only is structural, not a promise:
//
//   - Session lookup uses SessionManager.ListActiveSessionsSnapshot, which takes
//     the manager's read lock and copies values. Nothing is created, adopted or
//     touched.
//   - Route identity comes from Forwarder.SessionRouteStates (value copies).
//   - Address evidence comes from policy.SessionCache.Entries, the listing
//     counterpart of Inspect: one atomic view load, no prune, no store, no
//     scope allocation.
//   - Flow evidence comes from DirectEgressManager.SnapshotSessionFlows, which
//     never calls LookupFlow and therefore never refreshes lastSeen or retires
//     an expired flow.
//   - No resolver is reachable from here. This file has no DNS dependency, so a
//     panel lookup can never become a client observation.
//
// What it does not have is as important as what it has: no query name, no
// CNAME chain, no decision time, no decision reason and no outcome is retained
// anywhere in the current data plane. Each of those is returned as an explicit
// unknown token rather than inferred from a route, a lastSeen or a current
// policy rule.
//
// Cross-subsystem atomicity is not promised. The three stores are read one after
// another under their own locks, so a rekey, a retirement or a policy refresh can
// land between them. The answer therefore re-reads the route identity after the
// copies and reports ClientDiagnosisStateInconsistent (withholding the records)
// when the selection changed while it was being read.

var (
	// ErrClientDiagnosisBusy reports that another diagnosis snapshot is already
	// being read. The flow listing visits the direct-egress table, which the
	// packet path also locks per lookup, so the reads are serialized.
	ErrClientDiagnosisBusy = errors.New("vpn: another client diagnosis snapshot is in flight")
	// ErrClientDiagnosisSessionRequired reports a request without a session id.
	// There is deliberately no user or connection resolution: a selection names
	// one incarnation.
	ErrClientDiagnosisSessionRequired = errors.New("vpn: client diagnosis requires a session id")
)

// clientDiagnosisEvidenceSource names the stores this slice reads.
const clientDiagnosisEvidenceSource = "route_cache_entries_and_live_flows"

// ClientDiagnosisTargets lists the session incarnations an administrator can
// select. It reads the live session registry and the registered routes only.
func (s *Service) ClientDiagnosisTargets() ClientDiagnosisTargets {
	out := ClientDiagnosisTargets{
		Clients:    []ClientDiagnosisTarget{},
		NotCovered: clientDiagnosisNotCovered(),
		ReadOnly:   true,
		SampledAt:  clientDiagnosisTime(time.Now()),
	}
	if s == nil {
		return out
	}
	fwd, mgr := s.clientDiagnosisSources()
	out.PolicyRoutingEnabled = fwd != nil && fwd.PBREnabled()

	var bySession map[string]forwarder.SessionRoute
	if fwd != nil {
		bySession = clientDiagnosisRouteIndex(fwd.SessionRouteStates())
	}
	if mgr == nil {
		// Without a registry there is no selectable identity: a route alone
		// cannot say which authenticated session owns it.
		return out
	}

	cache := s.clientDiagnosisRouteCache()
	for _, sess := range mgr.ListActiveSessionsSnapshot() {
		target := ClientDiagnosisTarget{
			SessionID:      sess.ID,
			ConnectionID:   sess.ConnectionID,
			ConnectionName: sess.ConnectionName,
			Username:       sess.Username,
			AssignedIP:     sess.AssignedIP,
			ConnectedAt:    clientDiagnosisTime(sess.ConnectedAt),
		}
		if route, ok := bySession[sess.ID]; ok {
			target.RouteLive = true
			target.RouteGeneration = route.Generation
		}
		if cache != nil {
			// Count is one view load and one map length: the picker never
			// copies a retained set.
			target.EvidenceEntries = cache.SessionScope(sess.ID).Count()
		}
		out.Clients = append(out.Clients, target)
	}
	return out
}

// ClientDiagnosis builds the retained-state answer for one session incarnation.
func (s *Service) ClientDiagnosis(ctx context.Context, req ClientDiagnosisRequest) (ClientDiagnosisResponse, error) {
	sessionID, release, err := s.clientDiagnosisBegin(ctx, req)
	if err != nil {
		return ClientDiagnosisResponse{}, err
	}
	defer release()

	fwd, mgr := s.clientDiagnosisSources()

	// One instant for the whole answer: every age and remaining lifetime below
	// is computed against it, so two fields can never disagree about "now".
	now := time.Now()

	// The retained pre-flow refusals of THIS session, read through the bounded ledger's
	// pure read. A session that was retired reads as empty; nothing here can see another
	// client's drops.
	var dropSnapshot forwarder.DropSnapshot
	if fwd != nil {
		dropSnapshot = fwd.ClientDropSnapshot(sessionID, 0)
	}

	out := ClientDiagnosisResponse{
		Selection:   ClientDiagnosisSelection{SessionID: sessionID},
		Coverage:    clientDiagnosisCoverage(fwd, now),
		DNS:         clientDiagnosisEmptyDNS(),
		Flows:       clientDiagnosisEmptyFlows(),
		Drops:       clientDiagnosisDropsSection(dropSnapshot),
		Limitations: clientDiagnosisLimitations(),
		EvaluatedAt: clientDiagnosisTime(now),
		ReadOnly:    true,
	}
	if req.HasRouteGeneration {
		requested := req.RouteGeneration
		out.Selection.RequestedRouteGeneration = &requested
	}

	// Sources that cannot answer at all are decided before any selection is
	// resolved, so their state never depends on a partially read store.
	if state, limitation := clientDiagnosisUnavailableState(fwd, mgr); state != "" {
		out.Selection.State = state
		out.Limitations = append(out.Limitations, limitation)
		return out, nil
	}

	selection, verdict := clientDiagnosisResolve(mgr, fwd, sessionID, req)
	out.Selection = selection
	out.Selection.State = verdict
	if verdict != ClientDiagnosisStateLive {
		out.Limitations = append(out.Limitations, clientDiagnosisRefusalLimitations(verdict)...)
		return out, nil
	}

	// Copies only: each helper reads and releases its own lock, and the response
	// is assembled outside every lock after this point.
	entries, generation := s.clientDiagnosisEntries(sessionID, now, req.EvidenceLimit)
	out.Selection.PolicyGeneration = generation
	flows, flowsAvailable := clientDiagnosisSnapshotFlows(fwd, sessionID, selection.RouteGeneration, now, req.FlowLimit)
	dnsRecords, dnsRecordsRead := s.clientDiagnosisDNSRecords(sessionID, req.DNSRecordLimit)
	dnsEvents := s.clientDiagnosisDNSEvents(sessionID, req.DNSEventLimit)
	if err := ctx.Err(); err != nil {
		return ClientDiagnosisResponse{}, err
	}

	// Revalidation: the identity this answer was built for must still be the
	// registered one. A rekey or retirement that landed during the reads makes
	// the record sets belong to different incarnations, so they are withheld
	// rather than presented as one client's session.
	if !clientDiagnosisStillSelected(fwd, sessionID, selection.RouteGeneration) {
		out.Selection.State = ClientDiagnosisStateInconsistent
		out.Limitations = append(out.Limitations, ClientDiagnosisLimitSelectionChanged)
		return out, nil
	}

	clientDiagnosisApplyRecords(&out, clientDiagnosisReads{
		entries:        entries,
		generation:     generation,
		flows:          flows,
		flowsAvailable: flowsAvailable,
		dnsRecords:     dnsRecords,
		dnsRecordsRead: dnsRecordsRead,
		dnsEvents:      dnsEvents,
	}, now)
	if dnsRecordsRead {
		// The observation boundary this build records at cannot see failure
		// answers, non-A queries, the transport or the query receipt time. Say so
		// once, so an empty history is never read as "this client asked nothing".
		out.Limitations = append(out.Limitations, ClientDiagnosisLimitDNSCoverage)
	}
	return out, nil
}

// clientDiagnosisBegin validates the request and takes the single in-flight
// slot, returning the trimmed session id and the release to defer. The flow
// listing visits the direct-egress table under the same lock the packet path
// takes per lookup, so concurrent administrative reads would multiply that
// contention; a second request is refused rather than queued.
func (s *Service) clientDiagnosisBegin(ctx context.Context, req ClientDiagnosisRequest) (string, func(), error) {
	if s == nil {
		return "", nil, errors.New("vpn: client diagnosis requires a service")
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return "", nil, ErrClientDiagnosisSessionRequired
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if !s.clientDiagBusy.CompareAndSwap(false, true) {
		return "", nil, ErrClientDiagnosisBusy
	}
	return sessionID, func() { s.clientDiagBusy.Store(false) }, nil
}

// clientDiagnosisUnavailableState reports the state of a service whose sources
// cannot answer, with the limitation that explains it. An empty state means the
// selection can be resolved normally.
func clientDiagnosisUnavailableState(fwd *forwarder.Forwarder, mgr *session.SessionManager) (string, string) {
	if fwd == nil || !fwd.PBREnabled() {
		return ClientDiagnosisStatePolicyDisabled, ClientDiagnosisLimitEvidenceScope
	}
	if mgr == nil {
		// A route alone is not a verified identity: refuse the selection instead
		// of presenting another layer's record as this session's evidence.
		return ClientDiagnosisStateIdentityUnavailable, ClientDiagnosisLimitIdentitySource
	}
	return "", ""
}

// clientDiagnosisRefusalLimitations lists what a refused verdict cannot state.
func clientDiagnosisRefusalLimitations(verdict string) []string {
	switch verdict {
	case ClientDiagnosisStateUnknownSession:
		return []string{ClientDiagnosisLimitSessionEnd}
	case ClientDiagnosisStateRouteAbsent, ClientDiagnosisStateRouteGenerationReplaced:
		return []string{ClientDiagnosisLimitEvidenceScope}
	default:
		return nil
	}
}

// clientDiagnosisSources snapshots the two live objects under the service lock
// and releases it before any read, so this endpoint never holds s.mu.
func (s *Service) clientDiagnosisSources() (*forwarder.Forwarder, *session.SessionManager) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.forwarder, s.sessionMgr
}

// clientDiagnosisRouteCache returns the authoritative route cache when the live
// policy configuration provides one.
func (s *Service) clientDiagnosisRouteCache() *MemoryRouteCache {
	cfg := s.getPBRConfig()
	if cfg == nil {
		return nil
	}
	mem, ok := cfg.RouteCache.(*MemoryRouteCache)
	if !ok || mem == nil {
		return nil
	}
	return mem
}

// clientDiagnosisEntries reads the selected session's retained address
// evidence and reports the policy generation it was compared against. A session
// that holds nothing answers absent, never an error: that is a state, not a
// failure.
func (s *Service) clientDiagnosisEntries(sessionID string, now time.Time, limit int) (policy.SessionEntryList, string) {
	mem := s.clientDiagnosisRouteCache()
	if mem == nil {
		return policy.SessionEntryList{State: policy.EvidenceAbsent, Entries: []policy.SessionEntry{}}, ""
	}
	generation := clientDiagnosisPolicyGeneration(s, mem)
	// SessionScope never creates a scope, so a diagnosis cannot consume one of
	// the cache's bounded session slots.
	return mem.SessionScope(sessionID).Entries(generation, now, limit), generation
}

// clientDiagnosisPolicyGeneration reports the policy generation the retained
// evidence is compared against.
//
// The authority is the matcher the route cache observes with: that is the
// generation its views are keyed by, so an inactive policy runtime cannot make
// live evidence look stale. The service's own policy runtime is the fallback for
// a cache attached without a matcher.
func clientDiagnosisPolicyGeneration(s *Service, mem *MemoryRouteCache) string {
	if mem != nil {
		if generation := matcherGeneration(mem.PolicyMatcher()); generation != "" {
			return generation
		}
	}
	if s != nil {
		return matcherGeneration(s.PolicyMatcher())
	}
	return ""
}

// matcherGeneration reports the generation a matcher currently publishes, or ""
// when it has no published snapshot.
func matcherGeneration(matcher *policy.Matcher) string {
	if matcher == nil {
		return ""
	}
	if snap := matcher.Current(); snap != nil {
		return snap.Generation()
	}
	return ""
}

// clientDiagnosisResolve matches the request against the live registry and the
// registered routes. It returns the identity to report and the verdict state:
// ClientDiagnosisStateLive is the only verdict that carries records.
func clientDiagnosisResolve(mgr *session.SessionManager, fwd *forwarder.Forwarder, sessionID string, req ClientDiagnosisRequest) (ClientDiagnosisSelection, string) {
	selection := ClientDiagnosisSelection{SessionID: sessionID}
	if req.HasRouteGeneration {
		requested := req.RouteGeneration
		selection.RequestedRouteGeneration = &requested
	}

	// Both lookups are value copies: the registry snapshot and the route state
	// are taken independently, and the caller revalidates afterwards.
	session := clientDiagnosisFindSession(mgr, sessionID)
	route, routeFound := clientDiagnosisFindRoute(fwd, sessionID)

	if session == nil && !routeFound {
		return selection, ClientDiagnosisStateUnknownSession
	}
	if session == nil {
		// A route without a live session cannot be attributed to an authenticated
		// incarnation, so it is reported as unknown rather than as live.
		return selection, ClientDiagnosisStateUnknownSession
	}
	selection.ConnectionID = session.ConnectionID
	selection.ConnectionName = session.ConnectionName
	selection.Username = session.Username
	selection.AssignedIP = session.AssignedIP
	selection.ConnectedAt = clientDiagnosisTime(session.ConnectedAt)

	if !routeFound {
		return selection, ClientDiagnosisStateRouteAbsent
	}
	selection.RouteGeneration = route.Generation
	if req.HasRouteGeneration && req.RouteGeneration != route.Generation {
		// The requested incarnation was replaced (a rekey of the same session):
		// its flow records are gone, and the current generation's records are
		// never substituted for it.
		return selection, ClientDiagnosisStateRouteGenerationReplaced
	}
	return selection, ClientDiagnosisStateLive
}

// clientDiagnosisFindSession returns a copy of the live session with this id, or
// nil. The registry snapshot is already a value copy, so the caller owns it.
func clientDiagnosisFindSession(mgr *session.SessionManager, sessionID string) *models.VPNSession {
	if mgr == nil {
		return nil
	}
	for _, candidate := range mgr.ListActiveSessionsSnapshot() {
		if candidate.ID == sessionID {
			copied := candidate
			return &copied
		}
	}
	return nil
}

// clientDiagnosisFindRoute returns the newest registered route for a session.
func clientDiagnosisFindRoute(fwd *forwarder.Forwarder, sessionID string) (forwarder.SessionRoute, bool) {
	var found forwarder.SessionRoute
	ok := false
	for _, candidate := range fwd.SessionRouteStates() {
		if candidate.SessionID != sessionID {
			continue
		}
		if !ok || candidate.Generation > found.Generation {
			found = candidate
			ok = true
		}
	}
	return found, ok
}

// clientDiagnosisRouteIndex maps a session id to its newest route.
func clientDiagnosisRouteIndex(routes []forwarder.SessionRoute) map[string]forwarder.SessionRoute {
	bySession := make(map[string]forwarder.SessionRoute, len(routes))
	for _, route := range routes {
		// Session ids are unique per admission, so one session owns at most one
		// route; a duplicate would be a stale entry, and the newest generation
		// wins deterministically.
		if current, ok := bySession[route.SessionID]; ok && current.Generation > route.Generation {
			continue
		}
		bySession[route.SessionID] = route
	}
	return bySession
}

// clientDiagnosisStillSelected reports whether the route generation the answer
// was built for is still the registered one.
func clientDiagnosisStillSelected(fwd *forwarder.Forwarder, sessionID string, generation uint64) bool {
	for _, route := range fwd.SessionRouteStates() {
		if route.SessionID == sessionID && route.Generation == generation {
			return true
		}
	}
	return false
}

// clientDiagnosisDNSRecords reads the session's observed-answer history from the
// bounded collector. It reports whether a collector was consulted at all: a
// service without one must say "not recorded", not "nothing was observed".
func (s *Service) clientDiagnosisDNSRecords(sessionID string, limit int) (dnsledger.SessionSnapshot, bool) {
	mem := s.clientDiagnosisRouteCache()
	if mem == nil {
		return dnsledger.SessionSnapshot{Records: []dnsledger.Record{}}, false
	}
	ledger := mem.DNSLedger()
	if ledger == nil {
		return dnsledger.SessionSnapshot{Records: []dnsledger.Record{}}, false
	}
	return ledger.Snapshot(sessionID, limit), true
}

// clientDiagnosisDNSEvents reads the session's terminal-query history. A service
// without a collector answers an empty snapshot; the response reports
// events_available=false so the panel can say "not recorded".
func (s *Service) clientDiagnosisDNSEvents(sessionID string, limit int) dnsledger.EventSnapshot {
	mem := s.clientDiagnosisRouteCache()
	if mem == nil {
		return dnsledger.EventSnapshot{Events: []dnsledger.Event{}}
	}
	ledger := mem.DNSLedger()
	if ledger == nil {
		return dnsledger.EventSnapshot{Events: []dnsledger.Event{}}
	}
	return ledger.SnapshotEvents(sessionID, limit)
}

// clientDiagnosisSnapshotFlows reads the selected incarnation's flow records and
// reports whether a flow store was actually consulted.
func clientDiagnosisSnapshotFlows(fwd *forwarder.Forwarder, sessionID string, generation uint64, now time.Time, limit int) (forwarder.SessionFlowList, bool) {
	dem := fwd.DirectEgress()
	if dem == nil {
		return forwarder.SessionFlowList{Flows: []forwarder.SessionFlow{}, ScanComplete: true}, false
	}
	return dem.SnapshotSessionFlows(sessionID, generation, now, limit), true
}
