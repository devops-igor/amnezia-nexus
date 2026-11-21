package vpn

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
)

// Producer-to-service coverage for the per-client diagnosis (issue #861,
// slice 1).
//
// Every record asserted below is produced by the real data path, not by a test
// seam:
//
//   - the flows come from crafted client packets through RouteClientToBackend,
//     which is where the packet path records its choice.
//
// The assertions then describe what ClientDiagnosis reports, so a change to any
// producer shows up here as a changed answer rather than as a passing unit test.

type clientDiagFixture struct {
	svc      *Service
	fwd      *forwarder.Forwarder
	dem      *forwarder.DirectEgressManager
	sessions *session.SessionManager
	wan      *mockPBRDevice
	backend  *mockPBRDevice
	// returnPath is the client return path the route was registered with, kept so
	// a rekey case can register the same incarnation again.
	returnPath *forwarder.ReturnPath

	mu       sync.Mutex
	replies  [][]byte
	clientIP netip.Addr
	example  netip.Addr
	proxyIP  netip.Addr
	peerKey  string
	// directAddrs are the destinations this fixture's classifier routes DIRECT.
	directAddrs map[netip.Addr]struct{}
}

// newClientDiagFixture builds the production chain the diagnosis reads: a
// forwarder with a backend device, a client return path, the installed
// classifier, the policy matcher and a real session registry.
//
// It installs no DNS resolver, no evidence producer and no route cache: this
// build records nothing for a client's lookups, and the answer carries no member
// for them.
func newClientDiagFixture(t *testing.T) *clientDiagFixture {
	t.Helper()
	ctx := context.Background()

	f := &clientDiagFixture{
		wan:      &mockPBRDevice{},
		backend:  &mockPBRDevice{},
		clientIP: netip.MustParseAddr("10.100.0.10"),
		example:  netip.MustParseAddr("93.184.216.34"),
		proxyIP:  netip.MustParseAddr("93.184.216.99"),
		peerKey:  "peer-client-diag",
	}

	matcher := policy.NewMatcher()
	rules, _, err := policy.Parse(ctx, strings.NewReader("proxy.example\n"), policy.Source{
		ID:             "diag-rules",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("policy Parse: %v", err)
	}
	snap, err := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{{SourceID: "diag-rules", Rules: rules}})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snap)

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	fwd.AttachBackendDevice(11, f.backend)
	returnPath := forwarder.NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		cp := make([]byte, len(packet))
		copy(cp, packet)
		f.replies = append(f.replies, cp)
		return len(packet), nil
	})

	f.sessions = session.NewSessionManager(nil, nil)
	sess, err := f.sessions.CreateSession(ctx, "user-1", f.peerKey, f.clientIP.String(), 11, "phone")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	fwd.RegisterSessionWithReturnPath(sess.ID, "conn-1", f.peerKey, f.clientIP.String(), 11, returnPath)
	f.returnPath = returnPath

	f.fwd = fwd
	f.svc = &Service{forwarder: fwd, sessionMgr: f.sessions}
	if err := f.svc.ConfigurePBR(PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("203.0.113.1"),
		WANDevice:     f.wan,
		PolicyMatcher: matcher,
	}); err != nil {
		t.Fatalf("ConfigurePBR: %v", err)
	}
	t.Cleanup(func() { _ = f.svc.TeardownPBR() })
	f.dem = fwd.DirectEgress()
	return f
}

// sendTCP is one client TCP packet through the real routing decision.
func (f *clientDiagFixture) sendTCP(t *testing.T, dst netip.Addr, srcPort, dstPort uint16) {
	t.Helper()
	pkt := buildTestPBRTCPPacket(f.clientIP, dst, srcPort, dstPort, []byte("payload"))
	if err := f.fwd.RouteClientToBackend(f.peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend(%s:%d): %v", dst, dstPort, err)
	}
}

func (f *clientDiagFixture) sessionID(t *testing.T) string {
	t.Helper()
	states := f.fwd.SessionRouteStates()
	if len(states) != 1 {
		t.Fatalf("route states = %d, want 1", len(states))
	}
	return states[0].SessionID
}

func (f *clientDiagFixture) generation(t *testing.T) uint64 {
	t.Helper()
	states := f.fwd.SessionRouteStates()
	if len(states) != 1 {
		t.Fatalf("route states = %d, want 1", len(states))
	}
	return states[0].Generation
}

func findFlow(t *testing.T, flows []ClientDiagnosisFlow, dst string, dstPort uint16) ClientDiagnosisFlow {
	t.Helper()
	for _, flow := range flows {
		if flow.DestinationIP == dst && flow.DestinationPort == dstPort {
			return flow
		}
	}
	t.Fatalf("no flow for %s:%d; flows=%+v", dst, dstPort, flows)
	return ClientDiagnosisFlow{}
}

// TestClientDiagnosisReportsTheProducersOwnRecords is the primary positive
// control: DIRECT and PROXY flows recorded by the packet path are reported for the
// session that produced them.
func TestClientDiagnosisReportsTheProducersOwnRecords(t *testing.T) {
	f := newClientDiagFixture(t)

	// One uncovered destination (PROXY default), one destination inside the
	// allocation (DIRECT by address), one PROXY destination (operator rule).
	f.direct(t, f.example)
	f.sendTCP(t, netip.MustParseAddr("8.8.4.4"), 40001, 80)
	f.sendTCP(t, f.example, 40002, 443)
	f.sendTCP(t, f.proxyIP, 40003, 443)

	sessionID := f.sessionID(t)
	generation := f.generation(t)
	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{
		SessionID:          sessionID,
		RouteGeneration:    generation,
		HasRouteGeneration: true,
	})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}

	if answer.Selection.State != ClientDiagnosisStateLive {
		t.Fatalf("selection.state = %q, want live; answer=%+v", answer.Selection.State, answer.Selection)
	}
	if answer.Selection.RouteGeneration != generation {
		t.Errorf("route_generation = %d, want %d", answer.Selection.RouteGeneration, generation)
	}
	if answer.Selection.ConnectionName != "phone" || answer.Selection.AssignedIP != f.clientIP.String() {
		t.Errorf("selection identity = %+v, want the admitted session's own", answer.Selection)
	}
	if !answer.ReadOnly {
		t.Error("the answer must declare that it is read-only")
	}

	if !answer.Flows.Available {
		t.Fatalf("flows = %+v, want an available section", answer.Flows)
	}
	if got := findFlow(t, answer.Flows.Entries, f.example.String(), 443); got.Choice != forwarder.EgressChoiceDirect.String() {
		t.Errorf("DIRECT flow choice = %q, want DIRECT", got.Choice)
	}
	if got := findFlow(t, answer.Flows.Entries, f.proxyIP.String(), 443); got.Choice != forwarder.EgressChoiceProxy.String() {
		t.Errorf("PROXY flow choice = %q, want PROXY", got.Choice)
	}
	if got := findFlow(t, answer.Flows.Entries, "8.8.4.4", 80); got.Choice != forwarder.EgressChoiceProxy.String() {
		t.Errorf("default flow choice = %q, want the PROXY default", got.Choice)
	}
	for _, flow := range answer.Flows.Entries {
		if flow.Protocol != "tcp" {
			t.Errorf("flow protocol = %q, want tcp", flow.Protocol)
		}
		if flow.RouteGeneration != generation {
			t.Errorf("flow generation = %d, want the selected %d", flow.RouteGeneration, generation)
		}
		// Slice 3b turned these from explicit unknowns into recorded facts. The
		// requirement did not weaken: each must carry the fact its producer wrote,
		// and a value that is absent still has to say so.
		if flow.DecisionTime == "" {
			t.Errorf("flow decision time is empty; it must be an instant or the not_recorded token")
		}
		if flow.DecisionReason == "" {
			t.Errorf("flow decision reason is empty; it must be a branch token or the not_recorded token")
		}
		if flow.PolicyGeneration == "" {
			t.Errorf("flow policy generation is empty; it must be a generation or the not_recorded token")
		}
	}

	// Every stated unknown is stated, and nothing the tables now record is claimed as
	// unrecorded: a limitation beside a recorded row would contradict it.
	for _, want := range []string{
		ClientDiagnosisLimitSingleSnapshot,
		ClientDiagnosisLimitFlowCountersSampled,
		ClientDiagnosisLimitFlowEvidenceInstall,
	} {
		if !clientDiagHas(answer.Limitations, want) {
			t.Errorf("limitations are missing %q: %v", want, answer.Limitations)
		}
	}
	for _, stale := range []string{
		"dns_names_not_retained",
		"dns_records_not_recorded",
		"dns_questions_not_retained",
		"route_cache_evidence_only",
		"encrypted_dns_not_observed",
		"records_without_route_generation",
		"flow_decision_time_not_recorded",
		"flow_decision_reason_not_recorded",
		"flow_outcomes_not_recorded",
		"drop_records_not_retained",
		"proxy_backend_write_not_attributed",
		"non_tcp_udp_flows_not_recorded",
	} {
		if clientDiagHas(answer.Limitations, stale) {
			t.Errorf("limitations still claim %q although the answer records it: %v",
				stale, answer.Limitations)
		}
	}
	// Application success and PROXY return are facts no router-side store can
	// ever hold, so they belong to the coverage list rather than to this
	// answer's caveats.
	for _, want := range []string{
		ClientDiagnosisLimitApplication,
		ClientDiagnosisLimitReturnTupleAssociation,
	} {
		if !clientDiagHas(answer.Coverage.NotCovered, want) {
			t.Errorf("coverage.not_covered is missing %q: %v", want, answer.Coverage.NotCovered)
		}
	}
	// The pre-flow refusal ledger is a real section now: a client with no refusal in the
	// retention window reads as available-but-empty, with its bounds stated, rather than as
	// an unrecorded section.
	if !answer.Drops.Available || answer.Drops.State != "none_retained" || len(answer.Drops.Entries) != 0 {
		t.Errorf("drops = %+v, want available with no retained refusals", answer.Drops)
	}
	if answer.Drops.Coverage.KeyLimit == 0 || answer.Drops.Coverage.AgeLimitSeconds == 0 {
		t.Errorf("drops coverage does not state its bounds: %+v", answer.Drops.Coverage)
	}

	// The wire shape is what the browser receives: no field may be dropped.
	raw, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundTrip map[string]any
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"selection", "coverage", "flows", "drops", "limitations", "evaluated_at", "read_only"} {
		if _, ok := roundTrip[key]; !ok {
			t.Errorf("wire answer is missing section %q", key)
		}
	}
	if strings.Contains(string(raw), f.peerKey) {
		t.Errorf("the answer carries the peer key: %s", raw)
	}
}

// TestClientDiagnosisIsolatesClients proves one client's record never appears
// in another client's answer, in either section.
func TestClientDiagnosisIsolatesClients(t *testing.T) {
	f := newClientDiagFixture(t)
	f.sendTCP(t, f.example, 41001, 443)
	firstSession := f.sessionID(t)

	// A second client, admitted through the same production path.
	otherIP := netip.MustParseAddr("10.100.0.11")
	otherPeer := "peer-client-diag-2"
	otherSess, err := f.sessions.CreateSession(context.Background(), "user-2", otherPeer, otherIP.String(), 11, "tablet")
	if err != nil {
		t.Fatalf("CreateSession(other): %v", err)
	}
	f.fwd.AttachBackendDevice(11, f.backend)
	f.fwd.RegisterSession(otherSess.ID, "conn-2", otherPeer, otherIP.String(), 11)
	otherPkt := buildTestPBRTCPPacket(otherIP, netip.MustParseAddr("1.1.1.1"), 41002, 53, []byte("other"))
	if err := f.fwd.RouteClientToBackend(otherPeer, otherPkt); err != nil {
		t.Fatalf("RouteClientToBackend(other): %v", err)
	}

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: firstSession})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.Selection.State != ClientDiagnosisStateLive {
		t.Fatalf("selection.state = %q, want live", answer.Selection.State)
	}
	for _, flow := range answer.Flows.Entries {
		if flow.DestinationIP == "1.1.1.1" {
			t.Error("the first client's answer contains the other client's flow")
		}
	}

	// The picker lists both incarnations with their own route generations.
	targets := f.svc.ClientDiagnosisTargets()
	if len(targets.Clients) != 2 {
		t.Fatalf("clients = %d, want 2", len(targets.Clients))
	}
	if !targets.PolicyRoutingEnabled || !targets.ReadOnly {
		t.Errorf("targets = %+v, want policy routing enabled and read-only", targets)
	}
	for _, target := range targets.Clients {
		if target.SessionID == firstSession {
			if !target.RouteLive || target.RouteGeneration == 0 {
				t.Errorf("first client target = %+v, want a live route generation", target)
			}
		}
	}
}

// TestClientDiagnosisRefusesAnotherIncarnation covers replaced, unknown and
// absent selections: none of them may return another incarnation's records.
func TestClientDiagnosisRefusesAnotherIncarnation(t *testing.T) {
	f := newClientDiagFixture(t)
	f.sendTCP(t, f.example, 42001, 443)
	sessionID := f.sessionID(t)
	oldGeneration := f.generation(t)

	// A same-session rekey replaces the route generation and purges the flows.
	f.fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", f.peerKey, f.clientIP.String(), 11, nil)
	newGeneration := f.generation(t)
	if newGeneration == oldGeneration {
		t.Fatal("rekey did not advance the route generation")
	}

	t.Run("ReplacedGeneration", func(t *testing.T) {
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{
			SessionID:          sessionID,
			RouteGeneration:    oldGeneration,
			HasRouteGeneration: true,
		})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		if answer.Selection.State != ClientDiagnosisStateRouteGenerationReplaced {
			t.Fatalf("state = %q, want route_generation_replaced", answer.Selection.State)
		}
		if len(answer.Flows.Entries) != 0 {
			t.Errorf("a replaced incarnation returned records: %+v", answer.Flows.Entries)
		}
		if answer.Selection.RequestedRouteGeneration == nil || *answer.Selection.RequestedRouteGeneration != oldGeneration {
			t.Errorf("requested generation = %v, want the refused %d", answer.Selection.RequestedRouteGeneration, oldGeneration)
		}
	})

	t.Run("CurrentGenerationIsLive", func(t *testing.T) {
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{
			SessionID:          sessionID,
			RouteGeneration:    newGeneration,
			HasRouteGeneration: true,
		})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		if answer.Selection.State != ClientDiagnosisStateLive {
			t.Fatalf("state = %q, want live for the current generation", answer.Selection.State)
		}
		// The flow table does not survive a rekey.
		if len(answer.Flows.Entries) != 0 {
			t.Errorf("flows = %d after a rekey, want 0", len(answer.Flows.Entries))
		}
	})

	t.Run("UnknownSession", func(t *testing.T) {
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: "sess-does-not-exist"})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		if answer.Selection.State != ClientDiagnosisStateUnknownSession {
			t.Fatalf("state = %q, want unknown_session", answer.Selection.State)
		}
		if len(answer.Flows.Entries) != 0 {
			t.Error("an unknown session returned records")
		}
		if !clientDiagHas(answer.Limitations, ClientDiagnosisLimitSessionEnd) {
			t.Errorf("limitations must state that an ended session cannot be told from an unknown one: %v", answer.Limitations)
		}
	})

	t.Run("RouteAbsent", func(t *testing.T) {
		// A session that is live in the registry but owns no forwarder route
		// (teardown in progress, or admitted without routing).
		orphan, err := f.sessions.CreateSession(context.Background(), "user-3", "peer-orphan", "10.100.0.12", 11, "laptop")
		if err != nil {
			t.Fatalf("CreateSession(orphan): %v", err)
		}
		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: orphan.ID})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		if answer.Selection.State != ClientDiagnosisStateRouteAbsent {
			t.Fatalf("state = %q, want route_absent", answer.Selection.State)
		}
		if len(answer.Flows.Entries) != 0 {
			t.Error("a session without a route returned records")
		}
	})
}

// TestClientDiagnosisPolicyDisabledAndMissingService covers the two states a
// service without an active policy path can truthfully report.
func TestClientDiagnosisPolicyDisabledAndMissingService(t *testing.T) {
	t.Run("PolicyDisabled", func(t *testing.T) {
		svc := &Service{}
		answer, err := svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: "sess-1"})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		if answer.Selection.State != ClientDiagnosisStatePolicyDisabled {
			t.Fatalf("state = %q, want policy_disabled", answer.Selection.State)
		}
		if answer.Coverage.PolicyRoutingEnabled {
			t.Error("coverage claims policy routing is enabled")
		}
		if answer.Flows.Available {
			t.Error("a disabled policy path must not report an available flow section")
		}
		if len(answer.Flows.Entries) != 0 {
			t.Error("a disabled policy path returned records")
		}
	})

	t.Run("SessionRequired", func(t *testing.T) {
		f := newClientDiagFixture(t)
		if _, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{}); err == nil {
			t.Fatal("an empty session id must be refused")
		}
	})

	t.Run("IdentityUnavailable", func(t *testing.T) {
		// A forwarder and policy runtime without the session registry cannot
		// verify which authenticated incarnation a route belongs to.
		f := newClientDiagFixture(t)
		bare := &Service{forwarder: f.fwd}
		answer, err := bare.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		if answer.Selection.State != ClientDiagnosisStateIdentityUnavailable {
			t.Fatalf("state = %q, want identity_unavailable", answer.Selection.State)
		}
	})
}

// TestClientDiagnosisBusyAndCancelled covers the concurrency and cancellation
// edges of the read.
func TestClientDiagnosisBusyAndCancelled(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)

	if !f.svc.clientDiagBusy.CompareAndSwap(false, true) {
		t.Fatal("fixture could not take the in-flight flag")
	}
	if _, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID}); err != ErrClientDiagnosisBusy {
		t.Fatalf("second snapshot error = %v, want ErrClientDiagnosisBusy", err)
	}
	f.svc.clientDiagBusy.Store(false)

	if _, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID}); err != nil {
		t.Fatalf("released flag must admit the next snapshot: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.svc.ClientDiagnosis(ctx, ClientDiagnosisRequest{SessionID: sessionID}); err == nil {
		t.Fatal("a cancelled context must not produce an answer")
	}
	if f.svc.clientDiagBusy.Load() {
		t.Error("the in-flight flag must be released on the error path")
	}
}

// TestClientDiagnosisLeavesEveryStoreUntouched is the read-only control: the
// counters and the flow table are identical before and after a diagnosis
// request.
func TestClientDiagnosisLeavesEveryStoreUntouched(t *testing.T) {
	f := newClientDiagFixture(t)
	f.sendTCP(t, f.example, 43001, 443)
	sessionID := f.sessionID(t)
	generation := f.generation(t)

	proxyBytesBefore, directBytesBefore, proxyDropsBefore := f.svc.PolicyDispatchCounters()
	directDropsBefore := f.svc.PolicyDirectDrops()
	flowsBefore := f.dem.SnapshotSessionFlows(sessionID, generation, time.Now(), 0)

	for i := 0; i < 3; i++ {
		if _, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID}); err != nil {
			t.Fatalf("ClientDiagnosis %d: %v", i, err)
		}
	}

	proxyBytesAfter, directBytesAfter, proxyDropsAfter := f.svc.PolicyDispatchCounters()
	if proxyBytesAfter != proxyBytesBefore || directBytesAfter != directBytesBefore || proxyDropsAfter != proxyDropsBefore {
		t.Errorf("dispatch counters moved: %d/%d/%d -> %d/%d/%d",
			proxyBytesBefore, directBytesBefore, proxyDropsBefore, proxyBytesAfter, directBytesAfter, proxyDropsAfter)
	}
	if got := f.svc.PolicyDirectDrops(); got != directDropsBefore {
		t.Errorf("direct drops moved: %d -> %d", directDropsBefore, got)
	}
	// The flow records themselves must be identical, including lastSeen: a read
	// that refreshed or retired one would change this.
	flowsAfter := f.dem.SnapshotSessionFlows(sessionID, generation, time.Now(), 0)
	if flowsAfter.Total != flowsBefore.Total {
		t.Fatalf("flow count moved: %d -> %d", flowsBefore.Total, flowsAfter.Total)
	}
	for i := range flowsBefore.Flows {
		if !flowsBefore.Flows[i].LastSeen.Equal(flowsAfter.Flows[i].LastSeen) {
			t.Errorf("flow %d lastSeen moved: %v -> %v", i, flowsBefore.Flows[i].LastSeen, flowsAfter.Flows[i].LastSeen)
		}
		if flowsBefore.Flows[i].Expired != flowsAfter.Flows[i].Expired {
			t.Errorf("flow %d expiry state moved", i)
		}
	}
}

// TestClientDiagnosisStillSelected pins the revalidation guard directly. The
// full interleaving (a rekey landing between the copies) cannot be scheduled
// deterministically, so the guard's contract is asserted as a pure decision:
// only the exact generation that was read counts as still selected.
func TestClientDiagnosisStillSelected(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	generation := f.generation(t)

	if !clientDiagnosisStillSelected(f.fwd, sessionID, generation) {
		t.Fatal("the registered generation must count as still selected")
	}
	if clientDiagnosisStillSelected(f.fwd, sessionID, generation+1) {
		t.Error("an unregistered generation must not count as selected")
	}
	if clientDiagnosisStillSelected(f.fwd, "sess-other", generation) {
		t.Error("another session must not count as selected")
	}

	f.fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", f.peerKey, f.clientIP.String(), 11, nil)
	if clientDiagnosisStillSelected(f.fwd, sessionID, generation) {
		t.Error("a replaced generation must not count as selected after a rekey")
	}
}

// TestClientDiagnosisHelperContracts pins the small pure helpers the read path is
// assembled from, so their branches are covered individually rather than only
// through one end-to-end path.
func TestClientDiagnosisHelperContracts(t *testing.T) {
	t.Run("RouteIndexKeepsTheNewestGeneration", func(t *testing.T) {
		index := clientDiagnosisRouteIndex([]forwarder.SessionRoute{
			{SessionID: "sess-a", Generation: 2},
			{SessionID: "sess-a", Generation: 5},
			{SessionID: "sess-a", Generation: 3},
			{SessionID: "sess-b", Generation: 1},
		})
		if got := index["sess-a"].Generation; got != 5 {
			t.Errorf("sess-a generation = %d, want the newest 5", got)
		}
		if got := index["sess-b"].Generation; got != 1 {
			t.Errorf("sess-b generation = %d, want 1", got)
		}
		if len(index) != 2 {
			t.Errorf("index holds %d sessions, want 2", len(index))
		}
	})

	t.Run("FindSessionAndRouteWithoutSources", func(t *testing.T) {
		if got := clientDiagnosisFindSession(nil, "sess-a"); got != nil {
			t.Errorf("nil registry returned a session: %+v", got)
		}
		if _, ok := clientDiagnosisFindRoute(&forwarder.Forwarder{}, "sess-a"); ok {
			t.Error("a forwarder with no routes reported one")
		}
	})

	t.Run("UnavailableStates", func(t *testing.T) {
		if state, limitation := clientDiagnosisUnavailableState(nil, nil); state != ClientDiagnosisStatePolicyDisabled || limitation != "" {
			t.Errorf("nil forwarder = %q/%q, want policy_disabled with no limitation", state, limitation)
		}
		fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
		fwd.SetPBREnabled(true)
		if state, limitation := clientDiagnosisUnavailableState(fwd, nil); state != ClientDiagnosisStateIdentityUnavailable || limitation != ClientDiagnosisLimitIdentitySource {
			t.Errorf("missing registry = %q/%q, want identity_unavailable", state, limitation)
		}
	})

	t.Run("RefusalLimitations", func(t *testing.T) {
		if got := clientDiagnosisRefusalLimitations(ClientDiagnosisStateUnknownSession); len(got) != 1 || got[0] != ClientDiagnosisLimitSessionEnd {
			t.Errorf("unknown_session limitations = %v, want [%s]", got, ClientDiagnosisLimitSessionEnd)
		}
		// The verdict token explains these on its own: no limitation names a store
		// this build no longer has.
		for _, verdict := range []string{ClientDiagnosisStateRouteAbsent, ClientDiagnosisStateRouteGenerationReplaced} {
			if got := clientDiagnosisRefusalLimitations(verdict); got != nil {
				t.Errorf("%s limitations = %v, want none", verdict, got)
			}
		}
		if got := clientDiagnosisRefusalLimitations(ClientDiagnosisStateLive); got != nil {
			t.Errorf("live verdict limitations = %v, want none", got)
		}
	})
}

func clientDiagHas(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
