package vpn

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
	mdns "github.com/miekg/dns"
)

// Query identity and publication waits for the client diagnosis fixture (issue #861).
//
// A delivered reply and a terminal event are two separate publications of one query:
// the chain writes the reply first and the ledger entry after it. The waits here match
// a query by its own identity - the client port it was sent from, its DNS id, its
// question - and match a terminal event only by the session, receipt incarnation, name
// and type it published under, after the dispatch instant. It also owns the idempotent
// release of the blocking upstream exchange, so every exit path unblocks it before the
// fixture tears the resolver down.

// clientDiagQueryBudget is the fixture's existing two-second wait, used separately for
// one query's reply and for its terminal publication.
const clientDiagQueryBudget = 2 * time.Second

// dnsQueryPlan is one client DNS query and the identity that makes a captured reply
// belong to it: the client port it is sent from and the DNS id it carries.
type dnsQueryPlan struct {
	name    string
	qtype   uint16
	srcPort uint16
	id      uint16
}

// queryWatch ties a dispatched query to the incarnation that received it and to the
// terminal history as it stood before dispatch, so a later event can be proven to be
// this query's publication rather than something that was already there.
type queryWatch struct {
	plan       dnsQueryPlan
	sessionID  string
	generation uint64
	startedAt  time.Time
	counts     map[uint64]int
	reply      []byte
}

// releaseSlow unblocks the blocking upstream exchange exactly once. It is registered
// with the fixture, so an early assertion failure releases it before teardown.
func (f *clientDiagFixture) releaseSlow() {
	f.slowOnce.Do(func() { close(f.slowRelease) })
}

// eventCounts snapshots the session's terminal events by sequence number. A collapse
// keeps the sequence number and raises the count, which is why both are recorded.
func (f *clientDiagFixture) eventCounts(sessionID string) map[uint64]int {
	counts := make(map[uint64]int)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()
	if ledger == nil {
		return counts
	}
	for _, event := range ledger.SnapshotEvents(sessionID, 0).Events {
		counts[event.Seq] = event.Count
	}
	return counts
}

// dispatchQuery sends one query through the intercepted path and returns its watch.
// It does not wait: the caller decides which completion it needs, and a worker
// goroutine can use it without touching a *testing.T.
func (f *clientDiagFixture) dispatchQuery(plan dnsQueryPlan) (*queryWatch, error) {
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(plan.name), plan.qtype)
	req.Id = plan.id
	raw, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query %s/%d: %w", plan.name, plan.qtype, err)
	}
	states := f.fwd.SessionRouteStates()
	if len(states) != 1 {
		return nil, fmt.Errorf("route states = %d, want 1", len(states))
	}
	watch := &queryWatch{
		plan:       plan,
		sessionID:  states[0].SessionID,
		generation: states[0].Generation,
		startedAt:  time.Now(),
		counts:     f.eventCounts(states[0].SessionID),
	}
	pkt := buildTestPBRUDPPacket(f.clientIP, f.gwDNS, plan.srcPort, 53, raw)
	if err := f.fwd.RouteClientToBackend(f.peerKey, pkt); err != nil {
		return nil, fmt.Errorf("RouteClientToBackend(%s/%d): %w", plan.name, plan.qtype, err)
	}
	return watch, nil
}

// capturedUDP returns the destination port and DNS payload of one captured IPv4/UDP
// reply packet.
func capturedUDP(pkt []byte) (dstPort uint16, payload []byte, ok bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 17 {
		return 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || total > len(pkt) || ihl+8 > total {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]), pkt[ihl+8 : total], true
}

// replyRCode returns the DNS response code one captured reply carries.
func replyRCode(t *testing.T, reply []byte) int {
	t.Helper()
	_, payload, ok := capturedUDP(reply)
	if !ok {
		t.Fatalf("captured reply is not an IPv4/UDP packet")
	}
	msg := new(mdns.Msg)
	if err := msg.Unpack(payload); err != nil {
		t.Fatalf("unpack captured reply: %v", err)
	}
	return msg.Rcode
}

// matchReply finds the captured reply that answers exactly this plan: addressed to the
// client port the query came from, carrying its DNS id and its question. Any other
// reply already captured by the fixture - an earlier answer, a refusal for another
// port - is not it.
func (f *clientDiagFixture) matchReply(plan dnsQueryPlan) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, reply := range f.replies {
		dstPort, payload, ok := capturedUDP(reply)
		if !ok || dstPort != plan.srcPort {
			continue
		}
		msg := new(mdns.Msg)
		if err := msg.Unpack(payload); err != nil || msg.Id != plan.id || len(msg.Question) != 1 {
			continue
		}
		if msg.Question[0].Name != mdns.Fqdn(plan.name) || msg.Question[0].Qtype != plan.qtype {
			continue
		}
		out := make([]byte, len(reply))
		copy(out, reply)
		return out, true
	}
	return nil, false
}

// awaitReply waits up to budget for this query's own reply. Delivery and terminal
// publication are separate facts, so this wait never stands in for the event wait.
func (f *clientDiagFixture) awaitReply(watch *queryWatch, budget time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(budget)
	for {
		if reply, ok := f.matchReply(watch.plan); ok {
			return reply, true
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// matchEvent finds the terminal event this query published: same session, same receipt
// generation, same name and type, of the requested kind when one is given, and newer
// than the history the watch captured. An event that was already in the ledger - even
// an answered one for the same name and type - is not this query's publication.
func (f *clientDiagFixture) matchEvent(watch *queryWatch, kind string) (dnsledger.Event, bool) {
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()
	if ledger == nil {
		return dnsledger.Event{}, false
	}
	wantName := strings.ToLower(strings.TrimSuffix(mdns.Fqdn(watch.plan.name), "."))
	for _, event := range ledger.SnapshotEvents(watch.sessionID, 0).Events {
		if event.Name != wantName || event.QType != watch.plan.qtype {
			continue
		}
		if !event.RouteGenerationKnown || event.RouteGeneration != watch.generation {
			continue
		}
		if kind != "" && event.Kind != kind {
			continue
		}
		if event.LastSeen.Before(watch.startedAt) {
			continue
		}
		if previous, existed := watch.counts[event.Seq]; existed && event.Count <= previous {
			continue
		}
		return event, true
	}
	return dnsledger.Event{}, false
}

// awaitEvent waits up to budget for this query's terminal publication. The ledger is
// written after the reply is delivered, so a delivered reply alone cannot satisfy it.
func (f *clientDiagFixture) awaitEvent(watch *queryWatch, budget time.Duration, kind string) (dnsledger.Event, bool) {
	deadline := time.Now().Add(budget)
	for {
		if event, ok := f.matchEvent(watch, kind); ok {
			return event, true
		}
		if time.Now().After(deadline) {
			return dnsledger.Event{}, false
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// awaitQuery waits for an already dispatched query's reply and then its terminal
// publication, each under the existing budget. It returns an error instead of failing a
// test, so a worker goroutine can report its own outcome and the parent can assert it.
func (f *clientDiagFixture) awaitQuery(watch *queryWatch) error {
	reply, ok := f.awaitReply(watch, clientDiagQueryBudget)
	if !ok {
		return fmt.Errorf("no DNS reply delivered for %s/%d on client port %d",
			watch.plan.name, watch.plan.qtype, watch.plan.srcPort)
	}
	watch.reply = reply
	// A service whose collector is detached publishes no terminal history, so there is
	// nothing to wait for; waiting anyway would turn "no collector" into a timeout.
	if f.svc.clientDiagnosisRouteCache().DNSLedger() == nil {
		return nil
	}
	if _, ok := f.awaitEvent(watch, clientDiagQueryBudget, ""); !ok {
		return fmt.Errorf("no terminal event published for %s/%d after its reply",
			watch.plan.name, watch.plan.qtype)
	}
	return nil
}

// query is one client DNS query through the intercepted path. It returns after the
// reply is delivered AND the terminal event is published, which is the order the chain
// uses, so a caller that reads history next reads settled state.
func (f *clientDiagFixture) query(plan dnsQueryPlan) (*queryWatch, error) {
	watch, err := f.dispatchQuery(plan)
	if err != nil {
		return nil, err
	}
	if err := f.awaitQuery(watch); err != nil {
		return watch, err
	}
	return watch, nil
}

// queryIP is one client A query through the intercepted path.
func (f *clientDiagFixture) queryIP(t *testing.T, name string, srcPort uint16) {
	t.Helper()
	if _, err := f.query(dnsQueryPlan{name: name, qtype: mdns.TypeA, srcPort: srcPort, id: 0x1234}); err != nil {
		t.Fatal(err)
	}
}

// queryType is one client DNS query of an arbitrary type through the
// intercepted path, which is how a non-A query reaches the observer.
func (f *clientDiagFixture) queryType(t *testing.T, name string, qtype uint16, srcPort uint16) {
	t.Helper()
	if _, err := f.query(dnsQueryPlan{name: name, qtype: qtype, srcPort: srcPort, id: 0x4321}); err != nil {
		t.Fatal(err)
	}
}
