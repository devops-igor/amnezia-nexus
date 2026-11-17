package vpn

import (
	"sync"
	"testing"
	"time"

	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	mdns "github.com/miekg/dns"
)

// DNS history lifetime controls (issue #861).
//
// Both history writers run after the client's reply has been delivered: the answer
// record first, the terminal event last. A client can disconnect in that window, so an
// already-admitted producer can resume after its session's history was erased. The
// history lifetime is the authority that decides those late writes: it opens at query
// receipt, closes in the same critical section that erases the rows, and both writers
// require it under the lock they append with.
//
// The pausing observer below holds the real writer at exactly that window, so the cases
// describe the production ordering rather than a simulated one.

// pausingObserver delegates every observation to the cache and can hold the first answer
// write and the first terminal-event write before they reach the real writer.
type pausingObserver struct {
	*MemoryRouteCache

	mu          sync.Mutex
	pauseAnswer bool
	pauseEvent  bool

	answerEntered chan struct{}
	answerRelease chan struct{}
	answerDone    chan struct{}

	eventEntered chan struct{}
	eventRelease chan struct{}
	eventDone    chan struct{}
}

// take reports whether this call should pause, and armed it for at most one write.
func takePause(armed *bool, mu *sync.Mutex) bool {
	mu.Lock()
	defer mu.Unlock()
	if !*armed {
		return false
	}
	*armed = false
	return true
}

func (o *pausingObserver) ObserveDNSResponse(sessionID string, req, resp *mdns.Msg) error {
	if takePause(&o.pauseAnswer, &o.mu) {
		close(o.answerEntered)
		<-o.answerRelease
		defer close(o.answerDone)
	}
	return o.MemoryRouteCache.ObserveDNSResponse(sessionID, req, resp)
}

func (o *pausingObserver) ObserveDNSQueryEvent(event gatewaydns.QueryEvent) {
	if takePause(&o.pauseEvent, &o.mu) {
		close(o.eventEntered)
		<-o.eventRelease
		defer close(o.eventDone)
	}
	o.MemoryRouteCache.ObserveDNSQueryEvent(event)
}

// releaseOnce returns an idempotent release for a pause channel, registered with the test
// so a failing case cannot leave the DNS worker blocked before the fixture tears down.
func releaseOnce(t *testing.T, ch chan struct{}) func() {
	var once sync.Once
	release := func() { once.Do(func() { close(ch) }) }
	t.Cleanup(release)
	return release
}

// waitOrFail waits for one of the pause signals.
func waitOrFail(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not happen", what)
	}
}

// requireNoHistory asserts both stores hold nothing for the session and that the
// collector's accounting is back to zero.
func requireNoHistory(t *testing.T, f *clientDiagFixture, sessionID string) {
	t.Helper()
	ledger := f.routeCache.DNSLedger()
	events := ledger.SnapshotEvents(sessionID, 0)
	answers := ledger.Snapshot(sessionID, 0)
	if events.Total != 0 {
		t.Fatalf("terminal history for a retired session: %d rows %+v", events.Total, events.Events)
	}
	if answers.Total != 0 {
		t.Fatalf("answer history for a retired session: %d rows", answers.Total)
	}
	if events.Stats.Events != 0 || events.Stats.Bytes != 0 || answers.Stats.Records != 0 || answers.Stats.Bytes != 0 {
		t.Fatalf("accounting outlived the session: events=%d/%d answers=%d/%d",
			events.Stats.Events, events.Stats.Bytes, answers.Stats.Records, answers.Stats.Bytes)
	}
}

// TestDNSHistoryCannotResurrectAfterRetirement is the retirement fence on both writers:
// the reply is genuinely delivered, the writer is held before the real write, the session
// is unregistered, and the resumed write must not recreate history in either store.
func TestDNSHistoryCannotResurrectAfterRetirement(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		name := "answer-writer"
		if terminal {
			name = "terminal-event-writer"
		}
		t.Run(name, func(t *testing.T) {
			f := newClientDiagFixture(t)
			sessionID := f.sessionID(t)
			observer := &pausingObserver{MemoryRouteCache: f.routeCache}
			var release func()
			if terminal {
				observer.pauseEvent = true
				observer.eventEntered = make(chan struct{})
				observer.eventRelease = make(chan struct{})
				observer.eventDone = make(chan struct{})
				release = releaseOnce(t, observer.eventRelease)
			} else {
				observer.pauseAnswer = true
				observer.answerEntered = make(chan struct{})
				observer.answerRelease = make(chan struct{})
				observer.answerDone = make(chan struct{})
				release = releaseOnce(t, observer.answerRelease)
			}
			f.svc.DNSGateway().SetObserver(observer)

			watch, err := f.dispatchQuery(dnsQueryPlan{name: "plain.example", qtype: mdns.TypeA, srcPort: 57501, id: 0x6789})
			if err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			entered, done := observer.answerEntered, observer.answerDone
			if terminal {
				entered, done = observer.eventEntered, observer.eventDone
			}
			waitOrFail(t, entered, "the paused history writer entering")
			if _, ok := f.awaitReply(watch, time.Second); !ok {
				t.Fatal("the client reply was not delivered")
			}

			// The client disconnects while the writer is still held.
			f.fwd.UnregisterSession(f.peerKey)
			requireNoHistory(t, f, sessionID)

			// The resumed writer must find its lifetime closed.
			release()
			waitOrFail(t, done, "the paused history writer finishing")
			requireNoHistory(t, f, sessionID)
		})
	}
}

// TestDNSHistorySurvivesLivePublicationAndSameSessionRekey is the positive beside the
// fence: a live session's history is recorded, and a same-session rekey keeps it - the
// first row keeps the generation it was received under, the second carries the rekey's.
func TestDNSHistorySurvivesLivePublicationAndSameSessionRekey(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	f.queryIP(t, "plain.example", 57601)

	ledger := f.routeCache.DNSLedger()
	first := ledger.SnapshotEvents(sessionID, 0)
	if first.Total != 1 {
		t.Fatalf("live publication: %d terminal rows, want 1", first.Total)
	}
	receiptGeneration := first.Events[0].RouteGeneration

	// Same session id, new route generation: a rekey, not a retirement.
	f.fwd.RegisterSessionWithReturnPath(sessionID, "conn-2", f.peerKey, f.clientIP.String(), 11, f.returnPath)
	rekeyGeneration := f.generation(t)
	if rekeyGeneration == receiptGeneration {
		t.Fatalf("the rekey did not advance the generation (%d)", rekeyGeneration)
	}

	f.queryIP(t, "nx.example", 57602)
	events := ledger.SnapshotEvents(sessionID, 0)
	if events.Total != 2 {
		t.Fatalf("history after the rekey: %d terminal rows, want both queries", events.Total)
	}
	for _, event := range events.Events {
		switch event.Name {
		case "plain.example":
			if event.RouteGeneration != receiptGeneration {
				t.Errorf("the pre-rekey row lost its receipt generation: %d, want %d",
					event.RouteGeneration, receiptGeneration)
			}
		case "nx.example":
			if event.RouteGeneration != rekeyGeneration {
				t.Errorf("the post-rekey row generation = %d, want %d", event.RouteGeneration, rekeyGeneration)
			}
			if event.Kind != gatewaydns.QueryEventNXDomain {
				t.Errorf("post-rekey kind = %q, want %q", event.Kind, gatewaydns.QueryEventNXDomain)
			}
		}
	}
	if got := ledger.Snapshot(sessionID, 0).Total; got != 1 {
		t.Errorf("answer history after the rekey = %d rows, want the one delivered answer", got)
	}
}

// TestDNSHistoryDoesNotCreditAReAdmittedLifetime proves a publication from a retired
// lifetime cannot be credited to a later admission of the same session id: the lifetime
// opened by the re-admitted session's own receipt bounds it, and the older receipt
// generation is refused. The re-admitted session's own query is recorded normally, so the
// fence does not close the door on the new lifetime.
func TestDNSHistoryDoesNotCreditAReAdmittedLifetime(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	observer := &pausingObserver{
		MemoryRouteCache: f.routeCache,
		pauseEvent:       true,
		eventEntered:     make(chan struct{}),
		eventRelease:     make(chan struct{}),
		eventDone:        make(chan struct{}),
	}
	release := releaseOnce(t, observer.eventRelease)
	f.svc.DNSGateway().SetObserver(observer)

	stale, err := f.dispatchQuery(dnsQueryPlan{name: "stale.example", qtype: mdns.TypeA, srcPort: 57701, id: 0x7a01})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	waitOrFail(t, observer.eventEntered, "the stale terminal writer entering")
	if _, ok := f.awaitReply(stale, time.Second); !ok {
		t.Fatal("the client reply was not delivered")
	}

	// Retire the lifetime the stale query was received under, then re-admit the same
	// session id: a new route generation, and a fresh history lifetime.
	f.fwd.UnregisterSession(f.peerKey)
	requireNoHistory(t, f, sessionID)
	f.fwd.RegisterSessionWithReturnPath(sessionID, "conn-2", f.peerKey, f.clientIP.String(), 11, f.returnPath)
	reAdmitted := f.generation(t)
	if reAdmitted <= stale.generation {
		t.Fatalf("re-admission generation %d is not later than the retired receipt %d", reAdmitted, stale.generation)
	}

	// The re-admitted session's own query opens its lifetime and is recorded while the
	// stale writer is still held.
	if _, err := f.query(dnsQueryPlan{name: "plain.example", qtype: mdns.TypeA, srcPort: 57702, id: 0x7a02}); err != nil {
		t.Fatalf("the re-admitted session's query: %v", err)
	}
	ledger := f.routeCache.DNSLedger()
	if got := ledger.SnapshotEvents(sessionID, 0).Total; got != 1 {
		t.Fatalf("the re-admitted lifetime's own query: %d terminal rows, want 1", got)
	}

	// Now let the stale writer run: its receipt generation predates this lifetime.
	release()
	waitOrFail(t, observer.eventDone, "the stale terminal writer finishing")
	events := ledger.SnapshotEvents(sessionID, 0)
	if events.Total != 1 || events.Events[0].Name != "plain.example" {
		t.Fatalf("the retired lifetime's publication was credited to the re-admitted one: %d rows %+v",
			events.Total, events.Events)
	}
	if events.Events[0].RouteGeneration != reAdmitted {
		t.Errorf("re-admitted row generation = %d, want %d", events.Events[0].RouteGeneration, reAdmitted)
	}
}

// TestDNSHistoryCountsAreBoundedOnTheOtherOrdering covers the other interleaving: the
// write lands before retirement, and retirement erases it - both stores empty and the
// collector's accounting back to zero.
func TestDNSHistoryCountsAreBoundedOnTheOtherOrdering(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	f.queryIP(t, "plain.example", 57801)

	ledger := f.routeCache.DNSLedger()
	if got := ledger.SnapshotEvents(sessionID, 0).Total; got != 1 {
		t.Fatalf("terminal history before retirement = %d rows, want 1", got)
	}
	if got := ledger.Snapshot(sessionID, 0).Total; got != 1 {
		t.Fatalf("answer history before retirement = %d rows, want 1", got)
	}
	f.fwd.UnregisterSession(f.peerKey)
	requireNoHistory(t, f, sessionID)
}
