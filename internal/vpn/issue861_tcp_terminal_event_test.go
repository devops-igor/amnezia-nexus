package vpn

import (
	"context"
	"net/netip"
	"testing"
	"time"

	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
	mdns "github.com/miekg/dns"
)

// Real client TCP control for the terminal DNS event (issue #861, R11).
//
// The previous attempt passed a blocking release gate to the upstream helper
// (issue863StartUpstream(t, 0, make(chan struct{}))), whose handler waits forever on
// that channel. The upstream therefore never answered, the client never received a
// reply, and the run hung. That was a fixture prerequisite, not a production defect:
// with a healthy upstream (nil gate) the same path completes.
//
// This test drives the actual client netstack and the gateway's real TCP transport,
// and asserts on the event the real producer wrote and on the real diagnosis API.

// waitForTCPEvent polls the session's terminal events until one with the TCP
// transport for the queried name appears, or the wait budget expires.
func waitForTCPEvent(t *testing.T, ledger *dnsledger.Ledger, sessionID, name string, budget time.Duration) *dnsledger.Event {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		events := ledger.SnapshotEvents(sessionID, 0).Events
		for i := range events {
			if events[i].Transport == "tcp" && events[i].Name == name {
				event := events[i]
				return &event
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil
}

func TestClientDiagnosisRecordsRealTCPQueryEvent(t *testing.T) {
	// A healthy upstream: latency zero and no release gate. The gate is only for
	// deliberate blocking controls, and passing one here is what hung the previous
	// attempt.
	up := issue863StartUpstream(t, 0, nil)
	env := issue863NewEnv(t, up)
	t.Cleanup(func() { _ = env.gw.Close() })

	// A real session identity, so the diagnosis API can select it and resolve the
	// receipt incarnation from the route that will carry the query.
	const peer, connID = "r11-tcp-peer", "r11-tcp-conn"
	clientIP := netip.MustParseAddr("10.100.0.93")
	mgr := session.NewSessionManager(nil, nil)
	sess, err := mgr.CreateSession(context.Background(), "user-r11", peer, clientIP.String(), 1, "tcp-client")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	env.svc.sessionMgr = mgr
	sessionID := sess.ID

	stack, _ := issue863ClientNetstack(t, env.fwd, sessionID, connID, peer, clientIP)

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := stack.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort("10.100.0.1:53"))
	if err != nil {
		t.Fatalf("dial gateway TCP: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	const queryName = "r11-tcp.example.test"
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(queryName), mdns.TypeA)
	query.Id = 0x71a1
	dnsConn := &mdns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(query); err != nil {
		t.Fatalf("write TCP query: %v", err)
	}
	reply, err := dnsConn.ReadMsg()
	if err != nil {
		t.Fatalf("read TCP reply (query never completed; upstream queries so far: %d): %v", up.queries.Load(), err)
	}
	if reply.Rcode != mdns.RcodeSuccess || len(reply.Answer) == 0 {
		t.Fatalf("TCP reply = rcode %d with %d answers, want a NOERROR answer", reply.Rcode, len(reply.Answer))
	}
	if got := up.queries.Load(); got < 1 {
		t.Fatalf("upstream queries = %d, want the TCP query to have reached the healthy upstream", got)
	}

	ledger := env.rc.DNSLedger()
	if ledger == nil {
		t.Fatal("the env cache has no DNS ledger")
	}
	event := waitForTCPEvent(t, ledger, sessionID, queryName, 3*time.Second)
	if event == nil {
		diagnostic := ledger.SnapshotEvents(sessionID, 0)
		routes := env.fwd.SessionRouteStates()
		t.Fatalf("no TCP terminal event recorded for %q; my session=%q; routes=%+v; session events=%+v; store written=%d stored=%d",
			queryName, sessionID, routes, diagnostic.Events, diagnostic.Stats.Written, diagnostic.Stats.Events)
	}
	if event.Kind != gatewaydns.QueryEventAnswered {
		t.Errorf("kind = %q, want answered for a delivered TCP answer", event.Kind)
	}
	if !event.Delivered {
		t.Error("the client read the reply, so the event must report delivery")
	}
	if event.QType != mdns.TypeA || event.RCode != mdns.RcodeSuccess {
		t.Errorf("qtype/rcode = %d/%d, want A/NOERROR", event.QType, event.RCode)
	}
	if event.ReceivedAt.IsZero() || event.AnsweredAt.IsZero() {
		t.Errorf("instants = %v/%v, want both recorded on the TCP path", event.ReceivedAt, event.AnsweredAt)
	}

	receiptGeneration, known := env.fwd.SessionRouteGeneration(sessionID)
	if !known {
		t.Fatal("the admitted session owns no route generation")
	}
	if !event.RouteGenerationKnown || event.RouteGeneration != receiptGeneration {
		t.Errorf("event incarnation = %d/%v, want the receipt incarnation %d",
			event.RouteGeneration, event.RouteGenerationKnown, receiptGeneration)
	}

	// The real diagnosis API must carry the same event, not a rebuild of it.
	answer, err := env.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.Selection.State != ClientDiagnosisStateLive {
		t.Fatalf("selection state = %q, want live; selection=%+v", answer.Selection.State, answer.Selection)
	}
	if !answer.DNS.EventsAvailable {
		t.Fatal("events_available = false with a live collector")
	}
	var apiEvent *ClientDiagnosisDNSQueryEvent
	for i := range answer.DNS.Events {
		if answer.DNS.Events[i].Name == queryName && answer.DNS.Events[i].Transport == "tcp" {
			apiEvent = &answer.DNS.Events[i]
		}
	}
	if apiEvent == nil {
		t.Fatalf("the diagnosis answer has no TCP event for %q; events=%+v", queryName, answer.DNS.Events)
	}
	if apiEvent.Kind != gatewaydns.QueryEventAnswered || !apiEvent.Delivered {
		t.Errorf("api event = %+v, want answered and delivered", apiEvent)
	}
	if apiEvent.ReceivedAt == "" || apiEvent.AnsweredAt == "" {
		t.Errorf("api instants = %q/%q, want both", apiEvent.ReceivedAt, apiEvent.AnsweredAt)
	}
	if !apiEvent.IncarnationKnown || apiEvent.RouteGeneration == nil || *apiEvent.RouteGeneration != receiptGeneration {
		t.Errorf("api incarnation = %v/%v, want the receipt incarnation %d",
			apiEvent.RouteGeneration, apiEvent.IncarnationKnown, receiptGeneration)
	}
}
