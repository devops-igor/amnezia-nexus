package gatewaydns

// Encrypted upstream consumer proof for #865.
//
// What this file proves, and why it lives here: the editor stores an operator's
// encrypted resolver list, but until this test the chain "client DNS packet →
// gateway intercept → upstream exchange over an authenticated DoT/DoH transport →
// answer back to the client → route evidence in that client's session" had never
// been driven end to end against a locally authenticated fixture. Everything used
// below is the production path: the real Gateway, the real Server, the real
// UpstreamResolver with its real DoT/DoH code, and a real client network stack that
// accepts or rejects the answer on its own.
//
// The certificate authority and both listeners are created inside the test on
// 127.0.0.1; no query leaves the host and no external resolver is contacted. The
// only test-only inputs are the resolver's documented fixture seams: the trust
// store, the dial hook and loopback admission (production never sets any of them,
// which is why a persisted setting can never point at a loopback fixture).
//
// The vpn package could not host this proof: it builds
// gatewaydns.ResolverConfig{Upstreams: …} without a way to supply a fixture CA or a
// dial hook, and those fields are unexported in this package. Reaching them would
// mean editing another owner's production wiring or weakening loopback validation,
// so the boundary stops here deliberately.

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// issue865Answers is the name→address table the fixtures answer with. One entry
// matches the compiled policy rule, the other is an ordinary public destination, so
// the same answer set produces both a PROXY and a DIRECT observation.
var issue865Answers = map[string]string{
	"matched.example.": "198.51.200.55",
	"direct.example.":  "93.184.216.34",
}

var (
	issue865MatchedIP = netip.MustParseAddr("198.51.200.55")
	issue865DirectIP  = netip.MustParseAddr("93.184.216.34")
)

// issue865AnswerHandler answers A queries from the table above.
func issue865AnswerHandler(t *testing.T, answers map[string]string) mdns.Handler {
	t.Helper()
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		if len(req.Question) != 1 {
			return
		}
		resp := new(mdns.Msg)
		resp.SetReply(req)
		name := strings.ToLower(req.Question[0].Name)
		if ip, ok := answers[name]; ok {
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 600},
				A:   net.ParseIP(ip).To4(),
			})
		}
		_ = w.WriteMsg(resp)
	})
}

// issue865DoHHandler serves the same answer table over the RFC 8484 path, and
// refuses anything that is not a DoH POST so a downgraded request is visible.
func issue865DoHHandler(t *testing.T, answers map[string]string) http.HandlerFunc {
	t.Helper()
	dnsHandler := issue865AnswerHandler(t, answers)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" {
			http.Error(w, "unexpected DoH request", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		req := new(mdns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		capture := &dohCaptureWriter{}
		dnsHandler.ServeDNS(capture, req)
		writeDoHMessage(w, capture.msg)
	}
}

// newIssue865InterceptedClient wires a real client stack to a gateway that runs the
// supplied resolver, and returns the client's query connection plus the session
// cache the answers are observed into.
func newIssue865InterceptedClient(t *testing.T, resolver Resolver) (net.Conn, *policy.SessionCache, *policy.Snapshot) {
	t.Helper()
	gwIP := netip.MustParseAddr("10.8.0.1")
	clientIP := netip.MustParseAddr("10.8.0.2")
	foreignResolver := netip.MustParseAddr("8.8.8.8")

	snap := compileTestSnapshot(t, "", "198.51.200.0/24")
	gw := newInterceptGateway(t, snap, resolver, gwIP)

	_, sess := setupTestSession(t, snap.Generation())
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(t.Context(), policy.Scope{SessionID: "sess-issue865", OwnershipEpoch: 1}, sess, writer)
	t.Cleanup(func() { gw.BeginRetire(scope) })

	client := newInterceptClient(t, gw, scope, clientIP)
	t.Cleanup(client.close)
	writer.onPacket = client.deliver

	conn, err := client.stack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(foreignResolver, 53))
	if err != nil {
		t.Fatalf("client failed to dial the foreign resolver: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, sess, snap
}

// assertAnswerIP asserts the client accepted exactly one answer and that it is the
// fixture's address: the reply is the one the gateway produced, not a placeholder.
func assertAnswerIP(t *testing.T, resp *mdns.Msg, want netip.Addr) {
	t.Helper()
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("client received rcode %s, want success", mdns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("client received %d answers, want 1", len(resp.Answer))
	}
	aRec, ok := resp.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("client answer is %T, want an A record", resp.Answer[0])
	}
	got, ok := netip.AddrFromSlice(aRec.A)
	if !ok || got != want {
		t.Fatalf("client answer address = %v, want %s", aRec.A, want)
	}
}

// assertServfailToClient asserts the encrypted upstream failure reached the client
// as a refusal rather than as an empty success.
func assertServfailToClient(t *testing.T, resp *mdns.Msg) {
	t.Helper()
	if resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("client received rcode %s, want SERVFAIL", mdns.RcodeToString[resp.Rcode])
	}
}

// assertNoEvidence asserts the client's session records nothing for the address.
// The observation runs after the resolver returns, so the window is bounded rather
// than instantaneous.
func assertNoEvidence(t *testing.T, sess *policy.SessionCache, generation string, ip netip.Addr) {
	t.Helper()
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sess.Lookup(ip, generation, time.Now()); got != policy.Unknown {
			t.Fatalf("a refused exchange produced evidence for %s: %v", ip, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestIssue865EncryptedConsumerDoTServesClientAndRecordsEvidence is the positive
// control for DNS over TLS: a client query is intercepted, resolved through the
// authenticated fixture, returned to the client, and observed as routing evidence.
func TestIssue865EncryptedConsumerDoTServesClientAndRecordsEvidence(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoTTestServer(t, certificate, issue865AnswerHandler(t, issue865Answers))
	entry := dotEntryOf(server.addr, "")

	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{entry},
		tlsRootCAs: ca.trustPool(),
	})
	conn, sess, snap := newIssue865InterceptedClient(t, resolver)

	assertAnswerIP(t, writeUDPQuery(t, conn, "matched.example.", 8651), issue865MatchedIP)
	assertAnswerIP(t, writeUDPQuery(t, conn, "direct.example.", 8652), issue865DirectIP)

	waitForDecision(t, sess, snap.Generation(), issue865MatchedIP, policy.Proxy)
	waitForDecision(t, sess, snap.Generation(), issue865DirectIP, policy.Direct)

	status := resolver.Status()
	if status.LastUpstream != entry.String() {
		t.Fatalf("resolver last upstream = %q, want the DoT entry %q", status.LastUpstream, entry.String())
	}
	if status.LastFailure != "" || status.LastFailureKind != "" {
		t.Fatalf("a successful encrypted exchange left a failure: %+v", status)
	}
	select {
	case <-server.sniSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("the DoT fixture saw no TLS handshake: the exchange did not use the encrypted transport")
	}
}

// TestIssue865EncryptedConsumerDoHServesClientAndRecordsEvidence is the DoH
// counterpart. It also asserts the fixture never saw a plaintext HTTP request on
// the encrypted port, so the answer cannot have come from a silent downgrade.
func TestIssue865EncryptedConsumerDoHServesClientAndRecordsEvidence(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoHTestServer(t, certificate, true, issue865DoHHandler(t, issue865Answers))
	entry := dohEntryOf(server.addr, "")

	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{entry},
		tlsRootCAs: ca.trustPool(),
	})
	conn, sess, snap := newIssue865InterceptedClient(t, resolver)

	assertAnswerIP(t, writeUDPQuery(t, conn, "matched.example.", 8653), issue865MatchedIP)
	assertAnswerIP(t, writeUDPQuery(t, conn, "direct.example.", 8654), issue865DirectIP)
	waitForDecision(t, sess, snap.Generation(), issue865MatchedIP, policy.Proxy)
	waitForDecision(t, sess, snap.Generation(), issue865DirectIP, policy.Direct)

	if got := server.plaintext.Load(); got != 0 {
		t.Fatalf("the DoH fixture received %d plaintext requests: the transport was downgraded", got)
	}
	seen := server.requests()
	if len(seen) == 0 {
		t.Fatal("the DoH fixture observed no request")
	}
	for _, req := range seen {
		if req.method != http.MethodPost || req.path != "/dns-query" {
			t.Fatalf("unexpected DoH request %s %s", req.method, req.path)
		}
		if req.contentType != dohMediaType {
			t.Fatalf("DoH request content type = %q, want %q", req.contentType, dohMediaType)
		}
	}
	if status := resolver.Status(); status.LastUpstream != entry.String() {
		t.Fatalf("resolver last upstream = %q, want the DoH entry %q", status.LastUpstream, entry.String())
	}
}

// TestIssue865EncryptedConsumerRefusesUntrustedCertificate proves the client-facing
// consequence of a certificate the resolver does not trust: SERVFAIL, no evidence,
// and a certificate failure recorded by the resolver. A resolver that skipped
// verification would answer here and record evidence.
func TestIssue865EncryptedConsumerRefusesUntrustedCertificate(t *testing.T) {
	fixtureCA := newDoTTestCA(t)
	certificate, _ := fixtureCA.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoTTestServer(t, certificate, issue865AnswerHandler(t, issue865Answers))

	untrustedCA := newDoTTestCA(t)
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{dotEntryOf(server.addr, "")},
		tlsRootCAs: untrustedCA.trustPool(),
	})
	conn, sess, snap := newIssue865InterceptedClient(t, resolver)

	assertServfailToClient(t, writeUDPQuery(t, conn, "direct.example.", 8655))
	assertNoEvidence(t, sess, snap.Generation(), issue865DirectIP)

	if status := resolver.Status(); status.LastFailureKind != FailureCertificate {
		t.Fatalf("resolver failure kind = %q, want %q", status.LastFailureKind, FailureCertificate)
	}
	if status := resolver.Status(); status.LastUpstream != "" {
		t.Fatalf("an untrusted certificate was reported as a serving upstream: %q", status.LastUpstream)
	}
}

// TestIssue865EncryptedConsumerRefusesPinMismatch is the pin control: the peer's
// chain verifies, the configured pin does not match its leaf key, and the answer is
// refused instead of accepted on the strength of the chain alone.
func TestIssue865EncryptedConsumerRefusesPinMismatch(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoTTestServer(t, certificate, issue865AnswerHandler(t, issue865Answers))

	// A pin computed over a different certificate's key, issued by the same CA so
	// only the pin can reject it.
	otherCertificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{dotEntryOf(server.addr, spkiPinOf(otherCertificate.Leaf))},
		tlsRootCAs: ca.trustPool(),
	})
	conn, sess, snap := newIssue865InterceptedClient(t, resolver)

	assertServfailToClient(t, writeUDPQuery(t, conn, "direct.example.", 8656))
	assertNoEvidence(t, sess, snap.Generation(), issue865DirectIP)

	if status := resolver.Status(); status.LastFailureKind != FailurePinMismatch {
		t.Fatalf("resolver failure kind = %q, want %q", status.LastFailureKind, FailurePinMismatch)
	}
}

// TestIssue865EncryptedConsumerFailsOverToSecondEncryptedEntry exercises the
// documented two-entry dial order: the first encrypted entry cannot complete a TLS
// handshake, so the second serves the query. The client still receives the real
// answer, evidence is recorded once, and the resolver reports the entry that
// actually served it.
func TestIssue865EncryptedConsumerFailsOverToSecondEncryptedEntry(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	healthy := startDoTTestServer(t, certificate, issue865AnswerHandler(t, issue865Answers))

	primary := dotEntryOf(startBrokenTLSListener(t), "")
	alternate := dotEntryOf(healthy.addr, "")
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{primary, alternate},
		tlsRootCAs: ca.trustPool(),
	})
	conn, sess, snap := newIssue865InterceptedClient(t, resolver)

	assertAnswerIP(t, writeUDPQuery(t, conn, "direct.example.", 8657), issue865DirectIP)
	waitForDecision(t, sess, snap.Generation(), issue865DirectIP, policy.Direct)

	status := resolver.Status()
	if status.LastUpstream != alternate.String() {
		t.Fatalf("resolver last upstream = %q, want the alternate %q", status.LastUpstream, alternate.String())
	}
	if status.LastFailureKind != "" {
		t.Fatalf("a served answer kept the earlier failure kind: %q", status.LastFailureKind)
	}
}

// TestIssue865EncryptedConsumerFailsClosedWithoutUsableUpstream is the unavailable
// control: nothing listens on the configured encrypted entry, so the client gets a
// refusal and no evidence is invented from it.
func TestIssue865EncryptedConsumerFailsClosedWithoutUsableUpstream(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve an unused port: %v", err)
	}
	addr := netip.MustParseAddrPort(listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}

	ca := newDoTTestCA(t)
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:      []policy.Upstream{dotEntryOf(addr, "")},
		tlsRootCAs:     ca.trustPool(),
		AttemptTimeout: 300 * time.Millisecond,
	})
	conn, sess, snap := newIssue865InterceptedClient(t, resolver)

	assertServfailToClient(t, writeUDPQuery(t, conn, "matched.example.", 8658))
	assertNoEvidence(t, sess, snap.Generation(), issue865MatchedIP)
	assertNoEvidence(t, sess, snap.Generation(), issue865DirectIP)

	status := resolver.Status()
	if status.LastFailure == "" || status.LastFailureKind == "" {
		t.Fatalf("an unavailable encrypted upstream left no failure record: %+v", status)
	}
	if status.LastUpstream != "" {
		t.Fatalf("an unavailable upstream was reported as serving: %q", status.LastUpstream)
	}
	// The failure-kind contract names a refused connection as a handshake failure
	// ("a refused connection, a peer that does not speak TLS"), while a dial error
	// surfaced before the handshake is a network failure; either is correct for a
	// closed port and what matters here is that the kind is from the closed set and
	// the exchange did not succeed.
	switch status.LastFailureKind {
	case FailureTLSHandshake, FailureNetwork, FailureTimeout:
	default:
		t.Fatalf("unexpected failure kind for a closed port: %q", status.LastFailureKind)
	}
}
