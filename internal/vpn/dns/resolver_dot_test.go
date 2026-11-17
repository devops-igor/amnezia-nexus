package gatewaydns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestResolver_DoTSuccess is the positive path: a query answered over TLS by a
// server whose chain and IP SAN verify against the trusted fixture CA.
func TestResolver_DoTSuccess(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.70"))

	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{dotEntryOf(server.addr, "")},
		tlsRootCAs: ca.trustPool(),
	})

	req := testQuery("dot.example.")
	req.Id = 31337
	resp, err := resolver.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange over DoT failed: %v", err)
	}
	if resp.Id != 31337 {
		t.Fatalf("response id = %d, want the client's 31337", resp.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.70" {
		t.Fatalf("answer = %v, want 203.0.113.70", resp.Answer[0])
	}

	status := resolver.Status()
	if status.LastUpstream != "dot://"+server.addr.String() {
		t.Fatalf("last upstream = %q, want %q", status.LastUpstream, "dot://"+server.addr.String())
	}
	if status.LastFailure != "" || status.LastFailureKind != "" {
		t.Fatalf("a successful DoT exchange reported a failure: %+v", status)
	}
}

// TestResolver_DoTHostnameVerification proves the name rules per address shape:
// a hostname entry sends SNI and is verified as a name, an IP literal sends no
// SNI and is verified against an IP SAN.
func TestResolver_DoTHostnameVerification(t *testing.T) {
	t.Run("hostname entry sends SNI and verifies the name", func(t *testing.T) {
		ca := newDoTTestCA(t)
		certificate, _ := ca.issue(t, dotLeafOptions{dnsNames: []string{"resolver.test"}})
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.71"))

		entry := policy.Upstream{Address: "resolver.test", Port: int(server.addr.Port()), Transport: policy.TransportDoT}
		var dialedAddress string
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: ca.trustPool(),
			dotDial: func(ctx context.Context, address string) (net.Conn, error) {
				dialedAddress = address
				var dialer net.Dialer
				return dialer.DialContext(ctx, "tcp", server.addr.String())
			},
		})

		if _, err := resolver.Exchange(context.Background(), testQuery("sni.example.")); err != nil {
			t.Fatalf("Exchange with a hostname DoT entry failed: %v", err)
		}
		if dialedAddress != entry.HostPort() {
			t.Fatalf("dial address = %q, want the entry's %q", dialedAddress, entry.HostPort())
		}
		select {
		case sni := <-server.sniSeen:
			if sni != "resolver.test" {
				t.Fatalf("SNI = %q, want %q", sni, "resolver.test")
			}
		default:
			t.Fatal("the server never saw a client hello")
		}
	})

	t.Run("ip literal sends no SNI and verifies an ip san", func(t *testing.T) {
		ca := newDoTTestCA(t)
		// The DNS name deliberately does not match; only the IP SAN does.
		certificate, _ := ca.issue(t, dotLeafOptions{
			dnsNames: []string{"other.test"},
			ips:      []net.IP{net.ParseIP("127.0.0.1")},
		})
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.72"))

		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{dotEntryOf(server.addr, "")},
			tlsRootCAs: ca.trustPool(),
		})
		if _, err := resolver.Exchange(context.Background(), testQuery("ip-san.example.")); err != nil {
			t.Fatalf("Exchange verified by IP SAN failed: %v", err)
		}
		select {
		case sni := <-server.sniSeen:
			if sni != "" {
				t.Fatalf("SNI for an IP literal = %q, want none", sni)
			}
		default:
			t.Fatal("the server never saw a client hello")
		}
	})
}

// TestResolver_DoTCertificateRejections covers the three verification failures
// an operator can hit, each reported as a certificate failure rather than a
// timeout or a plaintext retry.
func TestResolver_DoTCertificateRejections(t *testing.T) {
	t.Run("name mismatch", func(t *testing.T) {
		ca := newDoTTestCA(t)
		certificate, _ := ca.issue(t, dotLeafOptions{dnsNames: []string{"other.test"}})
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.73"))

		entry := policy.Upstream{Address: "resolver.test", Port: int(server.addr.Port()), Transport: policy.TransportDoT}
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: ca.trustPool(),
			dotDial: func(ctx context.Context, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "tcp", server.addr.String())
			},
		})
		assertDoTFailure(t, resolver, entry, FailureCertificate)
	})

	t.Run("expired certificate", func(t *testing.T) {
		ca := newDoTTestCA(t)
		certificate, _ := ca.issue(t, dotLeafOptions{
			ips:       []net.IP{net.ParseIP("127.0.0.1")},
			notBefore: time.Now().Add(-48 * time.Hour),
			notAfter:  time.Now().Add(-24 * time.Hour),
		})
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.74"))

		entry := dotEntryOf(server.addr, "")
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: ca.trustPool(),
		})
		assertDoTFailure(t, resolver, entry, FailureCertificate)
	})

	t.Run("untrusted chain", func(t *testing.T) {
		serverCA := newDoTTestCA(t)
		certificate, _ := serverCA.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.75"))

		// The resolver trusts a different CA, and its pool replaces the system
		// store, so this chain can never verify.
		otherCA := newDoTTestCA(t)
		entry := dotEntryOf(server.addr, "")
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: otherCA.trustPool(),
		})
		assertDoTFailure(t, resolver, entry, FailureCertificate)
	})

	t.Run("ip literal without a matching san", func(t *testing.T) {
		ca := newDoTTestCA(t)
		// A DNS SAN for an unrelated name must not satisfy an IP-literal entry:
		// verification is performed, not skipped.
		certificate, _ := ca.issue(t, dotLeafOptions{dnsNames: []string{"127.0.0.1"}})
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.76"))

		entry := dotEntryOf(server.addr, "")
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: ca.trustPool(),
		})
		assertDoTFailure(t, resolver, entry, FailureCertificate)
	})
}

// assertDoTFailure requires the exchange to fail with the expected kind, return
// no answer and name the failing entry in the status.
func assertDoTFailure(t *testing.T, resolver *UpstreamResolver, entry policy.Upstream, want FailureKind) {
	t.Helper()
	resp, err := resolver.Exchange(context.Background(), testQuery("rejected.example."))
	if err == nil {
		t.Fatalf("Exchange() = (%v, nil), want a failure for %s", resp, entry.String())
	}
	if resp != nil {
		t.Fatalf("Exchange() returned an answer (%v) for a failed DoT attempt", resp)
	}
	status := resolver.Status()
	if status.LastFailureKind != want {
		t.Fatalf("failure kind = %q, want %q (cause: %v)", status.LastFailureKind, want, err)
	}
	if status.LastFailure != entry.String() {
		t.Fatalf("failing upstream = %q, want %q", status.LastFailure, entry.String())
	}
	if status.LastUpstream != "" {
		t.Fatalf("last upstream = %q, want empty after only failures", status.LastUpstream)
	}
}

// TestResolver_DoTPin covers the optional key pin: it accepts the configured
// leaf key and rejects any other key even when the chain itself is valid.
func TestResolver_DoTPin(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, leaf := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	otherCertificate, otherLeaf := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	if spkiPinOf(leaf) == spkiPinOf(otherLeaf) {
		t.Fatal("fixture leaves share an SPKI digest")
	}

	t.Run("matching pin accepted", func(t *testing.T) {
		server := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.77"))
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{dotEntryOf(server.addr, spkiPinOf(leaf))},
			tlsRootCAs: ca.trustPool(),
		})
		resp, err := resolver.Exchange(context.Background(), testQuery("pinned.example."))
		if err != nil {
			t.Fatalf("Exchange with a matching pin failed: %v", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("answers = %d, want 1", len(resp.Answer))
		}
	})

	t.Run("mismatched pin rejected despite a valid chain", func(t *testing.T) {
		server := startDoTTestServer(t, otherCertificate, answerHandler(t, "203.0.113.78"))
		entry := dotEntryOf(server.addr, spkiPinOf(leaf))
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: ca.trustPool(),
		})
		assertDoTFailure(t, resolver, entry, FailurePinMismatch)
	})
}

// TestResolver_DoTHandshakeFailureKinds separates a handshake failure from a
// timeout: a peer that answers with non-TLS bytes fails the handshake, and a peer
// that accepts TCP and stalls is reported as a timeout inside the attempt budget.
func TestResolver_DoTHandshakeFailureKinds(t *testing.T) {
	t.Run("non-tls peer is a handshake failure", func(t *testing.T) {
		addr := startBrokenTLSListener(t)
		entry := dotEntryOf(addr, "")
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:      []policy.Upstream{entry},
			AttemptTimeout: 2 * time.Second,
			tlsRootCAs:     x509.NewCertPool(),
		})
		assertDoTFailure(t, resolver, entry, FailureTLSHandshake)
	})

	t.Run("stalled peer is a timeout inside the attempt budget", func(t *testing.T) {
		addr := startStalledTLSListener(t)
		entry := dotEntryOf(addr, "")
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:      []policy.Upstream{entry},
			QueryTimeout:   3 * time.Second,
			AttemptTimeout: 80 * time.Millisecond,
			tlsRootCAs:     x509.NewCertPool(),
		})

		start := time.Now()
		assertDoTFailure(t, resolver, entry, FailureTimeout)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("a stalled handshake took %v, longer than the attempt budget allows", elapsed)
		}
	})
}

// TestResolver_DoTNoPlaintextDowngrade is the security oracle: a failing DoT
// entry must not produce a plaintext query. A plaintext responder shares the DoT
// entry's port, so any UDP query it receives proves a downgrade; the responder
// answers, which is what makes a downgrading implementation look "successful".
func TestResolver_DoTNoPlaintextDowngrade(t *testing.T) {
	resolverCA := newDoTTestCA(t)
	serverCA := newDoTTestCA(t)
	certificate, _ := serverCA.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})

	pair := newLoopbackPortPair(t)
	addr := pair.addr()
	listener := tls.NewListener(pair.tcp, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	server := &mdns.Server{Listener: listener, Handler: answerHandler(t, "203.0.113.79")}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	plaintextHits := startPlaintextResponder(t, pair.udp, "203.0.113.80")

	entry := dotEntryOf(addr, "")
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:      []policy.Upstream{entry},
		AttemptTimeout: 2 * time.Second,
		tlsRootCAs:     resolverCA.trustPool(),
	})

	resp, err := resolver.Exchange(context.Background(), testQuery("no-downgrade.example."))
	if hits := plaintextHits.Load(); hits != 0 {
		t.Fatalf("a DoT entry sent %d plaintext quer(y/ies) to %s after the TLS failure", hits, addr)
	}
	if err == nil {
		t.Fatalf("Exchange() = (%v, nil), want a certificate failure and no answer", resp)
	}
	if resp != nil {
		t.Fatalf("Exchange() returned an answer (%v), want none for a failed DoT entry", resp)
	}
	if got := resolver.Status().LastFailureKind; got != FailureCertificate {
		t.Fatalf("failure kind = %q, want %q (cause: %v)", got, FailureCertificate, err)
	}
}

// TestResolver_DoTFailoverKeepsTransports proves failover moves to the next
// configured entry and nothing else: a DoT primary hands over to a DoT alternate
// or to an explicitly plain one, and never sends its own query in plaintext.
func TestResolver_DoTFailoverKeepsTransports(t *testing.T) {
	ca := newDoTTestCA(t)
	pair := newLoopbackPortPair(t)
	broken := startBrokenTLSListenerOn(t, pair.tcp)

	t.Run("encrypted alternate answers", func(t *testing.T) {
		certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
		alternate := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.81"))

		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{dotEntryOf(broken, ""), dotEntryOf(alternate.addr, "")},
			tlsRootCAs: ca.trustPool(),
		})
		resp, err := resolver.Exchange(context.Background(), testQuery("dot-alternate.example."))
		if err != nil {
			t.Fatalf("Exchange failed over to the DoT alternate: %v", err)
		}
		if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.81" {
			t.Fatalf("answer = %v, want the alternate's 203.0.113.81", resp.Answer[0])
		}
		if got := resolver.Status().LastUpstream; got != "dot://"+alternate.addr.String() {
			t.Fatalf("last upstream = %q, want the DoT alternate %q", got, "dot://"+alternate.addr.String())
		}
	})

	t.Run("explicitly plain alternate answers and the dot entry stays plaintext-free", func(t *testing.T) {
		plaintextHits := startPlaintextResponder(t, pair.udp, "203.0.113.82")
		plainAlternate := startMockServer(t, answerHandler(t, "203.0.113.83"))

		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{dotEntryOf(broken, ""), upstreamOf(plainAlternate.udpAddr)},
			tlsRootCAs: ca.trustPool(),
		})
		resp, err := resolver.Exchange(context.Background(), testQuery("plain-alternate.example."))
		if err != nil {
			t.Fatalf("Exchange failed over to the plain alternate: %v", err)
		}
		if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.83" {
			t.Fatalf("answer = %v, want the plain alternate's 203.0.113.83", resp.Answer[0])
		}
		if hits := plaintextHits.Load(); hits != 0 {
			t.Fatalf("the failing DoT entry sent %d plaintext quer(y/ies) before the alternate answered", hits)
		}
		if got := resolver.Status().LastUpstream; got != plainAlternate.udpAddr.String() {
			t.Fatalf("last upstream = %q, want the plain alternate %q", got, plainAlternate.udpAddr.String())
		}
	})
}

// TestResolver_SetUpstreamsSwapsDoTList is the live-apply contract for DoT: a
// changed list takes effect without rebuilding the resolver, and a refused update
// leaves the previous list installed.
func TestResolver_SetUpstreamsSwapsDoTList(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	first := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.84"))
	second := startDoTTestServer(t, certificate, answerHandler(t, "203.0.113.85"))

	firstEntry := dotEntryOf(first.addr, "")
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{firstEntry},
		tlsRootCAs: ca.trustPool(),
	})

	if _, err := resolver.Exchange(context.Background(), testQuery("before-swap.example.")); err != nil {
		t.Fatalf("Exchange before the swap failed: %v", err)
	}

	secondEntry := dotEntryOf(second.addr, "")
	if err := resolver.SetUpstreams([]policy.Upstream{secondEntry}); err != nil {
		t.Fatalf("SetUpstreams(DoT) = %v, want nil", err)
	}
	resp, err := resolver.Exchange(context.Background(), testQuery("after-swap.example."))
	if err != nil {
		t.Fatalf("Exchange after the DoT swap failed: %v", err)
	}
	if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.85" {
		t.Fatalf("answer after the swap = %v, want the new upstream's 203.0.113.85", resp.Answer[0])
	}

	// A refused update keeps the accepted list, including its transport.
	if err := resolver.SetUpstreams([]policy.Upstream{{Address: "dns.example.com", Port: 443, Transport: "quic"}}); !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatalf("SetUpstreams(quic) = %v, want ErrUnsupportedTransport", err)
	}
	upstreams := resolver.Upstreams()
	if len(upstreams) != 1 || upstreams[0] != secondEntry {
		t.Fatalf("upstreams after a refused update = %v, want the previous %v", upstreams, secondEntry)
	}
	if _, err := resolver.Exchange(context.Background(), testQuery("still-dot.example.")); err != nil {
		t.Fatalf("Exchange after a refused update failed: %v", err)
	}
}
