package gatewaydns

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestResolver_DoHSuccess is the positive path and the wire contract: one HTTP/2
// POST of a DNS message with ID 0 to /dns-query, the DoH media type in both
// directions, and the client's own ID restored on the answer.
func TestResolver_DoHSuccess(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.90"))

	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{dohEntryOf(server.addr, "")},
		tlsRootCAs: ca.trustPool(),
	})

	req := testQuery("doh.example.")
	req.Id = 31337
	resp, err := resolver.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange over DoH failed: %v", err)
	}
	if resp.Id != 31337 {
		t.Fatalf("response id = %d, want the client's 31337", resp.Id)
	}
	if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.90" {
		t.Fatalf("answer = %v, want 203.0.113.90", resp.Answer[0])
	}

	seen := server.requests()
	if len(seen) != 1 {
		t.Fatalf("server saw %d requests, want exactly 1", len(seen))
	}
	assertDoHWireRequest(t, seen[0])

	status := resolver.Status()
	if want := "doh://" + server.addr.String(); status.LastUpstream != want {
		t.Fatalf("last upstream = %q, want %q", status.LastUpstream, want)
	}
	if status.LastFailure != "" || status.LastFailureKind != "" {
		t.Fatalf("a successful DoH exchange reported a failure: %+v", status)
	}
}

// assertDoHWireRequest checks the RFC 8484 request the server received.
func assertDoHWireRequest(t *testing.T, got dohSeenRequest) {
	t.Helper()
	if got.method != http.MethodPost || got.path != "/dns-query" || got.rawQuery != "" {
		t.Fatalf("request = %s %s?%s, want POST /dns-query with no query string", got.method, got.path, got.rawQuery)
	}
	if got.proto != "HTTP/2.0" {
		t.Fatalf("request protocol = %q, want HTTP/2.0", got.proto)
	}
	if got.contentType != dohMediaType || got.accept != dohMediaType {
		t.Fatalf("content-type %q accept %q, want %q for both", got.contentType, got.accept, dohMediaType)
	}
	wire := new(mdns.Msg)
	if err := wire.Unpack(got.body); err != nil {
		t.Fatalf("request body is not a DNS message: %v", err)
	}
	if wire.Id != 0 {
		t.Fatalf("DNS id on the wire = %d, want 0 (RFC 8484 section 4.1)", wire.Id)
	}
	if len(wire.Question) != 1 || wire.Question[0].Name != "doh.example." {
		t.Fatalf("question on the wire = %v, want doh.example.", wire.Question)
	}
}

// TestResolver_DoHHostnameVerification proves the name rules per address shape,
// the same as DoT: a hostname entry sends SNI and Host for that name, an IP
// literal sends no SNI and is verified against an IP SAN.
func TestResolver_DoHHostnameVerification(t *testing.T) {
	t.Run("hostname entry sends SNI and Host and verifies the name", func(t *testing.T) {
		ca := newDoTTestCA(t)
		certificate, _ := ca.issue(t, dotLeafOptions{dnsNames: []string{"resolver.test"}})
		server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.91"))

		entry := policy.Upstream{Address: "resolver.test", Port: int(server.addr.Port()), Transport: policy.TransportDoH}
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
			t.Fatalf("Exchange with a hostname DoH entry failed: %v", err)
		}
		if dialedAddress != entry.HostPort() {
			t.Fatalf("dial address = %q, want the entry's %q", dialedAddress, entry.HostPort())
		}
		seen := server.requests()
		if len(seen) != 1 || seen[0].sni != "resolver.test" || seen[0].host != entry.HostPort() {
			t.Fatalf("server saw %+v, want one request with SNI resolver.test and Host %s", seen, entry.HostPort())
		}
	})

	t.Run("ip literal sends no SNI and verifies an ip san", func(t *testing.T) {
		ca := newDoTTestCA(t)
		certificate, _ := ca.issue(t, dotLeafOptions{
			dnsNames: []string{"other.test"},
			ips:      []net.IP{net.ParseIP("127.0.0.1")},
		})
		server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.92"))
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{dohEntryOf(server.addr, "")},
			tlsRootCAs: ca.trustPool(),
		})
		if _, err := resolver.Exchange(context.Background(), testQuery("ip-san.example.")); err != nil {
			t.Fatalf("Exchange verified by IP SAN failed: %v", err)
		}
		if seen := server.requests(); len(seen) != 1 || seen[0].sni != "" {
			t.Fatalf("server saw %+v, want one request and no SNI for an IP literal", seen)
		}
	})
}

// assertDoHFailure requires the exchange to fail with the expected kind, return
// no answer, name the failing entry and leave no plaintext connection behind.
func assertDoHFailure(t *testing.T, resolver *UpstreamResolver, entry policy.Upstream, want FailureKind) {
	t.Helper()
	resp, err := resolver.Exchange(context.Background(), testQuery("rejected.example."))
	if err == nil || resp != nil {
		t.Fatalf("Exchange() = (%v, %v), want a failure and no answer for %s", resp, err, entry.String())
	}
	status := resolver.Status()
	if status.LastFailureKind != want {
		t.Fatalf("failure kind = %q, want %q (cause: %v)", status.LastFailureKind, want, err)
	}
	if status.LastFailure != entry.String() || status.LastUpstream != "" {
		t.Fatalf("status = %+v, want failing upstream %q and no last upstream", status, entry.String())
	}
}

// TestResolver_DoHCertificateRejections covers the verification failures an
// operator can hit. Each is a certificate failure, never a timeout, a plaintext
// retry or an answer, and the HTTP handler is never reached.
func TestResolver_DoHCertificateRejections(t *testing.T) {
	cases := []struct {
		name  string
		leaf  func(*dotTestCA) dotLeafOptions
		trust func(*dotTestCA) *x509.CertPool
		host  string
	}{
		{"name mismatch", func(*dotTestCA) dotLeafOptions { return dotLeafOptions{dnsNames: []string{"other.test"}} },
			func(ca *dotTestCA) *x509.CertPool { return ca.trustPool() }, "resolver.test"},
		{"expired certificate", func(*dotTestCA) dotLeafOptions {
			return dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour)}
		}, func(ca *dotTestCA) *x509.CertPool { return ca.trustPool() }, ""},
		{"untrusted chain", func(*dotTestCA) dotLeafOptions { return dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}} },
			func(*dotTestCA) *x509.CertPool { return newDoTTestCA(t).trustPool() }, ""},
		{"ip literal without a matching san", func(*dotTestCA) dotLeafOptions { return dotLeafOptions{dnsNames: []string{"127.0.0.1"}} },
			func(ca *dotTestCA) *x509.CertPool { return ca.trustPool() }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newDoTTestCA(t)
			certificate, _ := ca.issue(t, tc.leaf(ca))
			server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.93"))
			entry := dohEntryOf(server.addr, "")
			cfg := ResolverConfig{Upstreams: []policy.Upstream{entry}, tlsRootCAs: tc.trust(ca)}
			if tc.host != "" {
				entry.Address = tc.host
				cfg.Upstreams = []policy.Upstream{entry}
				cfg.dotDial = func(ctx context.Context, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "tcp", server.addr.String())
				}
			}
			assertDoHFailure(t, mustLoopbackResolver(t, cfg), entry, FailureCertificate)
			if got := len(server.requests()); got != 0 {
				t.Fatalf("the handler ran %d times for a rejected certificate", got)
			}
		})
	}
}

// TestResolver_DoHPin covers the optional key pin: the configured leaf key is
// accepted, any other key is a pin_mismatch even though the chain is valid, and
// the request is never sent over a connection whose key failed the pin.
func TestResolver_DoHPin(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, leaf := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	_, otherLeaf := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})

	t.Run("matching pin answers", func(t *testing.T) {
		server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.94"))
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{dohEntryOf(server.addr, spkiPinOf(leaf))},
			tlsRootCAs: ca.trustPool(),
		})
		if _, err := resolver.Exchange(context.Background(), testQuery("pin.example.")); err != nil {
			t.Fatalf("Exchange with a matching pin failed: %v", err)
		}
	})

	t.Run("other key is a pin mismatch and sends nothing", func(t *testing.T) {
		server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.95"))
		entry := dohEntryOf(server.addr, spkiPinOf(otherLeaf))
		resolver := mustLoopbackResolver(t, ResolverConfig{
			Upstreams:  []policy.Upstream{entry},
			tlsRootCAs: ca.trustPool(),
		})
		assertDoHFailure(t, resolver, entry, FailurePinMismatch)
		if got := len(server.requests()); got != 0 {
			t.Fatalf("the server received %d request(s) over a connection that failed the pin", got)
		}
	})
}

// TestResolver_DoHRequiresHTTP2 proves a peer that negotiates only HTTP/1.1 is
// refused as a handshake failure instead of being spoken to in a weaker protocol.
func TestResolver_DoHRequiresHTTP2(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{ips: []net.IP{net.ParseIP("127.0.0.1")}})
	server := startDoHTestServer(t, certificate, false, dohAnswerHandler(t, "203.0.113.96"))
	entry := dohEntryOf(server.addr, "")
	resolver := mustLoopbackResolver(t, ResolverConfig{Upstreams: []policy.Upstream{entry}, tlsRootCAs: ca.trustPool()})
	assertDoHFailure(t, resolver, entry, FailureTLSHandshake)
	if got := len(server.requests()); got != 0 {
		t.Fatalf("an HTTP/1.1-only peer received %d request(s)", got)
	}
}

// TestDoHURLForAcceptedEndpointForms pins the one URL the resolver can build for
// each accepted entry shape: always https, the entry's own host and port, the
// fixed well-known path, and brackets for an IPv6 literal.
func TestDoHURLForAcceptedEndpointForms(t *testing.T) {
	tests := []struct {
		name  string
		entry policy.Upstream
		want  string
	}{
		{"hostname with default port", policy.Upstream{Address: "dns.example.com", Transport: policy.TransportDoH}, "https://dns.example.com:443/dns-query"},
		{"hostname with explicit port", policy.Upstream{Address: "dns.example.com", Port: 8443, Transport: policy.TransportDoH}, "https://dns.example.com:8443/dns-query"},
		{"hostname with trailing dot", policy.Upstream{Address: "dns.example.com.", Transport: policy.TransportDoH}, "https://dns.example.com:443/dns-query"},
		{"ipv4 literal", policy.Upstream{Address: "94.140.14.14", Transport: policy.TransportDoH}, "https://94.140.14.14:443/dns-query"},
		{"ipv6 literal", policy.Upstream{Address: "2a10:50c0::ad1:ff", Transport: policy.TransportDoH}, "https://[2a10:50c0::ad1:ff]:443/dns-query"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.entry.Validate(); err != nil {
				t.Fatalf("Validate(%+v) = %v, want the form accepted", tc.entry, err)
			}
			if got := dohURL(tc.entry); got != tc.want {
				t.Fatalf("dohURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDoHTransportFailsClosed asserts the structure the DoH transport relies on
// for its no-plaintext guarantee, directly: it has no proxy function, and its
// plaintext dial hook refuses to connect. An https URL never reaches that hook,
// so only a direct call proves it would fail closed if a request ever lost TLS.
func TestDoHTransportFailsClosed(t *testing.T) {
	resolver := mustLoopbackResolver(t, ResolverConfig{Upstreams: []policy.Upstream{{Address: "dns.example.com", Transport: policy.TransportDoH}}})
	transport := resolver.dohTransport(context.Background(), policy.Upstream{Address: "dns.example.com", Transport: policy.TransportDoH}, nil)
	if transport.Proxy != nil {
		t.Fatal("the DoH transport has a proxy function; the environment could redirect the query")
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "dns.example.com:80")
	if conn != nil || !errors.Is(err, errDoHPlaintextForbidden) {
		t.Fatalf("DialContext() = (%v, %v), want no connection and errDoHPlaintextForbidden", conn, err)
	}
}
