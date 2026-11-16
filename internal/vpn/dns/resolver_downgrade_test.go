package gatewaydns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This file is the no-downgrade oracle for BOTH encrypted transports. The
// original DoT oracle watched one channel: a plaintext UDP responder on the
// entry's port. A DoH downgrade does not have to look like that. It can be an
// http:// request over TCP, a followed redirect to an http:// URL, or a
// port-53 style retry, so the oracle watches every channel a plaintext query
// could use, for every way an encrypted exchange can fail:
//
//   - udp: a plaintext DNS responder bound to the entry's own port number
//   - tcp: a first byte that is not a TLS handshake record on the entry's port
//   - http: a plain-HTTP server that a redirect or fallback could be steered to
//
// Every scenario must end in the expected failure kind with no answer and zero
// observations on every channel. The responders answer, which is what makes a
// downgrading implementation look "successful" instead of merely failing.

// downgradeSettle is how long the oracle waits after an exchange before reading
// the plaintext counters. Loopback delivery is microseconds; this is a ceiling
// for a loaded CI machine, not a tuned value.
const downgradeSettle = 250 * time.Millisecond

// downgradeScenario is one failing encrypted entry plus the evidence collectors
// that would show a plaintext query.
type downgradeScenario struct {
	entry    policy.Upstream
	roots    *x509.CertPool
	want     FailureKind
	attempt  time.Duration
	udpHits  *atomic.Int32
	tcpPlain *atomic.Int32
	httpHits *atomic.Int32
}

// startSniffedDoTServer serves DoT behind a listener that counts connections
// whose first byte is not a TLS record.
func startSniffedDoTServer(t *testing.T, certificate tls.Certificate) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DoT: %v", err)
	}
	plain := &atomic.Int32{}
	listener := tls.NewListener(&sniffListener{Listener: raw, plaintext: plain}, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	server := &mdns.Server{Listener: listener, Handler: answerHandler(t, "203.0.113.110")}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return netip.MustParseAddrPort(raw.Addr().String()), plain
}

// startPlainHTTPTarget is an http:// server that answers any request with a
// valid DNS message, and counts every request it receives.
func startPlainHTTPTarget(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	answer := dohAnswerHandler(t, "203.0.113.111")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		answer(w, r)
	}))
	t.Cleanup(server.Close)
	return server, hits
}

// assertNoPlaintextAfterFailure runs one exchange for a failing encrypted entry
// and requires the expected failure, no answer and zero plaintext observations
// on every channel the scenario watches. The channels are checked first, so a
// downgrade that happens to end in an answer is reported as a downgrade.
func assertNoPlaintextAfterFailure(t *testing.T, sc downgradeScenario) {
	t.Helper()
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:      []policy.Upstream{sc.entry},
		AttemptTimeout: sc.attempt,
		tlsRootCAs:     sc.roots,
	})
	resp, err := resolver.Exchange(context.Background(), testQuery("no-downgrade.example."))

	// A downgrade does not have to wait for a reply, so Exchange returning proves
	// nothing about bytes already on the wire. Give the listeners a bounded moment
	// to read what was sent before the counters are judged; without it a plaintext
	// write that races the return is missed.
	time.Sleep(downgradeSettle)

	channels := []struct {
		name string
		hits *atomic.Int32
	}{{"udp", sc.udpHits}, {"tcp", sc.tcpPlain}, {"http", sc.httpHits}}
	for _, channel := range channels {
		if channel.hits != nil && channel.hits.Load() != 0 {
			t.Errorf("%s entry sent %d plaintext %s quer(y/ies) after the encrypted attempt failed",
				sc.entry.EffectiveTransport(), channel.hits.Load(), channel.name)
		}
	}
	if err == nil || resp != nil {
		t.Fatalf("Exchange() = (%v, %v), want a failure and no answer for %s", resp, err, sc.entry.String())
	}
	if got := resolver.Status().LastFailureKind; got != sc.want {
		t.Fatalf("failure kind = %q, want %q (cause: %v)", got, sc.want, err)
	}
}

func loopbackIPs() []net.IP { return []net.IP{net.ParseIP("127.0.0.1")} }

// TestResolver_DoHNoPlaintextDowngrade is the DoH half of the oracle. Every
// scenario is a way a DoH exchange can fail; none may produce plaintext on the
// entry's port (UDP or TCP) or reach the plain-HTTP target a redirect points at.
func TestResolver_DoHNoPlaintextDowngrade(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, leaf := ca.issue(t, dotLeafOptions{ips: loopbackIPs()})
	_, otherLeaf := ca.issue(t, dotLeafOptions{ips: loopbackIPs()})

	// start serves DoH with the given handler and attaches a plaintext UDP
	// responder to the same port number, the way the DoT oracle always has.
	start := func(t *testing.T, cert tls.Certificate, h2 bool, handler http.HandlerFunc) (*dohTestServer, *atomic.Int32) {
		server := startDoHTestServer(t, cert, h2, handler)
		return server, startPlaintextResponder(t, server.addr, "203.0.113.112")
	}

	scenarios := []struct {
		name string
		want FailureKind
		run  func(t *testing.T) downgradeScenario
	}{
		{"untrusted chain", FailureCertificate, func(t *testing.T) downgradeScenario {
			server, udp := start(t, certificate, true, dohAnswerHandler(t, "203.0.113.113"))
			return downgradeScenario{entry: dohEntryOf(server.addr, ""), roots: newDoTTestCA(t).trustPool(), udpHits: udp, tcpPlain: server.plaintext}
		}},
		{"pin mismatch", FailurePinMismatch, func(t *testing.T) downgradeScenario {
			server, udp := start(t, certificate, true, dohAnswerHandler(t, "203.0.113.114"))
			return downgradeScenario{entry: dohEntryOf(server.addr, spkiPinOf(otherLeaf)), roots: ca.trustPool(), udpHits: udp, tcpPlain: server.plaintext}
		}},
		{"http/1.1-only peer", FailureTLSHandshake, func(t *testing.T) downgradeScenario {
			server, udp := start(t, certificate, false, dohAnswerHandler(t, "203.0.113.115"))
			return downgradeScenario{entry: dohEntryOf(server.addr, ""), roots: ca.trustPool(), udpHits: udp, tcpPlain: server.plaintext}
		}},
		{"redirect to a plain http url", FailureRedirect, func(t *testing.T) downgradeScenario {
			plainTarget, httpHits := startPlainHTTPTarget(t)
			server, udp := start(t, certificate, true, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, plainTarget.URL+"/dns-query", http.StatusTemporaryRedirect)
			})
			return downgradeScenario{entry: dohEntryOf(server.addr, spkiPinOf(leaf)), roots: ca.trustPool(), udpHits: udp, tcpPlain: server.plaintext, httpHits: httpHits}
		}},
		{"server error status", FailureHTTPStatus, func(t *testing.T) downgradeScenario {
			server, udp := start(t, certificate, true, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
			return downgradeScenario{entry: dohEntryOf(server.addr, ""), roots: ca.trustPool(), udpHits: udp, tcpPlain: server.plaintext}
		}},
		{"stalled after the handshake", FailureTimeout, func(t *testing.T) downgradeScenario {
			server, udp := start(t, certificate, true, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
			return downgradeScenario{entry: dohEntryOf(server.addr, ""), roots: ca.trustPool(), udpHits: udp, tcpPlain: server.plaintext, attempt: 400 * time.Millisecond}
		}},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			sc := scenario.run(t)
			sc.want = scenario.want
			if sc.attempt == 0 {
				sc.attempt = 2 * time.Second
			}
			assertNoPlaintextAfterFailure(t, sc)
		})
	}
}

// TestResolver_DoTNoPlaintextDowngradeAllChannels extends the DoT oracle past the
// single UDP channel it watched before: a DoT entry that fails must also leave
// no plaintext TCP connection on its port.
func TestResolver_DoTNoPlaintextDowngradeAllChannels(t *testing.T) {
	serverCA := newDoTTestCA(t)
	certificate, _ := serverCA.issue(t, dotLeafOptions{ips: loopbackIPs()})

	scenarios := []struct {
		name  string
		want  FailureKind
		trust func() *x509.CertPool
	}{
		{"untrusted chain", FailureCertificate, func() *x509.CertPool { return newDoTTestCA(t).trustPool() }},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			addr, tcpPlain := startSniffedDoTServer(t, certificate)
			udp := startPlaintextResponder(t, addr, "203.0.113.116")
			assertNoPlaintextAfterFailure(t, downgradeScenario{
				entry: dotEntryOf(addr, ""), roots: scenario.trust(), want: scenario.want,
				attempt: 2 * time.Second, udpHits: udp, tcpPlain: tcpPlain,
			})
		})
	}
}

// dohProxyChildEnv marks the re-executed test process that performs the exchange.
const dohProxyChildEnv = "DOH_PROXY_PROBE_CHILD"

// TestResolver_DoHIgnoresProxyEnvironment proves the transport is pinned: a
// proxy named in the environment is never contacted. The proxy is a real
// listener that counts connections.
//
// The exchange runs in a re-executed child process on purpose. net/http reads
// the proxy environment once per process and caches it, so in a shared test
// binary an earlier test would already have fixed the (empty) answer and this
// test would pass even with proxy support switched on. A fresh process reads the
// environment for the first time.
func TestResolver_DoHIgnoresProxyEnvironment(t *testing.T) {
	if os.Getenv(dohProxyChildEnv) != "" {
		runDoHProxyChild(t)
		return
	}
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	var proxied atomic.Int32
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			proxied.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = proxy.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^TestResolver_DoHIgnoresProxyEnvironment$", "-test.count=1")
	cmd.Env = append(os.Environ(), dohProxyChildEnv+"=1", "NO_PROXY=", "no_proxy=")
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		cmd.Env = append(cmd.Env, name+"=http://"+proxy.Addr().String())
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child exchange with a proxy in the environment failed: %v\n%s", err, output)
	}
	if got := proxied.Load(); got != 0 {
		t.Fatalf("the proxy named in the environment received %d connection(s)", got)
	}
}

// runDoHProxyChild performs one DoH exchange against a hostname entry. The
// entry is a hostname, not a loopback literal, because ProxyFromEnvironment
// never proxies loopback targets and a loopback entry would prove nothing.
func runDoHProxyChild(t *testing.T) {
	ca := newDoTTestCA(t)
	certificate, _ := ca.issue(t, dotLeafOptions{dnsNames: []string{"resolver.test"}})
	server := startDoHTestServer(t, certificate, true, dohAnswerHandler(t, "203.0.113.117"))
	entry := policy.Upstream{Address: "resolver.test", Port: int(server.addr.Port()), Transport: policy.TransportDoH}
	resolver := mustLoopbackResolver(t, ResolverConfig{
		Upstreams:  []policy.Upstream{entry},
		tlsRootCAs: ca.trustPool(),
		dotDial: func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", server.addr.String())
		},
	})
	if _, err := resolver.Exchange(context.Background(), testQuery("proxy.example.")); err != nil {
		t.Fatalf("Exchange failed with a proxy in the environment: %v", err)
	}
	if got := len(server.requests()); got != 1 {
		t.Fatalf("server saw %d requests, want 1 direct request", got)
	}
}
