package vpn

// Issue #865: the VPN Service-configured encrypted resolver consumer proof.
//
// The gap this file closes, precisely: the existing module and gateway tests
// prove that a client DNS packet intercepted by a gateway reaches an
// authenticated encrypted fixture. They do not prove that a resolver built by
// the VPN Service from the operator's configured upstream list does the same,
// because the Service passes gatewaydns.ResolverConfig{Upstreams: ...} only.
//
// Both Service resolver-construction paths consume the same operator list, so the
// distinction below is the whole point of the file:
//
//   - Exercised: the continuity responder. installDNSContinuity() is the
//     production startup entry point (service_lifecycle.go); it builds the
//     resolver from the Service's own configured upstream list and serves
//     already-issued client profiles through the real forwarder return path.
//     Its resolver factory, newDNSContinuityResolver, is an existing documented
//     test substitution point; the substitution below calls the real
//     gatewaydns.NewUpstreamResolver with the real config and adds only
//     AllowLoopbackUpstream (an exported field documented as needed by resolver
//     fixtures). Nothing is mocked, replaced or prebuilt, and no validation is
//     skipped other than admitting the loopback fixture address.
//   - NOT exercised, deliberately: the policy/intercepting resolver. It has no
//     factory substitution point, its only hooks are pre-set resolver/gateway
//     fields (i.e. injecting a prebuilt resolver, which is not factory proof),
//     and its configured list admits no loopback endpoint. Routing evidence for a
//     Service-configured encrypted list therefore remains unproved and is
//     reported as the remaining gap rather than approximated here. The continuity
//     responder writes no routing evidence by design.
//
// Trust isolation: the resolver in this path uses the process system store
// (tlsRootCAs nil). The parent test mints a private CA and re-executes this test
// binary as a child with SSL_CERT_FILE pointing at that CA only, so the child's
// first system-pool load trusts it while the host, other processes and all
// production configuration are untouched. Chain, hostname/IP verification and
// pins remain the real ones.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

const (
	// issue865ChildEnv marks the isolated child process, whose system trust store
	// is the private fixture CA supplied through SSL_CERT_FILE.
	issue865ChildEnv = "ISSUE865_SERVICE_CHILD"
	// issue865FixtureDirEnv points the child at the key material the parent minted.
	issue865FixtureDirEnv = "ISSUE865_SERVICE_FIXTURE_DIR"
	// issue865ChildMarker is printed only after every controlled result passed.
	issue865ChildMarker = "ISSUE865_SERVICE_PROOF_OK"
)

// issue865FixtureAnswers is the name→address table the encrypted fixtures serve.
var issue865FixtureAnswers = map[string]string{
	"matched.example.": "198.51.200.55",
	"direct.example.":  "93.184.216.34",
}

var (
	issue865MatchedIP = netip.MustParseAddr("198.51.200.55")
	issue865DirectIP  = netip.MustParseAddr("93.184.216.34")
	issue865Gateway   = netip.MustParseAddr("10.100.0.1")
	issue865ClientIP  = netip.MustParseAddr("10.100.0.2")
)

// issue865CA is a private certificate authority for one test process tree.
type issue865CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue865MintCA creates a CA that signs the fixture leaves.
func issue865MintCA(t *testing.T) *issue865CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fixture CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate fixture CA serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "issue865 fixture ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create fixture CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse fixture CA certificate: %v", err)
	}
	return &issue865CA{cert: cert, key: key}
}

// issue865WriteCA writes this CA's certificate as the child's trust bundle.
func (ca *issue865CA) issue865WriteCA(t *testing.T, path string) {
	t.Helper()
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}
}

// issue865WriteLeaf mints a server certificate for the loopback fixture and
// writes it next to its key so the child process can load it.
func issue865WriteLeaf(t *testing.T, dir, name string, ca *issue865CA) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fixture leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate fixture leaf serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dns-fixture.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"dns-fixture.example"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create fixture leaf certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal fixture leaf key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write fixture leaf certificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write fixture leaf key: %v", err)
	}
}

// issue865LoadKeyPair loads one leaf the parent wrote.
func issue865LoadKeyPair(t *testing.T, dir, name string) tls.Certificate {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(dir, name+".pem"))
	if err != nil {
		t.Fatalf("read fixture leaf certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatalf("read fixture leaf key: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load fixture leaf key pair: %v", err)
	}
	return pair
}

// issue865SPKIPin renders the pin an operator would configure for a certificate.
func issue865SPKIPin(t *testing.T, pair tls.Certificate) string {
	t.Helper()
	leaf := pair.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatalf("parse fixture leaf: %v", err)
		}
		leaf = parsed
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

// issue865Answers is the DNS answer handler shared by both encrypted fixtures.
func issue865Answers(t *testing.T, answers map[string]string) mdns.Handler {
	t.Helper()
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		if len(req.Question) != 1 {
			return
		}
		resp := new(mdns.Msg)
		resp.SetReply(req)
		if ip, ok := answers[strings.ToLower(req.Question[0].Name)]; ok {
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 600},
				A:   net.ParseIP(ip).To4(),
			})
		}
		_ = w.WriteMsg(resp)
	})
}

// issue865DoTFixture is a local DNS-over-TLS responder. handshakes counts every
// completed TLS client hello, so a refused control can prove the resolver really
// reached the encrypted listener instead of never dialing it.
type issue865DoTFixture struct {
	port       int
	handshakes *atomic.Int32
}

// issue865StartDoT serves DNS over TLS on an ephemeral loopback port.
func issue865StartDoT(t *testing.T, pair tls.Certificate) *issue865DoTFixture {
	t.Helper()
	fixture := &issue865DoTFixture{handshakes: &atomic.Int32{}}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			fixture.handshakes.Add(1)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("listen DoT fixture: %v", err)
	}
	server := &mdns.Server{Listener: listener, Handler: issue865Answers(t, issue865FixtureAnswers)}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	fixture.port = listener.Addr().(*net.TCPAddr).Port
	return fixture
}

// issue865DoHFixture is a local DNS-over-HTTPS responder on the RFC 8484 path.
type issue865DoHFixture struct {
	port     int
	requests *atomic.Int32
	rejected *atomic.Int32
}

// issue865StartDoH serves DNS over HTTPS with HTTP/2 on an ephemeral loopback
// port. A request that is not a DoH POST is rejected and counted, so an
// unexpected transport cannot pass as a DoH exchange.
func issue865StartDoH(t *testing.T, pair tls.Certificate) *issue865DoHFixture {
	t.Helper()
	fixture := &issue865DoHFixture{requests: &atomic.Int32{}, rejected: &atomic.Int32{}}
	dnsHandler := issue865Answers(t, issue865FixtureAnswers)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" ||
			r.Header.Get("Content-Type") != "application/dns-message" {
			fixture.rejected.Add(1)
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		req := new(mdns.Msg)
		if err := req.Unpack(body); err != nil {
			fixture.rejected.Add(1)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		capture := &issue865CaptureWriter{}
		dnsHandler.ServeDNS(capture, req)
		wire, err := capture.msg.Pack()
		if err != nil {
			http.Error(w, "pack failed", http.StatusInternalServerError)
			return
		}
		fixture.requests.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	fixture.port = server.Listener.Addr().(*net.TCPAddr).Port
	return fixture
}

// issue865CaptureWriter keeps the message an ordinary DNS handler produced.
type issue865CaptureWriter struct {
	mdns.ResponseWriter
	msg *mdns.Msg
}

// WriteMsg records the message instead of writing it to a socket.
func (c *issue865CaptureWriter) WriteMsg(m *mdns.Msg) error {
	c.msg = m
	return nil
}

// issue865AssertAnswer asserts the client accepted exactly one answer and that it
// is the fixture's address.
func issue865AssertAnswer(t *testing.T, label string, resp *mdns.Msg, want netip.Addr) {
	t.Helper()
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("%s: client rcode = %s, want success", label, mdns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("%s: client received %d answers, want 1", label, len(resp.Answer))
	}
	aRec, ok := resp.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("%s: client answer is %T, want an A record", label, resp.Answer[0])
	}
	got, ok := netip.AddrFromSlice(aRec.A)
	if !ok || got != want {
		t.Fatalf("%s: client answer address = %v, want %s", label, aRec.A, want)
	}
}

// issue865AssertRefused asserts the encrypted failure reached the client as a
// refusal rather than an empty success.
func issue865AssertRefused(t *testing.T, label string, resp *mdns.Msg) {
	t.Helper()
	if resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("%s: client rcode = %s, want SERVFAIL", label, mdns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("%s: a refused exchange still answered %d records", label, len(resp.Answer))
	}
}

// TestIssue865ServiceEncryptedConsumer is the parent half: it mints the private
// fixture material and runs the isolated child that owns the system-trust
// override. A skipped, empty or failed child is a failure here.
func TestIssue865ServiceEncryptedConsumer(t *testing.T) {
	if os.Getenv(issue865ChildEnv) == "1" {
		t.Skip("this is the isolated child process; the parent test is the entry point")
	}
	dir := t.TempDir()
	trusted := issue865MintCA(t)
	trusted.issue865WriteCA(t, filepath.Join(dir, "ca.pem"))
	issue865WriteLeaf(t, dir, "leaf", trusted)
	untrusted := issue865MintCA(t)
	issue865WriteLeaf(t, dir, "other", untrusted)

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate this test binary: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable,
		"-test.run=^TestIssue865ServiceEncryptedConsumerChild$",
		"-test.v", "-test.count=1", "-test.timeout=90s")
	cmd.Env = append(os.Environ(),
		issue865ChildEnv+"=1",
		"SSL_CERT_FILE="+filepath.Join(dir, "ca.pem"),
		issue865FixtureDirEnv+"="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated child failed: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{
		"--- PASS: TestIssue865ServiceEncryptedConsumerChild",
		issue865ChildMarker,
		"dot=1",
		"doh=1",
		"cert_refused=1",
		"pin_refused=1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("isolated child output is missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "--- SKIP") {
		t.Fatalf("the isolated child skipped instead of proving the consumer:\n%s", text)
	}
	// Keep the child's own report in the test log: it is the evidence that the
	// four controlled results actually executed in the isolated process.
	t.Logf("isolated child output:\n%s", text)
}

// TestIssue865ServiceEncryptedConsumerChild drives a real Service-configured
// encrypted resolver through a real client. It runs only in the child process the
// parent starts, because the system trust store must be loaded for the first time
// with the private fixture CA in SSL_CERT_FILE.
func TestIssue865ServiceEncryptedConsumerChild(t *testing.T) {
	if os.Getenv(issue865ChildEnv) != "1" {
		t.Skip("runs only inside the isolated child process started by the parent test")
	}
	dir := os.Getenv(issue865FixtureDirEnv)
	if dir == "" {
		t.Fatal("fixture directory is missing from the child environment")
	}
	trusted := issue865LoadKeyPair(t, dir, "leaf")
	untrusted := issue865LoadKeyPair(t, dir, "other")

	// The Service's own resolver factory, substituted at its documented test seam.
	// The real constructor still builds the resolver from the config the Service
	// passes; only the test-only loopback admission is enabled.
	previousFactory := newDNSContinuityResolver
	newDNSContinuityResolver = func(cfg gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
		cfg.AllowLoopbackUpstream = true
		return gatewaydns.NewUpstreamResolver(cfg)
	}
	t.Cleanup(func() { newDNSContinuityResolver = previousFactory })

	// Real forwarder, real returned packets, real client stack.
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	fwd.AttachBackendDevice(9, &mockPBRDevice{})
	client, path := newContinuityClient(t, fwd, "issue865-service-peer", issue865ClientIP)
	t.Cleanup(client.close)
	fwd.RegisterSessionWithReturnPath("issue865-service-session", "issue865-service-connection",
		"issue865-service-peer", issue865ClientIP.String(), 9, path)

	svc := &Service{forwarder: fwd}
	t.Cleanup(svc.closeDNSContinuity)
	dst := netip.AddrPortFrom(issue865Gateway, 53)

	// 1. DoT positive: the Service builds the resolver from the configured list
	// and the client receives the fixture's answer through the encrypted exchange.
	dot := issue865StartDoT(t, trusted)
	svc.dnsUpstreams = []policy.Upstream{{
		Address: "127.0.0.1", Port: dot.port, Transport: policy.TransportDoT,
	}}
	svc.installDNSContinuity()
	issue865AssertAnswer(t, "DoT configured upstream", continuityUDPQuery(t, client.stack, dst, "matched.example.", 8651), issue865MatchedIP)
	if got := dot.handshakes.Load(); got == 0 {
		t.Fatal("DoT fixture saw no TLS handshake: the configured entry was not dialed")
	}

	// 2. DoH positive: same wiring, DoH transport, and the fixture rejects anything
	// that is not a DoH POST.
	doh := issue865StartDoH(t, trusted)
	svc.dnsUpstreams = []policy.Upstream{{
		Address: "127.0.0.1", Port: doh.port, Transport: policy.TransportDoH,
	}}
	svc.installDNSContinuity()
	issue865AssertAnswer(t, "DoH configured upstream", continuityUDPQuery(t, client.stack, dst, "direct.example.", 8652), issue865DirectIP)
	if got := doh.requests.Load(); got == 0 {
		t.Fatal("DoH fixture served no DoH request: the configured entry was not dialed")
	}
	if got := doh.rejected.Load(); got != 0 {
		t.Fatalf("DoH fixture rejected %d requests: the exchange was not a DoH POST on the RFC 8484 path", got)
	}

	// 3. Certificate refusal: the fixture presents a leaf from a CA the child does
	// not trust, so the encrypted exchange must fail even though the resolver
	// reached the listener.
	certRefused := issue865StartDoT(t, untrusted)
	svc.dnsUpstreams = []policy.Upstream{{
		Address: "127.0.0.1", Port: certRefused.port, Transport: policy.TransportDoT,
	}}
	svc.installDNSContinuity()
	issue865AssertRefused(t, "untrusted certificate", continuityUDPQuery(t, client.stack, dst, "matched.example.", 8653))
	if got := certRefused.handshakes.Load(); got == 0 {
		t.Fatal("the untrusted-certificate control never reached the encrypted listener")
	}

	// 4. Pin refusal: the chain verifies, the configured pin does not match the
	// serving leaf, and the answer must be refused on the pin alone.
	pinRefused := issue865StartDoT(t, trusted)
	svc.dnsUpstreams = []policy.Upstream{{
		Address: "127.0.0.1", Port: pinRefused.port, Transport: policy.TransportDoT,
		SPKIPin: issue865SPKIPin(t, untrusted),
	}}
	svc.installDNSContinuity()
	issue865AssertRefused(t, "pin mismatch", continuityUDPQuery(t, client.stack, dst, "matched.example.", 8654))
	if got := pinRefused.handshakes.Load(); got == 0 {
		t.Fatal("the pin-mismatch control never reached the encrypted listener")
	}

	fmt.Printf("%s dot=1 doh=1 cert_refused=1 pin_refused=1\n", issue865ChildMarker)
}
