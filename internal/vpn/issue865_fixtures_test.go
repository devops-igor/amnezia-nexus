package vpn

// Shared fixtures for the issue #865 encrypted-consumer proofs: a private
// certificate authority, encrypted DNS responders and a real client network
// stack wired into the production forwarder.
//
// The fixtures live in their own file because two proofs use them: the policy
// resolver proof (issue865_policy_encrypted_consumer_test.go) and, before this
// file existed, a proof for the resolver that served already-issued gateway
// profiles. That resolver is gone; the fixtures it shared remain.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
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

// dnsTestClient is a real client network stack. Its outbound packets enter the
// production forwarder entry point and performed DNS replies arrive through the
// session's return path, so an unmodified client accepts every answer.
type dnsTestClient struct {
	dev   tun.Device
	stack *netstack.Net
	stop  chan struct{}
	done  chan struct{}
}

func newDNSTestClient(t *testing.T, fwd *forwarder.Forwarder, peerKey string, clientIP netip.Addr) (*dnsTestClient, *forwarder.ReturnPath) {
	t.Helper()
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}
	path := forwarder.NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		return dev.Write([][]byte{packet}, 0)
	})
	c := &dnsTestClient{dev: dev, stack: stack, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			select {
			case <-c.stop:
				return
			default:
			}
			n, err := dev.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				_ = fwd.RouteClientToBackend(peerKey, pkt)
			}
		}
	}()
	return c, path
}

func (c *dnsTestClient) close() {
	close(c.stop)
	_ = c.dev.Close()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
	}
}

// dnsUDPQuery performs one DNS A query from a real client stack and returns the
// answer the client received.
func dnsUDPQuery(t *testing.T, stack *netstack.Net, dst netip.AddrPort, name string, id uint16) *mdns.Msg {
	t.Helper()
	conn, err := stack.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		t.Fatalf("client failed to dial %s over UDP: %v", dst, err)
	}
	defer conn.Close()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write DNS query to %s: %v", dst, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no UDP reply from %s: %v", dst, err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack UDP reply from %s: %v", dst, err)
	}
	return resp
}

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
