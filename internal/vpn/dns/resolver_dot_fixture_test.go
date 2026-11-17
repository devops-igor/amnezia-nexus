package gatewaydns

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These fixtures are hermetic: every listener is on 127.0.0.1, every
// certificate is issued by a CA created inside the test, and no query leaves the
// host. The resolver trusts a fixture CA through the resolver's trust-store seam,
// so the production path (system store, chain and name verification) is the same
// code that runs here.

// dotTestCA is a local certificate authority for the DoT fixtures.
type dotTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newDoTTestCA mints a CA that signs the fixture server certificates.
func newDoTTestCA(t *testing.T) *dotTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "dot fixture ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &dotTestCA{cert: cert, key: key}
}

// trustPool is the trust store a resolver needs to accept this CA's leaves.
func (ca *dotTestCA) trustPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// dotLeafOptions describes one server certificate.
type dotLeafOptions struct {
	dnsNames  []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

// issue signs one server certificate with this CA.
func (ca *dotTestCA) issue(t *testing.T, opts dotLeafOptions) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	notBefore := opts.notBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	commonName := "dot fixture leaf"
	if len(opts.dnsNames) > 0 {
		commonName = opts.dnsNames[0]
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     opts.dnsNames,
		IPAddresses:  opts.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// spkiPinOf renders the pin an operator would configure for a certificate.
func spkiPinOf(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return serial
}

// dotTestServer is a local DNS-over-TLS responder. sniSeen receives the SNI of
// every completed TLS client hello, so a test can assert what was offered.
type dotTestServer struct {
	addr    netip.AddrPort
	sniSeen chan string
	// pair is the TCP/UDP port pair this server owns, so a caller that needs a
	// plaintext oracle on the same number can use its UDP half.
	pair *loopbackPortPair
}

// startDoTTestServer serves DNS over TLS with the given certificate.
func startDoTTestServer(t *testing.T, certificate tls.Certificate, handler mdns.Handler) *dotTestServer {
	t.Helper()
	sniSeen := make(chan string, 8)
	pair := newLoopbackPortPair(t)
	listener := tls.NewListener(pair.tcp, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniSeen <- hello.ServerName:
			default:
			}
			return nil, nil
		},
	})
	server := &mdns.Server{Listener: listener, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return &dotTestServer{addr: pair.addr(), sniSeen: sniSeen, pair: pair}
}

// startBrokenTLSListener accepts TCP and answers with bytes that are not a TLS
// record, which is how a wrong-port or non-TLS peer behaves.
func startBrokenTLSListener(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return startBrokenTLSListenerOn(t, listener)
}

// startBrokenTLSListenerOn serves the non-TLS peer on an already-reserved
// listener, so a scenario that also needs the same number for plaintext UDP can
// own one port pair instead of binding the number twice.
func startBrokenTLSListenerOn(t *testing.T, listener net.Listener) netip.AddrPort {
	t.Helper()
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("this is not a TLS server\n"))
			_ = conn.Close()
		}
	}()
	return netip.MustParseAddrPort(listener.Addr().String())
}

// startStalledTLSListener accepts TCP connections and never answers the client
// hello, so the attempt can only end in its own deadline.
func startStalledTLSListener(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	var held sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			held.Add(1)
			go func(conn net.Conn) {
				defer held.Done()
				<-done
				_ = conn.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		close(done)
		held.Wait()
	})
	return netip.MustParseAddrPort(listener.Addr().String())
}

// startPlaintextResponder answers plaintext UDP DNS on conn and counts every query
// it receives: it is the oracle for "did an encrypted entry leak a plaintext
// query?". conn is the UDP half of the fixture's port pair, already held on the
// same number the encrypted listener uses, so no second bind of that number can
// fail in setup.
func startPlaintextResponder(t *testing.T, conn net.PacketConn, answerIP string) *atomic.Int32 {
	t.Helper()
	hits := &atomic.Int32{}
	answer := answerHandler(t, answerIP)
	server := &mdns.Server{PacketConn: conn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		hits.Add(1)
		answer.ServeDNS(w, req)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return hits
}

// dotEntryOf renders a fixture listener as a DoT upstream entry.
func dotEntryOf(addr netip.AddrPort, pin string) policy.Upstream {
	return policy.Upstream{
		Address:   addr.Addr().String(),
		Port:      int(addr.Port()),
		Transport: policy.TransportDoT,
		SPKIPin:   pin,
	}
}

// mustLoopbackResolver builds a resolver that admits the loopback fixtures.
func mustLoopbackResolver(t *testing.T, cfg ResolverConfig) *UpstreamResolver {
	t.Helper()
	cfg.AllowLoopbackUpstream = true
	resolver, err := NewUpstreamResolver(cfg)
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	return resolver
}
