//go:build linux

package forwarder

// The HTTP/2-only origin used by the egress qualification: a TLS server whose
// ALPN list is exactly "h2" and which refuses HTTP/1.1, plus the certificate the
// re-executed in-namespace origin helper receives through its environment.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

const (
	// h2OriginHelperEnv turns a re-exec of this binary into the in-namespace
	// HTTP/2-only origin, mirroring NEXUS_E2E_ECHO_HELPER in the echo fixture.
	h2OriginHelperEnv  = "NEXUS_E2E_HTTP2_ORIGIN_HELPER"
	h2OriginCertEnv    = "NEXUS_E2E_HTTP2_ORIGIN_CERT_PEM"
	h2OriginKeyEnv     = "NEXUS_E2E_HTTP2_ORIGIN_KEY_PEM"
	h2OriginTargetEnv  = "TARGET_ADDR"
	h2DirectOriginAddr = "198.51.200.2:8443" // direct path origin (namespace fixture)
	h2ProxyOriginIP    = "198.51.200.60"     // proxy backend origin (netstack device)
	h2ProxyOriginPort  = 8443                //
	h2OriginServerName = "h2-origin.test"    // SNI/verification name, never resolved
	h2OriginPath       = "/h2-only"          //
	h2OriginBodyBytes  = 6144                // far larger than one small segment
	h2PathMTU          = 1280                // production client tunnel MTU
	h2CorrectClientMTU = 1280                // MTU the panel issues: MSS 1240 fits
	h2LegacyClientMTU  = 1420                // pre-fix MTU: advertises MSS 1380
	h2ClampedMSS       = h2PathMTU - 40      // path MTU minus IPv4 + TCP headers
	h2PositiveTimeout  = 20 * time.Second
	h2NegativeTimeout  = 3 * time.Second
)

func init() {
	if os.Getenv(h2OriginHelperEnv) == "1" {
		runLinuxE2EHTTP2Origin()
		os.Exit(0)
	}
}

// runLinuxE2EHTTP2Origin serves the h2-only origin inside the fixture network
// namespace until its stdin closes.
func runLinuxE2EHTTP2Origin() {
	target := os.Getenv(h2OriginTargetEnv)
	if target == "" {
		target = h2DirectOriginAddr
	}
	cert, err := tls.X509KeyPair([]byte(os.Getenv(h2OriginCertEnv)), []byte(os.Getenv(h2OriginKeyEnv)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "http2 origin: load certificate: %v\n", err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp4", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "http2 origin: listen %s: %v\n", target, err)
		os.Exit(1)
	}
	srv := newHTTP2OnlyOrigin(cert, h2OriginBody())
	go func() { _ = srv.Serve(tls.NewListener(ln, srv.TLSConfig)) }()

	fmt.Println("READY")
	_ = os.Stdout.Sync()
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// h2OriginBody is the deterministic payload the origin serves. Byte equality on
// a patterned body catches truncation, duplication and reordering, which a
// length-only assertion would accept.
func h2OriginBody() []byte {
	body := make([]byte, h2OriginBodyBytes)
	for i := range body {
		body[i] = byte((i*37 + 11) & 0xff)
	}
	return body
}

// h2OnlyOriginHandler serves the full body to HTTP/2 requests only. A request
// that is not HTTP/2 is refused, so an HTTP/1.1 client can never be served.
func h2OnlyOriginHandler(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusHTTPVersionNotSupported)
			_, _ = w.Write([]byte("origin is HTTP/2 only\n"))
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
}

// newHTTP2OnlyOrigin builds a TLS server whose ALPN list is exactly "h2".
//
// TLSNextProto is populated explicitly: net/http only adds its bundled HTTP/2
// support (and appends "http/1.1" to NextProtos) when the map has no "h2" entry,
// so this keeps the advertised protocol list to "h2" alone. A client offering
// only http/1.1 fails the handshake with no_application_protocol.
func newHTTP2OnlyOrigin(cert tls.Certificate, body []byte) *http.Server {
	//nolint:staticcheck // SA1019: keeps the origin's ALPN list to "h2" alone; net/http also offers http/1.1.
	var h2 http2.Server
	return &http.Server{
		Handler: h2OnlyOriginHandler(body),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{http2.NextProtoTLS},
			MinVersion:   tls.VersionTLS12,
		},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
			http2.NextProtoTLS: func(s *http.Server, c *tls.Conn, h http.Handler) {
				//nolint:staticcheck // SA1019: serves the negotiated "h2" connection above.
				h2.ServeConn(c, &http2.ServeConnOpts{BaseConfig: s, Handler: h})
			},
		},
	}
}

// newH2OriginCertificate issues the fixture certificate and the PEM form the
// re-executed origin helper receives through its environment.
func newH2OriginCertificate(tb testing.TB) (tls.Certificate, *x509.CertPool, []byte, []byte) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(833),
		Subject:               pkix.Name{CommonName: h2OriginServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{h2OriginServerName},
		IPAddresses: []net.IP{
			net.ParseIP("198.51.200.2"),
			net.ParseIP(h2ProxyOriginIP),
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		tb.Fatalf("x509.CreateCertificate failed: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		tb.Fatalf("x509.MarshalECPrivateKey failed: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("x509.ParseCertificate failed: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, pool, certPEM, keyPEM
}
