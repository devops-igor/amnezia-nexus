package gatewaydns

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These fixtures are hermetic like the DoT ones: every listener is on
// 127.0.0.1 and every certificate comes from a CA created inside the test.

// dohSeenRequest is what the fixture server observed for one HTTP request.
type dohSeenRequest struct {
	method      string
	path        string
	rawQuery    string
	proto       string
	host        string
	sni         string
	contentType string
	accept      string
	body        []byte
}

// dohTestServer is a local DNS-over-HTTPS responder. plaintext counts TCP
// connections whose first byte was not a TLS record, which is what a plaintext
// HTTP request to the DoH port looks like on the wire.
type dohTestServer struct {
	addr      netip.AddrPort
	plaintext *atomic.Int32
	mu        sync.Mutex
	seen      []dohSeenRequest
}

// requests returns a copy of everything the server has seen so far.
func (s *dohTestServer) requests() []dohSeenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]dohSeenRequest(nil), s.seen...)
}

// sniffListener wraps accepted connections so the first bytes read from each
// are inspected before TLS sees them.
type sniffListener struct {
	net.Listener
	plaintext *atomic.Int32
}

// Accept wraps the accepted connection.
func (l *sniffListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: conn, plaintext: l.plaintext}, nil
}

// sniffConn records, once per connection, whether the first byte received was a
// TLS handshake record (0x16). Anything else is a plaintext request.
type sniffConn struct {
	net.Conn
	plaintext *atomic.Int32
	once      sync.Once
}

// Read forwards the read and inspects the first byte of the connection.
func (c *sniffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.once.Do(func() {
			if p[0] != 0x16 {
				c.plaintext.Add(1)
			}
		})
	}
	return n, err
}

// startDoHTestServer serves HTTPS with the given certificate. http2 selects
// whether the server offers h2 in ALPN; false makes it an HTTP/1.1-only peer.
// The handler sees every request after the fixture has recorded it.
func startDoHTestServer(t *testing.T, certificate tls.Certificate, http2 bool, handler http.HandlerFunc) *dohTestServer {
	t.Helper()
	fixture := &dohTestServer{
		plaintext: &atomic.Int32{},
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(body))
		seen := dohSeenRequest{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery, proto: r.Proto,
			host: r.Host, contentType: r.Header.Get("Content-Type"), accept: r.Header.Get("Accept"), body: body,
		}
		if r.TLS != nil {
			seen.sni = r.TLS.ServerName
		}
		fixture.mu.Lock()
		fixture.seen = append(fixture.seen, seen)
		fixture.mu.Unlock()
		handler(w, r)
	}))
	fixture.addr = netip.MustParseAddrPort(server.Listener.Addr().String())
	server.Listener = &sniffListener{Listener: server.Listener, plaintext: fixture.plaintext}
	server.EnableHTTP2 = http2
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})
	return fixture
}

// dohAnswerHandler answers every DoH POST with a well-formed DNS message whose
// A record is answerIP.
func dohAnswerHandler(t *testing.T, answerIP string) http.HandlerFunc {
	t.Helper()
	dnsAnswer := answerHandler(t, answerIP)
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		req := new(mdns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		capture := &dohCaptureWriter{}
		dnsAnswer.ServeDNS(capture, req)
		writeDoHMessage(w, capture.msg)
	}
}

// writeDoHMessage writes msg with the DoH media type.
func writeDoHMessage(w http.ResponseWriter, msg *mdns.Msg) {
	wire, err := msg.Pack()
	if err != nil {
		http.Error(w, "pack failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", dohMediaType)
	_, _ = w.Write(wire)
}

// dohCaptureWriter lets an ordinary DNS handler produce the message a DoH
// handler then writes over HTTP.
type dohCaptureWriter struct {
	mdns.ResponseWriter
	msg *mdns.Msg
}

// WriteMsg keeps the message instead of writing it to a socket.
func (c *dohCaptureWriter) WriteMsg(m *mdns.Msg) error {
	c.msg = m
	return nil
}

// dohEntryOf renders a fixture listener as a DoH upstream entry.
func dohEntryOf(addr netip.AddrPort, pin string) policy.Upstream {
	return policy.Upstream{
		Address:   addr.Addr().String(),
		Port:      int(addr.Port()),
		Transport: policy.TransportDoH,
		SPKIPin:   pin,
	}
}
