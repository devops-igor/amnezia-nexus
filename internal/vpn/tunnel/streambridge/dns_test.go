package streambridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
	"golang.org/x/net/http2"
)

// startTCPDNSServer starts a TCP server that implements RFC 1035 / RFC 7766 DNS over TCP.
// It accepts queries with 2-byte length prefixes and echoes back a simulated DNS response.
func startTCPDNSServer(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp dns: %v", err)
	}
	var wg sync.WaitGroup
	closed := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-closed:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				lenBuf := make([]byte, 2)
				buf := make([]byte, 65536)
				for {
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					if _, err := io.ReadFull(c, lenBuf); err != nil {
						return
					}
					qLen := int(binary.BigEndian.Uint16(lenBuf))
					if qLen <= 0 || qLen > len(buf) {
						return
					}
					if _, err := io.ReadFull(c, buf[:qLen]); err != nil {
						return
					}

					// Construct DNS response: duplicate query, set QR bit (response), add 1 answer
					resp := make([]byte, qLen+16)
					copy(resp, buf[:qLen])
					if len(resp) >= 4 {
						resp[2] |= 0x80 // QR bit = 1 (response)
						resp[3] |= 0x80 // RA bit = 1 (recursion available)
						resp[7] = 1     // ANCOUNT = 1
					}
					// Synthetic answer record: name pointer 0xc00c, type A, class IN, TTL 60, data 93.184.216.34
					ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34}
					copy(resp[qLen:], ans)
					respLen := qLen + len(ans)

					binary.BigEndian.PutUint16(lenBuf, uint16(respLen))
					_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, err := c.Write(lenBuf); err != nil {
						return
					}
					if _, err := c.Write(resp[:respLen]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(closed)
		_ = l.Close()
		wg.Wait()
	}
	return l.Addr().String(), cleanup
}

func TestFlows_UDPDNSTranslationOverTCP(t *testing.T) {
	dnsAddr, stopDNS := startTCPDNSServer(t)
	defer stopDNS()

	var dialedNetwork atomic.Value
	var dialedAddr atomic.Value

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialedNetwork.Store(network)
		dialedAddr.Store(address)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dnsAddr)
	})

	cfg := Config{
		UDPIdleTimeout: 500 * time.Millisecond,
		DialTimeout:    2 * time.Second,
	}
	dev, err := New(cfg, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	conn, err := tc.DialUDP("198.51.100.1:53")
	if err != nil {
		t.Fatalf("DialUDP to port 53 error: %v", err)
	}
	defer conn.Close()

	// Standard DNS query for example.com (type A, class IN)
	query := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // standard query, recursion desired
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	if _, err := conn.Write(query); err != nil {
		t.Fatalf("conn.Write error: %v", err)
	}

	resp := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("conn.Read DNS response error: %v", err)
	}

	if n < len(query) {
		t.Fatalf("expected response length >= %d, got %d", len(query), n)
	}

	// Verify DNS transaction ID matches
	if binary.BigEndian.Uint16(resp[:2]) != 0x1234 {
		t.Fatalf("expected transaction ID 0x1234, got 0x%04x", binary.BigEndian.Uint16(resp[:2]))
	}
	// Verify QR bit is 1 (response)
	if resp[2]&0x80 == 0 {
		t.Fatalf("expected QR bit set in response, flags: 0x%02x%02x", resp[2], resp[3])
	}

	// Verify the streambridge dialed "tcp" to port 53
	netVal, _ := dialedNetwork.Load().(string)
	addrVal, _ := dialedAddr.Load().(string)
	if netVal != "tcp" {
		t.Fatalf("expected dialer network 'tcp', got %q", netVal)
	}
	if addrVal != "198.51.100.1:53" {
		t.Fatalf("expected dialer target '198.51.100.1:53', got %q", addrVal)
	}
}

// auditObservedDialer records dial parameters and results to simulate the audit probe.
type auditObservedDialer struct {
	dialer  StreamDialer
	results chan struct {
		network string
		address string
		err     error
	}
}

func (a auditObservedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := a.dialer.DialContext(ctx, network, address)
	a.results <- struct {
		network string
		address string
		err     error
	}{network: network, address: address, err: err}
	return c, err
}

func (a auditObservedDialer) Unwrap() StreamDialer {
	return a.dialer
}

func TestFlows_NaiveDefaultDNSBridgeRegression(t *testing.T) {
	// Replicates TestAudit662_NaiveDefaultDNSHasNoBridge from audit evidence.
	dialer, err := naive.New("127.0.0.1:1", models.NaiveProxyParams{
		Username: "audit-only-user", Password: "audit-only-password", Domain: "proxy.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	results := make(chan struct {
		network string
		address string
		err     error
	}, 1)

	dev, err := New(Config{}, auditObservedDialer{dialer: dialer, results: results})
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	client := newTestClient(t, dev)
	defer client.Close()

	conn, err := client.DialUDP("94.140.14.14:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}

	select {
	case result := <-results:
		t.Logf("actual dial boundary: network=%q destination=%q error=%v", result.network, result.address, result.err)
		if result.network == "udp" && result.err != nil {
			t.Fatalf("generic client's default DNS is passed unbridged to Naive and rejected: %v", result.err)
		}
		if result.network != "tcp" {
			t.Fatalf("expected bridged DNS flow to dial network 'tcp', got %q", result.network)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS datagram never reached the backend dial boundary")
	}
}

type testFlushWriter struct {
	mu     sync.Mutex
	w      io.Writer
	f      http.Flusher
	closed bool
}

func (fw *testFlushWriter) Write(p []byte) (int, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.closed {
		return 0, net.ErrClosed
	}
	n, err := fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

func (fw *testFlushWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.closed = true
	return nil
}

// TestFlows_NaiveBackedStreambridgeDNS exercises the full end-to-end data path:
// Client UDP -> streambridge (RFC 1035 TCP-framed) -> real Naive H2 proxy -> upstream TCP DNS server -> client UDP.
func TestFlows_NaiveBackedStreambridgeDNS(t *testing.T) {
	dnsAddr, stopDNS := startTCPDNSServer(t)
	defer stopDNS()

	// 1. Generate test CA & leaf cert for local H2 proxy
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Naive Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	naive.SetTestRootCAs(pool)
	defer naive.SetTestRootCAs(nil)

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "naive.test.local"},
		DNSNames:              []string{"naive.test.local", "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafPriv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDer},
			PrivateKey:  leafPriv,
		}},
		NextProtos: []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	expectedAuth := base64.StdEncoding.EncodeToString([]byte("user123:pass123"))

	h2Server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			if r.Header.Get("Proxy-Authorization") != "Basic "+expectedAuth {
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}

			// Forward connect target to local TCP DNS server
			targetConn, dialErr := net.DialTimeout("tcp", dnsAddr, 2*time.Second)
			if dialErr != nil {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			defer targetConn.Close()

			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}

			errc := make(chan error, 2)
			go func() {
				_, copyErr := io.Copy(targetConn, r.Body)
				if tc, ok := targetConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				errc <- copyErr
			}()
			fw := &testFlushWriter{w: w, f: flusher}
			go func() {
				_, copyErr := io.Copy(fw, targetConn)
				errc <- copyErr
			}()
			<-errc
			_ = targetConn.Close()
			_ = fw.Close()
		}),
	}
	//nolint:staticcheck // SA1019: http2.ConfigureServer test fixture helper
	_ = http2.ConfigureServer(h2Server, &http2.Server{})
	go func() { _ = h2Server.Serve(ln) }()
	defer func() { _ = h2Server.Close() }()

	// 2. Create real naive.Dialer
	dialer, err := naive.New(ln.Addr().String(), models.NaiveProxyParams{
		Username: "user123",
		Password: "pass123",
		Domain:   "naive.test.local",
	})
	if err != nil {
		t.Fatalf("naive.New: %v", err)
	}
	defer dialer.Close()

	// 3. Create streambridge backed by naive.Dialer
	dev, err := New(Config{DialTimeout: 3 * time.Second, UDPIdleTimeout: time.Second}, dialer)
	if err != nil {
		t.Fatalf("streambridge.New: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	// 4. Send ordinary UDP DNS query from client
	conn, err := tc.DialUDP("198.51.100.1:53")
	if err != nil {
		t.Fatalf("DialUDP to port 53: %v", err)
	}
	defer conn.Close()

	query := []byte{
		0x56, 0x78, // ID
		0x01, 0x00, // standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	if _, err := conn.Write(query); err != nil {
		t.Fatalf("conn.Write error: %v", err)
	}

	resp := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("conn.Read DNS response through Naive streambridge failed: %v", err)
	}

	if n < len(query) {
		t.Fatalf("DNS response too short: %d bytes", n)
	}
	if binary.BigEndian.Uint16(resp[:2]) != 0x5678 {
		t.Fatalf("expected transaction ID 0x5678, got 0x%04x", binary.BigEndian.Uint16(resp[:2]))
	}
	if resp[2]&0x80 == 0 {
		t.Fatalf("expected QR bit set in response")
	}
	t.Logf("successfully received valid %d-byte DNS reply through Naive-backed streambridge", n)
}

// startUDPDNSServer starts an in-process UDP DNS server.
// It accepts standard DNS queries over UDP and responds with an answer record.
func startUDPDNSServer(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp dns: %v", err)
	}
	closed := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n+16)
			copy(resp, buf[:n])
			if len(resp) >= 4 {
				resp[2] |= 0x80 // QR bit = 1 (response)
				resp[3] |= 0x80 // RA bit = 1
				resp[7] = 1     // ANCOUNT = 1
			}
			ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34}
			copy(resp[n:], ans)
			respLen := n + len(ans)
			_, _ = pc.WriteTo(resp[:respLen], addr)
		}
	}()
	cleanup := func() {
		close(closed)
		_ = pc.Close()
		wg.Wait()
	}
	return pc.LocalAddr().String(), cleanup
}

type udpCapableTestDialer struct {
	udpAddr       string
	dialedNetwork atomic.Value
	dialedAddr    atomic.Value
}

func (d *udpCapableTestDialer) SupportsUDP() bool {
	return true
}

func (d *udpCapableTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.dialedNetwork.Store(network)
	d.dialedAddr.Store(address)
	if network == "tcp" {
		return nil, errors.New("connection refused: upstream resolver is UDP only")
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.udpAddr)
}

func TestFlows_UDPCapableDialer_PreservesNativeUDPDNS(t *testing.T) {
	// Static capability checks for both concrete proxy dialers
	var vlessDialer vless.Dialer
	if !vlessDialer.SupportsUDP() {
		t.Fatal("expected vless.Dialer.SupportsUDP() to be true")
	}
	var naiveDialer naive.Dialer
	if naiveDialer.SupportsUDP() {
		t.Fatal("expected naive.Dialer.SupportsUDP() to be false")
	}

	udpDNSAddr, stopUDP := startUDPDNSServer(t)
	defer stopUDP()

	testDialer := &udpCapableTestDialer{
		udpAddr: udpDNSAddr,
	}

	cfg := Config{
		UDPIdleTimeout: 500 * time.Millisecond,
		DialTimeout:    2 * time.Second,
	}
	dev, err := New(cfg, testDialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	conn, err := tc.DialUDP("198.51.100.1:53")
	if err != nil {
		t.Fatalf("DialUDP to port 53 error: %v", err)
	}
	defer conn.Close()

	query := []byte{
		0xaa, 0xbb, // ID
		0x01, 0x00, // standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	if _, err := conn.Write(query); err != nil {
		t.Fatalf("conn.Write error: %v", err)
	}

	resp := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("conn.Read DNS response error (TCP refusal bypassed, native UDP expected): %v", err)
	}

	if n < len(query) {
		t.Fatalf("expected response length >= %d, got %d", len(query), n)
	}
	if binary.BigEndian.Uint16(resp[:2]) != 0xaabb {
		t.Fatalf("expected transaction ID 0xaabb, got 0x%04x", binary.BigEndian.Uint16(resp[:2]))
	}
	if resp[2]&0x80 == 0 {
		t.Fatalf("expected QR bit set in response")
	}

	netVal, _ := testDialer.dialedNetwork.Load().(string)
	addrVal, _ := testDialer.dialedAddr.Load().(string)
	if netVal != "udp" {
		t.Fatalf("expected dialer network 'udp' for UDP-capable dialer, got %q", netVal)
	}
	if addrVal != "198.51.100.1:53" {
		t.Fatalf("expected dialer target '198.51.100.1:53', got %q", addrVal)
	}
}
