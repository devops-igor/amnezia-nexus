package naive

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

var (
	testCACert    *x509.Certificate
	testCAKey     *ecdsa.PrivateKey
	testCACertPEM []byte
)

const testCamouflageDomain = "naive.example.com"

func TestMain(m *testing.M) {
	caCert, caKey, caPEM, err := generateTestCA()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate test CA: %v\n", err)
		os.Exit(1)
	}
	testCACert = caCert
	testCAKey = caKey
	testCACertPEM = caPEM

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	testRootCAs = pool

	os.Exit(m.Run())
}

func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NaiveProxy Test CA"},
			CommonName:   "NaiveProxy Root CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return parsed, priv, pemBytes, nil
}

func generateLeafCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

func setupTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}

	var wg sync.WaitGroup
	closed := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		close(closed)
		_ = ln.Close()
		wg.Wait()
	}

	return ln.Addr().String(), cleanup
}

func startBlackholeListener(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole: %v", err)
	}

	var connsMu sync.Mutex
	var conns []net.Conn

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
		}
	}()

	cleanup := func() {
		_ = ln.Close()
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
	}

	return ln.Addr().String(), cleanup
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

func setupTestH2Server(t *testing.T, authUser, authPass string, probeResistance bool) (string, func()) {
	t.Helper()
	cert, err := generateLeafCert(testCACert, testCAKey, testCamouflageDomain)
	if err != nil {
		t.Fatalf("generate leaf cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("listen h2 tls: %v", err)
	}

	expectedAuth := basicAuth(authUser, authPass)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}

			// Validate Proxy-Authorization
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader != "Basic "+expectedAuth {
				if probeResistance {
					http.Redirect(w, r, "/", http.StatusPermanentRedirect) // 308
				} else {
					w.WriteHeader(http.StatusProxyAuthRequired) // 407
				}
				return
			}

			// Check if target is camouflage domain (health probe)
			camTarget := net.JoinHostPort(testCamouflageDomain, "443")
			if r.Host == camTarget {
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}

			// Forward to backing target (e.g. echo server)
			targetConn, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
			if err != nil {
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
				_, err := io.Copy(targetConn, r.Body)
				if tc, ok := targetConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				errc <- err
			}()
			fw := &flushWriter{w: w, f: flusher}
			go func() {
				_, err := io.Copy(fw, targetConn)
				errc <- err
			}()
			<-errc
		}),
	}
	//nolint:staticcheck // SA1019: http2.ConfigureServer test fixture helper
	_ = http2.ConfigureServer(server, &http2.Server{})

	go func() {
		_ = server.Serve(ln)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func setupTestH3Server(t *testing.T, authUser, authPass string, probeResistance bool) (string, func()) {
	t.Helper()
	cert, err := generateLeafCert(testCACert, testCAKey, testCamouflageDomain)
	if err != nil {
		t.Fatalf("generate leaf cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	expectedAuth := basicAuth(authUser, authPass)

	server := &http3.Server{
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}

			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader != "Basic "+expectedAuth {
				if probeResistance {
					http.Redirect(w, r, "/", http.StatusPermanentRedirect) // 308
				} else {
					w.WriteHeader(http.StatusProxyAuthRequired) // 407
				}
				return
			}

			camTarget := net.JoinHostPort(testCamouflageDomain, "443")
			if r.Host == camTarget {
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}

			targetConn, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
			if err != nil {
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
				_, err := io.Copy(targetConn, r.Body)
				if tc, ok := targetConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				errc <- err
			}()
			fw := &flushWriter{w: w, f: flusher}
			go func() {
				_, err := io.Copy(fw, targetConn)
				errc <- err
			}()
			<-errc
		}),
	}

	go func() {
		_ = server.Serve(udpConn)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = udpConn.Close()
	}

	return udpConn.LocalAddr().String(), cleanup
}

func setupDualStackH2H3Server(t *testing.T, authUser, authPass string) (string, *atomic.Bool, func()) {
	t.Helper()
	h2Addr, cleanupH2 := setupTestH2Server(t, authUser, authPass, true)
	_, portStr, err := net.SplitHostPort(h2Addr)
	if err != nil {
		cleanupH2()
		t.Fatalf("split host port: %v", err)
	}
	sharedPort, _ := strconv.Atoi(portStr)

	h3Addr, cleanupH3 := setupTestH3Server(t, authUser, authPass, true)
	up, err := net.ResolveUDPAddr("udp", h3Addr)
	if err != nil {
		cleanupH2()
		cleanupH3()
		t.Fatalf("resolve udp: %v", err)
	}

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sharedPort})
	if err != nil {
		cleanupH2()
		cleanupH3()
		t.Fatalf("listen udp relay: %v", err)
	}

	upConn, err := net.DialUDP("udp", nil, up)
	if err != nil {
		cleanupH2()
		cleanupH3()
		_ = relay.Close()
		t.Fatalf("dial udp relay: %v", err)
	}

	var drop atomic.Bool
	var client atomic.Pointer[net.UDPAddr]

	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := relay.ReadFromUDP(b)
			if err != nil {
				return
			}
			client.Store(a)
			if !drop.Load() {
				_, _ = upConn.Write(b[:n])
			}
		}
	}()

	go func() {
		b := make([]byte, 65535)
		for {
			n, err := upConn.Read(b)
			if err != nil {
				return
			}
			if a := client.Load(); a != nil && !drop.Load() {
				_, _ = relay.WriteToUDP(b[:n], a)
			}
		}
	}()

	cleanup := func() {
		_ = relay.Close()
		_ = upConn.Close()
		cleanupH3()
		cleanupH2()
	}

	return h2Addr, &drop, cleanup
}
