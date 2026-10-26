package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/net/http2"
)

func setupTestH2ServerWithMaxStreams(t *testing.T, authUser, authPass string, maxStreams uint32) (string, func()) {
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

			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader != "Basic "+expectedAuth {
				http.Redirect(w, r, "/", http.StatusPermanentRedirect)
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
	//nolint:staticcheck // SA1019: http2.ConfigureServer test fixture helper
	_ = http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: maxStreams,
	})

	go func() {
		_ = server.Serve(ln)
	}()

	cleanup := func() {
		_ = server.Close()
		_ = ln.Close()
	}

	return ln.Addr().String(), cleanup
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func TestDialer_H2_RetiredConnectionsClosedOnDialerClose(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// MaxConcurrentStreams = 1 forces a new HTTP/2 ClientConn for each concurrent CONNECT stream.
	proxyAddr, cleanupH2 := setupTestH2ServerWithMaxStreams(t, "testuser", "testpass", 1)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Stream 1 saturates connection 1
	conn1, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 1: %v", err)
	}
	defer conn1.Close()

	// Stream 2 forces rotation to connection 2 (connection 1 is now retired)
	conn2, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 2: %v", err)
	}
	defer conn2.Close()

	// Stream 3 forces rotation to connection 3 (connection 2 is now also retired)
	conn3, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 3: %v", err)
	}
	defer conn3.Close()

	// Verify all 3 connections are tracked by the pool
	tracked := d.h2Pool.trackedConns()
	if len(tracked) != 3 {
		t.Fatalf("expected 3 tracked connections (2 retired + 1 active), got %d", len(tracked))
	}

	// Verify that each connection is distinct
	connMap := make(map[*http2.ClientConn]bool)
	for _, cc := range tracked {
		if connMap[cc] {
			t.Fatal("duplicate ClientConn pointer found in tracked connections")
		}
		connMap[cc] = true
		if cc.State().Closed {
			t.Fatal("connection should not be closed before dialer.Close()")
		}
	}

	// Verify all streams are functional
	for i, c := range []net.Conn{conn1, conn2, conn3} {
		msg := []byte("echo test payload")
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("conn %d write: %v", i+1, err)
		}
		recv := make([]byte, len(msg))
		if _, err := io.ReadFull(c, recv); err != nil {
			t.Fatalf("conn %d read: %v", i+1, err)
		}
		if !bytes.Equal(recv, msg) {
			t.Fatalf("conn %d payload mismatch: got %q, want %q", i+1, recv, msg)
		}
	}

	// Close dialer: MUST terminate both the active connection and all previously retired connections
	if err := d.Close(); err != nil {
		t.Fatalf("d.Close(): %v", err)
	}

	// Assert every tracked connection (active and retired) is terminated
	for i, cc := range tracked {
		if !cc.State().Closed {
			t.Errorf("connection %d (%p) was not terminated after dialer.Close()", i+1, cc)
		}
	}

	// Assert pool is cleared
	if remaining := len(d.h2Pool.trackedConns()); remaining != 0 {
		t.Errorf("expected 0 remaining tracked connections in pool, got %d", remaining)
	}

	// Assert subsequent dial fails because dialer pool is closed
	_, err = d.DialContext(ctx, "tcp", echoAddr)
	if err == nil {
		t.Error("expected DialContext after d.Close() to fail, got nil error")
	}
}

//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func TestDialer_H2_InvalidateRetiredConnection(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2ServerWithMaxStreams(t, "testuser", "testpass", 1)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn1, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 1: %v", err)
	}
	defer conn1.Close()

	conn2, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 2: %v", err)
	}
	defer conn2.Close()

	tracked := d.h2Pool.trackedConns()
	if len(tracked) != 2 {
		t.Fatalf("expected 2 tracked connections, got %d", len(tracked))
	}

	// Identify the retired connection (the one that is not current d.h2Pool.cc)
	var retiredCC *http2.ClientConn
	d.h2Pool.mu.Lock()
	currentCC := d.h2Pool.cc
	for _, cc := range tracked {
		if cc != currentCC {
			retiredCC = cc
			break
		}
	}
	d.h2Pool.mu.Unlock()

	if retiredCC == nil {
		t.Fatal("could not find retired connection in pool")
	}

	// Invalidate the retired connection
	d.h2Pool.invalidate(retiredCC)

	// Verify retired connection is removed from tracked connections, but currentCC remains
	afterInvalidate := d.h2Pool.trackedConns()
	if len(afterInvalidate) != 1 {
		t.Fatalf("expected 1 tracked connection after invalidating retired connection, got %d", len(afterInvalidate))
	}
	if afterInvalidate[0] != currentCC {
		t.Errorf("expected currentCC to remain tracked, got %p (current %p)", afterInvalidate[0], currentCC)
	}
}
