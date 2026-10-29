package naive

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
			// Stop the copier before returning: the server reuses w's buffer after the handler exits.
			_ = targetConn.Close()
			_ = fw.Close()
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

// TestDialer_H2_HandshakeBlocksNeitherCancelledWaiterNorClose verifies finding R5-H1:
// when an H2 handshake is stalled, a second caller with a short context timeout returns
// promptly with context.DeadlineExceeded without blocking on the pool mutex, and
// Dialer.Close() returns promptly and terminates in-flight setup.
func TestDialer_H2_HandshakeBlocksNeitherCancelledWaiterNorClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	entered := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 1)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		close(entered) // ClientHello proves first dial is actively inside TLS handshake
		<-release
	}()

	d, err := New(ln.Addr().String(), models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpassword",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		c, err := d.DialContext(firstCtx, "tcp", "example.com:443")
		if c != nil {
			_ = c.Close()
		}
		firstDone <- err
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no ClientHello received by test server")
	}

	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancelWaiter()

	waiterDone := make(chan error, 1)
	go func() {
		c, err := d.DialContext(waiterCtx, "tcp", "example.com:443")
		if c != nil {
			_ = c.Close()
		}
		waiterDone <- err
	}()

	start := time.Now()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("waiter dial expected DeadlineExceeded, got: %v", err)
		}
	case <-time.After(350 * time.Millisecond):
		t.Errorf("queued dial still blocked after %v with 75ms context; ctx.Err()=%v", time.Since(start), waiterCtx.Err())
	}

	closeDone := make(chan struct{})
	go func() {
		_ = d.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(350 * time.Millisecond):
		t.Error("Dialer.Close blocked by in-flight TLS handshake")
	}

	// In-flight dial must unblock promptly following Close()
	select {
	case err := <-firstDone:
		if err == nil {
			t.Error("expected first dial to fail following Close(), got nil")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("first dial did not unblock after Dialer.Close()")
	}

	close(release)
	<-serverDone
}

func TestDialer_H2_HandshakeLateCompletionAfterCloseNotRetained(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
	defer cleanupH2()

	d, err := New(proxyAddr, models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Close before dial
	if err := d.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("expected nil conn after Close()")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close(), got %v", err)
	}

	if tracked := d.h2Pool.trackedConns(); len(tracked) != 0 {
		t.Fatalf("expected 0 tracked conns after Close(), got %d", len(tracked))
	}
}
