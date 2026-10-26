package naive

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDialer_H2_Echo256KiB(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
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

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext H2: %v", err)
	}
	defer conn.Close()

	// 256 KiB payload
	const payloadSize = 256 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("generate payload: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errc <- err
	}()

	recv := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("ReadFull H2: %v", err)
	}

	if err := <-errc; err != nil {
		t.Fatalf("Write H2: %v", err)
	}

	if !bytes.Equal(payload, recv) {
		t.Fatal("received payload does not match sent payload over H2")
	}
}

func TestDialer_H3_Echo256KiB(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH3 := setupTestH3Server(t, "testuser", "testpass", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext H3: %v", err)
	}
	defer conn.Close()

	const payloadSize = 256 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("generate payload: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errc <- err
	}()

	recv := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("ReadFull H3: %v", err)
	}

	if err := <-errc; err != nil {
		t.Fatalf("Write H3: %v", err)
	}

	if !bytes.Equal(payload, recv) {
		t.Fatal("received payload does not match sent payload over H3")
	}
}

func TestDialer_H3_FallbackToH2(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// Only start H2 server, UDP/QUIC listener will not exist
	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true, // H3 requested, but UDP endpoint is unavailable
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext should fall back to H2, but got: %v", err)
	}
	defer conn.Close()

	// Verify the connection functions properly over the fallback transport
	testMsg := []byte("hello through fallback h2")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("write over fallback: %v", err)
	}

	recv := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read over fallback: %v", err)
	}

	if !bytes.Equal(testMsg, recv) {
		t.Fatalf("payload mismatch over fallback: got %q, want %q", recv, testMsg)
	}
}

func TestDialer_Validation(t *testing.T) {
	validParams := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   "example.com",
	}

	tests := []struct {
		name     string
		endpoint string
		params   models.NaiveProxyParams
		wantErr  string
	}{
		{
			name:     "empty endpoint",
			endpoint: "",
			params:   validParams,
			wantErr:  "invalid endpoint",
		},
		{
			name:     "missing port",
			endpoint: "127.0.0.1",
			params:   validParams,
			wantErr:  "invalid endpoint",
		},
		{
			name:     "invalid port non-numeric",
			endpoint: "127.0.0.1:abc",
			params:   validParams,
			wantErr:  "invalid endpoint port",
		},
		{
			name:     "invalid port 0",
			endpoint: "127.0.0.1:0",
			params:   validParams,
			wantErr:  "invalid endpoint port",
		},
		{
			name:     "invalid port 65536",
			endpoint: "127.0.0.1:65536",
			params:   validParams,
			wantErr:  "invalid endpoint port",
		},
		{
			name:     "empty host",
			endpoint: ":443",
			params:   validParams,
			wantErr:  "endpoint host cannot be empty",
		},
		{
			name:     "empty domain",
			endpoint: "127.0.0.1:443",
			params: models.NaiveProxyParams{
				Username: "u",
				Password: "p",
				Domain:   "",
			},
			wantErr: "domain cannot be empty",
		},
		{
			name:     "domain with space",
			endpoint: "127.0.0.1:443",
			params: models.NaiveProxyParams{
				Username: "u",
				Password: "p",
				Domain:   "foo bar.com",
			},
			wantErr: "invalid domain name",
		},
		{
			name:     "domain with slash",
			endpoint: "127.0.0.1:443",
			params: models.NaiveProxyParams{
				Username: "u",
				Password: "p",
				Domain:   "foo/bar.com",
			},
			wantErr: "invalid domain name",
		},
		{
			name:     "domain with colon",
			endpoint: "127.0.0.1:443",
			params: models.NaiveProxyParams{
				Username: "u",
				Password: "p",
				Domain:   "foo:443",
			},
			wantErr: "invalid domain name",
		},
		{
			name:     "empty username",
			endpoint: "127.0.0.1:443",
			params: models.NaiveProxyParams{
				Username: "",
				Password: "p",
				Domain:   "example.com",
			},
			wantErr: "username cannot be empty",
		},
		{
			name:     "empty password",
			endpoint: "127.0.0.1:443",
			params: models.NaiveProxyParams{
				Username: "u",
				Password: "",
				Domain:   "example.com",
			},
			wantErr: "password cannot be empty",
		},
		{
			name:     "valid parameters",
			endpoint: "127.0.0.1:443",
			params:   validParams,
			wantErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := New(tt.endpoint, tt.params)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if d == nil {
					t.Fatal("expected non-nil dialer")
				}
				_ = d.Close()
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestDialer_ReadDeadline_H2(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// 1. Arm tight read deadline with no data written
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error on read, got nil")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected net.Error timeout, got: %v", err)
	}

	// 2. Extend deadline and verify connection recovery
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("recovery packet after timeout")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write after timeout: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read after recovery: %v", err)
	}

	if !bytes.Equal(msg, recv) {
		t.Fatalf("mismatch after recovery: got %q, want %q", recv, msg)
	}
}

func TestDialer_ReadDeadline_H3(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH3 := setupTestH3Server(t, "testuser", "testpass", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error on read, got nil")
	}

	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected net.Error timeout, got: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("recovery packet after h3 timeout")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write after timeout: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read after recovery: %v", err)
	}

	if !bytes.Equal(msg, recv) {
		t.Fatalf("mismatch after recovery: got %q, want %q", recv, msg)
	}
}

func TestDialer_UnsupportedNetwork(t *testing.T) {
	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   "example.com",
	}
	d, err := New("127.0.0.1:443", p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx := context.Background()
	networks := []string{"udp", "unix", "ip", "udp4", "tcp6"}
	for _, netName := range networks {
		if netName == "tcp" {
			continue
		}
		_, err := d.DialContext(ctx, netName, "127.0.0.1:80")
		if err == nil {
			t.Fatalf("expected error for network %q, got nil", netName)
		}
		if !strings.Contains(err.Error(), "unsupported network") {
			t.Fatalf("expected 'unsupported network' error for %q, got: %v", netName, err)
		}
	}
}

func TestDialer_ConnectionReuse(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "u", "p", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx := context.Background()

	// Dial two streams concurrently
	c1, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 1: %v", err)
	}
	defer c1.Close()

	c2, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 2: %v", err)
	}
	defer c2.Close()

	// Verify both connections have identical remote transport address
	if c1.RemoteAddr().String() != c2.RemoteAddr().String() {
		t.Fatalf("expected same RemoteAddr for multiplexed connections, got %v and %v",
			c1.RemoteAddr(), c2.RemoteAddr())
	}
	if c1.LocalAddr() == nil || c2.LocalAddr() == nil {
		t.Fatal("expected non-nil LocalAddr")
	}

	// Verify both connections can communicate independently
	msg1 := []byte("msg on stream 1")
	msg2 := []byte("msg on stream 2")

	if _, err := c1.Write(msg1); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	if _, err := c2.Write(msg2); err != nil {
		t.Fatalf("c2 write: %v", err)
	}

	r1 := make([]byte, len(msg1))
	if _, err := io.ReadFull(c1, r1); err != nil {
		t.Fatalf("c1 read: %v", err)
	}
	r2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(c2, r2); err != nil {
		t.Fatalf("c2 read: %v", err)
	}

	if !bytes.Equal(msg1, r1) || !bytes.Equal(msg2, r2) {
		t.Fatal("multiplexed streams data mismatch")
	}
}

func TestDialer_H3_ConnectionReuseAndMethods(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH3 := setupTestH3Server(t, "u", "p", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx := context.Background()

	c1, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext H3: %v", err)
	}
	defer c1.Close()

	if c1.LocalAddr() == nil || c1.RemoteAddr() == nil {
		t.Fatal("expected non-nil addresses on H3 conn")
	}

	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))
	_ = c1.SetWriteDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("test h3 conn methods")
	if _, err := c1.Write(msg); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(c1, recv); err != nil {
		t.Fatalf("c1 read: %v", err)
	}
	if !bytes.Equal(msg, recv) {
		t.Fatal("h3 payload mismatch")
	}
}

func TestDialer_AuthFailure_H2(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "correctUser", "correctPass", false)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "wrongUser",
		Password: "wrongPass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = d.DialContext(ctx, "tcp", echoAddr)
	if err == nil {
		t.Fatal("expected dial error on proxy auth failure, got nil")
	}
	if !strings.Contains(err.Error(), "status 407") {
		t.Fatalf("expected status 407 error, got: %v", err)
	}
}

func TestDialer_AuthFailure_H3(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH3 := setupTestH3Server(t, "correctUser", "correctPass", false)
	defer cleanupH3()

	p := models.NaiveProxyParams{
		Username: "wrongUser",
		Password: "wrongPass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = d.DialContext(ctx, "tcp", echoAddr)
	if err == nil {
		t.Fatal("expected dial error on proxy auth failure over H3, got nil")
	}
	if !strings.Contains(err.Error(), "status 407") {
		t.Fatalf("expected status 407 error, got: %v", err)
	}
}

func TestDialer_ConnClose_WriteError(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "u", "p", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	c, err := d.DialContext(context.Background(), "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))

	// Close conn
	if err := c.Close(); err != nil {
		t.Fatalf("Close conn: %v", err)
	}

	// Double close should succeed
	if err := c.Close(); err != nil {
		t.Fatalf("double close conn: %v", err)
	}

	// Write after close should return error
	_, err = c.Write([]byte("after close"))
	if err == nil {
		t.Fatal("expected error writing to closed conn, got nil")
	}
}

func TestDialer_H2_DialCtxCancelledAfterReturn(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: false}
	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := d.DialContext(dialCtx, "tcp", echoAddr)
	dialCancel() // Cancel dial context immediately after return (mirrors streambridge flows.go)

	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Verify that cancelling dialCtx did not abort the H2 stream
	time.Sleep(50 * time.Millisecond)
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	msg := []byte("payload after dial ctx cancel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write after dialCtx cancel: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read after dialCtx cancel: %v", err)
	}

	if !bytes.Equal(recv, msg) {
		t.Fatalf("payload mismatch: got %q, want %q", recv, msg)
	}
}

func TestDialer_H2_StreamTimeoutDoesNotKillSiblings(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: false}
	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	// Establish sibling connection on the pooled H2 conn
	c1, err := d.DialContext(context.Background(), "tcp", echoAddr)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer c1.Close()

	// Dial an unroutable target with a tight timeout to trigger a stream-level timeout
	// In the test fixture, net.DialTimeout to an unroutable IP hangs for 3s before 502
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	_, err = d.DialContext(ctx2, "tcp", "10.255.255.1:80")
	cancel2()
	if err == nil {
		t.Fatal("expected timed out dial to fail, got nil")
	}

	// Verify that c1 is still functional on the pooled H2 conn
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("sibling flow still alive after other stream timeout")
	if _, err := c1.Write(msg); err != nil {
		t.Fatalf("sibling write after other stream timeout: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(c1, recv); err != nil {
		t.Fatalf("sibling read after other stream timeout: %v", err)
	}

	if !bytes.Equal(recv, msg) {
		t.Fatalf("sibling payload mismatch: got %q, want %q", recv, msg)
	}
}

func TestDialer_H3_HonorsContextDeadlineOnSlowResponse(t *testing.T) {
	proxyAddr, cleanupH3 := setupTestH3Server(t, "testuser", "testpass", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: true}
	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	// Dial an unroutable target where upstream takes 3s, but caller ctx deadline is 300ms
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = d.DialContext(ctx, "tcp", "10.255.255.1:80")
	elapsed := time.Since(start)
	t.Logf("H3 slow upstream dial returned in: %v (err=%v)", elapsed, err)

	if err == nil {
		t.Fatal("expected dial to fail, got nil")
	}

	if elapsed > 1*time.Second {
		t.Fatalf("H3 dial did not honor 300ms context deadline: took %v", elapsed)
	}
}

func TestDialer_H3_PooledConnUDPDropFallback(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, drop, cleanupServer := setupDualStackH2H3Server(t, "testuser", "testpass")
	defer cleanupServer()

	p := models.NaiveProxyParams{Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: true}
	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	// 1. First dial over H3 through relay: succeeds and pools QUIC conn
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	c1, err := d.DialContext(ctx1, "tcp", echoAddr)
	cancel1()
	if err != nil {
		t.Fatalf("first dial (H3) failed: %v", err)
	}
	testMsg1 := []byte("first flow over H3")
	if _, err := c1.Write(testMsg1); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	recv1 := make([]byte, len(testMsg1))
	if _, err := io.ReadFull(c1, recv1); err != nil {
		t.Fatalf("c1 read: %v", err)
	}
	if !bytes.Equal(recv1, testMsg1) {
		t.Fatalf("c1 payload mismatch: got %q, want %q", recv1, testMsg1)
	}
	_ = c1.Close()

	// 2. Drop all UDP traffic through relay
	drop.Store(true)

	// 3. Second dial: tries H3 on pooled QUIC conn, aborts in 2s, falls back to H2 on same port
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()

	start := time.Now()
	c2, err := d.DialContext(ctx2, "tcp", echoAddr)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("second dial after UDP drop failed to fall back to H2: %v", err)
	}
	defer c2.Close()

	if elapsed > 4*time.Second {
		t.Fatalf("H3 fallback to H2 took too long (%v), exceeded H3 budget", elapsed)
	}

	testMsg2 := []byte("second flow over H2 fallback")
	if _, err := c2.Write(testMsg2); err != nil {
		t.Fatalf("c2 write over H2 fallback: %v", err)
	}
	recv2 := make([]byte, len(testMsg2))
	if _, err := io.ReadFull(c2, recv2); err != nil {
		t.Fatalf("c2 read over H2 fallback: %v", err)
	}
	if !bytes.Equal(recv2, testMsg2) {
		t.Fatalf("c2 payload mismatch: got %q, want %q", recv2, testMsg2)
	}
}

func TestDialer_H2_CloseWrite(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2Server(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: false}
	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	conn, err := d.DialContext(context.Background(), "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("h2Conn does not implement CloseWrite()")
	}

	msg := []byte("half-close test message H2")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if !bytes.Equal(recv, msg) {
		t.Fatalf("payload mismatch: got %q, want %q", recv, msg)
	}

	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}

	// Further writes must fail
	if _, err := conn.Write([]byte("extra data after CloseWrite")); err == nil {
		t.Fatal("expected write after CloseWrite to fail, got nil")
	}
}

func TestDialer_H3_CloseWrite(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH3 := setupTestH3Server(t, "testuser", "testpass", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{Username: "testuser", Password: "testpass", Domain: testCamouflageDomain, EnableH3: true}
	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	conn, err := d.DialContext(context.Background(), "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("h3Conn does not implement CloseWrite()")
	}

	msg := []byte("half-close test message H3")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read after CloseWrite: %v", err)
	}
	if !bytes.Equal(recv, msg) {
		t.Fatalf("payload mismatch: got %q, want %q", recv, msg)
	}

	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}
}
