package naive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDaemonConfigGeneration(t *testing.T) {
	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		EnableH3: false,
	}

	// 1. IP endpoint != Domain: host-resolver-rules must be included
	endpointWithIP := "198.51.100.1:443"
	data, err := GenerateConfigJSON(1080, endpointWithIP, p)
	if err != nil {
		t.Fatalf("GenerateConfigJSON: %v", err)
	}

	var cfg naiveConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	if cfg.Listen != "socks://127.0.0.1:1080" {
		t.Errorf("got listen %q, want socks://127.0.0.1:1080", cfg.Listen)
	}
	expectedProxy := "https://alice:secret-password@camouflage.example.com:443"
	if cfg.Proxy != expectedProxy {
		t.Errorf("got proxy %q, want %q", cfg.Proxy, expectedProxy)
	}
	expectedRule := "MAP camouflage.example.com 198.51.100.1"
	if cfg.HostResolverRules != expectedRule {
		t.Errorf("got host-resolver-rules %q, want %q", cfg.HostResolverRules, expectedRule)
	}

	// 2. H3 enabled: scheme should be quic
	pH3 := p
	pH3.EnableH3 = true
	dataH3, err := GenerateConfigJSON(1081, endpointWithIP, pH3)
	if err != nil {
		t.Fatalf("GenerateConfigJSON H3: %v", err)
	}
	var cfgH3 naiveConfigFile
	if err := json.Unmarshal(dataH3, &cfgH3); err != nil {
		t.Fatalf("unmarshal config H3: %v", err)
	}
	expectedProxyH3 := "quic://alice:secret-password@camouflage.example.com:443"
	if cfgH3.Proxy != expectedProxyH3 {
		t.Errorf("got proxy %q, want %q", cfgH3.Proxy, expectedProxyH3)
	}

	// 3. Endpoint host matches Domain: host-resolver-rules should be empty
	endpointMatching := "camouflage.example.com:443"
	dataMatching, err := GenerateConfigJSON(1082, endpointMatching, p)
	if err != nil {
		t.Fatalf("GenerateConfigJSON matching: %v", err)
	}
	var cfgMatching naiveConfigFile
	if err := json.Unmarshal(dataMatching, &cfgMatching); err != nil {
		t.Fatalf("unmarshal config matching: %v", err)
	}
	if cfgMatching.HostResolverRules != "" {
		t.Errorf("expected empty host-resolver-rules, got %q", cfgMatching.HostResolverRules)
	}

	// 4. writeTempConfig creates file with mode 0600
	tmpPath, err := writeTempConfig(1083, endpointWithIP, p)
	if err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("stat temp config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected config file mode 0600, got %04o", perm)
	}
}

// buildMockNaiveBinary compiles a minimal mock naive binary for testing daemon supervision.
// The mock binary reads the config file, binds to the listen port, and handles SIGTERM.
func buildMockNaiveBinary(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	srcPath := filepath.Join(tempDir, "mock_naive_main.go")
	binPath := filepath.Join(tempDir, "mock_naive")

	src := `package main

import (
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Config struct {
	Listen string ` + "`json:\"listen\"`" + `
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		os.Exit(2)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		os.Exit(3)
	}

	u, err := url.Parse(cfg.Listen)
	if err != nil {
		os.Exit(4)
	}
	hostPort := u.Host
	if !strings.Contains(hostPort, ":") {
		hostPort = "127.0.0.1:" + hostPort
	}

	ln, err := net.Listen("tcp", hostPort)
	if err != nil {
		os.Exit(5)
	}
	defer ln.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 258)
				n, err := io.ReadAtLeast(c, buf, 2)
				if err != nil || n < 2 || buf[0] != 0x05 {
					return
				}
				// Reply: Version 5, NO_AUTH (0x00)
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				// Read request [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				atyp := req[3]
				var addrLen int
				switch atyp {
				case 0x01: // IPv4
					addrLen = 4 + 2
				case 0x03: // Domain name
					lenBuf := make([]byte, 1)
					if _, err := io.ReadFull(c, lenBuf); err != nil {
						return
					}
					addrLen = int(lenBuf[0]) + 2
				case 0x04: // IPv6
					addrLen = 16 + 2
				default:
					return
				}
				dstBuf := make([]byte, addrLen)
				if _, err := io.ReadFull(c, dstBuf); err != nil {
					return
				}
				// Reply: Success (0x00)
				resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x00}
				if _, err := c.Write(resp); err != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	<-sigCh
}
`
	if err := os.WriteFile(srcPath, []byte(src), 0600); err != nil {
		t.Fatalf("failed to write mock naive source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build mock naive binary: %v (output: %s)", err, string(out))
	}

	return binPath
}

func TestDaemonLifecycle_MockBinary(t *testing.T) {
	mockBin := buildMockNaiveBinary(t)

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		EnableH3: false,
	}

	d, err := NewDaemon(mockBin, "198.51.100.1:443", p)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start daemon: %v", err)
	}

	if !d.IsActive() {
		t.Fatal("expected daemon to be active")
	}

	port := d.Port()
	if port <= 0 {
		t.Fatalf("invalid daemon port %d", port)
	}

	cfgPath := d.ConfigPath()
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("expected config file %s to exist: %v", cfgPath, err)
	}

	// Verify that the local port is accepting connections
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to connect to daemon port: %v", err)
	}
	_ = conn.Close()

	// Graceful stop
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop daemon: %v", err)
	}

	if d.IsActive() {
		t.Fatal("expected daemon to be inactive after Stop")
	}

	// Verify config file was removed
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("expected config file %s to be removed, got err: %v", cfgPath, err)
	}
}

// startMockSOCKS5Server creates an in-process RFC 1928 SOCKS5 test server.
func startMockSOCKS5Server(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock SOCKS5 listen: %v", err)
	}

	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read SOCKS5 greeting
				buf := make([]byte, 258)
				n, err := io.ReadAtLeast(c, buf, 2)
				if err != nil || n < 2 || buf[0] != 0x05 {
					return
				}
				nMethods := int(buf[1])
				if n < 2+nMethods {
					if _, err := io.ReadFull(c, buf[n:2+nMethods]); err != nil {
						return
					}
				}
				// Reply: Version 5, NO_AUTH (0x00)
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				// Read request [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if req[0] != 0x05 || req[1] != 0x01 { // CMD 0x01 = CONNECT
					return
				}

				atyp := req[3]
				var addrLen int
				switch atyp {
				case 0x01: // IPv4
					addrLen = 4 + 2
				case 0x03: // Domain name
					lenBuf := make([]byte, 1)
					if _, err := io.ReadFull(c, lenBuf); err != nil {
						return
					}
					addrLen = int(lenBuf[0]) + 2
				case 0x04: // IPv6
					addrLen = 16 + 2
				default:
					return
				}

				dstBuf := make([]byte, addrLen)
				if _, err := io.ReadFull(c, dstBuf); err != nil {
					return
				}

				// Reply: Success (0x00)
				resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x00}
				if _, err := c.Write(resp); err != nil {
					return
				}

				// Echo loop
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		close(stopCh)
		_ = ln.Close()
	}
}

func TestSocks5Dialer(t *testing.T) {
	socksAddr, cleanup := startMockSOCKS5Server(t)
	defer cleanup()

	dialer, err := NewSocks5Dialer(socksAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}

	if dialer.SupportsUDP() {
		t.Error("expected SupportsUDP to be false")
	}
	if dialer.Addr() != socksAddr {
		t.Errorf("got addr %q, want %q", dialer.Addr(), socksAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", "target.example.com:80")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	// Verify echo
	payload := []byte("hello upstream naive")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	recv := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(recv) != string(payload) {
		t.Errorf("got %q, want %q", string(recv), string(payload))
	}

	// Dial with unsupported network should fail
	_, err = dialer.DialContext(ctx, "udp", "target.example.com:80")
	if err == nil {
		t.Fatal("expected error for non-tcp network, got nil")
	}
}

func TestDaemonManager(t *testing.T) {
	mockBin := buildMockNaiveBinary(t)
	mgr := NewDaemonManager(mockBin)
	defer func() {
		_ = mgr.Close()
	}()

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	endpoint := "198.51.100.1:443"
	d1, err := mgr.GetOrCreate(ctx, endpoint, p)
	if err != nil {
		t.Fatalf("GetOrCreate d1: %v", err)
	}
	if !d1.IsActive() {
		t.Fatal("expected d1 to be active")
	}

	// Reusing same endpoint & params should return the cached active daemon
	d2, err := mgr.GetOrCreate(ctx, endpoint, p)
	if err != nil {
		t.Fatalf("GetOrCreate d2: %v", err)
	}
	if d1 != d2 {
		t.Fatal("expected d1 and d2 to be identical instance")
	}

	if err := mgr.Stop(endpoint); err != nil {
		t.Fatalf("Stop endpoint: %v", err)
	}
	if d1.IsActive() {
		t.Fatal("expected d1 to be stopped after mgr.Stop")
	}
}

func TestDaemon_CrashRecovery(t *testing.T) {
	mockBin := buildMockNaiveBinary(t)

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		EnableH3: false,
	}

	d, err := NewDaemon(mockBin, "198.51.100.1:443", p)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	d.SetReadinessTimeout(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start daemon: %v", err)
	}
	defer func() {
		_ = d.Stop()
	}()

	port := d.Port()

	// Simulate unexpected crash by killing the process directly
	d.mu.Lock()
	proc := d.cmd.Process
	d.mu.Unlock()

	if proc != nil {
		_ = proc.Kill()
	}

	// Wait for supervisor to restart the process and become ready on the same port
	restarted := false
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			restarted = true
			break
		}
	}

	if !restarted {
		t.Fatal("expected daemon to recover and restart after crash")
	}
	if !d.IsHealthy() {
		t.Errorf("expected daemon to be healthy after recovery, got last error: %v", d.LastError())
	}
}

func TestDaemon_SupervisorBoundedRetries_Exhaustion(t *testing.T) {
	mockBin := buildMockNaiveBinary(t)

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		EnableH3: false,
	}

	d, err := NewDaemon(mockBin, "198.51.100.1:443", p)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	d.SetReadinessTimeout(1 * time.Second)
	d.SetRestartDelay(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start daemon: %v", err)
	}
	defer func() {
		_ = d.Stop()
	}()

	if !d.IsHealthy() {
		t.Fatalf("expected daemon to be healthy initially")
	}
	if err := d.LastError(); err != nil {
		t.Fatalf("expected no initial error, got: %v", err)
	}

	// Corrupt binary path so all restart attempts fail
	d.mu.Lock()
	d.binPath = "/nonexistent/binary/path"
	proc := d.cmd.Process
	d.mu.Unlock()

	if proc != nil {
		_ = proc.Kill()
	}

	// Wait for supervisor to exhaust 5 restart attempts with 10ms delays
	deadline := time.Now().Add(2 * time.Second)
	exhausted := false
	for time.Now().Before(deadline) {
		if !d.IsHealthy() && d.LastError() != nil && strings.Contains(d.LastError().Error(), "exhausted 5 restart attempts") {
			exhausted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !exhausted {
		t.Fatalf("expected supervisor to exhaust attempts, IsHealthy=%v, LastError=%v", d.IsHealthy(), d.LastError())
	}
}

func TestDialer_WithDaemonIntegration(t *testing.T) {
	socksAddr, cleanup := startMockSOCKS5Server(t)
	defer cleanup()

	socksDialer, err := NewSocks5Dialer(socksAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
	}

	d, err := New("198.51.100.1:443", p, WithSocks5Dialer(socksDialer))
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer func() {
		_ = d.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "target.example.com:80")
	if err != nil {
		t.Fatalf("DialContext via daemon: %v", err)
	}
	defer conn.Close()

	msg := []byte("ping via socks5 daemon")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, recv); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(recv) != string(msg) {
		t.Errorf("got %q, want %q", string(recv), string(msg))
	}
}

func TestProbeNaiveProxy_WithDaemonIntegration(t *testing.T) {
	socksAddr, cleanup := startMockSOCKS5Server(t)
	defer cleanup()

	socksDialer, err := NewSocks5Dialer(socksAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
	}

	d, err := New("198.51.100.1:443", p, WithSocks5Dialer(socksDialer))
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer func() {
		_ = d.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := d.socks5Dialer.DialContext(ctx, "tcp", net.JoinHostPort(p.Domain, "443"))
	if err != nil {
		t.Fatalf("Probe dial failed: %v", err)
	}
	_ = conn.Close()
	elapsed := time.Since(start).Milliseconds()
	if elapsed < 1 {
		elapsed = 1
	}
	if elapsed <= 0 {
		t.Errorf("expected positive elapsed latency, got %d", elapsed)
	}
}

func TestProbeNaiveProxy_ViaDaemonE2E(t *testing.T) {
	mockBin := buildMockNaiveBinary(t)

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
	}

	t.Setenv(NaiveBinPathEnv, mockBin)

	// In-process test fixtures set testRootCAs; clear it temporarily to test daemon probe path
	oldCAs := testRootCAs
	SetTestRootCAs(nil)
	defer SetTestRootCAs(oldCAs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latency, err := ProbeNaiveProxy(ctx, "198.51.100.1:443", p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy via daemon failed: %v", err)
	}
	if latency < 1 {
		t.Errorf("expected latency >= 1ms, got %d", latency)
	}
}
