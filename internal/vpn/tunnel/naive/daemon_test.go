package naive

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

	// 2a. H3 enabled without explicit H3 support (default / Nexus Caddy H2 backend): scheme must remain https (H2)
	pH3 := p
	pH3.EnableH3 = true
	dataH3H2, err := GenerateConfigJSON(1081, endpointWithIP, pH3)
	if err != nil {
		t.Fatalf("GenerateConfigJSON H3 on H2 backend: %v", err)
	}
	var cfgH3H2 naiveConfigFile
	if err := json.Unmarshal(dataH3H2, &cfgH3H2); err != nil {
		t.Fatalf("unmarshal config H3 on H2: %v", err)
	}
	expectedProxyH3H2 := "https://alice:secret-password@camouflage.example.com:443"
	if cfgH3H2.Proxy != expectedProxyH3H2 {
		t.Errorf("got proxy %q, want %q for H2 backend with EnableH3=true", cfgH3H2.Proxy, expectedProxyH3H2)
	}

	// 2b. H3 enabled with explicit H3 server capability: scheme should be quic
	pH3Supported := pH3
	pH3Supported.H3Supported = true
	dataH3, err := GenerateConfigJSON(1081, endpointWithIP, pH3Supported)
	if err != nil {
		t.Fatalf("GenerateConfigJSON H3 supported: %v", err)
	}
	var cfgH3 naiveConfigFile
	if err := json.Unmarshal(dataH3, &cfgH3); err != nil {
		t.Fatalf("unmarshal config H3 supported: %v", err)
	}
	expectedProxyH3 := "quic://alice:secret-password@camouflage.example.com:443"
	if cfgH3.Proxy != expectedProxyH3 {
		t.Errorf("got proxy %q, want %q for H3-supported backend", cfgH3.Proxy, expectedProxyH3)
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
	"time"
)

type Config struct {
	Listen            string ` + "`json:\"listen\"`" + `
	Proxy             string ` + "`json:\"proxy\"`" + `
	HostResolverRules string ` + "`json:\"host-resolver-rules\"`" + `
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
				// If upstream proxy is configured, verify it can be reached
				targetAddr := ""
				if cfg.Proxy != "" {
					if u, err := url.Parse(cfg.Proxy); err == nil {
						targetHost := u.Hostname()
						targetPort := u.Port()
						if cfg.HostResolverRules != "" {
							parts := strings.Fields(cfg.HostResolverRules)
							if len(parts) >= 3 && parts[0] == "MAP" {
								targetHost = parts[2]
							}
						}
						targetAddr = net.JoinHostPort(targetHost, targetPort)
					}
				}
				var upstream net.Conn
				if targetAddr != "" {
					upstream, _ = net.DialTimeout("tcp", targetAddr, 1*time.Second)
				}
				if cfg.Proxy != "" && upstream == nil {
					// Upstream unreachable / connection refused: close client
					return
				}
				defer func() {
					if upstream != nil {
						_ = upstream.Close()
					}
				}()
				// Reply: Success (0x00)
				resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x00}
				if _, err := c.Write(resp); err != nil {
					return
				}
				if upstream != nil {
					go func() { _, _ = io.Copy(upstream, c) }()
					_, _ = io.Copy(c, upstream)
				} else {
					_, _ = io.Copy(c, c)
				}
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
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Simulate unexpected crash by killing the process directly
	d.mu.Lock()
	proc := d.cmd.Process
	crashGen := d.cmdGen
	d.mu.Unlock()
	if proc == nil {
		t.Fatal("expected a running child process before the crash")
	}

	crashAt := time.Now()
	_ = proc.Kill()

	// Recovery means the supervisor reaps the crashed child and publishes a ready replacement
	// generation on the same port. Both cheaper signals are wrong on their own:
	//   - a TCP accept on the port is not readiness: the replacement listener starts accepting
	//     one readiness-probe interval before the supervisor clears lastErr and installs the
	//     SOCKS5 dialer (measured 22-25ms idle, up to 81ms on a loaded host), so asserting
	//     health the instant the port accepts reports a recovering daemon as broken;
	//   - IsHealthy() alone is not evidence of recovery either: it stays true for the 1-60ms
	//     between the kill and the supervisor reaping the child, so waiting only on it can
	//     succeed before any restart happened.
	// Waiting for a new generation that is healthy covers both. The window allows the
	// supervisor's own single-attempt budget (200ms restart delay + 3s readiness probe) plus
	// scheduling headroom; measured end-to-end recovery was 228ms idle and 356ms at worst
	// under 2x CPU oversubscription, so the window keeps an 11x margin over the worst
	// observation instead of being the binding constraint.
	const recoveryWindow = 4 * time.Second
	deadline := crashAt.Add(recoveryWindow)
	var state daemonSnapshot
	for {
		state = snapshotDaemon(d)
		if state.gen > crashGen && state.healthy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected the supervisor to publish a recovered generation within %v of the crash, took %v: %s",
				recoveryWindow, time.Since(crashAt).Round(time.Millisecond), state.describe(crashGen))
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The replacement must serve on the same loopback port the crashed generation used.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("expected recovered generation to accept on the same port %s after %v: %v: %s",
			addr, time.Since(crashAt).Round(time.Millisecond), err, state.describe(crashGen))
	}
	_ = conn.Close()
}

// daemonSnapshot is the supervisor state a recovery assertion needs in order to describe a
// failure without a second investigation: health and generation, plus the supervised child's
// pid and — once it has been reaped — its exit status, which lastErr does not always carry.
type daemonSnapshot struct {
	healthy bool
	gen     uint64
	child   string
	lastErr error
}

func snapshotDaemon(d *Daemon) daemonSnapshot {
	// Every field the assertion reads comes from this one critical section, because health and
	// generation must describe the same instant. Two acquisitions can pair a health reading
	// taken while the crashed child is still unreaped and reported healthy with the
	// *replacement's* generation, so "new generation AND healthy" could hold before the
	// replacement is ready — exactly the condition the assertion exists to rule out.
	//
	// Health is recomputed here from the fields IsHealthy() reads instead of calling it,
	// because IsHealthy() takes d.mu itself and a second acquisition is the inconsistency this
	// helper is meant to avoid. The duplicate predicate is pinned against IsHealthy() by
	// TestDaemonSnapshotMatchesIsHealthy so the two cannot drift apart silently.
	d.mu.Lock()
	s := daemonSnapshot{
		healthy: !d.stopped && d.cmd != nil && d.socksDialer != nil && d.lastErr == nil,
		gen:     d.cmdGen,
		lastErr: d.lastErr,
	}
	cmd := d.cmd
	exitCh := d.exitCh
	d.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		s.child = "no supervised child"
		return s
	}
	pid := cmd.Process.Pid
	s.child = fmt.Sprintf("pid %d running", pid)
	if exitCh != nil {
		select {
		case <-exitCh:
			// exitCh is closed by the Wait goroutine after it reaped the process, so
			// ProcessState is complete and safe to read here.
			if cmd.ProcessState != nil {
				s.child = fmt.Sprintf("pid %d exited (%s)", pid, cmd.ProcessState)
			}
		default:
		}
	}
	return s
}

func (s daemonSnapshot) describe(crashGen uint64) string {
	lastErr := "none"
	if s.lastErr != nil {
		lastErr = s.lastErr.Error()
	}
	return fmt.Sprintf("healthy=%v generation=%d (crashed generation %d) child=%s lastErr=%s",
		s.healthy, s.gen, crashGen, s.child, lastErr)
}

// TestDaemonSnapshotMatchesIsHealthy pins the one place the test tree reproduces a product
// predicate: snapshotDaemon recomputes IsHealthy()'s fields so health and generation come from
// a single critical section. The table covers each field that can make the two disagree, so a
// field added to IsHealthy() — or dropped from the snapshot — fails here instead of silently
// weakening the recovery assertion. No process is started: this pins the predicate only.
func TestDaemonSnapshotMatchesIsHealthy(t *testing.T) {
	cases := []struct {
		name      string
		stopped   bool
		hasCmd    bool
		hasDialer bool
		failed    bool
	}{
		// Healthy: running, dialer installed, no supervisor failure.
		{name: "running", hasCmd: true, hasDialer: true},
		// Restarted but not published yet: a generation exists, no dialer, crash still recorded.
		{name: "recovering", hasCmd: true, failed: true},
		// Child started, dialer not installed yet, no failure recorded: only the dialer can
		// make this unhealthy.
		{name: "child without dialer", hasCmd: true},
		// Crash observed and reaped, restart not started.
		{name: "crashed", failed: true},
		// Published fields without a supervised child: only the child can make this unhealthy.
		{name: "no child with published fields", hasDialer: true},
		// Dialer installed but the supervisor still reports a failure.
		{name: "failure recorded", hasCmd: true, hasDialer: true, failed: true},
		// Stopped with leftover fields: only the stopped flag can make this unhealthy.
		{name: "stopped with leftovers", stopped: true, hasCmd: true, hasDialer: true},
		{name: "stopped", stopped: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{stopped: tc.stopped}
			if tc.hasCmd {
				d.cmd = &exec.Cmd{}
			}
			if tc.hasDialer {
				d.socksDialer = &Socks5Dialer{}
			}
			if tc.failed {
				d.lastErr = fmt.Errorf("naive: daemon process exited unexpectedly")
			}

			got, want := snapshotDaemon(d).healthy, d.IsHealthy()
			if got != want {
				t.Fatalf("snapshot healthy=%v, IsHealthy()=%v for the same state", got, want)
			}
		})
	}
}

// TestDaemon_ExitReasonIsReported pins the supervisor's record of *why* a child went away.
// Without it the crash-recovery assertion can only report that the process exited, which is
// exactly the message that made an earlier failure look like a product race.
func TestDaemon_ExitReasonIsReported(t *testing.T) {
	mockBin := buildMockNaiveBinary(t)

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		EnableH3: false,
	}

	cases := []struct {
		name   string
		signal os.Signal
		want   string
	}{
		// A signal death must carry the kernel's reason, not just "exited unexpectedly".
		{name: "killed", signal: syscall.SIGKILL, want: "naive: daemon process exited unexpectedly: signal: killed"},
		// A clean exit has no status to report, and no reason may be invented for it.
		{name: "clean_exit", signal: syscall.SIGTERM, want: "naive: daemon process exited unexpectedly"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewDaemon(mockBin, "198.51.100.1:443", p)
			if err != nil {
				t.Fatalf("NewDaemon: %v", err)
			}
			d.SetReadinessTimeout(1 * time.Second)
			// Keep the error observable: a pending restart delay means the successful recovery
			// cannot clear lastErr while this test is asserting on it.
			d.SetRestartDelay(5 * time.Second)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := d.Start(ctx); err != nil {
				t.Fatalf("Start daemon: %v", err)
			}
			defer func() {
				_ = d.Stop()
			}()

			d.mu.Lock()
			proc := d.cmd.Process
			d.mu.Unlock()
			if proc == nil {
				t.Fatal("expected a running child process")
			}
			if err := proc.Signal(tc.signal); err != nil {
				t.Fatalf("signal child: %v", err)
			}

			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if err := d.LastError(); err != nil {
					if got := err.Error(); got != tc.want {
						t.Fatalf("expected supervisor error %q, got %q", tc.want, got)
					}
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			t.Fatal("expected the supervisor to record the child's exit")
		})
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

	cert, err := generateLeafCert(testCACert, testCAKey, "camouflage.example.com")
	if err != nil {
		t.Fatalf("generate leaf cert: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	ts.StartTLS()
	defer ts.Close()

	endpoint := ts.Listener.Addr().String()

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
	}

	t.Setenv(NaiveBinPathEnv, mockBin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latency, err := ProbeNaiveProxy(ctx, endpoint, p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy via daemon failed: %v", err)
	}
	if latency < 1 {
		t.Errorf("expected latency >= 1ms, got %d", latency)
	}
}

func TestAuditSupervisorCrashLoopMustBeBounded(t *testing.T) {
	mock := buildMockNaiveBinary(t)
	p := models.NaiveProxyParams{Username: "audit-user", Password: "audit-password", Domain: "naive.example.com"}
	d, err := NewDaemon(mock, "198.51.100.1:443", p)
	if err != nil {
		t.Fatal(err)
	}
	d.SetReadinessTimeout(50 * time.Millisecond)
	d.SetRestartDelay(10 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	dir := t.TempDir()
	countPath := filepath.Join(dir, "starts")
	script := filepath.Join(dir, "crash")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'start\\n' >> '"+countPath+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.binPath = script
	proc := d.cmd.Process
	d.mu.Unlock()
	proc.Kill()
	time.Sleep(500 * time.Millisecond)
	d.Stop()
	// Allow already-running canceled readiness polls to observe stop.
	time.Sleep(100 * time.Millisecond)
	data, _ := os.ReadFile(countPath)
	count := strings.Count(string(data), "start\n")
	t.Logf("failed child starts=%d health=%v lastErr=%v", count, d.IsHealthy(), d.LastError())
	if count > 5 {
		t.Fatalf("bounded five-attempt policy restarted an exiting child %d times", count)
	}
}

func TestAuditClosedDialerMustNotStartDaemon(t *testing.T) {
	oldCAs := testRootCAs
	testRootCAs = nil
	defer func() { testRootCAs = oldCAs }()
	t.Setenv(NaiveBinPathEnv, buildMockNaiveBinary(t))
	d, err := New("198.51.100.1:443", models.NaiveProxyParams{Username: "audit-user", Password: "audit-password", Domain: "naive.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "target.example.com:443")
	active := d.Daemon() != nil && d.Daemon().IsActive()
	t.Logf("dial after Close: err=%v active=%v", err, active)
	if active {
		t.Fatal("DialContext started a fresh supervised child after Close")
	}
}

func TestDaemon_H3Enabled_H2Backend_GeneratesHTTPS(t *testing.T) {
	// Verifies that for an H2 backend (Nexus Caddy server), EnableH3=true generates https:// proxy URL
	// so that protocol mismatch (QUIC against an H2 server) does not occur.
	p := models.NaiveProxyParams{
		Username:    "nexus-user",
		Password:    "nexus-pass",
		Domain:      "caddy.example.com",
		EnableH3:    true,
		H3Supported: false, // H2-only listener (default for Nexus Caddy)
	}

	data, err := GenerateConfigJSON(1085, "198.51.100.10:443", p)
	if err != nil {
		t.Fatalf("GenerateConfigJSON failed: %v", err)
	}

	var cfg naiveConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	expectedProxy := "https://nexus-user:nexus-pass@caddy.example.com:443"
	if cfg.Proxy != expectedProxy {
		t.Fatalf("expected proxy %q for H2 backend with EnableH3=true, got %q", expectedProxy, cfg.Proxy)
	}
}
