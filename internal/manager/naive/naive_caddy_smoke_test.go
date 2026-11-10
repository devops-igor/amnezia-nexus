package naive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"go/build"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// findCaddyBinary locates a usable caddy executable. It fails the test immediately
// if caddy is not installed, preventing silent skipping in integration suites.
func findCaddyBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("CADDY_BIN"); bin != "" {
		if path, err := exec.LookPath(bin); err == nil {
			return path
		}
		if fi, err := os.Stat(bin); err == nil && !fi.IsDir() {
			return bin
		}
	}
	if path, err := exec.LookPath("caddy"); err == nil {
		return path
	}

	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	if gopath != "" {
		candidate := filepath.Join(gopath, "bin", "caddy")
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}

	home, err := os.UserHomeDir()
	if err == nil {
		candidate := filepath.Join(home, "go", "bin", "caddy")
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
		candidateLocal := filepath.Join(home, ".local", "bin", "caddy")
		if fi, err := os.Stat(candidateLocal); err == nil && !fi.IsDir() {
			return candidateLocal
		}
	}

	t.Fatalf("mandatory caddy binary not found in PATH or GOPATH/bin; integration smoke test requires caddy")
	return ""
}

// ensureCaddyHasForwardProxy verifies that the caddy binary has forward_proxy compiled in.
func ensureCaddyHasForwardProxy(t *testing.T, caddyPath string) {
	t.Helper()
	cmd := exec.Command(caddyPath, "list-modules")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to query caddy modules with %s: %v", caddyPath, err)
	}
	if !strings.Contains(string(out), "forward_proxy") {
		t.Fatalf("caddy binary at %s is missing forward_proxy plugin (modules: %s)", caddyPath, string(out))
	}
}

// getFreePort allocates a temporary free TCP loopback port.
func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// TestCaddyRuntimeSmoke_ConfigurationValidation verifies that Caddyfile configurations
// rendered for both production and decoy environments successfully pass real Caddyfile
// validation with forward_proxy enabled.
func TestCaddyRuntimeSmoke_ConfigurationValidation(t *testing.T) {
	caddyBin := findCaddyBinary(t)
	ensureCaddyHasForwardProxy(t, caddyBin)

	testCases := []struct {
		name    string
		port    int
		domain  string
		clients []NaiveClient
	}{
		{
			name:    "authenticated_production_443",
			port:    443,
			domain:  "vpn.prod.org",
			clients: []NaiveClient{{Username: "user1", Password: "secret_password_1"}},
		},
		{
			name:    "authenticated_custom_port_8443",
			port:    8443,
			domain:  "vpn.custom.org",
			clients: []NaiveClient{{Username: "user2", Password: "secret_password_2"}},
		},
		{
			name:    "decoy_site_zero_clients",
			port:    443,
			domain:  "vpn.prod.org",
			clients: nil,
		},
		{
			name:    "internal_tls_localhost",
			port:    18443,
			domain:  "localhost",
			clients: []NaiveClient{{Username: "localuser", Password: "localpassword"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			caddyfile := RenderCaddyfile(tc.port, tc.domain, tc.clients)

			tmp, err := os.CreateTemp("", "caddy-val-*.caddyfile")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			tmpPath := tmp.Name()
			defer os.Remove(tmpPath)

			if _, err := tmp.WriteString(caddyfile); err != nil {
				_ = tmp.Close()
				t.Fatalf("failed to write caddyfile: %v", err)
			}
			_ = tmp.Close()

			cmd := exec.Command(caddyBin, "validate", "--adapter", "caddyfile", "--config", tmpPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("caddy validate failed on %s: %v\nOutput:\n%s\nCaddyfile:\n%s",
					tc.name, err, string(out), caddyfile)
			}
		})
	}
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// caddyStderrBufferLimit caps how much child output is retained. `debug` logging
// is verbose, and a failing fixture must not grow the buffer without bound while
// it is being torn down.
const caddyStderrBufferLimit = 4 << 20

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := caddyStderrBufferLimit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	// Always report the full length consumed: a short Write would make the child
	// see an I/O error on its own stderr and change its behaviour.
	return len(p), nil
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Len reports the number of captured bytes. It is used to detect that the child
// has stopped producing output before a failure report is taken.
func (b *safeBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// caddyStartupBudget bounds the fixture's whole startup wait: the listener probe
// and the known-site TLS gate below share it.
const caddyStartupBudget = 15 * time.Second

// awaitKnownSiteTLS returns nil once one handshake on the configured site (known
// SNI) completes, which is when Caddy holds that site's certificate. The listener
// opens before the managed certificate reaches the cache, so a TCP accept is not TLS
// readiness. Every attempt and wait is bounded by what is left of the shared startup
// budget and by ctx: an exhausted budget or a cancelled caller neither dials nor
// reports readiness, and no attempt outlives the time it was given.
func awaitKnownSiteTLS(ctx context.Context, addr, site string, budget time.Duration) error {
	if budget <= 0 {
		return fmt.Errorf("no startup budget left for known-site TLS readiness of %q", site)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(budget)
	// Never nil: a gate that ran out of time before any attempt is a failure too.
	lastErr := fmt.Errorf("no TLS handshake for %q could start within %s", site, budget)
	// InsecureSkipVerify accepts the fixture's internal CA, as the assertions do.
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: site, InsecureSkipVerify: true}}
	for wait := 10 * time.Millisecond; ; wait = min(2*wait, 100*time.Millisecond) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return lastErr
		}
		// DialContext carries the handshake itself, closes the raw connection when
		// the handshake fails, and is bounded by what is left of the shared budget.
		attemptCtx, cancel := context.WithTimeout(ctx, remaining)
		conn, err := dialer.DialContext(attemptCtx, "tcp", addr)
		cancel()
		if err == nil {
			return conn.Close()
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(min(wait, time.Until(deadline))):
		}
	}
}

// tlsStallPeer listens but never accepts, so a client's TCP connect completes in the
// kernel backlog and its TLS handshake is never answered. The returned function
// reports whether any connection was queued, which proves a dial either happened or
// did not.
func tlsStallPeer(t *testing.T) (advertise string, dialed func() bool) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to open stall listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), func() bool {
		_ = ln.SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn, err := ln.Accept()
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}

// TestKnownSiteTLSReadiness_Controls pins the gate's outcomes. A ready endpoint
// passes; an exhausted budget, a cancelled caller, and a peer that accepts TCP but
// never answers TLS all fail, the last inside its real elapsed budget.
func TestKnownSiteTLSReadiness_Controls(t *testing.T) {
	ready := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ready.Close()
	if err := awaitKnownSiteTLS(context.Background(), ready.Listener.Addr().String(), "localhost", 5*time.Second); err != nil {
		t.Fatalf("gate rejected a ready TLS endpoint: %v", err)
	}

	// Neither an exhausted budget nor a cancelled caller may reach the peer at all.
	for _, tc := range []struct {
		name   string
		budget time.Duration
		ctx    func() context.Context
	}{
		{"exhausted budget", 0, func() context.Context { return context.Background() }},
		{"cancelled caller", 5 * time.Second, func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}},
	} {
		t.Run(tc.name+" does not dial", func(t *testing.T) {
			addr, dialed := tlsStallPeer(t)
			if err := awaitKnownSiteTLS(tc.ctx(), addr, "localhost", tc.budget); err == nil {
				t.Fatal("gate reported readiness without an attempt it was allowed to make")
			}
			if dialed() {
				t.Fatal("gate dialled when it had no attempt left to make")
			}
		})
	}

	t.Run("stalled TLS ends at the budget", func(t *testing.T) {
		addr, dialed := tlsStallPeer(t)
		const budget = 300 * time.Millisecond
		start := time.Now()
		err := awaitKnownSiteTLS(context.Background(), addr, "localhost", budget)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("gate reported readiness for a peer that never answered TLS")
		}
		// A fresh fixed per-attempt allowance overran this contract; the attempt is
		// bounded by what remains of the budget it was given.
		if elapsed <= budget/2 || elapsed > budget+250*time.Millisecond {
			t.Fatalf("gate did not honour a %s contract: gave up after %s", budget, elapsed)
		}
		if !dialed() {
			t.Fatal("control never reached the stalled listener")
		}
		t.Logf("stalled TLS: %v after %s", err, elapsed.Round(time.Millisecond))
	})
}

// TestCaddyRuntimeSmoke_ProbingDefenseAndProxyTunnel exercises the four mandatory
// runtime behaviors of the hardened Caddy deployment in Issue #684:
// 1. Caddy configuration validation passes for authenticated configurations.
// 2. Unknown/unrecognized SNI completes TLS handshake without alert.
// 3. Active HTTP probe requests return HTTP 404 without Server or Alt-Svc headers.
// 4. Authenticated CONNECT requests establish proxy tunnels; unauthenticated requests return 404.
func TestCaddyRuntimeSmoke_ProbingDefenseAndProxyTunnel(t *testing.T) {
	caddyBin := findCaddyBinary(t)
	ensureCaddyHasForwardProxy(t, caddyBin)

	proxyPort := getFreePort(t)
	adminPort := getFreePort(t)
	httpPort := getFreePort(t)

	clients := []NaiveClient{{Username: "testuser", Password: "testpassword"}}
	caddyfile := RenderCaddyfile(proxyPort, "localhost", clients)

	// Replace loopback admin port with allocated test port, specify http_port, and disable auto_https redirects to prevent 308 redirects.
	// Allow loopback in forward_proxy ACL for hermetic in-process fixture tunneling.
	//
	// `debug` is enabled so the child records the certificate cache and
	// certificate-selection decisions for each ClientHello; at the default info
	// level Caddy omits them, which is exactly the evidence a failed TLS
	// obligation needs. It changes no TLS or routing behaviour, and the failure
	// report whitelists what it may print.
	//
	// `skip_install_trust` is required rather than optional: TRUST_STORES=none in
	// the child environment does not stop Caddy from adding its internal root to
	// the user NSS database, so without this the fixture mutates the host trust
	// store on every local run. It changes no TLS, routing or assertion.
	caddyfile = strings.Replace(
		caddyfile,
		"admin 127.0.0.1:2019",
		fmt.Sprintf("admin 127.0.0.1:%d\n    http_port %d\n    auto_https disable_redirects\n    debug\n    skip_install_trust", adminPort, httpPort),
		1,
	)
	caddyfile = strings.Replace(
		caddyfile,
		"probe_resistance\n",
		"probe_resistance\n            acl {\n                allow 127.0.0.1\n            }\n",
		1,
	)

	tmp, err := os.CreateTemp("", "caddy-runtime-*.caddyfile")
	if err != nil {
		t.Fatalf("failed to create temp caddyfile: %v", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(caddyfile); err != nil {
		_ = tmp.Close()
		t.Fatalf("failed to write caddyfile: %v", err)
	}
	_ = tmp.Close()

	// 1. Validate in the fixture's own Caddy storage: no host CA, no cached cert.
	fixtureHome := t.TempDir()
	env := append(os.Environ(), "TRUST_STORES=none",
		"XDG_DATA_HOME="+fixtureHome, "XDG_CONFIG_HOME="+filepath.Join(fixtureHome, "config"))
	valCmd := exec.Command(caddyBin, "validate", "--adapter", "caddyfile", "--config", tmpPath)
	valCmd.Env = env
	if valOut, err := valCmd.CombinedOutput(); err != nil {
		t.Fatalf("pre-run caddy validate failed: %v\nOutput: %s", err, string(valOut))
	}

	// Launch Caddy process
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, caddyBin, "run", "--adapter", "caddyfile", "--config", tmpPath)
	cmd.Env = env
	var stderrBuf safeBuffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start caddy process: %v", err)
	}
	defer func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	// A subtest failure must leave behind why the child rejected the handshake.
	// The digest is taken while the child is still alive (subtest cleanups run
	// before the deferred kill above), and it is whitelisted so the CI log gains
	// certificate/handshake facts rather than raw paths or request headers.
	//
	// A subtest cleanup runs before the parent's, and a failed subtest also fails
	// the parent, so only the first failure reports. The digest holds the child's
	// whole timeline, so one report covers every obligation in the run.
	var (
		diagMu       sync.Mutex
		diagReported bool
	)
	reportOnFailure := func(t *testing.T, label string) {
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			diagMu.Lock()
			alreadyReported := diagReported
			diagReported = true
			diagMu.Unlock()
			if alreadyReported {
				return
			}
			// Let the child finish writing the record for the ClientHello that
			// just failed; the child is still alive here, so its final line is
			// normally already in flight.
			waitForCaddyStderrSettled(&stderrBuf, 40*time.Millisecond, 2*time.Second)
			reportCaddyDiagnostics(t, label, &stderrBuf)
		})
	}
	// The parent covers a failure that stops the run before any subtest starts,
	// such as the TCP listener never becoming ready.
	reportOnFailure(t, "fixture")

	// Wait for Caddy to start listening on proxyPort; the gate below shares this
	// one startup allowance, so it cannot extend how long the fixture waits.
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	startupDeadline := time.Now().Add(caddyStartupBudget)
	ready := false
	for time.Now().Before(startupDeadline) {
		conn, dialErr := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("caddy failed to listen on %s within %s. Stderr: %s", proxyAddr, caddyStartupBudget, stderrBuf.String())
	}

	// A TCP accept is not TLS readiness: Caddy opens the HTTPS listener before the
	// managed certificate reaches the cache, so a ClientHello inside that window is
	// rejected for every SNI. Wait for the configured site (known SNI "localhost") to
	// complete one handshake, which means the certificate is cached. The four
	// assertions below are unchanged and none runs before this gate.
	if err := awaitKnownSiteTLS(ctx, proxyAddr, "localhost", time.Until(startupDeadline)); err != nil {
		t.Fatalf("caddy did not become TLS-ready for the configured site on %s: %v", proxyAddr, err)
	}

	baseTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // Internal self-signed testing CA
	}

	// 2. Unknown-SNI TLS handshake completion
	t.Run("UnknownSNI_CompletesHandshakeWithoutAlert", func(t *testing.T) {
		reportOnFailure(t, "UnknownSNI_CompletesHandshakeWithoutAlert")
		conf := baseTLSConfig.Clone()
		conf.ServerName = "unrecognized.random-sni.net"

		conn, err := tls.Dial("tcp", proxyAddr, conf)
		if err != nil {
			t.Fatalf("unknown-SNI TLS handshake failed: %v", err)
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if !state.HandshakeComplete {
			t.Error("TLS handshake did not complete for unknown SNI")
		}
	})

	// 3. Active HTTP probe returns HTTP 404 without Server or Alt-Svc headers
	t.Run("ActiveProbe_Returns404WithCamouflagedHeaders", func(t *testing.T) {
		reportOnFailure(t, "ActiveProbe_Returns404WithCamouflagedHeaders")
		conf := baseTLSConfig.Clone()
		conf.ServerName = "unrecognized.random-sni.net"

		conn, err := tls.Dial("tcp", proxyAddr, conf)
		if err != nil {
			t.Fatalf("tls dial failed: %v", err)
		}
		defer conn.Close()

		probeReq := "GET / HTTP/1.1\r\nHost: 198.51.100.1\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(probeReq)); err != nil {
			t.Fatalf("failed to send probe request: %v", err)
		}

		reader := bufio.NewReader(conn)
		req, _ := http.NewRequest("GET", "http://198.51.100.1/", nil)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("failed to read probe response: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", resp.StatusCode)
		}
		if serverHdr := resp.Header.Get("Server"); serverHdr != "" {
			t.Errorf("expected Server header to be suppressed, got %q", serverHdr)
		}
		if altSvcHdr := resp.Header.Get("Alt-Svc"); altSvcHdr != "" {
			t.Errorf("expected Alt-Svc header to be suppressed, got %q", altSvcHdr)
		}
	})

	// In-process HTTP fixture for hermetic proxy tunnel destination
	const echoBody = "hermetic-connect-test-payload"
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(echoBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer echoServer.Close()
	echoAddr := echoServer.Listener.Addr().String()

	// 4a. Probe resistance: unauthenticated CONNECT returns 404 (not 407)
	t.Run("ProbeResistance_UnauthenticatedCONNECTReturns404", func(t *testing.T) {
		reportOnFailure(t, "ProbeResistance_UnauthenticatedCONNECTReturns404")
		conf := baseTLSConfig.Clone()
		conf.ServerName = "localhost"

		conn, err := tls.Dial("tcp", proxyAddr, conf)
		if err != nil {
			t.Fatalf("tls dial failed: %v", err)
		}
		defer conn.Close()

		hostHeader := fmt.Sprintf("localhost:%d", proxyPort)
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr, hostHeader)
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			t.Fatalf("failed to send CONNECT request: %v", err)
		}

		reader := bufio.NewReader(conn)
		req, _ := http.NewRequest("CONNECT", "http://"+echoAddr, nil)
		req.Host = hostHeader
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("failed to read unauthenticated CONNECT response: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusProxyAuthRequired {
			t.Fatalf("probe resistance failed: server returned 407 Proxy Authentication Required")
		}
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusPermanentRedirect {
			t.Errorf("expected probe resistance to conceal proxy (404 Not Found or 308 Decoy Redirect), got %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusPermanentRedirect && resp.Header.Get("Location") != "/" {
			t.Errorf("expected 308 redirect location to be '/', got %q", resp.Header.Get("Location"))
		}
	})

	// 4b. Authenticated CONNECT successfully establishes proxy tunnel
	t.Run("AuthenticatedCONNECT_EstablishesProxyTunnel", func(t *testing.T) {
		reportOnFailure(t, "AuthenticatedCONNECT_EstablishesProxyTunnel")
		conf := baseTLSConfig.Clone()
		conf.ServerName = "localhost"

		conn, err := tls.Dial("tcp", proxyAddr, conf)
		if err != nil {
			t.Fatalf("tls dial failed: %v", err)
		}
		defer conn.Close()

		auth := base64.StdEncoding.EncodeToString([]byte("testuser:testpassword"))
		connectReq := fmt.Sprintf(
			"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			echoAddr,
			echoAddr,
			auth,
		)
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			t.Fatalf("failed to write authenticated CONNECT: %v", err)
		}

		reader := bufio.NewReader(conn)
		req, _ := http.NewRequest("CONNECT", "http://"+echoAddr, nil)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("failed to read authenticated CONNECT response: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK for authenticated CONNECT, got %d", resp.StatusCode)
		}
		if padding := resp.Header.Get("Padding"); padding == "" {
			t.Error("expected probe resistance Padding header in CONNECT response")
		}

		// Exercise bidirectional tunnel traffic to local in-process HTTP fixture
		getReq := fmt.Sprintf("GET /echo HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr)
		if _, err := conn.Write([]byte(getReq)); err != nil {
			t.Fatalf("failed to send payload through tunnel: %v", err)
		}

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		targetReq, _ := http.NewRequest("GET", "http://"+echoAddr+"/echo", nil)
		targetResp, err := http.ReadResponse(reader, targetReq)
		if err != nil {
			t.Fatalf("failed to read response from local fixture through tunnel: %v", err)
		}
		defer targetResp.Body.Close()

		if targetResp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK from local fixture, got %d", targetResp.StatusCode)
		}

		body, err := io.ReadAll(targetResp.Body)
		if err != nil {
			t.Fatalf("failed to read payload from local fixture: %v", err)
		}
		if string(body) != echoBody {
			t.Fatalf("expected payload %q from local fixture, got %q", echoBody, string(body))
		}
	})
}
