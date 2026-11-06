//go:build with_utls

package naive

// R12 — authentic whole-flow qualification coverage for NaiveProxy.
//
// ORIGINAL OBLIGATION (issue #703 work9 / Tests): real selected-protocol traffic
// must be proven before a backend may be used; the Tests require a real
// selected-protocol request/reply integration test.
//
// This test reuses the repository's EXISTING authentic fixture stack — real Caddy
// with forwardproxy + real native `naive` binary, both provisioned by the CI job's
// own steps — and drives the PRODUCTION qualification entry
// (ProbeNaiveProxyTunnel) through a real HTTP request/reply to a real echo origin.
// No injected success callback is used in the assertion path.
//
// PREREQUISITES: needs a runnable native naive binary and a Caddy binary with
// forwardproxy. Both are built by .github/workflows/ci.yml. Locally this SKIPS
// rather than faking a pass - a skip is not evidence of anything.
//
// SCOPE BOUNDARY: exercises the protocol's authentic qualification primitive. The
// admission/selectability half of the journey is covered by
// internal/vpn/r12_wholeflow_test.go against the real VLESS/REALITY server.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// mustJSONNaive marshals naive params for the tunnel fixture.
func mustJSONNaive(t *testing.T, p models.NaiveProxyParams) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal naive params: %v", err)
	}
	return b
}

// TestR12_NaiveAuthenticQualificationRequestReply runs the production
// qualification probe end-to-end over the real native naive + Caddy stack.
func TestR12_NaiveAuthenticQualificationRequestReply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping authentic R12 naive qualification in short mode")
	}
	binPath := resolveRunnableNaiveBinary(t)
	if binPath == "" {
		t.Skip("skipping R12 naive qualification: authentic runnable naive binary not found (CI builds it)")
	}
	caddyBin := resolveCaddyBinary()
	if caddyBin == "" {
		t.Skip("skipping R12 naive qualification: caddy binary with forwardproxy not found (CI builds it)")
	}

	tmpDir := t.TempDir()
	caCertPath, srvCertPath, srvKeyPath := generateTestCerts(t, tmpDir)
	t.Setenv("SSL_CERT_FILE", caCertPath)

	// Real echo origin the tunneled HTTP request will reach.
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	defer originLn.Close()
	go func() {
		for {
			c, err := originLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}(c)
		}
	}()

	// Real Caddy forward_proxy server.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate caddy proxy port: %v", err)
	}
	proxyPort := proxyLn.Addr().(*net.TCPAddr).Port
	_ = proxyLn.Close()
	httpRedirectLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate caddy http port: %v", err)
	}
	httpPort := httpRedirectLn.Addr().(*net.TCPAddr).Port
	_ = httpRedirectLn.Close()

	caddyfilePath := filepath.Join(tmpDir, "Caddyfile")
	caddyfile := fmt.Sprintf(`{
    admin off
    auto_https disable_redirects
    http_port %d
}
127.0.0.1:%d {
    tls %s %s
    forward_proxy {
        basic_auth testuser testpass
        hide_ip
        hide_via
        acl {
            allow 127.0.0.1
        }
    }
}
`, httpPort, proxyPort, srvCertPath, srvKeyPath)
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0o600); err != nil {
		t.Fatalf("write Caddyfile: %v", err)
	}

	caddyCtx, caddyCancel := context.WithCancel(context.Background())
	defer caddyCancel()
	caddyCmd := exec.CommandContext(caddyCtx, caddyBin, "run", "--config", caddyfilePath, "--adapter", "caddyfile")
	if err := caddyCmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() { caddyCancel(); _ = caddyCmd.Wait() })

	caddyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	ready := false
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		if conn, derr := net.DialTimeout("tcp", caddyAddr, 100*time.Millisecond); derr == nil {
			_ = conn.Close()
			ready = true
			break
		}
	}
	if !ready {
		t.Fatalf("caddy did not become ready on %s", caddyAddr)
	}

	// Production qualification entry over the real stack.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tun := &models.BackendTunnel{
		Protocol: models.ProtocolNaive,
		Endpoint: caddyAddr,
		ProtocolParams: mustJSONNaive(t, models.NaiveProxyParams{
			Username: "testuser",
			Password: "testpass",
			Domain:   "127.0.0.1",
			Port:     proxyPort,
		}),
	}
	latencyMS, err := ProbeNaiveProxyTunnel(ctx, tun, 30*time.Second)
	if err != nil {
		t.Fatalf("authentic naive request/reply failed: %v", err)
	}
	if latencyMS < 1 {
		t.Fatalf("expected positive latency from a real exchange, got %d", latencyMS)
	}
	t.Logf("AUTHENTIC NAIVE REQUEST/REPLY ok: proxy=%s origin=%s latency=%dms", caddyAddr, originLn.Addr().String(), latencyMS)
}
