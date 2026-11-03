package naive

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// generateTestCerts generates a self-signed root CA and a server certificate with SANs
// for 127.0.0.1 and localhost, writing them as PEM files to dir.
func generateTestCerts(t *testing.T, dir string) (caCertPath, srvCertPath, srvKeyPath string) {
	t.Helper()

	// 1. Root CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "NaiveTestCA",
			Organization: []string{"AmneziaNexusTest"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCertPath = filepath.Join(dir, "ca.crt")
	caFile, err := os.Create(caCertPath)
	if err != nil {
		t.Fatalf("create ca.crt: %v", err)
	}
	defer caFile.Close()
	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		t.Fatalf("encode ca.crt: %v", err)
	}

	// 2. Server Certificate
	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caTemplate, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	srvCertPath = filepath.Join(dir, "server.crt")
	srvFile, err := os.Create(srvCertPath)
	if err != nil {
		t.Fatalf("create server.crt: %v", err)
	}
	defer srvFile.Close()
	if err := pem.Encode(srvFile, &pem.Block{Type: "CERTIFICATE", Bytes: srvDER}); err != nil {
		t.Fatalf("encode server.crt: %v", err)
	}

	srvKeyPath = filepath.Join(dir, "server.key")
	srvKeyFile, err := os.OpenFile(srvKeyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create server.key: %v", err)
	}
	defer srvKeyFile.Close()
	if err := pem.Encode(srvKeyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(srvKey),
	}); err != nil {
		t.Fatalf("encode server.key: %v", err)
	}

	return caCertPath, srvCertPath, srvKeyPath
}

// resolveRunnableNaiveBinary searches for an authentic runnable native naive binary.
func resolveRunnableNaiveBinary(t *testing.T) string {
	t.Helper()

	candidates := []string{
		os.Getenv(NaiveBinPathEnv),
		GetNaiveBinPath(),
		"/var/lib/amnezia-nexus/bin/naive",
		"./tasks/issue-695/evidence/upstream-naive-glibc.elf",
		"./tasks/issue-695/evidence/upstream-naive.elf",
	}

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0 {
			out, err := exec.Command(cand, "--version").CombinedOutput()
			if err == nil && strings.Contains(strings.ToLower(string(out)), "naive") {
				return cand
			}
			t.Logf("candidate binary %s failed version check: %v, out: %s", cand, err, strings.TrimSpace(string(out)))
		}
	}

	// Try EnsureNaiveBinary
	scratchDir := t.TempDir()
	binPath := filepath.Join(scratchDir, "naive")
	t.Setenv(NaiveBinPathEnv, binPath)
	downloaded, err := EnsureNaiveBinary(context.Background())
	if err == nil {
		out, err := exec.Command(downloaded, "--version").CombinedOutput()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "naive") {
			return downloaded
		}
		t.Logf("downloaded binary %s failed version check: %v, out: %s", downloaded, err, strings.TrimSpace(string(out)))
	} else {
		t.Logf("EnsureNaiveBinary failed: %v", err)
	}

	return ""
}

// resolveCaddyBinary checks PATH and GOPATH for a caddy executable with forwardproxy.
func resolveCaddyBinary() string {
	if bin, err := exec.LookPath("caddy"); err == nil {
		return bin
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		cand := filepath.Join(gopath, "bin", "caddy")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, "go", "bin", "caddy")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

func TestCaddyIntegration_NativeUpstreamBidirectionalEgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping authentic native Caddy integration test in short mode")
	}

	binPath := resolveRunnableNaiveBinary(t)
	if binPath == "" {
		t.Skip("skipping integration test: authentic runnable naive binary not found")
	}

	caddyBin := resolveCaddyBinary()
	if caddyBin == "" {
		t.Skip("skipping integration test: caddy binary not available")
	}

	tmpDir := t.TempDir()
	caCertPath, srvCertPath, srvKeyPath := generateTestCerts(t, tmpDir)
	t.Setenv("SSL_CERT_FILE", caCertPath)

	// 1. Echo backend TCP server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for echo backend: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	echoErrCh := make(chan error, 1)
	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			echoErrCh <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				resp := append([]byte("ECHO:"), buf[:n]...)
				if _, wErr := conn.Write(resp); wErr != nil {
					echoErrCh <- wErr
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					echoErrCh <- err
				} else {
					echoErrCh <- nil
				}
				return
			}
		}
	}()

	// 2. Launch Caddy forward_proxy server
	caddyProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate caddy proxy port: %v", err)
	}
	caddyProxyPort := caddyProxyLn.Addr().(*net.TCPAddr).Port
	_ = caddyProxyLn.Close()

	caddyHTTPRedirectLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate caddy http redirect port: %v", err)
	}
	caddyHTTPPort := caddyHTTPRedirectLn.Addr().(*net.TCPAddr).Port
	_ = caddyHTTPRedirectLn.Close()

	caddyfilePath := filepath.Join(tmpDir, "Caddyfile")
	caddyfileContent := fmt.Sprintf(`{
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
`, caddyHTTPPort, caddyProxyPort, srvCertPath, srvKeyPath)

	if err := os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0o600); err != nil {
		t.Fatalf("write Caddyfile: %v", err)
	}

	caddyCtx, caddyCancel := context.WithCancel(context.Background())
	defer caddyCancel()
	caddyCmd := exec.CommandContext(caddyCtx, caddyBin, "run", "--config", caddyfilePath, "--adapter", "caddyfile")
	caddyCmd.Stdout = io.Discard
	caddyCmd.Stderr = io.Discard
	if err := caddyCmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		caddyCancel()
		_ = caddyCmd.Wait()
	})

	// Wait for Caddy to be ready
	caddyReady := false
	caddyAddr := fmt.Sprintf("127.0.0.1:%d", caddyProxyPort)
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", caddyAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			caddyReady = true
			break
		}
	}
	if !caddyReady {
		t.Fatalf("caddy did not become ready on %s", caddyAddr)
	}

	// 3. Start native naive daemon pointing to Caddy
	params := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   "127.0.0.1",
		EnableH3: false,
	}

	daemon, err := NewDaemon(binPath, caddyAddr, params)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	if err := daemon.Start(startCtx); err != nil {
		t.Fatalf("daemon.Start: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Stop()
	})

	if !daemon.IsActive() {
		t.Fatal("expected native daemon to be active")
	}

	// 4. Connect via SOCKS5 through the native daemon
	socksAddr := daemon.SocksAddr()
	socksConn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("connect to SOCKS5 listener %s: %v", socksAddr, err)
	}
	defer socksConn.Close()

	// SOCKS5 Greeting: NO AUTH
	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greetingResp); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("socks greeting rejected: %v", greetingResp)
	}

	// SOCKS5 CONNECT to 127.0.0.1:echoPort
	connectReq := []byte{
		0x05, 0x01, 0x00, 0x01,
		127, 0, 0, 1,
		byte(echoPort >> 8), byte(echoPort & 0xff),
	}
	if _, err := socksConn.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}

	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, connectResp); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("socks connect request failed with status 0x%02x", connectResp[1])
	}

	// 5. Verify bidirectional payload data
	payload := []byte("Nexus upstream naive binary verified bidirectional wire payload!")
	if _, err := socksConn.Write(payload); err != nil {
		t.Fatalf("socks write payload: %v", err)
	}

	replyBuf := make([]byte, len("ECHO:")+len(payload))
	if _, err := io.ReadFull(socksConn, replyBuf); err != nil {
		t.Fatalf("socks read echo reply: %v", err)
	}

	expectedReply := "ECHO:" + string(payload)
	if string(replyBuf) != expectedReply {
		t.Fatalf("payload mismatch:\ngot:  %q\nwant: %q", string(replyBuf), expectedReply)
	}

	t.Logf("Authentic upstream NaiveProxy <-> Caddy integration verified successfully over wire")
}

func TestCaddyIntegration_H3Enabled_FallbackToHTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping authentic native Caddy integration test in short mode")
	}

	binPath := resolveRunnableNaiveBinary(t)
	if binPath == "" {
		t.Skip("skipping integration test: authentic runnable naive binary not found")
	}

	caddyBin := resolveCaddyBinary()
	if caddyBin == "" {
		t.Skip("skipping integration test: caddy binary not available")
	}

	tmpDir := t.TempDir()
	caCertPath, srvCertPath, srvKeyPath := generateTestCerts(t, tmpDir)
	t.Setenv("SSL_CERT_FILE", caCertPath)

	// 1. Echo backend TCP server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for echo backend: %v", err)
	}
	defer echoLn.Close()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				resp := append([]byte("ECHO:"), buf[:n]...)
				if _, wErr := conn.Write(resp); wErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// 2. Launch Caddy forward_proxy server
	caddyProxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate caddy proxy port: %v", err)
	}
	caddyProxyPort := caddyProxyLn.Addr().(*net.TCPAddr).Port
	_ = caddyProxyLn.Close()

	caddyHTTPRedirectLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate caddy http redirect port: %v", err)
	}
	caddyHTTPPort := caddyHTTPRedirectLn.Addr().(*net.TCPAddr).Port
	_ = caddyHTTPRedirectLn.Close()

	caddyfilePath := filepath.Join(tmpDir, "Caddyfile")
	caddyfileContent := fmt.Sprintf(`{
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
`, caddyHTTPPort, caddyProxyPort, srvCertPath, srvKeyPath)

	if err := os.WriteFile(caddyfilePath, []byte(caddyfileContent), 0o600); err != nil {
		t.Fatalf("write Caddyfile: %v", err)
	}

	caddyCtx, caddyCancel := context.WithCancel(context.Background())
	defer caddyCancel()
	caddyCmd := exec.CommandContext(caddyCtx, caddyBin, "run", "--config", caddyfilePath, "--adapter", "caddyfile")
	caddyCmd.Stdout = io.Discard
	caddyCmd.Stderr = io.Discard
	if err := caddyCmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		caddyCancel()
		_ = caddyCmd.Wait()
	})

	caddyReady := false
	caddyAddr := fmt.Sprintf("127.0.0.1:%d", caddyProxyPort)
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", caddyAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			caddyReady = true
			break
		}
	}
	if !caddyReady {
		t.Fatalf("caddy did not become ready on %s", caddyAddr)
	}

	// Test: EnableH3 is true, but server is an H2 Caddy backend (H3Supported is false by default)
	// Must generate https:// and connect cleanly without QUIC protocol mismatch
	params := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   "127.0.0.1",
		EnableH3: true,
	}

	daemon, err := NewDaemon(binPath, caddyAddr, params)
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()
	if err := daemon.Start(startCtx); err != nil {
		t.Fatalf("daemon.Start: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Stop()
	})

	// SOCKS5 connect and send payload
	socksAddr := daemon.SocksAddr()
	socksConn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("connect to SOCKS5 listener: %v", err)
	}
	defer socksConn.Close()

	if _, err := socksConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks greeting write: %v", err)
	}
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greetingResp); err != nil {
		t.Fatalf("socks greeting read: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("socks greeting rejected: %v", greetingResp)
	}

	connectReq := []byte{
		0x05, 0x01, 0x00, 0x01,
		127, 0, 0, 1,
		byte(echoPort >> 8), byte(echoPort & 0xff),
	}
	if _, err := socksConn.Write(connectReq); err != nil {
		t.Fatalf("socks connect write: %v", err)
	}

	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, connectResp); err != nil {
		t.Fatalf("socks connect read: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("socks connect request failed with status 0x%02x", connectResp[1])
	}

	payload := []byte("H3Enabled on H2 backend wire payload verified!")
	if _, err := socksConn.Write(payload); err != nil {
		t.Fatalf("socks write payload: %v", err)
	}

	replyBuf := make([]byte, len("ECHO:")+len(payload))
	if _, err := io.ReadFull(socksConn, replyBuf); err != nil {
		t.Fatalf("socks read echo reply: %v", err)
	}

	expectedReply := "ECHO:" + string(payload)
	if string(replyBuf) != expectedReply {
		t.Fatalf("payload mismatch:\ngot:  %q\nwant: %q", string(replyBuf), expectedReply)
	}

	t.Logf("EnableH3=true against H2 Caddy backend verified successfully over wire")
}

// Ensure unused import http does not trigger linter if unused
var _ = http.StatusOK
