package health

// Real amneziawg-go container integration test (Issue #5 round-2 review,
// carried HIGH: "no real-amneziawg-go integration test exists").
//
// The test starts amneziavpn/amneziawg-go:latest with a server config that
// registers a PSK-less probe peer (the exact policy AddClient implements for
// caller-supplied probe identities), then runs the portal's real probe
// (PerformAWGHandshake) against the container's UDP endpoint and asserts a
// genuine handshake response is received and verified. This is the test that
// would have caught both the identity bug (registered key != probing key) and
// the PSK-mismatch bug (peer registered with PSK, prober probing with psk="").
//
// Skips gracefully when Docker is unavailable or the image cannot be pulled,
// so CI without Docker stays green.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	awgContainerImage  = "amneziavpn/amneziawg-go:latest"
	containerStartWait = 15 * time.Second
	probeTimeout       = 5 * time.Second
)

func dockerDaemonReachable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
	return cmd.Run() == nil
}

func dockerImagePresent(image string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	return cmd.Run() == nil
}

func dockerPullImage(image string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pull %s failed: %v: %s", image, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// generateIntegrationKeypair returns a fresh base64 (private, public) pair.
func generateIntegrationKeypair(t *testing.T) (string, string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand priv: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// freeUDPPort grabs an ephemeral UDP port and releases it for the container.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free UDP port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// TestAWGRealContainer_HandshakeWithPSKLessProbePeer is the acceptance
// criterion for the prober rework: a real amneziawg-go daemon accepts a probe
// handshake built by the portal's own Noise implementation when the probe peer
// is registered with the caller's public key and no PresharedKey.
func TestAWGRealContainer_HandshakeWithPSKLessProbePeer(t *testing.T) {
	if !dockerDaemonReachable() {
		t.Skip("docker daemon unreachable — skipping real-amneziawg-go integration test")
	}
	if !dockerImagePresent(awgContainerImage) {
		if err := dockerPullImage(awgContainerImage); err != nil {
			t.Skipf("image %s missing and pull failed — skipping: %v", awgContainerImage, err)
		}
	}

	serverPriv, serverPub := generateIntegrationKeypair(t)
	proberPriv, proberPub := generateIntegrationKeypair(t)
	port := freeUDPPort(t)

	// Server config registering the probe peer with NO PresharedKey. Header/
	// junk values match the portal builder defaults used when no explicit
	// awgParams are passed to PerformAWGHandshake.
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.1.1/24
ListenPort = %d
MTU = 1280
Jc = 0
Jmin = 30
Jmax = 80
S1 = %d
S2 = %d
S3 = %d
S4 = %d
H1 = %d
H2 = %d
H3 = %d
H4 = %d

[Peer]
PublicKey = %s
AllowedIPs = 10.8.1.2/32
`,
		serverPriv, port,
		DefaultS1, DefaultS2, DefaultS3, DefaultS4,
		DefaultH1, DefaultH2, DefaultH3, DefaultH4,
		proberPub,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	cName := fmt.Sprintf("awg-probe-integration-%d", time.Now().UnixNano()%1000000)
	// NOTE: we must NOT pipe the config via `docker run -d -i` stdin — docker detaches
	// immediately and stdin closes before the shell reads it, leaving an EMPTY config
	// file (verified empirically: 0-byte awg0.conf, daemon runs with defaults and drops
	// every initiation). Instead: start the container bare, then write the config via
	// `docker exec` with the content passed through the exec command's stdin.
	runCmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--privileged",
		"--cap-add=NET_ADMIN",
		"--device", "/dev/net/tun",
		"-p", fmt.Sprintf("%d:%d/udp", port, port),
		"--entrypoint", "/bin/sh",
		"--name", cName,
		awgContainerImage,
		"-c", "mkdir -p /opt/amnezia/awg && exec tail -f /dev/null",
	)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
		t.Fatalf("failed to start %s container: %v: %s",
			awgContainerImage, err, strings.TrimSpace(string(runOut)))
	}
	// Write the server config via docker exec (stdin stays attached for exec).
	writeCmd := exec.CommandContext(ctx, "docker", "exec", "-i", cName,
		"sh", "-c", "cat > /opt/amnezia/awg/awg0.conf")
	writeCmd.Stdin = strings.NewReader(conf)
	if wOut, wErr := writeCmd.CombinedOutput(); wErr != nil {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
		t.Fatalf("failed to write awg0.conf into container: %v: %s", wErr, strings.TrimSpace(string(wOut)))
	}
	// Sanity: the config must be non-empty before we bring the interface up.
	var confSizeOut []byte
	confSizeOut, err = exec.CommandContext(ctx, "docker", "exec", cName, "wc", "-c", "/opt/amnezia/awg/awg0.conf").CombinedOutput()
	if err != nil || !strings.Contains(string(confSizeOut), fmt.Sprintf("%d", len(conf))) {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
		t.Fatalf("awg0.conf size mismatch (want %d bytes): %s", len(conf), strings.TrimSpace(string(confSizeOut)))
	}
	upOut, upErr := exec.CommandContext(ctx, "docker", "exec", cName,
		"sh", "-c", "awg-quick up /opt/amnezia/awg/awg0.conf").CombinedOutput()
	if upErr != nil {
		logs, _ := exec.Command("docker", "logs", cName).CombinedOutput()
		_ = exec.Command("docker", "rm", "-f", cName).Run()
		t.Fatalf("awg-quick up failed: %v: %s\ncontainer logs: %s",
			upErr, strings.TrimSpace(string(upOut)), strings.TrimSpace(string(logs)))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
	})

	// Wait until the awg0 interface is up inside the container.
	// NOTE: readiness = the interface exists and reports a listening port.
	// We deliberately do NOT wait for a "peer:" section in `awg show`:
	// the userspace amneziawg-go implementation only prints peer blocks
	// after a peer has completed a handshake, so requiring "peer:"
	// pre-handshake deadlocks the test even though the listener is ready.
	var awgShow string
	ready := false
	deadline := time.Now().Add(containerStartWait)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "docker", "exec", cName, "awg", "show", "awg0").CombinedOutput()
		awgShow = string(out)
		if err == nil &&
			strings.Contains(awgShow, "interface: awg0") &&
			strings.Contains(awgShow, "listening port:") {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("container interface never came up: %s", awgShow)
		case <-time.After(1 * time.Second):
		}
	}
	if !ready {
		logs, _ := exec.Command("docker", "logs", cName).CombinedOutput()
		t.Fatalf("awg0 interface not ready after %v:\nawg show: %s\ncontainer logs: %s",
			containerStartWait, strings.TrimSpace(awgShow), strings.TrimSpace(string(logs)))
	}
	t.Logf("container interface up:\n%s", awgShow)

	// The probe identity is the private key whose public half the container
	// registered — exactly what AddClient's caller-supplied-key path stores.
	// Probe target: the docker host's bridge gateway. When this test runs inside a
	// container (golang builder with the host docker socket mounted), "127.0.0.1" is
	// the test container itself, NOT the host where -p maps the server's UDP port.
	// The bridge gateway address reaches the host's mapped ports from any container.
	probeHost := "127.0.0.1"
	if ip := os.Getenv("AWG_PROBE_HOST"); ip != "" {
		probeHost = ip
	}
	res, err := PerformAWGHandshake(ctx, probeHost, port, serverPub, proberPriv, "", "", nil, "", probeTimeout)
	if err != nil {
		t.Fatalf("PerformAWGHandshake against real amneziawg-go returned hard error: %v", err)
	}
	if res["handshake_complete"] != true {
		t.Fatalf("real amneziawg-go handshake incomplete: %+v", res)
	}
	if res["reachable"] != true {
		t.Fatalf("real amneziawg-go endpoint not reachable per probe result: %+v", res)
	}
	if errMsg, _ := res["error"].(string); errMsg != "" {
		t.Fatalf("probe reported error despite completed handshake: %s (%+v)", errMsg, res)
	}
	t.Logf("real amneziawg-go handshake verified, latency_ms=%v", res["latency_ms"])
}

// bootAWGContainer is the shared container boot helper for the real
// amneziawg-go integration tests: writes the given server config into a fresh
// amneziavpn/amneziawg-go container, brings the interface up, and waits until
// it reports a listening port. Returns the container name (registered for
// cleanup) and skips the test when Docker is unavailable or the image cannot
// be pulled. Boot sequence notes live on TestAWGRealContainer_HandshakeWithPSKLessProbePeer.
func bootAWGContainer(t *testing.T, conf string) (cName string, ctx context.Context) {
	t.Helper()
	if !dockerDaemonReachable() {
		t.Skip("docker daemon unreachable — skipping real-amneziawg-go integration test")
	}
	if !dockerImagePresent(awgContainerImage) {
		if err := dockerPullImage(awgContainerImage); err != nil {
			t.Skipf("image %s missing and pull failed — skipping: %v", awgContainerImage, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)

	cName = fmt.Sprintf("awg-probe-integration-%d", time.Now().UnixNano()%1000000)
	// NOTE: we must NOT pipe the config via `docker run -d -i` stdin — docker detaches
	// immediately and stdin closes before the shell reads it, leaving an EMPTY config
	// file (verified empirically: 0-byte awg0.conf, daemon runs with defaults and drops
	// every initiation). Instead: start the container bare, then write the config via
	// `docker exec` with the content passed through the exec command's stdin.
	runCmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--privileged",
		"--cap-add=NET_ADMIN",
		"--device", "/dev/net/tun",
		"--entrypoint", "/bin/sh",
		"--name", cName,
		awgContainerImage,
		"-c", "mkdir -p /opt/amnezia/awg && exec tail -f /dev/null",
	)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
		t.Fatalf("failed to start %s container: %v: %s",
			awgContainerImage, err, strings.TrimSpace(string(runOut)))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
	})

	// Write the server config via docker exec (stdin stays attached for exec).
	writeCmd := exec.CommandContext(ctx, "docker", "exec", "-i", cName,
		"sh", "-c", "cat > /opt/amnezia/awg/awg0.conf")
	writeCmd.Stdin = strings.NewReader(conf)
	if wOut, wErr := writeCmd.CombinedOutput(); wErr != nil {
		t.Fatalf("failed to write awg0.conf into container: %v: %s", wErr, strings.TrimSpace(string(wOut)))
	}

	// Sanity: the config must be non-empty before we bring the interface up.
	confSizeOut, err := exec.CommandContext(ctx, "docker", "exec", cName, "wc", "-c", "/opt/amnezia/awg/awg0.conf").CombinedOutput()
	if err != nil || !strings.Contains(string(confSizeOut), fmt.Sprintf("%d", len(conf))) {
		t.Fatalf("awg0.conf size mismatch (want %d bytes): %s", len(conf), strings.TrimSpace(string(confSizeOut)))
	}

	upOut, upErr := exec.CommandContext(ctx, "docker", "exec", cName,
		"sh", "-c", "awg-quick up /opt/amnezia/awg/awg0.conf").CombinedOutput()
	if upErr != nil {
		logs, _ := exec.Command("docker", "logs", cName).CombinedOutput()
		t.Fatalf("awg-quick up failed: %v: %s\ncontainer logs: %s",
			upErr, strings.TrimSpace(string(upOut)), strings.TrimSpace(string(logs)))
	}

	// Wait until the awg0 interface is up inside the container.
	// NOTE: readiness = the interface exists and reports a listening port.
	// We deliberately do NOT wait for a "peer:" section in `awg show`:
	// the userspace amneziawg-go implementation only prints peer blocks
	// after a peer has completed a handshake, so requiring "peer:"
	// pre-handshake deadlocks the test even though the listener is ready.
	var awgShow string
	ready := false
	deadline := time.Now().Add(containerStartWait)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "docker", "exec", cName, "awg", "show", "awg0").CombinedOutput()
		awgShow = string(out)
		if err == nil &&
			strings.Contains(awgShow, "interface: awg0") &&
			strings.Contains(awgShow, "listening port:") {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("container interface never came up: %s", awgShow)
		case <-time.After(1 * time.Second):
		}
	}
	if !ready {
		logs, _ := exec.Command("docker", "logs", cName).CombinedOutput()
		t.Fatalf("awg0 interface not ready after %v:\nawg show: %s\ncontainer logs: %s",
			containerStartWait, strings.TrimSpace(awgShow), strings.TrimSpace(string(logs)))
	}
	t.Logf("container interface up:\n%s", awgShow)
	return cName, ctx
}

// awgProbeHost picks the probe target host: the docker host's bridge gateway.
// When this test runs inside a container (golang builder with the host docker
// socket mounted), "127.0.0.1" is the test container itself, NOT the host
// where -p maps the server's UDP port. The bridge gateway address reaches the
// host's mapped ports from any container.
func awgProbeHost() string {
	if ip := os.Getenv("AWG_PROBE_HOST"); ip != "" {
		return ip
	}
	return "127.0.0.1"
}

// TestAWGRealContainer_HandshakeWithHeaderProtectionKey is the Issue #18 R5
// acceptance criterion: the probe's header-protection support works against a
// REAL amneziawg-go. The server conf declares a HeaderProtectionKey (32B key,
// base64-decoded then hex-encoded for the conf, as amneziawg expects) plus
// S1..S4 = 15 (>= 12 junk sizes the header protection constraint requires).
// The probe is issued with the same key in the portal's base64 form — the
// exact shape ExtractHeaderProtectionKey returns from stored awg_params — so
// a verified handshake response proves both sides derived matching header
// protection ciphers.
func TestAWGRealContainer_HandshakeWithHeaderProtectionKey(t *testing.T) {
	if !dockerDaemonReachable() {
		t.Skip("docker daemon unreachable — skipping real-amneziawg-go integration test")
	}
	if !dockerImagePresent(awgContainerImage) {
		if err := dockerPullImage(awgContainerImage); err != nil {
			t.Skipf("image %s missing and pull failed — skipping: %v", awgContainerImage, err)
		}
	}

	serverPriv, serverPub := generateIntegrationKeypair(t)
	proberPriv, proberPub := generateIntegrationKeypair(t)

	// The header-protection key: 32 random bytes, base64 (portal/awg_params
	// form) and hex (server conf form) of the SAME key.
	hpRaw := make([]byte, 32)
	if _, err := rand.Read(hpRaw); err != nil {
		t.Fatalf("rand hp key: %v", err)
	}
	hpKeyB64 := base64.StdEncoding.EncodeToString(hpRaw)
	hpKeyHex := hex.EncodeToString(hpRaw)

	port := freeUDPPort(t)

	// S1..S4 = 15 (>= 12 per the header-protection constraint); H values stay
	// at the portal defaults.
	const sVal = 15
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.1.1/24
ListenPort = %d
MTU = 1280
Jc = 0
Jmin = 30
Jmax = 80
S1 = %d
S2 = %d
S3 = %d
S4 = %d
H1 = %d
H2 = %d
H3 = %d
H4 = %d
HeaderProtectionKey = %s

[Peer]
PublicKey = %s
AllowedIPs = 10.8.1.2/32
`,
		serverPriv, port,
		sVal, sVal, sVal, sVal,
		DefaultH1, DefaultH2, DefaultH3, DefaultH4,
		hpKeyHex,
		proberPub,
	)

	// The probe must consume the header-protection key in the SAME shape the
	// reachability/tunnel probers pass it: ExtractHeaderProtectionKey over the
	// stored awg_params object returns the base64 form.
	awgParams := map[string]any{"header_protection_key": hpKeyB64}
	probeHPKey := ExtractHeaderProtectionKey(awgParams)
	if probeHPKey != hpKeyB64 {
		t.Fatalf("ExtractHeaderProtectionKey lost the hp key: got %q, want %q", probeHPKey, hpKeyB64)
	}

	_, ctx := bootAWGContainer(t, conf)

	res, err := PerformAWGHandshake(ctx, awgProbeHost(), port, serverPub, proberPriv, "", probeHPKey, awgParams, "", probeTimeout)
	if err != nil {
		t.Fatalf("PerformAWGHandshake (with header protection) returned hard error: %v", err)
	}
	if res["handshake_complete"] != true {
		t.Fatalf("real amneziawg-go handshake with header protection incomplete: %+v", res)
	}
	if res["reachable"] != true {
		t.Fatalf("real amneziawg-go endpoint with header protection not reachable per probe result: %+v", res)
	}
	if errMsg, _ := res["error"].(string); errMsg != "" {
		t.Fatalf("probe reported error despite completed handshake: %s (%+v)", errMsg, res)
	}
	t.Logf("real amneziawg-go header-protection handshake verified, latency_ms=%v", res["latency_ms"])
}
