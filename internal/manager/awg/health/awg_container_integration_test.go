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
	"fmt"
	"net"
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
	runCmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--privileged",
		"--cap-add=NET_ADMIN",
		"--device", "/dev/net/tun",
		"-p", fmt.Sprintf("%d:%d/udp", port, port),
		"--entrypoint", "/bin/sh",
		"--name", cName,
		awgContainerImage,
		"-c", "mkdir -p /opt/amnezia/awg && cat > /opt/amnezia/awg/awg0.conf && awg-quick up /opt/amnezia/awg/awg0.conf && exec tail -f /dev/null",
	)
	// The config is piped into the container's stdin via docker run -i.
	runCmd.Stdin = strings.NewReader(conf)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		// Container may have started but failed at startup: dump logs.
		logs, _ := exec.Command("docker", "logs", cName).CombinedOutput()
		_ = exec.Command("docker", "rm", "-f", cName).Run()
		t.Fatalf("failed to start %s container: %v: %s\ncontainer logs: %s",
			awgContainerImage, err, strings.TrimSpace(string(runOut)), strings.TrimSpace(string(logs)))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", cName).Run()
	})

	// Wait until the awg0 interface is up inside the container.
	var awgShow string
	deadline := time.Now().Add(containerStartWait)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "docker", "exec", cName, "awg", "show", "awg0").CombinedOutput()
		awgShow = string(out)
		if err == nil && strings.Contains(awgShow, "peer:") {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("container interface never came up: %s", awgShow)
		case <-time.After(1 * time.Second):
		}
	}
	if !strings.Contains(awgShow, "peer:") {
		logs, _ := exec.Command("docker", "logs", cName).CombinedOutput()
		t.Fatalf("awg0 interface or peer not ready after %v:\nawg show: %s\ncontainer logs: %s",
			containerStartWait, strings.TrimSpace(awgShow), strings.TrimSpace(string(logs)))
	}
	t.Logf("container interface up:\n%s", awgShow)

	// The probe identity is the private key whose public half the container
	// registered — exactly what AddClient's caller-supplied-key path stores.
	res, err := PerformAWGHandshake(ctx, "127.0.0.1", port, serverPub, proberPriv, "", nil, "", probeTimeout)
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
