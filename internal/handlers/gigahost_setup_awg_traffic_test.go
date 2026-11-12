//go:build with_utls

package handlers

// Authentic AWG traffic qualification: a real encrypted AWG packet exchange decides admission.
//
// What these tests prove, precisely:
//
//	the PRODUCTION AWG client device (`tunnel.NewAWGClientDevice`, the same constructor
//	`attachBackendForwarder` calls) establishes a real amneziawg session with a real server
//	device over loopback, and the PRODUCTION canary (`tunnel.ProbePacketDevice`, the same
//	function `defaultCanaryProbe` calls) succeeds only when the far side's IP stack answers.
//
// What they do NOT prove, and this is stated rather than implied: the handler-level wrapper
// (`ProbeCanary` -> `qualifyBackendTraffic` -> `finishInstall`) is not driven here. See the
// handover for that gap and why it is a fixture-wiring problem, not a tunnel problem.
//
// No success callback, no error callback, no destination override and no synthesized reply:
// the peer's real stack is the component that answers, and the negative is produced by giving
// that stack a different address so the canary has no local owner.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// TestProductionAWGQualificationSucceedsOverARealPeer is the positive.
func TestProductionAWGQualificationSucceedsOverARealPeer(t *testing.T) {
	peer := startAuthenticAWGPeer(t, true)
	dev := dialProductionAWGDevice(t, peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The forwarder's read pump, which the canary's response hook depends on.
	pumpAWGDevice(ctx, dev)

	// Let the userspace handshake settle, then run the unmodified production canary.
	time.Sleep(200 * time.Millisecond)
	probeCtx, probeCancel := context.WithTimeout(ctx, awgProbeTimeout)
	defer probeCancel()

	if err := tunnel.ProbePacketDevice(probeCtx, dev, 6*time.Second, "10.100.0.0/16"); err != nil {
		t.Fatalf("the production canary did not complete over a healthy real AWG peer: %v", err)
	}

	// The tunnel is genuinely established, not merely silent: the device reports a handshake
	// and the peer saw the client's traffic.
	ipc, err := dev.DeviceIPC()
	if err != nil {
		t.Fatalf("read the production device IPC: %v", err)
	}
	if !deviceHasHandshake(ipc) {
		t.Fatalf("the production device reports no completed handshake:\n%s", ipc)
	}
}

// TestProductionAWGQualificationFailsWhenThePeerDoesNotAnswer is the negative.
//
// The peer is a real AWG server: the encrypted handshake completes and the transport delivers
// datagrams. Its stack does not own the canary destination, so the payload is never answered,
// and the production canary must fail. A handshake-only oracle would pass this - which is the
// distinction the original acceptance requires.
func TestProductionAWGQualificationFailsWhenThePeerDoesNotAnswer(t *testing.T) {
	peer := startAuthenticAWGPeer(t, false)
	dev := dialProductionAWGDevice(t, peer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pumpAWGDevice(ctx, dev)

	time.Sleep(200 * time.Millisecond)
	probeCtx, probeCancel := context.WithTimeout(ctx, 6*time.Second)
	defer probeCancel()

	err := tunnel.ProbePacketDevice(probeCtx, dev, 3*time.Second, "10.100.0.0/16")
	if err == nil {
		t.Fatal("a peer that never answers the payload still passed the production canary")
	}

	// The handshake DID complete, so the failure is the missing payload and not a dead
	// transport. Without this the negative would be indistinguishable from a broken tunnel.
	ipc, ipcErr := dev.DeviceIPC()
	if ipcErr != nil {
		t.Fatalf("read the production device IPC: %v", ipcErr)
	}
	if !deviceHasHandshake(ipc) {
		t.Fatalf("the negative case did not even establish a handshake, so it does not prove "+
			"that the payload is what failed:\n%s", ipc)
	}
	t.Logf("negative: handshake established, payload unanswered (%v)", err)
}

// TestAWGPeerRejectsAMismatchedObfuscationDialect proves the peer is not answering anything
// that arrives. A client speaking a different dialect must fail to establish a session, which
// shows the successful cases depend on a real matched handshake rather than on permissive
// fixtures.
func TestAWGPeerRejectsAMismatchedObfuscationDialect(t *testing.T) {
	peer := startAuthenticAWGPeer(t, true)

	// jc=1 on the client, jc=0 on the peer: the initiation is dropped before it is parsed.
	mismatched := map[string]any{
		"jc": 1, "jmin": 0, "jmax": 0, "s1": 0, "s2": 0, "s3": 0, "s4": 0,
		"h1": 1, "h2": 2, "h3": 3, "h4": 4,
	}
	dev, err := tunnel.NewAWGClientDevice("awg-mismatch", peer.endpoint,
		peer.clientPrivateKey, peer.serverPublicKey, 1280, mismatched)
	if err != nil {
		t.Fatalf("create AWG device with a mismatched dialect: %v", err)
	}
	defer func() { _ = dev.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pumpAWGDevice(ctx, dev)

	time.Sleep(200 * time.Millisecond)
	probeCtx, probeCancel := context.WithTimeout(ctx, 4*time.Second)
	defer probeCancel()

	if err := tunnel.ProbePacketDevice(probeCtx, dev, 2*time.Second, "10.100.0.0/16"); err == nil {
		t.Fatal("a client with a mismatched obfuscation dialect still completed the canary, " +
			"so the peer is not really validating the handshake")
	}
}

// deviceHasHandshake reports whether a device IPC dump shows a completed handshake.
func deviceHasHandshake(ipc string) bool {
	// UAPI prints `last_handshake_time_sec=<unix>`; a completed handshake is non-zero.
	const prefix = "last_handshake_time_sec="
	for _, line := range splitLines(ipc) {
		if len(line) <= len(prefix) || line[:len(prefix)] != prefix {
			continue
		}
		if line[len(prefix):] != "0" && line[len(prefix):] != "" {
			return true
		}
	}
	return false
}

// splitLines splits on newlines without importing strings just for this.
func splitLines(s string) []string {
	out := make([]string, 0, 32)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
