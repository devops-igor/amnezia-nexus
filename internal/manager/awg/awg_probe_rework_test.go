package awg

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/curve25519"
)

// testProberKeypair derives a deterministic prober keypair (base64, as the
// portal stores/derives keys) from a fixed 32-byte private key.
func testProberKeypair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// peerBlockFor extracts the full [Peer] section for the given public key from
// a server config text. Returns "" when no such peer exists.
func peerBlockFor(t *testing.T, confText, pubKey string) string {
	t.Helper()
	lines := strings.Split(confText, "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "[Peer]" {
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "[") {
			j++
		}
		block := strings.Join(lines[i:j], "\n")
		if strings.Contains(block, "PublicKey = "+pubKey) {
			return block
		}
		i = j - 1
	}
	return ""
}

// TestAWGManager_AddClient_ProbePeerUsesCallerKey_R3 exercises the REAL
// AWGManager.AddClient against the mock SSH layer (round-2 review finding 1):
// a caller-supplied public key must be registered verbatim as the [Peer]
// PublicKey (no keypair generation), the peer must carry NO PresharedKey line
// (finding 2), and re-registration for the same identity must not duplicate
// the peer or allocate a new IP (idempotency).
func TestAWGManager_AddClient_ProbePeerUsesCallerKey_R3(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	proberPriv, proberPub := testProberKeypair(t)

	// --- First registration (as EnableBackend would call it) ---
	res, err := mgr.AddClient(ctx, server, map[string]any{
		"clientName":        "Health Probe",
		"name":              "Health Probe",
		"public_key":        proberPub,
		"client_public_key": proberPub,
	})
	if err != nil {
		t.Fatalf("AddClient (probe path) failed: %v", err)
	}
	_ = proberPriv // proberPriv is exercised in TestAWGManager_AddClient_ProbePubKeyMatchesPrivate_R3

	// 1a. Result echoes the CALLER-supplied key as the peer identity.
	if res["client_id"] != proberPub {
		t.Fatalf("probe peer client_id = %v, want caller-supplied proberPub %s", res["client_id"], proberPub)
	}
	// 1b. No client private key exists on the probe path.
	if cfg, _ := res["config"].(string); cfg != "" {
		t.Fatalf("probe path must not render a client config (no private key), got: %s", cfg)
	}

	confText := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])

	// 1c. The [Peer] appended to the server config carries the caller's key.
	peer := peerBlockFor(t, confText, proberPub)
	if peer == "" {
		t.Fatalf("server config has no [Peer] with PublicKey = %s\nconfig:\n%s", proberPub, confText)
	}

	// 2. The probe peer section contains NO PresharedKey line.
	if strings.Contains(peer, "PresharedKey") {
		t.Fatalf("probe [Peer] must not contain a PresharedKey line:\n%s", peer)
	}
	if !strings.Contains(peer, "AllowedIPs = ") {
		t.Fatalf("probe [Peer] missing AllowedIPs:\n%s", peer)
	}

	// 3a. Idempotency: second AddClient for the same identity must not append
	// a duplicate [Peer] nor allocate a new IP.
	firstIP := ""
	for _, line := range strings.Split(peer, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AllowedIPs = ") {
			firstIP = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "AllowedIPs = "))
		}
	}
	if firstIP == "" {
		t.Fatalf("could not extract first probe IP from peer:\n%s", peer)
	}
	// clientsTable stores the bare address; the config uses a CIDR.
	firstIPAddr := strings.TrimSuffix(firstIP, "/32")

	if _, err := mgr.AddClient(ctx, server, map[string]any{
		"clientName":        "Health Probe",
		"name":              "Health Probe",
		"public_key":        proberPub,
		"client_public_key": proberPub,
	}); err != nil {
		t.Fatalf("second AddClient (idempotency) failed: %v", err)
	}

	confText2 := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	peerCount := strings.Count(confText2, "PublicKey = "+proberPub)
	if peerCount != 1 {
		t.Fatalf("expected exactly 1 [Peer] with the prober pubkey after re-registration, got %d\nconfig:\n%s", peerCount, confText2)
	}
	peer2 := peerBlockFor(t, confText2, proberPub)
	if strings.Contains(peer2, "PresharedKey") {
		t.Fatalf("probe [Peer] gained a PresharedKey after re-registration:\n%s", peer2)
	}
	if !strings.Contains(peer2, "AllowedIPs = "+firstIP) {
		t.Fatalf("idempotent re-registration changed the probe peer IP: want %s, got:\n%s", firstIP, peer2)
	}

	// 3b. clientsTable: exactly one entry for the probe identity, and the
	// total entry count must not grow on re-registration.
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	probeEntries := 0
	for _, c := range clients {
		if ud, ok := c["userData"].(map[string]any); ok && ud["clientName"] == "Health Probe" {
			probeEntries++
			if ip, _ := ud["clientIp"].(string); ip != "" && ip != firstIPAddr {
				t.Errorf("probe client IP changed across re-registration: %s -> %s", firstIPAddr, ip)
			}
			// No private key may be stored for a probe peer.
			if priv, _ := ud["clientPrivateKey"].(string); priv != "" {
				t.Errorf("probe peer must not store a client private key, got %q", priv)
			}
		}
	}
	if probeEntries != 1 {
		t.Fatalf("expected exactly 1 'Health Probe' clientsTable entry, got %d", probeEntries)
	}
	if len(clients) != 2 { // pubkey1 (pre-existing) + Health Probe
		t.Fatalf("expected 2 clientsTable entries total, got %d", len(clients))
	}
}

// TestAWGManager_AddClient_NormalPathKeepsKeypairAndPSK_R3 guards the normal
// client path: generated keypair, PresharedKey present, client config rendered.
func TestAWGManager_AddClient_NormalPathKeepsKeypairAndPSK_R3(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	res, err := mgr.AddClient(ctx, server, map[string]any{"clientName": "Regular User"})
	if err != nil {
		t.Fatalf("AddClient (normal path) failed: %v", err)
	}

	clientPub, _ := res["client_id"].(string)
	if clientPub == "" {
		t.Fatalf("normal path must return a generated client_id, got %+v", res)
	}

	confText := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	peer := peerBlockFor(t, confText, clientPub)
	if peer == "" {
		t.Fatalf("server config has no [Peer] for generated key %s\nconfig:\n%s", clientPub, confText)
	}
	if !strings.Contains(peer, "PresharedKey = ") {
		t.Fatalf("normal client [Peer] must keep the PresharedKey line:\n%s", peer)
	}

	if cfg, _ := res["config"].(string); cfg == "" {
		t.Fatalf("normal path must render a client config, got %+v", res)
	}
}

// TestAWGManager_AddClient_InvalidCallerKeyFallsBackToGenerated_R3: an
// invalid caller-supplied key must be ignored (fall back to keypair
// generation), never registered as the peer identity.
func TestAWGManager_AddClient_InvalidCallerKeyFallsBackToGenerated_R3(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	res, err := mgr.AddClient(ctx, server, map[string]any{
		"clientName": "Bad Key Client",
		"public_key": "not-a-valid-key!!!",
	})
	if err != nil {
		t.Fatalf("AddClient with invalid caller key failed: %v", err)
	}
	if res["client_id"] == "not-a-valid-key!!!" {
		t.Fatalf("invalid caller key must not be registered as peer identity")
	}
	clientPub, _ := res["client_id"].(string)
	if clientPub == "" {
		t.Fatalf("fallback path must generate a keypair, got %+v", res)
	}
}

// TestAWGManager_AddClient_ProbePubKeyMatchesPrivate_R3 ties the registered
// probe peer identity to the private key the prober actually signs with: the
// caller-supplied public key must equal the public half of the tunnel's
// private key, so a handshake built from that private key is accepted.
func TestAWGManager_AddClient_ProbePubKeyMatchesPrivate_R3(t *testing.T) {
	proberPriv, proberPub := testProberKeypair(t)
	derived, err := health.ComputePublicKeyFromPrivate(proberPriv)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate failed: %v", err)
	}
	if derived != proberPub {
		t.Fatalf("derived prober pubkey %s != registered %s", derived, proberPub)
	}
}

// TestAWGManager_AddClient_RegistrationPathsConverge_R2 pins the Issue #18 R2
// unification contract against the same mock SSH server: the tunnel prober's
// caller-key registration (EnableBackend passes public_key/client_public_key)
// and the reachability prober's provisioned-key registration (the orchestrator
// derives the public key from the private key it probes with) must land the
// IDENTICAL probe peer — same PublicKey, no PresharedKey line — so both probers
// share one PSK-less peer identity on every server. A fresh private key (the
// reachability no-cache path) must likewise land a PSK-less peer.
func TestAWGManager_AddClient_RegistrationPathsConverge_R2(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	proberPriv, proberPub := testProberKeypair(t)

	// --- Path 1: EnableBackend's caller-key registration. ---
	resA, err := mgr.AddClient(ctx, server, map[string]any{
		"clientName":        "Health Probe",
		"name":              "Health Probe",
		"public_key":        proberPub,
		"client_public_key": proberPub,
	})
	if err != nil {
		t.Fatalf("AddClient (EnableBackend caller-key path) failed: %v", err)
	}
	if resA["client_id"] != proberPub {
		t.Fatalf("caller-key path client_id = %v, want %s", resA["client_id"], proberPub)
	}

	confA := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	peerA := peerBlockFor(t, confA, proberPub)
	if peerA == "" {
		t.Fatalf("caller-key path produced no [Peer] with PublicKey = %s\nconfig:\n%s", proberPub, confA)
	}
	if strings.Contains(peerA, "PresharedKey") {
		t.Fatalf("caller-key [Peer] must not contain a PresharedKey line:\n%s", peerA)
	}
	ipA := ""
	for _, line := range strings.Split(peerA, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AllowedIPs = ") {
			ipA = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "AllowedIPs = "))
		}
	}
	if ipA == "" {
		t.Fatalf("could not extract caller-key peer IP from:\n%s", peerA)
	}

	// --- Path 2: reachability's provisioned-key registration. ---
	// The orchestrator derives the public key from the private key the prober
	// signs with (provisionHealthProbeClientWithPublicKey), so the derived key
	// must equal the caller-registered identity by construction.
	derived, err := health.ComputePublicKeyFromPrivate(proberPriv)
	if err != nil {
		t.Fatalf("ComputePublicKeyFromPrivate failed: %v", err)
	}
	if derived != proberPub {
		t.Fatalf("provisioned-key path derives %s, want the registered %s", derived, proberPub)
	}

	resB, err := mgr.AddClient(ctx, server, map[string]any{
		"clientName":        "Health Probe",
		"name":              "Health Probe",
		"public_key":        derived,
		"client_public_key": derived,
	})
	if err != nil {
		t.Fatalf("AddClient (reachability provisioned-key path) failed: %v", err)
	}
	if resB["client_id"] != proberPub {
		t.Fatalf("provisioned-key path client_id = %v, want the identical peer %s", resB["client_id"], proberPub)
	}

	confB := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	peerB := peerBlockFor(t, confB, proberPub)
	if peerB == "" {
		t.Fatalf("provisioned-key path produced no [Peer] with PublicKey = %s\nconfig:\n%s", proberPub, confB)
	}
	if strings.Contains(peerB, "PresharedKey") {
		t.Fatalf("provisioned-key [Peer] must not contain a PresharedKey line:\n%s", peerB)
	}
	if !strings.Contains(peerB, "AllowedIPs = "+ipA) {
		t.Fatalf("provisioned-key registration must keep the caller-key peer (AllowedIPs = %s), got:\n%s", ipA, peerB)
	}
	if n := strings.Count(confB, "PublicKey = "+proberPub); n != 1 {
		t.Fatalf("expected exactly 1 [Peer] for the probe identity after both paths, got %d\nconfig:\n%s", n, confB)
	}

	// clientsTable: one probe entry, the shared identity, no private key.
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	probeEntries := 0
	for _, c := range clients {
		if ud, ok := c["userData"].(map[string]any); ok && ud["clientName"] == "Health Probe" {
			probeEntries++
			if cid, _ := c["clientId"].(string); cid != proberPub {
				t.Errorf("probe clientsTable identity = %q, want the shared %s", cid, proberPub)
			}
			if priv, _ := ud["clientPrivateKey"].(string); priv != "" {
				t.Errorf("probe peer must not store a client private key, got %q", priv)
			}
		}
	}
	if probeEntries != 1 {
		t.Fatalf("expected exactly 1 'Health Probe' clientsTable entry after both paths, got %d", probeEntries)
	}

	// --- Fresh-priv leg: reachability's no-cache provisioning path. ---
	// A brand-new server where only the reachability prober registers (a
	// freshly generated private key, derived public key) must also land a
	// PSK-less peer.
	freshPriv, freshPub, err := GenerateWGKeypair()
	if err != nil {
		t.Fatalf("GenerateWGKeypair failed: %v", err)
	}
	sshClient2 := newMockAWGSSHClient()
	mgr2 := NewAWGManager(&mockAWGSSHProvider{client: sshClient2})
	server2 := &models.Server{ID: 2, Host: "5.6.7.8"}

	resC, err := mgr2.AddClient(ctx, server2, map[string]any{
		"clientName":        "Health Probe",
		"name":              "Health Probe",
		"public_key":        freshPub,
		"client_public_key": freshPub,
	})
	if err != nil {
		t.Fatalf("AddClient (fresh-priv reachability path) failed: %v", err)
	}
	if resC["client_id"] != freshPub {
		t.Fatalf("fresh-priv path client_id = %v, want derived %s", resC["client_id"], freshPub)
	}
	_ = freshPriv
	confC := string(sshClient2.files["/opt/amnezia/awg/awg0.conf"])
	peerC := peerBlockFor(t, confC, freshPub)
	if peerC == "" {
		t.Fatalf("fresh-priv path produced no [Peer] with PublicKey = %s\nconfig:\n%s", freshPub, confC)
	}
	if strings.Contains(peerC, "PresharedKey") {
		t.Fatalf("fresh-priv [Peer] must not contain a PresharedKey line:\n%s", peerC)
	}
}
