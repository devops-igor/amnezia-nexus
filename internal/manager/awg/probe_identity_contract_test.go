package awg

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/curve25519"
)

// probeRegistrationParams mirrors exactly what the background reachability
// prober sends for its "Health Probe" peer: an identity the CALLER owns, supplied
// as a public key, under the probe peer name.
func probeRegistrationParams(t *testing.T) (priv, pub string, params map[string]any) {
	t.Helper()
	priv, pub = testProberKeypair(t)
	return priv, pub, map[string]any{
		"name":              "Health Probe",
		"clientName":        "Health Probe",
		"public_key":        pub,
		"client_public_key": pub,
	}
}

// alternateProberKeypair derives a second deterministic prober keypair, distinct
// from testProberKeypair, so a test can express "the peer identity changed".
func alternateProberKeypair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i + 101)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

// TestAWGManager_AddClient_ProbeRegistrationReturnsNoClientCredential pins the
// manager half of the reachability identity contract.
//
// A caller-key registration cannot return credential material: the manager never
// generated the private key, so there is nothing to render into a client config
// and nothing to store. A caller that waits for a private key in this response
// therefore has no identity at all on the first cycle after a fresh install,
// even though the registration succeeded.
//
// The contract is therefore: the response confirms the identity that was
// REGISTERED (client_pub_key) and carries no config/userData; the caller's own
// private key is the credential.
func TestAWGManager_AddClient_ProbeRegistrationReturnsNoClientCredential(t *testing.T) {
	ctx := context.Background()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: newMockAWGSSHClient()})
	server := &models.Server{ID: 1, Host: "192.0.2.10"}

	_, pub, params := probeRegistrationParams(t)

	res, err := mgr.AddClient(ctx, server, params)
	if err != nil {
		t.Fatalf("probe registration failed: %v", err)
	}

	if cfg, has := res["config"].(string); has && cfg != "" {
		t.Errorf("probe registration must not render a client config, got %q", cfg)
	}
	if ud, has := res["userData"]; has && ud != nil {
		t.Errorf("probe registration must not return client userData, got %v", ud)
	}
	echoed, _ := res["client_pub_key"].(string)
	if echoed != pub {
		t.Errorf("registration must echo the registered identity: client_pub_key = %q, want %q", echoed, pub)
	}
	if id, _ := res["client_id"].(string); id != pub {
		t.Errorf("probe registration must land the caller key as the peer identity: client_id = %q, want %q", id, pub)
	}
}

// TestAWGManager_AddClient_ProbeRegistrationPersistsNoCredential asserts the
// backend-side record stays truthful for a caller-key peer: no private key and no
// PresharedKey, because neither exists for that peer.
func TestAWGManager_AddClient_ProbeRegistrationPersistsNoCredential(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 2, Host: "192.0.2.11"}

	_, pub, params := probeRegistrationParams(t)
	if _, err := mgr.AddClient(ctx, server, params); err != nil {
		t.Fatalf("probe registration failed: %v", err)
	}

	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	var entry map[string]any
	for _, c := range clients {
		if ud, ok := c["userData"].(map[string]any); ok && ud["clientName"] == "Health Probe" {
			entry = ud
		}
	}
	if entry == nil {
		t.Fatalf("no Health Probe clientsTable entry after registration: %v", clients)
	}
	if priv, _ := entry["clientPrivateKey"].(string); priv != "" {
		t.Errorf("caller-key probe peer must store no private key, got %q", priv)
	}
	if psk, _ := entry["psk"].(string); psk != "" {
		t.Errorf("caller-key probe peer must store no PresharedKey, got %q", psk)
	}

	conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	peer := peerBlockFor(t, conf, pub)
	if peer == "" {
		t.Fatalf("no [Peer] for the registered identity %s\nconfig:\n%s", pub, conf)
	}
	if strings.Contains(peer, "PresharedKey") {
		t.Errorf("probe [Peer] must carry no PresharedKey:\n%s", peer)
	}
	if !strings.Contains(peer, "AllowedIPs = ") {
		t.Errorf("probe [Peer] must stay narrowly scoped (client IP /32):\n%s", peer)
	}
	if strings.Contains(peer, "0.0.0.0/0") {
		t.Errorf("probe [Peer] must never be granted a default route:\n%s", peer)
	}
}

// TestAWGManager_AddClient_ProbeRegistrationPreservesStoredCredential is the
// regression guard for a credential that silently disappeared.
//
// A backend provisioned by the older name-only registration holds a stored
// private key for its "Health Probe" peer. The portal re-reads that credential and
// re-registers the SAME identity (its public half). The registration carries no
// private key by design, so an unconditional overwrite erased the only copy of a
// live credential — after which every later cycle generated a new key, re-pointed
// the peer and lost the stored credential again.
func TestAWGManager_AddClient_ProbeRegistrationPreservesStoredCredential(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()

	// Legacy state: name-only registration stored a keypair for the probe peer.
	legacyPriv, legacyPub := testProberKeypair(t)
	sshClient.files["/opt/amnezia/awg/clientsTable"] = []byte(`[
  {
    "clientId": "` + legacyPub + `",
    "userData": {
      "clientName": "Health Probe",
      "clientPrivateKey": "` + legacyPriv + `",
      "clientIp": "192.0.2.31",
      "psk": "pskKey123456789012345678901234567890123=",
      "enabled": true
    }
  }
]`)

	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 3, Host: "192.0.2.12"}

	if _, err := mgr.AddClient(ctx, server, map[string]any{
		"name":              "Health Probe",
		"clientName":        "Health Probe",
		"public_key":        legacyPub,
		"client_public_key": legacyPub,
	}); err != nil {
		t.Fatalf("re-registration of the stored probe identity failed: %v", err)
	}

	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	stored := ""
	for _, c := range clients {
		if ud, ok := c["userData"].(map[string]any); ok && ud["clientName"] == "Health Probe" {
			stored, _ = ud["clientPrivateKey"].(string)
		}
	}
	if stored != legacyPriv {
		t.Fatalf("re-registering an unchanged identity erased the stored probe credential: got %q, want the existing %q", stored, legacyPriv)
	}

	// The peer moved to the PSK-less probe identity, so the recorded PSK must
	// agree with the configuration that was just written: one peer, no PSK.
	conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	if peer := peerBlockFor(t, conf, legacyPub); strings.Contains(peer, "PresharedKey") {
		t.Errorf("re-registered probe [Peer] must carry no PresharedKey:\n%s", peer)
	}
	if n := strings.Count(conf, "PublicKey = "+legacyPub); n != 1 {
		t.Errorf("expected exactly one [Peer] for the probe identity, got %d\nconfig:\n%s", n, conf)
	}
}

// TestAWGManager_AddClient_IdentityChangeReplacesStoredCredential keeps the
// preservation guard from over-reaching: when the peer identity itself changes,
// the stored credential belonged to the OLD key and cannot sign for the new one,
// so it must not survive.
func TestAWGManager_AddClient_IdentityChangeReplacesStoredCredential(t *testing.T) {
	ctx := context.Background()
	sshClient := newMockAWGSSHClient()

	oldPriv, oldPub := testProberKeypair(t)
	sshClient.files["/opt/amnezia/awg/clientsTable"] = []byte(`[
  {
    "clientId": "` + oldPub + `",
    "userData": {
      "clientName": "Health Probe",
      "clientPrivateKey": "` + oldPriv + `",
      "clientIp": "192.0.2.31",
      "enabled": true
    }
  }
]`)

	mgr := NewAWGManager(&mockAWGSSHProvider{client: sshClient})
	server := &models.Server{ID: 4, Host: "192.0.2.13"}

	newPriv, newPub := alternateProberKeypair(t)
	_ = newPriv
	if _, err := mgr.AddClient(ctx, server, map[string]any{
		"name":              "Health Probe",
		"clientName":        "Health Probe",
		"public_key":        newPub,
		"client_public_key": newPub,
	}); err != nil {
		t.Fatalf("identity-changing registration failed: %v", err)
	}

	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	var entry map[string]any
	for _, c := range clients {
		if ud, ok := c["userData"].(map[string]any); ok && ud["clientName"] == "Health Probe" {
			entry = ud
			if id, _ := c["clientId"].(string); id != newPub {
				t.Errorf("peer identity = %q, want the newly registered %q", id, newPub)
			}
		}
	}
	if entry == nil {
		t.Fatalf("Health Probe entry disappeared: %v", clients)
	}
	if priv, _ := entry["clientPrivateKey"].(string); priv == oldPriv || priv != "" {
		t.Fatalf("credential of the replaced identity must not survive a caller-key re-point: got %q", priv)
	}
}
