package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/curve25519"
)

func TestAWGGetClients_ExternalPeers(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	// Add an external peer to awg0.conf not in clientsTable
	client.files["/opt/amnezia/awg/awg0.conf"] = []byte(`[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.8.1.1/24
ListenPort = 55424

[Peer]
PublicKey = externalPubkey123=
AllowedIPs = 10.8.1.99/32
`)
	provider := &mockAWGSSHProvider{client: client}
	mgr := NewAWGManager(provider)
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}

	foundExternal := false
	for _, c := range clients {
		if c["clientId"] == "externalPubkey123=" {
			foundExternal = true
			ud, _ := c["userData"].(map[string]any)
			if ext, ok := ud["externalClient"].(bool); !ok || !ext {
				t.Errorf("expected externalClient true for external peer")
			}
		}
	}
	if !foundExternal {
		t.Errorf("external peer not found in GetClients result")
	}
}

func TestAWGManager_EditClient(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	provider := &mockAWGSSHProvider{client: client}
	mgr := NewAWGManager(provider)
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// 1. Edit client name
	editParams := map[string]any{
		"name": "RenamedUser",
	}
	if err := mgr.EditClient(ctx, server, "pubkey1", editParams); err != nil {
		t.Fatalf("EditClient failed: %v", err)
	}

	clients, err := mgr.getClientsTable(ctx, client)
	if err != nil {
		t.Fatalf("getClientsTable failed: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	if clients[0].UserData.ClientName != "RenamedUser" {
		t.Errorf("expected client name RenamedUser, got %s", clients[0].UserData.ClientName)
	}

	// 2. Edit enabled status (toggle disable, then enable)
	if err := mgr.EditClient(ctx, server, "pubkey1", map[string]any{"enabled": false}); err != nil {
		t.Fatalf("EditClient(enabled=false) failed: %v", err)
	}
	clients, _ = mgr.getClientsTable(ctx, client)
	if clients[0].UserData.Enabled {
		t.Errorf("expected client to be disabled")
	}

	if err := mgr.EditClient(ctx, server, "pubkey1", map[string]any{"enabled": true}); err != nil {
		t.Fatalf("EditClient(enabled=true) failed: %v", err)
	}
	clients, _ = mgr.getClientsTable(ctx, client)
	if !clients[0].UserData.Enabled {
		t.Errorf("expected client to be enabled")
	}

	// 4. Edit mimicry
	if err := mgr.EditClient(ctx, server, "pubkey1", map[string]any{"awg_mimicry": "quic"}); err != nil {
		t.Fatalf("EditClient(mimicry) failed: %v", err)
	}
	clients, _ = mgr.getClientsTable(ctx, client)
	if clients[0].UserData.AWGMimicry != "quic" {
		t.Errorf("expected mimicry quic, got %s", clients[0].UserData.AWGMimicry)
	}

	// 5. Error cases
	if err := mgr.EditClient(ctx, server, "nonexistent", editParams); err == nil {
		t.Errorf("expected error for nonexistent client")
	}
	if err := mgr.EditClient(ctx, nil, "pubkey1", editParams); err == nil {
		t.Errorf("expected error for nil server")
	}
}

func TestAWGManager_RotateMimicry(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	provider := &mockAWGSSHProvider{client: client}
	mgr := NewAWGManager(provider)
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// Initial client has awg_mimicry: "tls"
	// Sequence: tls -> sip -> dns -> sip -> dns (cycling strictly between DPI-passing UDP profiles, with tls/quic falling back to sip)
	proto1, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || proto1 != "sip" {
		t.Fatalf("RotateMimicry 1 expected sip, got %s, err: %v", proto1, err)
	}

	proto2, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || proto2 != "dns" {
		t.Fatalf("RotateMimicry 2 expected dns, got %s, err: %v", proto2, err)
	}

	proto3, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || proto3 != "sip" {
		t.Fatalf("RotateMimicry 3 expected sip, got %s, err: %v", proto3, err)
	}

	proto4, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || proto4 != "dns" {
		t.Fatalf("RotateMimicry 4 expected dns, got %s, err: %v", proto4, err)
	}

	clients, _ := mgr.getClientsTable(ctx, client)
	if clients[0].UserData.AWGMimicry != "dns" {
		t.Errorf("expected clientsTable mimicry dns, got %s", clients[0].UserData.AWGMimicry)
	}
	if clients[0].UserData.RotatedAt == "" {
		t.Errorf("expected rotated_at timestamp to be set")
	}

	// Test auto -> dns
	clients[0].UserData.AWGMimicry = "auto"
	_ = mgr.saveClientsTable(ctx, client, clients)
	protoAuto, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || protoAuto != "dns" {
		t.Fatalf("RotateMimicry from auto expected dns, got %s, err: %v", protoAuto, err)
	}

	// Test quic -> sip
	clients[0].UserData.AWGMimicry = "quic"
	_ = mgr.saveClientsTable(ctx, client, clients)
	protoQuic, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || protoQuic != "sip" {
		t.Fatalf("RotateMimicry from quic expected sip, got %s, err: %v", protoQuic, err)
	}

	// Error cases
	if _, err := mgr.RotateMimicry(ctx, server, "nonexistent"); err == nil {
		t.Errorf("expected error for nonexistent client")
	}
	if _, err := mgr.RotateMimicry(ctx, nil, "pubkey1"); err == nil {
		t.Errorf("expected error for nil server")
	}
}

func TestAWGManager_AddClient_NameAndClientNameFallback(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// 1. Add client with "clientName" key (e.g. Health Probe)
	res1, err := mgr.AddClient(ctx, server, map[string]any{"clientName": "Health Probe"})
	if err != nil {
		t.Fatalf("AddClient with clientName failed: %v", err)
	}
	if res1["client_name"] != "Health Probe" {
		t.Errorf("expected client_name to be 'Health Probe', got %v", res1["client_name"])
	}

	// Verify clients table has "Health Probe"
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	var foundHealthProbe bool
	for _, c := range clients {
		if ud, ok := c["userData"].(map[string]any); ok {
			if ud["clientName"] == "Health Probe" {
				foundHealthProbe = true
				break
			}
		}
	}
	if !foundHealthProbe {
		t.Errorf("expected 'Health Probe' client in GetClients, got %+v", clients)
	}

	// 2. Add client with "name" key
	res2, err := mgr.AddClient(ctx, server, map[string]any{"name": "Regular User"})
	if err != nil {
		t.Fatalf("AddClient with name failed: %v", err)
	}
	if res2["client_name"] != "Regular User" {
		t.Errorf("expected client_name to be 'Regular User', got %v", res2["client_name"])
	}
}

func TestAWGManager_PublicKeyFallbackFromPrivateKeyAndPortDiscovery(t *testing.T) {
	ctx := context.Background()

	// Generate known Curve25519 keypair
	privBytes := make([]byte, 32)
	for i := range privBytes {
		privBytes[i] = byte(i + 1)
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519 failed: %v", err)
	}
	expectedPub := base64.StdEncoding.EncodeToString(pubBytes)
	privB64 := base64.StdEncoding.EncodeToString(privBytes)

	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		// Mock dynamic container discovery
		if strings.Contains(cmd, "docker ps --filter name=^'amnezia-awg2'$") && strings.Contains(cmd, "{{.Names}}") {
			return "amnezia-awg2\n", "", 0, nil
		}
		// Public key file / wg show fails
		if strings.Contains(cmd, "wireguard_server_public_key.key") || strings.Contains(cmd, "show awg0 public-key") {
			return "", "", 1, errors.New("file not found")
		}
		// Return config with PrivateKey when catting awg0.conf
		if strings.Contains(cmd, "cat") && strings.Contains(cmd, "awg0.conf") {
			return fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = 51820\n", privB64), "", 0, nil
		}
		// Docker port discovery
		if strings.Contains(cmd, "docker port") {
			return "51820/udp -> 0.0.0.0:51822\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 2, Host: "1.2.3.4"}

	// 1. Verify Curve25519 public key derivation from PrivateKey
	pubKey, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if pubKey != expectedPub {
		t.Errorf("derived public key mismatch: got %s, want %s", pubKey, expectedPub)
	}

	// 2. Verify fallback port discovery via extractContainerPort
	port := mgr.extractContainerPort(ctx, client, "amnezia-awg2")
	if port != 51822 {
		t.Errorf("extractContainerPort mismatch: got %d, want 51822", port)
	}

	// Also verify inspect format fallback
	clientInspect := newMockAWGSSHClient()
	clientInspect.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker port") {
			return "", "", 1, errors.New("no port mapping")
		}
		if strings.Contains(cmd, "docker inspect") {
			return "51823\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}
	portInspect := mgr.extractContainerPort(ctx, clientInspect, "amnezia-awg2")
	if portInspect != 51823 {
		t.Errorf("extractContainerPort via inspect mismatch: got %d, want 51823", portInspect)
	}
}

func TestAWGManager_Server2_AWG31_AddClient_And_GetClientConfig(t *testing.T) {
	ctx := context.Background()

	server2Conf := `[Interface]
PrivateKey = c2VydmVyMlByaXZLZXkxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ=
Address = 10.8.1.1/24
ListenPort = 33950
MTU = 1280
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890
HeaderProtectionKey = dGVzdC1zZXJ2ZXIyLWhwLWtleS0xMjM0NQ==
RandomTrailers = on
DisableCookies = on
`
	server2PubKey := "server2PubKey1234567890123456789012345="
	server2PSK := "server2PSK12345678901234567890123456789012="

	mockClient := &mockAWGSSHClient{
		files: map[string][]byte{
			"/opt/amnezia/awg/awg0.conf":                       []byte(server2Conf),
			"/opt/amnezia/awg/wireguard_server_public_key.key": []byte(server2PubKey),
			"/opt/amnezia/awg/wireguard_psk.key":               []byte(server2PSK),
			"/opt/amnezia/awg/clientsTable":                    []byte("[]"),
		},
		host: "91.226.221.253",
		port: 22,
	}

	var commandsExecuted []string
	mockClient.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commandsExecuted = append(commandsExecuted, cmd)

		// Any command specifically targeting "amnezia-awg" (without 2) must FAIL on Server #2
		if strings.Contains(cmd, "'amnezia-awg' ") ||
			strings.Contains(cmd, "'amnezia-awg':") ||
			strings.Contains(cmd, "name=^'amnezia-awg'$") ||
			strings.Contains(cmd, "docker exec -i 'amnezia-awg' ") {
			return "", "Error response from daemon: No such container: amnezia-awg", 1, errors.New("exit status 1")
		}

		// Container discovery for amnezia-awg2
		if strings.Contains(cmd, "docker ps --filter name=^'amnezia-awg2'$") {
			if strings.Contains(cmd, "{{.Names}}") {
				return "amnezia-awg2\n", "", 0, nil
			}
			return "Up 5 hours\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=amnezia-awg") {
			return "amnezia-awg2\n", "", 0, nil
		}

		// Reading files inside amnezia-awg2
		if strings.Contains(cmd, "'amnezia-awg2' cat '/opt/amnezia/awg/wireguard_server_public_key.key'") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "'amnezia-awg2' cat '/opt/amnezia/awg/wireguard_psk.key'") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "'amnezia-awg2' cat '/opt/amnezia/awg/awg0.conf'") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "'amnezia-awg2' cat '/opt/amnezia/awg/clientsTable'") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}

		// docker cp to amnezia-awg2
		if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config") && strings.Contains(cmd, "awg0.conf") {
			for p, c := range mockClient.files {
				if strings.Contains(p, "_amnz_edit_config") {
					mockClient.files["/opt/amnezia/awg/awg0.conf"] = c
					break
				}
			}
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_clients") && strings.Contains(cmd, "clientsTable") {
			for p, c := range mockClient.files {
				if strings.Contains(p, "_amnz_clients") {
					mockClient.files["/opt/amnezia/awg/clientsTable"] = c
					break
				}
			}
			return "", "", 0, nil
		}

		// WireGuard / TC / live remediation commands
		if strings.Contains(cmd, "tc ") || strings.Contains(cmd, "iptables") || strings.Contains(cmd, "ip route") || strings.Contains(cmd, "sysctl") {
			return "OK", "", 0, nil
		}
		if strings.Contains(cmd, "awg syncconf") || strings.Contains(cmd, "show all") {
			return "OK", "", 0, nil
		}

		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: mockClient})
	server := &models.Server{
		ID:      2,
		Host:    "91.226.221.253",
		SSHPort: 22,
	}

	// 1. AddClient
	addParams := map[string]any{
		"name": "TestServer2User",
	}
	res, err := mgr.AddClient(ctx, server, addParams)
	if err != nil {
		t.Fatalf("AddClient failed on Server #2 (amnezia-awg2): %v", err)
	}

	clientID, ok := res["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatalf("AddClient did not return valid client_id: %+v", res)
	}

	configStr, ok := res["config"].(string)
	if !ok || configStr == "" {
		t.Fatalf("AddClient did not return config: %+v", res)
	}

	// Assertions on generated client config
	if !strings.Contains(configStr, "PublicKey = "+server2PubKey) {
		t.Errorf("AddClient generated empty or wrong PublicKey: expected %s, got config:\n%s", server2PubKey, configStr)
	}
	if strings.Contains(configStr, "PublicKey = \n") {
		t.Errorf("AddClient produced config with empty PublicKey: %s", configStr)
	}
	if !strings.Contains(configStr, "HeaderProtectionKey = dGVzdC1zZXJ2ZXIyLWhwLWtleS0xMjM0NQ==") {
		t.Errorf("AddClient missing HeaderProtectionKey: %s", configStr)
	}
	if !strings.Contains(configStr, "RandomTrailers = on") {
		t.Errorf("AddClient missing RandomTrailers = on: %s", configStr)
	}
	if !strings.Contains(configStr, "DisableCookies = on") {
		t.Errorf("AddClient missing DisableCookies = on: %s", configStr)
	}
	if !strings.Contains(configStr, "Endpoint = 91.226.221.253:33950") {
		t.Errorf("AddClient missing correct Endpoint: %s", configStr)
	}

	// 2. GetClientConfig
	getClientCfg, err := mgr.GetClientConfig(ctx, server, clientID)
	if err != nil {
		t.Fatalf("GetClientConfig failed on Server #2: %v", err)
	}
	if !strings.Contains(getClientCfg, "PublicKey = "+server2PubKey) {
		t.Errorf("GetClientConfig generated empty or wrong PublicKey: expected %s, got:\n%s", server2PubKey, getClientCfg)
	}
	if strings.Contains(getClientCfg, "PublicKey = \n") {
		t.Errorf("GetClientConfig produced config with empty PublicKey: %s", getClientCfg)
	}
	if !strings.Contains(getClientCfg, "HeaderProtectionKey = dGVzdC1zZXJ2ZXIyLWhwLWtleS0xMjM0NQ==") {
		t.Errorf("GetClientConfig missing HeaderProtectionKey: %s", getClientCfg)
	}
	if !strings.Contains(getClientCfg, "RandomTrailers = on") {
		t.Errorf("GetClientConfig missing RandomTrailers = on: %s", getClientCfg)
	}
	if !strings.Contains(getClientCfg, "DisableCookies = on") {
		t.Errorf("GetClientConfig missing DisableCookies = on: %s", getClientCfg)
	}
	if !strings.Contains(getClientCfg, "Endpoint = 91.226.221.253:33950") {
		t.Errorf("GetClientConfig missing correct Endpoint: %s", getClientCfg)
	}

	// 3. RemoveClient
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient failed on Server #2: %v", err)
	}
}

func TestAWGManager_ServerPubKeyEmpty_FailsLoudly(t *testing.T) {
	ctx := context.Background()

	confWithoutPrivKey := `[Interface]
Address = 10.8.1.1/24
ListenPort = 55424
`
	mockClient := &mockAWGSSHClient{
		files: map[string][]byte{
			"/opt/amnezia/awg/awg0.conf": []byte(confWithoutPrivKey),
			"/opt/amnezia/awg/clientsTable": []byte(`[
  {
    "clientId": "testExistingClient",
    "userData": {
      "clientName": "Existing",
      "clientPrivateKey": "privkey123",
      "clientIp": "10.8.1.2"
    }
  }
]`),
		},
	}

	// Handler returns empty/error for public key retrieval
	mockClient.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "wireguard_server_public_key.key") || strings.Contains(cmd, "public-key") {
			return "", "file not found", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: mockClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// AddClient must fail loudly when server public key cannot be retrieved
	_, err := mgr.AddClient(ctx, server, map[string]any{"name": "ShouldFail"})
	if err == nil {
		t.Fatal("expected AddClient to fail loudly when server public key is empty, got nil err")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Errorf("expected error to mention public key, got: %v", err)
	}

	// GetClientConfig must also fail loudly
	_, err = mgr.GetClientConfig(ctx, server, "testExistingClient")
	if err == nil {
		t.Fatal("expected GetClientConfig to fail loudly when server public key is empty, got nil err")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Errorf("expected error to mention public key, got: %v", err)
	}
}

func TestAWGManager_RollbackAddClient_RestoresUpsertPeer(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// 1. Pre-create peer "UpsertTargetUser"
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "UpsertTargetUser",
		"awg_mimicry": "tls",
	})
	if err != nil {
		t.Fatalf("initial AddClient failed: %v", err)
	}
	if isUpsert, ok := res1["is_upsert"].(bool); ok && isUpsert {
		t.Fatalf("expected first creation to NOT be upsert")
	}

	confBeforeUpsert := string(client.files["/opt/amnezia/awg/awg0.conf"])
	clientsTableBeforeUpsert := string(client.files["/opt/amnezia/awg/clientsTable"])
	origClientID := res1["client_id"].(string)

	// 2. Perform upsert with same name and different mimicry
	res2, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "UpsertTargetUser",
		"awg_mimicry": "wireguard",
	})
	if err != nil {
		t.Fatalf("upsert AddClient failed: %v", err)
	}
	if isUpsert, ok := res2["is_upsert"].(bool); !ok || !isUpsert {
		t.Fatalf("expected second creation to be flagged as is_upsert=true, got %v", res2["is_upsert"])
	}

	// Verify that state actually changed after upsert
	confAfterUpsert := string(client.files["/opt/amnezia/awg/awg0.conf"])
	clientsTableAfterUpsert := string(client.files["/opt/amnezia/awg/clientsTable"])
	if clientsTableAfterUpsert == clientsTableBeforeUpsert {
		t.Fatalf("expected clientsTable to change after upsert")
	}
	if confAfterUpsert == confBeforeUpsert {
		t.Fatalf("expected awg0.conf to change after upsert")
	}

	// 3. Rollback the upsert (simulating DB insert failure)
	if err := mgr.RollbackAddClient(ctx, server, res2); err != nil {
		t.Fatalf("RollbackAddClient failed: %v", err)
	}

	// 4. Verify original peer survived unchanged in awg0.conf and clientsTable
	confAfterRollback := string(client.files["/opt/amnezia/awg/awg0.conf"])
	clientsTableAfterRollback := string(client.files["/opt/amnezia/awg/clientsTable"])

	if confAfterRollback != confBeforeUpsert {
		t.Errorf("expected awg0.conf to be restored to pre-upsert state.\nWant:\n%s\nGot:\n%s", confBeforeUpsert, confAfterRollback)
	}
	if clientsTableAfterRollback != clientsTableBeforeUpsert {
		t.Errorf("expected clientsTable to be restored to pre-upsert state.\nWant:\n%s\nGot:\n%s", clientsTableBeforeUpsert, clientsTableAfterRollback)
	}

	// 5. Verify the peer is still registered under origClientID
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	var foundOriginal bool
	for _, c := range clients {
		cid, _ := c["clientId"].(string)
		if cid == origClientID {
			foundOriginal = true
			if ud, ok := c["userData"].(map[string]any); ok {
				if ud["awg_mimicry"] != "tls" {
					t.Errorf("expected mimicry to be restored to tls, got %v", ud["awg_mimicry"])
				}
			}
			break
		}
	}
	if !foundOriginal {
		t.Errorf("original peer %s was deleted instead of restored!", origClientID)
	}
}

func TestAWGManager_RollbackAddClient_PreservesConcurrentModifications(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// 1. Pre-create Peer A and Peer B
	resA, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerA",
		"awg_mimicry": "tls",
	})
	if err != nil {
		t.Fatalf("AddClient PeerA failed: %v", err)
	}
	origPeerAKey := resA["client_id"].(string)

	resB, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerB",
		"awg_mimicry": "wireguard",
	})
	if err != nil {
		t.Fatalf("AddClient PeerB failed: %v", err)
	}
	origPeerBKey := resB["client_id"].(string)

	// 2. Perform upsert on Peer A
	resAUpsert, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerA",
		"awg_mimicry": "sip",
	})
	if err != nil {
		t.Fatalf("upsert AddClient PeerA failed: %v", err)
	}
	if isUpsert, ok := resAUpsert["is_upsert"].(bool); !ok || !isUpsert {
		t.Fatalf("expected is_upsert=true for PeerA upsert")
	}

	// 3. Simulate a concurrent operation on the same server: add Peer C
	resC, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerC_Concurrent",
		"awg_mimicry": "quic",
	})
	if err != nil {
		t.Fatalf("concurrent AddClient PeerC failed: %v", err)
	}
	peerCKey := resC["client_id"].(string)

	// Verify Peer C is currently in both awg0.conf and clientsTable
	confBeforeRollback := string(client.files["/opt/amnezia/awg/awg0.conf"])
	if !strings.Contains(confBeforeRollback, peerCKey) {
		t.Fatalf("expected Peer C key %s in awg0.conf before rollback", peerCKey)
	}

	// 4. Trigger RollbackAddClient for Peer A (e.g. because DB write for Peer A failed)
	if err := mgr.RollbackAddClient(ctx, server, resAUpsert); err != nil {
		t.Fatalf("RollbackAddClient PeerA failed: %v", err)
	}

	// 5. Assert:
	// - Peer A is restored to original pre-upsert state ("tls")
	// - Peer B remains intact ("wireguard")
	// - Peer C (the concurrent modification) remains intact in BOTH awg0.conf and clientsTable
	confAfterRollback := string(client.files["/opt/amnezia/awg/awg0.conf"])
	if !strings.Contains(confAfterRollback, peerCKey) {
		t.Errorf("Peer C key %s was clobbered in awg0.conf by Peer A rollback!", peerCKey)
	}
	if !strings.Contains(confAfterRollback, origPeerBKey) {
		t.Errorf("Peer B key %s was clobbered in awg0.conf by Peer A rollback!", origPeerBKey)
	}
	if !strings.Contains(confAfterRollback, origPeerAKey) {
		t.Errorf("Peer A original key %s missing in awg0.conf after rollback!", origPeerAKey)
	}

	clientsAfterRollback, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	var foundA, foundB, foundC bool
	for _, c := range clientsAfterRollback {
		cid, _ := c["clientId"].(string)
		ud, _ := c["userData"].(map[string]any)
		var name string
		if ud != nil {
			name, _ = ud["clientName"].(string)
		}
		switch name {
		case "PeerA":
			foundA = true
			if cid != origPeerAKey {
				t.Errorf("Peer A key mismatch: want %s, got %s", origPeerAKey, cid)
			}
			if ud["awg_mimicry"] != "tls" {
				t.Errorf("Peer A mimicry want tls, got %v", ud["awg_mimicry"])
			}
		case "PeerB":
			foundB = true
			if cid != origPeerBKey {
				t.Errorf("Peer B key mismatch: want %s, got %s", origPeerBKey, cid)
			}
			if ud["awg_mimicry"] != "wireguard" {
				t.Errorf("Peer B mimicry want wireguard, got %v", ud["awg_mimicry"])
			}
		case "PeerC_Concurrent":
			foundC = true
			if cid != peerCKey {
				t.Errorf("Peer C key mismatch: want %s, got %s", peerCKey, cid)
			}
			if ud["awg_mimicry"] != "quic" {
				t.Errorf("Peer C mimicry want quic, got %v", ud["awg_mimicry"])
			}
		}
	}

	if !foundA {
		t.Errorf("Peer A missing from clientsTable after rollback")
	}
	if !foundB {
		t.Errorf("Peer B missing from clientsTable after rollback")
	}
	if !foundC {
		t.Errorf("Peer C (concurrent change) missing from clientsTable after rollback!")
	}
}

func TestAWGManager_RollbackAddClient_AbstainsOnSupersededPeer(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	// 1. Initial creation: Peer A = K0 ("tls")
	res0, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerA",
		"awg_mimicry": "tls",
	})
	if err != nil {
		t.Fatalf("AddClient PeerA (K0) failed: %v", err)
	}
	keyK0 := res0["client_id"].(string)

	// 2. Request 1 upserts Peer A -> K1 ("sip")
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerA",
		"awg_mimicry": "sip",
	})
	if err != nil {
		t.Fatalf("Request 1 upsert PeerA (K1) failed: %v", err)
	}
	keyK1 := res1["client_id"].(string)

	// 3. Request 2 upserts same Peer A -> K2 ("quic") and succeeds
	res2, err := mgr.AddClient(ctx, server, map[string]any{
		"name":        "PeerA",
		"awg_mimicry": "quic",
	})
	if err != nil {
		t.Fatalf("Request 2 upsert PeerA (K2) failed: %v", err)
	}
	keyK2 := res2["client_id"].(string)

	// 4. Request 1's subsequent DB write fails, so Request 1 triggers RollbackAddClient(res1)
	if err := mgr.RollbackAddClient(ctx, server, res1); err != nil {
		t.Fatalf("RollbackAddClient Request 1 failed: %v", err)
	}

	// 5. Assert:
	// - Rollback for Request 1 detected that Peer A was superseded by Request 2 (K2)
	// - Newer state K2 remains active in both clientsTable and awg0.conf
	// - Old K0 was NOT restored over K2!
	confAfterRollback := string(client.files["/opt/amnezia/awg/awg0.conf"])
	if !strings.Contains(confAfterRollback, keyK2) {
		t.Errorf("Superseding key K2 %s was lost from awg0.conf after Request 1 rollback!", keyK2)
	}
	if strings.Contains(confAfterRollback, keyK0) {
		t.Errorf("Old key K0 %s was erroneously restored over superseding key K2 in awg0.conf!", keyK0)
	}
	if strings.Contains(confAfterRollback, keyK1) {
		t.Errorf("Rolled back key K1 %s is still present in awg0.conf!", keyK1)
	}

	clientsAfterRollback, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	var foundPeerA bool
	for _, c := range clientsAfterRollback {
		cid, _ := c["clientId"].(string)
		ud, _ := c["userData"].(map[string]any)
		if ud != nil && ud["clientName"] == "PeerA" {
			foundPeerA = true
			if cid != keyK2 {
				t.Errorf("expected active client to remain K2 %s, got %s", keyK2, cid)
			}
		}
	}
	if !foundPeerA {
		t.Errorf("PeerA missing from clientsTable after rollback")
	}
}
