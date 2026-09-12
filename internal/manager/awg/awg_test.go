package awg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/ssh"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"golang.org/x/crypto/curve25519"
	gossh "golang.org/x/crypto/ssh"
)

type mockAWGSSHClient struct {
	files             map[string][]byte
	sudoCmdHandler    func(cmd string) (string, string, int, error)
	sudoScriptHandler func(script string) (string, string, int, error)
	host              string
	port              int
	serverID          *int64
}

func newMockAWGSSHClient() *mockAWGSSHClient {
	c := &mockAWGSSHClient{
		files: make(map[string][]byte),
	}
	// Seed initial server keys and config
	c.files["/opt/amnezia/awg/wireguard_server_public_key.key"] = []byte("serverPubKey1234567890123456789012345=")
	c.files["/opt/amnezia/awg/wireguard_server_private_key.key"] = []byte("serverPrivKey1234567890123456789012345=")
	c.files["/opt/amnezia/awg/wireguard_psk.key"] = []byte("pskKey123456789012345678901234567890123=")
	c.files["/opt/amnezia/awg/awg0.conf"] = []byte(`[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.8.1.1/24
ListenPort = 55424
MTU = 1280
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890
`)
	c.files["/opt/amnezia/awg/clientsTable"] = []byte(`[
  {
    "clientId": "pubkey1",
    "userData": {
      "clientName": "TestClient1",
      "clientPrivateKey": "privkey1",
      "clientIp": "10.8.1.2",
      "psk": "pskKey123456789012345678901234567890123=",
      "enabled": true,
      "awg_mimicry": "tls"
    }
  }
]`)
	return c
}

func (m *mockAWGSSHClient) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker --version") {
		return "Docker version 24.0.5", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *mockAWGSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if m.sudoCmdHandler != nil {
		return m.sudoCmdHandler(cmd)
	}
	if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
		return string(m.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
	}
	if strings.Contains(cmd, "cat /opt/amnezia/awg/clientsTable") {
		return string(m.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
	}
	if strings.Contains(cmd, "cat /opt/amnezia/awg/wireguard_server_public_key.key") {
		return string(m.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
	}
	if strings.Contains(cmd, "cat /opt/amnezia/awg/wireguard_psk.key") {
		return string(m.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
	}
	if strings.Contains(cmd, "docker cp /tmp/_amnz_clients.json") {
		m.files["/opt/amnezia/awg/clientsTable"] = m.files["/tmp/_amnz_clients.json"]
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp /tmp/_amnz_edit_config.conf") {
		m.files["/opt/amnezia/awg/awg0.conf"] = m.files["/tmp/_amnz_edit_config.conf"]
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp /tmp/_amnz_awg0.conf") {
		m.files["/opt/amnezia/awg/awg0.conf"] = m.files["/tmp/_amnz_awg0.conf"]
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps --filter name=^") {
		if strings.Contains(cmd, "{{.Names}}") {
			for _, name := range AWGContainerNames {
				if strings.Contains(cmd, name) {
					return name, "", 0, nil
				}
			}
			return "amnezia-awg", "", 0, nil
		}
		return "Up 2 hours", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps -a --filter name=^") {
		for _, name := range AWGContainerNames {
			if strings.Contains(cmd, name) {
				return name, "", 0, nil
			}
		}
		return "amnezia-awg", "", 0, nil
	}
	if strings.Contains(cmd, "wireguard_server_public_key.key") || strings.Contains(cmd, "public-key") {
		return "serverPubKey123456789012345678901234567890=", "", 0, nil
	}
	if strings.Contains(cmd, "wireguard_psk.key") {
		return "serverPSK1234567890123456789012345678901234=", "", 0, nil
	}
	if strings.Contains(cmd, "awg show all") {
		return "peer: pubkey1\n  latest handshake: 1 minute ago\n  transfer: 1.50 MiB received, 3.20 MiB sent\n  allowed ips: 10.8.1.2/32\n", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *mockAWGSSHClient) RunScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *mockAWGSSHClient) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	if m.sudoScriptHandler != nil {
		return m.sudoScriptHandler(script)
	}
	return "OK", "", 0, nil
}

func (m *mockAWGSSHClient) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.files[remotePath] = content
	return nil
}

func (m *mockAWGSSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.files[remotePath] = content
	return nil
}

func (m *mockAWGSSHClient) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	return m.files[remotePath], nil
}

func (m *mockAWGSSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	_, exists := m.files[remotePath]
	return exists, nil
}

func (m *mockAWGSSHClient) TestConnection(ctx context.Context) (string, error) {
	return "Linux", nil
}

func (m *mockAWGSSHClient) Close() error {
	return nil
}

func (m *mockAWGSSHClient) IsAlive() bool {
	return true
}

func (m *mockAWGSSHClient) GetUnderlyingClient() *gossh.Client {
	return nil
}

func (m *mockAWGSSHClient) GetHost() string {
	if m.host != "" {
		return m.host
	}
	return "127.0.0.1"
}

func (m *mockAWGSSHClient) GetPort() int {
	if m.port != 0 {
		return m.port
	}
	return 22
}

func (m *mockAWGSSHClient) GetUser() string {
	return "root"
}

func (m *mockAWGSSHClient) GetServerID() *int64 {
	return m.serverID
}

func (m *mockAWGSSHClient) GetLastActive() time.Time {
	return time.Now()
}

type mockAWGSSHProvider struct {
	client *mockAWGSSHClient
}

func (p *mockAWGSSHProvider) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	if p.client == nil {
		p.client = newMockAWGSSHClient()
	}
	return p.client, nil
}

func TestAWGManagerLifecycle(t *testing.T) {
	ctx := context.Background()
	provider := &mockAWGSSHProvider{}
	mgr := NewAWGManager(provider)

	server := &models.Server{
		ID:      1,
		Host:    "1.2.3.4",
		SSHPort: 22,
		SSHUser: "root",
	}

	if proto := mgr.Protocol(); proto != "awg" {
		t.Errorf("expected protocol awg, got %s", proto)
	}

	// 1. Test Install
	params := map[string]any{
		"port":        "55424",
		"awg_profile": "standard",
	}
	if err := mgr.Install(ctx, server, params); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// 2. Test GetServerStatus
	status, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus failed: %v", err)
	}
	if exists, ok := status["container_exists"].(bool); !ok || !exists {
		t.Errorf("expected container_exists to be true")
	}

	// 3. Test GetClients
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	if len(clients) == 0 {
		t.Errorf("expected clients list not to be empty")
	}

	// 4. Test AddClient
	addParams := map[string]any{
		"name":                 "NewUser",
		"awg_speed_limit_down": 20,
		"awg_speed_limit_up":   10,
		"awg_mimicry":          "tls",
	}
	newClient, err := mgr.AddClient(ctx, server, addParams)
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}
	clientID, ok := newClient["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatalf("AddClient did not return client_id")
	}

	// 5. Test GetClientConfig
	conf, err := mgr.GetClientConfig(ctx, server, clientID)
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if !strings.Contains(conf, "[Interface]") || !strings.Contains(conf, "[Peer]") {
		t.Errorf("GetClientConfig returned invalid config:\n%s", conf)
	}

	// 6. Test ToggleClient
	if err := mgr.ToggleClient(ctx, server, clientID, false); err != nil {
		t.Fatalf("ToggleClient(disable) failed: %v", err)
	}
	if err := mgr.ToggleClient(ctx, server, clientID, true); err != nil {
		t.Fatalf("ToggleClient(enable) failed: %v", err)
	}

	// 7. Test RemoveClient
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}

	// 8. Test Uninstall
	if err := mgr.Uninstall(ctx, server); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	// 9. Error tests: nonexistent client
	if _, err := mgr.GetClientConfig(ctx, server, "nonexistent"); err == nil {
		t.Errorf("expected error for nonexistent client config")
	}
	if err := mgr.ToggleClient(ctx, server, "nonexistent", true); err == nil {
		t.Errorf("expected error for nonexistent client toggle")
	}

	// 10. Nil server / pool errors
	nilMgr := NewAWGManager(nil)
	if err := nilMgr.Install(ctx, server, nil); err == nil {
		t.Errorf("expected error for nil ssh pool")
	}
	if err := mgr.Install(ctx, nil, nil); err == nil {
		t.Errorf("expected error for nil server")
	}
}

func TestParseSizeHuman(t *testing.T) {
	cases := []struct {
		input string
		want  int64
	}{
		{"100 KiB", 100 * 1024},
		{"2.5 MiB", int64(2.5 * 1024 * 1024)},
		{"1.5 GiB", int64(1.5 * 1024 * 1024 * 1024)},
		{"1 TiB", 1024 * 1024 * 1024 * 1024},
		{"invalid", 0},
		{"100", 0},
	}
	for _, tc := range cases {
		got := parseSizeHuman(tc.input)
		if got != tc.want {
			t.Errorf("parseSizeHuman(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

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

	// 1. Edit client name and speed limits
	editParams := map[string]any{
		"name":             "RenamedUser",
		"speed_limit_down": 50,
		"speed_limit_up":   25,
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
	if clients[0].UserData.SpeedLimitDown == nil || *clients[0].UserData.SpeedLimitDown != 50 {
		t.Errorf("expected speed_limit_down 50, got %v", clients[0].UserData.SpeedLimitDown)
	}
	if clients[0].UserData.SpeedLimitUp == nil || *clients[0].UserData.SpeedLimitUp != 25 {
		t.Errorf("expected speed_limit_up 25, got %v", clients[0].UserData.SpeedLimitUp)
	}

	// 2. Remove speed limits (set to 0)
	clearLimits := map[string]any{
		"speed_limit_down": 0,
		"speed_limit_up":   0,
	}
	if err := mgr.EditClient(ctx, server, "pubkey1", clearLimits); err != nil {
		t.Fatalf("EditClient(clear limits) failed: %v", err)
	}
	clients, _ = mgr.getClientsTable(ctx, client)
	if clients[0].UserData.SpeedLimitDown != nil {
		t.Errorf("expected nil speed_limit_down, got %v", clients[0].UserData.SpeedLimitDown)
	}

	// 3. Edit enabled status (toggle disable, then enable)
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
	// Sequence: tls -> quic -> dns -> sip -> tls
	proto1, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || proto1 != "quic" {
		t.Fatalf("RotateMimicry 1 expected quic, got %s, err: %v", proto1, err)
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
	if err != nil || proto4 != "tls" {
		t.Fatalf("RotateMimicry 4 expected tls, got %s, err: %v", proto4, err)
	}

	clients, _ := mgr.getClientsTable(ctx, client)
	if clients[0].UserData.AWGMimicry != "tls" {
		t.Errorf("expected clientsTable mimicry tls, got %s", clients[0].UserData.AWGMimicry)
	}
	if clients[0].UserData.RotatedAt == "" {
		t.Errorf("expected rotated_at timestamp to be set")
	}

	// Test auto -> tls
	clients[0].UserData.AWGMimicry = "auto"
	_ = mgr.saveClientsTable(ctx, client, clients)
	protoAuto, err := mgr.RotateMimicry(ctx, server, "pubkey1")
	if err != nil || protoAuto != "tls" {
		t.Fatalf("RotateMimicry from auto expected tls, got %s, err: %v", protoAuto, err)
	}

	// Error cases
	if _, err := mgr.RotateMimicry(ctx, server, "nonexistent"); err == nil {
		t.Errorf("expected error for nonexistent client")
	}
	if _, err := mgr.RotateMimicry(ctx, nil, "pubkey1"); err == nil {
		t.Errorf("expected error for nil server")
	}
}

func TestAWGManager_GetServerStatus_LegacyContainersAndErrors(t *testing.T) {
	ctx := context.Background()

	// Test with amnezia-awg2 container
	client2 := newMockAWGSSHClient()
	client2.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps -a --filter name=^amnezia-awg2$") {
			return "amnezia-awg2\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps -a --filter") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=^amnezia-awg2$") {
			return "Up 5 hours", "", 0, nil
		}
		return "OK", "", 0, nil
	}
	mgr2 := NewAWGManager(&mockAWGSSHProvider{client: client2})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}
	status2, err := mgr2.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus failed for amnezia-awg2: %v", err)
	}
	if exists, ok := status2["container_exists"].(bool); !ok || !exists {
		t.Errorf("expected amnezia-awg2 to exist")
	}
	if running, ok := status2["container_running"].(bool); !ok || !running {
		t.Errorf("expected amnezia-awg2 to be running")
	}

	// Test with docker daemon error
	clientErr := newMockAWGSSHClient()
	clientErr.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			return "", "Cannot connect to the Docker daemon", 1, errors.New("exit code 1")
		}
		return "", "", 0, nil
	}
	mgrErr := NewAWGManager(&mockAWGSSHProvider{client: clientErr})
	if _, err := mgrErr.GetServerStatus(ctx, server); err == nil {
		t.Errorf("expected GetServerStatus to fail when docker daemon fails")
	}

	// Test GetServerPublicKey and GetServerPSK
	pubKey, err := mgr2.GetServerPublicKey(ctx, server)
	if err != nil || pubKey == "" {
		t.Errorf("GetServerPublicKey failed: %v", err)
	}
	psk, err := mgr2.GetServerPSK(ctx, server)
	if err != nil || psk == "" {
		t.Errorf("GetServerPSK failed: %v", err)
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
		if strings.Contains(cmd, "docker ps --filter name=^amnezia-awg2$") && strings.Contains(cmd, "{{.Names}}") {
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

func TestIsValidContainerName(t *testing.T) {
	validNames := []string{
		"amnezia-awg",
		"amnezia-awg2",
		"amnezia-awg-legacy",
		"container.1_test",
		"my-awg-server.node",
		"A123_456",
		"awg0",
		"server-1",
		"test.container-name_v1.0",
	}
	for _, name := range validNames {
		if !IsValidContainerName(name) {
			t.Errorf("expected valid container name %q to pass validation", name)
		}
	}

	invalidNames := []string{
		"",
		"amnezia; rm -rf /",
		"amnezia`whoami`",
		"amnezia$(id)",
		"amnezia container",
		"../../etc/passwd",
		"-leading-dash",
		".leading-dot",
		"_leading-underscore",
		"container|cat",
		"container>file",
		"container&",
		"container\nnewline",
		"container'quoted'",
		"container\"quoted\"",
		"container/sub",
		"container\\sub",
		"container#comment",
		"container!bang",
	}
	for _, name := range invalidNames {
		if IsValidContainerName(name) {
			t.Errorf("expected invalid container name %q to fail validation", name)
		}
	}
}

func TestAWGManager_ContainerCaching(t *testing.T) {
	ctx := context.Background()
	var dockerPsCount int
	sID := int64(100)

	client := newMockAWGSSHClient()
	client.host = "10.0.0.1"
	client.port = 22
	client.serverID = &sID
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			dockerPsCount++
			if strings.Contains(cmd, "amnezia-awg2") {
				return "amnezia-awg2\n", "", 0, nil
			}
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(client.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{
		ID:      sID,
		Host:    "10.0.0.1",
		SSHPort: 22,
	}

	// 1. Initial resolution: cache miss, executes SSH discovery
	cName := mgr.resolveContainerName(ctx, client)
	if cName != "amnezia-awg2" {
		t.Fatalf("expected resolved name amnezia-awg2, got %q", cName)
	}
	initialPsCount := dockerPsCount
	if initialPsCount == 0 {
		t.Fatal("expected docker ps to be executed on cache miss")
	}

	// 2. Repeated resolution: cache hit, no duplicate SSH commands
	cName2 := mgr.resolveContainerName(ctx, client)
	if cName2 != "amnezia-awg2" {
		t.Fatalf("expected cached name amnezia-awg2, got %q", cName2)
	}
	if dockerPsCount != initialPsCount {
		t.Fatalf("expected no additional docker ps commands on cache hit; got %d, want %d", dockerPsCount, initialPsCount)
	}

	// 3. Different client instance with same server ID/host: cache hit
	client2 := newMockAWGSSHClient()
	client2.host = "10.0.0.1"
	client2.port = 22
	client2.serverID = &sID
	client2.sudoCmdHandler = client.sudoCmdHandler

	cName3 := mgr.resolveContainerName(ctx, client2)
	if cName3 != "amnezia-awg2" {
		t.Fatalf("expected cached name amnezia-awg2 on client2, got %q", cName3)
	}
	if dockerPsCount != initialPsCount {
		t.Fatalf("expected no additional docker ps commands on client2 cache hit; got %d, want %d", dockerPsCount, initialPsCount)
	}

	// 4. Test GetServerStatus records foundName in cache and passes it downstream
	sID2 := int64(200)
	clientStatus := newMockAWGSSHClient()
	clientStatus.host = "10.0.0.2"
	clientStatus.port = 22
	clientStatus.serverID = &sID2
	var statusPsCount int
	clientStatus.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			statusPsCount++
			var res string
			if strings.Contains(cmd, "ps -a") && strings.Contains(cmd, "amnezia-awg2") {
				res = "amnezia-awg2\n"
			} else if strings.Contains(cmd, "Status") || strings.Contains(cmd, "status") {
				res = "Up 3 hours\n"
			}
			return res, "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(clientStatus.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "docker port") {
			return "0.0.0.0:55424\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgrStatus := NewAWGManager(&mockAWGSSHProvider{client: clientStatus})
	serverStatus := &models.Server{
		ID:      sID2,
		Host:    "10.0.0.2",
		SSHPort: 22,
	}

	st, err := mgrStatus.GetServerStatus(ctx, serverStatus)
	if err != nil {
		t.Fatalf("GetServerStatus failed: %v", err)
	}
	if st["container_running"] != true {
		t.Errorf("expected container_running=true, got %v", st["container_running"])
	}

	// Check that subsequent resolveContainerName uses the cached name recorded by GetServerStatus
	countBeforeResolve := statusPsCount
	resolvedFromStatus := mgrStatus.resolveContainerName(ctx, clientStatus)
	if resolvedFromStatus != "amnezia-awg2" {
		t.Fatalf("expected cached name amnezia-awg2 from GetServerStatus, got %q", resolvedFromStatus)
	}
	if statusPsCount != countBeforeResolve {
		t.Errorf("resolveContainerName issued unexpected SSH commands after GetServerStatus cached foundName")
	}

	// 5. Test cache invalidation on Uninstall
	if err := mgr.Uninstall(ctx, server); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	psCountAfterUninstall := dockerPsCount
	_ = mgr.resolveContainerName(ctx, client)
	if dockerPsCount <= psCountAfterUninstall {
		t.Errorf("expected cache miss and new docker ps command after Uninstall invalidation")
	}
}

func TestAWGManager_ResolveContainerName_MaliciousRejected(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	client.host = "10.0.0.99"
	client.port = 22
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			// Malicious injection attempt in container name output
			return "amnezia-awg; rm -rf /\n", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	cName := mgr.resolveContainerName(ctx, client)

	// Malicious name must be rejected and fallback to safe default "amnezia-awg2"
	if cName != "amnezia-awg2" {
		t.Fatalf("expected fallback to safe default 'amnezia-awg2', got %q", cName)
	}
	if !IsValidContainerName(cName) {
		t.Fatalf("fallback name %q is not valid", cName)
	}

	// Also verify extractContainerPort rejects malicious containerName argument
	var injectedCmd string
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		injectedCmd = cmd
		return "", "", 0, nil
	}
	_ = mgr.extractContainerPort(ctx, client, "amnezia-awg`whoami`")
	if strings.Contains(injectedCmd, "`whoami`") {
		t.Fatalf("malicious container name was interpolated into command: %s", injectedCmd)
	}

	// Also verify getServerConfig rejects malicious containerName argument
	injectedCmd = ""
	_, _ = mgr.getServerConfig(ctx, client, "amnezia-awg; id")
	if strings.Contains(injectedCmd, "; id") {
		t.Fatalf("malicious container name was interpolated into command: %s", injectedCmd)
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
		if strings.Contains(cmd, " amnezia-awg ") ||
			strings.Contains(cmd, " amnezia-awg:") ||
			strings.Contains(cmd, "name=^amnezia-awg$") ||
			strings.Contains(cmd, "docker exec -i amnezia-awg ") {
			return "", "Error response from daemon: No such container: amnezia-awg", 1, errors.New("exit status 1")
		}

		// Container discovery for amnezia-awg2
		if strings.Contains(cmd, "docker ps --filter name=^amnezia-awg2$") {
			if strings.Contains(cmd, "{{.Names}}") {
				return "amnezia-awg2\n", "", 0, nil
			}
			return "Up 5 hours\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=amnezia-awg") {
			return "amnezia-awg2\n", "", 0, nil
		}

		// Reading files inside amnezia-awg2
		if strings.Contains(cmd, "amnezia-awg2 cat /opt/amnezia/awg/wireguard_server_public_key.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "amnezia-awg2 cat /opt/amnezia/awg/wireguard_psk.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "amnezia-awg2 cat /opt/amnezia/awg/awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "amnezia-awg2 cat /opt/amnezia/awg/clientsTable") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}

		// docker cp to amnezia-awg2
		if strings.Contains(cmd, "docker cp /tmp/_amnz_edit_config.conf amnezia-awg2:/opt/amnezia/awg/awg0.conf") {
			mockClient.files["/opt/amnezia/awg/awg0.conf"] = mockClient.files["/tmp/_amnz_edit_config.conf"]
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp /tmp/_amnz_clients.json amnezia-awg2:/opt/amnezia/awg/clientsTable") {
			mockClient.files["/opt/amnezia/awg/clientsTable"] = mockClient.files["/tmp/_amnz_clients.json"]
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
		"name":                 "TestServer2User",
		"awg_speed_limit_down": 50,
		"awg_speed_limit_up":   25,
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
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/clientsTable") {
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

func TestAWGManager_SaveServerConfig_SyncconfFailure_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockAWGSSHClient()

	mockClient.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "syncconf") {
			return "", "Line unrecognized: `DisableCookies = on`", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/clientsTable") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_server_public_key.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_psk.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: mockClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	_, err := mgr.AddClient(ctx, server, map[string]any{"name": "SyncFailClient"})
	if err == nil {
		t.Fatal("expected AddClient to fail when syncconf fails, but got nil")
	}
	if !strings.Contains(err.Error(), "sync") {
		t.Errorf("expected error to mention sync, got: %v", err)
	}
}

func TestAWGManager_SaveServerConfig_DynamicConfigPath(t *testing.T) {
	ctx := context.Background()
	mockClient := newMockAWGSSHClient()

	var copiedTarget string
	var syncCmdExecuted string

	mockClient.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "test -f /opt/amnezia/awg/awg0.conf") {
			return "", "No such file", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "test -f /etc/amnezia/amneziawg/awg0.conf") {
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config.conf") {
			copiedTarget = cmd
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "syncconf") {
			syncCmdExecuted = cmd
			return "OK", "", 0, nil
		}
		if strings.Contains(cmd, "cat /etc/amnezia/amneziawg/awg0.conf") {
			return string(mockClient.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return "", "No such file", 1, errors.New("exit status 1")
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/clientsTable") {
			return string(mockClient.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_server_public_key.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "wireguard_psk.key") {
			return string(mockClient.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: mockClient})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	_, err := mgr.AddClient(ctx, server, map[string]any{"name": "DynamicPathClient"})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	if !strings.Contains(copiedTarget, "/etc/amnezia/amneziawg/awg0.conf") {
		t.Errorf("expected config to be copied to /etc/amnezia/amneziawg/awg0.conf, got: %s", copiedTarget)
	}
	if !strings.Contains(syncCmdExecuted, "/etc/amnezia/amneziawg/awg0.conf") {
		t.Errorf("expected syncconf to target /etc/amnezia/amneziawg/awg0.conf, got: %s", syncCmdExecuted)
	}
}

func TestBuildAndRunAWGContainer_PinnedImageAndPull(t *testing.T) {
	var dockerfile string
	var commands []string
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commands = append(commands, cmd)
		if strings.Contains(cmd, "docker build") {
			uploaded, ok := client.files["/opt/amnezia/amnezia-awg2/Dockerfile"]
			if !ok {
				return "", "Dockerfile missing", 1, nil
			}
			dockerfile = string(uploaded)
		}
		return "OK", "", 0, nil
	}

	if err := buildAndRunAWGContainer(context.Background(), client, "55424"); err != nil {
		t.Fatalf("buildAndRunAWGContainer failed: %v", err)
	}

	if dockerfile == "" {
		t.Fatalf("Dockerfile was never uploaded before docker build")
	}
	if !strings.Contains(dockerfile, "FROM "+awgBaseImage+"\n") {
		t.Errorf("Dockerfile must pin FROM %s, got:\n%s", awgBaseImage, dockerfile)
	}
	if strings.Contains(dockerfile, ":latest") {
		t.Errorf("Dockerfile must not reference :latest, got:\n%s", dockerfile)
	}

	pullIdx, buildIdx := -1, -1
	for i, cmd := range commands {
		if strings.HasPrefix(cmd, "docker pull "+awgBaseImage) && pullIdx == -1 {
			pullIdx = i
		}
		if strings.Contains(cmd, "docker build") && buildIdx == -1 {
			buildIdx = i
		}
	}
	if pullIdx == -1 {
		t.Errorf("expected an explicit %q command, got: %v", "docker pull "+awgBaseImage, commands)
	}
	if buildIdx == -1 {
		t.Errorf("expected a docker build command, got: %v", commands)
	}
	if pullIdx != -1 && buildIdx != -1 && pullIdx > buildIdx {
		t.Errorf("docker pull (idx %d) must run before docker build (idx %d)", pullIdx, buildIdx)
	}
}

func TestBuildAndRunAWGContainer_PullFailureAborts(t *testing.T) {
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.HasPrefix(cmd, "docker pull ") {
			return "", "manifest unknown", 1, nil
		}
		if strings.Contains(cmd, "docker build") {
			t.Error("docker build must not run when the base image pull fails")
		}
		return "OK", "", 0, nil
	}

	err := buildAndRunAWGContainer(context.Background(), client, "55424")
	if err == nil {
		t.Fatalf("expected an error when docker pull fails")
	}
	if !strings.Contains(err.Error(), awgBaseImage) {
		t.Errorf("error should mention the pinned base image, got: %v", err)
	}
}

// TestInstall_HeaderProtectionDefaultOn verifies the plumbing contract:
// absent awg_header_protection defaults to true (AWG 3.1), explicit false
// keeps 2.0 semantics, explicit true generates 3.1 params.
func TestInstall_HeaderProtectionDefaultOn(t *testing.T) {
	tests := []struct {
		name        string
		hpValue     any
		wantHPKey   bool
		wantRandom  bool
		wantCookies bool
	}{
		{name: "absent_defaults_true", hpValue: nil, wantHPKey: true, wantRandom: true, wantCookies: true},
		{name: "explicit_true", hpValue: true, wantHPKey: true, wantRandom: true, wantCookies: true},
		{name: "string_true", hpValue: "true", wantHPKey: true, wantRandom: true, wantCookies: true},
		{name: "explicit_false_2_0", hpValue: false, wantHPKey: false, wantRandom: false, wantCookies: false},
		{name: "string_false_2_0", hpValue: "false", wantHPKey: false, wantRandom: false, wantCookies: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]any{"port": "55424", "awg_profile": "standard"}
			if tc.hpValue != nil {
				params["awg_header_protection"] = tc.hpValue
			}

			awgParams, err := generateAWGParamsForInstall(params)
			if err != nil {
				t.Fatalf("generateAWGParamsForInstall failed: %v", err)
			}
			hasHP := awgParams.HeaderProtectionKey != ""
			if hasHP != tc.wantHPKey {
				t.Errorf("HeaderProtectionKey present = %v, want %v", hasHP, tc.wantHPKey)
			}
			if (awgParams.RandomTrailers != "") != tc.wantRandom {
				t.Errorf("RandomTrailers present = %v, want %v", awgParams.RandomTrailers != "", tc.wantRandom)
			}
			if (awgParams.DisableCookies != "") != tc.wantCookies {
				t.Errorf("DisableCookies present = %v, want %v", awgParams.DisableCookies != "", tc.wantCookies)
			}
		})
	}
}

// generateAWGParamsForInstall mirrors Install()'s header-protection defaulting
// logic so the default-on contract is testable without touching live hosts.
func generateAWGParamsForInstall(params map[string]any) (*AWGParams, error) {
	profile := "standard"
	if p, ok := params["awg_profile"]; ok && fmt.Sprint(p) != "" {
		profile = fmt.Sprint(p)
	}
	hpOn := true
	if v, ok := parseBoolParam(params["awg_header_protection"]); ok {
		hpOn = v
	}
	return GenerateAWGParams(profile, hpOn)
}

func TestGetServerStatus_ProtocolGenerationEnrichment(t *testing.T) {
	tests := []struct {
		name              string
		conf              string
		wantGeneration    string
		wantHasGeneration bool
	}{
		{
			name: "31_backend_reports_3_1",
			conf: `[Interface]
PrivateKey = k
Address = 10.8.1.1/24
MTU = 1280
ListenPort = 55424
Jc = 4
H1 = 12345
HeaderProtectionKey = AbCdEf1234567890AbCdEf1234567890AbCdEf12=
RandomTrailers = on
DisableCookies = on
`,
			wantGeneration:    "3.1",
			wantHasGeneration: true,
		},
		{
			name: "20_backend_reports_2_0",
			conf: `[Interface]
PrivateKey = k
Address = 10.8.1.1/24
MTU = 1280
ListenPort = 55424
Jc = 4
H1 = 12345
`,
			wantGeneration:    "2.0",
			wantHasGeneration: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockAWGSSHClient()
			client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
				if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
					return tc.conf, "", 0, nil
				}
				if strings.Contains(cmd, "awg --version") {
					return "wireguard-go version 0.0.20230223-amneziawg\n", "", 0, nil
				}
				if strings.Contains(cmd, "docker ps --filter") {
					return "Up 2 hours", "", 0, nil
				}
				if strings.Contains(cmd, "docker ps -a --filter") {
					return "amnezia-awg", "", 0, nil
				}
				return "OK", "", 0, nil
			}
			mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
			server := &models.Server{ID: 1, Host: "1.2.3.4"}

			status, err := mgr.GetServerStatus(context.Background(), server)
			if err != nil {
				t.Fatalf("GetServerStatus failed: %v", err)
			}
			if got, ok := status["protocol_generation"]; !ok || got != tc.wantGeneration {
				t.Errorf("protocol_generation = %v (present=%v), want %q", got, ok, tc.wantGeneration)
			}
			if v, ok := status["awg_version"]; !ok || v != "wireguard-go version 0.0.20230223-amneziawg" {
				t.Errorf("awg_version = %v (present=%v), want mocked version line", v, ok)
			}
		})
	}
}

func TestGetServerStatus_AWGVersionNonFatal(t *testing.T) {
	client := newMockAWGSSHClient()
	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "awg --version") {
			return "", "command not found", 127, nil
		}
		if strings.Contains(cmd, "docker ps --filter") {
			return "Up 2 hours", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps -a --filter") {
			return "amnezia-awg", "", 0, nil
		}
		return "OK", "", 0, nil
	}
	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 1, Host: "1.2.3.4"}

	status, err := mgr.GetServerStatus(context.Background(), server)
	if err != nil {
		t.Fatalf("GetServerStatus must not fail when awg --version fails: %v", err)
	}
	if v, ok := status["awg_version"]; ok && fmt.Sprint(v) != "" {
		t.Errorf("awg_version should be absent/empty on failure, got %v", v)
	}
	// protocol_generation comes from the config, which still parses fine here.
	if got := status["protocol_generation"]; got != "2.0" {
		t.Errorf("protocol_generation = %v, want 2.0", got)
	}
}

func TestInstall_CreatesAWG2Container_CommandsAndConfig(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commandsRun []string

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commandsRun = append(commandsRun, cmd)
		if strings.Contains(cmd, "docker ps") {
			if strings.Contains(cmd, "amnezia-awg2") {
				return "amnezia-awg2\n", "", 0, nil
			}
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp") {
			return "", "", 0, nil
		}
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	if mgr.containerName() != "amnezia-awg2" {
		t.Fatalf("expected default containerName to be amnezia-awg2, got %q", mgr.containerName())
	}

	server := &models.Server{ID: 10, Host: "10.0.0.10", SSHPort: 22, SSHUser: "root"}
	params := map[string]any{
		"port":        "55424",
		"awg_profile": "standard",
	}
	if err := mgr.Install(ctx, server, params); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// 1. Verify Dockerfile uploaded to /opt/amnezia/amnezia-awg2/Dockerfile
	dockerfileBytes, ok := client.files["/opt/amnezia/amnezia-awg2/Dockerfile"]
	if !ok {
		t.Fatalf("Dockerfile was not uploaded to /opt/amnezia/amnezia-awg2/Dockerfile")
	}
	if !strings.Contains(string(dockerfileBytes), "FROM "+awgBaseImage) {
		t.Errorf("Dockerfile missing pinned base image")
	}

	// 2. Verify command sequence targets amnezia-awg2
	var foundPull, foundBuild, foundRun, foundNetwork, foundKeygen, foundCpConf, foundCpStart, foundChmod, foundRestart bool
	for _, cmd := range commandsRun {
		if strings.HasPrefix(cmd, "docker pull "+awgBaseImage) {
			foundPull = true
		}
		if strings.Contains(cmd, "docker build --no-cache -t amnezia-awg2 /opt/amnezia/amnezia-awg2") {
			foundBuild = true
		}
		if strings.Contains(cmd, "docker run -d") && strings.Contains(cmd, "--name amnezia-awg2") && strings.Contains(cmd, "amnezia-awg2") {
			foundRun = true
		}
		if strings.Contains(cmd, "docker network connect amnezia-dns-net amnezia-awg2") {
			foundNetwork = true
		}
		if strings.Contains(cmd, "docker exec -i amnezia-awg2 bash -c") && strings.Contains(cmd, "wireguard_server_private_key.key") {
			foundKeygen = true
		}
		if strings.Contains(cmd, "docker cp /tmp/_amnz_awg0.conf amnezia-awg2:/opt/amnezia/awg/awg0.conf") {
			foundCpConf = true
		}
		if strings.Contains(cmd, "docker cp /tmp/_amnz_start.sh amnezia-awg2:/opt/amnezia/start.sh") {
			foundCpStart = true
		}
		if strings.Contains(cmd, "docker exec amnezia-awg2 chmod +x /opt/amnezia/start.sh") {
			foundChmod = true
		}
		if strings.Contains(cmd, "docker restart amnezia-awg2") {
			foundRestart = true
		}
	}

	if !foundPull {
		t.Errorf("expected docker pull %s command", awgBaseImage)
	}
	if !foundBuild {
		t.Errorf("expected docker build command targeting amnezia-awg2")
	}
	if !foundRun {
		t.Errorf("expected docker run command with --name amnezia-awg2")
	}
	if !foundNetwork {
		t.Errorf("expected docker network connect command targeting amnezia-awg2")
	}
	if !foundKeygen {
		t.Errorf("expected keygen docker exec command targeting amnezia-awg2")
	}
	if !foundCpConf {
		t.Errorf("expected docker cp config targeting amnezia-awg2")
	}
	if !foundCpStart {
		t.Errorf("expected docker cp start.sh targeting amnezia-awg2")
	}
	if !foundChmod {
		t.Errorf("expected chmod docker exec command targeting amnezia-awg2")
	}
	if !foundRestart {
		t.Errorf("expected docker restart amnezia-awg2")
	}
}

func TestUninstall_CleansUpBothAWGAndAWG2(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var commandsRun []string

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		commandsRun = append(commandsRun, cmd)
		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 11, Host: "10.0.0.11", SSHPort: 22}

	if err := mgr.Uninstall(ctx, server); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	var stoppedAwg, stoppedAwg2, rmAwg, rmAwg2, rmiAwg, rmiAwg2, rmDirs bool
	for _, cmd := range commandsRun {
		if strings.Contains(cmd, "docker stop amnezia-awg ") || strings.HasSuffix(cmd, "docker stop amnezia-awg") {
			stoppedAwg = true
		}
		if strings.Contains(cmd, "docker stop amnezia-awg2 ") || strings.HasSuffix(cmd, "docker stop amnezia-awg2") {
			stoppedAwg2 = true
		}
		if strings.Contains(cmd, "docker rm -fv amnezia-awg ") || strings.HasSuffix(cmd, "docker rm -fv amnezia-awg") {
			rmAwg = true
		}
		if strings.Contains(cmd, "docker rm -fv amnezia-awg2 ") || strings.HasSuffix(cmd, "docker rm -fv amnezia-awg2") {
			rmAwg2 = true
		}
		if strings.Contains(cmd, "docker rmi amnezia-awg ") || strings.HasSuffix(cmd, "docker rmi amnezia-awg") {
			rmiAwg = true
		}
		if strings.Contains(cmd, "docker rmi amnezia-awg2 ") || strings.HasSuffix(cmd, "docker rmi amnezia-awg2") {
			rmiAwg2 = true
		}
		if strings.Contains(cmd, "rm -rf /opt/amnezia/amnezia-awg /opt/amnezia/amnezia-awg2 /opt/amnezia/awg") {
			rmDirs = true
		}
	}

	if !stoppedAwg || !stoppedAwg2 {
		t.Errorf("Uninstall must stop both containers: stoppedAwg=%v, stoppedAwg2=%v", stoppedAwg, stoppedAwg2)
	}
	if !rmAwg || !rmAwg2 {
		t.Errorf("Uninstall must remove both containers: rmAwg=%v, rmAwg2=%v", rmAwg, rmAwg2)
	}
	if !rmiAwg || !rmiAwg2 {
		t.Errorf("Uninstall must remove images for both: rmiAwg=%v, rmiAwg2=%v", rmiAwg, rmiAwg2)
	}
	if !rmDirs {
		t.Errorf("Uninstall must remove directories for both amnezia-awg and amnezia-awg2")
	}
}

func TestBackwardCompatibility_LegacyAmneziaAWGContainer(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()

	client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		// Strictly fail if any command targets amnezia-awg2
		if strings.Contains(cmd, "amnezia-awg2") {
			if strings.Contains(cmd, "docker ps") {
				return "", "", 0, nil
			}
			return "", "Error: No such container: amnezia-awg2", 1, errors.New("container not found")
		}

		// amnezia-awg exists and is running
		if strings.Contains(cmd, "docker ps --filter name=^amnezia-awg$") {
			if strings.Contains(cmd, "{{.Names}}") {
				return "amnezia-awg\n", "", 0, nil
			}
			return "Up 24 hours\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps -a --filter name=^amnezia-awg$") {
			return "amnezia-awg\n", "", 0, nil
		}
		if strings.Contains(cmd, "docker ps --filter name=amnezia-awg") {
			return "amnezia-awg\n", "", 0, nil
		}

		// Container reads and cp for amnezia-awg
		if strings.Contains(cmd, "cat /opt/amnezia/awg/awg0.conf") {
			return string(client.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/clientsTable") {
			return string(client.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/wireguard_server_public_key.key") {
			return string(client.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "cat /opt/amnezia/awg/wireguard_psk.key") {
			return string(client.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
		}
		if strings.Contains(cmd, "docker cp /tmp/_amnz_clients.json amnezia-awg:/opt/amnezia/awg/clientsTable") {
			client.files["/opt/amnezia/awg/clientsTable"] = client.files["/tmp/_amnz_clients.json"]
			return "", "", 0, nil
		}
		if strings.Contains(cmd, "docker cp /tmp/_amnz_edit_config.conf amnezia-awg:/opt/amnezia/awg/awg0.conf") {
			client.files["/opt/amnezia/awg/awg0.conf"] = client.files["/tmp/_amnz_edit_config.conf"]
			return "", "", 0, nil
		}

		return "OK", "", 0, nil
	}

	mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
	server := &models.Server{ID: 12, Host: "10.0.0.12", SSHPort: 22}

	// 1. Resolve container name
	resolved := mgr.ResolveContainerName(ctx, client)
	if resolved != "amnezia-awg" {
		t.Fatalf("expected legacy container amnezia-awg, got %q", resolved)
	}

	// 2. GetServerStatus
	status, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus failed on legacy container: %v", err)
	}
	if exists, ok := status["container_exists"].(bool); !ok || !exists {
		t.Errorf("expected legacy container to exist")
	}
	if running, ok := status["container_running"].(bool); !ok || !running {
		t.Errorf("expected legacy container to be running")
	}

	// 3. GetServerPublicKey & PSK
	pubKey, err := mgr.GetServerPublicKey(ctx, server)
	if err != nil || pubKey == "" {
		t.Fatalf("GetServerPublicKey failed on legacy container: %v", err)
	}
	psk, err := mgr.GetServerPSK(ctx, server)
	if err != nil || psk == "" {
		t.Fatalf("GetServerPSK failed on legacy container: %v", err)
	}

	// 4. GetClients
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed on legacy container: %v", err)
	}
	if len(clients) == 0 {
		t.Errorf("expected clients on legacy container")
	}

	// 5. AddClient
	addParams := map[string]any{
		"name": "LegacyClientUser",
	}
	newClient, err := mgr.AddClient(ctx, server, addParams)
	if err != nil {
		t.Fatalf("AddClient failed on legacy container: %v", err)
	}
	clientID, ok := newClient["client_id"].(string)
	if !ok || clientID == "" {
		t.Fatalf("AddClient did not return clientID on legacy container")
	}

	// 6. GetClientConfig
	clientCfg, err := mgr.GetClientConfig(ctx, server, clientID)
	if err != nil {
		t.Fatalf("GetClientConfig failed on legacy container: %v", err)
	}
	if !strings.Contains(clientCfg, "Endpoint = 10.0.0.12:55424") {
		t.Errorf("GetClientConfig missing correct Endpoint: %s", clientCfg)
	}

	// 7. RemoveClient
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient failed on legacy container: %v", err)
	}
}

func TestPrepareHostAndContainers_DirectoryCreation(t *testing.T) {
	ctx := context.Background()
	client := newMockAWGSSHClient()
	var prepScriptExecuted string

	client.sudoScriptHandler = func(script string) (string, string, int, error) {
		prepScriptExecuted = script
		return "OK", "", 0, nil
	}

	if err := prepareHostAndContainers(ctx, client); err != nil {
		t.Fatalf("prepareHostAndContainers failed: %v", err)
	}

	if !strings.Contains(prepScriptExecuted, "/opt/amnezia/amnezia-awg2") {
		t.Errorf("prep script missing /opt/amnezia/amnezia-awg2 path:\n%s", prepScriptExecuted)
	}
}
