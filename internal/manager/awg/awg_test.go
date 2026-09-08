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
	files          map[string][]byte
	sudoCmdHandler func(cmd string) (string, string, int, error)
	host           string
	port           int
	serverID       *int64
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

	// Malicious name must be rejected and fallback to safe default "amnezia-awg"
	if cName != "amnezia-awg" {
		t.Fatalf("expected fallback to safe default 'amnezia-awg', got %q", cName)
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
