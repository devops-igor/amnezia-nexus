package awg

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
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
	return m.defaultRunSudo(cmd)
}

func (m *mockAWGSSHClient) defaultRunSudo(cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "amnezia_awg_") {
		return "OK", "", 0, nil
	}
	if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf") {
		return string(m.files["/opt/amnezia/awg/awg0.conf"]), "", 0, nil
	}
	if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "clientsTable") {
		return string(m.files["/opt/amnezia/awg/clientsTable"]), "", 0, nil
	}
	if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "wireguard_server_public_key.key") {
		return string(m.files["/opt/amnezia/awg/wireguard_server_public_key.key"]), "", 0, nil
	}
	if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "wireguard_psk.key") {
		return string(m.files["/opt/amnezia/awg/wireguard_psk.key"]), "", 0, nil
	}
	if strings.HasPrefix(cmd, "rm -f ") {
		path := strings.Trim(strings.TrimSpace(strings.TrimPrefix(cmd, "rm -f ")), "'\"")
		if strings.HasPrefix(path, "/tmp/_amnz_edit_config_") || strings.HasPrefix(path, "/tmp/_amnz_clients_") {
			delete(m.files, path)
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "ss -lun") {
		// Preflight: no UDP listener bound on the mock host.
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps --filter publish=") {
		// Preflight: no existing container publishes the port.
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_clients") {
		fields := strings.Fields(cmd)
		if len(fields) >= 3 {
			src := strings.Trim(fields[2], "'\"")
			if m.files[src] != nil {
				m.files["/opt/amnezia/awg/clientsTable"] = m.files[src]
				return "", "", 0, nil
			}
		}
		for p, c := range m.files {
			if strings.Contains(p, "_amnz_clients") {
				m.files["/opt/amnezia/awg/clientsTable"] = c
				break
			}
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config") {
		fields := strings.Fields(cmd)
		if len(fields) >= 3 {
			src := strings.Trim(fields[2], "'\"")
			if m.files[src] != nil {
				m.files["/opt/amnezia/awg/awg0.conf"] = m.files[src]
				return "", "", 0, nil
			}
		}
		for p, c := range m.files {
			if strings.Contains(p, "_amnz_edit_config") {
				m.files["/opt/amnezia/awg/awg0.conf"] = c
				break
			}
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_awg0.conf") {
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
	if strings.Contains(cmd, "show all") && strings.Contains(cmd, "awg") {
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

func (m *mockAWGSSHClient) DownloadSudoFile(ctx context.Context, remotePath string) ([]byte, error) {
	return m.DownloadFile(ctx, remotePath)
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

func (m *mockAWGSSHClient) InUse() bool {
	return false
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
		"name":        "NewUser",
		"awg_mimicry": "tls",
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
