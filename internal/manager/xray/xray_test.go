package xray

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

type mockXraySSHClient struct {
	mu          sync.Mutex
	commands    []string
	files       map[string][]byte
	dockerAlive bool
}

func newMockXraySSHClient() *mockXraySSHClient {
	return &mockXraySSHClient{
		files:       make(map[string][]byte),
		dockerAlive: true,
	}
}

func (m *mockXraySSHClient) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, cmd)

	if strings.Contains(cmd, "docker --version") {
		return "Docker version 25.0.3", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-xray") {
		if m.dockerAlive {
			return "amnezia-xray\n", "", 0, nil
		}
		return "", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *mockXraySSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, "sudo: "+cmd)

	if strings.Contains(cmd, "docker run") {
		m.dockerAlive = true
		return "container_id_xray", "", 0, nil
	}
	if strings.Contains(cmd, "docker stop") || strings.Contains(cmd, "docker rm") {
		m.dockerAlive = false
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker restart") {
		return "amnezia-xray", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *mockXraySSHClient) RunScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *mockXraySSHClient) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *mockXraySSHClient) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = append([]byte(nil), content...)
	return nil
}

func (m *mockXraySSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = append([]byte(nil), content...)
	return nil
}

func (m *mockXraySSHClient) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[remotePath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *mockXraySSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.files[remotePath]
	return ok, nil
}

func (m *mockXraySSHClient) TestConnection(ctx context.Context) (string, error) {
	return "Linux", nil
}

func (m *mockXraySSHClient) Close() error {
	return nil
}

func (m *mockXraySSHClient) IsAlive() bool {
	return true
}

func (m *mockXraySSHClient) GetUnderlyingClient() *gossh.Client {
	return nil
}

func (m *mockXraySSHClient) GetHost() string {
	return "192.0.2.1"
}

func (m *mockXraySSHClient) GetPort() int {
	return 22
}

func (m *mockXraySSHClient) GetUser() string {
	return "root"
}

func (m *mockXraySSHClient) GetServerID() *int64 {
	id := int64(42)
	return &id
}

func (m *mockXraySSHClient) GetLastActive() time.Time {
	return time.Now()
}

func (m *mockXraySSHClient) InUse() bool {
	return false
}

type mockXrayPool struct {
	client ssh.SSHClient
}

func (p *mockXrayPool) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

func TestXrayConfig_CryptoAndURI(t *testing.T) {
	privB64, pubB64, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	if len(privB64) != 43 || len(pubB64) != 43 {
		t.Errorf("unexpected key lengths: priv=%d pub=%d", len(privB64), len(pubB64))
	}

	derivedPub, err := DerivePublicKey(privB64)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	if derivedPub != pubB64 {
		t.Errorf("derived pubkey mismatch: got %q, want %q", derivedPub, pubB64)
	}

	sid, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}
	if len(sid) != 16 {
		t.Errorf("expected 16 hex chars for 8-byte short ID, got %d (%s)", len(sid), sid)
	}

	// Render config
	clients := []XrayClient{
		{ID: "c1-uuid", Flow: "xtls-rprx-vision", Email: "alice"},
	}
	cfgBytes, err := RenderXrayConfig(443, 54321, "gateway.icloud.com", "gateway.icloud.com:443", privB64, []string{sid}, clients)
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}

	parsed, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d", len(parsed.Inbounds))
	}
	if parsed.Inbounds[0].Port != 443 || parsed.Inbounds[1].Port != 54321 {
		t.Errorf("inbound ports mismatch: %d, %d", parsed.Inbounds[0].Port, parsed.Inbounds[1].Port)
	}
	if len(parsed.Inbounds[0].Settings.Clients) != 1 {
		t.Errorf("expected 1 client in inbound 0, got %d", len(parsed.Inbounds[0].Settings.Clients))
	}

	// Build URI
	uri, err := BuildVLESSURI("203.0.113.1", 443, "test-uuid", "bob", "gateway.icloud.com", pubB64, sid, "xtls-rprx-vision")
	if err != nil {
		t.Fatalf("BuildVLESSURI: %v", err)
	}
	if !strings.HasPrefix(uri, "vless://test-uuid@203.0.113.1:443?") {
		t.Errorf("unexpected URI start: %s", uri)
	}
	if !strings.HasSuffix(uri, "#bob") {
		t.Errorf("unexpected URI suffix: %s", uri)
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	q := parsedURL.Query()
	if q.Get("security") != "reality" || q.Get("pbk") != pubB64 || q.Get("sid") != sid || q.Get("flow") != "xtls-rprx-vision" {
		t.Errorf("query parameters mismatch in URI: %+v", q)
	}
}

func TestXrayManager_Lifecycle(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	pool := &mockXrayPool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewXrayManagerWithServerLocks(pool, locks)

	if mgr.Protocol() != "vless" {
		t.Errorf("expected Protocol() == 'vless', got %q", mgr.Protocol())
	}

	server := &models.Server{
		ID:      42,
		Host:    "192.0.2.1",
		SSHPort: 22,
	}

	// 1. Install
	installParams := map[string]any{
		"port": 443,
		"vless_options": models.VLESSInstallOptions{
			Port:       "443",
			ServerName: "gateway.icloud.com",
			Flow:       "xtls-rprx-vision",
		},
	}
	ctx := context.Background()
	err := mgr.Install(ctx, server, installParams)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	cfgBytes, ok := mockSSH.files[XrayConfigPath]
	if !ok || len(cfgBytes) == 0 {
		t.Fatalf("config.json was not uploaded to %s", XrayConfigPath)
	}

	var initialCfg XrayConfig
	if err := json.Unmarshal(cfgBytes, &initialCfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if initialCfg.Inbounds[0].Port != 443 {
		t.Errorf("expected port 443, got %d", initialCfg.Inbounds[0].Port)
	}

	// 2. Status Check
	status, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus: %v", err)
	}
	if running, _ := status["container_running"].(bool); !running {
		t.Errorf("expected container_running=true")
	}
	if port, _ := status["port"].(int); port != 443 {
		t.Errorf("expected port 443 in status, got %v", status["port"])
	}

	// 3. AddClient
	addRes, err := mgr.AddClient(ctx, server, map[string]any{
		"name": "developer-laptop",
	})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	clientID, _ := addRes["client_id"].(string)
	if clientID == "" {
		t.Fatalf("missing client_id in AddClient response")
	}
	configURI, _ := addRes["config"].(string)
	if !strings.HasPrefix(configURI, "vless://") {
		t.Errorf("expected config to be vless:// URI, got %s", configURI)
	}

	// 4. GetClients
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	if clients[0]["client_id"] != clientID {
		t.Errorf("client ID mismatch in GetClients")
	}

	// 5. GetClientConfig
	retrievedConfig, err := mgr.GetClientConfig(ctx, server, clientID)
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if retrievedConfig != configURI {
		t.Errorf("GetClientConfig mismatch:\ngot  %s\nwant %s", retrievedConfig, configURI)
	}

	// 6. RemoveClient
	err = mgr.RemoveClient(ctx, server, clientID)
	if err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}

	clientsAfterRemove, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients after remove failed: %v", err)
	}
	if len(clientsAfterRemove) != 0 {
		t.Errorf("expected 0 clients after remove, got %d", len(clientsAfterRemove))
	}

	// 7. Uninstall
	err = mgr.Uninstall(ctx, server)
	if err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	statusAfterUninstall, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus after uninstall: %v", err)
	}
	if running, _ := statusAfterUninstall["container_running"].(bool); running {
		t.Errorf("expected container_running=false after uninstall")
	}
}
