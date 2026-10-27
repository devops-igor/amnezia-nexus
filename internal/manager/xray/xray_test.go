package xray

import (
	"context"
	"encoding/json"
	"fmt"
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
	mu                 sync.Mutex
	commands           []string
	files              map[string][]byte
	dockerAlive        bool
	sshUser            string
	denyConfigDownload bool
}

func newMockXraySSHClient() *mockXraySSHClient {
	return &mockXraySSHClient{
		files:       make(map[string][]byte),
		dockerAlive: true,
		sshUser:     "root",
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

	if strings.Contains(cmd, "docker inspect") {
		if m.dockerAlive {
			return "true false\n", "", 0, nil
		}
		return "false false\n", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-xray") {
		if m.dockerAlive {
			return "amnezia-xray\n", "", 0, nil
		}
		return "", "", 0, nil
	}
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
	if strings.HasPrefix(cmd, "cat /opt/amnezia/") {
		for p, data := range m.files {
			if strings.Contains(cmd, p) {
				return string(data), "", 0, nil
			}
		}
		return "", "", 1, nil
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
	if m.denyConfigDownload && remotePath == XrayConfigPath {
		return nil, os.ErrPermission
	}
	data, ok := m.files[remotePath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *mockXraySSHClient) DownloadSudoFile(ctx context.Context, remotePath string) ([]byte, error) {
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
	return m.sshUser
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
	if parsed.DNS != nil {
		t.Errorf("expected parsed.DNS to be nil in rendered config, got %+v", parsed.DNS)
	}
	var rawMap map[string]any
	if err := json.Unmarshal(cfgBytes, &rawMap); err != nil {
		t.Fatalf("unmarshal raw config: %v", err)
	}
	if _, ok := rawMap["dns"]; ok {
		t.Errorf("expected rendered config to omit 'dns' block, but 'dns' key was present")
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
	if !strings.HasPrefix(retrievedConfig, "vless://"+clientID+"@") {
		t.Errorf("GetClientConfig missing vless client prefix: %s", retrievedConfig)
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

func TestXrayManager_SudoNodeClientOperationsAfterRawConfigSave(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 45, Host: "192.0.2.4", SSHUser: "ubuntu"}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if err := mockSSH.UploadSudoFile(ctx, XrayConfigPath, mockSSH.files[XrayConfigPath], 0600); err != nil {
		t.Fatalf("raw config save failed: %v", err)
	}
	mockSSH.sshUser = "ubuntu"
	mockSSH.denyConfigDownload = true

	added, err := mgr.AddClient(ctx, server, map[string]any{"name": "sudo-user"})
	if err != nil {
		t.Fatalf("AddClient after root-owned 0600 save failed: %v", err)
	}
	clientID, _ := added["client_id"].(string)
	if _, err := mgr.GetClientConfig(ctx, server, clientID); err != nil {
		t.Fatalf("GetClientConfig after root-owned 0600 save failed: %v", err)
	}
	clients, err := mgr.GetClients(ctx, server)
	if err != nil || len(clients) != 1 {
		t.Fatalf("GetClients after root-owned 0600 save failed: clients=%v err=%v", clients, err)
	}
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient after root-owned 0600 save failed: %v", err)
	}
}

func TestXrayManager_DuplicateClientNameDistinctEmails(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	pool := &mockXrayPool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewXrayManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:      43,
		Host:    "192.0.2.2",
		SSHPort: 22,
	}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// Add two clients with the identical display name "phone"
	res1, err := mgr.AddClient(ctx, server, map[string]any{"name": "phone"})
	if err != nil {
		t.Fatalf("first AddClient failed: %v", err)
	}
	res2, err := mgr.AddClient(ctx, server, map[string]any{"name": "phone"})
	if err != nil {
		t.Fatalf("second AddClient failed: %v", err)
	}

	id1, _ := res1["client_id"].(string)
	id2, _ := res2["client_id"].(string)
	if id1 == "" || id2 == "" || id1 == id2 {
		t.Fatalf("expected distinct non-empty client IDs, got %q and %q", id1, id2)
	}

	cfgBytes, ok := mockSSH.files[XrayConfigPath]
	if !ok {
		t.Fatalf("config.json missing from mock files")
	}
	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		t.Fatalf("ParseXrayConfig failed: %v", err)
	}

	inboundClients := cfg.Inbounds[0].Settings.Clients
	if len(inboundClients) != 2 {
		t.Fatalf("expected 2 clients in inbounds[0], got %d", len(inboundClients))
	}

	// B2 assertion: emails MUST be distinct and equal to client IDs, NOT colliding on "phone"
	if inboundClients[0].Email == inboundClients[1].Email {
		t.Fatalf("duplicate client email collision detected: %q vs %q", inboundClients[0].Email, inboundClients[1].Email)
	}
	if inboundClients[0].Email != id1 || inboundClients[1].Email != id2 {
		t.Errorf("expected emails to match client IDs: got (%q, %q), want (%q, %q)",
			inboundClients[0].Email, inboundClients[1].Email, id1, id2)
	}

	// Display name is preserved in URI fragment
	cfg1, _ := res1["config"].(string)
	cfg2, _ := res2["config"].(string)
	if !strings.HasSuffix(cfg1, "#phone") || !strings.HasSuffix(cfg2, "#phone") {
		t.Errorf("expected #phone fragment in URIs: %q and %q", cfg1, cfg2)
	}
}

func TestXrayManager_ContainerFlagsAndSudo(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	pool := &mockXrayPool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewXrayManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:      44,
		Host:    "192.0.2.3",
		SSHPort: 22,
	}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	var runCmd string
	var inspectCmd string
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker run") {
			runCmd = cmd
		}
		if strings.Contains(cmd, "docker inspect") {
			inspectCmd = cmd
		}
	}

	if runCmd == "" {
		t.Fatalf("docker run command was not recorded")
	}

	// B1 & Hardening flag assertions
	expectedFlags := []string{
		"--user 0:0",
		"--cap-drop ALL",
		"--cap-add NET_BIND_SERVICE",
		"--security-opt no-new-privileges:true",
		"--log-driver none",
		"--tmpfs /tmp:rw,noexec,nosuid,size=16m",
		"--tmpfs /run:rw,noexec,nosuid,size=16m",
		"-v '/opt/amnezia/xray':/etc/xray:ro",
	}
	for _, flag := range expectedFlags {
		if !strings.Contains(runCmd, flag) {
			t.Errorf("docker run missing expected flag %q:\n%s", flag, runCmd)
		}
	}

	// B3 assertion: resolv.conf bind mount must NOT be present
	if strings.Contains(runCmd, "resolv.conf") {
		t.Errorf("docker run must not contain resolv.conf mount:\n%s", runCmd)
	}

	// H2 assertion: inspectCmd was executed with sudo
	if inspectCmd == "" || !strings.HasPrefix(inspectCmd, "sudo: ") {
		t.Errorf("expected docker inspect via RunSudoCommand, got %q", inspectCmd)
	}

	// H2 assertion: GetServerStatus uses RunSudoCommand for docker ps
	mockSSH.commands = nil
	if _, err := mgr.GetServerStatus(ctx, server); err != nil {
		t.Fatalf("GetServerStatus failed: %v", err)
	}
	var psFound bool
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker ps") {
			psFound = true
			if !strings.HasPrefix(cmd, "sudo: ") {
				t.Errorf("docker ps must be run with sudo, got: %s", cmd)
			}
		}
	}
	if !psFound {
		t.Errorf("docker ps was not executed in GetServerStatus")
	}
}

type failXraySSHClient struct {
	*mockXraySSHClient
	stopFails bool
}

func (m *failXraySSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker stop") && m.stopFails {
		return "", "daemon error: cannot stop container", 1, fmt.Errorf("command exited 1")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_UninstallFailurePropagation(t *testing.T) {
	mockSSH := &failXraySSHClient{
		mockXraySSHClient: newMockXraySSHClient(),
		stopFails:         true,
	}
	pool := &mockXrayPool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewXrayManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:        99,
		Host:      "198.51.100.2",
		Protocols: map[string]any{models.ProtocolVLESS: map[string]any{"installed": true}},
	}
	ctx := context.Background()

	// Initial install
	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// Attempt uninstall with failing stop/rm
	err := mgr.Uninstall(ctx, server)
	if err == nil {
		t.Fatalf("expected error from Uninstall when stop/rm fails")
	}

	// Config directory must NOT be deleted
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "rm -rf") && strings.Contains(cmd, XrayConfigDir) {
			t.Errorf("rm -rf config directory must not be run when container removal fails")
		}
	}

	// Protocol must still be in in-memory map
	if _, ok := server.Protocols[models.ProtocolVLESS]; !ok {
		t.Errorf("server.Protocols[vless] must not be deleted on uninstall failure")
	}

	// Also verify idempotent uninstall when container is absent
	absentMockSSH := newMockXraySSHClient()
	absentMockSSH.dockerAlive = false
	absentMgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: absentMockSSH}, awg.NewServerLockRegistry())
	server2 := &models.Server{
		ID:        100,
		Host:      "198.51.100.3",
		Protocols: map[string]any{models.ProtocolVLESS: map[string]any{"installed": true}},
	}
	if err := absentMgr.Uninstall(ctx, server2); err != nil {
		t.Fatalf("expected idempotent success on absent container, got: %v", err)
	}
	if _, ok := server2.Protocols[models.ProtocolVLESS]; ok {
		t.Errorf("expected server.Protocols[vless] deleted on successful absent uninstall")
	}
}

func TestXrayManager_ReinstallPreservesClientsAndKeys(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	pool := &mockXrayPool{client: mockSSH}
	mgr := NewXrayManagerWithServerLocks(pool, awg.NewServerLockRegistry())

	server := &models.Server{
		ID:        77,
		Host:      "198.51.100.77",
		Protocols: make(map[string]any),
	}
	ctx := context.Background()

	// 1. Initial install
	installParams := map[string]any{
		"port": 443,
		"vless_options": models.VLESSInstallOptions{
			Port:       "443",
			ServerName: "gateway.icloud.com",
			Flow:       "xtls-rprx-vision",
		},
	}
	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Initial install failed: %v", err)
	}

	protoMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected server.Protocols[vless] to be populated")
	}
	origPubKey, _ := protoMeta["public_key"].(string)
	origShortID, _ := protoMeta["short_id"].(string)
	if origPubKey == "" || origShortID == "" {
		t.Fatalf("expected non-empty origPubKey and origShortID, got pub=%q sid=%q", origPubKey, origShortID)
	}

	// 2. Add two clients
	c1, err := mgr.AddClient(ctx, server, map[string]any{"name": "alice"})
	if err != nil {
		t.Fatalf("AddClient alice failed: %v", err)
	}
	c2, err := mgr.AddClient(ctx, server, map[string]any{"name": "bob"})
	if err != nil {
		t.Fatalf("AddClient bob failed: %v", err)
	}

	clientsBefore, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	if len(clientsBefore) != 2 {
		t.Fatalf("expected 2 clients before reinstall, got %d", len(clientsBefore))
	}

	// 3. Reinstall
	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Reinstall failed: %v", err)
	}

	// 4. Verify keys and short IDs are preserved
	protoMetaAfter, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected server.Protocols[vless] populated after reinstall")
	}
	afterPubKey, _ := protoMetaAfter["public_key"].(string)
	afterShortID, _ := protoMetaAfter["short_id"].(string)

	if afterPubKey != origPubKey {
		t.Errorf("public_key changed on reinstall: want %q, got %q", origPubKey, afterPubKey)
	}
	if afterShortID != origShortID {
		t.Errorf("short_id changed on reinstall: want %q, got %q", origShortID, afterShortID)
	}

	// 5. Verify clients are preserved in config.json and GetClients
	clientsAfter, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients after reinstall failed: %v", err)
	}
	if len(clientsAfter) != 2 {
		t.Fatalf("expected 2 clients after reinstall, got %d", len(clientsAfter))
	}
	if clientsAfter[0]["client_id"] != c1["client_id"] || clientsAfter[1]["client_id"] != c2["client_id"] {
		t.Errorf("client IDs mismatched after reinstall: got %+v", clientsAfter)
	}
}

func TestXrayManager_StandardVLESS_EmptyFlow(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	pool := &mockXrayPool{client: mockSSH}
	mgr := NewXrayManagerWithServerLocks(pool, awg.NewServerLockRegistry())

	server := &models.Server{
		ID:        80,
		Host:      "198.51.100.80",
		Protocols: make(map[string]any),
	}
	ctx := context.Background()

	// 1. Install with explicit empty flow (Standard VLESS)
	installParams := map[string]any{
		"port": 443,
		"vless_options": map[string]any{
			"port":        "443",
			"server_name": "gateway.icloud.com",
			"flow":        "",
		},
	}
	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Standard VLESS install failed: %v", err)
	}

	protoMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected server.Protocols[vless] to be populated")
	}
	if protoMeta["flow"] != "" {
		t.Errorf("expected empty flow in server.Protocols[vless], got %v", protoMeta["flow"])
	}
	if protoMeta["public_key"] == "" || protoMeta["short_id"] == "" || protoMeta["server_name"] == "" {
		t.Errorf("expected complete metadata retained, got %+v", protoMeta)
	}

	// 2. Add client to Standard VLESS server
	clientRes, err := mgr.AddClient(ctx, server, map[string]any{"name": "standard-user"})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}
	clientID, _ := clientRes["client_id"].(string)

	// 3. Verify client config has no vision flow
	uri, err := mgr.GetClientConfig(ctx, server, clientID)
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if strings.Contains(uri, "flow=") {
		t.Errorf("expected client URI to have NO flow parameter for Standard VLESS, got: %s", uri)
	}

	// 4. Verify config.json inbounds[0].settings.clients[0].flow is empty
	cfgBytes := mockSSH.files[XrayConfigPath]
	cfg, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		t.Fatalf("ParseXrayConfig failed: %v", err)
	}
	if len(cfg.Inbounds[0].Settings.Clients) == 0 {
		t.Fatalf("expected at least 1 client in config.json")
	}
	clientInConfig := cfg.Inbounds[0].Settings.Clients[0]
	if clientInConfig.Flow != "" {
		t.Errorf("expected empty flow in config.json client, got %q", clientInConfig.Flow)
	}
}

func TestXrayManager_InstallFailsClosedOnMalformedOrUncertainConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("Malformed JSON config fails closed", func(t *testing.T) {
		mockSSH := newMockXraySSHClient()
		malformed := []byte(`{"inbounds": [{"settings": {"clients": [{"id": "abc"}]`) // truncated JSON
		mockSSH.files[XrayConfigPath] = malformed

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		server := &models.Server{ID: 1, Host: "192.0.2.1"}

		err := mgr.Install(ctx, server, map[string]any{"port": 443})
		if err == nil {
			t.Fatalf("expected Install to fail closed on malformed config, got nil error")
		}
		if !strings.Contains(err.Error(), "parse") {
			t.Errorf("expected error to mention parsing failure, got: %v", err)
		}
		// Verify file was NOT overwritten with fresh credentials
		if string(mockSSH.files[XrayConfigPath]) != string(malformed) {
			t.Errorf("malformed config was overwritten despite failure!")
		}
	})

	t.Run("Missing reality private key fails closed", func(t *testing.T) {
		mockSSH := newMockXraySSHClient()
		noKey := []byte(`{"inbounds": [{"protocol": "vless", "streamSettings": {"realitySettings": {}}}]}`)
		mockSSH.files[XrayConfigPath] = noKey

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		server := &models.Server{ID: 1, Host: "192.0.2.1"}

		err := mgr.Install(ctx, server, map[string]any{"port": 443})
		if err == nil {
			t.Fatalf("expected Install to fail closed on missing private key, got nil error")
		}
		if !strings.Contains(err.Error(), "private key") {
			t.Errorf("expected error to mention missing private key, got: %v", err)
		}
	})
}
