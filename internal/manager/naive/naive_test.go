package naive

import (
	"context"
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

type mockNaiveSSHClient struct {
	mu          sync.Mutex
	commands    []string
	files       map[string][]byte
	dockerAlive bool
	reloaded    int
}

func newMockNaiveSSHClient() *mockNaiveSSHClient {
	return &mockNaiveSSHClient{
		files:       make(map[string][]byte),
		dockerAlive: true,
	}
}

func (m *mockNaiveSSHClient) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, cmd)

	if strings.Contains(cmd, "docker --version") {
		return "Docker version 25.0.3", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-caddy") {
		if m.dockerAlive {
			return "amnezia-caddy\n", "", 0, nil
		}
		return "", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *mockNaiveSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.commands = append(m.commands, "sudo: "+cmd)

	if strings.Contains(cmd, "docker inspect") {
		if m.dockerAlive {
			return "true false\n", "", 0, nil
		}
		return "false false\n", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-caddy") {
		if m.dockerAlive {
			return "amnezia-caddy\n", "", 0, nil
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker build") {
		return "Successfully built", "", 0, nil
	}
	if strings.Contains(cmd, "docker run") {
		m.dockerAlive = true
		return "container_id_caddy", "", 0, nil
	}
	if strings.Contains(cmd, "docker stop") || strings.Contains(cmd, "docker rm") {
		m.dockerAlive = false
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "caddy reload") {
		m.reloaded++
		return "reload successful", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *mockNaiveSSHClient) RunScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *mockNaiveSSHClient) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *mockNaiveSSHClient) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = append([]byte(nil), content...)
	return nil
}

func (m *mockNaiveSSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = append([]byte(nil), content...)
	return nil
}

func (m *mockNaiveSSHClient) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[remotePath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *mockNaiveSSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.files[remotePath]
	return ok, nil
}

func (m *mockNaiveSSHClient) TestConnection(ctx context.Context) (string, error) {
	return "Linux", nil
}

func (m *mockNaiveSSHClient) Close() error {
	return nil
}

func (m *mockNaiveSSHClient) IsAlive() bool {
	return true
}

func (m *mockNaiveSSHClient) GetUnderlyingClient() *gossh.Client {
	return nil
}

func (m *mockNaiveSSHClient) GetHost() string {
	return "198.51.100.1"
}

func (m *mockNaiveSSHClient) GetPort() int {
	return 22
}

func (m *mockNaiveSSHClient) GetUser() string {
	return "root"
}

func (m *mockNaiveSSHClient) GetServerID() *int64 {
	id := int64(88)
	return &id
}

func (m *mockNaiveSSHClient) GetLastActive() time.Time {
	return time.Now()
}

func (m *mockNaiveSSHClient) InUse() bool {
	return false
}

type mockNaivePool struct {
	client ssh.SSHClient
}

func (p *mockNaivePool) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

func TestNaiveConfig_CaddyfileAndURI(t *testing.T) {
	user, pass, err := GenerateNaiveCredentials()
	if err != nil {
		t.Fatalf("GenerateNaiveCredentials failed: %v", err)
	}
	if !strings.HasPrefix(user, "user_") || len(pass) != 32 {
		t.Errorf("unexpected credential shape: user=%s pass=%s", user, pass)
	}

	clients := []NaiveClient{
		{Username: user, Password: pass},
	}
	caddyfile := RenderCaddyfile(443, "vpn.example.com", clients)

	// Verify loopback admin API is present and admin off is absent
	if strings.Contains(caddyfile, "admin off") {
		t.Errorf("Caddyfile must not contain 'admin off'")
	}
	if !strings.Contains(caddyfile, "admin 127.0.0.1:2019") {
		t.Errorf("Caddyfile missing loopback admin directive")
	}
	if !strings.Contains(caddyfile, "basic_auth "+user+" "+pass) {
		t.Errorf("Caddyfile missing basic_auth credentials")
	}

	domain, port, parsedClients, err := ParseCaddyfile(caddyfile)
	if err != nil {
		t.Fatalf("ParseCaddyfile failed: %v", err)
	}
	if domain != "vpn.example.com" || port != 443 {
		t.Errorf("domain/port mismatch: domain=%s port=%d", domain, port)
	}
	if len(parsedClients) != 1 || parsedClients[0].Username != user || parsedClients[0].Password != pass {
		t.Errorf("clients mismatch: %+v", parsedClients)
	}

	// URI formatting
	uri, err := BuildNaiveURI("vpn.example.com", 443, user, pass, "laptop")
	if err != nil {
		t.Fatalf("BuildNaiveURI failed: %v", err)
	}
	if !strings.HasPrefix(uri, "https://") {
		t.Errorf("expected https:// URI, got: %s", uri)
	}
	if !strings.HasSuffix(uri, "#laptop") {
		t.Errorf("expected #laptop fragment, got: %s", uri)
	}

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	if u.User.Username() != user {
		t.Errorf("URI user mismatch: got %s, want %s", u.User.Username(), user)
	}
	p, _ := u.User.Password()
	if p != pass {
		t.Errorf("URI password mismatch")
	}
}

func TestNaiveManager_Lifecycle(t *testing.T) {
	mockSSH := newMockNaiveSSHClient()
	pool := &mockNaivePool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewNaiveManagerWithServerLocks(pool, locks)

	if mgr.Protocol() != "naive" {
		t.Errorf("expected Protocol() == 'naive', got %q", mgr.Protocol())
	}

	server := &models.Server{
		ID:      88,
		Host:    "198.51.100.1",
		SSHPort: 22,
	}

	ctx := context.Background()

	// 1. Install
	installParams := map[string]any{
		"port": 443,
		"naive_options": models.NaiveInstallOptions{
			Port:          "443",
			Domain:        "naive.example.com",
			DecoyTemplate: "default",
		},
	}

	err := mgr.Install(ctx, server, installParams)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	caddyfileBytes, ok := mockSSH.files[NaiveCaddyfilePath]
	if !ok || len(caddyfileBytes) == 0 {
		t.Fatalf("Caddyfile was not uploaded")
	}
	if !strings.Contains(string(caddyfileBytes), "naive.example.com") {
		t.Errorf("uploaded Caddyfile missing domain")
	}

	decoyBytes, ok := mockSSH.files[NaiveHTMLDir+"/index.html"]
	if !ok || len(decoyBytes) == 0 {
		t.Errorf("decoy index.html was not uploaded")
	}

	// 2. Status check
	status, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus failed: %v", err)
	}
	if running, _ := status["container_running"].(bool); !running {
		t.Errorf("expected container_running=true")
	}
	if d, _ := status["domain"].(string); d != "naive.example.com" {
		t.Errorf("expected domain naive.example.com in status, got %v", status["domain"])
	}

	// 3. AddClient
	addRes, err := mgr.AddClient(ctx, server, map[string]any{
		"name": "work-macbook",
	})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	username, _ := addRes["username"].(string)
	if username == "" {
		t.Fatalf("missing username in AddClient response")
	}
	configURI, _ := addRes["config"].(string)
	if !strings.HasPrefix(configURI, "https://") {
		t.Errorf("expected config https:// URI, got %s", configURI)
	}

	if mockSSH.reloaded != 1 {
		t.Errorf("expected exactly 1 caddy reload invocation, got %d", mockSSH.reloaded)
	}

	// 4. GetClients
	clients, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients failed: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}
	if clients[0]["username"] != username {
		t.Errorf("client mismatch in GetClients")
	}

	// 5. GetClientConfig
	clientConfig, err := mgr.GetClientConfig(ctx, server, username)
	if err != nil {
		t.Fatalf("GetClientConfig failed: %v", err)
	}
	if !strings.Contains(clientConfig, username) {
		t.Errorf("expected config to contain username, got %s", clientConfig)
	}

	// 6. RemoveClient
	err = mgr.RemoveClient(ctx, server, username)
	if err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}
	if mockSSH.reloaded != 2 {
		t.Errorf("expected 2 caddy reload invocations after remove, got %d", mockSSH.reloaded)
	}

	clientsAfterRemove, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients after remove: %v", err)
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

func TestNaiveConfig_ZeroClientsNoProbeResistance(t *testing.T) {
	// B5 assertion: zero-client Caddyfile must NOT emit probe_resistance
	caddyfileNil := RenderCaddyfile(443, "vpn.example.com", nil)
	if strings.Contains(caddyfileNil, "probe_resistance") {
		t.Errorf("RenderCaddyfile with nil clients must not contain probe_resistance:\n%s", caddyfileNil)
	}

	caddyfileEmpty := RenderCaddyfile(443, "vpn.example.com", []NaiveClient{})
	if strings.Contains(caddyfileEmpty, "probe_resistance") {
		t.Errorf("RenderCaddyfile with empty clients must not contain probe_resistance:\n%s", caddyfileEmpty)
	}

	// When clients with credentials exist, probe_resistance MUST be present
	caddyfileWithClients := RenderCaddyfile(443, "vpn.example.com", []NaiveClient{
		{Username: "user1", Password: "test_secret_pass_123"},
	})
	if !strings.Contains(caddyfileWithClients, "probe_resistance") {
		t.Errorf("RenderCaddyfile with authenticated clients must contain probe_resistance:\n%s", caddyfileWithClients)
	}
	if !strings.Contains(caddyfileWithClients, "basic_auth user1 test_secret_pass_123") {
		t.Errorf("RenderCaddyfile missing basic_auth directive:\n%s", caddyfileWithClients)
	}
}

func TestNaiveManager_DockerBuildAndDirectoryMount(t *testing.T) {
	mockSSH := newMockNaiveSSHClient()
	pool := &mockNaivePool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewNaiveManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:      89,
		Host:    "198.51.100.2",
		SSHPort: 22,
	}
	ctx := context.Background()

	installParams := map[string]any{
		"port": 443,
		"naive_options": models.NaiveInstallOptions{
			Port:   "443",
			Domain: "naive.example.com",
		},
	}

	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	// B4 assertion: Dockerfile must be uploaded with xcaddy builder for klzgrad/forwardproxy
	dockerfilePath := NaiveConfigDir + "/Dockerfile"
	dfBytes, ok := mockSSH.files[dockerfilePath]
	if !ok || len(dfBytes) == 0 {
		t.Fatalf("Dockerfile was not uploaded to %s", dockerfilePath)
	}
	dfContent := string(dfBytes)
	if !strings.Contains(dfContent, "FROM caddy:builder AS builder") {
		t.Errorf("Dockerfile missing builder stage:\n%s", dfContent)
	}
	if !strings.Contains(dfContent, "c096d6a00cb28e019cc1995b04bdc6a9311d8024") {
		t.Errorf("Dockerfile missing pinned forwardproxy commit digest:\n%s", dfContent)
	}
	if !strings.Contains(dfContent, "FROM caddy:alpine") {
		t.Errorf("Dockerfile missing alpine runtime stage:\n%s", dfContent)
	}

	// B4 assertion: docker build command was executed with sudo
	var buildCmd string
	var runCmd string
	var inspectCmd string
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker build") {
			buildCmd = cmd
		}
		if strings.Contains(cmd, "docker run") {
			runCmd = cmd
		}
		if strings.Contains(cmd, "docker inspect") {
			inspectCmd = cmd
		}
	}

	if buildCmd == "" || !strings.HasPrefix(buildCmd, "sudo: ") {
		t.Errorf("expected docker build via RunSudoCommand, got %q", buildCmd)
	}
	if !strings.Contains(buildCmd, "-t 'amnezia-caddy:local'") {
		t.Errorf("expected docker build tag amnezia-caddy:local, got: %s", buildCmd)
	}

	// H1 & Hardening assertions: directory mount instead of single file, no resolv.conf, hardening flags
	if runCmd == "" {
		t.Fatalf("docker run command was not recorded")
	}
	if !strings.Contains(runCmd, "-v '/opt/amnezia/caddy':/etc/caddy:ro") {
		t.Errorf("docker run must mount config directory /opt/amnezia/caddy, got:\n%s", runCmd)
	}
	if strings.Contains(runCmd, "/etc/caddy/Caddyfile:ro") {
		t.Errorf("docker run must NOT mount single file Caddyfile directly:\n%s", runCmd)
	}
	if strings.Contains(runCmd, "resolv.conf") {
		t.Errorf("docker run must NOT mount resolv.conf:\n%s", runCmd)
	}
	if !strings.Contains(runCmd, "'amnezia-caddy:local'") {
		t.Errorf("docker run must use local built image amnezia-caddy:local, got:\n%s", runCmd)
	}
	if !strings.Contains(runCmd, "--log-driver none") {
		t.Errorf("docker run missing --log-driver none flag:\n%s", runCmd)
	}
	if !strings.Contains(runCmd, "--tmpfs /tmp:rw,noexec,nosuid,size=16m") {
		t.Errorf("docker run missing tmpfs /tmp flag:\n%s", runCmd)
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
				t.Errorf("docker ps must be run with sudo in GetServerStatus, got: %s", cmd)
			}
		}
	}
	if !psFound {
		t.Errorf("docker ps was not executed in GetServerStatus")
	}
}
