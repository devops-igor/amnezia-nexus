package naive

import (
	"context"
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

type mockNaiveSSHClient struct {
	mu                 sync.Mutex
	commands           []string
	files              map[string][]byte
	dockerAlive        bool
	reloaded           int
	sshUser            string
	denyConfigDownload bool
	denyConfigStat     bool
}

func newMockNaiveSSHClient() *mockNaiveSSHClient {
	return &mockNaiveSSHClient{
		files:       make(map[string][]byte),
		dockerAlive: true,
		sshUser:     "root",
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
	if strings.HasPrefix(cmd, "test -f ") {
		path := strings.Trim(strings.TrimPrefix(cmd, "test -f "), "'")
		if _, ok := m.files[path]; ok {
			return "", "", 0, nil
		}
		return "", "", 1, nil
	}
	if strings.HasPrefix(cmd, "cat ") && strings.Contains(cmd, "/opt/amnezia/") {
		for p, data := range m.files {
			if strings.Contains(cmd, p) {
				return string(data), "", 0, nil
			}
		}
		return "", "", 1, nil
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
	if m.denyConfigDownload && remotePath == NaiveCaddyfilePath {
		return nil, os.ErrPermission
	}
	data, ok := m.files[remotePath]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *mockNaiveSSHClient) DownloadSudoFile(ctx context.Context, remotePath string) ([]byte, error) {
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
	if m.denyConfigStat && remotePath == NaiveCaddyfilePath {
		return false, os.ErrPermission
	}
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
	return m.sshUser
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
	if !strings.HasPrefix(uri, "naive+https://") {
		t.Errorf("expected naive+https:// URI, got: %s", uri)
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
	if strings.Contains(string(caddyfileBytes), "forward_proxy") {
		t.Errorf("initial install Caddyfile with 0 clients must NOT contain forward_proxy directive")
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
	if !strings.HasPrefix(configURI, "naive+https://") {
		t.Errorf("expected config naive+https:// URI, got %s", configURI)
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

	caddyfileAfterRemove := string(mockSSH.files[NaiveCaddyfilePath])
	requireNoActiveProxy(t, caddyfileAfterRemove)

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

func TestNaiveManager_GetClientsReturnsEnumerationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		wantErr string
	}{
		{name: "download failure", wantErr: "download caddyfile"},
		{name: "parse failure", content: []byte("not a caddyfile"), wantErr: "parse caddyfile"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSSH := newMockNaiveSSHClient()
			if tt.content != nil {
				mockSSH.files[NaiveCaddyfilePath] = tt.content
			}
			mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())

			clients, err := mgr.GetClients(context.Background(), &models.Server{ID: 88})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("GetClients error = %v, want error containing %q", err, tt.wantErr)
			}
			if clients != nil {
				t.Fatalf("GetClients clients = %v, want nil", clients)
			}
		})
	}
}

func TestNaiveManager_SudoNodeClientOperationsAfterRawConfigSave(t *testing.T) {
	mockSSH := newMockNaiveSSHClient()
	mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 90, Host: "198.51.100.90", SSHUser: "ubuntu"}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if err := mockSSH.UploadSudoFile(ctx, NaiveCaddyfilePath, mockSSH.files[NaiveCaddyfilePath], 0600); err != nil {
		t.Fatalf("raw config save failed: %v", err)
	}
	mockSSH.sshUser = "ubuntu"
	mockSSH.denyConfigDownload = true

	added, err := mgr.AddClient(ctx, server, map[string]any{"username": "sudo-user", "password": "secret-password"})
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

func TestNaiveConfig_ZeroClientsNoProbeResistance(t *testing.T) {
	// B5 & R2-B1 assertion: zero-client Caddyfile must NOT emit probe_resistance or forward_proxy
	caddyfileNil := RenderCaddyfile(443, "vpn.example.com", nil)
	if strings.Contains(caddyfileNil, "probe_resistance") {
		t.Errorf("RenderCaddyfile with nil clients must not contain probe_resistance:\n%s", caddyfileNil)
	}
	if strings.Contains(caddyfileNil, "forward_proxy") {
		t.Errorf("RenderCaddyfile with nil clients must NOT contain forward_proxy directive:\n%s", caddyfileNil)
	}
	if !strings.Contains(caddyfileNil, "root * /var/www/html") || !strings.Contains(caddyfileNil, "file_server") {
		t.Errorf("RenderCaddyfile with nil clients must contain decoy site:\n%s", caddyfileNil)
	}

	caddyfileEmpty := RenderCaddyfile(443, "vpn.example.com", []NaiveClient{})
	if strings.Contains(caddyfileEmpty, "probe_resistance") {
		t.Errorf("RenderCaddyfile with empty clients must not contain probe_resistance:\n%s", caddyfileEmpty)
	}
	if strings.Contains(caddyfileEmpty, "forward_proxy") {
		t.Errorf("RenderCaddyfile with empty clients must NOT contain forward_proxy directive:\n%s", caddyfileEmpty)
	}

	// When clients with credentials exist, forward_proxy, basic_auth, and probe_resistance MUST be present
	caddyfileWithClients := RenderCaddyfile(443, "vpn.example.com", []NaiveClient{
		{Username: "user1", Password: "test_secret_pass_123"},
	})
	if !strings.Contains(caddyfileWithClients, "forward_proxy {") {
		t.Errorf("RenderCaddyfile with authenticated clients must contain forward_proxy:\n%s", caddyfileWithClients)
	}
	if !strings.Contains(caddyfileWithClients, "probe_resistance") {
		t.Errorf("RenderCaddyfile with authenticated clients must contain probe_resistance:\n%s", caddyfileWithClients)
	}
	if !strings.Contains(caddyfileWithClients, "basic_auth user1 test_secret_pass_123") {
		t.Errorf("RenderCaddyfile missing basic_auth directive:\n%s", caddyfileWithClients)
	}
}

func TestNaiveConfig_NonDefaultPortRoundTrip(t *testing.T) {
	// R3-H1: port 8443 must render :port, domain:port to enable CONNECT routing while automating domain TLS
	domain := "vpn.custom.org"
	port := 8443
	clients := []NaiveClient{
		{Username: "user8443", Password: "pass8443secret"},
	}

	expectedHeader := fmt.Sprintf(":%d, %s:%d {", port, domain, port)

	rendered := RenderCaddyfile(port, domain, clients)
	if !strings.Contains(rendered, expectedHeader) {
		t.Errorf("expected rendered Caddyfile to contain %q, got:\n%s", expectedHeader, rendered)
	}
	if strings.Contains(rendered, "https://") {
		t.Errorf("rendered Caddyfile must NOT emit https:// site address (creates host matcher blocking CONNECT), got:\n%s", rendered)
	}

	parsedDomain, parsedPort, parsedClients, err := ParseCaddyfile(rendered)
	if err != nil {
		t.Fatalf("ParseCaddyfile failed: %v", err)
	}
	if parsedDomain != domain {
		t.Errorf("domain mismatch: expected %q, got %q", domain, parsedDomain)
	}
	if parsedPort != port {
		t.Errorf("port mismatch: expected %d, got %d", port, parsedPort)
	}
	if len(parsedClients) != 1 || parsedClients[0].Username != "user8443" || parsedClients[0].Password != "pass8443secret" {
		t.Errorf("parsed clients mismatch: %+v", parsedClients)
	}

	// Also verify 0-client custom port
	rendered0 := RenderCaddyfile(port, domain, nil)
	if !strings.Contains(rendered0, expectedHeader) {
		t.Errorf("expected 0-client custom port Caddyfile to contain %q, got:\n%s", expectedHeader, rendered0)
	}
	if strings.Contains(rendered0, "forward_proxy") {
		t.Errorf("0-client custom port Caddyfile must not have forward_proxy:\n%s", rendered0)
	}
	parsedDomain0, parsedPort0, parsedClients0, err := ParseCaddyfile(rendered0)
	if err != nil {
		t.Fatalf("ParseCaddyfile 0-client failed: %v", err)
	}
	if parsedDomain0 != domain || parsedPort0 != port || len(parsedClients0) != 0 {
		t.Errorf("parsed 0-client mismatch: domain=%s port=%d clients=%v", parsedDomain0, parsedPort0, parsedClients0)
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

type failNaiveSSHClient struct {
	*mockNaiveSSHClient
	stopFails bool
}

func (m *failNaiveSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker stop") && m.stopFails {
		return "", "daemon error: cannot stop container", 1, fmt.Errorf("command exited 1")
	}
	return m.mockNaiveSSHClient.RunSudoCommand(ctx, cmd)
}

func TestNaiveManager_UninstallFailurePropagation(t *testing.T) {
	mockSSH := &failNaiveSSHClient{
		mockNaiveSSHClient: newMockNaiveSSHClient(),
		stopFails:          true,
	}
	pool := &mockNaivePool{client: mockSSH}
	locks := awg.NewServerLockRegistry()
	mgr := NewNaiveManagerWithServerLocks(pool, locks)

	server := &models.Server{
		ID:        99,
		Host:      "198.51.100.2",
		Protocols: map[string]any{models.ProtocolNaive: map[string]any{"installed": true}},
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
		if strings.Contains(cmd, "rm -rf") && strings.Contains(cmd, NaiveConfigDir) {
			t.Errorf("rm -rf config directory must not be run when container removal fails")
		}
	}

	// Protocol must still be in in-memory map
	if _, ok := server.Protocols[models.ProtocolNaive]; !ok {
		t.Errorf("server.Protocols[naive] must not be deleted on uninstall failure")
	}

	// Also verify idempotent uninstall when container is absent
	absentMockSSH := newMockNaiveSSHClient()
	absentMockSSH.dockerAlive = false
	absentMgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: absentMockSSH}, awg.NewServerLockRegistry())
	server2 := &models.Server{
		ID:        100,
		Host:      "198.51.100.3",
		Protocols: map[string]any{models.ProtocolNaive: map[string]any{"installed": true}},
	}
	if err := absentMgr.Uninstall(ctx, server2); err != nil {
		t.Fatalf("expected idempotent success on absent container, got: %v", err)
	}
	if _, ok := server2.Protocols[models.ProtocolNaive]; ok {
		t.Errorf("expected server.Protocols[naive] deleted on successful absent uninstall")
	}
}

func TestNaiveManager_ReinstallPreservesClients(t *testing.T) {
	mockSSH := newMockNaiveSSHClient()
	pool := &mockNaivePool{client: mockSSH}
	mgr := NewNaiveManagerWithServerLocks(pool, awg.NewServerLockRegistry())

	server := &models.Server{
		ID:        78,
		Host:      "198.51.100.78",
		Protocols: make(map[string]any),
	}
	ctx := context.Background()

	// 1. Initial install
	installParams := map[string]any{
		"port": 443,
		"naive_options": models.NaiveInstallOptions{
			Port:   "443",
			Domain: "naive.example.com",
		},
	}
	if err := mgr.Install(ctx, server, installParams); err != nil {
		t.Fatalf("Initial install failed: %v", err)
	}

	// 2. Add two clients
	c1, err := mgr.AddClient(ctx, server, map[string]any{"username": "user1", "password": "pass1_secure"})
	if err != nil {
		t.Fatalf("AddClient user1 failed: %v", err)
	}
	c2, err := mgr.AddClient(ctx, server, map[string]any{"username": "user2", "password": "pass2_secure"})
	if err != nil {
		t.Fatalf("AddClient user2 failed: %v", err)
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

	// 4. Verify clients preserved
	clientsAfter, err := mgr.GetClients(ctx, server)
	if err != nil {
		t.Fatalf("GetClients after reinstall failed: %v", err)
	}
	if len(clientsAfter) != 2 {
		t.Fatalf("expected 2 clients after reinstall, got %d", len(clientsAfter))
	}
	if clientsAfter[0]["username"] != c1["username"] || clientsAfter[1]["username"] != c2["username"] {
		t.Errorf("client usernames mismatched after reinstall: got %+v", clientsAfter)
	}
}

func TestNaiveManager_InstallFailsClosedOnMalformedOrUncertainConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("Truncated Caddyfile with unmatched braces fails closed", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		truncated := []byte("{\n    admin 127.0.0.1:2019\n\n:443, localhost {\n    route {\n") // unmatched braces
		mockSSH.files[NaiveCaddyfilePath] = truncated

		pool := &mockNaivePool{client: mockSSH}
		mgr := NewNaiveManagerWithServerLocks(pool, awg.NewServerLockRegistry())
		server := &models.Server{ID: 1, Host: "192.0.2.1"}

		err := mgr.Install(ctx, server, map[string]any{"port": 443})
		if err == nil {
			t.Fatalf("expected Install to fail closed on truncated Caddyfile, got nil error")
		}
		if !strings.Contains(err.Error(), "unmatched") && !strings.Contains(err.Error(), "parse") {
			t.Errorf("expected error to mention parsing or unmatched braces, got: %v", err)
		}
		// Verify file was NOT overwritten
		if string(mockSSH.files[NaiveCaddyfilePath]) != string(truncated) {
			t.Errorf("truncated Caddyfile was overwritten despite failure!")
		}
	})

	t.Run("Malformed basic_auth directive fails closed", func(t *testing.T) {
		mockSSH := newMockNaiveSSHClient()
		malformed := []byte("{\n    admin 127.0.0.1:2019\n}\n:443, localhost {\n    route {\n        forward_proxy {\n            basic_auth truncated_no_pass\n        }\n    }\n}\n")
		mockSSH.files[NaiveCaddyfilePath] = malformed

		pool := &mockNaivePool{client: mockSSH}
		mgr := NewNaiveManagerWithServerLocks(pool, awg.NewServerLockRegistry())
		server := &models.Server{ID: 1, Host: "192.0.2.1"}

		err := mgr.Install(ctx, server, map[string]any{"port": 443})
		if err == nil {
			t.Fatalf("expected Install to fail closed on malformed basic_auth, got nil error")
		}
		if !strings.Contains(err.Error(), "basic_auth") {
			t.Errorf("expected error to mention basic_auth, got: %v", err)
		}
	})
}
