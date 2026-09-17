package awg_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

type threadSafeMockSSHClient struct {
	mu                   sync.RWMutex
	files                map[string][]byte
	failSaveServerConfig atomic.Bool
	host                 string
	port                 int
	serverID             *int64
}

func newThreadSafeMockSSHClient() *threadSafeMockSSHClient {
	c := &threadSafeMockSSHClient{
		files: make(map[string][]byte),
	}
	c.files["/opt/amnezia/awg/wireguard_server_public_key.key"] = []byte("serverPubKey1234567890123456789012345=")
	c.files["/opt/amnezia/awg/wireguard_server_private_key.key"] = []byte("serverPrivKey1234567890123456789012345=")
	c.files["/opt/amnezia/awg/wireguard_psk.key"] = []byte("pskKey123456789012345678901234567890123=")
	c.files["/opt/amnezia/awg/awg0.conf"] = []byte(`[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.66.66.1/24
ListenPort = 51820
MTU = 1420
Jc = 4
Jmin = 30
Jmax = 80
S1 = 40
S2 = 60
H1 = 12345
H2 = 67890
`)
	c.files["/opt/amnezia/awg/clientsTable"] = []byte(`[]`)
	return c
}

func (m *threadSafeMockSSHClient) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker --version") {
		return "Docker version 24.0.5", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *threadSafeMockSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failSaveServerConfig.Load() {
		if strings.Contains(cmd, "docker cp") && (strings.Contains(cmd, "awg0.conf") || strings.Contains(cmd, "edit_config")) {
			return "", "simulated write failure", 1, errors.New("simulated remote failure on saveServerConfig")
		}
		if strings.Contains(cmd, "awg syncconf") {
			return "", "simulated syncconf failure", 1, errors.New("simulated remote failure on awg syncconf")
		}
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
	if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "clients") {
		for path, content := range m.files {
			if strings.Contains(path, "clients") && path != "/opt/amnezia/awg/clientsTable" {
				m.files["/opt/amnezia/awg/clientsTable"] = content
				break
			}
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp") && (strings.Contains(cmd, "awg0.conf") || strings.Contains(cmd, "edit_config")) {
		for path, content := range m.files {
			if (strings.Contains(path, "awg0.conf") || strings.Contains(path, "edit_config")) && path != "/opt/amnezia/awg/awg0.conf" {
				m.files["/opt/amnezia/awg/awg0.conf"] = content
				break
			}
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker ps") {
		return "amnezia-awg", "", 0, nil
	}
	return "OK", "", 0, nil
}

func (m *threadSafeMockSSHClient) RunScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *threadSafeMockSSHClient) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}

func (m *threadSafeMockSSHClient) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = content
	return nil
}

func (m *threadSafeMockSSHClient) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[remotePath] = content
	return nil
}

func (m *threadSafeMockSSHClient) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.files[remotePath], nil
}

func (m *threadSafeMockSSHClient) FileExists(ctx context.Context, remotePath string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.files[remotePath]
	return exists, nil
}

func (m *threadSafeMockSSHClient) TestConnection(ctx context.Context) (string, error) {
	return "Linux", nil
}

func (m *threadSafeMockSSHClient) Close() error {
	return nil
}

func (m *threadSafeMockSSHClient) IsAlive() bool {
	return true
}

func (m *threadSafeMockSSHClient) GetUnderlyingClient() *gossh.Client {
	return nil
}

func (m *threadSafeMockSSHClient) GetHost() string {
	if m.host != "" {
		return m.host
	}
	return "127.0.0.1"
}

func (m *threadSafeMockSSHClient) GetPort() int {
	if m.port != 0 {
		return m.port
	}
	return 22
}

func (m *threadSafeMockSSHClient) GetUser() string {
	return "root"
}

func (m *threadSafeMockSSHClient) GetServerID() *int64 {
	return m.serverID
}

func (m *threadSafeMockSSHClient) GetLastActive() time.Time {
	return time.Now()
}

type threadSafeMockSSHProvider struct {
	client *threadSafeMockSSHClient
}

func (p *threadSafeMockSSHProvider) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}

func setupAWGManagerWithDB(t *testing.T) (*awg.AWGManager, *database.DB, *threadSafeMockSSHClient, *models.Server, func()) {
	t.Helper()
	db, err := database.Open(":memory:", "")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	sshClient := newThreadSafeMockSSHClient()
	provider := &threadSafeMockSSHProvider{client: sshClient}
	mgr := awg.NewAWGManager(provider)
	mgr.SetIPAllocator(db)

	server := &models.Server{
		ID:   1,
		Name: "test-awg-server",
		Host: "192.0.2.1",
	}

	cleanup := func() {
		_ = db.Close()
	}

	return mgr, db, sshClient, server, cleanup
}

func TestAWGManager_ConcurrentClientProvisioning(t *testing.T) {
	mgr, db, _, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()
	const numClients = 25
	var wg sync.WaitGroup

	type allocResult struct {
		clientID string
		clientIP string
		err      error
	}
	results := make([]allocResult, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			params := map[string]any{
				"client_name": fmt.Sprintf("concurrent-client-%d", idx),
			}
			res, err := mgr.AddClient(ctx, server, params)
			if err != nil {
				results[idx] = allocResult{err: err}
				return
			}
			ip, _ := res["client_ip"].(string)
			cID, _ := res["client_id"].(string)
			results[idx] = allocResult{
				clientID: cID,
				clientIP: ip,
				err:      nil,
			}
		}(i)
	}

	wg.Wait()

	seenIPs := make(map[string]string)
	for i, res := range results {
		if res.err != nil {
			t.Fatalf("client %d provision failed: %v", i, res.err)
		}
		if res.clientIP == "" {
			t.Fatalf("client %d returned empty client_ip", i)
		}
		if prevClient, exists := seenIPs[res.clientIP]; exists {
			t.Fatalf("DUPLICATE IP DETECTED: IP %s assigned to both %s and %s", res.clientIP, prevClient, res.clientID)
		}
		seenIPs[res.clientIP] = res.clientID
	}

	if len(seenIPs) != numClients {
		t.Fatalf("expected %d distinct IPs, got %d", numClients, len(seenIPs))
	}

	// Verify database allocations match exactly
	allocatedDB, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query allocated IPs from db: %v", err)
	}
	if len(allocatedDB) != numClients {
		t.Fatalf("expected %d allocations in DB, got %d", numClients, len(allocatedDB))
	}
	for _, ip := range allocatedDB {
		if _, ok := seenIPs[ip]; !ok {
			t.Fatalf("IP %s in DB was not in provisioning results", ip)
		}
	}
}

func TestAWGManager_RollbackOnRemoteFailure(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Successfully provision one client to verify baseline
	res1, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "good-client"})
	if err != nil {
		t.Fatalf("baseline provision failed: %v", err)
	}
	ip1 := res1["client_ip"].(string)

	allocated1, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated1) != 1 {
		t.Fatalf("expected 1 allocated IP in DB, got: %v (err: %v)", allocated1, err)
	}

	// 2. Arm failure on remote server config save
	sshClient.failSaveServerConfig.Store(true)

	// 3. Attempt to provision second client — remote save will fail
	_, err = mgr.AddClient(ctx, server, map[string]any{"client_name": "failing-client"})
	if err == nil {
		t.Fatalf("expected error due to simulated remote failure, got nil")
	}

	// 4. Confirm rollback: the reserved IP for failing-client MUST have been released from DB
	allocatedAfterFailure, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocatedAfterFailure) != 1 || allocatedAfterFailure[0] != ip1 {
		t.Fatalf("rollback failed: expected only %s in DB, got: %+v", ip1, allocatedAfterFailure)
	}

	// 5. Disarm failure and re-provision second client — it should succeed and receive the next IP
	sshClient.failSaveServerConfig.Store(false)
	res2, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "retry-client"})
	if err != nil {
		t.Fatalf("retry provision failed: %v", err)
	}
	ip2 := res2["client_ip"].(string)
	if ip2 == ip1 {
		t.Fatalf("new client got duplicate IP %s", ip2)
	}

	allocatedFinal, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocatedFinal) != 2 {
		t.Fatalf("expected 2 allocations in DB, got: %+v", allocatedFinal)
	}
}

func TestAWGManager_RemoveClientReleasesIP(t *testing.T) {
	mgr, db, _, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Provision a client
	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "client-to-remove"})
	if err != nil {
		t.Fatalf("provision failed: %v", err)
	}
	clientID := res["client_id"].(string)
	clientIP := res["client_ip"].(string)

	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != 1 || allocated[0] != clientIP {
		t.Fatalf("expected IP %s in DB, got: %+v", clientIP, allocated)
	}

	// Remove client
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient failed: %v", err)
	}

	// Verify IP was released from allocations table
	allocatedAfterRemove, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocatedAfterRemove) != 0 {
		t.Fatalf("expected 0 allocations after remove, got: %+v", allocatedAfterRemove)
	}
}

func TestAWGManager_FallbackWithoutAllocator(t *testing.T) {
	// When ipAllocator is nil, AddClient falls back to resolveClientIP
	sshClient := newThreadSafeMockSSHClient()
	provider := &threadSafeMockSSHProvider{client: sshClient}
	mgr := awg.NewAWGManager(provider)
	// ipAllocator is explicitly nil

	server := &models.Server{
		ID:   1,
		Name: "no-alloc-server",
		Host: "192.0.2.1",
	}

	ctx := context.Background()
	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "legacy-mock-client"})
	if err != nil {
		t.Fatalf("AddClient failed without allocator: %v", err)
	}
	ip, ok := res["client_ip"].(string)
	if !ok || ip == "" {
		t.Fatalf("expected valid client_ip from fallback, got: %+v", res)
	}
}
