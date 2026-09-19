package awg_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

var (
	mockRemoteLocksMu sync.Mutex
	mockRemoteLocks   = make(map[string]chan struct{})
)

func getMockRemoteLock(path string) chan struct{} {
	mockRemoteLocksMu.Lock()
	defer mockRemoteLocksMu.Unlock()
	ch, ok := mockRemoteLocks[path]
	if !ok {
		ch = make(chan struct{}, 1)
		ch <- struct{}{}
		mockRemoteLocks[path] = ch
	}
	return ch
}

func extractLockKey(cmd string) string {
	idx := strings.Index(cmd, "/tmp/amnezia_awg_")
	if idx == -1 {
		return "default_lock"
	}
	sub := cmd[idx:]
	end := strings.Index(sub, ".lock")
	if end == -1 {
		return sub
	}
	return sub[:end+5]
}

type threadSafeMockSSHClient struct {
	mu                           sync.RWMutex
	files                        map[string][]byte
	failSaveServerConfig         atomic.Bool
	failSyncconf                 atomic.Bool
	failSyncconfOnce             atomic.Bool
	syncconfCount                atomic.Int32
	failSaveClientsTable         atomic.Bool
	failSaveClientsTableOnSecond atomic.Bool
	saveClientsTableCount        atomic.Int32
	failEnsureNAT                atomic.Bool
	failOnSecondSaveConfig       atomic.Bool
	saveConfigCount              atomic.Int32
	driftCount                   atomic.Int32
	host                         string
	port                         int
	serverID                     *int64
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
	if strings.Contains(cmd, "amnezia_awg_") && (strings.Contains(cmd, "mkdir") || strings.Contains(cmd, "flock")) {
		key := extractLockKey(cmd)
		ch := getMockRemoteLock(key)
		select {
		case <-ctx.Done():
			return "", "lock acquisition cancelled", 1, ctx.Err()
		case <-ch:
			return "OK", "", 0, nil
		}
	}

	if strings.Contains(cmd, "amnezia_awg_") && (strings.Contains(cmd, "rm -rf") || strings.Contains(cmd, "rmdir") || strings.Contains(cmd, "unlock")) {
		key := extractLockKey(cmd)
		ch := getMockRemoteLock(key)
		select {
		case ch <- struct{}{}:
		default:
		}
		return "OK", "", 0, nil
	}

	if strings.Contains(cmd, "amnezia_awg_") && strings.Contains(cmd, "touch -m") {
		return "OK", "", 0, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failSyncconf.Load() && strings.Contains(cmd, "syncconf") {
		return "", "simulated syncconf failure after docker cp", 1, errors.New("simulated syncconf failure")
	}

	if m.failSyncconfOnce.Load() && strings.Contains(cmd, "syncconf") {
		if m.syncconfCount.Add(1) <= 2 {
			return "", "simulated syncconf failure after docker cp", 1, errors.New("simulated syncconf failure")
		}
	}

	if m.failEnsureNAT.Load() && strings.Contains(cmd, "iptables") {
		return "", "simulated iptables failure", 1, errors.New("simulated iptables failure")
	}

	if m.failOnSecondSaveConfig.Load() && strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "edit_config") {
		if m.saveConfigCount.Add(1) >= 2 {
			return "", "simulated remote remove failure", 1, errors.New("simulated remote remove failure")
		}
	}

	if m.failSaveServerConfig.Load() {
		if strings.Contains(cmd, "docker cp") && (strings.Contains(cmd, "awg0.conf") || strings.Contains(cmd, "edit_config")) {
			return "", "simulated write failure", 1, errors.New("simulated remote failure on saveServerConfig")
		}
		if strings.Contains(cmd, "awg syncconf") {
			return "", "simulated syncconf failure", 1, errors.New("simulated remote failure on awg syncconf")
		}
	}

	if strings.HasPrefix(cmd, "rm -f ") {
		path := strings.TrimSpace(strings.TrimPrefix(cmd, "rm -f "))
		delete(m.files, path)
		return "", "", 0, nil
	}

	if strings.Contains(cmd, "cat ") && strings.Contains(cmd, "awg0.conf") {
		if d := m.driftCount.Load(); d > 0 {
			m.driftCount.Add(-1)
			m.files["/opt/amnezia/awg/awg0.conf"] = append(m.files["/opt/amnezia/awg/awg0.conf"], []byte(fmt.Sprintf("\n# drift_%d\n", d))...)
		}
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
	if strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "clients") {
		if m.failSaveClientsTable.Load() {
			return "", "simulated write failure on clientsTable", 1, errors.New("simulated failure saving clientsTable")
		}
		if m.failSaveClientsTableOnSecond.Load() {
			if m.saveClientsTableCount.Add(1) >= 2 {
				return "", "simulated write failure on second clientsTable save", 1, errors.New("simulated failure saving clientsTable")
			}
		}
		fields := strings.Fields(cmd)
		if len(fields) >= 3 {
			src := strings.Trim(fields[2], "'\"")
			if m.files[src] != nil {
				m.files["/opt/amnezia/awg/clientsTable"] = m.files[src]
				return "", "", 0, nil
			}
		}
		for path, content := range m.files {
			if strings.Contains(path, "clients") && path != "/opt/amnezia/awg/clientsTable" {
				m.files["/opt/amnezia/awg/clientsTable"] = content
				break
			}
		}
		return "", "", 0, nil
	}
	if strings.Contains(cmd, "docker cp") && (strings.Contains(cmd, "awg0.conf") || strings.Contains(cmd, "edit_config")) {
		fields := strings.Fields(cmd)
		if len(fields) >= 3 {
			src := strings.Trim(fields[2], "'\"")
			if m.files[src] != nil {
				m.files["/opt/amnezia/awg/awg0.conf"] = m.files[src]
				return "", "", 0, nil
			}
		}
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

func TestAWGManager_CAS_RemoteConfigDriftRetry(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Simulate a remote config drift that happens once during CAS check
	sshClient.driftCount.Store(1)

	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "drift-client"})
	if err != nil {
		t.Fatalf("AddClient failed with drift retry: %v", err)
	}

	clientIP, ok := res["client_ip"].(string)
	if !ok || clientIP == "" {
		t.Fatalf("expected valid client_ip, got: %v", res)
	}

	// Verify that the final remote awg0.conf contains both the drifted marker and the new client IP
	sshClient.mu.RLock()
	confText := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	sshClient.mu.RUnlock()

	if !strings.Contains(confText, "# drift_1") {
		t.Errorf("expected remote config to retain drifted change # drift_1, got:\n%s", confText)
	}
	if !strings.Contains(confText, clientIP) {
		t.Errorf("expected remote config to contain client IP %s, got:\n%s", clientIP, confText)
	}

	// Verify DB has 1 allocation
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != 1 || allocated[0] != clientIP {
		t.Fatalf("expected 1 allocation for %s, got: %+v", clientIP, allocated)
	}
}

func TestAWGManager_CAS_RetryLimitExceeded(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Cause remote config to drift continuously (more than 5 times)
	sshClient.driftCount.Store(10)

	_, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "exhausted-drift-client"})
	if err == nil {
		t.Fatalf("expected error when CAS retry limit exceeded, got nil")
	}
	if !strings.Contains(err.Error(), "CAS retry limit exceeded") {
		t.Errorf("expected error to mention CAS retry limit exceeded, got: %v", err)
	}

	// Verify that newly allocated IP was rolled back from DB because remoteCommitted was false
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 0 {
		t.Errorf("expected 0 allocations after CAS abort, got: %+v", allocated)
	}
}

func TestAWGManager_StateAwareRollback_RemoteRemovalFailure(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Cause step after remote save (ensureBackendNATRule) to fail
	sshClient.failEnsureNAT.Store(true)
	// 2. Cause peer removal from remote to ALSO fail (on second saveServerConfig)
	sshClient.failOnSecondSaveConfig.Store(true)

	_, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "rollback-failed-client"})
	if err == nil {
		t.Fatalf("expected error from AddClient, got nil")
	}

	// Because remoteCommitted = true AND remote removal failed,
	// the IP MUST NOT be released from the DB to prevent zombie collision!
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 1 {
		t.Fatalf("expected allocation to be retained in DB to prevent zombie collision, got: %+v", allocated)
	}

	// Disarm simulated failures and verify a subsequent client does not collide with the zombie peer
	zombieIP := allocated[0]
	sshClient.failEnsureNAT.Store(false)
	sshClient.failOnSecondSaveConfig.Store(false)

	res2, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "subsequent-client"})
	if err != nil {
		t.Fatalf("subsequent AddClient failed: %v", err)
	}
	subsequentIP, _ := res2["client_ip"].(string)
	if subsequentIP == zombieIP {
		t.Fatalf("subsequent client collided with retained zombie IP: %s", subsequentIP)
	}

	allocatedAfter, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocatedAfter) != 2 {
		t.Fatalf("expected 2 allocations in DB (zombie + subsequent), got: %+v", allocatedAfter)
	}
}

func TestAWGManager_StateAwareRollback_RemoteRemovalSuccess(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Cause step after remote save (ensureBackendNATRule) to fail
	sshClient.failEnsureNAT.Store(true)
	// 2. Remote removal succeeds (failRemoveRemote is false)

	_, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "rollback-success-client"})
	if err == nil {
		t.Fatalf("expected error from AddClient, got nil")
	}

	// Because remote removal succeeded, the IP should be released from DB!
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 0 {
		t.Fatalf("expected 0 allocations in DB after clean remote rollback, got: %+v", allocated)
	}

	// Disarm simulated failure and verify new client can cleanly allocate an IP
	sshClient.failEnsureNAT.Store(false)
	res2, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "subsequent-success-client"})
	if err != nil {
		t.Fatalf("subsequent AddClient after clean rollback failed: %v", err)
	}
	allocatedAfter, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocatedAfter) != 1 || allocatedAfter[0] != res2["client_ip"].(string) {
		t.Fatalf("expected 1 allocation in DB after subsequent provision, got: %+v", allocatedAfter)
	}
}

func TestAWGManager_PerServerSubnetParams(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Update remote awg0.conf with a custom subnet
	customSubnetConf := `[Interface]
PrivateKey = serverPrivKey1234567890123456789012345=
Address = 10.77.77.1/24
ListenPort = 51820
MTU = 1420
`
	sshClient.mu.Lock()
	sshClient.files["/opt/amnezia/awg/awg0.conf"] = []byte(customSubnetConf)
	sshClient.mu.Unlock()

	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "custom-subnet-client"})
	if err != nil {
		t.Fatalf("AddClient with custom subnet failed: %v", err)
	}

	clientIP, _ := res["client_ip"].(string)
	if !strings.HasPrefix(clientIP, "10.77.77.") {
		t.Fatalf("expected client IP in 10.77.77.0/24 subnet, got: %s", clientIP)
	}

	// Verify DB allocation reflects the custom subnet IP
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != 1 || allocated[0] != clientIP {
		t.Fatalf("expected DB to contain %s, got: %+v", clientIP, allocated)
	}

	// Provision a second client to ensure allocation increments within custom subnet
	res2, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "custom-subnet-client-2"})
	if err != nil {
		t.Fatalf("second AddClient with custom subnet failed: %v", err)
	}
	clientIP2, _ := res2["client_ip"].(string)
	if !strings.HasPrefix(clientIP2, "10.77.77.") || clientIP2 == clientIP {
		t.Fatalf("expected distinct client IP in 10.77.77.0/24 subnet, got: %s (first was %s)", clientIP2, clientIP)
	}
	allocated2, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated2) != 2 {
		t.Fatalf("expected 2 DB allocations in custom subnet, got: %+v", allocated2)
	}
}

func TestAWGManager_PerServerLockRegistry_CrossManagerSync(t *testing.T) {
	db, err := database.Open(":memory:", "")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	defer db.Close()

	sshClient := newThreadSafeMockSSHClient()
	provider := &threadSafeMockSSHProvider{client: sshClient}

	// Create TWO separate manager instances targeting the same server
	mgr1 := awg.NewAWGManager(provider)
	mgr1.SetIPAllocator(db)
	mgr2 := awg.NewAWGManager(provider)
	mgr2.SetIPAllocator(db)

	server := &models.Server{
		ID:   42,
		Name: "shared-lock-server",
		Host: "192.0.2.42",
	}

	ctx := context.Background()
	const numClients = 16
	var wg sync.WaitGroup

	type clientResult struct {
		clientID   string
		clientIP   string
		clientName string
	}
	results := make([]clientResult, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var m *awg.AWGManager
			if idx%2 == 0 {
				m = mgr1
			} else {
				m = mgr2
			}
			cName := fmt.Sprintf("multi-mgr-client-%d", idx)
			params := map[string]any{
				"client_name": cName,
			}
			res, addErr := m.AddClient(ctx, server, params)
			if addErr != nil {
				t.Errorf("client %d AddClient failed: %v", idx, addErr)
				return
			}
			results[idx] = clientResult{
				clientID:   res["client_id"].(string),
				clientIP:   res["client_ip"].(string),
				clientName: cName,
			}
		}(i)
	}

	wg.Wait()

	// Objective 1a: Every successfully provisioned client receives a 100% unique IP address
	seenIPs := make(map[string]string)
	for i, r := range results {
		if r.clientIP == "" || r.clientID == "" {
			t.Fatalf("client %d had empty IP or clientID: %+v", i, r)
		}
		if prev, exists := seenIPs[r.clientIP]; exists {
			t.Fatalf("duplicate IP %s detected across managers: client %s and %s", r.clientIP, prev, r.clientID)
		}
		seenIPs[r.clientIP] = r.clientID
	}

	// Objective 1b: Every successfully created peer is present in the final remote configuration (awg0.conf) without lost updates
	sshClient.mu.RLock()
	finalConf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	finalClientsTable := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()

	_, peers, err := awg.ParseServerConfig(finalConf)
	if err != nil {
		t.Fatalf("failed to parse final remote configuration: %v", err)
	}
	if len(peers) != numClients {
		t.Fatalf("expected %d peers in final remote awg0.conf, got %d", numClients, len(peers))
	}
	peerMap := make(map[string]string) // pubKey -> AllowedIPs
	for _, p := range peers {
		peerMap[p.PublicKey] = p.AllowedIPs
	}
	for _, r := range results {
		allowedIPs, ok := peerMap[r.clientID]
		if !ok {
			t.Fatalf("peer %s (%s) missing from final remote awg0.conf without lost updates", r.clientID, r.clientName)
		}
		if !strings.Contains(allowedIPs, r.clientIP) {
			t.Fatalf("peer %s in awg0.conf has AllowedIPs %q, expected client IP %s", r.clientID, allowedIPs, r.clientIP)
		}
	}

	// Objective 1c: Every client is present in clientsTable
	clientsList, err := awg.ParseClientsTable(finalClientsTable)
	if err != nil {
		t.Fatalf("failed to parse final clientsTable: %v", err)
	}
	if len(clientsList) != numClients {
		t.Fatalf("expected %d clients in clientsTable, got %d", numClients, len(clientsList))
	}
	clientTableMap := make(map[string]awg.AWGClient)
	for _, c := range clientsList {
		clientTableMap[c.ClientID] = c
	}
	for _, r := range results {
		c, ok := clientTableMap[r.clientID]
		if !ok {
			t.Fatalf("client %s (%s) missing from clientsTable", r.clientID, r.clientName)
		}
		if c.UserData.ClientIP != r.clientIP {
			t.Fatalf("client %s in clientsTable has IP %s, expected %s", r.clientID, c.UserData.ClientIP, r.clientIP)
		}
		if c.UserData.ClientName != r.clientName {
			t.Fatalf("client %s in clientsTable has name %s, expected %s", r.clientID, c.UserData.ClientName, r.clientName)
		}
	}

	// Objective 1d: Allocations in DB match remote config peers
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != numClients {
		t.Fatalf("expected %d allocations in DB, got: %d (err: %v)", numClients, len(allocated), err)
	}
	dbIPSet := make(map[string]bool)
	for _, ip := range allocated {
		dbIPSet[ip] = true
	}
	for _, p := range peers {
		allowedIPs := p.AllowedIPs
		ipOnly := strings.Split(allowedIPs, "/")[0]
		if !dbIPSet[ipOnly] {
			t.Fatalf("peer AllowedIP %s in remote awg0.conf not found in DB allocations %+v", ipOnly, allocated)
		}
	}
}

func TestAWGManager_Rollback_DockerCpSucceeds_SyncconfFails_RemoteRemovalSuccess(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Arm single syncconf failure: first syncconf fails (during AddClient), but
	// second syncconf succeeds (during rollback peer removal).
	sshClient.failSyncconfOnce.Store(true)

	_, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "syncconf-fail-client"})
	if err == nil {
		t.Fatalf("expected AddClient to fail when syncconf fails")
	}
	if !strings.Contains(err.Error(), "syncconf failure") {
		t.Errorf("expected error to mention syncconf failure, got: %v", err)
	}

	// Remote removal succeeds during rollback, so allocated IP should be released from DB
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 0 {
		t.Fatalf("expected 0 allocations in DB after successful remote rollback, got: %+v", allocated)
	}

	// Disarm failure and verify provisioning succeeds cleanly
	sshClient.failSyncconfOnce.Store(false)
	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "recovered-client"})
	if err != nil {
		t.Fatalf("AddClient after recovery failed: %v", err)
	}
	if res["client_ip"] == "" {
		t.Fatalf("expected valid client_ip after recovery, got empty")
	}
}

func TestAWGManager_Rollback_DockerCpSucceeds_SyncconfFails_RemoteRemovalFailure(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Arm syncconf failure (docker cp succeeds, diskWritten = true) AND
	// arm second saveServerConfig failure (remote removal during rollback fails)
	sshClient.failSyncconf.Store(true)
	sshClient.failOnSecondSaveConfig.Store(true)

	_, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "zombie-syncconf-client"})
	if err == nil {
		t.Fatalf("expected AddClient to fail")
	}

	// Because remote cleanup failed, DB allocation MUST be retained to prevent zombie collision
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 1 {
		t.Fatalf("expected 1 allocation retained in DB to prevent zombie collision, got: %+v", allocated)
	}
	zombieIP := allocated[0]

	// Disarm failures
	sshClient.failSyncconf.Store(false)
	sshClient.failOnSecondSaveConfig.Store(false)

	// Provision subsequent client: MUST NOT receive the zombie IP
	res2, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "subsequent-syncconf-client"})
	if err != nil {
		t.Fatalf("subsequent AddClient failed: %v", err)
	}
	subsequentIP, _ := res2["client_ip"].(string)
	if subsequentIP == zombieIP {
		t.Fatalf("subsequent client collided with retained zombie IP %s", subsequentIP)
	}

	allocatedFinal, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocatedFinal) != 2 {
		t.Fatalf("expected 2 allocations in DB (zombie + subsequent), got: %+v", allocatedFinal)
	}
}

func TestAWGManager_ReKeying_K1_K2_K1(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyK1 = "ERERERERERERERERERERERERERERERERERERERERERE="
		keyK2 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	)

	// 1. Initial provision with key K1
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("initial AddClient with K1 failed: %v", err)
	}
	clientID1, _ := res1["client_id"].(string)
	if clientID1 != keyK1 {
		t.Fatalf("expected client_id %s, got: %s", keyK1, clientID1)
	}
	ip1, _ := res1["client_ip"].(string)
	if ip1 == "" {
		t.Fatalf("expected valid IP for K1")
	}

	allocated1, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated1) != 1 || allocated1[0] != ip1 {
		t.Fatalf("expected 1 DB allocation for K1 (%s), got: %+v", ip1, allocated1)
	}
	owner1, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner1 != keyK1 {
		t.Fatalf("expected DB lease owner %s, got: %s (err: %v)", keyK1, owner1, err)
	}
	// Assert remote peers in awg0.conf and clientsTable metadata
	sshClient.mu.RLock()
	conf1 := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	table1 := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()
	_, peers1, err := awg.ParseServerConfig(conf1)
	if err != nil || len(peers1) != 1 || peers1[0].PublicKey != keyK1 {
		t.Fatalf("expected 1 peer with key %s in awg0.conf, got: %+v", keyK1, peers1)
	}
	clients1, err := awg.ParseClientsTable(table1)
	if err != nil || len(clients1) != 1 || clients1[0].ClientID != keyK1 || clients1[0].UserData.ClientIP != ip1 {
		t.Fatalf("expected 1 client in clientsTable with key %s and IP %s, got: %+v", keyK1, ip1, clients1)
	}

	// 2. Re-key Alice to key K2
	res2, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK2,
	})
	if err != nil {
		t.Fatalf("re-key AddClient with K2 failed: %v", err)
	}
	clientID2, _ := res2["client_id"].(string)
	if clientID2 != keyK2 {
		t.Fatalf("expected client_id %s, got: %s", keyK2, clientID2)
	}
	ip2, _ := res2["client_ip"].(string)
	if ip2 != ip1 {
		t.Fatalf("expected re-keyed client to retain original IP %s, got: %s", ip1, ip2)
	}

	allocated2, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated2) != 1 || allocated2[0] != ip1 {
		t.Fatalf("expected DB allocations count to remain 1 with IP %s, got: %+v", ip1, allocated2)
	}
	owner2, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner2 != keyK2 {
		t.Fatalf("expected DB lease owner updated to %s, got: %s (err: %v)", keyK2, owner2, err)
	}
	// Assert remote peers in awg0.conf and clientsTable metadata
	sshClient.mu.RLock()
	conf2 := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	table2 := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()
	_, peers2, err := awg.ParseServerConfig(conf2)
	if err != nil || len(peers2) != 1 || peers2[0].PublicKey != keyK2 {
		t.Fatalf("expected 1 peer with key %s in awg0.conf (keyK1 removed), got: %+v", keyK2, peers2)
	}
	clients2, err := awg.ParseClientsTable(table2)
	if err != nil || len(clients2) != 1 || clients2[0].ClientID != keyK2 || clients2[0].UserData.ClientIP != ip1 {
		t.Fatalf("expected 1 client in clientsTable with key %s and IP %s, got: %+v", keyK2, ip1, clients2)
	}

	// 3. Re-key Alice back to key K1
	res3, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("re-key AddClient back to K1 failed: %v", err)
	}
	clientID3, _ := res3["client_id"].(string)
	if clientID3 != keyK1 {
		t.Fatalf("expected client_id %s, got: %s", keyK1, clientID3)
	}
	ip3, _ := res3["client_ip"].(string)
	if ip3 != ip1 {
		t.Fatalf("expected re-keyed client back to K1 to retain original IP %s, got: %s", ip1, ip3)
	}

	allocated3, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated3) != 1 || allocated3[0] != ip1 {
		t.Fatalf("expected DB allocations count to remain 1 with IP %s, got: %+v", ip1, allocated3)
	}
	owner3, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner3 != keyK1 {
		t.Fatalf("expected DB lease owner updated back to %s, got: %s (err: %v)", keyK1, owner3, err)
	}
	// Assert remote peers in awg0.conf and clientsTable metadata
	sshClient.mu.RLock()
	conf3 := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	table3 := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()
	_, peers3, err := awg.ParseServerConfig(conf3)
	if err != nil || len(peers3) != 1 || peers3[0].PublicKey != keyK1 {
		t.Fatalf("expected 1 peer with key %s in awg0.conf, got: %+v", keyK1, peers3)
	}
	clients3, err := awg.ParseClientsTable(table3)
	if err != nil || len(clients3) != 1 || clients3[0].ClientID != keyK1 || clients3[0].UserData.ClientIP != ip1 {
		t.Fatalf("expected 1 client in clientsTable with key %s and IP %s, got: %+v", keyK1, ip1, clients3)
	}
}

func TestAWGManager_SaveClientsTableFailure_TriggersRollback(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Arm failure on saving clientsTable
	sshClient.failSaveClientsTable.Store(true)

	_, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "table-fail-client"})
	if err == nil {
		t.Fatalf("expected AddClient to fail when saveClientsTable fails")
	}
	if !strings.Contains(err.Error(), "failed to save clients table") {
		t.Errorf("expected error mentioning failed to save clients table, got: %v", err)
	}

	// Rollback should trigger: remote peer removed and IP released from DB
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 0 {
		t.Fatalf("expected 0 allocations in DB after rollback from saveClientsTable failure, got: %+v", allocated)
	}

	// Disarm failure and provision successfully
	sshClient.failSaveClientsTable.Store(false)
	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "recovered-client"})
	if err != nil {
		t.Fatalf("provision after recovery failed: %v", err)
	}
	if res["client_ip"] == "" {
		t.Fatalf("expected valid client_ip after recovery")
	}
}

func TestAWGManager_RemoteLockSerialization_CrossProcess(t *testing.T) {
	db, err := database.Open(":memory:", "")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	defer db.Close()

	sshClient := newThreadSafeMockSSHClient()
	provider := &threadSafeMockSSHProvider{client: sshClient}

	// Create TWO separate manager instances with INDEPENDENT in-process lock registries,
	// simulating separate operating system processes where in-process mutexes are not shared.
	mgr1 := awg.NewAWGManager(provider)
	mgr1.SetIPAllocator(db)
	mgr1.SetServerLockRegistry(awg.NewServerLockRegistry())

	mgr2 := awg.NewAWGManager(provider)
	mgr2.SetIPAllocator(db)
	mgr2.SetServerLockRegistry(awg.NewServerLockRegistry())

	server := &models.Server{
		ID:   99,
		Name: "cross-process-server",
		Host: "192.0.2.99",
	}

	ctx := context.Background()
	const numClients = 16
	var wg sync.WaitGroup

	type clientResult struct {
		clientID   string
		clientIP   string
		clientName string
	}
	results := make([]clientResult, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var m *awg.AWGManager
			if idx%2 == 0 {
				m = mgr1
			} else {
				m = mgr2
			}
			cName := fmt.Sprintf("proc-client-%d", idx)
			params := map[string]any{
				"client_name": cName,
			}
			res, addErr := m.AddClient(ctx, server, params)
			if addErr != nil {
				t.Errorf("client %d AddClient failed: %v", idx, addErr)
				return
			}
			results[idx] = clientResult{
				clientID:   res["client_id"].(string),
				clientIP:   res["client_ip"].(string),
				clientName: cName,
			}
		}(i)
	}

	wg.Wait()

	// 1. Verify every provisioned client has a unique IP (no collisions)
	seenIPs := make(map[string]string)
	for i, r := range results {
		if r.clientIP == "" || r.clientID == "" {
			t.Fatalf("client %d had empty IP or clientID: %+v", i, r)
		}
		if prev, exists := seenIPs[r.clientIP]; exists {
			t.Fatalf("duplicate IP %s detected across separate manager processes: client %s and %s", r.clientIP, prev, r.clientID)
		}
		seenIPs[r.clientIP] = r.clientID
	}

	if len(seenIPs) != numClients {
		t.Fatalf("expected %d unique IPs across separate processes, got %d", numClients, len(seenIPs))
	}

	// 2. Verify all peers present in remote configuration (no lost updates)
	sshClient.mu.RLock()
	finalConf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	finalClientsTable := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()

	_, peers, err := awg.ParseServerConfig(finalConf)
	if err != nil {
		t.Fatalf("failed to parse final remote configuration: %v", err)
	}
	if len(peers) != numClients {
		t.Fatalf("expected %d peers in final remote awg0.conf, got %d", numClients, len(peers))
	}

	// 3. Verify all clients present in clientsTable
	clientsList, err := awg.ParseClientsTable(finalClientsTable)
	if err != nil {
		t.Fatalf("failed to parse final clientsTable: %v", err)
	}
	if len(clientsList) != numClients {
		t.Fatalf("expected %d clients in clientsTable, got %d", numClients, len(clientsList))
	}

	// 4. Verify DB allocations match numClients
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != numClients {
		t.Fatalf("expected %d allocations in DB, got: %d (err: %v)", numClients, len(allocated), err)
	}
}

func TestRemoteLock_ShellScriptContentionAndStaleLockReclamation(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	serverID := int64(8888)
	lockPath := awg.RemoteLockPath(serverID)
	_ = os.RemoveAll(lockPath)
	defer os.RemoveAll(lockPath)

	ctx := context.Background()

	// 1. Verify contention: run 5 workers concurrently competing for the lock
	const numWorkers = 5
	var (
		activeWorkers atomic.Int32
		maxConcurrent atomic.Int32
		wg            sync.WaitGroup
	)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			token := fmt.Sprintf("worker-%d-%d", wID, time.Now().UnixNano())
			acqCmd := awg.RemoteLockAcquireCmd(serverID, token)

			cmd := exec.CommandContext(ctx, "bash", "-c", acqCmd)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("worker %d failed to acquire lock: %v (out: %s)", wID, err, string(out))
				return
			}

			// In critical section
			curr := activeWorkers.Add(1)
			for {
				max := maxConcurrent.Load()
				if curr > max {
					if maxConcurrent.CompareAndSwap(max, curr) {
						break
					}
				} else {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
			activeWorkers.Add(-1)

			relCmd := awg.RemoteLockReleaseCmd(serverID, token)
			relExec := exec.CommandContext(ctx, "bash", "-c", relCmd)
			if relOut, relErr := relExec.CombinedOutput(); relErr != nil {
				t.Errorf("worker %d failed to release lock: %v (out: %s)", wID, relErr, string(relOut))
			}
		}(i)
	}

	wg.Wait()

	if max := maxConcurrent.Load(); max > 1 {
		t.Fatalf("expected mutual exclusion under contention, but max concurrent was %d", max)
	}

	// 2. Verify stale lock reclamation & explicit ownership protection
	_ = os.RemoveAll(lockPath)
	if err := os.Mkdir(lockPath, 0755); err != nil {
		t.Fatalf("failed to create stale lock dir: %v", err)
	}
	oldOwnerToken := "stale-owner-token"
	ownerFile := filepath.Join(lockPath, "owner")
	if err := os.WriteFile(ownerFile, []byte(oldOwnerToken+"\n"), 0644); err != nil {
		t.Fatalf("failed to write owner file: %v", err)
	}

	// Set directory mtime to 120 seconds in the past (> 60 seconds stale threshold)
	pastTime := time.Now().Add(-120 * time.Second)
	if err := os.Chtimes(lockPath, pastTime, pastTime); err != nil {
		t.Fatalf("failed to set past mtime: %v", err)
	}

	newToken := "successor-token"
	acqCmd := awg.RemoteLockAcquireCmd(serverID, newToken)
	cmd := exec.CommandContext(ctx, "bash", "-c", acqCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to reclaim stale lock: %v (out: %s)", err, string(out))
	}

	// Lock dir must exist with the new token
	ownerData, err := os.ReadFile(ownerFile)
	if err != nil {
		t.Fatalf("failed to read owner file after reclamation: %v", err)
	}
	if fields := strings.Fields(string(ownerData)); len(fields) == 0 || fields[0] != newToken {
		t.Fatalf("expected owner token %s, got: %s", newToken, strings.TrimSpace(string(ownerData)))
	}

	// Old stale owner attempts release using old token - MUST NOT delete successor's lock!
	staleRelCmd := awg.RemoteLockReleaseCmd(serverID, oldOwnerToken)
	relExec := exec.CommandContext(ctx, "bash", "-c", staleRelCmd)
	if relOut, relErr := relExec.CombinedOutput(); relErr != nil {
		t.Fatalf("stale release command failed: %v (out: %s)", relErr, string(relOut))
	}

	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Fatalf("stale owner release erroneously removed successor's lock!")
	}

	// Successor releases with its valid token: MUST remove lock dir
	successorRelCmd := awg.RemoteLockReleaseCmd(serverID, newToken)
	succExec := exec.CommandContext(ctx, "bash", "-c", successorRelCmd)
	if succOut, succErr := succExec.CombinedOutput(); succErr != nil {
		t.Fatalf("successor release failed: %v (out: %s)", succErr, string(succOut))
	}

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected lock dir to be deleted after valid successor release")
	}
}

func TestAWGManager_IncompleteMetadataRollbackFailure_RetainsLease(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Provision client A
	resA, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "clientA"})
	if err != nil {
		t.Fatalf("provisioning clientA failed: %v", err)
	}
	ipA, _ := resA["client_ip"].(string)

	// Arm failure on NAT rule and failure on second saveClientsTable (which happens during rollback)
	sshClient.failEnsureNAT.Store(true)
	sshClient.failSaveClientsTableOnSecond.Store(true)

	// Provision client B: will fail at NAT and trigger rollback
	_, err = mgr.AddClient(ctx, server, map[string]any{"client_name": "clientB"})
	if err == nil {
		t.Fatalf("expected AddClient for clientB to fail")
	}

	// Because saving clientsTable during rollback failed, clientB's IP lease MUST be retained
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if len(allocated) != 2 {
		t.Fatalf("expected 2 DB allocations retained (clientA + clientB), got %d: %+v", len(allocated), allocated)
	}
	if allocated[0] != ipA && allocated[1] != ipA {
		t.Fatalf("expected clientA IP %s in allocations: %+v", ipA, allocated)
	}
}

func TestAWGManager_FailedRekeying_RollbackCompensation(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyK1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		keyK2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	)

	// 1. Initial provision with key K1
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("initial AddClient failed: %v", err)
	}
	ip1, _ := res1["client_ip"].(string)

	owner1, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner1 != keyK1 {
		t.Fatalf("expected initial owner %s, got: %s (err: %v)", keyK1, owner1, err)
	}

	// 2. Arm failure on saving server config so commitPeerConfigWithCAS fails before remote commit
	sshClient.failSaveServerConfig.Store(true)

	// Attempt re-keying to key K2
	_, err = mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK2,
	})
	if err == nil {
		t.Fatalf("expected re-keying to fail when saveServerConfig fails")
	}

	// 3. Verify rollback compensation: lease ownership in DB MUST be restored to key K1!
	ownerAfter, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || ownerAfter != keyK1 {
		t.Fatalf("expected DB lease owner reverted back to %s after pre-commit failure, got: %s (err: %v)", keyK1, ownerAfter, err)
	}

	// Total allocations count must remain 1
	allocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated) != 1 || allocated[0] != ip1 {
		t.Fatalf("expected 1 allocation with IP %s, got: %+v", ip1, allocated)
	}
}

func TestAWGManager_ExistingClientWithoutLeaseRow_MetadataSyncAndAdoption(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyAlice = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
		legacyIP = "10.66.66.77"
	)

	// Populate remote state with a legacy client in clientsTable and awg0.conf,
	// but NO allocation in DB (simulating upgrade of an existing deployment).
	legacyClient := awg.AWGClient{
		ClientID: keyAlice,
		UserData: awg.AWGClientUserData{
			ClientName: "LegacyAlice",
			ClientIP:   legacyIP,
			Enabled:    true,
		},
	}
	tableData, err := awg.SerializeClientsTable([]awg.AWGClient{legacyClient})
	if err != nil {
		t.Fatalf("failed to serialize clientsTable: %v", err)
	}

	sshClient.mu.Lock()
	sshClient.files["/opt/amnezia/awg/clientsTable"] = []byte(tableData)
	sshClient.files["/opt/amnezia/awg/awg0.conf"] = []byte(fmt.Sprintf(
		"[Interface]\nPrivateKey = privkey\nAddress = 10.66.66.1/24\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n",
		keyAlice, legacyIP,
	))
	sshClient.mu.Unlock()

	// Verify DB has 0 allocations initially
	initialAllocated, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(initialAllocated) != 0 {
		t.Fatalf("expected 0 initial allocations in DB, got: %+v", initialAllocated)
	}

	// 1. Provisioning / updating LegacyAlice should adopt legacyIP into DB and preserve it
	res, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "LegacyAlice",
		"public_key":  keyAlice,
	})
	if err != nil {
		t.Fatalf("AddClient for legacy client failed: %v", err)
	}
	returnedIP, _ := res["client_ip"].(string)
	if returnedIP != legacyIP {
		t.Fatalf("expected legacy IP %s to be preserved, got: %s", legacyIP, returnedIP)
	}

	// Verify DB now has legacyIP allocated to keyAlice
	owner, err := db.GetAWGIPAllocationOwner(ctx, server.ID, legacyIP)
	if err != nil || owner != keyAlice {
		t.Fatalf("expected DB lease owner %s for legacy IP %s, got: %s (err: %v)", keyAlice, legacyIP, owner, err)
	}

	// 2. Verify metadata IP synchronization when existingIdx >= 0 and IP changes
	// Setup client Bob in clientsTable with an IP that is already claimed by someone else in DB
	const (
		keyBob      = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
		claimedIP   = "10.66.66.88"
		otherClient = "someone-else-key"
	)
	// Other client claims 10.66.66.88 in DB
	adopted, err := db.AdoptAWGClientIPLease(ctx, server.ID, otherClient, otherClient, claimedIP)
	if err != nil || !adopted {
		t.Fatalf("failed to adopt claimedIP for otherClient: %v (adopted: %v)", err, adopted)
	}

	bobClient := awg.AWGClient{
		ClientID: keyBob,
		UserData: awg.AWGClientUserData{
			ClientName: "Bob",
			ClientIP:   claimedIP,
			Enabled:    true,
		},
	}
	sshClient.mu.Lock()
	currentTable, _ := awg.ParseClientsTable(string(sshClient.files["/opt/amnezia/awg/clientsTable"]))
	currentTable = append(currentTable, bobClient)
	newTableBytes, _ := awg.SerializeClientsTable(currentTable)
	sshClient.files["/opt/amnezia/awg/clientsTable"] = []byte(newTableBytes)
	sshClient.mu.Unlock()

	// Provision Bob: since claimedIP is owned by otherClient, allocator should assign a new IP,
	// and upsertClientEntry MUST update Bob's ClientIP in clientsTable!
	resBob, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Bob",
		"public_key":  keyBob,
	})
	if err != nil {
		t.Fatalf("AddClient for Bob failed: %v", err)
	}
	bobNewIP, _ := resBob["client_ip"].(string)
	if bobNewIP == claimedIP || bobNewIP == "" {
		t.Fatalf("expected Bob to receive a new distinct IP, got: %s", bobNewIP)
	}

	// Verify clientsTable metadata was updated with the new IP for Bob
	sshClient.mu.RLock()
	finalTable, err := awg.ParseClientsTable(string(sshClient.files["/opt/amnezia/awg/clientsTable"]))
	sshClient.mu.RUnlock()
	if err != nil {
		t.Fatalf("failed to parse final clientsTable: %v", err)
	}
	foundBob := false
	for _, c := range finalTable {
		if c.ClientID == keyBob {
			foundBob = true
			if c.UserData.ClientIP != bobNewIP {
				t.Fatalf("expected Bob's ClientIP in clientsTable metadata to be updated to %s, got: %s", bobNewIP, c.UserData.ClientIP)
			}
		}
	}
	if !foundBob {
		t.Fatalf("Bob not found in clientsTable")
	}
}

func TestAWGManager_EditClient_ErrorPropagation(t *testing.T) {
	mgr, _, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	// Initial provision client (enabled = true)
	res, err := mgr.AddClient(ctx, server, map[string]any{"client_name": "edit-client"})
	if err != nil {
		t.Fatalf("initial AddClient failed: %v", err)
	}
	clientID, _ := res["client_id"].(string)

	// Arm failure on server config update
	sshClient.failSaveServerConfig.Store(true)

	// Attempt to disable client
	err = mgr.EditClient(ctx, server, clientID, map[string]any{"enabled": false})
	if err == nil {
		t.Fatalf("expected EditClient to fail when updateServerConfigPeer fails")
	}
	if !strings.Contains(err.Error(), "failed to update server peer config") {
		t.Errorf("expected error mentioning failed to update server peer config, got: %v", err)
	}

	// Verify target.UserData.Enabled was NOT updated to false in clientsTable
	sshClient.mu.RLock()
	tableStr := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()

	clients, err := awg.ParseClientsTable(tableStr)
	if err != nil {
		t.Fatalf("failed to parse clientsTable: %v", err)
	}
	for _, c := range clients {
		if c.ClientID == clientID {
			if !c.UserData.Enabled {
				t.Fatalf("expected client enabled to remain true after uncommitted update failure")
			}
		}
	}
}

func TestRemoteLock_TwoSimultaneousStaleLockReclaimers(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	serverID := int64(9991)
	lockPath := awg.RemoteLockPath(serverID)
	_ = os.RemoveAll(lockPath)
	defer os.RemoveAll(lockPath)

	ctx := context.Background()

	// 1. Create a stale lock directory with past mtime (>60s) and an initial owner token
	if err := os.Mkdir(lockPath, 0755); err != nil {
		t.Fatalf("failed to create stale lock dir: %v", err)
	}
	initialOwner := "stale-owner-999"
	ownerFile := filepath.Join(lockPath, "owner")
	if err := os.WriteFile(ownerFile, []byte(initialOwner+"\n"), 0644); err != nil {
		t.Fatalf("failed to write initial owner file: %v", err)
	}
	pastTime := time.Now().Add(-120 * time.Second)
	if err := os.Chtimes(lockPath, pastTime, pastTime); err != nil {
		t.Fatalf("failed to set past mtime: %v", err)
	}

	// 2. Spawn two concurrent goroutines executing RemoteLockAcquireCmd simultaneously
	var (
		activeHolders atomic.Int32
		maxConcurrent atomic.Int32
		acquiredCount atomic.Int32
		wg            sync.WaitGroup
		startBarrier  = make(chan struct{})
	)

	const numReclaimers = 2
	for i := 0; i < numReclaimers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			token := fmt.Sprintf("reclaimer-%d-%d", workerID, time.Now().UnixNano())
			acqCmd := awg.RemoteLockAcquireCmd(serverID, token)

			<-startBarrier

			cmd := exec.CommandContext(ctx, "bash", "-c", acqCmd)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("worker %d failed to acquire lock: %v (out: %s)", workerID, err, string(out))
				return
			}

			// Critical section
			curr := activeHolders.Add(1)
			for {
				max := maxConcurrent.Load()
				if curr > max {
					if maxConcurrent.CompareAndSwap(max, curr) {
						break
					}
				} else {
					break
				}
			}

			// Verify owner file matches our token
			ownerData, err := os.ReadFile(ownerFile)
			if err != nil {
				t.Errorf("worker %d failed to read owner file: %v", workerID, err)
			} else if fields := strings.Fields(string(ownerData)); len(fields) == 0 || fields[0] != token {
				t.Errorf("worker %d found unexpected owner %s, expected %s", workerID, strings.TrimSpace(string(ownerData)), token)
			}

			acquiredCount.Add(1)
			time.Sleep(100 * time.Millisecond)

			activeHolders.Add(-1)

			relCmd := awg.RemoteLockReleaseCmd(serverID, token)
			relExec := exec.CommandContext(ctx, "bash", "-c", relCmd)
			if relOut, relErr := relExec.CombinedOutput(); relErr != nil {
				t.Errorf("worker %d failed to release lock: %v (out: %s)", workerID, relErr, string(relOut))
			}
		}(i)
	}

	close(startBarrier)
	wg.Wait()

	if acquired := acquiredCount.Load(); acquired != 2 {
		t.Fatalf("expected both reclaimers to acquire lock, got: %d", acquired)
	}
	if max := maxConcurrent.Load(); max != 1 {
		t.Fatalf("expected mutual exclusion strictly preserved (max 1), got: %d", max)
	}
}

type localBashSSHClient struct {
	*threadSafeMockSSHClient
	heartbeats atomic.Int32
}

func newLocalBashSSHClient(serverID int64) *localBashSSHClient {
	mock := newThreadSafeMockSSHClient()
	mock.serverID = &serverID
	return &localBashSSHClient{
		threadSafeMockSSHClient: mock,
	}
}

func (c *localBashSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker ps") {
		return "amnezia-awg", "", 0, nil
	}
	if strings.Contains(cmd, "touch -m") {
		c.heartbeats.Add(1)
	}
	execCmd := exec.CommandContext(ctx, "bash", "-c", cmd)
	out, err := execCmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return string(out), string(out), exitErr.ExitCode(), err
		}
		return string(out), string(out), 1, err
	}
	return string(out), "", 0, nil
}

func TestRemoteLock_ActiveHolderExceedsStaleTimeout_ContenderBlocked(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	serverID := int64(9995)
	mgrA := awg.NewAWGManager(nil)
	// Fast heartbeat in test: refresh mtime every 40ms with 2s timeout
	mgrA.SetLockHeartbeatConfig(40*time.Millisecond, 2*time.Second)

	clientA := newLocalBashSSHClient(serverID)
	ctx := context.Background()
	resource := mgrA.ResolveLockResource(ctx, clientA, serverID)
	lockPath := awg.RemoteLockPath(resource)
	_ = os.RemoveAll(lockPath)
	defer os.RemoveAll(lockPath)

	// 1. Holder A acquires the remote lock with token A and keeps heartbeat active
	unlockA, err := mgrA.AcquireRemoteServerLock(ctx, clientA, serverID)
	if err != nil {
		t.Fatalf("Holder A failed to acquire remote lock: %v", err)
	}

	ownerFile := filepath.Join(lockPath, "owner")
	ownerBytes, err := os.ReadFile(ownerFile)
	if err != nil {
		unlockA()
		t.Fatalf("failed to read owner file after Holder A acquired: %v", err)
	}
	ownerFields := strings.Fields(string(ownerBytes))
	if len(ownerFields) == 0 {
		unlockA()
		t.Fatalf("expected non-empty token A in owner file")
	}
	tokenA := ownerFields[0]

	// Verify that Holder A's heartbeat actively refreshes mtime even if directory timestamp ages:
	// Intentionally backdate mtime to simulate elapsed time exceeding the 60s stale threshold
	pastTime := time.Now().Add(-120 * time.Second)
	if err := os.Chtimes(lockPath, pastTime, pastTime); err != nil {
		unlockA()
		t.Fatalf("failed to set past mtime: %v", err)
	}

	// Wait for heartbeat ticker to execute touch -m
	time.Sleep(120 * time.Millisecond)

	fi, err := os.Stat(lockPath)
	if err != nil {
		unlockA()
		t.Fatalf("lock directory missing: %v", err)
	}
	if time.Since(fi.ModTime()) > 5*time.Second {
		unlockA()
		t.Fatalf("expected heartbeat to keep mtime fresh, but lock age is %v", time.Since(fi.ModTime()))
	}
	if clientA.heartbeats.Load() == 0 {
		unlockA()
		t.Fatalf("expected heartbeat touch commands to be executed")
	}

	// 2. Contender B attempts to acquire the lock while Holder A is active.
	// Contender B checks whether directory is stale. Because Holder A's heartbeat keeps mtime fresh,
	// Contender B must be blocked and cannot steal the lock.
	tokenB := "contender-b-token"
	acqCmdB := awg.RemoteLockAcquireCmd(resource, tokenB)

	contenderDone := make(chan error, 1)
	go func() {
		cmdB := exec.CommandContext(ctx, "bash", "-c", acqCmdB)
		out, runErr := cmdB.CombinedOutput()
		if runErr != nil {
			contenderDone <- fmt.Errorf("contender failed: %w (out: %s)", runErr, string(out))
			return
		}
		contenderDone <- nil
	}()

	// Assert that Contender B is blocked while Holder A remains active
	select {
	case err := <-contenderDone:
		unlockA()
		t.Fatalf("contender should be blocked while Holder A is active, but finished early: %v", err)
	case <-time.After(350 * time.Millisecond):
		// Expected: contender remains blocked
	}

	// Assert that Holder A still owns the lock (lock not stolen)
	currentOwner, err := os.ReadFile(ownerFile)
	if err != nil {
		unlockA()
		t.Fatalf("failed to read owner file: %v", err)
	}
	if fields := strings.Fields(string(currentOwner)); len(fields) == 0 || fields[0] != tokenA {
		unlockA()
		t.Fatalf("lock was stolen! expected owner %s, got %s", tokenA, strings.TrimSpace(string(currentOwner)))
	}

	// 3. Holder A releases the lock
	unlockA()
	heartbeatsAfterUnlock := clientA.heartbeats.Load()

	// Verify heartbeat goroutine was stopped by unlockA: no more heartbeats should fire
	time.Sleep(100 * time.Millisecond)
	if extraHeartbeats := clientA.heartbeats.Load() - heartbeatsAfterUnlock; extraHeartbeats > 0 {
		t.Fatalf("heartbeat continued firing after unlock: %d extra heartbeats", extraHeartbeats)
	}

	// 4. Assert that Contender B can successfully acquire the lock now that Holder A released it
	select {
	case err := <-contenderDone:
		if err != nil {
			t.Fatalf("contender failed to acquire lock after Holder A released: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("contender timed out waiting to acquire lock after release")
	}

	// Assert Contender B is now the registered owner
	finalOwner, err := os.ReadFile(ownerFile)
	if err != nil {
		t.Fatalf("failed to read owner file after Contender B acquired: %v", err)
	}
	if fields := strings.Fields(string(finalOwner)); len(fields) == 0 || fields[0] != tokenB {
		t.Fatalf("expected Contender B token %s, got: %s", tokenB, strings.TrimSpace(string(finalOwner)))
	}

	// Clean up: Contender B releases the lock
	relCmdB := awg.RemoteLockReleaseCmd(resource, tokenB)
	relExec := exec.CommandContext(ctx, "bash", "-c", relCmdB)
	if relOut, relErr := relExec.CombinedOutput(); relErr != nil {
		t.Fatalf("contender failed to release lock: %v (out: %s)", relErr, string(relOut))
	}

	// Verify lock directory is removed
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after release")
	}
}

func TestRemoteLock_OwnerlessStaleLockRecovery(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	tests := []struct {
		name       string
		writeOwner bool
		ownerData  []byte
	}{
		{
			name:       "MissingOwnerFile",
			writeOwner: false,
		},
		{
			name:       "EmptyOwnerFile",
			writeOwner: true,
			ownerData:  []byte(""),
		},
		{
			name:       "WhitespaceOwnerFile",
			writeOwner: true,
			ownerData:  []byte("   \n"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverID := int64(7700 + time.Now().UnixNano()%1000)
			lockPath := awg.RemoteLockPath(serverID)
			_ = os.RemoveAll(lockPath)
			defer os.RemoveAll(lockPath)

			if err := os.MkdirAll(lockPath, 0755); err != nil {
				t.Fatalf("failed to create lock directory: %v", err)
			}

			if tc.writeOwner {
				ownerPath := filepath.Join(lockPath, "owner")
				if err := os.WriteFile(ownerPath, tc.ownerData, 0644); err != nil {
					t.Fatalf("failed to write owner file: %v", err)
				}
			}

			// Backdate mtime past 60s stale threshold
			pastTime := time.Now().Add(-120 * time.Second)
			if err := os.Chtimes(lockPath, pastTime, pastTime); err != nil {
				t.Fatalf("failed to set past mtime: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			token := fmt.Sprintf("contender-%s-%d", tc.name, time.Now().UnixNano())
			acqCmd := awg.RemoteLockAcquireCmd(serverID, token)

			cmd := exec.CommandContext(ctx, "bash", "-c", acqCmd)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("failed to acquire lock over ownerless stale directory: %v (output: %s)", err, string(out))
			}

			// Verify contender became the owner
			ownerBytes, err := os.ReadFile(filepath.Join(lockPath, "owner"))
			if err != nil {
				t.Fatalf("failed to read owner file after acquisition: %v", err)
			}
			if fields := strings.Fields(string(ownerBytes)); len(fields) == 0 || fields[0] != token {
				t.Fatalf("expected owner token %s, got: %s", token, strings.TrimSpace(string(ownerBytes)))
			}

			// Clean up via release
			relCmd := awg.RemoteLockReleaseCmd(serverID, token)
			relExec := exec.CommandContext(ctx, "bash", "-c", relCmd)
			if relOut, relErr := relExec.CombinedOutput(); relErr != nil {
				t.Fatalf("failed to release lock: %v (output: %s)", relErr, string(relOut))
			}

			if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
				t.Fatalf("lock directory still exists after release")
			}
		})
	}
}

func TestRemoteLock_DifferentServerIDsSameTarget_Serialize(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	mgr := awg.NewAWGManager(nil)

	serverID1 := int64(101)
	serverID2 := int64(102)

	client1 := newLocalBashSSHClient(serverID1)
	client2 := newLocalBashSSHClient(serverID2)

	res1 := mgr.ResolveLockResource(ctx, client1, serverID1)
	res2 := mgr.ResolveLockResource(ctx, client2, serverID2)

	if res1 != res2 {
		t.Fatalf("expected both server IDs to resolve to identical resource, got res1=%s res2=%s", res1, res2)
	}

	path1 := awg.RemoteLockPath(res1)
	path2 := awg.RemoteLockPath(res2)

	if path1 != path2 {
		t.Fatalf("expected both server IDs to use identical lock path, got path1=%s path2=%s", path1, path2)
	}

	_ = os.RemoveAll(path1)
	defer os.RemoveAll(path1)

	var (
		activeCount   atomic.Int32
		maxConcurrent atomic.Int32
		orderMu       sync.Mutex
		acquireOrder  []int64
		wg            sync.WaitGroup
	)

	startGate := make(chan struct{})

	runWorker := func(serverID int64, client ssh.SSHClient) {
		defer wg.Done()
		<-startGate

		unlock, err := mgr.AcquireRemoteServerLock(ctx, client, serverID)
		if err != nil {
			t.Errorf("server %d failed to acquire lock: %v", serverID, err)
			return
		}

		current := activeCount.Add(1)
		for {
			max := maxConcurrent.Load()
			if current > max {
				if maxConcurrent.CompareAndSwap(max, current) {
					break
				}
			} else {
				break
			}
		}

		orderMu.Lock()
		acquireOrder = append(acquireOrder, serverID)
		orderMu.Unlock()

		// Hold critical section briefly to force serialized queueing
		time.Sleep(100 * time.Millisecond)

		activeCount.Add(-1)
		unlock()
	}

	wg.Add(2)
	go runWorker(serverID1, client1)
	go runWorker(serverID2, client2)

	close(startGate)
	wg.Wait()

	if max := maxConcurrent.Load(); max != 1 {
		t.Fatalf("expected strict serialization (maxConcurrent=1), got: %d", max)
	}

	orderMu.Lock()
	defer orderMu.Unlock()
	if len(acquireOrder) != 2 {
		t.Fatalf("expected 2 acquisitions, got: %d", len(acquireOrder))
	}

	if _, err := os.Stat(path1); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after both servers released")
	}
}

func TestAWGManager_ResolveLockResource_And_LockPaths(t *testing.T) {
	ctx := context.Background()
	mgr := awg.NewAWGManager(nil)

	// 1. Nil client resolves to physical interface target
	resNil := mgr.ResolveLockResource(ctx, nil, 42)
	if resNil != "iface_awg0" {
		t.Fatalf("expected iface_awg0 for nil client, got: %s", resNil)
	}

	// 2. Client with mock SSH client resolves to physical interface target
	mockClient := newThreadSafeMockSSHClient()
	resMock := mgr.ResolveLockResource(ctx, mockClient, 42)
	if resMock != "iface_awg0" {
		t.Fatalf("expected iface_awg0 for mockClient, got: %s", resMock)
	}

	// 3. remoteLockPath compatibility: int64, string, full path
	if p := awg.RemoteLockPath(int64(42)); p != "/tmp/amnezia_awg_server_42.lock" {
		t.Fatalf("unexpected path for int64: %s", p)
	}
	if p := awg.RemoteLockPath("server_42"); p != "/tmp/amnezia_awg_server_42.lock" {
		t.Fatalf("unexpected path for server_42: %s", p)
	}
	if p := awg.RemoteLockPath("iface_awg0"); p != "/tmp/amnezia_awg_iface_awg0.lock" {
		t.Fatalf("unexpected path for iface_awg0: %s", p)
	}
	if p := awg.RemoteLockPath("amnezia-awg_awg0"); p != "/tmp/amnezia_awg_amnezia-awg_awg0.lock" {
		t.Fatalf("unexpected path for resource string: %s", p)
	}
	if p := awg.RemoteLockResourcePath("custom_resource"); p != "/tmp/amnezia_awg_custom_resource.lock" {
		t.Fatalf("unexpected path for RemoteLockResourcePath: %s", p)
	}
	if p := awg.RemoteLockPath("/tmp/amnezia_awg_already_full.lock"); p != "/tmp/amnezia_awg_already_full.lock" {
		t.Fatalf("unexpected path for already full path: %s", p)
	}
}

type failingAllocDecorator struct {
	awg.IPAllocator
	failAllocate atomic.Bool
}

func (d *failingAllocDecorator) AllocateAWGClientIP(ctx context.Context, serverID int64, clientID, clientPubKey string, usedIPs []string, subnetAddr string, subnetCIDR int, gatewayIP string) (string, error) {
	if d.failAllocate.Load() {
		return "", errors.New("simulated IP allocation failure after lease transfer")
	}
	return d.IPAllocator.AllocateAWGClientIP(ctx, serverID, clientID, clientPubKey, usedIPs, subnetAddr, subnetCIDR, gatewayIP)
}

func TestAWGManager_ReKeying_AllocErrorAfterTransfer_RevertsOwnership(t *testing.T) {
	mgr, db, _, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	allocator := &failingAllocDecorator{IPAllocator: db}
	mgr.SetIPAllocator(allocator)

	const (
		keyK1 = "ERERERERERERERERERERERERERERERERERERERERERE="
		keyK2 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	)

	// 1. Initial provision with K1 succeeds
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("initial AddClient with K1 failed: %v", err)
	}
	ip1, _ := res1["client_ip"].(string)
	if ip1 == "" {
		t.Fatalf("expected valid IP for K1")
	}

	owner1, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner1 != keyK1 {
		t.Fatalf("expected initial lease owner %s, got: %s (err: %v)", keyK1, owner1, err)
	}

	// 2. Arm failure on AllocateAWGClientIP: transfer from K1 to K2 will succeed, but allocation fails
	allocator.failAllocate.Store(true)

	_, err = mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK2,
	})
	if err == nil {
		t.Fatalf("expected AddClient with K2 to fail due to simulated allocation failure")
	}
	if !strings.Contains(err.Error(), "simulated IP allocation failure after lease transfer") {
		t.Errorf("unexpected error: %v", err)
	}

	// 3. Verify lease for ip1 is reverted to K1 in DB
	ownerAfterFailure, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil {
		t.Fatalf("failed to query owner after failure: %v", err)
	}
	if ownerAfterFailure != keyK1 {
		t.Fatalf("expected lease ownership to revert back to %s, got: %s", keyK1, ownerAfterFailure)
	}
}

func TestAWGManager_ReKeying_DiskWriteSucceeds_SyncconfFails_RestoresPreviousPeer(t *testing.T) {
	ctx := context.Background()

	const (
		keyK1 = "ERERERERERERERERERERERERERERERERERERERERERE="
		keyK2 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	)

	// Scenario A1: Remote restoration succeeds -> remote peer K1 is restored and lease reverts to K1
	t.Run("RemoteRestoreSucceeds_RevertsLeaseToK1", func(t *testing.T) {
		mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
		defer cleanup()

		res1, err := mgr.AddClient(ctx, server, map[string]any{
			"client_name": "Alice",
			"public_key":  keyK1,
		})
		if err != nil {
			t.Fatalf("initial AddClient with K1 failed: %v", err)
		}
		ip1, _ := res1["client_ip"].(string)

		// Arm syncconf failure for first two sync attempts (AddClient + retry), but subsequent attempts (restore) succeed
		sshClient.failSyncconfOnce.Store(true)

		_, err = mgr.AddClient(ctx, server, map[string]any{
			"client_name": "Alice",
			"public_key":  keyK2,
		})
		if err == nil {
			t.Fatalf("expected AddClient with K2 to fail due to syncconf failure")
		}

		// Verify remote peer in awg0.conf was restored to K1
		sshClient.mu.RLock()
		conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
		table := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
		sshClient.mu.RUnlock()

		_, peers, err := awg.ParseServerConfig(conf)
		if err != nil || len(peers) != 1 || peers[0].PublicKey != keyK1 {
			t.Fatalf("expected remote peer in awg0.conf to be restored to %s, got: %+v", keyK1, peers)
		}

		clients, err := awg.ParseClientsTable(table)
		if err != nil || len(clients) != 1 || clients[0].ClientID != keyK1 {
			t.Fatalf("expected remote client in clientsTable to be restored to %s, got: %+v", keyK1, clients)
		}

		// Verify DB lease was reverted to K1
		owner, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
		if err != nil || owner != keyK1 {
			t.Fatalf("expected DB lease owner to revert to %s, got: %s (err: %v)", keyK1, owner, err)
		}
	})

	// Scenario A2: Remote restoration fails -> lease stays K2 to prevent zombie IP collision
	t.Run("RemoteRestoreFails_RetainsLeaseK2", func(t *testing.T) {
		mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
		defer cleanup()

		res1, err := mgr.AddClient(ctx, server, map[string]any{
			"client_name": "Alice",
			"public_key":  keyK1,
		})
		if err != nil {
			t.Fatalf("initial AddClient with K1 failed: %v", err)
		}
		ip1, _ := res1["client_ip"].(string)

		// Arm persistent syncconf failure so both the initial commit and remote rollback restore fail
		sshClient.failSyncconf.Store(true)

		_, err = mgr.AddClient(ctx, server, map[string]any{
			"client_name": "Alice",
			"public_key":  keyK2,
		})
		if err == nil {
			t.Fatalf("expected AddClient with K2 to fail due to syncconf failure")
		}

		// Verify DB lease stays K2 to prevent zombie collision because remote state was not restored
		owner, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
		if err != nil || owner != keyK2 {
			t.Fatalf("expected DB lease owner to remain %s when remote restore fails, got: %s (err: %v)", keyK2, owner, err)
		}
	})
}

func TestAWGManager_ReKeying_ConfigRestoreSucceeds_ClientsTableFails_RevertsLeaseToK1(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyK1 = "ERERERERERERERERERERERERERERERERERERERERERE="
		keyK2 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	)

	// 1. Initial provision with K1 succeeds
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("initial AddClient with K1 failed: %v", err)
	}
	ip1, _ := res1["client_ip"].(string)
	if ip1 == "" {
		t.Fatalf("expected valid IP for K1")
	}

	owner1, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || owner1 != keyK1 {
		t.Fatalf("expected initial lease owner %s, got: %s (err: %v)", keyK1, owner1, err)
	}

	// 2. Arm saveClientsTable failure.
	// commitPeerConfigWithCAS (awg0.conf write + syncconf) will succeed for K2,
	// but saveClientsTable will fail.
	// In rollbackAddClient:
	// - restorePreviousPeer calls saveServerConfig(K1) -> succeeds! (configRestored = true)
	// - restorePreviousPeer calls saveClientsTable -> fails!
	// - rollbackAddClient sees configRestored = true and reverts DB lease to K1.
	sshClient.failSaveClientsTable.Store(true)

	_, err = mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK2,
	})
	if err == nil {
		t.Fatalf("expected AddClient with K2 to fail due to clientsTable save failure")
	}

	// 3. Assertion 1: DB lease is reverted back to K1 (previousOwner).
	ownerAfterRollback, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil {
		t.Fatalf("failed to query owner after rollback: %v", err)
	}
	if ownerAfterRollback != keyK1 {
		t.Fatalf("expected DB lease owner to revert back to K1 (%s), got: %s", keyK1, ownerAfterRollback)
	}

	// Also verify remote peer in awg0.conf was restored to K1
	sshClient.mu.RLock()
	conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	sshClient.mu.RUnlock()

	_, peers, err := awg.ParseServerConfig(conf)
	if err != nil || len(peers) != 1 || peers[0].PublicKey != keyK1 {
		t.Fatalf("expected live peer in awg0.conf to be restored to %s, got: %+v", keyK1, peers)
	}

	// 4. Assertion 2: A subsequent allocation for K2 receives a different IP and cannot reuse K1's IP.
	// Reset failure flag so subsequent client provisioning can succeed
	sshClient.failSaveClientsTable.Store(false)

	res2, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Bob",
		"public_key":  keyK2,
	})
	if err != nil {
		t.Fatalf("subsequent AddClient with K2 failed: %v", err)
	}
	ip2, _ := res2["client_ip"].(string)
	if ip2 == "" {
		t.Fatalf("expected valid IP for K2")
	}
	if ip2 == ip1 {
		t.Fatalf("expected K2 to receive a different IP from K1 (%s), but got duplicate IP %s", ip1, ip2)
	}

	// Verify both leases in DB
	ownerK1, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip1)
	if err != nil || ownerK1 != keyK1 {
		t.Fatalf("expected ip1 to be owned by K1 (%s), got: %s", keyK1, ownerK1)
	}
	ownerK2, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip2)
	if err != nil || ownerK2 != keyK2 {
		t.Fatalf("expected ip2 to be owned by K2 (%s), got: %s", keyK2, ownerK2)
	}
}

func TestAWGManager_ObtainClientIP_ZombieDBLease_CollidesWithRemotePeer_ReallocatesNewIP(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyK1 = "ERERERERERERERERERERERERERERERERERERERERERE="
		keyK2 = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI="
	)

	// 1. Initial provision with K1 succeeds on 10.66.66.2
	res1, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("initial AddClient with K1 failed: %v", err)
	}
	ip1, _ := res1["client_ip"].(string)

	// 2. Simulate zombie lease in DB:
	// Manually force an active lease for K2 pointing to K1's IP (10.66.66.2)
	// (e.g. from an uncompensated legacy crash or stale state)
	_, _ = db.ExecContext(ctx, "DELETE FROM awg_ip_allocations WHERE client_id = ?", keyK1)
	_, err = db.ExecContext(ctx,
		"INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at) VALUES (?, ?, ?, 'allocated', datetime('now'), datetime('now'))",
		server.ID, keyK2, ip1,
	)
	if err != nil {
		t.Fatalf("failed to insert zombie lease: %v", err)
	}

	// In awg0.conf, K1 is still the active live peer occupying ip1
	sshClient.mu.RLock()
	conf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	sshClient.mu.RUnlock()
	_, peers, err := awg.ParseServerConfig(conf)
	if err != nil || len(peers) != 1 || peers[0].PublicKey != keyK1 {
		t.Fatalf("expected live peer in awg0.conf to be K1 (%s), got: %+v", keyK1, peers)
	}

	// 3. Now provision K2 as a new client ("Bob").
	// obtainClientIP allocator defense-in-depth:
	// AllocateAWGClientIP finds existing DB lease (ip1).
	// But conflictingRemotePeer detects that ip1 is occupied by K1 on awg0.conf!
	// It releases K2's stale lease, adds ip1 to usedIPs, and re-allocates a new IP.
	res2, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Bob",
		"public_key":  keyK2,
	})
	if err != nil {
		t.Fatalf("AddClient with K2 failed: %v", err)
	}
	ip2, _ := res2["client_ip"].(string)
	if ip2 == "" {
		t.Fatalf("expected valid IP for K2")
	}
	if ip2 == ip1 {
		t.Fatalf("defense-in-depth failed: expected K2 to receive different IP than live peer K1 (%s), got duplicate %s", ip1, ip2)
	}

	// Verify K2 owns ip2 in DB
	ownerK2, err := db.GetAWGIPAllocationOwner(ctx, server.ID, ip2)
	if err != nil || ownerK2 != keyK2 {
		t.Fatalf("expected ip2 to be owned by K2 (%s), got: %s", keyK2, ownerK2)
	}
}

func TestAWGManager_LegacyAdoption_ConflictingRemotePeer_AllocatesFreshIP(t *testing.T) {
	mgr, db, sshClient, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyOther   = "OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO="
		keyClient  = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
		conflictIP = "10.66.66.5"
	)

	// Remote state:
	// clientsTable has Client1 with IP 10.66.66.5 and keyClient
	// awg0.conf has a DIFFERENT peer keyOther occupying 10.66.66.5/32
	// DB has 0 allocations initially
	clientEntry := awg.AWGClient{
		ClientID: keyClient,
		UserData: awg.AWGClientUserData{
			ClientName: "Client1",
			ClientIP:   conflictIP,
			Enabled:    true,
		},
	}
	tableData, err := awg.SerializeClientsTable([]awg.AWGClient{clientEntry})
	if err != nil {
		t.Fatalf("failed to serialize clientsTable: %v", err)
	}

	sshClient.mu.Lock()
	sshClient.files["/opt/amnezia/awg/clientsTable"] = []byte(tableData)
	sshClient.files["/opt/amnezia/awg/awg0.conf"] = []byte(fmt.Sprintf(
		"[Interface]\nPrivateKey = serverPrivKey1234567890123456789012345=\nAddress = 10.66.66.1/24\nListenPort = 51820\nMTU = 1420\nJc = 4\nJmin = 30\nJmax = 80\nS1 = 40\nS2 = 60\nH1 = 12345\nH2 = 67890\n\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n",
		keyOther, conflictIP,
	))
	sshClient.mu.Unlock()

	// Client keyClient attempts adoption / provisioning
	res, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Client1",
		"public_key":  keyClient,
	})
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}

	allocatedIP, _ := res["client_ip"].(string)
	if allocatedIP == "" {
		t.Fatalf("expected non-empty allocated IP")
	}
	if allocatedIP == conflictIP {
		t.Fatalf("expected adoption to be rejected for conflicting IP %s, but got %s", conflictIP, allocatedIP)
	}

	// Verify DB lease was created for keyClient with the fresh IP, NOT the conflicting IP
	ownerOfConflictIP, err := db.GetAWGIPAllocationOwner(ctx, server.ID, conflictIP)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected error querying owner of conflictIP: %v", err)
	}
	if ownerOfConflictIP != "" {
		t.Fatalf("expected conflictIP to have no DB owner, got: %s", ownerOfConflictIP)
	}

	ownerOfAllocated, err := db.GetAWGIPAllocationOwner(ctx, server.ID, allocatedIP)
	if err != nil || ownerOfAllocated != keyClient {
		t.Fatalf("expected fresh IP %s to be allocated to %s, got owner: %s (err: %v)", allocatedIP, keyClient, ownerOfAllocated, err)
	}

	// Verify awg0.conf contains BOTH the existing keyOther peer and the new keyClient peer with allocatedIP
	sshClient.mu.RLock()
	finalConf := string(sshClient.files["/opt/amnezia/awg/awg0.conf"])
	finalTable := string(sshClient.files["/opt/amnezia/awg/clientsTable"])
	sshClient.mu.RUnlock()

	_, peers, err := awg.ParseServerConfig(finalConf)
	if err != nil {
		t.Fatalf("failed to parse final awg0.conf: %v", err)
	}
	foundOther := false
	foundClient := false
	for _, p := range peers {
		if p.PublicKey == keyOther && strings.Contains(p.AllowedIPs, conflictIP) {
			foundOther = true
		}
		if p.PublicKey == keyClient && strings.Contains(p.AllowedIPs, allocatedIP) {
			foundClient = true
		}
	}
	if !foundOther {
		t.Fatalf("expected keyOther peer with %s to be preserved in awg0.conf", conflictIP)
	}
	if !foundClient {
		t.Fatalf("expected keyClient peer with %s to be present in awg0.conf", allocatedIP)
	}

	// Verify clientsTable metadata was updated with the fresh IP
	clients, err := awg.ParseClientsTable(finalTable)
	if err != nil {
		t.Fatalf("failed to parse clientsTable: %v", err)
	}
	foundClientInTable := false
	for _, c := range clients {
		if c.ClientID == keyClient {
			foundClientInTable = true
			if c.UserData.ClientIP != allocatedIP {
				t.Fatalf("expected ClientIP in clientsTable to be updated to %s, got: %s", allocatedIP, c.UserData.ClientIP)
			}
		}
	}
	if !foundClientInTable {
		t.Fatalf("expected keyClient to be present in clientsTable")
	}
}
