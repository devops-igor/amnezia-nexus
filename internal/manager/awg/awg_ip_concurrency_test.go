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
	idx := strings.Index(cmd, "/tmp/amnezia_awg_server_")
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
	mu                     sync.RWMutex
	files                  map[string][]byte
	failSaveServerConfig   atomic.Bool
	failSyncconf           atomic.Bool
	failSyncconfOnce       atomic.Bool
	syncconfCount          atomic.Int32
	failSaveClientsTable   atomic.Bool
	failEnsureNAT          atomic.Bool
	failOnSecondSaveConfig atomic.Bool
	saveConfigCount        atomic.Int32
	driftCount             atomic.Int32
	host                   string
	port                   int
	serverID               *int64
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
	if strings.Contains(cmd, "amnezia_awg_server_") && (strings.Contains(cmd, "mkdir") || strings.Contains(cmd, "flock")) {
		key := extractLockKey(cmd)
		ch := getMockRemoteLock(key)
		select {
		case <-ctx.Done():
			return "", "lock acquisition cancelled", 1, ctx.Err()
		case <-ch:
			return "OK", "", 0, nil
		}
	}

	if strings.Contains(cmd, "amnezia_awg_server_") && (strings.Contains(cmd, "rm -rf") || strings.Contains(cmd, "rmdir") || strings.Contains(cmd, "unlock")) {
		key := extractLockKey(cmd)
		ch := getMockRemoteLock(key)
		select {
		case ch <- struct{}{}:
		default:
		}
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

	// Provision subsequent client — MUST NOT receive the zombie IP
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
	mgr, db, _, server, cleanup := setupAWGManagerWithDB(t)
	defer cleanup()

	ctx := context.Background()

	const (
		keyK1 = "pubKeyK1================================"
		keyK2 = "pubKeyK2================================"
	)

	// 1. Initial provision with key K1
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

	allocated1, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated1) != 1 || allocated1[0] != ip1 {
		t.Fatalf("expected 1 DB allocation for K1 (%s), got: %+v", ip1, allocated1)
	}

	// 2. Re-key Alice to key K2
	res2, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK2,
	})
	if err != nil {
		t.Fatalf("re-key AddClient with K2 failed: %v", err)
	}
	ip2, _ := res2["client_ip"].(string)
	if ip2 != ip1 {
		t.Fatalf("expected re-keyed client to retain original IP %s, got: %s", ip1, ip2)
	}

	allocated2, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated2) != 1 || allocated2[0] != ip1 {
		t.Fatalf("expected DB allocations count to remain 1 with IP %s, got: %+v", ip1, allocated2)
	}

	// 3. Re-key Alice back to key K1
	res3, err := mgr.AddClient(ctx, server, map[string]any{
		"client_name": "Alice",
		"public_key":  keyK1,
	})
	if err != nil {
		t.Fatalf("re-key AddClient back to K1 failed: %v", err)
	}
	ip3, _ := res3["client_ip"].(string)
	if ip3 != ip1 {
		t.Fatalf("expected re-keyed client back to K1 to retain original IP %s, got: %s", ip1, ip3)
	}

	allocated3, err := db.GetAllocatedAWGIPs(ctx, server.ID)
	if err != nil || len(allocated3) != 1 || allocated3[0] != ip1 {
		t.Fatalf("expected DB allocations count to remain 1 with IP %s, got: %+v", ip1, allocated3)
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
