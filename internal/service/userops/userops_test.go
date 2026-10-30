package userops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

type mockProtocolManager struct {
	proto       string
	mu          sync.Mutex
	deleted     []string
	toggled     map[string]bool
	added       []string
	returnError bool
}

func newMockProtocolManager(proto string) *mockProtocolManager {
	return &mockProtocolManager{
		proto:   proto,
		toggled: make(map[string]bool),
	}
}

func (m *mockProtocolManager) Protocol() string {
	return m.proto
}

func (m *mockProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}

func (m *mockProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (m *mockProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}

func (m *mockProtocolManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.returnError {
		return nil, errors.New("add client error")
	}
	name, _ := clientParams["name"].(string)
	clientID := fmt.Sprintf("cid-%s", name)
	m.added = append(m.added, clientID)
	return map[string]any{
		"client_id": clientID,
	}, nil
}

func (m *mockProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.returnError {
		return errors.New("remove client error")
	}
	m.deleted = append(m.deleted, clientID)
	return nil
}

func (m *mockProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

func (m *mockProtocolManager) ToggleClient(ctx context.Context, server *models.Server, clientID string, enable bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.returnError {
		return errors.New("toggle client error")
	}
	m.toggled[clientID] = enable
	return nil
}

type mockRegistry struct {
	mu       sync.RWMutex
	managers map[string]manager.ProtocolManager
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{
		managers: make(map[string]manager.ProtocolManager),
	}
}

func (r *mockRegistry) Register(mgr manager.ProtocolManager) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.managers[models.NormalizeProtocol(mgr.Protocol())] = mgr
}

func (r *mockRegistry) Get(proto string) (manager.ProtocolManager, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mgr, ok := r.managers[models.NormalizeProtocol(proto)]
	return mgr, ok
}

func setupTestDB(t *testing.T) (*database.DB, func()) {
	f, err := os.CreateTemp("", "test_userops_*.db")
	if err != nil {
		t.Fatalf("failed to create temp db: %v", err)
	}
	dbPath := f.Name()
	_ = f.Close()

	db, err := database.New(dbPath, "test-secret-key")
	if err != nil {
		_ = os.Remove(dbPath)
		t.Fatalf("failed to open test db: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
	}

	return db, cleanup
}

func TestUserOpsService_DeleteUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID1, err := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "192.168.1.10",
		SSHPort: 22,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	sID2, err := db.CreateServer(ctx, &models.Server{
		Name:    "Server 2",
		Host:    "192.168.1.11",
		SSHPort: 22,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	uID, err := db.CreateUser(ctx, &models.User{
		Username: "alice",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-1",
		UserID:    uID,
		ServerID:  sID1,
		Protocol:  "awg",
		ClientID:  "client-1",
		Name:      "alice_awg1",
		CreatedAt: time.Now().UTC(),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-2",
		UserID:    uID,
		ServerID:  sID1,
		Protocol:  "awg",
		ClientID:  "client-2",
		Name:      "alice_awg2",
		CreatedAt: time.Now().UTC(),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-3",
		UserID:    uID,
		ServerID:  sID2,
		Protocol:  "telemt",
		ClientID:  "client-3",
		Name:      "alice_telemt",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	awgMgr := newMockProtocolManager("awg")
	telemtMgr := newMockProtocolManager("telemt")
	reg.Register(awgMgr)
	reg.Register(telemtMgr)

	svc := NewUserOpsService(db, reg)

	// Non-existent user returns false, nil
	ok, err := svc.DeleteUser(ctx, "non-existent-user-id")
	if err != nil || ok {
		t.Errorf("expected (false, nil) for non-existent user, got (%v, %v)", ok, err)
	}

	// Delete alice
	ok, err = svc.DeleteUser(ctx, uID)
	if err != nil || !ok {
		t.Fatalf("DeleteUser failed: ok=%v, err=%v", ok, err)
	}

	// Verify protocol managers called
	if len(awgMgr.deleted) != 2 {
		t.Errorf("expected 2 awg clients deleted, got %d", len(awgMgr.deleted))
	}
	if len(telemtMgr.deleted) != 1 {
		t.Errorf("expected 1 telemt client deleted, got %d", len(telemtMgr.deleted))
	}

	// Verify DB is clean
	deletedUser, err := db.GetUser(ctx, uID)
	if err != nil {
		t.Fatalf("GetUser error: %v", err)
	}
	if deletedUser != nil {
		t.Error("user should be deleted from DB")
	}

	remainingConns, _ := db.GetConnectionsByUserID(ctx, uID)
	if len(remainingConns) != 0 {
		t.Errorf("expected 0 remaining connections, got %d", len(remainingConns))
	}
}

func TestUserOpsService_ToggleUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "192.168.1.10",
		SSHPort: 22,
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "bob",
		Role:     models.RoleUser,
		Enabled:  true,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-bob-1",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "bob-client-1",
		Name:      "bob_vpn",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	awgMgr := newMockProtocolManager("awg")
	reg.Register(awgMgr)

	svc := NewUserOpsService(db, reg)

	// Non-existent user
	ok, err := svc.ToggleUser(ctx, "non-existent", false)
	if err != nil || ok {
		t.Errorf("expected (false, nil), got (%v, %v)", ok, err)
	}

	// Toggle disable
	ok, err = svc.ToggleUser(ctx, uID, false)
	if err != nil || !ok {
		t.Fatalf("ToggleUser(false) failed: ok=%v, err=%v", ok, err)
	}

	if awgMgr.toggled["bob-client-1"] != false {
		t.Error("expected bob-client-1 toggled to false")
	}

	u, _ := db.GetUser(ctx, uID)
	if u.Enabled {
		t.Error("user in DB should be disabled")
	}

	// Toggle enable
	ok, err = svc.ToggleUser(ctx, uID, true)
	if err != nil || !ok {
		t.Fatalf("ToggleUser(true) failed: ok=%v, err=%v", ok, err)
	}

	if awgMgr.toggled["bob-client-1"] != true {
		t.Error("expected bob-client-1 toggled to true")
	}

	u, _ = db.GetUser(ctx, uID)
	if !u.Enabled {
		t.Error("user in DB should be enabled")
	}
}

func TestUserOpsService_PerformMassOperations_CreatesAndDeletes(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "192.168.1.10",
		SSHPort: 22,
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "charlie",
		Role:     models.RoleUser,
		Enabled:  true,
	})

	reg := newMockRegistry()
	awgMgr := newMockProtocolManager("awg")
	reg.Register(awgMgr)

	svc := NewUserOpsService(db, reg)

	req := MassOperationRequest{
		CreateConns: []ConnectionCreateRequest{
			{
				UserID:   uID,
				ServerID: sID,
				Protocol: "awg",
				Name:     "charlie_vpn_1",
			},
		},
	}

	if err := svc.PerformMassOperations(ctx, req); err != nil {
		t.Fatalf("PerformMassOperations create failed: %v", err)
	}

	conns, _ := db.GetConnectionsByUserID(ctx, uID)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection created, got %d", len(conns))
	}
	if conns[0].ClientID != "cid-charlie_vpn_1" {
		t.Errorf("unexpected client ID: %s", conns[0].ClientID)
	}
}

func TestUserOpsService_ErrorIsolationAndNilDB(t *testing.T) {
	nilSvc := NewUserOpsService(nil, nil)
	ctx := context.Background()

	if _, err := nilSvc.DeleteUser(ctx, "any"); err == nil {
		t.Error("expected error for nil DB in DeleteUser")
	}
	if _, err := nilSvc.ToggleUser(ctx, "any", true); err == nil {
		t.Error("expected error for nil DB in ToggleUser")
	}
	if err := nilSvc.PerformMassOperations(ctx, MassOperationRequest{}); err == nil {
		t.Error("expected error for nil DB in PerformMassOperations")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server Fail",
		Host:    "192.168.1.20",
		SSHPort: 22,
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "failing_user",
		Role:     models.RoleUser,
		Enabled:  true,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-fail-1",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "cid-fail",
		Name:      "fail_vpn",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	failingAwg := newMockProtocolManager("awg")
	failingAwg.returnError = true
	reg.Register(failingAwg)

	svc := NewUserOpsService(db, reg)

	// A failed remote removal must be surfaced, not reported as a successful deletion.
	ok, err := svc.DeleteUser(ctx, uID)
	if err == nil || ok {
		t.Fatalf("DeleteUser should report incomplete revocation: ok=%v, err=%v", ok, err)
	}

	// Verify connection is NOT deleted to prevent state mismatch with remote server
	conns, _ := db.GetConnectionsByUserID(ctx, uID)
	if len(conns) == 0 {
		t.Error("connection should be preserved in DB when remote removal fails")
	}

	// Verify user is preserved while connections remain
	u, _ := db.GetUser(ctx, uID)
	if u == nil {
		t.Error("user should be preserved in DB while remaining connections exist")
	}
}

type panickingUserOpsManager struct {
	proto string
}

func (p *panickingUserOpsManager) Protocol() string { return p.proto }
func (p *panickingUserOpsManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}
func (p *panickingUserOpsManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}
func (p *panickingUserOpsManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}
func (p *panickingUserOpsManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	panic("simulated panic in AddClient")
}
func (p *panickingUserOpsManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	panic("simulated panic in RemoveClient")
}
func (p *panickingUserOpsManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

func TestUserOpsService_PanicRecovery(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server Panic",
		Host:    "192.168.1.30",
		SSHPort: 22,
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "panic_user",
		Role:     models.RoleUser,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-panic-1",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "cid-panic",
		Name:      "panic_vpn",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	reg.Register(&panickingUserOpsManager{proto: "awg"})

	svc := NewUserOpsService(db, reg)

	// Should safely recover from child goroutine panic without crashing
	if err := svc.PerformMassOperations(ctx, MassOperationRequest{
		DeleteUIDs: []string{uID},
	}); err != nil {
		t.Fatalf("PerformMassOperations failed fatally on panic: %v", err)
	}
}

func TestUserOpsService_CreateConnection_RollbackOnDBFailure(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:      "Server 1",
		Host:      "192.168.1.50",
		SSHPort:   22,
		Protocols: map[string]any{"awg": map[string]any{"installed": true}},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "create_fail_user",
		Role:     models.RoleUser,
		Enabled:  true,
	})

	reg := newMockRegistry()
	awgMgr := newMockProtocolManager("awg")
	reg.Register(awgMgr)

	svc := NewUserOpsService(db, reg)

	// Inject DB insert failure trigger on user_connections
	_, err := db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_ops BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated connection insert failure'); END;")
	if err != nil {
		t.Fatalf("failed to create fail trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_ops")
	}()

	err = svc.PerformMassOperations(ctx, MassOperationRequest{
		CreateConns: []ConnectionCreateRequest{
			{
				UserID:   uID,
				ServerID: sID,
				Protocol: "awg",
				Name:     "rollback_conn",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	// Verify client was added remotely, but then rolled back (deleted) due to DB failure
	awgMgr.mu.Lock()
	defer awgMgr.mu.Unlock()
	if len(awgMgr.added) != 1 {
		t.Fatalf("expected 1 remote client added, got %d", len(awgMgr.added))
	}
	addedCID := awgMgr.added[0]
	if len(awgMgr.deleted) != 1 || awgMgr.deleted[0] != addedCID {
		t.Fatalf("expected remote client %s to be rolled back, got deleted: %v", addedCID, awgMgr.deleted)
	}

	// Verify no connection was left in DB
	conns, _ := db.GetConnectionsByUserID(ctx, uID)
	if len(conns) != 0 {
		t.Errorf("expected 0 connections in DB, got %d", len(conns))
	}
}

type mockNonToggleNaiveManager struct {
	proto   string
	deleted []string
	added   []string
	failAdd bool
	mu      sync.Mutex
}

func (m *mockNonToggleNaiveManager) Protocol() string { return m.proto }
func (m *mockNonToggleNaiveManager) Install(context.Context, *models.Server, map[string]any) error {
	return nil
}
func (m *mockNonToggleNaiveManager) Uninstall(context.Context, *models.Server) error { return nil }
func (m *mockNonToggleNaiveManager) GetClients(context.Context, *models.Server) ([]map[string]any, error) {
	return nil, nil
}
func (m *mockNonToggleNaiveManager) AddClient(_ context.Context, _ *models.Server, params map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAdd {
		return nil, errors.New("injected provisioning failure")
	}
	name, _ := params["name"].(string)
	m.added = append(m.added, name)
	return map[string]any{"username": name, "password": "replacement-secret"}, nil
}
func (m *mockNonToggleNaiveManager) RemoveClient(_ context.Context, _ *models.Server, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, clientID)
	return nil
}
func (m *mockNonToggleNaiveManager) GetClientConfig(context.Context, *models.Server, string) (string, error) {
	return "", nil
}

func (m *mockNonToggleNaiveManager) ProbeBackendCredential(_ context.Context, _ *models.Server, candidate *models.BackendTunnel) error {
	var p models.NaiveProxyParams
	if err := json.Unmarshal(candidate.ProtocolParams, &p); err != nil {
		return err
	}
	if p.Username == "" || p.Password != "replacement-secret" {
		return errors.New("replacement credentials not authenticated")
	}
	return nil
}

func TestUserOps_ToggleUser_PreservesSharedBackendCredential(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "naive-srv-uops-tog",
		Host:    "10.0.0.1",
		SSHPort: 22,
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{
		Username: "u-ops-tog",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	sharedCred := "shared-ops-toggle-cred"

	naiveParams, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "tog.example.com",
		Username: sharedCred,
		Password: "password",
	})
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:       sID,
		InterfaceName:  "naive-be-ops-tog",
		Endpoint:       "10.0.0.1:443",
		Protocol:       models.ProtocolNaive,
		ProtocolParams: naiveParams,
		Enabled:        true,
		Status:         models.TunnelStatusActive,
		StateVersion:   1,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	connID := "c-ops-tog"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        connID,
		UserID:    uID,
		ServerID:  sID,
		Protocol:  models.ProtocolNaive,
		ClientID:  sharedCred,
		Name:      "Shared Ops Conn",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}
	_ = db.RecordPeerLifecycle(ctx, sID, models.ProtocolNaive, sharedCred, "Shared Ops Conn", uID, "active")

	mgr := &mockNonToggleNaiveManager{proto: "naive"}
	reg := newMockRegistry()
	reg.Register(mgr)
	svc := New(db, reg)

	ok, err := svc.ToggleUser(ctx, uID, false)
	if err == nil || ok {
		t.Fatalf("shared credential operation must fail: ok=%v err=%v", ok, err)
	}
	if c, err := db.GetConnection(ctx, connID); err != nil || c == nil {
		t.Fatalf("connection must remain: %+v %v", c, err)
	}
	if u, err := db.GetUser(ctx, uID); err != nil || u == nil || !u.Enabled {
		t.Fatalf("user must remain enabled: %+v %v", u, err)
	}
	if tunnels, err := db.GetBackendTunnelsByServerID(ctx, sID); err != nil || len(tunnels) != 1 || !tunnels[0].Enabled {
		t.Fatalf("backend must remain: %+v %v", tunnels, err)
	}
}

func TestUserOps_RotatesSharedBackendCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		delete  bool
		failAdd bool
	}{
		{name: "delete", delete: true},
		{name: "disable"},
		{name: "provisioning failure on delete", delete: true, failAdd: true},
		{name: "provisioning failure on disable", failAdd: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := t.Context()
			sid, err := db.CreateServer(ctx, &models.Server{Name: "backend", Host: "127.0.0.1", SSHPort: 22})
			if err != nil {
				t.Fatal(err)
			}
			uid, err := db.CreateUser(ctx, &models.User{Username: "shared", Role: models.RoleUser, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			old := "shared-credential"
			params, err := json.Marshal(models.NaiveProxyParams{Username: old, Password: "old-password", Domain: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID: sid, InterfaceName: "naive-backend", Endpoint: "127.0.0.1:443",
				Protocol: models.ProtocolNaive, ProtocolParams: params, Enabled: true, Status: models.TunnelStatusActive,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.CreateConnection(ctx, &models.UserConnection{
				ID: "shared-conn", UserID: uid, ServerID: sid, Protocol: models.ProtocolNaive, ClientID: old,
			})
			if err != nil {
				t.Fatal(err)
			}
			vpnSvc, err := vpn.NewVPNService(db, &models.VPNConfig{EnableMultiProtocolBackends: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if tun, err := vpnSvc.GetTunnel(sid); err == nil {
					if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
						_ = dev.Close()
					}
				}
			})
			mgr := &mockNonToggleNaiveManager{proto: models.ProtocolNaive, failAdd: tc.failAdd}
			reg := newMockRegistry()
			reg.Register(mgr)
			svc := New(db, reg)
			svc.SetVPNService(vpnSvc)
			var ok bool
			if tc.delete {
				ok, err = svc.DeleteUser(ctx, uid)
			} else {
				ok, err = svc.ToggleUser(ctx, uid, false)
			}
			if tc.failAdd {
				if err == nil || ok {
					t.Fatalf("expected provisioning failure: ok=%v err=%v", ok, err)
				}
			} else if err != nil || !ok {
				t.Fatalf("withdraw user: ok=%v err=%v", ok, err)
			}
			mgr.mu.Lock()
			added, removed := append([]string{}, mgr.added...), append([]string{}, mgr.deleted...)
			mgr.mu.Unlock()
			if tc.failAdd {
				if len(added) != 0 || len(removed) != 0 {
					t.Fatalf("mutated remote on failed provision: %v %v", added, removed)
				}
			} else if len(added) != 1 || len(removed) != 1 || removed[0] != old {
				t.Fatalf("rotation/revocation missing: added=%v removed=%v", added, removed)
			}
			row, err := db.GetBackendTunnelByServerID(ctx, sid)
			if err != nil || row == nil {
				t.Fatalf("backend row: %+v %v", row, err)
			}
			live, liveErr := vpnSvc.GetTunnel(sid)
			if liveErr != nil {
				t.Fatal(liveErr)
			}
			want := old
			if !tc.failAdd {
				want = added[0]
			}
			if !row.Enabled || row.Status != models.TunnelStatusActive ||
				vpn.ExtractClientIDFromProtocolParams(row.Protocol, row.ProtocolParams) != want ||
				vpn.ExtractClientIDFromProtocolParams(live.Protocol, live.ProtocolParams) != want {
				t.Fatalf("backend did not retain expected credential %q: row=%+v live=%+v", want, row, live)
			}
			conn, err := db.GetConnection(ctx, "shared-conn")
			if err != nil || (conn != nil) != tc.failAdd {
				t.Fatalf("connection state: %+v %v", conn, err)
			}
			user, err := db.GetUser(ctx, uid)
			if err != nil {
				t.Fatal(err)
			}
			if tc.delete {
				if (user != nil) != tc.failAdd {
					t.Fatalf("user deletion state: %+v", user)
				}
			} else if user == nil || user.Enabled != tc.failAdd {
				t.Fatalf("user disable state: %+v", user)
			}
		})
	}
}

func TestPerformMassOperations_ReportsRemoteRevocationFailure(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()
	sid, err := db.CreateServer(ctx, &models.Server{Name: "failed-removal", Host: "127.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	uid, err := db.CreateUser(ctx, &models.User{Username: "failed-removal", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "failed-conn", UserID: uid, ServerID: sid, Protocol: models.ProtocolAWG, ClientID: "failed-client",
	}); err != nil {
		t.Fatal(err)
	}
	mgr := newMockProtocolManager(models.ProtocolAWG)
	mgr.returnError = true
	reg := newMockRegistry()
	reg.Register(mgr)
	err = New(db, reg).PerformMassOperations(ctx, MassOperationRequest{DeleteUIDs: []string{uid}})
	if err == nil || !strings.Contains(err.Error(), "remove remote client failed-client: remove client error") {
		t.Fatalf("expected remote removal error in batch result, got %v", err)
	}
	if c, err := db.GetConnection(ctx, "failed-conn"); err != nil || c == nil {
		t.Fatalf("failed remote removal lost retryable row: %v %v", c, err)
	}
}

func TestUserOps_SharedCredentialDoesNotDisconnectOtherUser(t *testing.T) {
	for _, toggle := range []bool{false, true} {
		t.Run(fmt.Sprintf("toggle_%t", toggle), func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := t.Context()
			sid, err := db.CreateServer(ctx, &models.Server{Name: "two-users", Host: "127.0.0.1", SSHPort: 22})
			if err != nil {
				t.Fatal(err)
			}
			var aliceID string
			for _, name := range []string{"alice", "bob"} {
				uid, err := db.CreateUser(ctx, &models.User{Username: name, Enabled: true})
				if err != nil {
					t.Fatal(err)
				}
				if name == "alice" {
					aliceID = uid
				}
				if _, err := db.CreateConnection(ctx, &models.UserConnection{
					ID: name, UserID: uid, ServerID: sid, Protocol: models.ProtocolNaive, ClientID: "same-login",
				}); err != nil {
					t.Fatal(err)
				}
			}
			mgr := &mockNonToggleNaiveManager{proto: models.ProtocolNaive}
			reg := newMockRegistry()
			reg.Register(mgr)
			svc := New(db, reg)
			if toggle {
				_, err = svc.ToggleUser(ctx, aliceID, false)
			} else {
				_, err = svc.DeleteUser(ctx, aliceID)
			}
			if !errors.Is(err, database.ErrSharedUserCredential) {
				t.Fatalf("expected shared credential refusal: %v", err)
			}
			if len(mgr.deleted) != 0 {
				t.Fatalf("removed Bob's credential: %v", mgr.deleted)
			}
			for _, id := range []string{"alice", "bob"} {
				if c, err := db.GetConnection(ctx, id); err != nil || c == nil {
					t.Fatalf("%s connection lost: %v %v", id, c, err)
				}
			}
		})
	}
}

func TestUserOps_DeleteUser_PreservesSharedBackendCredential(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "naive-srv-uops-del",
		Host:    "10.0.0.1",
		SSHPort: 22,
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{
		Username: "u-ops-del",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	sharedCred := "shared-ops-del-cred"

	naiveParams, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "del.example.com",
		Username: sharedCred,
		Password: "password",
	})
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:       sID,
		InterfaceName:  "naive-be-ops-del",
		Endpoint:       "10.0.0.1:443",
		Protocol:       models.ProtocolNaive,
		ProtocolParams: naiveParams,
		Enabled:        true,
		Status:         models.TunnelStatusActive,
		StateVersion:   1,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	connID := "c-ops-del"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        connID,
		UserID:    uID,
		ServerID:  sID,
		Protocol:  models.ProtocolNaive,
		ClientID:  sharedCred,
		Name:      "Shared Ops Del Conn",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}
	_ = db.RecordPeerLifecycle(ctx, sID, models.ProtocolNaive, sharedCred, "Shared Ops Del Conn", uID, "active")

	mgr := &mockNonToggleNaiveManager{proto: "naive"}
	reg := newMockRegistry()
	reg.Register(mgr)
	svc := New(db, reg)

	ok, err := svc.DeleteUser(ctx, uID)
	if err == nil || ok {
		t.Fatalf("shared credential operation must fail: ok=%v err=%v", ok, err)
	}
	if c, err := db.GetConnection(ctx, connID); err != nil || c == nil {
		t.Fatalf("connection must remain: %+v %v", c, err)
	}
	if u, err := db.GetUser(ctx, uID); err != nil || u == nil || !u.Enabled {
		t.Fatalf("user must remain enabled: %+v %v", u, err)
	}
	if tunnels, err := db.GetBackendTunnelsByServerID(ctx, sID); err != nil || len(tunnels) != 1 || !tunnels[0].Enabled {
		t.Fatalf("backend must remain: %+v %v", tunnels, err)
	}
}
