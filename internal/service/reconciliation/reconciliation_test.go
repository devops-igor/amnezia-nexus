package reconciliation

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/supervisor"
)

type mockStatusProtocolManager struct {
	proto           string
	containerExists bool
	returnError     bool
}

func (m *mockStatusProtocolManager) Protocol() string {
	return m.proto
}

func (m *mockStatusProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}

func (m *mockStatusProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (m *mockStatusProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}

func (m *mockStatusProtocolManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *mockStatusProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}

func (m *mockStatusProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

func (m *mockStatusProtocolManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	if m.returnError {
		return nil, errors.New("remote check error")
	}
	return map[string]any{
		"container_exists": m.containerExists,
	}, nil
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
	f, err := os.CreateTemp("", "test_reconciliation_*.db")
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

func TestReconciler_Phase1_DBOnlyCleanup(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "user1",
		Role:     models.RoleUser,
	})

	// AWG connection (valid)
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-awg",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "cid-awg",
		Name:      "u1_awg",
		CreatedAt: time.Now().UTC(),
	})

	// TeleMT connection (orphaned because telemt is not in server.Protocols)
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-telemt",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "telemt",
		ClientID:  "cid-telemt",
		Name:      "u1_telemt",
		CreatedAt: time.Now().UTC(),
	})

	r := New(db, nil)

	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	conns, _ := db.GetConnectionsByServerID(ctx, sID)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection remaining, got %d", len(conns))
	}
	if conns[0].Protocol != "awg" {
		t.Errorf("expected remaining connection protocol awg, got %s", conns[0].Protocol)
	}
}

func TestReconciler_Phase2_SSHBasedCleanup(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg":    map[string]any{"port": 55424},
			"telemt": map[string]any{"port": 443},
		},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "user2",
		Role:     models.RoleUser,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-awg",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "cid-awg",
		Name:      "u2_awg",
		CreatedAt: time.Now().UTC(),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-telemt",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "telemt",
		ClientID:  "cid-telemt",
		Name:      "u2_telemt",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	// AWG exists
	reg.Register(&mockStatusProtocolManager{proto: "awg", containerExists: true})
	// TeleMT container is missing on host!
	reg.Register(&mockStatusProtocolManager{proto: "telemt", containerExists: false})

	r := New(db, reg)

	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	// TeleMT connection should be removed
	conns, _ := db.GetConnectionsByServerID(ctx, sID)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection remaining, got %d", len(conns))
	}
	if conns[0].Protocol != "awg" {
		t.Errorf("expected awg connection, got %s", conns[0].Protocol)
	}

	// Server.Protocols should no longer contain telemt
	srv, _ := db.GetServer(ctx, sID)
	if _, ok := srv.Protocols["telemt"]; ok {
		t.Error("telemt should have been removed from server.Protocols")
	}
	if _, ok := srv.Protocols["awg"]; !ok {
		t.Error("awg should still be in server.Protocols")
	}
}

func TestReconciler_ErrorIsolationAndEdgeCases(t *testing.T) {
	ctx := context.Background()

	// Nil DB returns error
	nilR := New(nil, nil)
	if err := nilR.CleanupStaleProtocols(ctx); err == nil {
		t.Error("expected error for nil DB")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	sID1, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1 (Fails)",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	})

	sID2, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 2 (OK)",
		Host:    "10.0.0.2",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "user3",
		Role:     models.RoleUser,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-s1",
		UserID:    uID,
		ServerID:  sID1,
		Protocol:  "awg",
		ClientID:  "cid-1",
		Name:      "u3_s1",
		CreatedAt: time.Now().UTC(),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-s2",
		UserID:    uID,
		ServerID:  sID2,
		Protocol:  "awg",
		ClientID:  "cid-2",
		Name:      "u3_s2",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	// Manager that errors
	reg.Register(&mockStatusProtocolManager{proto: "awg", returnError: true})

	r := New(db, reg)

	// Should not crash or return fatal error
	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Errorf("unexpected fatal error during reconciliation with failing server: %v", err)
	}

	// Connections must NOT be deleted when remote check errors
	connsS1, _ := db.GetConnectionsByServerID(ctx, sID1)
	if len(connsS1) != 1 {
		t.Errorf("expected connection on sID1 to be preserved on error, got %d", len(connsS1))
	}
	srv1, _ := db.GetServer(ctx, sID1)
	if _, ok := srv1.Protocols["awg"]; !ok {
		t.Errorf("expected awg protocol to be preserved on sID1 on error")
	}
}

func TestReconciler_LegacyAWG2Preserved(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Legacy AWG2 Server",
		Host:    "10.0.0.5",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424, "container": "amnezia-awg2"},
		},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "legacy_user",
		Role:     models.RoleUser,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-awg2",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "cid-awg2",
		Name:      "u_awg2",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	// Manager reports container exists (as amnezia-awg2)
	reg.Register(&mockStatusProtocolManager{proto: "awg", containerExists: true})

	r := New(db, reg)
	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	conns, _ := db.GetConnectionsByServerID(ctx, sID)
	if len(conns) != 1 {
		t.Fatalf("expected connection to be preserved for amnezia-awg2 server, got %d", len(conns))
	}
	srv, _ := db.GetServer(ctx, sID)
	if _, ok := srv.Protocols["awg"]; !ok {
		t.Errorf("expected awg protocol to be preserved for amnezia-awg2 server")
	}
}

type mockNonCheckerManager struct {
	proto string
}

func (m *mockNonCheckerManager) Protocol() string { return m.proto }
func (m *mockNonCheckerManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}
func (m *mockNonCheckerManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}
func (m *mockNonCheckerManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}
func (m *mockNonCheckerManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}
func (m *mockNonCheckerManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}
func (m *mockNonCheckerManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

type mockStatusErrorManager struct {
	proto string
}

func (m *mockStatusErrorManager) Protocol() string { return m.proto }
func (m *mockStatusErrorManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}
func (m *mockStatusErrorManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}
func (m *mockStatusErrorManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}
func (m *mockStatusErrorManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}
func (m *mockStatusErrorManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}
func (m *mockStatusErrorManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}
func (m *mockStatusErrorManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{
		"error":            "daemon crashed",
		"container_exists": false,
	}, nil
}

func TestReconciler_AdditionalBranches(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Server with empty protocols
	sIDEmpty, _ := db.CreateServer(ctx, &models.Server{
		Name:      "Empty Server",
		Host:      "10.0.0.10",
		SSHPort:   22,
		Protocols: map[string]any{},
	})

	// 2. Server with non-checker protocol and unregistered protocol and status error
	sIDMulti, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Multi Server",
		Host:    "10.0.0.11",
		SSHPort: 22,
		Protocols: map[string]any{
			"unregistered": map[string]any{"port": 1111},
			"nonchecker":   map[string]any{"port": 2222},
			"statuserror":  map[string]any{"port": 3333},
		},
	})

	reg := newMockRegistry()
	reg.Register(&mockNonCheckerManager{proto: "nonchecker"})
	reg.Register(&mockStatusErrorManager{proto: "statuserror"})

	r := New(db, reg)
	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	srv, _ := db.GetServer(ctx, sIDMulti)
	if len(srv.Protocols) != 3 {
		t.Errorf("expected all 3 protocols preserved, got %d", len(srv.Protocols))
	}
	_ = sIDEmpty
}

func TestReconciler_DNSTeleMTErrorsPreserveProtocols(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "DNS and TeleMT Server",
		Host:    "10.0.0.50",
		SSHPort: 22,
		Protocols: map[string]any{
			"dns":    map[string]any{"port": 53},
			"telemt": map[string]any{"port": 443},
		},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "dual_user",
		Role:     models.RoleUser,
	})

	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-dns",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "dns",
		ClientID:  "cid-dns",
		Name:      "u_dns",
		CreatedAt: time.Now().UTC(),
	})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-telemt",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "telemt",
		ClientID:  "cid-telemt",
		Name:      "u_telemt",
		CreatedAt: time.Now().UTC(),
	})

	reg := newMockRegistry()
	// Both managers report transient errors (e.g. docker daemon stopped / CLI error)
	reg.Register(&mockStatusProtocolManager{proto: "dns", returnError: true})
	reg.Register(&mockStatusProtocolManager{proto: "telemt", returnError: true})

	r := New(db, reg)
	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	// Connections must be preserved
	conns, _ := db.GetConnectionsByServerID(ctx, sID)
	if len(conns) != 2 {
		t.Fatalf("expected 2 connections preserved for DNS and TeleMT, got %d", len(conns))
	}

	// Protocols must be preserved
	srv, _ := db.GetServer(ctx, sID)
	if _, ok := srv.Protocols["dns"]; !ok {
		t.Errorf("expected dns protocol to be preserved on error")
	}
	if _, ok := srv.Protocols["telemt"]; !ok {
		t.Errorf("expected telemt protocol to be preserved on error")
	}
}

type mockZombiePeerProtocolManager struct {
	proto          string
	clients        []map[string]any
	deleted        []string
	getClientsErr  bool
	removeErr      bool
	getClientsHook func()
	mu             sync.Mutex
}

func (m *mockZombiePeerProtocolManager) Protocol() string {
	return m.proto
}
func (m *mockZombiePeerProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}
func (m *mockZombiePeerProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}
func (m *mockZombiePeerProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getClientsHook != nil {
		m.getClientsHook()
	}
	if m.getClientsErr {
		return nil, errors.New("remote get clients error")
	}
	return m.clients, nil
}
func (m *mockZombiePeerProtocolManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}
func (m *mockZombiePeerProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeErr {
		return errors.New("remote remove client error")
	}
	m.deleted = append(m.deleted, clientID)
	return nil
}
func (m *mockZombiePeerProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}
func (m *mockZombiePeerProtocolManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{"container_exists": true}, nil
}

func TestReconciler_CleanupZombiePeers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	})

	uID, _ := db.CreateUser(ctx, &models.User{
		Username: "user1",
		Role:     models.RoleUser,
	})

	// Valid DB connection
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-valid-1",
		UserID:    uID,
		ServerID:  sID,
		Protocol:  "awg",
		ClientID:  "peer-valid-db",
		Name:      "Valid DB Client",
		CreatedAt: time.Now().UTC(),
	})

	// Track peer-zombie-1 as known failed lifecycle operation
	_ = db.RecordPeerLifecycle(ctx, sID, "awg", "peer-zombie-1", "Zombie One", "", "failed")

	// Track peer-zombie-2 as stale pending creation (> 5 minutes ago)
	staleTime := time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
	_, _ = db.ExecContext(ctx, "INSERT INTO peer_lifecycle (server_id, protocol, client_id, name, user_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		sID, "awg", "peer-zombie-2", "Zombie Two", "", "pending", staleTime, staleTime)

	remoteClients := []map[string]any{
		{"clientId": "peer-valid-db", "name": "Valid DB Client"},
		{"clientId": "peer-zombie-1", "name": "Zombie One"},
		{"clientId": "peer-zombie-2", "userData": map[string]any{"clientName": "Zombie Two"}},
		{"clientId": "peer-portal-data", "name": "Portal Data Plane"},
		{"clientId": "peer-portal-probe", "userData": map[string]any{"clientName": "Portal Health Probe"}},
		{"clientId": "peer-health-probe", "userData": map[string]any{"clientName": "Health Probe"}},
		{"clientId": "peer-external", "userData": map[string]any{"clientName": "External Peer", "externalClient": true}},
		{"clientId": "peer-external-top", "clientName": "External Peer Top", "externalClient": true},
	}

	mgr := &mockZombiePeerProtocolManager{
		proto:   "awg",
		clients: remoteClients,
	}

	reg := newMockRegistry()
	reg.Register(mgr)

	r := New(db, reg)

	if err := r.CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers failed: %v", err)
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	expectedDeleted := map[string]bool{
		"peer-zombie-1": true,
		"peer-zombie-2": true,
	}

	if len(mgr.deleted) != len(expectedDeleted) {
		t.Fatalf("expected exactly %d deleted peers, got %d: %v", len(expectedDeleted), len(mgr.deleted), mgr.deleted)
	}

	for _, id := range mgr.deleted {
		if !expectedDeleted[id] {
			t.Errorf("unexpected peer was deleted: %s", id)
		}
	}
}

func TestReconciler_CleanupZombiePeers_ToleratesErrors(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg":    map[string]any{"port": 55424},
			"telemt": map[string]any{"port": 443},
		},
	})

	// AWG manager fails to GetClients
	awgMgr := &mockZombiePeerProtocolManager{
		proto:         "awg",
		getClientsErr: true,
	}

	// TeleMT manager has two zombie peers; one fails on RemoveClient
	_ = db.RecordPeerLifecycle(ctx, sID, "telemt", "zombie-telemt-1", "ZT1", "", "failed")
	telemtMgr := &mockZombiePeerProtocolManager{
		proto: "telemt",
		clients: []map[string]any{
			{"clientId": "zombie-telemt-1", "name": "ZT1"},
		},
		removeErr: true,
	}

	reg := newMockRegistry()
	reg.Register(awgMgr)
	reg.Register(telemtMgr)

	r := New(db, reg)

	// Must tolerate remote errors gracefully without returning fatal error
	if err := r.CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers should tolerate remote errors, got: %v", err)
	}

	srv, err := db.GetServer(ctx, sID)
	if err != nil || srv == nil {
		t.Fatalf("server should still exist after error-tolerant pass")
	}
}

func TestReconciler_CleanupStaleProtocols_ExecutesPhase3(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	_, _ = db.CreateServer(ctx, &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	})

	_ = db.RecordPeerLifecycle(ctx, 1, "awg", "peer-zombie-phase3", "Zombie In Phase 3", "", "failed")
	remoteClients := []map[string]any{
		{"clientId": "peer-zombie-phase3", "name": "Zombie In Phase 3"},
	}

	mgr := &mockZombiePeerProtocolManager{
		proto:   "awg",
		clients: remoteClients,
	}

	reg := newMockRegistry()
	reg.Register(mgr)

	r := New(db, reg)

	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if len(mgr.deleted) != 1 || mgr.deleted[0] != "peer-zombie-phase3" {
		t.Fatalf("expected peer-zombie-phase3 to be removed during Phase 3, got: %v", mgr.deleted)
	}
}

func TestReconciler_CleanupZombiePeers_NilDBAndClosedDB(t *testing.T) {
	ctx := context.Background()

	nilR := New(nil, nil)
	if err := nilR.CleanupZombiePeers(ctx); err == nil {
		t.Error("expected error for nil DB in CleanupZombiePeers")
	}

	db, cleanup := setupTestDB(t)
	r := New(db, nil)
	cleanup() // close DB

	if err := r.CleanupZombiePeers(ctx); err == nil {
		t.Error("expected error when DB is closed in CleanupZombiePeers")
	}
}

func TestReconciler_CleanupZombiePeers_PreservesUnassignedConnections(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	srv := &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg":    map[string]any{"port": 55424},
			"telemt": map[string]any{"port": 443},
		},
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Pre-upgrade legacy untracked unassigned AWG connection (neither in user_connections nor in peer_lifecycle)
	legacyAWG := "awg-legacy-unassigned-1"

	// 2. Pre-upgrade legacy untracked unassigned TeleMT connection (neither in user_connections nor in peer_lifecycle)
	legacyTeleMT := "telemt-legacy-unassigned-1"

	// 3. Known failed lifecycle peer (status: "failed") that MUST be purged
	failedAWG := "awg-failed-peer-2"
	if err := db.RecordPeerLifecycle(ctx, sID, "awg", failedAWG, "Failed AWG", "", "failed"); err != nil {
		t.Fatalf("failed to record failed AWG peer: %v", err)
	}

	// 4. Stale pending lifecycle peer (status: "pending", created > 5 minutes ago) that MUST be purged
	stalePendingAWG := "awg-stale-pending-peer-3"
	staleTime := time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
	_, err = db.ExecContext(ctx, "INSERT INTO peer_lifecycle (server_id, protocol, client_id, name, user_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		sID, "awg", stalePendingAWG, "Stale Pending AWG", "", "pending", staleTime, staleTime)
	if err != nil {
		t.Fatalf("failed to insert stale pending peer: %v", err)
	}

	// 5. Recent pending lifecycle peer (status: "pending", created < 5m ago) that MUST survive
	recentPendingAWG := "awg-recent-pending-peer-4"
	if err := db.RecordPeerLifecycle(ctx, sID, "awg", recentPendingAWG, "Recent Pending AWG", "", "pending"); err != nil {
		t.Fatalf("failed to record recent pending peer: %v", err)
	}

	// 6. Known failed TeleMT peer (status: "failed") that MUST be purged
	failedTeleMT := "telemt-failed-peer-2"
	if err := db.RecordPeerLifecycle(ctx, sID, "telemt", failedTeleMT, "Failed TeleMT", "", "failed"); err != nil {
		t.Fatalf("failed to record failed TeleMT peer: %v", err)
	}

	// Remote peers reported by managers (older than 2-minute creation grace period to verify lifecycle-based decisions)
	oldTimestamp := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)

	awgMgr := &mockZombiePeerProtocolManager{
		proto: "awg",
		clients: []map[string]any{
			{"clientId": legacyAWG, "clientName": "Legacy Unassigned AWG", "creationDate": oldTimestamp},
			{"clientId": failedAWG, "clientName": "Failed AWG", "creationDate": oldTimestamp},
			{"clientId": stalePendingAWG, "clientName": "Stale Pending AWG", "creationDate": oldTimestamp},
			{"clientId": recentPendingAWG, "clientName": "Recent Pending AWG", "creationDate": time.Now().Format(time.RFC3339)},
		},
	}

	telemtMgr := &mockZombiePeerProtocolManager{
		proto: "telemt",
		clients: []map[string]any{
			{"clientId": legacyTeleMT, "clientName": "Legacy Unassigned TeleMT", "creationDate": oldTimestamp},
			{"clientId": failedTeleMT, "clientName": "Failed TeleMT", "creationDate": oldTimestamp},
		},
	}

	reg := newMockRegistry()
	reg.Register(awgMgr)
	reg.Register(telemtMgr)

	r := New(db, reg)

	// Execute startup reconciliation
	if err := r.CleanupStaleProtocols(ctx); err != nil {
		t.Fatalf("CleanupStaleProtocols failed: %v", err)
	}

	awgMgr.mu.Lock()
	deletedAWG := append([]string(nil), awgMgr.deleted...)
	awgMgr.mu.Unlock()

	telemtMgr.mu.Lock()
	deletedTeleMT := append([]string(nil), telemtMgr.deleted...)
	telemtMgr.mu.Unlock()

	// Assert:
	// - Legacy unassigned AWG survives and was adopted into peer_lifecycle as active
	// - Failed AWG was deleted
	// - Stale pending AWG was deleted
	// - Recent pending AWG survives
	expectedDeletedAWG := map[string]bool{
		failedAWG:       true,
		stalePendingAWG: true,
	}
	if len(deletedAWG) != len(expectedDeletedAWG) {
		t.Fatalf("expected exactly %d deleted AWG peers, got %d: %v", len(expectedDeletedAWG), len(deletedAWG), deletedAWG)
	}
	for _, id := range deletedAWG {
		if !expectedDeletedAWG[id] {
			t.Errorf("unexpected AWG peer was deleted: %s", id)
		}
	}

	// Assert:
	// - Legacy unassigned TeleMT survives and was adopted into peer_lifecycle as active
	// - Failed TeleMT was deleted
	if len(deletedTeleMT) != 1 || deletedTeleMT[0] != failedTeleMT {
		t.Fatalf("expected only failed TeleMT peer %s to be deleted, got: %v", failedTeleMT, deletedTeleMT)
	}

	// Verify adoption in peer_lifecycle
	activeAWGPeers, err := db.GetActivePeerIDs(ctx, sID, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs AWG failed: %v", err)
	}
	if !activeAWGPeers[legacyAWG] {
		t.Errorf("expected legacy AWG peer %s to be adopted into peer_lifecycle with active status", legacyAWG)
	}
	if !activeAWGPeers[recentPendingAWG] {
		t.Errorf("expected recent pending AWG peer %s to remain active in peer_lifecycle", recentPendingAWG)
	}

	activeTeleMTPeers, err := db.GetActivePeerIDs(ctx, sID, "telemt")
	if err != nil {
		t.Fatalf("GetActivePeerIDs TeleMT failed: %v", err)
	}
	if !activeTeleMTPeers[legacyTeleMT] {
		t.Errorf("expected legacy TeleMT peer %s to be adopted into peer_lifecycle with active status", legacyTeleMT)
	}
}

func TestReconciler_BackgroundService_StartAndStop(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &models.Server{
		Name:    "Server 1",
		Host:    "10.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"awg": map[string]any{"port": 55424},
		},
	}
	if _, err := db.CreateServer(ctx, srv); err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	callCount := 0
	var mu sync.Mutex
	awgMgr := &mockZombiePeerProtocolManager{
		proto:   "awg",
		clients: []map[string]any{},
	}
	awgMgr.getClientsHook = func() {
		mu.Lock()
		defer mu.Unlock()
		callCount++
	}

	reg := newMockRegistry()
	reg.Register(awgMgr)

	r := New(db, reg,
		WithBootDelay(10*time.Millisecond),
		WithInterval(20*time.Millisecond),
	)

	if name := r.Name(); name != "protocol_reconciler" {
		t.Fatalf("expected Name() to be 'protocol_reconciler', got %s", name)
	}

	sup := supervisor.New(
		supervisor.WithRestartDelay(10 * time.Millisecond),
	)
	sup.RegisterService(r)

	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Start(ctx)
	}()

	// Wait for background service to execute at least 2 ticks
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := callCount
		mu.Unlock()
		if c >= 2 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	mu.Lock()
	finalCount := callCount
	mu.Unlock()
	if finalCount < 1 {
		t.Fatalf("expected at least 1 execution of reconciler loop, got %d", finalCount)
	}

	// Stop supervisor and assert clean termination
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := sup.Stop(stopCtx); err != nil {
		t.Fatalf("supervisor.Stop failed: %v", err)
	}

	select {
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("supervisor.Start exited with unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("supervisor did not stop within deadline")
	}

	r.mu.Lock()
	running := r.running
	r.mu.Unlock()
	if running {
		t.Fatalf("expected reconciler.running to be false after Stop")
	}
}
