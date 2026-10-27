package userops

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type expiryProtocolManager struct {
	proto     string
	mu        sync.Mutex
	clients   map[string]struct{}
	removeErr error
}

func newExpiryProtocolManager(proto, clientID string) *expiryProtocolManager {
	return &expiryProtocolManager{
		proto:   proto,
		clients: map[string]struct{}{clientID: {}},
	}
}

func (m *expiryProtocolManager) Protocol() string {
	return m.proto
}

func (m *expiryProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}

func (m *expiryProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (m *expiryProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	clients := make([]map[string]any, 0, len(m.clients))
	for clientID := range m.clients {
		clients = append(clients, map[string]any{"client_id": clientID})
	}
	return clients, nil
}

func (m *expiryProtocolManager) AddClient(ctx context.Context, server *models.Server, params map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *expiryProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.clients, clientID)
	return nil
}

func (m *expiryProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[clientID]; !ok {
		return "", errors.New("client is not authorized")
	}
	return "client config", nil
}

func (m *expiryProtocolManager) setRemoveError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeErr = err
}

func setupExpiryFixture(t *testing.T, protocol string) (*database.DB, *expiryProtocolManager, *Service, string, string) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{
		Name:    "expiry server",
		Host:    "192.168.1.60",
		SSHPort: 22,
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	userID, err := db.CreateUser(ctx, &models.User{
		Username: "expiry-user-" + protocol,
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	clientID := protocol + "-client"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        "expiry-connection-" + protocol,
		UserID:    userID,
		ServerID:  serverID,
		Protocol:  protocol,
		ClientID:  clientID,
		Name:      "expiry connection",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	mgr := newExpiryProtocolManager(protocol, clientID)
	registry := newMockRegistry()
	registry.Register(mgr)
	return db, mgr, NewUserOpsService(db, registry), userID, clientID
}

func TestPerformMassOperations_DisableWithdrawsNonTogglingClients(t *testing.T) {
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(protocol, func(t *testing.T) {
			t.Run("withdraws remote authorization", func(t *testing.T) {
				db, mgr, svc, userID, clientID := setupExpiryFixture(t, protocol)
				ctx := context.Background()

				if err := svc.PerformMassOperations(ctx, MassOperationRequest{
					ToggleUIDs: []UserToggle{{UserID: userID, Enabled: false}},
				}); err != nil {
					t.Fatalf("disable user: %v", err)
				}

				clients, err := mgr.GetClients(ctx, nil)
				if err != nil || len(clients) != 0 {
					t.Fatalf("remote clients after disable = %v, err = %v; want none", clients, err)
				}
				if _, err := mgr.GetClientConfig(ctx, nil, clientID); err == nil {
					t.Fatal("withdrawn client still has a usable config")
				}
				connections, err := db.GetConnectionsByUserID(ctx, userID)
				if err != nil || len(connections) != 0 {
					t.Fatalf("connections after withdrawal = %v, err = %v; want none", connections, err)
				}
				user, err := db.GetUser(ctx, userID)
				if err != nil || user == nil || user.Enabled {
					t.Fatalf("user after disable = %+v, err = %v; want disabled", user, err)
				}
			})

			t.Run("failed removal remains retryable", func(t *testing.T) {
				db, mgr, svc, userID, clientID := setupExpiryFixture(t, protocol)
				ctx := context.Background()
				removeErr := fmt.Errorf("%s removal failed", protocol)
				mgr.setRemoveError(removeErr)
				req := MassOperationRequest{
					ToggleUIDs: []UserToggle{{UserID: userID, Enabled: false}},
				}

				err := svc.PerformMassOperations(ctx, req)
				if !errors.Is(err, removeErr) {
					t.Fatalf("disable error = %v; want wrapped removal error", err)
				}
				user, dbErr := db.GetUser(ctx, userID)
				if dbErr != nil || user == nil || !user.Enabled {
					t.Fatalf("user after failed disable = %+v, err = %v; want enabled", user, dbErr)
				}
				connections, dbErr := db.GetConnectionsByUserID(ctx, userID)
				if dbErr != nil || len(connections) != 1 {
					t.Fatalf("connections after failed disable = %v, err = %v; want retained", connections, dbErr)
				}
				if _, configErr := mgr.GetClientConfig(ctx, nil, clientID); configErr != nil {
					t.Fatalf("remote credential should remain after failed removal: %v", configErr)
				}

				mgr.setRemoveError(nil)
				if err := svc.PerformMassOperations(ctx, req); err != nil {
					t.Fatalf("retry disable: %v", err)
				}
				user, dbErr = db.GetUser(ctx, userID)
				if dbErr != nil || user == nil || user.Enabled {
					t.Fatalf("user after successful retry = %+v, err = %v; want disabled", user, dbErr)
				}
				if _, configErr := mgr.GetClientConfig(ctx, nil, clientID); configErr == nil {
					t.Fatal("client still has a usable config after successful retry")
				}
			})
		})
	}
}
