package userops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type coordinatingTwoServerManager struct {
	proto string

	serverAID int64
	serverBID int64

	serverBStarted   chan struct{}
	serverAFailed    chan struct{}
	serverBCompleted chan struct{}

	mu      sync.Mutex
	deleted map[int64][]string
}

func newCoordinatingTwoServerManager(proto string, serverAID, serverBID int64) *coordinatingTwoServerManager {
	return &coordinatingTwoServerManager{
		proto:            proto,
		serverAID:        serverAID,
		serverBID:        serverBID,
		serverBStarted:   make(chan struct{}),
		serverAFailed:    make(chan struct{}),
		serverBCompleted: make(chan struct{}),
		deleted:          make(map[int64][]string),
	}
}

func (m *coordinatingTwoServerManager) Protocol() string {
	return m.proto
}

func (m *coordinatingTwoServerManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}

func (m *coordinatingTwoServerManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (m *coordinatingTwoServerManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}

func (m *coordinatingTwoServerManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *coordinatingTwoServerManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

func (m *coordinatingTwoServerManager) ToggleClient(ctx context.Context, server *models.Server, clientID string, enable bool) error {
	return nil
}

func (m *coordinatingTwoServerManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	switch server.ID {
	case m.serverBID:
		// Signal that server B has begun revocation
		close(m.serverBStarted)

		// Wait for server A to fail while server B is still in flight
		select {
		case <-m.serverAFailed:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("timeout waiting for server A failure")
		}

		// Ensure server B's context was NOT canceled by server A's sibling failure
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("server B context canceled by sibling error: %w", err)
		}

		m.mu.Lock()
		m.deleted[server.ID] = append(m.deleted[server.ID], clientID)
		m.mu.Unlock()
		close(m.serverBCompleted)
		return nil

	case m.serverAID:
		// Ensure server B has actively started revocation before server A fails
		select {
		case <-m.serverBStarted:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("timeout waiting for server B to start")
		}

		// Signal that server A is failing and return the failure immediately
		close(m.serverAFailed)
		return errors.New("remote removal failed on server A")

	default:
		return nil
	}
}

type blockingMockManager struct {
	proto    string
	onRemove func(ctx context.Context) error
}

func (m *blockingMockManager) Protocol() string {
	return m.proto
}

func (m *blockingMockManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}

func (m *blockingMockManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (m *blockingMockManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}

func (m *blockingMockManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *blockingMockManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

func (m *blockingMockManager) ToggleClient(ctx context.Context, server *models.Server, clientID string, enable bool) error {
	return nil
}

func (m *blockingMockManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	if m.onRemove != nil {
		return m.onRemove(ctx)
	}
	return nil
}

func TestPerformMassOperations_MultiServerIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()

	serverA, err := db.CreateServer(ctx, &models.Server{Name: "server-a", Host: "10.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer A: %v", err)
	}
	serverB, err := db.CreateServer(ctx, &models.Server{Name: "server-b", Host: "10.0.0.2", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer B: %v", err)
	}

	uid, err := db.CreateUser(ctx, &models.User{Username: "test-multiserver", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	connAID := "conn-server-a"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        connAID,
		UserID:    uid,
		ServerID:  serverA,
		Protocol:  models.ProtocolAWG,
		ClientID:  "cid-server-a",
		Name:      "Conn A",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateConnection A: %v", err)
	}

	connBID := "conn-server-b"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        connBID,
		UserID:    uid,
		ServerID:  serverB,
		Protocol:  models.ProtocolAWG,
		ClientID:  "cid-server-b",
		Name:      "Conn B",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateConnection B: %v", err)
	}

	mgr := newCoordinatingTwoServerManager(models.ProtocolAWG, serverA, serverB)
	reg := newMockRegistry()
	reg.Register(mgr)

	svc := New(db, reg)

	err = svc.PerformMassOperations(ctx, MassOperationRequest{
		DeleteUIDs: []string{uid},
	})

	// 1. Assert that the operation failed overall because Server A failed
	if err == nil {
		t.Fatal("expected PerformMassOperations to return error when Server A failed, got nil")
	}
	if !strings.Contains(err.Error(), "remote removal failed on server A") {
		t.Fatalf("expected error from Server A, got: %v", err)
	}
	if strings.Contains(err.Error(), "server B") {
		t.Fatalf("server B should not have failed, got error: %v", err)
	}

	// 2. Assert that Server B completed successfully
	select {
	case <-mgr.serverBCompleted:
		// success
	default:
		t.Fatal("expected server B removal to complete successfully")
	}

	// 3. Assert DB state: Server B connection removed, Server A connection retained for retry
	connB, err := db.GetConnection(ctx, connBID)
	if err != nil {
		t.Fatalf("GetConnection B: %v", err)
	}
	if connB != nil {
		t.Fatalf("connection on Server B should have been deleted, but was found: %+v", connB)
	}

	connA, err := db.GetConnection(ctx, connAID)
	if err != nil {
		t.Fatalf("GetConnection A: %v", err)
	}
	if connA == nil {
		t.Fatal("connection on Server A should be retained for retry, but was deleted")
	}

	// 4. Assert user record was retained because Server A's connection still exists
	user, err := db.GetUser(ctx, uid)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user == nil {
		t.Fatal("user record should be retained when one connection fails removal")
	}
}

func TestPerformMassOperations_CallerCancellationPreserved(t *testing.T) {
	t.Run("pre-canceled context returns context.Canceled", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		serverA, err := db.CreateServer(t.Context(), &models.Server{Name: "cancel-srv-a", Host: "10.0.1.1", SSHPort: 22})
		if err != nil {
			t.Fatalf("CreateServer A: %v", err)
		}
		uid, err := db.CreateUser(t.Context(), &models.User{Username: "test-cancel", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if _, err := db.CreateConnection(t.Context(), &models.UserConnection{
			ID:        "cancel-conn-a",
			UserID:    uid,
			ServerID:  serverA,
			Protocol:  models.ProtocolAWG,
			ClientID:  "cancel-cid-a",
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateConnection A: %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Pre-canceled context from caller

		reg := newMockRegistry()
		reg.Register(newMockProtocolManager(models.ProtocolAWG))
		svc := New(db, reg)

		err = svc.PerformMassOperations(ctx, MassOperationRequest{
			DeleteUIDs: []string{uid},
		})
		if err == nil {
			t.Fatal("expected error with canceled context, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled in error, got: %v", err)
		}
	})

	t.Run("in-flight canceled context cancels active workers", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		serverA, err := db.CreateServer(t.Context(), &models.Server{Name: "inflight-cancel-srv", Host: "10.0.1.3", SSHPort: 22})
		if err != nil {
			t.Fatalf("CreateServer: %v", err)
		}
		uid, err := db.CreateUser(t.Context(), &models.User{Username: "test-inflight-cancel", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if _, err := db.CreateConnection(t.Context(), &models.UserConnection{
			ID:        "inflight-conn",
			UserID:    uid,
			ServerID:  serverA,
			Protocol:  models.ProtocolAWG,
			ClientID:  "inflight-cid",
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateConnection: %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})

		mgr := &blockingMockManager{
			proto: models.ProtocolAWG,
			onRemove: func(c context.Context) error {
				close(started)
				<-c.Done()
				return c.Err()
			},
		}
		reg := newMockRegistry()
		reg.Register(mgr)
		svc := New(db, reg)

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.PerformMassOperations(ctx, MassOperationRequest{
				DeleteUIDs: []string{uid},
			})
		}()

		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for worker to start")
		}

		cancel()

		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("expected error on in-flight cancellation, got nil")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context.Canceled in error, got: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for PerformMassOperations to return after cancellation")
		}
	})
}

func TestPerformMassOperations_MultiServerAllErrorsCollected(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := t.Context()

	serverA, err := db.CreateServer(ctx, &models.Server{Name: "all-err-a", Host: "10.0.2.1", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer A: %v", err)
	}
	serverB, err := db.CreateServer(ctx, &models.Server{Name: "all-err-b", Host: "10.0.2.2", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer B: %v", err)
	}

	uid, err := db.CreateUser(ctx, &models.User{Username: "test-all-errs", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        "all-err-conn-a",
		UserID:    uid,
		ServerID:  serverA,
		Protocol:  models.ProtocolAWG,
		ClientID:  "cid-err-a",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateConnection A: %v", err)
	}

	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:        "all-err-conn-b",
		UserID:    uid,
		ServerID:  serverB,
		Protocol:  models.ProtocolAWG,
		ClientID:  "cid-err-b",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateConnection B: %v", err)
	}

	mgr := newMockProtocolManager(models.ProtocolAWG)
	mgr.returnError = true // Both servers will fail
	reg := newMockRegistry()
	reg.Register(mgr)

	svc := New(db, reg)

	err = svc.PerformMassOperations(ctx, MassOperationRequest{
		DeleteUIDs: []string{uid},
	})
	if err == nil {
		t.Fatal("expected error when both servers fail, got nil")
	}
	if !strings.Contains(err.Error(), "cid-err-a") || !strings.Contains(err.Error(), "cid-err-b") {
		t.Fatalf("expected errors for both cid-err-a and cid-err-b, got: %v", err)
	}
}
