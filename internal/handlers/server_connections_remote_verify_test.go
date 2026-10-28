package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestEditServerConnectionRejectsRemovedRemoteClient(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	const clientID = "removed-remote-client"
	userID := "remote-verify-user"
	if _, err := db.CreateUser(ctx, &models.User{
		ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	remoteExists := true
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		getClientConfigFn: func(_ context.Context, _ *models.Server, id string) (string, error) {
			if id != clientID {
				t.Fatalf("GetClientConfig client ID = %q, want %q", id, clientID)
			}
			if !remoteExists {
				return "", errors.New("remote client not found")
			}
			return "remote-config", nil
		},
		removeClientFn: func(_ context.Context, _ *models.Server, id string) error {
			if id != clientID {
				t.Fatalf("RemoveClient client ID = %q, want %q", id, clientID)
			}
			remoteExists = false
			return nil
		},
	})

	router := setupFullServerConnectionsRouter(h)
	w := resourceRBACRequest(t, router, http.MethodPost,
		fmt.Sprintf("/api/servers/%d/connections/remove", serverID), resourceRBACSession(models.RoleAdmin),
		models.ConnectionActionRequest{Protocol: models.ProtocolVLESS, ClientID: clientID})
	if w.Code != http.StatusOK {
		t.Fatalf("remove status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	w = resourceRBACRequest(t, router, http.MethodPost,
		fmt.Sprintf("/api/servers/%d/connections/edit", serverID), resourceRBACSession(models.RoleAdmin),
		models.EditConnectionRequest{Protocol: models.ProtocolVLESS, ClientID: clientID, UserID: &userID})
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "client_not_found") {
		t.Fatalf("edit status = %d, body = %s; want 404 client_not_found", w.Code, w.Body.String())
	}

	connections, err := db.GetAllConnections(ctx)
	if err != nil {
		t.Fatalf("GetAllConnections: %v", err)
	}
	peers, err := db.GetPeerLifecycles(ctx, serverID, models.ProtocolVLESS)
	if err != nil {
		t.Fatalf("GetPeerLifecycles: %v", err)
	}
	if len(connections) != 0 || len(peers) != 0 {
		t.Fatalf("removed client was resurrected: connections=%+v peers=%+v", connections, peers)
	}
}

func TestNameOnlyConnectionEditAfterUserDeletionDoesNotRecreateLifecycle(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	const userID = "name-only-delete-user"
	const clientID = "name-only-delete-client"
	if _, err := db.CreateUser(ctx, &models.User{
		ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	createResourceRBACConnection(t, db, "name-only-delete-connection", userID, serverID, models.ProtocolVLESS, clientID)
	if err := db.RecordPeerLifecycle(ctx, serverID, models.ProtocolVLESS, clientID, "Old Name", userID, "active"); err != nil {
		t.Fatalf("RecordPeerLifecycle: %v", err)
	}
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		getClientConfigFn: func(_ context.Context, _ *models.Server, _ string) (string, error) {
			return "remote-config", nil
		},
		removeClientFn: func(_ context.Context, _ *models.Server, _ string) error {
			return nil
		},
	})

	w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodPost,
		"/api/users/"+userID+"/delete", resourceRBACSession(models.RoleAdmin), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	name := "New Name"
	w = resourceRBACRequest(t, setupFullServerConnectionsRouter(h), http.MethodPost,
		fmt.Sprintf("/api/servers/%d/connections/edit", serverID), resourceRBACSession(models.RoleAdmin),
		models.EditConnectionRequest{Protocol: models.ProtocolVLESS, ClientID: clientID, Name: &name})
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "connection_not_found") {
		t.Fatalf("edit status = %d, body = %s; want 404 connection_not_found", w.Code, w.Body.String())
	}
	peers, err := db.GetPeerLifecycles(ctx, serverID, models.ProtocolVLESS)
	if err != nil {
		t.Fatalf("GetPeerLifecycles: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("active lifecycle records after deleted-user edit = %+v, want none", peers)
	}
}

func TestEditServerConnectionAllowsAWGClientWithoutStoredPrivateKey(t *testing.T) {
	const clientID = "awg-client-without-private-key"
	const clientsTable = `[{"clientId":"awg-client-without-private-key","userData":{"clientName":"Old Name","clientPrivateKey":"","enabled":true,"awg_mimicry":"auto"}}]`
	var savedClientsTable []byte
	mockSSH := &testMockSSHClient{
		cmdFunc: func(_ context.Context, cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "cat") && strings.Contains(cmd, "clientsTable") {
				return clientsTable, "", 0, nil
			}
			return "ok", "", 0, nil
		},
		uploadFn: func(_ context.Context, _ string, content []byte) error {
			savedClientsTable = append([]byte(nil), content...)
			return nil
		},
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()
	serverID, err := db.CreateServer(ctx, &models.Server{
		Name: "awg-remote-verify", Host: "192.0.2.91", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{models.ProtocolAWG: map[string]any{"installed": true}}, CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	const userID = "awg-remote-verify-user"
	if _, err := db.CreateUser(ctx, &models.User{
		ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	createResourceRBACConnection(t, db, "awg-remote-verify-connection", userID, serverID, models.ProtocolAWG, clientID)

	name := "renamed-awg-client"
	mimicry := string(models.AWGMimicryDNS)
	w := resourceRBACRequest(t, setupFullServerConnectionsRouter(h), http.MethodPost,
		fmt.Sprintf("/api/servers/%d/connections/edit", serverID), resourceRBACSession(models.RoleAdmin),
		models.EditConnectionRequest{
			Protocol: models.ProtocolAWG, ClientID: clientID, Name: &name, AWGMimicry: &mimicry,
		})
	if w.Code != http.StatusOK {
		t.Fatalf("edit status = %d, body = %s; want 200", w.Code, w.Body.String())
	}

	var remoteClients []struct {
		UserData struct {
			ClientPrivateKey string `json:"clientPrivateKey"`
			AWGMimicry       string `json:"awg_mimicry"`
		} `json:"userData"`
	}
	if err := json.Unmarshal(savedClientsTable, &remoteClients); err != nil {
		t.Fatalf("Unmarshal saved clients table: %v", err)
	}
	if len(remoteClients) != 1 || remoteClients[0].UserData.AWGMimicry != mimicry {
		t.Fatalf("saved remote clients = %+v, want mimicry %q", remoteClients, mimicry)
	}
	if remoteClients[0].UserData.ClientPrivateKey != "" {
		t.Fatal("test unexpectedly stored a remote private key")
	}
	connection, err := db.GetConnection(ctx, "awg-remote-verify-connection")
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if connection == nil || connection.Name != name {
		t.Fatalf("connection = %+v, want name %q", connection, name)
	}
}

func TestAddUserConnectionAllowsAWGClientWithoutStoredPrivateKey(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	const userID = "awg-add-remote-verify-user"
	clientID := "awg-add-client-without-private-key"
	if _, err := db.CreateUser(ctx, &models.User{
		ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolAWG,
		getClientConfigFn: func(_ context.Context, _ *models.Server, _ string) (string, error) {
			return "", errors.New("client private key not stored; config cannot be reconstructed")
		},
	})

	w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodPost,
		"/api/users/"+userID+"/connections/add", resourceRBACSession(models.RoleAdmin),
		models.AddUserConnectionRequest{
			ServerID: serverID, Protocol: models.ProtocolAWG, ClientID: &clientID, Name: "imported-awg-client",
		})
	if w.Code != http.StatusOK {
		t.Fatalf("add status = %d, body = %s; want 200", w.Code, w.Body.String())
	}
	connections, err := db.GetConnectionsByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetConnectionsByUserID: %v", err)
	}
	if len(connections) != 1 || connections[0].ClientID != clientID {
		t.Fatalf("connections = %+v, want client %q", connections, clientID)
	}
}
