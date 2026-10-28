package handlers

import (
	"context"
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
