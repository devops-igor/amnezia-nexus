package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestUserRevocationProtocolCollision(t *testing.T) {
	for _, action := range []string{"delete", "disable"} {
		t.Run(action, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := t.Context()
			serverID, err := db.CreateServer(ctx, &models.Server{
				Name: "protocol-collision", Host: "127.0.0.1", SSHPort: 22,
				Protocols: map[string]any{
					"naive": map[string]any{"installed": true},
					"vless": map[string]any{"installed": true},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			const credential = "same-identifier"
			p, err := json.Marshal(models.NaiveProxyParams{Username: credential, Password: "backend-password"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID: serverID, Protocol: models.ProtocolNaive, ProtocolParams: p,
				InterfaceName: "naive-backend-collision", Enabled: true, Status: models.TunnelStatusActive,
			}); err != nil {
				t.Fatal(err)
			}
			userID, err := db.CreateUser(ctx, &models.User{Username: "collision-user", Role: models.RoleUser, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateConnection(ctx, &models.UserConnection{
				ID: "vless-collision", UserID: userID, ServerID: serverID,
				Protocol: models.ProtocolVLESS, ClientID: credential,
			}); err != nil {
				t.Fatal(err)
			}

			// The fake node authenticates from its live protocol-specific credential stores,
			// independently of user_connections. Database-only deletion cannot pass this test.
			vlessAuth := map[string]bool{credential: true}
			naiveAuth := map[string]bool{credential: true}
			h.registry.Register(&mockProtocolManager{
				protocol: models.ProtocolVLESS,
				removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
					delete(vlessAuth, clientID)
					return nil
				},
			})
			var body *bytes.Reader
			if action == "disable" {
				body = bytes.NewReader([]byte(`{"enabled":false}`))
			} else {
				body = bytes.NewReader(nil)
			}
			path := fmt.Sprintf("/api/users/%s/%s", userID, map[bool]string{true: "toggle", false: "delete"}[action == "disable"])
			req := httptest.NewRequest(http.MethodPost, path, body)
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			w := httptest.NewRecorder()
			setupFullUsersRouter(h).ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("%s failed: %d %s", action, w.Code, w.Body.String())
			}
			if vlessAuth[credential] {
				t.Fatalf("%s user still authenticates to VLESS node", action)
			}
			if !naiveAuth[credential] {
				t.Fatal("active Naive backend lost authentication")
			}
			if backend, err := db.GetBackendTunnelByServerID(ctx, serverID); err != nil || backend == nil || !backend.Enabled {
				t.Fatalf("backend disconnected: %+v, %v", backend, err)
			}
		})
	}
}
