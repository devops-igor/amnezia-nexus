package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestServerConnectionAdminProtocolRBAC(t *testing.T) {
	operations := []struct {
		name string
		path string
		body func(string) any
	}{
		{
			name: "add",
			path: "add",
			body: func(protocol string) any {
				return models.AddConnectionRequest{Protocol: protocol, Name: "RBAC test"}
			},
		},
		{
			name: "remove",
			path: "remove",
			body: func(protocol string) any {
				return models.ConnectionActionRequest{Protocol: protocol, ClientID: "client-1"}
			},
		},
		{
			name: "config",
			path: "config",
			body: func(protocol string) any {
				return models.ConnectionActionRequest{Protocol: protocol, ClientID: "client-1"}
			},
		},
	}

	for _, operation := range operations {
		for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
			for _, role := range []models.UserRole{models.RoleSupport, models.RoleAdmin} {
				name := fmt.Sprintf("%s/%s/%s", operation.name, protocol, role)
				t.Run(name, func(t *testing.T) {
					h, db, _ := setupTestHandlers(t)
					h.registry.Register(&mockProtocolManager{protocol: models.ProtocolVLESS})
					h.registry.Register(&mockProtocolManager{protocol: models.ProtocolNaive})

					serverID, err := db.CreateServer(context.Background(), &models.Server{
						Name:    "RBAC server",
						Host:    "192.0.2.10",
						SSHPort: 22,
						SSHUser: "root",
						Protocols: map[string]any{
							protocol: map[string]any{"installed": true},
						},
						CreatedAt: time.Now(),
					})
					if err != nil {
						t.Fatalf("CreateServer: %v", err)
					}

					body, err := json.Marshal(operation.body(protocol))
					if err != nil {
						t.Fatalf("Marshal request: %v", err)
					}
					path := fmt.Sprintf("/api/servers/%d/connections/%s", serverID, operation.path)
					req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
					req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
						UserID: "rbac-user",
						Role:   role,
					}))
					w := httptest.NewRecorder()
					setupFullServerConnectionsRouter(h).ServeHTTP(w, req)

					want := http.StatusOK
					if role == models.RoleSupport {
						want = http.StatusForbidden
					}
					if w.Code != want {
						t.Fatalf("status = %d, want %d (body: %s)", w.Code, want, w.Body.String())
					}
				})
			}
		}
	}
}

func TestAddUserConnectionAdminProtocolRBAC(t *testing.T) {
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		for _, role := range []models.UserRole{models.RoleSupport, models.RoleAdmin} {
			t.Run(fmt.Sprintf("%s/%s", protocol, role), func(t *testing.T) {
				h, db, _ := setupTestHandlers(t)
				h.registry.Register(&mockProtocolManager{protocol: protocol})
				ctx := context.Background()
				serverID, err := db.CreateServer(ctx, &models.Server{
					Name:    "User RBAC server",
					Host:    "192.0.2.11",
					SSHPort: 22,
					SSHUser: "root",
					Protocols: map[string]any{
						protocol: map[string]any{"installed": true},
					},
				})
				if err != nil {
					t.Fatalf("CreateServer: %v", err)
				}
				user := &models.User{
					ID:           "target-user",
					Username:     "target-user",
					PasswordHash: "hash",
					Role:         models.RoleUser,
					Enabled:      true,
					CreatedAt:    time.Now(),
				}
				if _, err := db.CreateUser(ctx, user); err != nil {
					t.Fatalf("CreateUser: %v", err)
				}

				body, err := json.Marshal(models.AddUserConnectionRequest{
					ServerID: serverID,
					Protocol: protocol,
					Name:     "User RBAC test",
				})
				if err != nil {
					t.Fatalf("Marshal request: %v", err)
				}
				path := fmt.Sprintf("/api/users/%s/connections/add", user.ID)
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID: "rbac-user",
					Role:   role,
				}))
				w := httptest.NewRecorder()
				setupFullUsersRouter(h).ServeHTTP(w, req)

				want := http.StatusOK
				if role == models.RoleSupport {
					want = http.StatusForbidden
				}
				if w.Code != want {
					t.Fatalf("status = %d, want %d (body: %s)", w.Code, want, w.Body.String())
				}
			})
		}
	}
}
