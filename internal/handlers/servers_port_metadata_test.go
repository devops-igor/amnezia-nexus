package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestInstallProtocolHandlerPortMetadata(t *testing.T) {
	tests := []struct {
		name        string
		managerPort any
		requestPort string
		wantPort    string
	}{
		{name: "preserve manager effective port", managerPort: 8443, requestPort: "443", wantPort: "8443"},
		{name: "fall back to request port", managerPort: nil, requestPort: "443", wantPort: "443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			h.registry = manager.NewRegistry()
			h.registry.Register(&mockProtocolManager{
				protocol: models.ProtocolVLESS,
				installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
					metadata := map[string]any{"installed": true}
					if tt.managerPort != nil {
						metadata["port"] = tt.managerPort
					}
					server.Protocols = map[string]any{models.ProtocolVLESS: metadata}
					return nil
				},
			})

			serverID, err := db.CreateServer(context.Background(), &models.Server{
				Name:      "Port metadata server",
				Host:      "192.0.2.12",
				SSHPort:   22,
				Protocols: make(map[string]any),
			})
			if err != nil {
				t.Fatalf("CreateServer: %v", err)
			}
			body, err := json.Marshal(models.InstallProtocolRequest{
				Protocol: models.ProtocolVLESS,
				Port:     tt.requestPort,
			})
			if err != nil {
				t.Fatalf("Marshal request: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
			routeCtx := chi.NewRouteContext()
			routeCtx.URLParams.Add("server_id", fmt.Sprint(serverID))
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "admin-user",
				Role:   models.RoleAdmin,
			}))
			w := httptest.NewRecorder()
			h.InstallProtocolHandler(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
			}

			saved, err := db.GetServer(context.Background(), serverID)
			if err != nil {
				t.Fatalf("GetServer: %v", err)
			}
			metadata, ok := saved.Protocols[models.ProtocolVLESS].(map[string]any)
			if !ok {
				t.Fatalf("VLESS metadata has type %T", saved.Protocols[models.ProtocolVLESS])
			}
			if got := fmt.Sprint(metadata["port"]); got != tt.wantPort {
				t.Fatalf("saved port = %s, want %s", got, tt.wantPort)
			}
		})
	}
}

func TestInstallProtocolHandler_OmittedPortWithStaleMetadataPreservesRemotePort(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	h.registry = manager.NewRegistry()

	var capturedParams map[string]any
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		installFn: func(ctx context.Context, server *models.Server, params map[string]any) error {
			capturedParams = params
			// Simulates XrayManager preserving remote inbound port 8443 when port is omitted
			// and port_explicit is false, repairing stale metadata.
			if explicit, ok := params["port_explicit"].(bool); ok && !explicit {
				server.Protocols[models.ProtocolVLESS] = map[string]any{
					"installed":      true,
					"port":           8443,
					"engine_profile": "modern_pq",
				}
			}
			return nil
		},
	})

	// Server in DB has STALE metadata: port 443, while remote Xray actually runs on 8443.
	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:    "Stale metadata server",
		Host:    "192.0.2.55",
		SSHPort: 22,
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           443, // Stale!
				"engine_profile": "legacy",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// Admin requests routine profile switch to modern_pq without specifying port.
	body, err := json.Marshal(models.InstallProtocolRequest{
		Protocol:      models.ProtocolVLESS,
		EngineProfile: "modern_pq",
		// Port is omitted
	})
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("server_id", fmt.Sprint(serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-user",
		Role:   models.RoleAdmin,
	}))

	w := httptest.NewRecorder()
	h.InstallProtocolHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	// Verify manager received port_explicit = false
	if explicit, ok := capturedParams["port_explicit"].(bool); !ok || explicit {
		t.Errorf("expected params[port_explicit] == false, got %v", capturedParams["port_explicit"])
	}

	// Verify database server protocols preserved/repaired remote inbound port 8443, NOT stale 443
	saved, err := db.GetServer(context.Background(), serverID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	metadata, ok := saved.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("VLESS metadata has type %T", saved.Protocols[models.ProtocolVLESS])
	}
	if got := fmt.Sprint(metadata["port"]); got != "8443" {
		t.Fatalf("saved port = %s, want 8443 (should not overwrite with stale 443)", got)
	}
}
