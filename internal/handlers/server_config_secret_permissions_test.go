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

func TestSaveServerConfigHandlerSecretPermissions(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:      "secret-config-server",
		Host:      "192.0.2.60",
		SSHUser:   "ubuntu",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	router := setupFullServerRouter(h)

	tests := []struct {
		protocol string
		wantMode int
	}{
		{protocol: models.ProtocolVLESS, wantMode: 0600},
		{protocol: models.ProtocolNaive, wantMode: 0600},
		{protocol: "dns", wantMode: 0644},
	}
	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			body, err := json.Marshal(models.ServerConfigSaveRequest{Protocol: tt.protocol, Config: "raw config"})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			path := fmt.Sprintf("/api/servers/%d/server_config/save", serverID)
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "admin-config",
				Role:   models.RoleAdmin,
			}))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			if int(mockSSH.uploadSudoMode) != tt.wantMode {
				t.Errorf("upload mode = %04o, want %04o", mockSSH.uploadSudoMode, tt.wantMode)
			}
		})
	}
}
