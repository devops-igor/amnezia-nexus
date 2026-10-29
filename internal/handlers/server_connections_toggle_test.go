package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestToggleServerConnectionHandlerStrictResolution(t *testing.T) {
	h, db, _ := setupTestHandlersWithMockSSH(t, &testMockSSHClient{})
	ctx := t.Context()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Toggle-VPN", Host: "192.168.1.80", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if _, err := db.CreateUser(ctx, &models.User{
		ID: "tg-user", Username: "tguser", PasswordHash: "hash", Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "tg-vless", UserID: "tg-user", ServerID: sID, Protocol: "vless", ClientID: "tg-vless-client", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if err := db.RecordPeerLifecycle(ctx, sID, "naive", "tg-naive-client", "n", "", "active"); err != nil {
		t.Fatalf("record lifecycle: %v", err)
	}
	if err := db.RecordPeerLifecycle(ctx, sID, "awg", "client-1", "a", "", "active"); err != nil {
		t.Fatalf("record lifecycle: %v", err)
	}

	toggle := func(h *Handlers, body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/connections/toggle", sID), bytes.NewReader(b))
		w := httptest.NewRecorder()
		setupFullServerConnectionsRouter(h).ServeHTTP(w, req)
		return w
	}

	tests := []struct {
		name     string
		body     map[string]any
		wantCode int
		wantBody string
	}{
		{"unassigned client, protocol omitted", map[string]any{"client_id": "ghost", "enabled": false}, http.StatusBadRequest, "validation_failed"},
		{"unknown protocol", map[string]any{"client_id": "client-1", "protocol": "bogus", "enabled": false}, http.StatusBadRequest, "validation_failed"},
		{"non-toggle protocol (telemt)", map[string]any{"client_id": "client-1", "protocol": "telemt", "enabled": false}, http.StatusBadRequest, "validation_failed"},
		{"vless resolved from user_connections", map[string]any{"client_id": "tg-vless-client", "enabled": false}, http.StatusBadRequest, "unsupported_action"},
		{"naive resolved from peer_lifecycle", map[string]any{"client_id": "tg-naive-client", "enabled": false}, http.StatusBadRequest, "unsupported_action"},
		{"awg resolved from peer_lifecycle", map[string]any{"client_id": "client-1", "enabled": false}, http.StatusOK, `"status":"ok"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := toggle(h, tc.body)
			if w.Code != tc.wantCode || !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("want %d containing %q, got %d: %s", tc.wantCode, tc.wantBody, w.Code, w.Body.String())
			}
		})
	}

	t.Run("awg manager missing", func(t *testing.T) {
		h.awgMgr = nil
		if w := toggle(h, map[string]any{"client_id": "client-1", "protocol": "awg", "enabled": true}); w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("awg toggle error propagates", func(t *testing.T) {
		failing := &testMockSSHClient{cmdFunc: func(context.Context, string) (string, string, int, error) {
			return "", "", 1, errors.New("ssh down")
		}}
		hf, dbf, _ := setupTestHandlersWithMockSSH(t, failing)
		if _, err := dbf.CreateServer(ctx, &models.Server{
			Name: "Fail-VPN", Host: "192.168.1.81", SSHPort: 22, SSHUser: "root",
			Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("create server: %v", err)
		}
		if w := toggle(hf, map[string]any{"client_id": "client-1", "protocol": "awg", "enabled": false}); w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
		}
	})
}
