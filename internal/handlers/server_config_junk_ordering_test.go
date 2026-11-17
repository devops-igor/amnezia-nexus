package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestSaveServerConfigHandlerRejectsInvertedJunkSizes pins the handler boundary
// for the junk-size ordering rule the pinned upstream engine enforces: an
// inverted pair must be refused as a validation error by Nexus instead of being
// written and failing later at awg-quick up inside the backend container.
func TestSaveServerConfigHandlerRejectsInvertedJunkSizes(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:      "Junk-Order-1",
		Host:      "192.168.1.101",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "pass123",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	mockSSH.serverID = &serverID

	r := setupFullServerRouter(h)

	invertedConf := "[Interface]\nPrivateKey = aaaa\nListenPort = 55424\nJmin = 500\nJmax = 30\n"
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": invertedConf})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", serverID), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for inverted junk sizes, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "validation_failed" {
		t.Errorf("expected error code 'validation_failed', got %v", resp["error"])
	}
	detail, _ := resp["detail"].(string)
	if !strings.Contains(detail, "junk_packet_min_size") {
		t.Errorf("expected detail to name junk_packet_min_size, got %q", detail)
	}
}
