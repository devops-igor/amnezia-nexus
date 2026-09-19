package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestInstallProtocolHandler_FailureLogged verifies that a protocol install
// failure still returns 500 but NO LONGER swallows the underlying error: it
// must be emitted through slog so operators can diagnose ARM64/port issues
// (Issue #225: the handler previously returned an opaque install_failed with
// zero server-side trace of the actual error).
func TestInstallProtocolHandler_FailureLogged(t *testing.T) {
	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			return "", "simulated install failure", 1, fmt.Errorf("simulated install failure")
		},
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:    "Install-Fail-Server",
		Host:    "10.0.0.55",
		SSHPort: 22,
		SSHUser: "root",
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	r := setupFullServerRouter(h)

	// Capture slog default-logger output (same pattern as TestRenameServerHandler).
	var logBuf bytes.Buffer
	origLogger := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(origLogger)
	})
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))

	body, _ := json.Marshal(models.InstallProtocolRequest{
		Protocol: "awg",
		Port:     "55424",
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on install failure, got %d (body: %s)", w.Code, w.Body.String())
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "protocol install failed") {
		t.Fatalf("expected slog output to contain 'protocol install failed', got:\n%s", logs)
	}
	for _, want := range []string{"server_id", "protocol", "port", "err"} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected install-failure log to include %q, got:\n%s", want, logs)
		}
	}
}
