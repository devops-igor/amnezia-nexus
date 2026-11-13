package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
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
	var logBuf testSyncWriter
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
	for _, want := range []string{"server_id", "protocol", "port", "err", "duration_ms"} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected install-failure log to include %q, got:\n%s", want, logs)
		}
	}
	// The duration must be a real bounded integer so the offline collector can
	// separate a slow attempt from a fast failure (issue #680 Phase 0).
	duration := regexp.MustCompile(`duration_ms=(\d+)`).FindStringSubmatch(logs)
	if duration == nil {
		t.Fatalf("expected a numeric duration_ms in the install-failure log, got:\n%s", logs)
	}
	if ms, err := strconv.Atoi(duration[1]); err != nil || ms < 0 {
		t.Errorf("expected duration_ms to be a non-negative integer, got %q", duration[1])
	}
}
