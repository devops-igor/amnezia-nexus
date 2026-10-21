package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu       sync.Mutex
	deadline time.Time
}

func newDeadlineRecorder() *deadlineRecorder {
	return &deadlineRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadline = t
	return nil
}

func (d *deadlineRecorder) getDeadline() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deadline
}

func TestInstallProtocolHandler_WriteDeadlineAndContextTimeout(t *testing.T) {
	var capturedDeadline time.Time
	var deadlineFound bool

	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			if dl, ok := ctx.Deadline(); ok {
				capturedDeadline = dl
				deadlineFound = true
			}
			if strings.Contains(cmd, "ss -lun") || strings.Contains(cmd, "docker ps") {
				return "", "", 0, nil
			}
			return "ok", "", 0, nil
		},
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:    "Timeout-Test-Server",
		Host:    "10.0.0.60",
		SSHPort: 22,
		SSHUser: "root",
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	r := setupFullServerRouter(h)

	body, _ := json.Marshal(models.InstallProtocolRequest{
		Protocol: "awg",
		Port:     "55424",
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	rec := newDeadlineRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on install success, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 1. Verify HTTP write deadline was extended via ResponseController (15 minutes)
	writeDl := rec.getDeadline()
	if writeDl.IsZero() {
		t.Fatal("expected write deadline to be set via ResponseController")
	}
	remainingWrite := time.Until(writeDl)
	if remainingWrite < 14*time.Minute || remainingWrite > 16*time.Minute {
		t.Fatalf("expected write deadline ~15m, got remaining %v", remainingWrite)
	}

	// 2. Verify operational context deadline was propagated to SSH operations (15 minutes)
	if !deadlineFound {
		t.Fatal("expected operational context to carry a deadline")
	}
	remainingCtx := time.Until(capturedDeadline)
	if remainingCtx < 14*time.Minute || remainingCtx > 16*time.Minute {
		t.Fatalf("expected context deadline ~15m, got remaining %v", remainingCtx)
	}
}

func TestUninstallProtocolHandler_WriteDeadlineAndContextTimeout(t *testing.T) {
	var capturedDeadline time.Time
	var deadlineFound bool

	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			if dl, ok := ctx.Deadline(); ok {
				capturedDeadline = dl
				deadlineFound = true
			}
			if strings.Contains(cmd, "ss -lun") || strings.Contains(cmd, "docker ps") {
				return "", "", 0, nil
			}
			return "ok", "", 0, nil
		},
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:    "Uninstall-Timeout-Server",
		Host:    "10.0.0.61",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed": true,
				"port":      "55424",
			},
		},
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	r := setupFullServerRouter(h)

	body, _ := json.Marshal(models.ProtocolRequest{
		Protocol: "awg",
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/uninstall", serverID), bytes.NewReader(body))
	rec := newDeadlineRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on uninstall success, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 1. Verify HTTP write deadline was extended via ResponseController (5 minutes)
	writeDl := rec.getDeadline()
	if writeDl.IsZero() {
		t.Fatal("expected write deadline to be set via ResponseController")
	}
	remainingWrite := time.Until(writeDl)
	if remainingWrite < 4*time.Minute || remainingWrite > 6*time.Minute {
		t.Fatalf("expected write deadline ~5m, got remaining %v", remainingWrite)
	}

	// 2. Verify operational context deadline was propagated to SSH operations (5 minutes)
	if !deadlineFound {
		t.Fatal("expected operational context to carry a deadline")
	}
	remainingCtx := time.Until(capturedDeadline)
	if remainingCtx < 4*time.Minute || remainingCtx > 6*time.Minute {
		t.Fatalf("expected context deadline ~5m, got remaining %v", remainingCtx)
	}
}

func TestInstallProtocolHandler_ParentContextCanceled(t *testing.T) {
	canceled := make(chan struct{})
	var closeOnce sync.Once

	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			select {
			case <-ctx.Done():
				closeOnce.Do(func() { close(canceled) })
				return "", "canceled", 1, ctx.Err()
			case <-time.After(3 * time.Second):
				return "ok", "", 0, nil
			}
		},
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:    "Cancel-Test-Server",
		Host:    "10.0.0.62",
		SSHPort: 22,
		SSHUser: "root",
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	r := setupFullServerRouter(h)

	body, _ := json.Marshal(models.InstallProtocolRequest{
		Protocol: "awg",
		Port:     "55424",
	})
	reqCtx, reqCancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body)).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		reqCancel()
	}()

	r.ServeHTTP(rec, req)

	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("expected operation context to be canceled when request context was canceled")
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when canceled, got %d", rec.Code)
	}
}
