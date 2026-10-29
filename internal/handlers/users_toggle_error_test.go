package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	_ "modernc.org/sqlite"
)

func TestToggleUserHandlerConnectionSnapshotErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "toggle-error.db")
	db, err := database.Open(dbPath, testSecretKey)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	user := &models.User{
		ID:           "snapshot-error-user",
		Username:     "snapshot-error-user",
		PasswordHash: "hash",
		Role:         models.RoleUser,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := rawDB.ExecContext(ctx, "ALTER TABLE user_connections RENAME TO user_connections_unavailable"); err != nil {
		_ = rawDB.Close()
		t.Fatalf("break connection snapshot table: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("close raw database: %v", err)
	}

	h := NewHandlers(Dependencies{DB: db})
	req := httptest.NewRequest(http.MethodPost, "/api/users/"+user.ID+"/toggle", strings.NewReader(`{"enabled":false}`))
	w := httptest.NewRecorder()
	setupFullUsersRouter(h).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "database_error") {
		t.Fatalf("response does not contain database_error: %s", w.Body.String())
	}

	preserved, err := db.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if preserved == nil || !preserved.Enabled {
		t.Fatalf("user was disabled despite connection snapshot failure: %+v", preserved)
	}
}
