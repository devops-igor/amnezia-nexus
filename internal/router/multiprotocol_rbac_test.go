package router

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

type rbacMockSSH struct {
	files map[string][]byte
}

func (m *rbacMockSSH) RunCommand(ctx context.Context, cmd string) (string, string, int, error) {
	return "OK", "", 0, nil
}
func (m *rbacMockSSH) RunScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}
func (m *rbacMockSSH) RunSudoScript(ctx context.Context, script string) (string, string, int, error) {
	return "OK", "", 0, nil
}
func (m *rbacMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "cat ") {
		return "sample config content", "", 0, nil
	}
	return "OK", "", 0, nil
}
func (m *rbacMockSSH) UploadFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.files[remotePath] = content
	return nil
}
func (m *rbacMockSSH) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.files[remotePath] = content
	return nil
}
func (m *rbacMockSSH) DownloadFile(ctx context.Context, remotePath string) ([]byte, error) {
	if d, ok := m.files[remotePath]; ok {
		return d, nil
	}
	return []byte("sample config content"), nil
}
func (m *rbacMockSSH) DownloadSudoFile(ctx context.Context, remotePath string) ([]byte, error) {
	return m.DownloadFile(ctx, remotePath)
}
func (m *rbacMockSSH) FileExists(ctx context.Context, remotePath string) (bool, error) {
	return true, nil
}
func (m *rbacMockSSH) TestConnection(ctx context.Context) (string, error) {
	return "Linux 5.15", nil
}
func (m *rbacMockSSH) Close() error                       { return nil }
func (m *rbacMockSSH) IsAlive() bool                      { return true }
func (m *rbacMockSSH) GetUnderlyingClient() *gossh.Client { return nil }
func (m *rbacMockSSH) GetHost() string                    { return "192.0.2.30" }
func (m *rbacMockSSH) GetPort() int                       { return 22 }
func (m *rbacMockSSH) GetUser() string                    { return "root" }
func (m *rbacMockSSH) GetServerID() *int64                { return nil }
func (m *rbacMockSSH) GetLastActive() time.Time           { return time.Now() }
func (m *rbacMockSSH) InUse() bool                        { return false }

type rbacMockSSHPool struct {
	client ssh.SSHClient
}

func (p *rbacMockSSHPool) Get(ctx context.Context, server *models.Server) (ssh.SSHClient, error) {
	return p.client, nil
}
func (p *rbacMockSSHPool) Remove(serverID int64) {}

type rbacMockManager struct {
	proto string
	calls int
}

func (m *rbacMockManager) Protocol() string { return m.proto }
func (m *rbacMockManager) Install(ctx context.Context, s *models.Server, p map[string]any) error {
	m.calls++
	if s.Protocols == nil {
		s.Protocols = make(map[string]any)
	}
	s.Protocols[m.proto] = map[string]any{"installed": true}
	return nil
}
func (m *rbacMockManager) Uninstall(ctx context.Context, s *models.Server) error {
	m.calls++
	return nil
}
func (m *rbacMockManager) GetClients(context.Context, *models.Server) ([]map[string]any, error) {
	return nil, nil
}
func (m *rbacMockManager) AddClient(context.Context, *models.Server, map[string]any) (map[string]any, error) {
	return nil, nil
}
func (m *rbacMockManager) RemoveClient(context.Context, *models.Server, string) error {
	return nil
}
func (m *rbacMockManager) GetClientConfig(context.Context, *models.Server, string) (string, error) {
	return "", nil
}
func (m *rbacMockManager) GetServerStatus(context.Context, *models.Server) (map[string]any, error) {
	return map[string]any{"container_running": true}, nil
}

func TestMultiProtocol_RouterRBAC(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	ctx := context.Background()

	_, err := db.CreateUser(ctx, &models.User{
		ID:       "support-user-id",
		Username: "supportuser",
		Role:     models.RoleSupport,
		Enabled:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.CreateUser(ctx, &models.User{
		ID:       "admin-user-id",
		Username: "adminuser",
		Role:     models.RoleAdmin,
		Enabled:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	serverID, err := db.CreateServer(ctx, &models.Server{
		Name:    "router-rbac-server",
		Host:    "192.0.2.30",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{"installed": true},
			"naive": map[string]any{"installed": true},
			"awg":   map[string]any{"installed": true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	vlessMgr := &rbacMockManager{proto: "vless"}
	naiveMgr := &rbacMockManager{proto: "naive"}
	awgMgr := &rbacMockManager{proto: "awg"}

	reg := manager.NewRegistry()
	reg.Register(vlessMgr)
	reg.Register(naiveMgr)
	reg.Register(awgMgr)

	h := handlers.NewHandlers(handlers.Dependencies{
		Config:   cfg,
		DB:       db,
		Registry: reg,
		SSHPool:  &rbacMockSSHPool{client: &rbacMockSSH{files: make(map[string][]byte)}},
	})

	r := NewRouterWithOptions(Options{
		Config:   cfg,
		DB:       db,
		Handlers: h,
	})

	csrfTok := "csrf-token-rbac"

	// 1. Support role MUST be forbidden on VLESS and Naive on /api/servers/ routes
	for _, proto := range []string{"vless", "naive"} {
		for _, action := range []string{"install", "uninstall"} {
			testName := fmt.Sprintf("Support %s /api/servers/%s", proto, action)
			t.Run(testName, func(t *testing.T) {
				var body string
				if action == "install" {
					body = fmt.Sprintf(`{"protocol":%q,"port":"443"}`, proto)
				} else {
					body = fmt.Sprintf(`{"protocol":%q}`, proto)
				}

				vlessMgr.calls = 0
				naiveMgr.calls = 0

				urlPath := fmt.Sprintf("/api/servers/%d/%s", serverID, action)
				req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(middleware.CSRFHeaderName, csrfTok)
				req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
				req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID:   "support-user-id",
					Username: "supportuser",
					Role:     models.RoleSupport,
				}))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)

				if w.Code != http.StatusForbidden {
					t.Errorf("expected 403 Forbidden for Support role on %s %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
				}
				if vlessMgr.calls != 0 || naiveMgr.calls != 0 {
					t.Errorf("expected manager not to be called on forbidden request, got vless=%d naive=%d", vlessMgr.calls, naiveMgr.calls)
				}
			})
		}
	}

	// 2. Admin role MUST succeed on VLESS and Naive on /api/servers/ routes
	for _, proto := range []string{"vless", "naive"} {
		for _, action := range []string{"install", "uninstall"} {
			testName := fmt.Sprintf("Admin %s /api/servers/%s", proto, action)
			t.Run(testName, func(t *testing.T) {
				var body string
				if action == "install" {
					body = fmt.Sprintf(`{"protocol":%q,"port":"443"}`, proto)
				} else {
					body = fmt.Sprintf(`{"protocol":%q}`, proto)
				}

				urlPath := fmt.Sprintf("/api/servers/%d/%s", serverID, action)
				req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(middleware.CSRFHeaderName, csrfTok)
				req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
				req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID:   "admin-user-id",
					Username: "adminuser",
					Role:     models.RoleAdmin,
				}))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Errorf("expected 200 OK for Admin role on %s %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
				}
			})
		}
	}

	// 3. Support role CAN still manage legacy protocols like AWG
	for _, action := range []string{"install", "uninstall"} {
		testName := fmt.Sprintf("Support awg /api/servers/%s", action)
		t.Run(testName, func(t *testing.T) {
			var body string
			if action == "install" {
				body = `{"protocol":"awg","port":"51820"}`
			} else {
				body = `{"protocol":"awg"}`
			}

			urlPath := fmt.Sprintf("/api/servers/%d/%s", serverID, action)
			req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CSRFHeaderName, csrfTok)
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
			req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "support-user-id",
				Username: "supportuser",
				Role:     models.RoleSupport,
			}))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected 200 OK for Support role on awg %s, got %d (body: %s)", urlPath, w.Code, w.Body.String())
			}
		})
	}

	// 4. Support role MUST be forbidden from reading and saving VLESS and Naive server configs
	for _, proto := range []string{"vless", "naive"} {
		// Read config
		t.Run(fmt.Sprintf("Support %s /api/servers/server_config", proto), func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":%q}`, proto)
			urlPath := fmt.Sprintf("/api/servers/%d/server_config", serverID)
			req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CSRFHeaderName, csrfTok)
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
			req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "support-user-id",
				Username: "supportuser",
				Role:     models.RoleSupport,
			}))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden for Support role on %s %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
			}
		})

		// Save config
		t.Run(fmt.Sprintf("Support %s /api/servers/server_config/save", proto), func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":%q,"config":"# test config"}`, proto)
			urlPath := fmt.Sprintf("/api/servers/%d/server_config/save", serverID)
			req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CSRFHeaderName, csrfTok)
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
			req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "support-user-id",
				Username: "supportuser",
				Role:     models.RoleSupport,
			}))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden for Support role on %s %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
			}
		})
	}

	// 5. Admin role MUST succeed on reading and saving VLESS and Naive server configs
	for _, proto := range []string{"vless", "naive"} {
		// Read config
		t.Run(fmt.Sprintf("Admin %s /api/servers/server_config", proto), func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":%q}`, proto)
			urlPath := fmt.Sprintf("/api/servers/%d/server_config", serverID)
			req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CSRFHeaderName, csrfTok)
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
			req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "admin-user-id",
				Username: "adminuser",
				Role:     models.RoleAdmin,
			}))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected 200 OK for Admin role on %s %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
			}
		})

		// Save config
		t.Run(fmt.Sprintf("Admin %s /api/servers/server_config/save", proto), func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":%q,"config":"# test config"}`, proto)
			urlPath := fmt.Sprintf("/api/servers/%d/server_config/save", serverID)
			req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CSRFHeaderName, csrfTok)
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
			req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "admin-user-id",
				Username: "adminuser",
				Role:     models.RoleAdmin,
			}))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected 200 OK for Admin role on %s %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
			}
		})
	}

	// 6. Support role MUST be forbidden from container toggle on VLESS and Naive (canonical and aliases)
	for _, proto := range []string{"vless", "naive", "vless-reality", "naiveproxy"} {
		for _, action := range []string{"stop", "start", "restart"} {
			testName := fmt.Sprintf("Support toggle %s /api/servers/%s", proto, action)
			t.Run(testName, func(t *testing.T) {
				body := fmt.Sprintf(`{"protocol":%q,"action":%q}`, proto, action)
				urlPath := fmt.Sprintf("/api/servers/%d/container/toggle", serverID)
				req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(middleware.CSRFHeaderName, csrfTok)
				req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
				req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID:   "support-user-id",
					Username: "supportuser",
					Role:     models.RoleSupport,
				}))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)

				if w.Code != http.StatusForbidden {
					t.Errorf("expected 403 Forbidden for Support role on %s toggle %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
				}
			})
		}
	}

	// 7. Admin role MUST succeed on container toggle for VLESS and Naive
	for _, proto := range []string{"vless", "naive"} {
		for _, action := range []string{"stop", "start", "restart"} {
			testName := fmt.Sprintf("Admin toggle %s /api/servers/%s", proto, action)
			t.Run(testName, func(t *testing.T) {
				body := fmt.Sprintf(`{"protocol":%q,"action":%q}`, proto, action)
				urlPath := fmt.Sprintf("/api/servers/%d/container/toggle", serverID)
				req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(middleware.CSRFHeaderName, csrfTok)
				req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
				req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
				req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
					UserID:   "admin-user-id",
					Username: "adminuser",
					Role:     models.RoleAdmin,
				}))

				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Errorf("expected 200 OK for Admin role on %s toggle %s, got %d (body: %s)", proto, urlPath, w.Code, w.Body.String())
				}
			})
		}
	}

	// 8. Support role CAN still toggle legacy protocols like AWG
	for _, action := range []string{"stop", "start", "restart"} {
		testName := fmt.Sprintf("Support toggle awg /api/servers/%s", action)
		t.Run(testName, func(t *testing.T) {
			body := fmt.Sprintf(`{"protocol":"awg","action":%q}`, action)
			urlPath := fmt.Sprintf("/api/servers/%d/container/toggle", serverID)
			req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(middleware.CSRFHeaderName, csrfTok)
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
			req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "support-user-id",
				Username: "supportuser",
				Role:     models.RoleSupport,
			}))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected 200 OK for Support role on awg toggle %s, got %d (body: %s)", urlPath, w.Code, w.Body.String())
			}
		})
	}

	// 9. Clear Server: Support role MUST receive 403 Forbidden
	t.Run("Support clear /api/servers/{id}/clear", func(t *testing.T) {
		urlPath := fmt.Sprintf("/api/servers/%d/clear", serverID)
		req := httptest.NewRequest(http.MethodPost, urlPath, nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.CSRFHeaderName, csrfTok)
		req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
		req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID:   "support-user-id",
			Username: "supportuser",
			Role:     models.RoleSupport,
		}))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for Support role on clear %s, got %d (body: %s)", urlPath, w.Code, w.Body.String())
		}
	})

	// 10. Clear Server: Admin role MUST receive 200 OK
	t.Run("Admin clear /api/servers/{id}/clear", func(t *testing.T) {
		urlPath := fmt.Sprintf("/api/servers/%d/clear", serverID)
		req := httptest.NewRequest(http.MethodPost, urlPath, nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.CSRFHeaderName, csrfTok)
		req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
		req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID:   "admin-user-id",
			Username: "adminuser",
			Role:     models.RoleAdmin,
		}))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK for Admin role on clear %s, got %d (body: %s)", urlPath, w.Code, w.Body.String())
		}
	})
}
