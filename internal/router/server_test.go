package router

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func generateTestCertPEM(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return string(certPEM), string(keyPEM)
}

func TestServerLifecyclePlainHTTP(t *testing.T) {
	cfg := &config.Config{
		Host: "127.0.0.1",
		Port: 0, // dynamic port for testing
	}

	// Find free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg.Port = port
	r := NewRouter(cfg, nil, nil)
	srv := NewServer(cfg, r)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	// Make request
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/health", port))
	if err != nil {
		t.Fatalf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Errorf("server did not stop in time")
	}
}

func TestServerDynamicTLS(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "server_tls_test.db")
	db, err := database.Open(dbPath, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer db.Close()

	certPEM, keyPEM := generateTestCertPEM(t)

	// Configure SSL in database
	sslSettings := models.SSLSettings{
		Enabled:   true,
		Domain:    "localhost",
		CertText:  certPEM,
		KeyText:   keyPEM,
		PanelPort: 5443,
	}
	ctx := context.Background()
	if err := db.UpdateSetting(ctx, "ssl", sslSettings); err != nil {
		t.Fatalf("failed to update ssl setting: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := &config.Config{
		Host:      "127.0.0.1",
		Port:      port,
		SecretKey: testSecretKey,
	}

	r := NewRouter(cfg, db, nil)
	srv := NewServer(cfg, r, db)

	// Test LoadTLSCertificate
	cert, err := srv.LoadTLSCertificate(ctx)
	if err != nil || cert == nil {
		t.Fatalf("LoadTLSCertificate failed: %v", err)
	}

	// Test ReloadTLS
	srv.ReloadTLS(cert)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	// Make TLS request with InsecureSkipVerify
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- Test client
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/health", port))
	if err != nil {
		t.Fatalf("failed to make HTTPS request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

// TestServerCookiePolicyTracksTLS verifies the #83 wiring: NewServer installs
// the process-wide cookie policy, Secure stays false until a TLS certificate
// is loaded, ReloadTLS transitions the flag, and the policy is reachable by
// the session middleware.
func TestServerCookiePolicyTracksTLS(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cookie_policy_test.db")
	db, err := database.Open(dbPath, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer db.Close()

	certPEM, keyPEM := generateTestCertPEM(t)
	sslSettings := models.SSLSettings{
		Enabled:   true,
		Domain:    "localhost",
		CertText:  certPEM,
		KeyText:   keyPEM,
		PanelPort: 5443,
	}
	ctx := context.Background()
	if err := db.UpdateSetting(ctx, "ssl", sslSettings); err != nil {
		t.Fatalf("failed to update ssl setting: %v", err)
	}

	cfg := &config.Config{
		Host:      "127.0.0.1",
		Port:      0,
		SecretKey: testSecretKey,
	}

	r := NewRouter(cfg, db, nil)
	srv := NewServer(cfg, r, db)

	policy := srv.cookiePolicy
	if policy == nil {
		t.Fatal("NewServer must install a cookie policy")
	}
	if middleware.CurrentSessionCookiePolicy() != policy {
		t.Fatal("cookie policy must be installed process-wide for the middleware")
	}
	if policy.Source() != middleware.CookieSecureFromTLS {
		t.Errorf("expected source tls, got %q", policy.Source())
	}
	if policy.Secure() {
		t.Errorf("expected Secure=false before any certificate is loaded")
	}

	cert, err := srv.LoadTLSCertificate(ctx)
	if err != nil || cert == nil {
		t.Fatalf("LoadTLSCertificate failed: %v", err)
	}

	srv.ReloadTLS(cert)
	if !policy.Secure() {
		t.Errorf("expected Secure=true after ReloadTLS with certificate")
	}

	srv.ReloadTLS(nil)
	if policy.Secure() {
		t.Errorf("expected Secure=false after ReloadTLS(nil)")
	}
}

func TestServer_WriteTimeout(t *testing.T) {
	cfg := &config.Config{
		Host: "127.0.0.1",
		Port: 5000,
	}
	srv := NewServer(cfg, nil)
	if srv.httpServer.WriteTimeout != 300*time.Second {
		t.Fatalf("expected httpServer.WriteTimeout to be 300s, got %v", srv.httpServer.WriteTimeout)
	}
}

type mockTimeoutProtocolManager struct {
	mu               sync.Mutex
	protocol         string
	capturedDeadline time.Time
	deadlineFound    bool
	blockChan        chan struct{}
	cancelObserved   chan struct{}
}

func (m *mockTimeoutProtocolManager) Protocol() string {
	return m.protocol
}

func (m *mockTimeoutProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	m.mu.Lock()
	if dl, ok := ctx.Deadline(); ok {
		m.capturedDeadline = dl
		m.deadlineFound = true
	}
	block := m.blockChan
	m.mu.Unlock()

	if block != nil {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			if m.cancelObserved != nil {
				close(m.cancelObserved)
			}
			m.mu.Unlock()
			return ctx.Err()
		case <-block:
			return nil
		}
	}
	return nil
}

func (m *mockTimeoutProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if dl, ok := ctx.Deadline(); ok {
		m.capturedDeadline = dl
		m.deadlineFound = true
	}
	return nil
}

func (m *mockTimeoutProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return nil, nil
}

func (m *mockTimeoutProtocolManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}

func (m *mockTimeoutProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}

func (m *mockTimeoutProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}

func (m *mockTimeoutProtocolManager) getDeadline() (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.capturedDeadline, m.deadlineFound
}

func (m *mockTimeoutProtocolManager) resetDeadline() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.capturedDeadline = time.Time{}
	m.deadlineFound = false
}

func TestProductionRouter_EffectiveContextTimeouts(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	mgr := &mockTimeoutProtocolManager{protocol: "awg"}
	reg := manager.NewRegistry()
	reg.Register(mgr)

	h := handlers.NewHandlers(handlers.Dependencies{
		Config:   cfg,
		DB:       db,
		Registry: reg,
	})

	r := NewRouterWithOptions(Options{
		Config:   cfg,
		DB:       db,
		Handlers: h,
	})

	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:    "timeout-probe-server",
		Host:    "192.0.2.100",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed": true,
				"port":      "55424",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	newAuthReq := func(method, path string, body any) *http.Request {
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, reader)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID:   "admin-id",
			Username: "admin",
			Role:     models.RoleAdmin,
		}))
		req = req.WithContext(middleware.WithCSRFToken(req.Context(), "csrf-token-test"))
		req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "csrf-token-test"})
		req.Header.Set(middleware.CSRFHeaderName, "csrf-token-test")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req
	}

	// 1. /api/servers/{server_id}/install receives ~15 minute deadline
	t.Run("API Install route ~15m", func(t *testing.T) {
		mgr.resetDeadline()
		req := newAuthReq(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), models.InstallProtocolRequest{
			Protocol: "awg",
			Port:     "55424",
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		dl, found := mgr.getDeadline()
		if !found {
			t.Fatal("expected deadline to be set on install context")
		}
		remaining := time.Until(dl)
		if remaining < 14*time.Minute || remaining > 16*time.Minute {
			t.Fatalf("expected install context deadline ~15m, got remaining %v", remaining)
		}
	})

	// 2. Legacy /{server_id}/install receives ~15 minute deadline
	t.Run("Legacy Install route ~15m", func(t *testing.T) {
		mgr.resetDeadline()
		req := newAuthReq(http.MethodPost, fmt.Sprintf("/%d/install", serverID), models.InstallProtocolRequest{
			Protocol: "awg",
			Port:     "55424",
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		dl, found := mgr.getDeadline()
		if !found {
			t.Fatal("expected deadline to be set on legacy install context")
		}
		remaining := time.Until(dl)
		if remaining < 14*time.Minute || remaining > 16*time.Minute {
			t.Fatalf("expected legacy install context deadline ~15m, got remaining %v", remaining)
		}
	})

	// 3. /api/servers/{server_id}/uninstall receives ~5 minute deadline
	t.Run("API Uninstall route ~5m", func(t *testing.T) {
		mgr.resetDeadline()
		req := newAuthReq(http.MethodPost, fmt.Sprintf("/api/servers/%d/uninstall", serverID), models.ProtocolRequest{
			Protocol: "awg",
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		dl, found := mgr.getDeadline()
		if !found {
			t.Fatal("expected deadline to be set on uninstall context")
		}
		remaining := time.Until(dl)
		if remaining < 4*time.Minute || remaining > 6*time.Minute {
			t.Fatalf("expected uninstall context deadline ~5m, got remaining %v", remaining)
		}
	})

	// 4. Legacy /{server_id}/uninstall receives ~5 minute deadline
	t.Run("Legacy Uninstall route ~5m", func(t *testing.T) {
		mgr.resetDeadline()
		req := newAuthReq(http.MethodPost, fmt.Sprintf("/%d/uninstall", serverID), models.ProtocolRequest{
			Protocol: "awg",
		})
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		dl, found := mgr.getDeadline()
		if !found {
			t.Fatal("expected deadline to be set on legacy uninstall context")
		}
		remaining := time.Until(dl)
		if remaining < 4*time.Minute || remaining > 6*time.Minute {
			t.Fatalf("expected legacy uninstall context deadline ~5m, got remaining %v", remaining)
		}
	})

	// 5. Standard routes retain ~60-second deadline
	t.Run("Standard routes retain ~60s", func(t *testing.T) {
		var capturedStandard time.Time
		var standardFound bool
		r.Get("/test/standard_deadline_check", func(w http.ResponseWriter, req *http.Request) {
			capturedStandard, standardFound = req.Context().Deadline()
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test/standard_deadline_check", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		if !standardFound {
			t.Fatal("expected standard route context to carry a deadline")
		}
		remaining := time.Until(capturedStandard)
		if remaining < 55*time.Second || remaining > 65*time.Second {
			t.Fatalf("expected standard context deadline ~60s, got remaining %v", remaining)
		}
	})
}

func TestProductionRouter_RequestCancellation(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	mgr := &mockTimeoutProtocolManager{
		protocol:       "awg",
		blockChan:      make(chan struct{}),
		cancelObserved: make(chan struct{}),
	}
	reg := manager.NewRegistry()
	reg.Register(mgr)

	h := handlers.NewHandlers(handlers.Dependencies{
		Config:   cfg,
		DB:       db,
		Registry: reg,
	})

	r := NewRouterWithOptions(Options{
		Config:   cfg,
		DB:       db,
		Handlers: h,
	})

	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:    "cancel-probe-server",
		Host:    "192.0.2.101",
		SSHPort: 22,
		SSHUser: "root",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	body, _ := json.Marshal(models.InstallProtocolRequest{
		Protocol: "awg",
		Port:     "55424",
	})
	reqCtx, reqCancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body)).WithContext(reqCtx)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "admin-id",
		Username: "admin",
		Role:     models.RoleAdmin,
	}))
	req = req.WithContext(middleware.WithCSRFToken(req.Context(), "csrf-token-test"))
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "csrf-token-test"})
	req.Header.Set(middleware.CSRFHeaderName, "csrf-token-test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		reqCancel()
	}()

	r.ServeHTTP(rec, req)

	select {
	case <-mgr.cancelObserved:
		// cancellation successfully propagated to protocol manager
	case <-time.After(3 * time.Second):
		t.Fatal("expected client cancellation to immediately cancel handler context on production router")
	}

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 status when canceled, got %d", rec.Code)
	}
}
