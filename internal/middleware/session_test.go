package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

const testSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSessionMiddleware(t *testing.T) {
	sessionData := &models.SessionData{
		UserID:   "user-999",
		Username: "alice",
		Role:     models.RoleAdmin,
	}

	encodedCookie, err := security.EncodeSession(sessionData.ToMap(), testSecretKey)
	if err != nil {
		t.Fatalf("failed to encode session: %v", err)
	}

	middlewareFunc := Session(testSecretKey)

	var extractedSession *models.SessionData
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedSession = GetSession(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	// Case 1: Valid signed cookie
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: encodedCookie,
	})
	w := httptest.NewRecorder()
	middlewareFunc(testHandler).ServeHTTP(w, req)

	if extractedSession == nil || extractedSession.UserID != "user-999" || extractedSession.Role != models.RoleAdmin {
		t.Errorf("expected session to be extracted, got %+v", extractedSession)
	}

	// Case 2: Tampered cookie
	extractedSession = nil
	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: encodedCookie + "tampered",
	})
	w = httptest.NewRecorder()
	middlewareFunc(testHandler).ServeHTTP(w, req)

	if extractedSession != nil {
		t.Errorf("expected nil session for tampered cookie, got %+v", extractedSession)
	}

	// Case 3: Missing cookie
	extractedSession = nil
	req = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	w = httptest.NewRecorder()
	middlewareFunc(testHandler).ServeHTTP(w, req)

	if extractedSession != nil {
		t.Errorf("expected nil session for missing cookie, got %+v", extractedSession)
	}

	// Case 4: Unauthenticated session cookie (e.g., captcha id)
	extractedSession = nil
	guestSession := &models.SessionData{
		CaptchaID: "captcha-5678",
	}
	encodedGuestCookie, err := security.EncodeSession(guestSession.ToMap(), testSecretKey)
	if err != nil {
		t.Fatalf("failed to encode guest session: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.AddCookie(&http.Cookie{
		Name:  SessionCookieName,
		Value: encodedGuestCookie,
	})
	w = httptest.NewRecorder()
	middlewareFunc(testHandler).ServeHTTP(w, req)

	if extractedSession == nil || extractedSession.CaptchaID != "captcha-5678" {
		t.Errorf("expected guest session with captcha answer to be extracted, got %+v", extractedSession)
	}
	if extractedSession.IsAuthenticated() {
		t.Errorf("expected guest session to not be authenticated")
	}
}

func TestSetAndClearSessionCookie(t *testing.T) {
	// Install a policy with a TLS certificate present: cookies must be Secure.
	policy := NewSessionCookiePolicy(false)
	policy.SetTLSCertPresent(true)
	InstallSessionCookiePolicy(policy)
	defer InstallSessionCookiePolicy(nil)

	w := httptest.NewRecorder()
	sessionData := &models.SessionData{
		UserID:   "u-1",
		Username: "bob",
		Role:     models.RoleUser,
	}

	if err := SetSessionCookie(w, sessionData, testSecretKey, 3600); err != nil {
		t.Fatalf("SetSessionCookie failed: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != SessionCookieName || cookies[0].Value == "" {
		t.Fatalf("expected 1 session cookie, got %+v", cookies)
	}
	if !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Errorf("expected cookie to be HttpOnly and Secure")
	}

	// Clear cookie (Secure flag mirrors the policy)
	wClear := httptest.NewRecorder()
	ClearSessionCookie(wClear)
	clearCookies := wClear.Result().Cookies()
	if len(clearCookies) != 1 || clearCookies[0].MaxAge != -1 || clearCookies[0].Value != "" {
		t.Errorf("ClearSessionCookie failed, got %+v", clearCookies)
	}
	if !clearCookies[0].Secure {
		t.Errorf("expected clear cookie Secure flag to mirror policy (true)")
	}
}

func TestRequireAuth(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	protected := RequireAuth(okHandler)

	// API unauthenticated -> 401 JSON
	reqAPI := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	wAPI := httptest.NewRecorder()
	protected.ServeHTTP(wAPI, reqAPI)
	if wAPI.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauth API request, got %d", wAPI.Code)
	}
	var errResp ErrorResponse
	_ = json.Unmarshal(wAPI.Body.Bytes(), &errResp)
	if errResp.Error != "unauthorized" {
		t.Errorf("expected error=unauthorized, got %q", errResp.Error)
	}

	// HTML unauthenticated -> 302 to /login
	reqHTML := httptest.NewRequest(http.MethodGet, "/my", nil)
	reqHTML.Header.Set("Accept", "text/html")
	wHTML := httptest.NewRecorder()
	protected.ServeHTTP(wHTML, reqHTML)
	if wHTML.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for unauth HTML request, got %d", wHTML.Code)
	}
	if loc := wHTML.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}

	// Authenticated -> 200 OK
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	ctx := WithSession(reqAuth.Context(), &models.SessionData{UserID: "u-1", Role: models.RoleUser})
	wAuth := httptest.NewRecorder()
	protected.ServeHTTP(wAuth, reqAuth.WithContext(ctx))
	if wAuth.Code != http.StatusOK {
		t.Errorf("expected 200 for authenticated user, got %d", wAuth.Code)
	}
}

func TestRequireAdmin(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	adminProtected := RequireAdmin(okHandler)

	// Unauthenticated -> 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	wUnauth := httptest.NewRecorder()
	adminProtected.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated, got %d", wUnauth.Code)
	}

	// Authenticated regular user -> 403
	reqUser := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	ctxUser := WithSession(reqUser.Context(), &models.SessionData{UserID: "u-1", Role: models.RoleUser})
	wUser := httptest.NewRecorder()
	adminProtected.ServeHTTP(wUser, reqUser.WithContext(ctxUser))
	if wUser.Code != http.StatusForbidden {
		t.Errorf("expected 403 for regular user, got %d", wUser.Code)
	}

	// Authenticated admin user -> 200
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	ctxAdmin := WithSession(reqAdmin.Context(), &models.SessionData{UserID: "admin-1", Role: models.RoleAdmin})
	wAdmin := httptest.NewRecorder()
	adminProtected.ServeHTTP(wAdmin, reqAdmin.WithContext(ctxAdmin))
	if wAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 for admin user, got %d", wAdmin.Code)
	}
}

func TestRequireAdminOrSupport(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	supportProtected := RequireAdminOrSupport(okHandler)

	// User role -> 403
	reqUser := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	ctxUser := WithSession(reqUser.Context(), &models.SessionData{UserID: "u-1", Role: models.RoleUser})
	wUser := httptest.NewRecorder()
	supportProtected.ServeHTTP(wUser, reqUser.WithContext(ctxUser))
	if wUser.Code != http.StatusForbidden {
		t.Errorf("expected 403 for user role, got %d", wUser.Code)
	}

	// Support role -> 200
	reqSupport := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	ctxSupport := WithSession(reqSupport.Context(), &models.SessionData{UserID: "supp-1", Role: models.RoleSupport})
	wSupport := httptest.NewRecorder()
	supportProtected.ServeHTTP(wSupport, reqSupport.WithContext(ctxSupport))
	if wSupport.Code != http.StatusOK {
		t.Errorf("expected 200 for support role, got %d", wSupport.Code)
	}

	// Admin role -> 200
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	ctxAdmin := WithSession(reqAdmin.Context(), &models.SessionData{UserID: "adm-1", Role: models.RoleAdmin})
	wAdmin := httptest.NewRecorder()
	supportProtected.ServeHTTP(wAdmin, reqAdmin.WithContext(ctxAdmin))
	if wAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 for admin role, got %d", wAdmin.Code)
	}
}

// TestRequireAuthPlusAdminOrSupportChain proves the full middleware stack
// protecting /api/vpn/sessions (issue #191): in production the /api/vpn group
// sits inside a RequireAuth-wrapped tree with RequireAdminOrSupport applied
// on top. The chain — not the handler — must answer 401 for anonymous
// callers and 403 for authenticated non-privileged users.
func TestRequireAuthPlusAdminOrSupportChain(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chain := RequireAuth(RequireAdminOrSupport(okHandler))

	// Unauthenticated -> 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil)
	wUnauth := httptest.NewRecorder()
	chain.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated caller, got %d", wUnauth.Code)
	}

	// Authenticated regular user -> 403
	reqUser := httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil)
	ctxUser := WithSession(reqUser.Context(), &models.SessionData{UserID: "u-1", Role: models.RoleUser})
	wUser := httptest.NewRecorder()
	chain.ServeHTTP(wUser, reqUser.WithContext(ctxUser))
	if wUser.Code != http.StatusForbidden {
		t.Errorf("expected 403 for authenticated regular user, got %d", wUser.Code)
	}

	// Authenticated admin -> 200
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil)
	ctxAdmin := WithSession(reqAdmin.Context(), &models.SessionData{UserID: "adm-1", Role: models.RoleAdmin})
	wAdmin := httptest.NewRecorder()
	chain.ServeHTTP(wAdmin, reqAdmin.WithContext(ctxAdmin))
	if wAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 for admin, got %d", wAdmin.Code)
	}

	// Authenticated support -> 200
	reqSupport := httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil)
	ctxSupport := WithSession(reqSupport.Context(), &models.SessionData{UserID: "supp-1", Role: models.RoleSupport})
	wSupport := httptest.NewRecorder()
	chain.ServeHTTP(wSupport, reqSupport.WithContext(ctxSupport))
	if wSupport.Code != http.StatusOK {
		t.Errorf("expected 200 for support, got %d", wSupport.Code)
	}
}

func TestRequireAuth_SessionVersionRevocation(t *testing.T) {
	defer SetUserLookup(nil)

	dbUser := &models.User{
		ID:             "u-revoked",
		Username:       "bob",
		Role:           models.RoleUser,
		Enabled:        true,
		SessionVersion: 2,
	}

	SetUserLookup(func(ctx context.Context, userID string) (*models.User, error) {
		if userID == dbUser.ID {
			return dbUser, nil
		}
		return nil, nil
	})

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	protected := RequireAuth(okHandler)

	// 1. Session with matching session_version (2 == 2) -> 200 OK
	reqValid := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	ctxValid := WithSession(reqValid.Context(), &models.SessionData{
		UserID:         "u-revoked",
		Role:           models.RoleUser,
		SessionVersion: 2,
	})
	wValid := httptest.NewRecorder()
	protected.ServeHTTP(wValid, reqValid.WithContext(ctxValid))
	if wValid.Code != http.StatusOK {
		t.Errorf("expected 200 for matching session version, got %d", wValid.Code)
	}

	// 2. Stale session with older session_version (1 < 2) -> 401 Unauthorized + cookie cleared
	reqStale := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	ctxStale := WithSession(reqStale.Context(), &models.SessionData{
		UserID:         "u-revoked",
		Role:           models.RoleUser,
		SessionVersion: 1,
	})
	wStale := httptest.NewRecorder()
	protected.ServeHTTP(wStale, reqStale.WithContext(ctxStale))
	if wStale.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for stale session version, got %d", wStale.Code)
	}
	cookies := wStale.Result().Cookies()
	cleared := false
	for _, c := range cookies {
		if c.Name == SessionCookieName && c.MaxAge == -1 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Errorf("expected session cookie to be cleared for revoked session")
	}

	// 3. Stale session on HTML page -> 302 to /login + cookie cleared
	reqHTML := httptest.NewRequest(http.MethodGet, "/my", nil)
	reqHTML.Header.Set("Accept", "text/html")
	ctxHTML := WithSession(reqHTML.Context(), &models.SessionData{
		UserID:         "u-revoked",
		Role:           models.RoleUser,
		SessionVersion: 1,
	})
	wHTML := httptest.NewRecorder()
	protected.ServeHTTP(wHTML, reqHTML.WithContext(ctxHTML))
	if wHTML.Code != http.StatusFound {
		t.Errorf("expected 302 for stale session HTML request, got %d", wHTML.Code)
	}
	if loc := wHTML.Header().Get("Location"); loc != "/login" {
		t.Errorf("expected redirect to /login, got %q", loc)
	}

	// 4. Legacy session without session_version (0 -> effective 1) on user with SessionVersion 2 -> 401
	reqLegacyStale := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	ctxLegacyStale := WithSession(reqLegacyStale.Context(), &models.SessionData{
		UserID:         "u-revoked",
		Role:           models.RoleUser,
		SessionVersion: 0,
	})
	wLegacyStale := httptest.NewRecorder()
	protected.ServeHTTP(wLegacyStale, reqLegacyStale.WithContext(ctxLegacyStale))
	if wLegacyStale.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for legacy session against bumped user, got %d", wLegacyStale.Code)
	}

	// 5. Legacy session without session_version (0 -> effective 1) on user with SessionVersion 1 -> 200 OK
	dbUser.SessionVersion = 1
	reqLegacyValid := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	ctxLegacyValid := WithSession(reqLegacyValid.Context(), &models.SessionData{
		UserID:         "u-revoked",
		Role:           models.RoleUser,
		SessionVersion: 0,
	})
	wLegacyValid := httptest.NewRecorder()
	protected.ServeHTTP(wLegacyValid, reqLegacyValid.WithContext(ctxLegacyValid))
	if wLegacyValid.Code != http.StatusOK {
		t.Errorf("expected 200 for legacy session against baseline user, got %d", wLegacyValid.Code)
	}
}
