package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCSRFMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	csrfMiddleware := CSRF(false)(okHandler)

	// 1. Safe GET request without cookie -> sets cookie and succeeds
	reqGet := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	wGet := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(wGet, reqGet)

	if wGet.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", wGet.Code)
	}
	cookies := wGet.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatalf("expected CSRF cookie to be issued on GET request")
	}
	if csrfCookie.HttpOnly {
		t.Errorf("CSRF cookie must not be HttpOnly (client JS must read it)")
	}

	validToken := csrfCookie.Value

	// 2. State-mutating POST with matching header -> 200 OK
	reqPostValid := httptest.NewRequest(http.MethodPost, "/api/servers/add", nil)
	reqPostValid.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: validToken})
	reqPostValid.Header.Set(CSRFHeaderName, validToken)
	wPostValid := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(wPostValid, reqPostValid)

	if wPostValid.Code != http.StatusOK {
		t.Errorf("expected 200 for valid CSRF POST, got %d", wPostValid.Code)
	}

	// 3. State-mutating POST with matching form field -> 200 OK
	form := url.Values{}
	form.Set(CSRFFormField, validToken)
	form.Set("name", "server-1")
	reqPostForm := httptest.NewRequest(http.MethodPost, "/api/servers/add", strings.NewReader(form.Encode()))
	reqPostForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqPostForm.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: validToken})
	wPostForm := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(wPostForm, reqPostForm)

	if wPostForm.Code != http.StatusOK {
		t.Errorf("expected 200 for valid form CSRF POST, got %d", wPostForm.Code)
	}

	// 4. State-mutating POST with missing header/form -> 403 Forbidden
	reqPostMissing := httptest.NewRequest(http.MethodPost, "/api/servers/add", nil)
	reqPostMissing.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: validToken})
	wPostMissing := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(wPostMissing, reqPostMissing)

	if wPostMissing.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing CSRF header, got %d", wPostMissing.Code)
	}

	// 5. State-mutating POST with mismatched token -> 403 Forbidden
	reqPostMismatch := httptest.NewRequest(http.MethodPost, "/api/servers/add", nil)
	reqPostMismatch.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: validToken})
	reqPostMismatch.Header.Set(CSRFHeaderName, "invalid_csrf_token_value_here")
	wPostMismatch := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(wPostMismatch, reqPostMismatch)

	if wPostMismatch.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched CSRF token, got %d", wPostMismatch.Code)
	}

	// 6. Explicit exemptions -> 200 OK without CSRF header
	exemptions := []string{
		"/api/auth/login",
		"/api/auth/setup",
		"/api/share/xyz123token/auth",
	}
	for _, path := range exemptions {
		t.Run("Exempt: "+path, func(t *testing.T) {
			reqExempt := httptest.NewRequest(http.MethodPost, path, nil)
			wExempt := httptest.NewRecorder()
			csrfMiddleware.ServeHTTP(wExempt, reqExempt)
			if wExempt.Code != http.StatusOK {
				t.Errorf("expected 200 for exempt path %s, got %d", path, wExempt.Code)
			}
		})
	}
}

// TestCSRFRejectsTrace verifies TRACE is explicitly rejected with 405 at the
// middleware level (defense-in-depth), independent of router method matching.
func TestCSRFRejectsTrace(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler must not run for TRACE requests")
		w.WriteHeader(http.StatusOK)
	})
	csrfMiddleware := CSRF(false)(okHandler)

	req := httptest.NewRequest(http.MethodTrace, "/api/health", nil)
	// Even with a valid CSRF cookie present, TRACE is rejected outright.
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "some-token"})
	req.Header.Set(CSRFHeaderName, "some-token")
	w := httptest.NewRecorder()
	csrfMiddleware.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for TRACE, got %d", w.Code)
	}
}

// TestIsSafeHTTPMethod: safe set is exactly GET, HEAD, OPTIONS — TRACE and
// everything else must be excluded.
func TestIsSafeHTTPMethod(t *testing.T) {
	safe := map[string]bool{
		http.MethodGet:     true,
		http.MethodHead:    true,
		http.MethodOptions: true,
	}
	unsafe := []string{
		http.MethodTrace,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		"PROPFIND",
		"",
	}
	for m, want := range safe {
		if got := isSafeHTTPMethod(m); got != want {
			t.Errorf("isSafeHTTPMethod(%q) = %v, want %v", m, got, want)
		}
	}
	for _, m := range unsafe {
		if isSafeHTTPMethod(m) {
			t.Errorf("isSafeHTTPMethod(%q) = true, must be false", m)
		}
	}
	if isTraceMethod(http.MethodTrace) != true || isTraceMethod(http.MethodGet) != false {
		t.Errorf("isTraceMethod boundary broken")
	}
}

// TestRejectTraceMiddleware: the standalone middleware also blocks TRACE with
// 405 and passes everything else through.
func TestRejectTraceMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	traceBlocked := RejectTrace(okHandler)

	reqTrace := httptest.NewRequest(http.MethodTrace, "/anything", nil)
	wTrace := httptest.NewRecorder()
	traceBlocked.ServeHTTP(wTrace, reqTrace)
	if wTrace.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for TRACE, got %d", wTrace.Code)
	}

	reqGet := httptest.NewRequest(http.MethodGet, "/anything", nil)
	wGet := httptest.NewRecorder()
	traceBlocked.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Errorf("expected 200 for GET through RejectTrace, got %d", wGet.Code)
	}
}

func TestIsCSRFExempt(t *testing.T) {
	if !IsCSRFExempt(http.MethodGet, "/api/servers") {
		t.Errorf("GET should always be exempt")
	}
	if !IsCSRFExempt(http.MethodPost, "/api/auth/login") {
		t.Errorf("POST /api/auth/login should be exempt")
	}
	if !IsCSRFExempt(http.MethodPost, "/api/auth/setup") {
		t.Errorf("POST /api/auth/setup should be exempt")
	}
	if !IsCSRFExempt(http.MethodPost, "/api/share/abc123token/auth") {
		t.Errorf("POST /api/share/{token}/auth should be exempt")
	}
	if IsCSRFExempt(http.MethodPost, "/api/servers/add") {
		t.Errorf("POST /api/servers/add should NOT be exempt")
	}
	if IsCSRFExempt(http.MethodDelete, "/api/users/123/delete") {
		t.Errorf("DELETE /api/users/123/delete should NOT be exempt")
	}
}
