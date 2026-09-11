package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/middleware"
)

// newTestRateLimiter builds a small per-minute limiter with the given burst
// for endpoint rate-limit tests.
func newTestRateLimiter(t *testing.T, burst int) *middleware.RateLimiter {
	t.Helper()
	rl := middleware.NewRateLimiterPerMinute(burst, burst)
	t.Cleanup(rl.Stop)
	return rl
}

// TestCaptchaEndpointRateLimitedPerIP verifies that GET /api/auth/captcha
// returns 429 after the configured burst for a single client IP (issue #84).
func TestCaptchaEndpointRateLimitedPerIP(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	// Small limiter: burst of 3 -> 4th request from the same IP gets 429.
	captchaLimiter := newTestRateLimiter(t, 3)
	r := NewRouterWithOptions(Options{
		Config:         cfg,
		DB:             db,
		CaptchaLimiter: captchaLimiter,
	})

	client := "192.0.2.50:40000"
	var lastCode int
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/captcha", nil)
		req.RemoteAddr = client
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after threshold, got %d", lastCode)
	}

	// A different client IP must still be served.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/captcha", nil)
	req.RemoteAddr = "192.0.2.51:40000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for a different client IP, got %d", w.Code)
	}
}

// TestShareAuthEndpointRateLimitedPerIP verifies that POST
// /api/share/{token}/auth is rate-limited per client IP (issue #84).
func TestShareAuthEndpointRateLimitedPerIP(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	shareAuthLimiter := newTestRateLimiter(t, 2)
	r := NewRouterWithOptions(Options{
		Config:           cfg,
		DB:               db,
		ShareAuthLimiter: shareAuthLimiter,
	})

	client := "192.0.2.60:41000"
	var lastCode int
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/share/sometoken/auth", nil)
		req.RemoteAddr = client
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after threshold, got %d", lastCode)
	}

	// Different client IP: passes the limiter and reaches the handler (404
	// for unknown token, not 429).
	req := httptest.NewRequest(http.MethodPost, "/api/share/sometoken/auth", nil)
	req.RemoteAddr = "192.0.2.61:41000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("expected different IP to pass limiter, got %d", w.Code)
	}
}
