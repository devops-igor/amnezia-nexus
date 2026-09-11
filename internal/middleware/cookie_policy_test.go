package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

func newTestSessionCookie(t *testing.T) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	session := &models.SessionData{UserID: "u-1", Username: "alice", Role: models.RoleUser}
	if err := SetSessionCookie(w, session, testSecretKey, 3600); err != nil {
		t.Fatalf("SetSessionCookie failed: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %+v", cookies)
	}
	return cookies[0]
}

// TestCookiePolicySecureFollowsTLS: with a TLS certificate loaded every
// SetSessionCookie path emits Secure=true; without one, Secure=false.
func TestCookiePolicySecureFollowsTLS(t *testing.T) {
	policy := NewSessionCookiePolicy(false)

	policy.SetTLSCertPresent(true)
	InstallSessionCookiePolicy(policy)
	defer InstallSessionCookiePolicy(nil)

	c := newTestSessionCookie(t)
	if !c.Secure {
		t.Errorf("expected Secure=true with TLS certificate loaded, got false")
	}

	policy.SetTLSCertPresent(false)
	c = newTestSessionCookie(t)
	if c.Secure {
		t.Errorf("expected Secure=false without TLS certificate, got true")
	}
}

// TestCookiePolicyInsecureOverride: COOKIE_INSECURE=1 forces Secure=false
// even when a TLS certificate is loaded.
func TestCookiePolicyInsecureOverride(t *testing.T) {
	policy := NewSessionCookiePolicy(true)
	policy.SetTLSCertPresent(true)
	InstallSessionCookiePolicy(policy)
	defer InstallSessionCookiePolicy(nil)

	if policy.Secure() {
		t.Errorf("override active: Secure() must be false even with TLS cert")
	}
	if policy.Source() != CookieSecureFromOverride {
		t.Errorf("expected source override, got %q", policy.Source())
	}

	c := newTestSessionCookie(t)
	if c.Secure {
		t.Errorf("expected Secure=false under COOKIE_INSECURE override, got true")
	}
}

// TestCookiePolicyReloadTransitions: cert reload transitions the flag and the
// atomic read is safe for concurrent requests (run with -race).
func TestCookiePolicyReloadTransitions(t *testing.T) {
	policy := NewSessionCookiePolicy(false)
	InstallSessionCookiePolicy(policy)
	defer InstallSessionCookiePolicy(nil)

	policy.SetTLSCertPresent(true)
	if !policy.Secure() {
		t.Fatalf("expected Secure=true after cert load")
	}
	policy.SetTLSCertPresent(false)
	if policy.Secure() {
		t.Fatalf("expected Secure=false after cert removal")
	}
	policy.SetTLSCertPresent(true)
	if !policy.Secure() {
		t.Fatalf("expected Secure=true after cert re-load")
	}

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 500; j++ {
				_ = policy.Secure()
			}
		}()
	}
	policy.SetTLSCertPresent(false)
	for i := 0; i < 8; i++ {
		<-done
	}
}

// TestLoadSessionCookiePolicySeedsFromLookup: initial flag is seeded from the
// TLS state lookup; lookup errors degrade to Secure=false without failing.
func TestLoadSessionCookiePolicySeedsFromLookup(t *testing.T) {
	lookup := func(context.Context) (bool, error) { return true, nil }
	policy := LoadSessionCookiePolicy(context.Background(), false, lookup)
	defer InstallSessionCookiePolicy(nil)
	if !policy.Secure() {
		t.Errorf("expected policy seeded Secure=true from TLS lookup")
	}

	failing := func(context.Context) (bool, error) { return false, errors.New("db unavailable") }
	policy = LoadSessionCookiePolicy(context.Background(), false, failing)
	if policy.Secure() {
		t.Errorf("expected Secure=false when TLS lookup fails")
	}

	override := LoadSessionCookiePolicy(context.Background(), true, lookup)
	if override.Secure() || override.Source() != CookieSecureFromOverride {
		t.Errorf("expected override policy to force Secure=false")
	}
}

// TestSetSessionCookieDefaultsSecureOff: with no policy installed (unit-test
// default) cookies are not Secure — the safe default for plain-HTTP dev.
func TestSetSessionCookieDefaultsSecureOff(t *testing.T) {
	InstallSessionCookiePolicy(nil)
	defer InstallSessionCookiePolicy(nil)

	c := newTestSessionCookie(t)
	if c.Secure {
		t.Errorf("expected default policy Secure=false, got true")
	}
	if !c.HttpOnly {
		t.Errorf("expected HttpOnly=true regardless of policy")
	}
}
