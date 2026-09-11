package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/security"
)

const xfpTestSecret = "xfp-test-secret-key-0123456789abcdef"

// installXFPTestPolicy installs a policy with the given TLS cert state for
// the duration of the test.
func installXFPTestPolicy(t *testing.T, tlsCertPresent bool) {
	t.Helper()
	p := NewSessionCookiePolicy(false)
	p.SetTLSCertPresent(tlsCertPresent)
	InstallSessionCookiePolicy(p)
	t.Cleanup(func() {
		cookiePolicyMu.Lock()
		sessionCookiePolicy = nil
		cookiePolicyMu.Unlock()
	})
}

// secureFlagOf extracts the Secure attribute of the session cookie.
func secureFlagOf(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c.Secure
		}
	}
	return false
}

// setCookieFor sets the session cookie for a request that already carries the
// secure-conn context flag (as if SecureConn middleware had run).
func setCookieFor(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	sess := &models.SessionData{Username: "u"}
	if err := setSessionCookie(w, sess, xfpTestSecret, 3600, r); err != nil {
		t.Fatalf("setSessionCookie failed: %v", err)
	}
	return w
}

// withSecureConnApplied simulates the router: SecureConn middleware derives
// the per-request flag from the resolver.
func withSecureConnApplied(req *http.Request, resolver *RealIPResolver) *http.Request {
	return req.WithContext(WithSecureConn(req.Context(), secureFromRequest(req, resolver)))
}

// TestSetSessionCookie_TrustedProxyXFPMatrix covers the issue #100 required
// cases: trusted proxy + XFP decision matrix, direct TLS, fallback path and
// the COOKIE_INSECURE override.
func TestSetSessionCookie_TrustedProxyXFPMatrix(t *testing.T) {
	resolver := NewRealIPResolver("10.0.0.0/8")

	tests := []struct {
		name        string
		remoteAddr  string
		xfp         string
		tls         bool
		tlsCertOn   bool // process-wide policy TLS state for the fallback path
		wantSecure  bool
		description string
	}{
		// Trusted proxy + XFP:https -> Secure (policy cert state irrelevant).
		{"trusted proxy + XFP:https -> Secure", "10.1.2.3:50000", "https", false, false, true, ""},
		// Trusted proxy + XFP:http -> no Secure.
		{"trusted proxy + XFP:http -> no Secure", "10.1.2.3:50000", "http", false, true, false, ""},
		// UNTRUSTED peer sending XFP:https -> header ignored, no Secure.
		{"untrusted peer + XFP:https ignored", "203.0.113.9:50000", "https", false, true, false, ""},
		// Direct TLS -> Secure (existing behavior preserved).
		{"direct TLS -> Secure", "203.0.113.5:44300", "", true, false, true, ""},
		// Panel-native TLS, no proxy headers -> Secure via policy fallback path.
		{"panel-native TLS, no proxy headers -> Secure", "203.0.113.5:44300", "", true, true, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installXFPTestPolicy(t, tt.tlsCertOn)
			req := httptest.NewRequest(http.MethodGet, "http://example.com/login", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xfp != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xfp)
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			req = withSecureConnApplied(req, resolver)
			w := setCookieFor(t, req)
			if got := secureFlagOf(w); got != tt.wantSecure {
				t.Errorf("Secure = %v, want %v", got, tt.wantSecure)
			}
		})
	}
}

// TestSetSessionCookie_COOKIEInsecureOverridesEverything verifies that
// COOKIE_INSECURE=1 forces Secure=false even for a trusted proxy + XFP:https.
func TestSetSessionCookie_COOKIEInsecureOverridesEverything(t *testing.T) {
	p := NewSessionCookiePolicy(true) // insecure override active
	InstallSessionCookiePolicy(p)
	t.Cleanup(func() {
		cookiePolicyMu.Lock()
		sessionCookiePolicy = nil
		cookiePolicyMu.Unlock()
	})

	resolver := NewRealIPResolver("10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:50000"
	req.Header.Set("X-Forwarded-Proto", "https")
	req = withSecureConnApplied(req, resolver)

	w := setCookieFor(t, req)
	if secureFlagOf(w) {
		t.Error("COOKIE_INSECURE override must force Secure=false even for trusted proxy + XFP:https")
	}
}

// TestSetSessionCookie_FallbackWhenNoContextFlag verifies the process-wide
// policy fallback when no per-request flag exists (tests, non-HTTP callers).
func TestSetSessionCookie_FallbackWhenNoContextFlag(t *testing.T) {
	installXFPTestPolicy(t, true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if secureFlagOf(setCookieFor(t, req)) != true {
		t.Error("expected fallback to policy (tlsHasCert=true) to yield Secure")
	}

	installXFPTestPolicy(t, false)
	if secureFlagOf(setCookieFor(t, req)) != false {
		t.Error("expected fallback to policy (tlsHasCert=false) to yield no Secure")
	}
}

// TestSetSessionCookieForRequest_Contract verifies the exported request-aware
// API end-to-end, including session payload round-trip.
func TestSetSessionCookieForRequest_Contract(t *testing.T) {
	installXFPTestPolicy(t, false)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:50000"
	req.Header.Set("X-Forwarded-Proto", "https")
	req = req.WithContext(WithSecureConn(req.Context(), true))

	w := httptest.NewRecorder()
	if err := SetSessionCookieForRequest(w, req, &models.SessionData{Username: "u"}, xfpTestSecret, 3600); err != nil {
		t.Fatalf("SetSessionCookieForRequest failed: %v", err)
	}
	if !secureFlagOf(w) {
		t.Error("expected Secure=true for trusted proxy + XFP:https via exported API")
	}
	c := w.Result().Cookies()[0]
	dataMap, err := security.DecodeSession(c.Value, xfpTestSecret)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dataMap["username"] != "u" {
		t.Errorf("expected username round-trip, got %+v", dataMap)
	}
}
