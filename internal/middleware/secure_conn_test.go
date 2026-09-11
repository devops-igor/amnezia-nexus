package middleware

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// buildSecureReq builds a request with the given remote address and XFP header.
func buildSecureReq(remoteAddr, xfp string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/login", nil)
	req.RemoteAddr = remoteAddr
	if xfp != "" {
		req.Header.Set("X-Forwarded-Proto", xfp)
	}
	return req
}

func TestSecureFromRequest_DecisionMatrix(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xfp        string
		resolver   *RealIPResolver
		tls        bool
		want       bool
	}{
		{"direct TLS", "203.0.113.5:44300", "", nil, true, true},
		{"direct TLS beats XFP:http", "203.0.113.5:44300", "http", nil, true, true},
		{"trusted proxy + XFP https", "10.1.2.3:50000", "https", NewRealIPResolver("10.0.0.0/8"), false, true},
		{"trusted proxy + XFP https exact ip", "172.18.0.1:50000", "https", NewRealIPResolver("172.18.0.1"), false, true},
		{"trusted proxy + XFP http", "10.1.2.3:50000", "http", NewRealIPResolver("10.0.0.0/8"), false, false},
		{"trusted proxy + no XFP", "10.1.2.3:50000", "", NewRealIPResolver("10.0.0.0/8"), false, false},
		{"UNTRUSTED peer + XFP https is ignored", "203.0.113.9:50000", "https", NewRealIPResolver("10.0.0.0/8"), false, false},
		{"no resolver + XFP https is ignored", "10.1.2.3:50000", "https", nil, false, false},
		{"nil request", "", "", NewRealIPResolver("10.0.0.0/8"), false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildSecureReq(tt.remoteAddr, tt.xfp)
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.remoteAddr == "" {
				req = nil
			}
			if got := secureFromRequest(req, tt.resolver); got != tt.want {
				t.Errorf("secureFromRequest = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecureConnMiddlewareStoresContextFlag(t *testing.T) {
	resolver := NewRealIPResolver("10.0.0.0/8")
	handler := SecureConn(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure, ok := IsSecureConn(r.Context())
		if !ok {
			t.Error("expected secure-conn flag in context")
		}
		if w.Header().Get("X-Want-Secure") == "1" && !secure {
			t.Error("expected secure=true")
		}
		if w.Header().Get("X-Want-Secure") == "0" && secure {
			t.Error("expected secure=false")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Trusted proxy + XFP https -> secure
	req := buildSecureReq("10.1.2.3:50000", "https")
	req.Header.Set("X-Want-Secure", "1")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Untrusted peer + XFP https -> not secure
	req2 := buildSecureReq("203.0.113.9:50000", "https")
	req2.Header.Set("X-Want-Secure", "0")
	handler.ServeHTTP(httptest.NewRecorder(), req2)
}

func TestIsSecureConn_NoFlag(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := IsSecureConn(req.Context()); ok {
		t.Error("expected no flag when SecureConn middleware did not run")
	}
	if _, ok := IsSecureConn(context.TODO()); ok {
		t.Error("nil context should report no flag")
	}
}
