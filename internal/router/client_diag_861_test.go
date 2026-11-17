package router

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Authorization and CSRF coverage for the per-client diagnosis endpoints
// (issue #861).
//
// The endpoints carry no authorization logic of their own: they are mounted
// inside the existing /api/vpn/policy group. These cases assert what the shared
// middlewares do AND that the refusal is identical to a neighbouring policy
// endpoint's, so "admin-only, like the rest of the group" is a measured fact.
//
// The GET picker is included on purpose: it is the endpoint that names sessions,
// and it must be refused to the support role that may read GET /api/vpn/sessions.

func clientDiagnosisRoute(method, target string) *http.Request {
	var body *bytes.Reader
	if method == http.MethodPost {
		body = bytes.NewReader([]byte(`{"session_id":"sess-1"}`))
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// TestClientDiagnosisRoutesRefuseNonAdminsLikeTheirNeighbours checks that a
// non-admin gets the identical refusal from both new routes and from the
// neighbouring policy endpoints.
func TestClientDiagnosisRoutesRefuseNonAdminsLikeTheirNeighbours(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	routes := []struct{ method, target string }{
		{http.MethodGet, "/api/vpn/policy/clients"},
		{http.MethodPost, "/api/vpn/policy/client-diagnosis"},
	}

	for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
		t.Run(string(role), func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, roleRequest(t, role, http.MethodGet, "/api/vpn/policy/stats", nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("neighbour stats as %s = %d, want 403; body=%s", role, w.Code, w.Body.String())
			}
			reference := decodeJSON(t, w)

			for _, route := range routes {
				w := httptest.NewRecorder()
				r.ServeHTTP(w, roleRequest(t, role, route.method, route.target, nil))
				if w.Code != http.StatusForbidden {
					t.Fatalf("%s %s as %s = %d, want 403; body=%s",
						route.method, route.target, role, w.Code, w.Body.String())
				}
				got := decodeJSON(t, w)
				if got["error"] != reference["error"] || got["detail"] != reference["detail"] {
					t.Errorf("%s %s refusal = %v, want the neighbouring refusal %v",
						route.method, route.target, got, reference)
				}
			}
		})
	}
}

// TestClientDiagnosisRoutesRequireAuthentication mirrors the neighbours: an
// anonymous caller gets 401, not 403 and not an answer.
func TestClientDiagnosisRoutesRequireAuthentication(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	r := NewRouter(cfg, db, nil)

	for _, route := range []struct{ method, target string }{
		{http.MethodGet, "/api/vpn/policy/clients"},
		{http.MethodPost, "/api/vpn/policy/client-diagnosis"},
	} {
		req := clientDiagnosisRoute(route.method, route.target)
		ctx := middleware.WithCSRFToken(req.Context(), "token123")
		req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
		req.Header.Set(middleware.CSRFHeaderName, "token123")

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(ctx))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s %s = %d, want 401; body=%s",
				route.method, route.target, w.Code, w.Body.String())
		}
	}
}

// TestClientDiagnosisPostRequiresCSRF pins that the diagnosis POST is treated as
// a mutating-method request by the CSRF middleware exactly like POST /sync: it
// reads stores, but a POST without the token pair is still refused before the
// handler runs.
func TestClientDiagnosisPostRequiresCSRF(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	req := clientDiagnosisRoute(http.MethodPost, "/api/vpn/policy/client-diagnosis")
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "policy-admin",
		Role:   models.RoleAdmin,
	})
	ctx = middleware.WithCSRFToken(ctx, "token123")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req.WithContext(ctx))
	if w.Code != http.StatusForbidden {
		t.Fatalf("client-diagnosis without a CSRF token = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// TestClientDiagnosisRoutesAreAdminReachable proves both routes exist: this
// router has no VPN service, so the handler's own 503 is the answer, which a
// missing route (404) or a refused authorization (403) could not produce.
func TestClientDiagnosisRoutesAreAdminReachable(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	for _, route := range []struct {
		method string
		target string
	}{
		{http.MethodGet, "/api/vpn/policy/clients"},
		{http.MethodPost, "/api/vpn/policy/client-diagnosis"},
	} {
		w := httptest.NewRecorder()
		var body []byte
		if route.method == http.MethodPost {
			body = []byte(`{"session_id":"sess-1"}`)
		}
		r.ServeHTTP(w, adminRequest(t, route.method, route.target, body))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s as admin = %d, want 503; body=%s", route.method, route.target, w.Code, w.Body.String())
		}
		out := decodeJSON(t, w)
		if out["error"] != "unavailable" {
			t.Errorf("%s error = %v, want unavailable", route.target, out["error"])
		}
	}
}
