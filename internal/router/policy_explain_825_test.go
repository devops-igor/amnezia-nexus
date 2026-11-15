package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Authorization and CSRF coverage for POST /api/vpn/policy/explain (#825).
//
// The endpoint carries no authorization logic of its own: it is mounted inside
// the existing /api/vpn/policy group. These tests therefore assert what the
// shared middlewares do, and compare the refusal against a neighbouring policy
// endpoint so "same refusal" is a measured fact rather than a claim.

func explainRequestBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"domain": "www.example"})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

// TestPolicyExplainRefusesNonAdminsLikeItsNeighbours checks that a non-admin
// receives the identical answer from the dry run and from the neighbouring
// policy endpoints: same status, same error code, same message.
func TestPolicyExplainRefusesNonAdminsLikeItsNeighbours(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)
	body := explainRequestBody(t)

	neighbours := []struct {
		method string
		target string
	}{
		{http.MethodPost, "/api/vpn/policy/sync"},
		{http.MethodGet, "/api/vpn/policy/stats"},
	}

	for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
		t.Run(string(role), func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, roleRequest(t, role, http.MethodPost, "/api/vpn/policy/explain", body))
			if w.Code != http.StatusForbidden {
				t.Fatalf("explain as %s = %d, want 403; body=%s", role, w.Code, w.Body.String())
			}
			explainBody := decodeJSON(t, w)
			for _, n := range neighbours {
				wn := httptest.NewRecorder()
				r.ServeHTTP(wn, roleRequest(t, role, n.method, n.target, nil))
				if wn.Code != w.Code {
					t.Fatalf("%s %s as %s = %d, want the explain refusal %d",
						n.method, n.target, role, wn.Code, w.Code)
				}
				if got := decodeJSON(t, wn); got["error"] != explainBody["error"] || got["message"] != explainBody["message"] {
					t.Fatalf("%s %s refusal = %v, want the explain refusal %v",
						n.method, n.target, got, explainBody)
				}
			}
		})
	}
}

// TestPolicyExplainRequiresAuthentication mirrors the neighbouring endpoints: an
// anonymous caller gets 401, not 403 and not an answer.
func TestPolicyExplainRequiresAuthentication(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	r := NewRouter(cfg, db, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/vpn/policy/explain", bytes.NewReader(explainRequestBody(t)))
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.WithCSRFToken(req.Context(), "token123")
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
	req.Header.Set(middleware.CSRFHeaderName, "token123")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req.WithContext(ctx))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous explain = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// TestPolicyExplainRequiresCSRF pins that the dry run is a mutating-method
// request for the CSRF middleware exactly like POST /sync: an admin session
// without the token pair is refused before the handler runs.
func TestPolicyExplainRequiresCSRF(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/vpn/policy/explain", bytes.NewReader(explainRequestBody(t)))
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "policy-admin",
		Role:   models.RoleAdmin,
	})
	ctx = middleware.WithCSRFToken(ctx, "token123")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req.WithContext(ctx))
	if w.Code != http.StatusForbidden {
		t.Fatalf("explain without a CSRF token = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// TestPolicyExplainRouteIsAdminReachable proves the route exists and is reachable
// for an admin: this router has no VPN service, so the handler's own 503 is the
// answer, which could not be produced by a missing route (404) or a refused
// authorization (403).
func TestPolicyExplainRouteIsAdminReachable(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPost, "/api/vpn/policy/explain", explainRequestBody(t)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin explain without a data plane = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	if out["error"] != "unavailable" {
		t.Errorf("error = %v, want unavailable", out["error"])
	}
}
