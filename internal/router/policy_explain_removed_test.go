package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPolicyExplainEndpointIsRemoved pins the removal of the #825 dry run. An
// authenticated administrator is the relevant caller: unauthenticated requests
// may still be refused by session middleware before routing.
func TestPolicyExplainEndpointIsRemoved(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	body, err := json.Marshal(map[string]string{"domain": "www.example"})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPost, "/api/vpn/policy/explain", body))
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin explain = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}
