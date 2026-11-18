package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyExcludedDomainsRoundTripAndOverlap(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	body, err := json.Marshal(map[string]any{
		"enabled": false, "preset": "aggregate",
		"local_entries":         []string{"local.example"},
		"excluded_domains":      []string{"internal.api.example.com", "*.corp.example"},
		"sync_interval_seconds": 3600,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT excluded domains = %d; body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d", w.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	excluded, _ := got["excluded_domains"].([]any)
	if len(excluded) != 2 || excluded[0] != "internal.api.example.com" || excluded[1] != "*.corp.example" {
		t.Fatalf("excluded_domains = %v", got["excluded_domains"])
	}
	local, _ := got["local_entries"].([]any)
	if len(local) != 1 || local[0] != "local.example" {
		t.Fatalf("local_entries = %v", got["local_entries"])
	}

	// A local entry that is also excluded cannot be both proxied and direct.
	bad, _ := json.Marshal(map[string]any{
		"enabled": false, "preset": "aggregate",
		"local_entries":         []string{"api.example.com"},
		"excluded_domains":      []string{"example.com"},
		"sync_interval_seconds": 3600,
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", bad))
	if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte("excluded_domains")) {
		t.Fatalf("local/exclusion overlap = %d %s", w.Code, w.Body.String())
	}
}
