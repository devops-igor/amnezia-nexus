package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPolicyLocalEntriesRoundTripAndGuard(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	body, err := json.Marshal(map[string]any{
		"enabled": false, "preset": "aggregate",
		"local_entries":         []string{"local.example", "198.51.100.0/24"},
		"sync_interval_seconds": 3600,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT local entries = %d; body=%s", w.Code, w.Body.String())
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
	entries, _ := got["local_entries"].([]any)
	if len(entries) != 2 || entries[0] != "local.example" {
		t.Fatalf("local_entries = %v", got["local_entries"])
	}
	if got["preset"] != "aggregate" {
		t.Fatalf("preset = %v", got["preset"])
	}

	bad, _ := json.Marshal(map[string]any{
		"enabled": false, "preset": "aggregate",
		"local_entries":         []string{"ozon.ru"},
		"sync_interval_seconds": 3600,
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", bad))
	if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte("never-proxy guard")) {
		t.Fatalf("guarded local entry = %d %s", w.Code, w.Body.String())
	}
}
