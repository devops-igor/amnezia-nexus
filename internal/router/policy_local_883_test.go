package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The operator's IPv4 PROXY exception list, end to end through the admin API. This
// is the section's one input, so its round trip and its refusal are asserted at the
// real route rather than at the pure function.
func TestPolicyProxyExceptionsRoundTripAndRefusal(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	body, err := json.Marshal(map[string]any{
		"enabled":               false,
		"proxy_exceptions":      []string{"203.0.113.0/24", "198.51.100.7"},
		"sync_interval_seconds": 3600,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT proxy exceptions = %d; body=%s", w.Code, w.Body.String())
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
	entries, _ := got["proxy_exceptions"].([]any)
	if len(entries) != 2 || entries[0] != "203.0.113.0/24" || entries[1] != "198.51.100.7" {
		t.Fatalf("proxy_exceptions = %v", got["proxy_exceptions"])
	}
	// The read must not still advertise a source selection: there is none.
	if _, present := got["preset"]; present {
		t.Fatalf("GET still reports a source selection: %v", got["preset"])
	}

	// A domain line would be saved and never applied, so the API refuses it by name
	// and the stored record is untouched.
	bad, _ := json.Marshal(map[string]any{
		"enabled":               false,
		"proxy_exceptions":      []string{"ozon.ru"},
		"sync_interval_seconds": 3600,
	})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", bad))
	if w.Code != http.StatusBadRequest || !bytes.Contains(w.Body.Bytes(), []byte("proxy exception rejected")) {
		t.Fatalf("domain line in the exception list = %d %s", w.Code, w.Body.String())
	}
}
