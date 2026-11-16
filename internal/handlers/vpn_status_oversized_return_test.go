package handlers

// The oversized-return split must reach the response an administrator actually
// reads on /api/vpn/status, not only the Go struct. The producer-level values
// are proven in package vpn against the same DTO and JSON contract; this control
// proves the HTTP surface carries the keys and that an idle server reports zero
// rather than inventing loss or recovery.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func TestVPNStatusHandler_ExposesOversizedReturnSplit(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	h.vpnSvc = svc

	w := httptest.NewRecorder()
	h.VPNStatusHandler(w, httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		DropCategories map[string]any `json:"drop_categories"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status: %v", err)
	}

	want := map[string]float64{
		"return_packet_too_large":                   0,
		"return_packet_too_large_backend":           0,
		"return_packet_too_large_direct":            0,
		"return_packet_too_large_backend_max_bytes": 0,
		"return_packet_too_large_direct_max_bytes":  0,
	}
	for key, expected := range want {
		got, ok := body.DropCategories[key]
		if !ok {
			t.Fatalf("status response is missing drop_categories.%s: %s", key, w.Body.String())
		}
		if got != expected {
			t.Fatalf("drop_categories.%s = %v, want %v on an idle server", key, got, expected)
		}
	}
}
