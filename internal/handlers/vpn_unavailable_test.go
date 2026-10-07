package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func TestUnavailableStatusKeepsSchemaVersion(t *testing.T) {
	h := &Handlers{}
	w := httptest.NewRecorder()
	h.VPNStatusHandler(w, httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil))
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := body["status_schema_version"]; got != float64(vpn.VPNStatusSchemaVersion) {
		t.Fatalf("unavailable status schema=%v, want %d", got, vpn.VPNStatusSchemaVersion)
	}
	if body["forwarder_available"] != false {
		t.Fatal("unavailable telemetry claimed available")
	}
}
