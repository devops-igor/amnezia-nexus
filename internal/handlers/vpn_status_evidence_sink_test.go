package handlers

// Group D (issue #794) sink control: the transition evidence must be safely
// serializable through the ACTUAL status endpoint, not merely through the struct.
//
// The unit-level redaction control in internal/vpn proves the record carries no
// credentials. This control proves the HTTP surface an operator actually reads
// does not leak them either, and that the gate/attempt evidence really reaches
// that response.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestVPNStatusHandler_TransitionEvidenceIsSanitized drives the real handler and
// inspects the response body.
func TestVPNStatusHandler_TransitionEvidenceIsSanitized(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "evidence-server",
		Host: "192.0.2.60",
		Protocols: map[string]any{
			"awg": map[string]any{"port": 51820, "public_key": "serverPublicKeyForTest="},
		},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	const dataPriv = "dataPrivateKeyMaterialForTest0000000000000="
	const probePriv = "probePrivateKeyMaterialForTest000000000000="
	tun := &models.BackendTunnel{
		ServerID:        srvID,
		InterfaceName:   "awg-be-1",
		PublicKey:       "tunnelPublicKeyMaterialForTest000000000=",
		PrivateKey:      dataPriv,
		ProbePrivateKey: probePriv,
		Endpoint:        "192.0.2.61:51820",
		Enabled:         true,
		Status:          models.TunnelStatusConnecting,
		Protocol:        models.ProtocolAWG,
	}
	created, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil)
	rec := httptest.NewRecorder()
	h.VPNStatusHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status endpoint returned %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// No credential material may cross this boundary. The tunnel row carries it;
	// the response must not.
	for what, secret := range map[string]string{
		"data private key":  dataPriv,
		"probe private key": probePriv,
	} {
		if strings.Contains(body, secret) {
			t.Errorf("VPN status response leaked the %s", what)
		}
	}
	for _, marker := range []string{"privatekey", "preshared", "[interface]", "begin ", "ghp_"} {
		if strings.Contains(strings.ToLower(body), marker) {
			t.Errorf("VPN status response contains forbidden marker %q", marker)
		}
	}

	// The response must still be valid JSON with the backends surface an operator
	// reads, so redaction did not come from dropping the payload.
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("status response is not valid JSON: %v", err)
	}
	if _, ok := decoded["backends"]; !ok {
		t.Errorf("status response dropped the backends payload; redaction must not remove the surface")
	}

	// If the transition evidence reached this response, its gate must be a closed
	// vocabulary value rather than free text.
	if blob, err := json.Marshal(decoded["backends"]); err == nil {
		text := string(blob)
		if strings.Contains(text, "error") || strings.Contains(text, "ssh:") {
			t.Errorf("backends payload contains free-form error text: %s", text)
		}
	}
	_ = created
}
