package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func TestVPNConfigHTTPDoesNotExposeOrAcceptPortalKeys(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	router := setupFullVPNRouter(h)
	stored, err := db.GetVPNConfig(t.Context())
	if err != nil || stored.ServerPrivateKey == "" {
		t.Fatalf("initial portal key unavailable: %v", err)
	}
	plain, err := security.DecryptCredential(stored.ServerPrivateKey, db.SecretKey())
	if err != nil || plain == "" {
		t.Fatalf("initial portal key is not encrypted: %v", err)
	}

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET config: %d", get.Code)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(get.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, present := response["server_private_key"]; present || bytes.Contains(get.Body.Bytes(), []byte(plain)) || bytes.Contains(get.Body.Bytes(), []byte(stored.ServerPrivateKey)) {
		t.Fatal("GET config exposed the portal private key")
	}
	if _, present := response["server_public_key"]; !present {
		t.Fatal("GET config omitted the public key")
	}

	for _, body := range []string{
		`{"server_private_key":"attacker"}`,
		`{"SERVER_PRIVATE_KEY":null}`,
		`{"server_public_key":"attacker"}`,
	} {
		put := httptest.NewRecorder()
		router.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewBufferString(body)))
		if put.Code != http.StatusBadRequest {
			t.Fatalf("key update %s returned %d", body, put.Code)
		}
	}

	put := httptest.NewRecorder()
	router.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewBufferString(`{"public_endpoint":"vpn.example.test"}`)))
	if put.Code != http.StatusOK {
		t.Fatalf("ordinary update: %d %s", put.Code, put.Body.String())
	}
	after, err := db.GetVPNConfig(t.Context())
	if err != nil || after.ServerPrivateKey != stored.ServerPrivateKey || after.ServerPublicKey != stored.ServerPublicKey {
		t.Fatalf("HTTP update altered portal identity: %v", err)
	}
}
