package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestServerEnrollment_BracketedIPv6 verifies that enrolling a server with a bracketed IPv6
// address normalizes the host to an unbracketed representation, preventing double brackets
// in subsequent SSH address construction.
func TestServerEnrollment_BracketedIPv6(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	r := setupFullServerRouter(h)

	// 1. Enroll server with bracketed IPv6 address
	const bracketedHost = "[2001:db8::10]"
	const unbracketedHost = "2001:db8::10"

	enrollBody, err := json.Marshal(models.ConfirmFingerprintRequest{
		AddServerRequest: models.AddServerRequest{
			Host:     bracketedHost,
			SSHPort:  22,
			Username: "root",
			Password: "secretPass123!",
			Name:     "IPv6 Enrollment Test Server",
		},
		Fingerprint: "SHA256:abc123mockfingerprint",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/servers/confirm-fingerprint", bytes.NewReader(enrollBody))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on ConfirmFingerprintHandler, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	serverIDFloat, ok := resp["server_id"].(float64)
	if !ok || serverIDFloat <= 0 {
		t.Fatalf("expected positive server_id in response, got %v", resp["server_id"])
	}
	serverID := int64(serverIDFloat)

	// 2. Fetch server from DB and verify Host is normalized (unbracketed)
	server, err := db.GetServer(context.Background(), serverID)
	if err != nil {
		t.Fatalf("db.GetServer failed: %v", err)
	}
	if server == nil {
		t.Fatal("server not found in database")
	}
	if server.Host != unbracketedHost {
		t.Fatalf("expected server.Host in DB to be normalized to %q, got %q", unbracketedHost, server.Host)
	}

	// 3. Verify SSH client construction from server models.Server instance
	sshClient := ssh.NewClient(ssh.Config{
		Host:     server.Host,
		Port:     server.SSHPort,
		User:     server.SSHUser,
		Password: server.SSHPass,
	})
	if sshClient.GetHost() != unbracketedHost {
		t.Fatalf("expected SSH client GetHost() to be %q, got %q", unbracketedHost, sshClient.GetHost())
	}

	// 4. Defensively verify SSH client constructed directly with bracketed host normalizes it
	defensiveClient := ssh.NewClient(ssh.Config{
		Host: bracketedHost,
		Port: 22,
	})
	if defensiveClient.GetHost() != unbracketedHost {
		t.Fatalf("expected defensive SSH client GetHost() to be %q, got %q", unbracketedHost, defensiveClient.GetHost())
	}

	// 5. Verify net.JoinHostPort does NOT construct double brackets
	addr := net.JoinHostPort(strings.Trim(sshClient.GetHost(), "[]"), "22")
	if strings.Contains(addr, "[[") || strings.Contains(addr, "]]") {
		t.Fatalf("detected double brackets in SSH address: %q", addr)
	}
	expectedAddr := "[2001:db8::10]:22"
	if addr != expectedAddr {
		t.Fatalf("expected SSH address %q, got %q", expectedAddr, addr)
	}

	// 6. Test UpdateServerHostHandler with bracketed IPv6
	const updateBracketed = "  [2001:db8::20]  "
	const updateUnbracketed = "2001:db8::20"
	updateBody, _ := json.Marshal(models.UpdateServerHostRequest{
		Host: updateBracketed,
	})
	reqUpdate := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/host", serverID), bytes.NewReader(updateBody))
	wUpdate := httptest.NewRecorder()
	r.ServeHTTP(wUpdate, reqUpdate)

	if wUpdate.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on UpdateServerHostHandler, got %d: %s", wUpdate.Code, wUpdate.Body.String())
	}

	serverUpdated, err := db.GetServer(context.Background(), serverID)
	if err != nil {
		t.Fatalf("db.GetServer failed after update: %v", err)
	}
	if serverUpdated.Host != updateUnbracketed {
		t.Fatalf("expected updated server.Host to be %q, got %q", updateUnbracketed, serverUpdated.Host)
	}
}
