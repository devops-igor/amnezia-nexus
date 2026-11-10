package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	gossh "golang.org/x/crypto/ssh"
)

func rework4Signer(t *testing.T) gossh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// Actual SSH handshake, not a callback-only mock: authentication must not run
// until the administrator names the presented identity.
func TestRework4HostIdentityBeforeAuthentication(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	signer := rework4Signer(t)
	var authentications atomic.Int32
	cfg := &gossh.ServerConfig{PasswordCallback: func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) { authentications.Add(1); return nil, nil }}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			server, _, _, err := gossh.NewServerConn(conn, cfg)
			if err == nil {
				_ = server.Close()
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	h.SetSSHDialerForTest(nil)
	req := GigahostDeployRequest{SSHPort: port, SSHPassword: "fixture-only", ConfirmHostKey: true}
	_, err = h.verifyDeploySSHAccess(t.Context(), "127.0.0.1", req)
	var required *ssh.ErrFingerprintRequired
	if !errors.As(err, &required) || required.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("missing typed fingerprint challenge: %v", err)
	}
	if authentications.Load() != 0 {
		t.Fatal("credentials sent before confirmation")
	}
	req.ExpectedFingerprint = required.Fingerprint
	fp, err := h.verifyDeploySSHAccess(t.Context(), "127.0.0.1", req)
	if err != nil || fp != required.Fingerprint || authentications.Load() != 1 {
		t.Fatalf("confirmed handshake failed: %v", err)
	}
	server, err := h.registerDeployServer(t.Context(), req, nil, 0, 999, "127.0.0.1", fp)
	if err != nil {
		t.Fatal(err)
	}
	other := rework4Signer(t).PublicKey()
	req.ExpectedFingerprint = ssh.FingerprintSHA256(other)
	cb := h.buildDeployHostKeyCallback(t.Context(), req, &server.ID, nil)
	if err := cb(server.Host, &net.TCPAddr{}, other); err == nil {
		t.Fatal("supplied pin bypassed stored identity")
	}
	managerCallback := ssh.NewHostKeyCallback(t.Context(), ssh.HostKeyCallbackOptions{Store: h.db, ServerID: &server.ID})
	if err := managerCallback(server.Host, &net.TCPAddr{}, other); err == nil {
		t.Fatal("manager accepted changed identity")
	}
	if err := managerCallback(server.Host, &net.TCPAddr{}, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

type malformedDeployKey struct{ gossh.PublicKey }

func (malformedDeployKey) Marshal() []byte { return []byte(strings.Repeat("x", 128)) }

func TestRework4RejectInvalidAndUnboundHostKeys(t *testing.T) {
	h, _, _ := setupDeployTestEnv(t)
	key := rework4Signer(t).PublicKey()
	for _, tc := range []struct {
		name string
		req  GigahostDeployRequest
		key  gossh.PublicKey
	}{
		{"boolean alone", GigahostDeployRequest{ConfirmHostKey: true}, key},
		{"malformed wire key", GigahostDeployRequest{}, malformedDeployKey{key}},
		{"nil", GigahostDeployRequest{}, nil},
		{"invalid fingerprint", GigahostDeployRequest{ExpectedFingerprint: "SHA256:short"}, key},
		{"wrong identity", GigahostDeployRequest{ExpectedFingerprint: ssh.FingerprintSHA256(rework4Signer(t).PublicKey())}, key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.buildDeployHostKeyCallback(t.Context(), tc.req, nil, nil)("host", &net.TCPAddr{}, tc.key); err == nil {
				t.Fatal("untrusted identity accepted")
			}
		})
	}
	fp := ssh.FingerprintSHA256(key)
	if ssh.CompareFingerprints(fp, strings.ToLower(fp)) {
		t.Fatal("case-folded SHA256 accepted")
	}
	if err := h.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.resolveDeployServerID(context.Background(), "198.51.100.10", GigahostDeployRequest{}); err == nil {
		t.Fatal("store lookup failure became fresh host")
	}
}

func TestRework4HTTPConfirmationAndFailureContract(t *testing.T) {
	h, r, _ := setupDeployTestEnv(t)
	key := rework4Signer(t).PublicKey()
	h.SetSSHDialerForTest(func(ctx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
		if err := cfg.HostKeyCallback(cfg.Host, &net.TCPAddr{}, key); err != nil {
			return nil, err
		}
		return ssh.NewClient(cfg), nil
	})
	send := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/admin/hosting/gigahost/orders/rework4-http/setup", strings.NewReader(payload))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	first := send(`{"ssh_password":"fixture-only","confirm_host_key":true}`)
	var challenge struct {
		Status      string `json:"status"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if first.Code != 409 || challenge.Status != "host_key_confirmation_required" || challenge.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatalf("bad confirmation response HTTP %d: %s", first.Code, first.Body.String())
	}
	h.vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("qualification refused")
	})
	body, _ := json.Marshal(map[string]string{"ssh_password": "fixture-only", "expected_fingerprint": challenge.Fingerprint})
	failed := send(string(body))
	if failed.Code != 502 || !strings.Contains(failed.Body.String(), `"status":"failed"`) {
		t.Fatalf("qualification HTTP %d: %s", failed.Code, failed.Body.String())
	}
}
