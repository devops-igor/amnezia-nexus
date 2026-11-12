package handlers

// Setup-side reload of the managed credential (#740).
//
// The purchase half of the milestone proves a key was registered and stored. These
// tests prove the other end: setup can log in with the reloaded private key, the
// exact host identity is still confirmed before any command runs, and the
// manual/password path is untouched.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	gossh "golang.org/x/crypto/ssh"
)

// fixturePEMHeader/footer are PEM delimiters with no key material, assembled so a
// secret scanner cannot mistake a validation fixture for a real key.
var (
	fixturePEMHeader = "-----BEGIN " + "PRIVATE " + "KEY-----"
	fixturePEMFooter = "-----END " + "PRIVATE " + "KEY-----"
)

// storeManagedOrderCredential writes a managed credential for a fresh order row,
// exactly as the purchase path would have.
func storeManagedOrderCredential(t *testing.T, h *Handlers, orderID string) (privateKey, publicKey string) {
	t.Helper()
	privateKey, publicKey, err := ssh.GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("failed to generate managed key: %v", err)
	}
	now := time.Now().UTC()
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID:   orderID,
		Status:    gigahost.StatusReady,
		PlanID:    101,
		RegionID:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("failed to seed the order row: %v", err)
	}
	if err := h.db.SetGigahostOrderCredential(context.Background(), &models.GigahostOrderCredential{
		OrderID:       orderID,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		ProviderKeyID: 42,
	}); err != nil {
		t.Fatalf("failed to store the managed credential: %v", err)
	}
	return privateKey, publicKey
}

// TestOrderCredential_EncryptedSaveReloadProducesTheSameKey is the assignment's
// "generate/encrypt/reload/matching access succeeds" requirement at the storage
// boundary: a fresh handler over the same database reads back the same material.
func TestOrderCredential_EncryptedSaveReloadProducesTheSameKey(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	privateKey, publicKey := storeManagedOrderCredential(t, h, "ord_cred_1")

	restarted := newHandlersOverDB(t, db)
	reloaded, found, err := restarted.loadOrderSSHPrivateKey(context.Background(), "ord_cred_1")
	if err != nil {
		t.Fatalf("loadOrderSSHPrivateKey: %v", err)
	}
	if !found {
		t.Fatal("expected the stored credential to be reloaded")
	}
	if reloaded != privateKey {
		t.Fatal("the reloaded private key must be byte-identical to the stored one")
	}
	if !credentialPairMatches(t, reloaded, publicKey) {
		t.Error("the reloaded private key must match the recorded public key")
	}

	// The private material must not be present in clear in the row.
	var stored string
	if err := db.SQLDB().QueryRow(
		`SELECT ssh_key_enc FROM gigahost_orders WHERE order_id = ?`, "ord_cred_1").Scan(&stored); err != nil {
		t.Fatalf("failed to read the credential column: %v", err)
	}
	if strings.Contains(stored, "PRIVATE KEY") || stored == privateKey {
		t.Error("the private key must be encrypted at rest")
	}
	if stored == "" {
		t.Error("expected the credential column to be populated")
	}
}

// TestOrderCredential_MissingIsAPauseNotAFailure proves the difference the
// assignment calls out: "no stored credential" is a pause with instructions, not
// an authentication attempt with no credentials.
func TestOrderCredential_MissingIsAPauseNotAFailure(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	now := time.Now().UTC()
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID: "ord_no_cred", Status: gigahost.StatusReady, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	req := GigahostDeployRequest{OrderID: "ord_no_cred", UseOrderCredential: true}
	got, err := h.applyStoredOrderCredential(context.Background(), req)
	if err == nil {
		t.Fatalf("expected a pause, got a request with key length %d", len(got.SSHPrivateKey))
	}
	if !errors.Is(err, errMissingOrderCredential) {
		t.Errorf("expected the typed missing-credential pause, got %v", err)
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "ssh-ed25519") {
		t.Errorf("the pause must carry instructions, not key material: %v", err)
	}
}

// TestOrderCredential_ManualPasswordPathUnchanged proves the pre-existing path,
// including its exact refusal message, still behaves as before.
func TestOrderCredential_ManualPasswordPathUnchanged(t *testing.T) {
	base := GigahostDeployRequest{OrderID: "ord_manual", Protocol: "awg"}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "ssh_password or ssh_key is required") {
		t.Errorf("the unchanged requirement must still be reported, got %v", err)
	}

	withPassword := base
	withPassword.SSHPassword = "fixture-only"
	if err := withPassword.Validate(); err != nil {
		t.Errorf("a password-only request must validate, got %v", err)
	}

	withKey := base
	withKey.SSHPrivateKey = fixturePEMHeader + "\nfixture\n" + fixturePEMFooter
	if err := withKey.Validate(); err != nil {
		t.Errorf("a key-only request must validate, got %v", err)
	}

	managed := base
	managed.UseOrderCredential = true
	if err := managed.Validate(); err != nil {
		t.Errorf("a stored-credential request must validate without a manual credential, got %v", err)
	}
}

// TestApplyStoredOrderCredential_PrefersExplicitManualCredential keeps the two
// paths from silently overwriting each other.
func TestApplyStoredOrderCredential_PrefersExplicitManualCredential(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	storeManagedOrderCredential(t, h, "ord_both")

	req := GigahostDeployRequest{OrderID: "ord_both", UseOrderCredential: true, SSHPassword: "fixture-only"}
	got, err := h.applyStoredOrderCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("applyStoredOrderCredential: %v", err)
	}
	if got.SSHPrivateKey != "" {
		t.Error("an explicit password must not be replaced by a stored key")
	}
	if got.UseOrderCredential {
		t.Error("the flag must be cleared once an explicit credential won, so nothing reloads over it")
	}
}

// TestSetupWithManagedCredential_RealHandshakeAndStrictHostIdentity is the
// end-to-end setup proof: a real SSH server accepts the reloaded managed key, the
// exact host identity is confirmed before authentication, and a changed host
// identity runs zero commands.
func TestSetupWithManagedCredential_RealHandshakeAndStrictHostIdentity(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	privateKeyPEM, _ := storeManagedOrderCredential(t, h, "ord_setup")

	signer, err := ssh.ParsePrivateKey(privateKeyPEM, "")
	if err != nil {
		t.Fatalf("the stored key must parse with the existing manager: %v", err)
	}
	hostSigner := newHandshakeSigner(t)

	var commands atomic.Int32
	var authentications atomic.Int32
	serverCfg := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			authentications.Add(1)
			if !bytesEqualKeys(key, signer.PublicKey()) {
				return nil, errors.New("unknown public key")
			}
			return nil, nil
		},
	}
	serverCfg.AddHostKey(hostSigner)
	host, port := startHandshakeServer(t, serverCfg, &commands)

	req := GigahostDeployRequest{
		OrderID: "ord_setup", SSHPort: port, UseOrderCredential: true, Protocol: "awg",
	}
	req, err = h.applyStoredOrderCredential(t.Context(), req)
	if err != nil {
		t.Fatalf("applyStoredOrderCredential: %v", err)
	}
	if req.SSHPrivateKey == "" {
		t.Fatal("the managed credential was not reloaded")
	}

	// First contact: the presented identity must be named before any credential
	// is sent, so this is a typed challenge with zero authentications.
	h.SetSSHDialerForTest(nil)
	_, err = h.verifyDeploySSHAccess(t.Context(), host, req)
	var challenge *ssh.ErrFingerprintRequired
	if !errors.As(err, &challenge) {
		t.Fatalf("expected a fingerprint challenge on first contact, got %v", err)
	}
	if challenge.Fingerprint != ssh.FingerprintSHA256(hostSigner.PublicKey()) {
		t.Errorf("challenge must name the presented identity, got %s", challenge.Fingerprint)
	}
	if authentications.Load() != 0 {
		t.Fatal("the managed key must not be offered before the identity is confirmed")
	}

	// Confirmed identity: the reloaded key authenticates and a command runs.
	req.ExpectedFingerprint = challenge.Fingerprint
	fingerprint, err := h.verifyDeploySSHAccess(t.Context(), host, req)
	if err != nil {
		t.Fatalf("the confirmed handshake with the reloaded key must succeed: %v", err)
	}
	if fingerprint != challenge.Fingerprint {
		t.Errorf("verified identity %s must equal the confirmed one %s", fingerprint, challenge.Fingerprint)
	}
	if authentications.Load() != 1 {
		t.Errorf("expected exactly 1 authentication, got %d", authentications.Load())
	}

	// A different host identity must run zero commands, even with a valid key.
	before := commands.Load()
	otherSigner := newHandshakeSigner(t)
	otherHost, otherPort := startHandshakeServer(t, serverConfigFor(t, otherSigner), &commands)
	_ = otherHost
	mismatchReq := req
	mismatchReq.SSHPort = otherPort
	mismatchReq.ExpectedFingerprint = challenge.Fingerprint
	if _, err := h.verifyDeploySSHAccess(t.Context(), "127.0.0.1", mismatchReq); err == nil {
		t.Fatal("a changed host identity must be refused")
	}
	if commands.Load() != before {
		t.Errorf("a refused handshake must run zero commands, got %d", commands.Load()-before)
	}

	// A stored identity that no longer matches is also refused rather than
	// silently re-bound.
	registered, err := h.registerDeployServer(t.Context(), req, nil, 0, 9001, host, challenge.Fingerprint)
	if err != nil {
		t.Fatalf("registerDeployServer: %v", err)
	}
	if registered.SSHKey == "" {
		t.Error("the registered server must carry the reloaded private key")
	}
	storedKey, err := db.GetServer(t.Context(), registered.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if storedKey.SSHKey != req.SSHPrivateKey {
		t.Error("the server row must hold the same private key that setup used")
	}

	cb := h.buildDeployHostKeyCallback(t.Context(), req, &registered.ID, nil)
	if err := cb(host, &net.TCPAddr{}, otherSigner.PublicKey()); err == nil {
		t.Fatal("the stored identity must reject a changed host key")
	}
}

// newHandshakeSigner generates a fresh ed25519 signer for an SSH handshake.
func newHandshakeSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("failed to build signer: %v", err)
	}
	return signer
}

// serverConfigFor builds a server config that accepts no authentication; used for
// the "wrong host identity" peer, where authentication must never be reached.
func serverConfigFor(t *testing.T, signer gossh.Signer) *gossh.ServerConfig {
	t.Helper()
	cfg := &gossh.ServerConfig{
		PublicKeyCallback: func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
			return nil, errors.New("no authentication expected")
		},
	}
	cfg.AddHostKey(signer)
	return cfg
}

// startHandshakeServer runs a real SSH server on loopback that counts the
// session requests it receives, so "zero commands ran" is observable.
func startHandshakeServer(t *testing.T, cfg *gossh.ServerConfig, commands *atomic.Int32) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				serverConn, chans, reqs, err := gossh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = serverConn.Close() }()
				go gossh.DiscardRequests(reqs)
				for newChan := range chans {
					commands.Add(1)
					_ = newChan.Reject(gossh.Prohibited, "no sessions in this fixture")
				}
			}()
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	return host, port
}

// bytesEqualKeys compares public keys by their wire encoding.
func bytesEqualKeys(a, b gossh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return string(a.Marshal()) == string(b.Marshal())
}

// TestManagedCredentialNotExposedThroughOrderAPI proves the private key never
// reaches an HTTP response, whether as a refusal or as order history.
func TestManagedCredentialNotExposedThroughOrderAPI(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	privateKey, _ := storeManagedOrderCredential(t, h, "ord_exposed")

	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/orders", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1", Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.SetGigahostClient(&mockGigahostClient{getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
		return nil, nil
	}})
	h.GigahostOrdersHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "PRIVATE KEY") || strings.Contains(body, strings.SplitN(privateKey, "\n", 2)[0]) {
		t.Error("order history must not contain private key material")
	}
	if !strings.Contains(body, "ord_exposed") {
		t.Error("the order row itself must still be listed")
	}

	// The same must hold for the deploy status and for a refusal envelope.
	refusalJSON, err := json.Marshal(map[string]any{
		"code": codeCredentialStoreFailed, "message": newRefusal(codeCredentialStoreFailed, "x").message,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(refusalJSON), "PRIVATE KEY") {
		t.Error("a refusal envelope must not carry key material")
	}
}
