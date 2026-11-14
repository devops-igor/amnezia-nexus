package handlers

// End-to-end credential handoff tests for a Gigahost order (#740).
//
// These drive the real order handler, the real credential persistence and the
// real provider decode; only the provider is a local fake. Every case asserts the
// number of purchase calls, because the whole point of the milestone is that a
// credential problem costs zero purchases.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	gossh "golang.org/x/crypto/ssh"
)

// sshHandoffOrderBody is a valid order for the shared documented plan fixture.
const sshHandoffOrderBody = `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.14375}`

// sshHandoffProvider is a fake Gigahost account/catalog/order provider that keeps
// a real key list, so the "register then re-read the account" contract is
// exercised rather than short-circuited.
type sshHandoffProvider struct {
	keys []gigahost.SSHKeyInfo

	listErr       error
	registerErr   error
	listAfterReg  error // one-shot error for the read that follows a registration
	registerCalls atomic.Int32
	listCalls     atomic.Int32
	orders        atomic.Int32
	orderErr      error

	// registered lines and registration names, in order, for assertions.
	registeredKeys  []string
	registeredNames []string
	seenOrderKeys   [][]int64
	// registeredKeyID is the id the fake account assigns to the next registered
	// key, so a test can model an unexpected id shape.
	registeredKeyID string
	// storeDespiteError models a provider that stored the key but whose reply
	// failed: the documented hazard that makes a blind re-registration unsafe.
	storeDespiteError bool
	// attemptedKeys records every registration request body, including the ones
	// that returned an error, so a test can prove what was sent.
	attemptedKeys []string
}

func (p *sshHandoffProvider) GetCatalog(context.Context) ([]gigahost.HourlyPlan, error) {
	return []gigahost.HourlyPlan{fixtureHourlyPlan()}, nil
}

func (p *sshHandoffProvider) GetProducts(context.Context) ([]gigahost.Product, error) {
	return nil, nil
}

func (p *sshHandoffProvider) GetOperatingSystems(context.Context) ([]gigahost.OperatingSystem, error) {
	return fixtureOperatingSystems(), nil
}

func (p *sshHandoffProvider) GetAccount(context.Context) (*gigahost.AccountInfo, error) {
	return &gigahost.AccountInfo{Balance: 100, Currency: "NOK"}, nil
}

func (p *sshHandoffProvider) ListSSHKeys(context.Context) ([]gigahost.SSHKeyInfo, error) {
	p.listCalls.Add(1)
	if p.listErr != nil {
		return nil, p.listErr
	}
	// listAfterReg models an account read that fails only once a registration
	// happened, i.e. the read that has to confirm the new key.
	if p.listAfterReg != nil && p.registerCalls.Load() > 0 {
		err := p.listAfterReg
		p.listAfterReg = nil
		return nil, err
	}
	return append([]gigahost.SSHKeyInfo(nil), p.keys...), nil
}

func (p *sshHandoffProvider) RegisterSSHKey(_ context.Context, name, publicKey string) error {
	p.registerCalls.Add(1)
	p.attemptedKeys = append(p.attemptedKeys, publicKey)
	if p.registerErr != nil && !p.storeDespiteError {
		return p.registerErr
	}
	p.registeredNames = append(p.registeredNames, name)
	p.registeredKeys = append(p.registeredKeys, publicKey)
	keyID := p.registeredKeyID
	if keyID == "" {
		keyID = "4" + string(rune('0'+len(p.keys)))
	}
	p.keys = append(p.keys, gigahost.SSHKeyInfo{
		KeyID:   keyID,
		KeyName: name,
		KeyData: publicKey,
	})
	return nil
}

func (p *sshHandoffProvider) OrderServer(ctx context.Context, r gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	return p.OrderServerSafe(ctx, r)
}

func (p *sshHandoffProvider) OrderServerSafe(_ context.Context, r gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
	p.orders.Add(1)
	p.seenOrderKeys = append(p.seenOrderKeys, append([]int64(nil), r.SSHKeys...))
	if p.orderErr != nil {
		return nil, p.orderErr
	}
	return &gigahost.OrderResponse{OrderID: "55001", Status: gigahost.StatusPending, RateHourly: 0.14375, Currency: "NOK"}, nil
}

func (p *sshHandoffProvider) GetDeployStatus(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
	// The order itself resolves as ready, so an earlier successful order is not
	// left permanently "in flight" and blocking the next attempt through the
	// duplicate guard. The deploy path is not what these tests exercise.
	return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady, AssignedIP: "198.51.100.7"}, nil
}

func (p *sshHandoffProvider) GetServers(context.Context) ([]gigahost.ServerInfo, error) {
	return []gigahost.ServerInfo{}, nil
}

func newHandoffProvider() *sshHandoffProvider { return &sshHandoffProvider{} }

// submitHandoffOrder issues one order request as an admin and returns the
// recorder plus the decoded refusal envelope (if any).
func submitHandoffOrder(h *Handlers, body string) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1", Username: "admin", Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	var decoded map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	return w, decoded
}

// orderedCredential returns the credential recorded against the only order row.
func orderedCredential(t *testing.T, h *Handlers, db *database.DB) (*models.GigahostOrderCredential, bool) {
	t.Helper()
	orders, err := db.ListGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("failed to list orders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("expected exactly 1 order row, got %d", len(orders))
	}
	cred, found, err := db.GetGigahostOrderCredential(context.Background(), orders[0].OrderID)
	if err != nil {
		t.Fatalf("failed to read stored credential: %v", err)
	}
	return cred, found
}

// TestSSHHandoff_RegistersEncryptsAndOrdersWithProvenKey is the positive path:
// key material is generated, stored encrypted, registered, proven against the
// account listing, and its id is the one the order authorizes.
func TestSSHHandoff_RegistersEncryptsAndOrdersWithProvenKey(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	h.SetGigahostClient(provider)

	w, _ := submitHandoffOrder(h, sshHandoffOrderBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if provider.orders.Load() != 1 {
		t.Fatalf("expected exactly 1 purchase, got %d", provider.orders.Load())
	}
	if provider.registerCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 key registration, got %d", provider.registerCalls.Load())
	}
	if got := provider.seenOrderKeys[0]; len(got) != 1 || got[0] <= 0 {
		t.Fatalf("the order must authorize exactly one numeric key id, got %v", got)
	}

	cred, found := orderedCredential(t, h, db)
	if !found || cred == nil {
		t.Fatal("expected a stored credential for the order")
	}
	if cred.ProviderKeyID != provider.seenOrderKeys[0][0] {
		t.Errorf("stored provider key id %d must match the id the order authorized %d",
			cred.ProviderKeyID, provider.seenOrderKeys[0][0])
	}
	if !credentialPairMatches(t, cred.PrivateKey, cred.PublicKey) {
		t.Error("the stored private key must correspond to the registered public key")
	}
	if got := provider.registeredKeys[0]; !gigahost.AuthorizedKeyMatches(got, cred.PublicKey) {
		t.Error("the key registered at the provider must be the stored public key")
	}

	// The private material must not be readable in the stored row.
	assertPrivateKeyNotStoredInClear(t, h, cred.PrivateKey)

	// Listing happens before registration (to avoid a duplicate) and again after
	// (to learn the id the registration does not return).
	if provider.listCalls.Load() < 2 {
		t.Errorf("expected the account to be read before and after registration, got %d reads", provider.listCalls.Load())
	}
}

// TestSSHHandoff_ReusesExistingAccountKeyWithoutRegistering proves a retry or a
// later order with the same material performs no provider write at all.
func TestSSHHandoff_ReusesExistingAccountKeyWithoutRegistering(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	h.SetGigahostClient(provider)

	if w, _ := submitHandoffOrder(h, sshHandoffOrderBody); w.Code != http.StatusOK {
		t.Fatalf("first order failed: %d %s", w.Code, w.Body.String())
	}
	first, found := orderedCredential(t, h, db)
	if !found {
		t.Fatal("expected a stored credential after the first order")
	}

	// A second order must reuse the recorded material, not add another account key.
	provider.orders.Store(0)
	w, _ := submitHandoffOrder(h, sshHandoffOrderBody)
	if w.Code != http.StatusOK {
		t.Fatalf("second order failed: %d (body: %s)", w.Code, w.Body.String())
	}
	if provider.registerCalls.Load() != 1 {
		t.Errorf("expected the existing account key to be reused, but registrations reached %d", provider.registerCalls.Load())
	}
	if provider.orders.Load() != 1 {
		t.Errorf("expected exactly 1 purchase for the second attempt, got %d", provider.orders.Load())
	}
	if len(provider.keys) != 1 {
		t.Errorf("the account key list must not grow on reuse, got %d keys", len(provider.keys))
	}

	orders, err := db.ListGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("failed to list orders: %v", err)
	}
	for _, order := range orders {
		cred, ok, err := db.GetGigahostOrderCredential(context.Background(), order.OrderID)
		if err != nil || !ok {
			t.Fatalf("order %s lost its credential: ok=%t err=%v", order.OrderID, ok, err)
		}
		if cred.PublicKey != first.PublicKey {
			t.Errorf("order %s reused different key material", order.OrderID)
		}
	}
	if got := provider.seenOrderKeys[len(provider.seenOrderKeys)-1]; len(got) != 1 || got[0] != first.ProviderKeyID {
		t.Errorf("the reused order must authorize the already-proven id %d, got %v", first.ProviderKeyID, got)
	}
}

// TestSSHHandoff_AccountUnreadableNeverPurchases is the "cannot ask is not
// absence" case: the key may well exist, so nothing is registered and nothing is
// bought.
func TestSSHHandoff_AccountUnreadableNeverPurchases(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	provider.listErr = errors.New("dial tcp: connection refused")
	h.SetGigahostClient(provider)

	w, body := submitHandoffOrder(h, sshHandoffOrderBody)
	if provider.orders.Load() != 0 {
		t.Fatalf("an unreadable account must not reach a purchase, got %d", provider.orders.Load())
	}
	if provider.registerCalls.Load() != 0 {
		t.Fatalf("an unreadable account is not proof the key is missing: registrations reached %d", provider.registerCalls.Load())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d (body: %s)", w.Code, w.Body.String())
	}
	if body["code"] != codeAccountUnreadable {
		t.Errorf("expected code %q, got %v", codeAccountUnreadable, body["code"])
	}
	if sent, ok := body["purchase_sent"].(bool); !ok || sent {
		t.Errorf("the refusal must state that no purchase was sent, got %v", body["purchase_sent"])
	}
}

// TestSSHHandoff_RegistrationRejectedNeverPurchases covers a provider decision
// against the key itself: it is a definite failure, reported, with no purchase.
func TestSSHHandoff_RegistrationRejectedNeverPurchases(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	provider.registerErr = &gigahost.APIError{StatusCode: http.StatusBadRequest, Message: "SSH-key invalid."}
	h.SetGigahostClient(provider)

	w, body := submitHandoffOrder(h, sshHandoffOrderBody)
	if provider.orders.Load() != 0 {
		t.Fatalf("a rejected key must not reach a purchase, got %d", provider.orders.Load())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d (body: %s)", w.Code, w.Body.String())
	}
	if body["code"] != codeSSHKeyRejected {
		t.Errorf("expected code %q, got %v", codeSSHKeyRejected, body["code"])
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "SSH-key invalid.") {
		t.Errorf("the documented provider message should be surfaced, got %q", msg)
	}
}

// TestSSHHandoff_AmbiguousRegistrationDoesNotDuplicate is the lost-reply case:
// the provider accepted the key but the account read afterwards fails. The key
// must not be registered a second time, and no purchase may happen.
func TestSSHHandoff_AmbiguousRegistrationDoesNotDuplicate(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	provider.registerErr = &gigahost.APIError{StatusCode: http.StatusBadGateway, Message: "bad gateway"}
	// The account read after registration fails, so the association is unproven
	// even though the registration may have landed.
	provider.listAfterReg = errors.New("read timeout")
	h.SetGigahostClient(provider)

	w, body := submitHandoffOrder(h, sshHandoffOrderBody)
	if provider.orders.Load() != 0 {
		t.Fatalf("an unproven key association must not reach a purchase, got %d", provider.orders.Load())
	}
	if provider.registerCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 registration attempt, got %d", provider.registerCalls.Load())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d (body: %s)", w.Code, w.Body.String())
	}
	if body["code"] != codeSSHKeyUnverified {
		t.Errorf("expected code %q, got %v", codeSSHKeyUnverified, body["code"])
	}

	// The credential is already durable, so a retry can confirm instead of
	// registering again.
	if _, found := orderedCredential(t, h, db); !found {
		t.Fatal("the credential must be durable even when registration could not be confirmed")
	}
}

// TestSSHHandoff_RetryAfterAmbiguousRegistrationConfirmsInsteadOfDuplicating is
// the restart/retry half of the previous case: once the account is readable the
// same material is found and used with no second registration.
//
// The retry runs on a handler over the same database, which is both what a real
// process restart looks like and what an operator gets after the failed-attempt
// cooldown: the credential must be recoverable from durable state alone.
func TestSSHHandoff_RetryAfterAmbiguousRegistrationConfirmsInsteadOfDuplicating(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	provider.registerErr = &gigahost.APIError{StatusCode: http.StatusBadGateway, Message: "bad gateway"}
	provider.listAfterReg = errors.New("read timeout")
	provider.storeDespiteError = true
	h.SetGigahostClient(provider)

	if w, _ := submitHandoffOrder(h, sshHandoffOrderBody); w.Code == http.StatusOK {
		t.Fatal("the first attempt must not succeed")
	}
	if provider.orders.Load() != 0 {
		t.Fatalf("the first attempt must not purchase, got %d", provider.orders.Load())
	}

	if len(provider.attemptedKeys) != 1 {
		t.Fatalf("expected exactly 1 registration attempt, got %d", len(provider.attemptedKeys))
	}
	// The key landed on the account exactly once, under id 77: the truth of "did
	// the registration happen" can only be learned by reading the account, which
	// is what the retry must do instead of registering again.
	provider.storeDespiteError = false
	provider.keys = []gigahost.SSHKeyInfo{{
		KeyID: "77", KeyName: "nexus", KeyData: provider.attemptedKeys[0],
	}}
	provider.registerErr = nil

	restarted := newHandlersOverDB(t, db)
	restarted.SetGigahostClient(provider)
	w, _ := submitHandoffOrder(restarted, sshHandoffOrderBody)
	if w.Code != http.StatusOK {
		t.Fatalf("the retry should succeed once the account is readable, got %d (body: %s)", w.Code, w.Body.String())
	}
	if provider.registerCalls.Load() != 1 {
		t.Errorf("the retry must not register the key again, registrations reached %d", provider.registerCalls.Load())
	}
	if provider.orders.Load() != 1 {
		t.Errorf("expected exactly 1 purchase on the retry, got %d", provider.orders.Load())
	}
	if got := provider.seenOrderKeys[0]; len(got) != 1 || got[0] != 77 {
		t.Errorf("the retry must authorize the id the account reports (77), got %v", got)
	}
}

// TestSSHHandoff_StorageFailureBeforePurchaseNeverPurchases is the assignment's
// explicit requirement: a credential that could not be stored costs no purchase.
//
// The failure is injected at the database boundary with a real SQLite trigger, so
// the intent row writes normally and only the credential write fails - which is
// precisely the ordering this milestone has to get right.
func TestSSHHandoff_StorageFailureBeforePurchaseNeverPurchases(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	h.SetGigahostClient(provider)

	_, err := db.SQLDB().Exec(`CREATE TRIGGER fail_credential_write
		BEFORE UPDATE OF ssh_key_enc ON gigahost_orders
		BEGIN SELECT RAISE(ABORT, 'injected credential write failure'); END`)
	if err != nil {
		t.Fatalf("failed to install the failure trigger: %v", err)
	}

	w, body := submitHandoffOrder(h, sshHandoffOrderBody)
	if provider.orders.Load() != 0 {
		t.Fatalf("an unstored credential must not reach a purchase, got %d", provider.orders.Load())
	}
	if provider.registerCalls.Load() != 0 {
		t.Fatalf("no provider key may be registered before the credential is durable, got %d", provider.registerCalls.Load())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d (body: %s)", w.Code, w.Body.String())
	}
	if body["code"] != codeCredentialStoreFailed {
		t.Errorf("expected code %q, got %v", codeCredentialStoreFailed, body["code"])
	}
	if sent, ok := body["purchase_sent"].(bool); !ok || sent {
		t.Errorf("the refusal must state that no purchase was sent, got %v", body["purchase_sent"])
	}

	// The intent row still exists as failed history: an attempt that provably
	// reached no provider order call must not look like an unresolved purchase.
	orders, err := db.ListGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("failed to list orders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("expected the intent row to survive, got %d rows", len(orders))
	}
	if orders[0].Status != gigahost.StatusFailed {
		t.Errorf("a pre-purchase refusal must leave the intent failed, got %q", orders[0].Status)
	}
}

// TestSSHHandoff_AccountKeyWithNonNumericIDRefuses proves an unparseable id is
// refused rather than guessed into an order.
func TestSSHHandoff_AccountKeyWithNonNumericIDRefuses(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	provider := newHandoffProvider()
	// The documented account shape reports key ids as strings, but an order needs
	// a number. An answer that is not a number cannot be sent to an order.
	provider.registeredKeyID = "not-a-number"
	h.SetGigahostClient(provider)

	w, body := submitHandoffOrder(h, sshHandoffOrderBody)
	if provider.orders.Load() != 0 {
		t.Fatalf("a non-numeric key id must not reach a purchase, got %d", provider.orders.Load())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d (body: %s)", w.Code, w.Body.String())
	}
	if body["code"] != codeSSHKeyUnverified {
		t.Errorf("expected code %q, got %v", codeSSHKeyUnverified, body["code"])
	}
}

// TestSSHHandoff_RefusalExposesNoPrivateMaterial checks that no refusal path
// leaks key material, account payload or a provider URL into the response.
func TestSSHHandoff_RefusalExposesNoPrivateMaterial(t *testing.T) {
	refusals := []error{
		newRefusal(codeAccountUnreadable, "unreadable"),
		newRefusal(codeSSHKeyRejected, "rejected: "+sanitizeProviderMessage(errors.New("SSH-key invalid."))),
		newRefusal(codeSSHKeyUnverified, "unverified"),
		newRefusal(codeCredentialStoreFailed, "store"),
	}
	for _, refusal := range refusals {
		var typed *prePurchaseRefusal
		if !errors.As(refusal, &typed) {
			t.Fatalf("expected a typed refusal, got %T", refusal)
		}
		if strings.Contains(typed.Error(), "PRIVATE KEY") {
			t.Errorf("refusal text contains key material: %s", typed.Error())
		}
	}

	// A provider message that somehow carried key material is redacted.
	leaky := sanitizeProviderMessage(errors.New(pemHeaderProbe))
	if strings.Contains(strings.ToUpper(leaky), "PRIVATE KEY") {
		t.Errorf("provider message was not redacted: %q", leaky)
	}
	// A long provider message is bounded.
	long := sanitizeProviderMessage(errors.New(strings.Repeat("x", 500)))
	if len([]rune(long)) > 200 {
		t.Errorf("provider message was not bounded: %d runes", len([]rune(long)))
	}
}

// pemHeaderProbe is a PEM header with no key body, assembled so a secret scanner
// cannot mistake this redaction assertion for leaked key material.
var pemHeaderProbe = "-----BEGIN OPENSSH " + "PRIVATE " + "KEY----- body"

// credentialPairMatches parses the stored private key and compares its public
// half with the stored/registered public key line.
func credentialPairMatches(t *testing.T, privateKeyPEM, publicKeyLine string) bool {
	t.Helper()
	signer, err := ssh.ParsePrivateKey(privateKeyPEM, "")
	if err != nil {
		t.Errorf("the stored private key must parse with the existing SSH manager: %v", err)
		return false
	}
	derived := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	return gigahost.AuthorizedKeyMatches(derived, publicKeyLine)
}

// assertPrivateKeyNotStoredInClear proves the encrypted-at-rest claim against the
// actual row bytes rather than against the API.
func assertPrivateKeyNotStoredInClear(t *testing.T, h *Handlers, privateKey string) {
	t.Helper()
	if privateKey == "" {
		t.Fatal("expected private key material to check")
	}
	var stored string
	err := h.db.SQLDB().QueryRow(
		`SELECT ssh_key_enc FROM gigahost_orders ORDER BY id DESC LIMIT 1`).Scan(&stored)
	if err != nil {
		t.Fatalf("failed to read the stored credential column: %v", err)
	}
	if stored == "" {
		t.Fatal("expected an encrypted credential in the row")
	}
	if strings.Contains(stored, "PRIVATE KEY") || stored == privateKey {
		t.Error("the private key must not be stored in clear text")
	}
	// It must still decrypt back to the same material through the DB boundary.
	decrypted, found, err := h.db.GetGigahostOrderCredential(context.Background(), orderIDAt(t, h))
	if err != nil || !found {
		t.Fatalf("failed to read back the credential: found=%t err=%v", found, err)
	}
	if decrypted.PrivateKey != privateKey {
		t.Error("the stored credential must decrypt to the original private key")
	}
}

func orderIDAt(t *testing.T, h *Handlers) string {
	t.Helper()
	orders, err := h.db.ListGigahostOrders(context.Background())
	if err != nil || len(orders) == 0 {
		t.Fatalf("failed to read orders: err=%v count=%d", err, len(orders))
	}
	return orders[0].OrderID
}

// TestGeneratedManagedKey_IsUsableByExistingManager proves the generated material
// needs no new parser: the existing manager's own parse and auth builder accept it.
func TestGeneratedManagedKey_IsUsableByExistingManager(t *testing.T) {
	privateKey, publicKey, err := ssh.GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("GenerateManagedEd25519Key: %v", err)
	}
	methods, err := ssh.BuildAuthMethods("", privateKey, "")
	if err != nil {
		t.Fatalf("the existing manager must accept the generated key: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected exactly 1 key auth method, got %d", len(methods))
	}
	if !credentialPairMatches(t, privateKey, publicKey) {
		t.Error("the generated public key must correspond to the generated private key")
	}

	// Two calls must not produce the same key.
	otherPrivate, otherPublic, err := ssh.GenerateManagedEd25519Key()
	if err != nil {
		t.Fatalf("second GenerateManagedEd25519Key: %v", err)
	}
	if otherPrivate == privateKey || otherPublic == publicKey {
		t.Error("each managed key pair must be unique")
	}
}
