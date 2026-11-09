package handlers

// Pre-purchase SSH credential handoff for Gigahost orders.
//
// Why this exists as one unit: POST /deploy/servers accepts ssh_keys as numeric
// account key ids and the documented behavior is that "keys that are not yours
// are ignored". An id that is not proven to belong to this account therefore does
// not fail the order - it buys a server nobody can log into, and the operator
// discovers it only when the setup step cannot reach the host. So the credential
// and the purchase must be prepared together, before the provider is asked to
// sell anything.
//
// The documented contract also fixes the shape of the flow:
//   - POST /account/sshkey returns no key id at all ("the new key and its key_id
//     are listed in GET /account"), so the id can only be learned by re-reading
//     the account;
//   - only the public key is ever sent to the provider, so the private material
//     never leaves this process;
//   - account key ids are sent to an order as numbers while GET /account reports
//     them as strings.
//
// Failure policy: an unreadable account is NOT evidence that a key is missing, and
// an ambiguous registration reply is NOT permission to register again. Both are
// reported as unproven association and block the purchase; the stored public key
// makes the next attempt able to confirm instead of duplicating.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// Pre-purchase refusal codes. They are closed-set labels: the response never
// carries key material or account payload, only the provider's own validation
// message where the provider documented one.
//
// These are response identifiers, not credentials.
const (
	// #nosec G101 -- response code identifiers, not secret credentials
	codeCredentialStoreFailed = "credential_store_failed"
	// #nosec G101 -- response code identifiers, not secret credentials
	codeAccountUnreadable = "account_keys_unreadable"
	// #nosec G101 -- response code identifiers, not secret credentials
	codeSSHKeyRejected = "ssh_key_rejected"
	// #nosec G101 -- response code identifiers, not secret credentials
	codeSSHKeyUnverified = "ssh_key_unverified"
	// #nosec G101 -- response code identifiers, not secret credentials
	codeCredentialMissing = "credential_missing"
)

// prePurchaseRefusal reports that no purchase was attempted and why. It carries a
// public-safe message: never private key material and never account payload.
type prePurchaseRefusal struct {
	status  int
	code    string
	message string
}

func (e *prePurchaseRefusal) Error() string { return e.message }

func newRefusal(code, message string) *prePurchaseRefusal {
	return &prePurchaseRefusal{status: http.StatusBadGateway, code: code, message: message}
}

// managedCredential is the material an order will authorize at the provider.
type managedCredential struct {
	privateKey string
	publicKey  string
	providerID int64
}

// prepareOrderSSHCredential makes sure the order has a managed key registered on
// the provider account and returns the numeric id the order must authorize.
//
// The write order is deliberate: the credential is stored locally BEFORE the
// provider is asked to register anything, so a lost registration reply can be
// resolved by reading the account instead of registering a second key, and so a
// restart in the middle cannot leave a provider key nobody has the private half
// of.
func (h *Handlers) prepareOrderSSHCredential(
	ctx context.Context, client gigahost.Client, order *models.GigahostOrder,
) (int64, error) {
	if h.db == nil || client == nil || order == nil {
		return 0, newRefusal(codeCredentialStoreFailed,
			"The managed SSH credential could not be prepared; no purchase was attempted.")
	}

	cred, err := h.loadOrCreateManagedKey(ctx, order.OrderID)
	if err != nil {
		return 0, newRefusal(codeCredentialStoreFailed,
			"The managed SSH credential could not be stored; no purchase was attempted.")
	}
	if err := h.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:       order.OrderID,
		PrivateKey:    cred.privateKey,
		PublicKey:     cred.publicKey,
		ProviderKeyID: cred.providerID,
	}); err != nil {
		return 0, newRefusal(codeCredentialStoreFailed,
			"The managed SSH credential could not be stored; no purchase was attempted.")
	}

	keyID, err := h.confirmManagedKeyID(ctx, client, order.OrderID, cred)
	if err != nil {
		return 0, err
	}
	return keyID, nil
}

// loadOrCreateManagedKey returns the credential for this order: the one already
// recorded for it, otherwise the most recently recorded one (a restart or a later
// order reuses the existing account key instead of growing the key list), and only
// when neither exists is new key material generated.
func (h *Handlers) loadOrCreateManagedKey(ctx context.Context, orderID string) (*managedCredential, error) {
	if existing, found, err := h.db.GetGigahostOrderCredential(ctx, orderID); err != nil {
		return nil, err
	} else if found {
		return &managedCredential{
			privateKey: existing.PrivateKey,
			publicKey:  existing.PublicKey,
			providerID: existing.ProviderKeyID,
		}, nil
	}

	if reusable, found, err := h.db.LatestGigahostOrderCredential(ctx); err != nil {
		return nil, err
	} else if found {
		return &managedCredential{
			privateKey: reusable.PrivateKey,
			publicKey:  reusable.PublicKey,
			providerID: reusable.ProviderKeyID,
		}, nil
	}

	privateKey, publicKey, err := ssh.GenerateManagedEd25519Key()
	if err != nil {
		return nil, fmt.Errorf("generate managed ssh key: %w", err)
	}
	return &managedCredential{privateKey: privateKey, publicKey: publicKey}, nil
}

// confirmManagedKeyID proves the credential is registered on the account and
// returns the numeric id the order must authorize.
//
// Reading the listing first is what keeps a retry or restart from registering a
// duplicate key: if the material is already on the account, its id is reused with
// no provider write at all.
func (h *Handlers) confirmManagedKeyID(
	ctx context.Context, client gigahost.Client, orderID string, cred *managedCredential,
) (int64, error) {
	keys, err := client.ListSSHKeys(ctx)
	if err != nil {
		// Unreadable is not absent: a failed listing proves nothing about the
		// key, so neither re-registration nor a purchase may follow.
		return 0, newRefusal(codeAccountUnreadable,
			"The Gigahost account keys could not be read, so the managed key association is unproven; no purchase was attempted.")
	}
	if keyID, found, idErr := managedKeyID(keys, cred.publicKey); idErr != nil || found {
		return h.recordConfirmedKeyID(ctx, orderID, keyID, idErr)
	}
	if err := registerManagedKey(ctx, client, cred.publicKey); err != nil {
		return 0, err
	}
	return h.confirmRegisteredKeyID(ctx, client, orderID, cred.publicKey)
}

// recordConfirmedKeyID persists and returns an already-proven key id, passing an
// id-decode error straight through.
func (h *Handlers) recordConfirmedKeyID(ctx context.Context, orderID string, keyID int64, idErr error) (int64, error) {
	if idErr != nil {
		return 0, idErr
	}
	h.persistProviderKeyID(ctx, orderID, keyID)
	return keyID, nil
}

// registerManagedKey registers the public key, mapping a provider decision to a
// refusal. An ambiguous outcome is deliberately not an error here: it is resolved
// by reading the account back, which is the only authority on whether the key
// landed.
func registerManagedKey(ctx context.Context, client gigahost.Client, publicKey string) error {
	name, err := gigahost.ManagedKeyName(publicKey)
	if err != nil {
		return newRefusal(codeSSHKeyUnverified,
			"The managed SSH public key is malformed and cannot be registered; no purchase was attempted.")
	}
	regErr := client.RegisterSSHKey(ctx, name, publicKey)
	if regErr != nil && !gigahost.IsRegistrationAmbiguous(regErr) {
		return newRefusal(codeSSHKeyRejected,
			fmt.Sprintf("The provider rejected the managed SSH key (%s); no purchase was attempted.",
				sanitizeProviderMessage(regErr)))
	}
	return nil
}

// confirmRegisteredKeyID re-reads the account after a registration and returns the
// id it reports for the key.
//
// The read happens whether or not the registration looked successful, because the
// documented reply carries no id and an ambiguous reply carries no information at
// all. A key that is not listed is reported as unverified - never registered again.
func (h *Handlers) confirmRegisteredKeyID(
	ctx context.Context, client gigahost.Client, orderID, publicKey string,
) (int64, error) {
	keys, err := client.ListSSHKeys(ctx)
	if err != nil {
		return 0, newRefusal(codeSSHKeyUnverified,
			"The managed SSH key registration could not be verified because the account keys could not be read; no purchase was attempted and the key was not registered again.")
	}
	keyID, found, idErr := managedKeyID(keys, publicKey)
	if idErr != nil {
		return 0, idErr
	}
	if !found {
		return 0, newRefusal(codeSSHKeyUnverified,
			"The provider did not list the managed SSH key after accepting it; no purchase was attempted and the key was not registered again.")
	}
	h.persistProviderKeyID(ctx, orderID, keyID)
	return keyID, nil
}

// managedKeyID finds the numeric id of the account entry carrying publicKey.
func managedKeyID(keys []gigahost.SSHKeyInfo, publicKey string) (int64, bool, error) {
	match, ok := gigahost.FindSSHKeyByMaterial(keys, publicKey)
	if !ok {
		return 0, false, nil
	}
	id, err := match.ID()
	if err != nil {
		// The key is on the account but its reported id cannot be sent to an
		// order. Refuse rather than order with a guessed id.
		return 0, false, newRefusal(codeSSHKeyUnverified,
			"The provider reported a non-numeric id for the managed SSH key; no purchase was attempted.")
	}
	return id, true, nil
}

// persistProviderKeyID records the confirmed account key id against the order.
//
// A failure here is not fatal: the association has already been proven against
// the account for this purchase, and the stored public key lets the next attempt
// confirm the same id again. It is recorded, not retried, and never allowed to
// turn a proven association into a refused purchase.
func (h *Handlers) persistProviderKeyID(ctx context.Context, orderID string, keyID int64) {
	if h.db == nil || keyID <= 0 {
		return
	}
	cred, found, err := h.db.GetGigahostOrderCredential(ctx, orderID)
	if err != nil || !found {
		return
	}
	if cred.ProviderKeyID == keyID {
		return
	}
	_ = h.db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:       orderID,
		PrivateKey:    cred.PrivateKey,
		PublicKey:     cred.PublicKey,
		ProviderKeyID: keyID,
	})
}

// loadOrderSSHPrivateKey returns the stored private key for an order.
//
// found=false is a pause, not a failure of the server: the operator either placed
// a manual/password order or the credential was never recorded, and the caller
// must say so instead of dialing with no credential.
func (h *Handlers) loadOrderSSHPrivateKey(ctx context.Context, orderID string) (string, bool, error) {
	if h.db == nil || strings.TrimSpace(orderID) == "" {
		return "", false, nil
	}
	cred, found, err := h.db.GetGigahostOrderCredential(ctx, orderID)
	if err != nil || !found {
		return "", false, err
	}
	if strings.TrimSpace(cred.PrivateKey) == "" {
		return "", false, nil
	}
	return cred.PrivateKey, true, nil
}

// errMissingOrderCredential is returned when setup asked for the stored managed
// credential and there is none. It carries operator instructions, no secrets.
var errMissingOrderCredential = errors.New(
	"no managed SSH credential is stored for this order: place the order with a managed key, " +
		"or retry setup with ssh_password/ssh_key supplied manually")

// sanitizeProviderMessage bounds a provider validation message so it can be shown
// to an operator. It never receives key material: only the public key is sent to
// the provider, and the public key is not a secret.
func sanitizeProviderMessage(err error) string {
	if err == nil {
		return "no detail"
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if strings.Contains(strings.ToUpper(msg), "PRIVATE KEY") {
		return "provider validation error"
	}
	const limit = 160
	if utf8.RuneCountInString(msg) > limit {
		runes := []rune(msg)
		msg = string(runes[:limit]) + "..."
	}
	if msg == "" {
		return "no detail"
	}
	return msg
}

// applyStoredOrderCredential fills the request with the managed credential the
// order was placed with, when the request asked for it.
//
// It returns the request unchanged when the caller supplied manual credentials or
// did not ask for the stored one, so the pre-existing password/pasted-key path is
// unaffected. Asking for the stored credential and finding none is a pause with
// operator instructions, never a silent fall-back to "no authentication".
//
// The returned request keeps UseOrderCredential set: any later retry of the same
// request must reload the credential again rather than carry a plaintext key copy
// through the rest of the pipeline.
func (h *Handlers) applyStoredOrderCredential(ctx context.Context, req GigahostDeployRequest) (GigahostDeployRequest, error) {
	if !req.UseOrderCredential {
		return req, nil
	}
	if strings.TrimSpace(req.SSHPassword) != "" || strings.TrimSpace(req.SSHPrivateKey) != "" {
		// A manual credential was supplied alongside the flag: the explicit
		// credential wins, and the flag is cleared so nothing reloads over it.
		req.UseOrderCredential = false
		return req, nil
	}
	privateKey, found, err := h.loadOrderSSHPrivateKey(ctx, req.OrderID)
	if err != nil {
		return req, fmt.Errorf("failed to load the stored SSH credential for order %s: %w", req.OrderID, err)
	}
	if !found {
		return req, errMissingOrderCredential
	}
	req.SSHPrivateKey = privateKey
	return req, nil
}

// refuseBeforePurchase records the pre-purchase refusal against the intent row
// and reports it, so the durable history says why no purchase happened and the
// response carries the closed-set code.
//
// The intent is marked failed rather than left pending: it is a durable record of
// an attempt that provably reached no provider order call, and a pending intent
// would otherwise be treated as an unresolved purchase by the duplicate guard.
func (h *Handlers) refuseBeforePurchase(
	ctx context.Context, orderRecord *GigahostOrderRecord, cause error,
) (*GigahostOrderRecord, *gigahost.OrderResponse, error, bool) {
	var refusal *prePurchaseRefusal
	if errors.As(cause, &refusal) {
		orderRecord.Status = gigahost.StatusFailed
		updateCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = h.updateGigahostOrder(updateCtx, orderRecord)
		return orderRecord, nil, refusal, true
	}
	return nil, nil, nil, false
}

// writePrePurchaseRefusal reports a pre-purchase refusal and reports whether it
// handled the response.
//
// A refusal is a confirmed "no order was placed", so it must not be reported as
// request-time uncertainty, and it carries no provider order id by construction.
func writePrePurchaseRefusal(w http.ResponseWriter, orderErr error, h *Handlers) bool {
	var refusal *prePurchaseRefusal
	if !errors.As(orderErr, &refusal) {
		return false
	}
	h.JSON(w, refusal.status, map[string]any{
		"status":        "refused",
		"code":          refusal.code,
		"message":       refusal.message,
		"purchase_sent": false,
	})
	return true
}
