package database

// The granted automation authority binding for a setup intent.
//
// Recording the policy alone was not enough: it said "this panel may trust its own first
// observation" without saying for which resource. That left eligibility inferring
// ownership from a plan id and a key id, which the requirement explicitly forbids - an
// imported or mirror-created row can carry both. This file records the exact order,
// server, address and managed key the authority was granted for, in one statement, and
// proves the same facts again when the identity is pinned.
//
// The binding is written only by the grant and never overwritten afterwards, so a
// partially bound row cannot exist and a job cannot drift onto a different resource
// while keeping its authority.
//
// Only this package issues SQL for the table (module ownership rules).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// AutomationBinding is the resource an automation authority is granted for, proved from
// durable rows rather than from fields that coincidentally look valid.
//
// Every field is required and non-empty (ids > 0); an empty binding is not a weaker
// grant, it is no grant.
type AutomationBinding struct {
	// OrderID is the provider order this panel's purchase intent recorded.
	OrderID string
	// ProviderServerID and Address are the provider identity the job will dial.
	ProviderServerID int64
	Address          string
	// ProviderKeyID is the provider-side account key id the purchase path registered,
	// which is what correlates the stored key material with this order.
	ProviderKeyID int64
}

// IsComplete reports whether every fact the binding must establish is present.
func (b AutomationBinding) IsComplete() bool {
	return strings.TrimSpace(b.OrderID) != "" &&
		b.ProviderServerID > 0 &&
		strings.TrimSpace(b.Address) != "" &&
		b.ProviderKeyID > 0
}

// ErrAutomationBindingUnproven reports that the exact application-owned binding could
// not be established, so no automation authority may be granted.
var ErrAutomationBindingUnproven = errors.New("this order has no proven application-owned purchase binding")

// ProveAutomationBinding asks the durable rows whether this panel provably purchased
// exactly the resource the job describes.
//
// It answers three questions and refuses on any of them:
//
//  1. Did this panel purchase the order? Only the pre-purchase intent writer stamps
//     that, and no other writer can add the stamp later, so plan and key fields are
//     never consulted here.
//  2. Does the ledger row describe the same provider server and address the job is
//     about to dial? A row whose identity has moved is not this job's resource.
//  3. Does the managed credential exist with the provider-side key id the purchase
//     registered?
//
// A read error is reported as an error, never as a refusal: "could not ask" is not
// "no".
func (d *DB) ProveAutomationBinding(
	ctx context.Context, orderID string, providerServerID int64,
) (AutomationBinding, error) {
	orderID = strings.TrimSpace(orderID)
	binding := AutomationBinding{OrderID: orderID, ProviderServerID: providerServerID}
	if d == nil || d.sqlDB == nil || orderID == "" || providerServerID <= 0 {
		return binding, ErrAutomationBindingUnproven
	}
	if err := d.proveOrderResource(ctx, &binding); err != nil {
		return binding, err
	}
	return binding, d.proveManagedKey(ctx, &binding)
}

// proveOrderResource fills in the address from the ledger row, but only when that row is
// the panel's own purchase of this exact provider server.
//
// Provenance and identity are one check because they answer one question: is this row the
// resource the job describes? A row that is not the panel's purchase is refused whatever
// its plan or key say, and a row describing a different server is not this job's resource.
func (d *DB) proveOrderResource(ctx context.Context, binding *AutomationBinding) error {
	order, found, err := d.GetGigahostOrder(ctx, binding.OrderID)
	if err != nil {
		return fmt.Errorf("failed to read the order ledger: %w", err)
	}
	if !found || order == nil {
		return ErrAutomationBindingUnproven
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		// The row did not come from this panel's purchase intent. Whatever its plan,
		// key or status say, it is not evidence that this panel bought it.
		return ErrAutomationBindingUnproven
	}
	if order.ServerID != binding.ProviderServerID {
		return ErrAutomationBindingUnproven
	}
	binding.Address = strings.TrimSpace(order.AssignedIP)
	if binding.Address == "" {
		return ErrAutomationBindingUnproven
	}
	return nil
}

// proveManagedKey fills in the provider-side key id, which is the correlation between what
// this order authorized at the provider and the material the panel will log in with.
func (d *DB) proveManagedKey(ctx context.Context, binding *AutomationBinding) error {
	credential, hasCredential, err := d.GetGigahostOrderCredential(ctx, binding.OrderID)
	if err != nil {
		return fmt.Errorf("failed to read the managed credential: %w", err)
	}
	if !hasCredential || credential == nil || credential.ProviderKeyID <= 0 {
		return ErrAutomationBindingUnproven
	}
	binding.ProviderKeyID = credential.ProviderKeyID
	return nil
}

// SetGigahostSetupAutomationBinding grants the automation authority for exactly one
// resource.
//
// The policy and the binding are written in ONE statement, so a row can never carry
// authority without saying what it was granted for, and the WHERE clause carries the
// whole eligibility rule: still pending, no identity yet, policy not already granted.
//
// The caller must have proved the binding already with ProveAutomationBinding. This
// statement records it; it does not re-derive it, because re-deriving here would let a
// row that changed between proof and grant be recorded under the new facts while the
// proof described the old ones.
func (d *DB) SetGigahostSetupAutomationBinding(
	ctx context.Context, binding AutomationBinding,
) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || !binding.IsComplete() {
		return nil, false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	q := `UPDATE gigahost_setup_intents
	      SET host_trust_policy = ?,
	          host_trust_order_id = ?,
	          host_trust_server_id = ?,
	          host_trust_address = ?,
	          host_trust_key_id = ?,
	          host_trust_granted_at = ?,
	          updated_at = ?
	      WHERE order_id = ?
	        AND state = ?
	        AND host_fingerprint = ''
	        AND host_trust_granted_at = ''`
	res, err := d.execWrite(ctx, q,
		models.SetupTrustPolicyFirstContact,
		strings.TrimSpace(binding.OrderID), binding.ProviderServerID,
		strings.TrimSpace(binding.Address), binding.ProviderKeyID,
		formatSetupTimestamp(now), formatSetupTimestamp(now),
		strings.TrimSpace(binding.OrderID), models.SetupStatePending)
	if err != nil {
		return nil, false, fmt.Errorf("failed to record the automation authority binding: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("failed to confirm the automation authority binding write: %w", err)
	}
	current, found, err := d.GetGigahostSetupIntent(ctx, strings.TrimSpace(binding.OrderID))
	if err != nil || !found {
		return nil, false, err
	}
	return current, affected > 0, nil
}

// PinGigahostSetupFirstContact records the host identity the panel observed on its own
// first-contact challenge, but only while every granted fact still holds.
//
// The pin is the last moment before a credential could be sent, so the WHERE clause
// re-proves the binding rather than trusting the pass's snapshot: the row must still
// carry the granted order, server, address and key id, and it must still be pending with
// no identity. A job whose resource moved since the grant matches no row and is told its
// identity changed, which is a refusal, never a silent re-grant.
func (d *DB) PinGigahostSetupFirstContact(
	ctx context.Context, orderID, fingerprint string,
) (string, error) {
	if d == nil || d.sqlDB == nil {
		return models.FirstContactNotEligible, nil
	}
	orderID = strings.TrimSpace(orderID)
	fingerprint = strings.TrimSpace(fingerprint)
	if orderID == "" {
		return "", errors.New("a setup intent order id is required")
	}
	if err := models.ValidateHostFingerprint(fingerprint); err != nil {
		return "", err
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return "", err
	}

	// The final EXISTS is the important half: the intent's own columns are what the grant
	// recorded, but the resource itself is described by the ledger row. Requiring the row
	// to still carry the purchase stamp, the same server id and the same address - in this
	// same statement - is what makes a resource that moved after the grant unable to be
	// pinned, with no window between the check and the write.
	q := `UPDATE gigahost_setup_intents
	      SET host_fingerprint = ?,
	          host_trust_mode = ?,
	          host_candidate_fingerprint = '',
	          updated_at = ?
	      WHERE order_id = ?
	        AND state = ?
	        AND host_trust_policy = ?
	        AND host_fingerprint = ''
	        AND host_trust_granted_at != ''
	        AND host_trust_order_id = ?
	        AND host_trust_server_id > 0
	        AND host_trust_address != ''
	        AND host_trust_key_id > 0
	        AND EXISTS (
	              SELECT 1 FROM gigahost_orders o
	               WHERE o.order_id = gigahost_setup_intents.host_trust_order_id
	                 AND o.purchase_origin = ?
	                 AND o.server_id = gigahost_setup_intents.host_trust_server_id
	                 AND o.assigned_ip = gigahost_setup_intents.host_trust_address
	                 AND o.provider_ssh_key_id = gigahost_setup_intents.host_trust_key_id
	        )` // #nosec G202 -- placeholder-only text; every value is a bound argument
	res, err := d.execWrite(ctx, q,
		fingerprint, models.SetupTrustModeFirstContact,
		formatSetupTimestamp(time.Now().UTC()),
		orderID, models.SetupStatePending, models.SetupTrustPolicyFirstContact,
		orderID, models.PurchaseOriginPanelPurchase)
	if err != nil {
		return "", fmt.Errorf("failed to pin the first-contact host identity: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("failed to confirm the first-contact host pin: %w", err)
	}
	if affected > 0 {
		return models.FirstContactPinned, nil
	}
	return d.firstContactPinOutcome(ctx, orderID, fingerprint)
}

// BindingHolds reports whether the granted binding still describes this exact resource,
// so a caller can refuse before spending a challenge on a job that has already moved.
//
// It compares the intent's recorded grant with the durable order and credential rows.
// Any difference - a different server id, a different address, a different provider key
// id, or a row that is no longer the panel's purchase - means the authority no longer
// applies to what is there now.
func (d *DB) BindingHolds(ctx context.Context, intent *models.GigahostSetupIntent) (bool, error) {
	if d == nil || intent == nil || strings.TrimSpace(intent.HostTrustOrderID) == "" {
		return false, nil
	}
	binding, err := d.ProveAutomationBinding(ctx, intent.HostTrustOrderID, intent.HostTrustServerID)
	if err != nil {
		if errors.Is(err, ErrAutomationBindingUnproven) {
			return false, nil
		}
		return false, err
	}
	return binding.Address == strings.TrimSpace(intent.HostTrustAddress) &&
		binding.ProviderKeyID == intent.HostTrustKeyID &&
		binding.ProviderServerID == intent.HostTrustServerID, nil
}
