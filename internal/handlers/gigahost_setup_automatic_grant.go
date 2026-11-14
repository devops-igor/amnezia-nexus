package handlers

// Acquiring the scoped automation authority for an unattended job, with no browser.
//
// An automatic job is created with the policy and nothing else: no binding, so it is
// inert by construction. This is the step that gives it authority, and it is the only
// place in production where that happens. Everything it needs already exists:
//
//   - the order ledger, with the purchase stamp the pre-purchase writer committed;
//   - the managed credential the purchase registered with the provider;
//   - the provider's own answer about which server and address belong to the order;
//   - ProveAutomationBinding, which asks the durable rows all of that again;
//   - SetGigahostSetupAutomationBinding, the audited single-statement grant.
//
// What this file adds is the ordering and the narrowing. The ledger association is
// recorded first, from the provider's answer, because the binding proof reads the
// ledger and the ledger is what a fresh purchase is missing. Then the grant is offered to
// exactly one job: the row for this order, still automatic, still ungranted, still
// pending with no identity. Every other shape matches no row and changes nothing.
//
// A grant that cannot be proved is not a pause for a person. The whole point of the
// automatic path is that nobody is there, so a refusal leaves the job inert and the
// tracker asks again on its next pass, which is the same fail-closed shape the pin
// uses.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// GrantAutomaticGigahostSetupBinding acquires the scoped authority for one unattended
// job from the provider's own association answer.
//
// It is called by the tracker pass for a job that carries the automation policy, and it
// is safe to call repeatedly: a granted job is left alone, and a job whose facts do not
// yet prove ownership is refused with a reason that the pass records.
//
// The order of the steps is the safety property:
//
//  1. the current policy, again, because granting authority is the most consequential
//     thing this path does and a setting turned off since the job was created must stop
//     it here rather than after the grant;
//  2. the provider's association for this exact order and server, read from the same
//     read-only surface the tracker already has;
//  3. the ledger association, recorded from that answer - the only new write, and it
//     cannot manufacture provenance;
//  4. the binding proof, which re-reads the ledger and the credential;
//  5. the grant itself, which additionally requires the row to still be automatic,
//     ungranted and without an identity.
func (h *Handlers) GrantAutomaticGigahostSetupBinding(
	ctx context.Context, intent models.GigahostSetupIntent, reader gigahostsetup.ProviderReader,
) (models.GigahostSetupIntent, error) {
	if h.db == nil {
		return intent, errors.New("database not available")
	}
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		// Not an automatic job. Nothing to grant, and nothing to say: a manual approval
		// must never acquire automation authority through this path.
		return intent, nil
	}
	if err := h.requireAutomaticSetupEnabled(ctx); err != nil {
		return intent, fmt.Errorf("automatic authority was not granted: %w", err)
	}
	assoc, err := h.providerOrderAssociation(ctx, intent, reader)
	if err != nil {
		return intent, err
	}
	if _, err := h.db.RecordGigahostSetupProviderAssociation(
		ctx, intent.OrderID, assoc.ID, strings.TrimSpace(assoc.GetIP())); err != nil {
		return intent, err
	}
	return h.grantProvenAutomaticBinding(ctx, intent)
}

// providerOrderAssociation asks the provider which address belongs to this order's
// server, and refuses when its answer contradicts either fact we already hold.
//
// This is the same positive association the trust predicate requires, so a grant can
// never be built on a resource the provider attributes to somebody else. An absent
// answer is not an association: "the provider did not say" cannot grant authority.
func (h *Handlers) providerOrderAssociation(
	ctx context.Context, intent models.GigahostSetupIntent, reader gigahostsetup.ProviderReader,
) (gigahost.ServerInfo, error) {
	if reader == nil {
		return gigahost.ServerInfo{}, errors.New("the provider could not be asked to confirm the order")
	}
	if intent.ProviderServerID <= 0 {
		return gigahost.ServerInfo{}, errors.New("the job records no provider server identity to confirm")
	}
	callCtx, cancel := context.WithTimeout(ctx, providerAssociationTimeout)
	defer cancel()
	servers, err := reader.GetServers(callCtx)
	if err != nil {
		return gigahost.ServerInfo{}, fmt.Errorf("the provider server list could not be read: %w", err)
	}
	for _, s := range servers {
		if s.ID != intent.ProviderServerID {
			continue
		}
		return matchOrderAssociation(s, intent)
	}
	return gigahost.ServerInfo{}, fmt.Errorf(
		"the provider does not list server %d for order %s", intent.ProviderServerID, intent.OrderID)
}

// matchOrderAssociation reads the one provider entry that names this server and reports
// whether it attributes the server to this order at a usable address.
//
// The entry's own order id is required rather than merely non-contradictory, for the
// same reason the trust predicate requires it: for automatic authority "the provider did
// not attribute it" is indistinguishable from "the provider did not say", and neither is
// evidence that this panel owns the resource.
func matchOrderAssociation(s gigahost.ServerInfo, intent models.GigahostSetupIntent) (gigahost.ServerInfo, error) {
	switch {
	case s.OrderID != "" && s.OrderID != intent.OrderID:
		return gigahost.ServerInfo{}, fmt.Errorf(
			"the provider lists server %d under order %q, not %q", s.ID, s.OrderID, intent.OrderID)
	case s.OrderID == "":
		return gigahost.ServerInfo{}, fmt.Errorf(
			"the provider does not attribute server %d to any order", s.ID)
	case strings.TrimSpace(s.GetIP()) == "":
		return gigahost.ServerInfo{}, fmt.Errorf(
			"the provider reports no address for server %d", s.ID)
	}
	return s, nil
}

// providerAssociationTimeout bounds the read this grant depends on. It matches the
// tracker's own provider call budget, so a grant cannot stall a pass longer than a read.
const providerAssociationTimeout = 30 * time.Second

// grantProvenAutomaticBinding proves the binding from durable rows and records the grant.
//
// The proof is what makes the grant narrow: it requires the purchase stamp, the same
// provider server id, a non-empty address and a managed credential registered at the
// provider. Only then is the single-statement grant offered, and that statement adds the
// job-shaped half - still automatic, still ungranted, still pending with no identity.
func (h *Handlers) grantProvenAutomaticBinding(
	ctx context.Context, intent models.GigahostSetupIntent,
) (models.GigahostSetupIntent, error) {
	binding, err := h.db.ProveAutomationBinding(ctx, intent.OrderID, intent.ProviderServerID)
	if err != nil {
		if errors.Is(err, database.ErrAutomationBindingUnproven) {
			return intent, fmt.Errorf(
				"order %s has no proven application-owned purchase binding: %w", intent.OrderID, err)
		}
		return intent, fmt.Errorf("the order binding could not be read: %w", err)
	}
	granted, changed, err := h.db.SetGigahostSetupAutomationBinding(ctx, binding)
	if err != nil {
		return intent, err
	}
	if granted == nil {
		return intent, fmt.Errorf("the grant for order %s could not be read back", intent.OrderID)
	}
	if !changed {
		// The row was not in a shape this grant applies to: already granted, no longer
		// pending, or an identity already recorded. Returning the stored row leaves the
		// pass to decide from the real state, exactly as a repeated grant should.
		return *granted, nil
	}
	return *granted, nil
}
