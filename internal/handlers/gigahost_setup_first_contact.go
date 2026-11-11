package handlers

// Ownership proof for automatic first-contact host trust.
//
// Automatic trust means the panel records the host identity it observed itself,
// without a person confirming the value. That is only acceptable for a resource the
// panel provably created and can provably reach: a real provider order this account
// placed, with the managed credential the panel stored for it, whose published
// server identity matches the job exactly.
//
// This file is the only place that answers that question, and it answers it from
// durable records rather than from the caller's claims:
//
//   - the order must be a real provider order, not the ledger's placeholder for an
//     unresolved purchase;
//   - the ledger row must carry a contracted plan and the provider server id this
//     job is about, so the row and the job describe the same purchase;
//   - the managed SSH credential must exist with the provider-side key id the
//     purchase path recorded, which no imported or hand-built row has;
//   - the provider's own server list must positively list that server under this
//     order and with the address the job is about to dial;
//   - no registered panel server may already claim that provider server id or that
//     address, because a registered-but-unbound server is imported or unknown
//     install history and must stay a manual decision.
//
// Every one of those is a refusal on its own. A refusal is not an error: it means
// "this job uses the manual path", which is the existing behavior and is always
// available.

import (
	"context"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// firstContactEligible reports whether this job may pin its own first observation,
// with a bounded reason when it may not.
//
// The order of the checks is deliberate: the cheapest and most local facts come
// first, so a job that cannot possibly qualify never causes a provider call. Each
// group of facts is also answered by its own function, so the reason a job was
// refused names the group the refusal came from instead of one long predicate.
func (h *Handlers) firstContactEligible(
	ctx context.Context, intent models.GigahostSetupIntent,
) (bool, string) {
	orderID, reason, ok := h.firstContactAuthority(intent)
	if !ok {
		return false, reason
	}

	if reason, ok := h.firstContactOrderProof(ctx, intent, orderID); !ok {
		return false, reason
	}
	if reason, ok := h.firstContactCredentialProof(ctx, orderID); !ok {
		return false, reason
	}

	// Positive provider association: the server must be listed for this exact
	// order and must publish the address the job will dial. A server the provider
	// does not list, lists for another order, or lists at another address is not
	// this job's resource.
	if reason, ok := h.firstContactProviderAssociation(ctx, intent); !ok {
		return false, reason
	}

	// A registered server already claiming this provider identity, or already
	// answering on this address, is imported or unknown install history: its trust
	// is a human decision and it never inherits automatic authority.
	registered, conflict, err := h.firstContactRegistrationConflict(ctx, intent)
	if err != nil {
		return false, "the registered servers could not be read"
	}
	if registered {
		return false, conflict
	}
	return true, ""
}

// firstContactAuthority answers the two gates that come before any ownership fact: does
// this job carry the automation policy at all, and is its order a real provider order.
//
// A manual job is refused with no recorded reason, because it never asked for
// automation and a diagnosis in its error field would be advice nobody requested.
func (h *Handlers) firstContactAuthority(intent models.GigahostSetupIntent) (string, string, bool) {
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		return "", "", false
	}
	if h.db == nil {
		return "", "the panel has no database to prove ownership with", false
	}
	orderID := strings.TrimSpace(intent.OrderID)
	if orderID == "" || models.IsSyntheticGigahostOrderID(orderID) {
		return "", "the job does not refer to a provider order", false
	}
	return orderID, "", true
}

// firstContactOrderProof checks the ledger facts that only a purchase this panel made
// produces: a recorded order with a contracted plan, described by the same provider
// server identity and address the job is about to use.
//
// A row the deploy-status mirror created for an order the panel never placed has no
// plan, and that is precisely what this refuses. It is a proxy for "this panel owns
// the resource" until the automation controller supplies an explicit origin.
func (h *Handlers) firstContactOrderProof(
	ctx context.Context, intent models.GigahostSetupIntent, orderID string,
) (string, bool) {
	order, found, err := h.db.GetGigahostOrder(ctx, orderID)
	if err != nil {
		return "the order ledger could not be read", false
	}
	if !found || order == nil {
		return "the order is not recorded in the ledger", false
	}
	if order.PlanID <= 0 {
		return "the order records no contracted plan, so the panel did not place it", false
	}
	if intent.ProviderServerID <= 0 || order.ServerID != intent.ProviderServerID {
		return "the order and the job disagree about the provider server identity", false
	}
	if strings.TrimSpace(intent.AssignedIP) == "" {
		return "the job records no address to trust", false
	}
	return "", true
}

// firstContactCredentialProof checks that the managed credential exists and was
// registered at the provider.
//
// The provider-side key id is the correlation between what this order authorized and
// the material the panel will log in with, and only the purchase path produces it. An
// imported order, a hand-entered key or a bootstrap row therefore fails here.
func (h *Handlers) firstContactCredentialProof(ctx context.Context, orderID string) (string, bool) {
	credential, hasCredential, err := h.db.GetGigahostOrderCredential(ctx, orderID)
	if err != nil {
		return "the managed credential could not be read", false
	}
	if !hasCredential || credential == nil {
		return "the order carries no managed credential", false
	}
	if credential.ProviderKeyID <= 0 {
		return "the managed credential was not registered with the provider", false
	}
	return "", true
}

// firstContactProviderAssociation asks the provider's own server list whether this
// server belongs to this order at this address.
//
// The absence of an entry is a refusal, unlike the tracker's association check which
// tolerates it: for automatic trust, "the provider did not say" is not evidence that
// the panel owns the resource.
func (h *Handlers) firstContactProviderAssociation(
	ctx context.Context, intent models.GigahostSetupIntent,
) (string, bool) {
	reader, err := h.ResolveGigahostSetupProvider(ctx)
	if err != nil {
		return "the provider could not be asked to confirm the order", false
	}
	// Bounded, like every other provider call in this package: the ownership
	// question must not be able to stall a tracking pass on a slow provider.
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	servers, err := reader.GetServers(callCtx)
	if err != nil {
		return "the provider server list could not be read", false
	}
	for _, s := range servers {
		if s.ID == intent.ProviderServerID {
			return matchListedProviderServer(s, intent)
		}
	}
	return "the provider does not list that server for this order", false
}

// matchListedProviderServer reads the one provider entry that names this server and
// answers whether it attributes the server to this order at this address.
//
// The entry's own order id is required, not merely non-contradictory: for automatic trust
// "the provider did not attribute it" is indistinguishable from "the provider did not say",
// and neither is evidence that this panel owns the resource.
func matchListedProviderServer(s gigahost.ServerInfo, intent models.GigahostSetupIntent) (string, bool) {
	switch {
	case s.OrderID != "" && s.OrderID != intent.OrderID:
		// Someone else's server: the strongest form of the refusal, because the id
		// this job claims belongs to a different purchase.
		return "the provider lists that server under a different order", false
	case s.OrderID == "":
		// The provider knows the server but does not attribute it to any order.
		return "the provider does not attribute that server to this order", false
	case strings.TrimSpace(s.GetIP()) != "" && strings.TrimSpace(s.GetIP()) != strings.TrimSpace(intent.AssignedIP):
		return "the provider lists that server at a different address", false
	default:
		return "", true
	}
}

// firstContactRegistrationConflict reports whether a registered panel server already
// claims this provider identity or this address.
//
// A server that claims the provider server id is the same resource with existing
// history. A server that answers on the same address is address reuse, which must not
// silently become the same trust decision.
func (h *Handlers) firstContactRegistrationConflict(
	ctx context.Context, intent models.GigahostSetupIntent,
) (bool, string, error) {
	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		return false, "", err
	}
	ip := strings.TrimSpace(intent.AssignedIP)
	for _, s := range servers {
		if isRegisteredForProviderServer(s, intent.ProviderServerID) {
			return true, "a panel server is already registered for this provider server", nil
		}
		if strings.EqualFold(strings.TrimSpace(s.Host), ip) {
			return true, "a panel server is already registered at this address", nil
		}
	}
	return false, "", nil
}

// isRegisteredForProviderServer reports whether a stored server claims this provider
// server id for this provider.
func isRegisteredForProviderServer(s models.Server, providerServerID int64) bool {
	if providerServerID <= 0 || s.Protocols == nil {
		return false
	}
	provider, ok := s.Protocols["provider"].(string)
	if !ok || !strings.EqualFold(provider, "gigahost") {
		return false
	}
	return matchProviderServerID(s.Protocols["provider_server_id"], providerServerID)
}
