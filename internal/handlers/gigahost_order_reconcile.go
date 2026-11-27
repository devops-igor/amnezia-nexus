package handlers

// The order-level existence reconciliation.
//
// The provider's server inventory is the panel's only durable evidence that a
// deployment still exists. The server-row half of that evidence lives in
// gigahost_inventory.go; this file keeps the same fact on the ledger row, because
// an order that never registered a panel server has no server row to mark, and an
// order the provider no longer lists must stop being refreshed and stop being
// offered for setup.
//
// The fail-safe direction is the whole rule. Absence is written only when ALL of
// the following held for one read:
//
//   - the inventory read succeeded, and every entry in it named a usable provider
//     server id, so the answer is a complete enumeration rather than a partial one;
//   - the account that answered it could be identified, because one account's
//     listing says nothing about another account's orders;
//   - the order was observed under that same account, from a provider answer that
//     named it or the server it registered;
//   - the order's recorded state says a deployment exists to be listed (the
//     provider named a server for it, or the last status was ready).
//
// A failed, timed-out or unattributable read, an unknown account association and an
// order that has not deployed yet all change nothing. An order a later listing names
// has its record cleared, and clearing needs none of the above: presence is positive
// evidence on its own.
//
// This file performs no provider call of its own beyond the account identity that
// attributes the listing it is handed, and it never deletes a ledger row.

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// gigahostOrderNeedsExistenceCheck reports whether one order is one the provider's
// inventory is expected to account for.
//
// An order still being placed is not absent from a listing, it is simply not
// deployed yet, and a purchase the provider never acknowledged has no deployment at
// all. Judging either would record a deletion the provider never performed. An
// order the provider gave a server id for, or whose last confirmed state was ready,
// is the population this record exists for.
func gigahostOrderNeedsExistenceCheck(order *GigahostOrderRecord) bool {
	if order == nil || !isRefreshableOrderID(strings.TrimSpace(order.OrderID)) {
		return false
	}
	if isPendingOrInFlight(order.Status) {
		return false
	}
	return order.ServerID > 0 || isGigahostReady(order.Status)
}

// gigahostOrderPurchasedByPanel reports whether this panel's own purchase writer
// created the row, which is the only provenance the panel records for an order.
func gigahostOrderPurchasedByPanel(order *GigahostOrderRecord) bool {
	return order != nil && strings.TrimSpace(order.PurchaseOrigin) == models.PurchaseOriginPanelPurchase
}

// gigahostOrderObservedAccount returns the provider account this order is known to
// belong to, or "" when the panel holds no such association.
//
// Two provider answers can establish it, and both are answers about this order: the
// listing that named it, and the server row it registered, whose own account the
// registration recorded. The configured credential is deliberately not a source: an
// association borrowed from whichever key happens to be configured would let a key
// replacement mark another account's orders gone.
func gigahostOrderObservedAccount(order *GigahostOrderRecord, panelServers []models.Server) string {
	if order == nil {
		return ""
	}
	if account := strings.TrimSpace(order.ProviderAccountID); account != "" {
		return account
	}
	for i := range panelServers {
		if !gigahostServerRepresentsDeployment(panelServers[i], *order) {
			continue
		}
		if account := strings.TrimSpace(panelServers[i].ProviderAccountID); account != "" {
			return account
		}
	}
	return ""
}

// gigahostOrderAttributingAccount resolves the account an inventory answer was read
// from. An answer that cannot be attributed proves nothing about any order, so the
// caller records nothing.
func (h *Handlers) gigahostOrderAttributingAccount(ctx context.Context, client gigahost.Client) string {
	if client == nil {
		return ""
	}
	account, err := client.GetAccount(ctx)
	if err != nil {
		return ""
	}
	return gigahostAccountIdentity(account)
}

// gigahostReconcileOrderExistence records, on the ledger, whether a successful
// inventory answer still lists each order.
//
// observedAt is the instant the listing was requested, not the moment it was
// applied: the answer describes that instant, and stamping the observation later
// would claim more than the listing can.
//
// orders is modified in place for the rows whose record changed, so the response
// built from the same read presents the observation it just made rather than the
// state it loaded. panelServers is the whole server read: a deployment's account
// association can be recorded on the row it registered.
func (h *Handlers) gigahostReconcileOrderExistence(
	ctx context.Context, client gigahost.Client, orders []GigahostOrderRecord,
	panelServers []models.Server, inventory []gigahost.ServerInfo, inventoryKnown bool, observedAt time.Time,
) {
	if h == nil || h.db == nil || !inventoryKnown || len(orders) == 0 {
		return
	}
	// A listing with an entry that names no server is not evidence about the
	// account it claims to enumerate, so the whole answer is refused and every row
	// keeps the state it had.
	if _, err := gigahostIdentifiedServerIDs(inventory); err != nil {
		slog.Warn("Gigahost inventory could not identify every entry; order existence unchanged", "err", err)
		return
	}
	judged := false
	for i := range orders {
		if gigahostOrderNeedsExistenceCheck(&orders[i]) {
			judged = true
			break
		}
	}
	if !judged {
		return
	}
	accountID := h.gigahostOrderAttributingAccount(ctx, client)
	if accountID == "" {
		return
	}
	for i := range orders {
		h.gigahostReconcileOneOrder(ctx, &orders[i], panelServers, inventory, accountID, observedAt)
	}
}

// gigahostReconcileOneOrder applies one attributed inventory answer to one order.
func (h *Handlers) gigahostReconcileOneOrder(
	ctx context.Context, order *GigahostOrderRecord, panelServers []models.Server,
	inventory []gigahost.ServerInfo, accountID string, observedAt time.Time,
) {
	if !gigahostOrderNeedsExistenceCheck(order) {
		return
	}
	if entry, listed := inventoryServerForOrder(inventory, order); listed {
		h.recordGigahostOrderPresence(ctx, order, entry, accountID)
		return
	}
	// The listing omits the order. That is absence only for the account that
	// answered: an order of another account, or one with no recorded account, is
	// simply outside what this answer can see.
	account := gigahostOrderObservedAccount(order, panelServers)
	if account == "" && gigahostOrderPurchasedByPanel(order) {
		// One case has no provider answer to learn the association from, and it is
		// the case this record exists for: an order this panel bought, whose
		// deployment the provider no longer lists, so neither a listing entry nor the
		// server it registered can name its account any more. The purchase itself is
		// the association the panel holds - the row was written by the writer that
		// commits before the provider is asked to sell anything, and a panel holds one
		// provider credential - so the account that answered is recorded on the row,
		// once, and the retirement proceeds. It is logged because it is an inference
		// about provenance rather than a provider statement, and it is durable: a
		// later answer that names the order corrects it, and the configured key
		// changing afterwards does not re-judge a row whose account is recorded.
		slog.Info("Recording the provider account of a panel purchase from the inventory read that answered",
			"order_id", order.OrderID)
		if err := h.db.SetGigahostOrderProviderAccount(ctx, order.OrderID, accountID); err != nil {
			slog.Warn("Could not record the provider account of a Gigahost order", "order_id", order.OrderID, "err", err)
			return
		}
		order.ProviderAccountID = accountID
		account = accountID
	}
	if account != accountID {
		return
	}
	if order.ProviderAbsent() && order.ProviderAbsentAccountID == accountID {
		return
	}
	if err := h.db.SetGigahostOrderAbsence(ctx, order.OrderID, observedAt, accountID); err != nil {
		slog.Warn("Could not record provider absence for a Gigahost order", "order_id", order.OrderID, "err", err)
		return
	}
	order.ProviderAbsentAt = observedAt.UTC().Format(time.RFC3339)
	order.ProviderAbsentAccountID = accountID
}

// recordGigahostOrderPresence clears any absence record for an order the listing
// names, and records the account it was named under.
//
// Presence is positive evidence and needs no account match to clear a mark. The
// association is written only from an answer that agrees with the account the read
// was attributed to: an entry claiming a different account than the one that
// answered is an inconsistent answer, and no association is recorded from it.
func (h *Handlers) recordGigahostOrderPresence(
	ctx context.Context, order *GigahostOrderRecord, entry gigahost.ServerInfo, accountID string,
) {
	if order.ProviderAbsent() {
		if err := h.db.SetGigahostOrderAbsence(ctx, order.OrderID, time.Time{}, ""); err != nil {
			slog.Warn("Could not clear provider absence for a Gigahost order", "order_id", order.OrderID, "err", err)
		} else {
			order.ProviderAbsentAt = ""
			order.ProviderAbsentAccountID = ""
		}
	}
	association := strings.TrimSpace(entry.CustID.String())
	if association == "" {
		association = accountID
	} else if association != accountID {
		return
	}
	if strings.TrimSpace(order.ProviderAccountID) == association {
		return
	}
	if err := h.db.SetGigahostOrderProviderAccount(ctx, order.OrderID, association); err != nil {
		slog.Warn("Could not record the provider account of a Gigahost order", "order_id", order.OrderID, "err", err)
		return
	}
	order.ProviderAccountID = association
}
