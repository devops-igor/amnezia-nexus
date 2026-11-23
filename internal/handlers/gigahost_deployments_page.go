package handlers

// Deployments on the Servers page.
//
// The Servers list is built from the servers table, and a Gigahost deployment acquires a
// row there only when setup registers one (see registerDeployServer). A deployment that
// exists at the provider but has had no setup requested is therefore invisible on the
// page, even though it is the state an operator most needs to see: it costs money and it
// cannot carry traffic yet.
//
// This file closes that gap without touching provisioning: it names the ledger rows the
// page must show, and how each one is presented. The state shown is the row's own
// recorded status - the panel's copy of the last provider answer or the setup journal's
// outcome - never a derived guess, and never a claim that a provider was read while this
// page was rendered (this page performs no provider call).

import (
	"context"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// gigahostDeploymentGoneSpellings are the recorded statuses that mean the deployment no
// longer exists at the provider. Such a row is history, not a server that is coming, so
// the Servers page does not offer it as one. `failed` is deliberately absent: a failed
// deployment still exists and the operator has to see it to retry or remove it.
//
//nolint:misspell // "cancelled" is the provider's own spelling, accepted beside "canceled"
var gigahostDeploymentGoneSpellings = []string{"cancelled", "canceled", "deleted", "terminated"}

// gigahostDeploymentRow is one ledger row prepared for the Servers page. It carries only
// what the page displays, so the template cannot accidentally read a field this page has
// no basis for.
type gigahostDeploymentRow struct {
	OrderID string
	// Name follows the name setup gives the server when it registers it, so the card
	// keeps its identity once the deployment becomes a server.
	Name string
	// Status is the recorded state, verbatim. It is the panel's own record, so it is
	// shown as recorded rather than translated into a second vocabulary that could
	// disagree with the status view in Settings.
	Status string
	// BadgeClass is the existing badge vocabulary, chosen from the same status.
	BadgeClass string
	// Address is the provider-assigned address, empty until one exists.
	Address string
}

// gigahostDeploymentsForServers returns the deployments the Servers page must show
// because no panel server represents them yet.
//
// An order the panel purchased but the provider never acknowledged (a ledger placeholder)
// is not a deployment and is left out: nothing exists to show. A deployment that already
// has a server card is left out too, matched by the provider server id registration
// stores or by the address the server was created with, so one deployment is never shown
// twice.
func gigahostDeploymentsForServers(orders []models.GigahostOrder, servers []models.Server) []gigahostDeploymentRow {
	rows := make([]gigahostDeploymentRow, 0, len(orders))
	for i := range orders {
		order := orders[i]
		if !isRefreshableOrderID(order.OrderID) {
			continue
		}
		if gigahostDeploymentGone(order.Status) || gigahostDeploymentHasServer(order, servers) {
			continue
		}
		// An empty status column is not a state, and the status view in Settings reads it
		// as unknown too; showing an empty badge would state nothing at all.
		status := strings.TrimSpace(order.Status)
		if status == "" {
			status = "unknown"
		}
		rows = append(rows, gigahostDeploymentRow{
			OrderID:    order.OrderID,
			Name:       "Gigahost-" + order.OrderID,
			Status:     status,
			BadgeClass: gigahostDeploymentBadgeClass(status),
			Address:    strings.TrimSpace(order.AssignedIP),
		})
	}
	return rows
}

// gigahostDeploymentHasServer reports whether a panel server already represents this
// deployment. The provider server id is the link registration records; the address is
// the fallback for a row whose provider id was never recorded.
func gigahostDeploymentHasServer(order models.GigahostOrder, servers []models.Server) bool {
	for i := range servers {
		if gigahostServerRepresentsDeployment(servers[i], order) {
			return true
		}
	}
	return false
}

// gigahostServerRepresentsDeployment is the one place that decides whether one server
// row is the panel's record of one deployment.
func gigahostServerRepresentsDeployment(server models.Server, order models.GigahostOrder) bool {
	if gigahostServerMatchesProviderID(server, order) {
		return true
	}
	return order.AssignedIP != "" && strings.EqualFold(strings.TrimSpace(server.Host), order.AssignedIP)
}

// gigahostServerMatchesProviderID reports a server registered from this deployment's
// provider server id. Registration writes both the provider name and that id into the
// server's protocols, so both must agree before the match is claimed.
func gigahostServerMatchesProviderID(server models.Server, order models.GigahostOrder) bool {
	if order.ServerID <= 0 || server.Protocols == nil {
		return false
	}
	provider, ok := server.Protocols["provider"].(string)
	if !ok || !strings.EqualFold(provider, "gigahost") {
		return false
	}
	return matchProviderServerID(server.Protocols["provider_server_id"], order.ServerID)
}

// gigahostDeploymentGone reports a recorded status that means the deployment is over.
func gigahostDeploymentGone(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	for _, gone := range gigahostDeploymentGoneSpellings {
		if s == gone {
			return true
		}
	}
	return false
}

// gigahostDeploymentBadgeClass maps the recorded status onto the existing badge
// vocabulary. An unrecognized status is neutral, never green: a state this page does not
// understand must not look settled.
func gigahostDeploymentBadgeClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ready", "active":
		return "badge-success"
	case "failed", "error", "unavailable", "cancelled", "canceled", "deleted", "terminated": //nolint:misspell // provider spellings
		return "badge-danger"
	case "", "unknown":
		return "badge-secondary"
	default:
		return "badge-info"
	}
}

// gigahostDeploymentsForServersPage reads the ledger for the Servers page.
//
// A read failure is reported as no deployments rather than as an error page: the operator
// asked for their servers, and the pre-existing list still renders. The section is then
// simply absent, which invents nothing; a panel-wide notice for a ledger read is a
// separate change and is not part of this one.
func (h *Handlers) gigahostDeploymentsForServersPage(ctx context.Context, servers []models.Server) []gigahostDeploymentRow {
	if h.db == nil {
		return nil
	}
	orders, err := h.db.ListGigahostDeployments(ctx)
	if err != nil {
		return nil
	}
	return gigahostDeploymentsForServers(orders, servers)
}
