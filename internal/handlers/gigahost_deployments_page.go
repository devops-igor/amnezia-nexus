package handlers

// Deployments on the Servers page.
//
// The Servers grid is built from the servers table, and a Gigahost deployment acquires a
// row there only when setup registers one (see registerDeployServer). A deployment that
// exists at the provider but has had no setup requested therefore has no card of its own,
// even though it is the state an operator most needs to see: it costs money and it cannot
// carry traffic yet.
//
// This file decides which ledger rows the one grid also lists, and what state each one is
// presented with. The state is the row's own recorded status plus the panel's durable
// existence record - never a derived guess, and never a claim that a provider was read
// while this page was rendered (this page performs no provider call).
//
// An order whose life has ended is listed rather than dropped. Dropping it was why a
// canceled order and an order the provider no longer lists looked, to an administrator,
// like deployments still waiting for setup: they simply were not there, or they appeared
// with the same not-set-up treatment as a live one. It is presented as the deletion it is,
// with nothing to click.

import (
	"context"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// The state a deployment card is presented with. This vocabulary is the same one the
// order-status view module uses for the same rows (gigahost_order_status_model.js maps a
// provider spelling to a stage and presents a cancellation as a deletion), because the
// grid and the deployment list describe one order and must not disagree about it.
const (
	gigahostDeploymentStageDeleted = "deleted"
	gigahostDeploymentStageReady   = "ready"
	gigahostDeploymentStageFailed  = "failed"
	// gigahostDeploymentStageRequested is an accepted order whose deployment has not
	// started yet.
	gigahostDeploymentStageRequested = "requested"
	gigahostDeploymentStageDeploying = "deploying"
	gigahostDeploymentStageUnknown   = "unknown"
)

// The one action a deployment card can offer. An empty action is a card that offers
// nothing, which is the correct presentation for an order whose life has ended: every
// control would contact a deployment the order no longer covers.
const (
	gigahostDeploymentActionSetup = "setup"
	gigahostDeploymentActionRetry = "retry"
)

// gigahostDeploymentRow is one ledger row prepared for the Servers grid. It carries only
// what the page displays, so the template cannot accidentally read a field this page has
// no basis for.
type gigahostDeploymentRow struct {
	OrderID string
	// Name follows the name setup gives the server when it registers it, so the card
	// keeps its identity once the deployment becomes a server.
	Name string
	// Status is the recorded state, verbatim: the panel's copy of the last provider
	// answer or the setup journal's outcome. It is evidence beside the card's state
	// label, not the label itself.
	Status string
	// Address is the provider-assigned address, empty until one exists.
	Address string
	// Stage is the presented state, decided here so the template renders a decision
	// rather than making one.
	Stage string
	// StageKey is the translated label for that state. It is the same stage vocabulary
	// the deployment list uses, so one word change reaches every surface.
	StageKey string
	// Action names the one control this state allows, empty when it allows none.
	Action string
}

// Deleted reports whether this card presents an order whose life has ended.
func (r gigahostDeploymentRow) Deleted() bool {
	return r.Stage == gigahostDeploymentStageDeleted
}

// IsFailed reports a deployment whose last recorded outcome was a failure. It keeps the
// retry its state allows, unlike a finished order.
func (r gigahostDeploymentRow) IsFailed() bool {
	return r.Stage == gigahostDeploymentStageFailed
}

// IsDeploying reports a deployment still working, which is drawn with the in-flight
// badge rather than as something settled.
func (r gigahostDeploymentRow) IsDeploying() bool {
	return r.Stage == gigahostDeploymentStageDeploying
}

// gigahostDeploymentStage maps one ledger row to the state the interface presents.
//
// It delegates the "is this order over" question to models.GigahostOrder.Retired, which is
// the one definition every consumer shares, and only decides the presentation word. The
// operator's question is whether the deployment still exists, not which workflow last
// touched the row, so a recorded absence, a cancellation and a provider-final failure all
// present as the deletion they are: nothing about them is actionable, which is why none of
// them may read as a deployment still waiting for setup.
//
// A failure the panel's own onboarding journal accompanies is deliberately NOT in that
// class. It is execution the operator ran, so it keeps the retry its state allows.
func gigahostDeploymentStage(order models.GigahostOrder) string {
	if order.Retired() {
		return gigahostDeploymentStageDeleted
	}
	return gigahostDeploymentStageForStatus(order.Status)
}

// gigahostDeploymentStageByStatus is the status vocabulary as data: each recorded spelling
// maps to the state it presents.
//
// It is a table rather than an if-chain because the chain had to be re-read to answer "which
// spellings exist", and a spelling nobody listed fell through to the in-flight state - the
// one wrong answer for a newly added provider ending. The vocabulary is also read by
// gigahostDeploymentStageForStatus for the unlisted remainder, so there is one place to
// extend.
var gigahostDeploymentStageByStatus = map[string]string{
	"ready":   gigahostDeploymentStageReady,
	"active":  gigahostDeploymentStageReady,
	"failed":  gigahostDeploymentStageFailed,
	"error":   gigahostDeploymentStageFailed,
	"pending": gigahostDeploymentStageRequested,
	"waiting": gigahostDeploymentStageRequested,
	"":        gigahostDeploymentStageUnknown,
	"unknown": gigahostDeploymentStageUnknown,
	// Remaining spellings a provider uses for an accepted, queued order.
	"pending_payment": gigahostDeploymentStageRequested,
	"pending_order":   gigahostDeploymentStageRequested,
}

// gigahostDeploymentStageForStatus presents one recorded status. An unlisted spelling is a
// deployment the panel has no vocabulary for, which it reports as in flight rather than
// inventing a state.
func gigahostDeploymentStageForStatus(status string) string {
	if stage, known := gigahostDeploymentStageByStatus[strings.ToLower(strings.TrimSpace(status))]; known {
		return stage
	}
	return gigahostDeploymentStageDeploying
}

// gigahostDeploymentAction names the one control a presented state allows: a finished
// order offers none, a failed deployment offers the retry its state allows, and anything
// else offers the setup that is the reason the card exists.
func gigahostDeploymentAction(stage string) string {
	switch stage {
	case gigahostDeploymentStageDeleted:
		return ""
	case gigahostDeploymentStageFailed:
		return gigahostDeploymentActionRetry
	default:
		return gigahostDeploymentActionSetup
	}
}

// gigahostDeploymentsForServers returns the deployments the one Servers grid must list
// because no panel server represents them yet.
//
// An order the panel purchased but the provider never acknowledged (a ledger
// placeholder) is not a deployment and is left out: nothing exists to show. A deployment
// that already has a server card is left out too, matched by the provider server id
// registration stores or by the address the server was created with, so one deployment is
// never shown twice. Everything else is listed, including the ones that have ended.
func gigahostDeploymentsForServers(orders []models.GigahostOrder, servers []models.Server) []gigahostDeploymentRow {
	rows := make([]gigahostDeploymentRow, 0, len(orders))
	for i := range orders {
		order := orders[i]
		if !isRefreshableOrderID(order.OrderID) {
			continue
		}
		if gigahostDeploymentHasServer(order, servers) {
			continue
		}
		// An empty status column is not a state, and the deployment list reads it as
		// unknown too; showing an empty badge would state nothing at all.
		status := strings.TrimSpace(order.Status)
		if status == "" {
			status = "unknown"
		}
		stage := gigahostDeploymentStage(order)
		rows = append(rows, gigahostDeploymentRow{
			OrderID:  order.OrderID,
			Name:     "Gigahost-" + order.OrderID,
			Status:   status,
			Address:  strings.TrimSpace(order.AssignedIP),
			Stage:    stage,
			StageKey: "gigahost_status_stage_" + stage,
			Action:   gigahostDeploymentAction(stage),
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
//
// A provider server id is identity. When the deployment recorded one, only the server
// registered from that same id represents it, and the address is not consulted at all:
// two deployments with different provider ids are two deployments, whatever addresses
// they report. Sharing an address would otherwise merge them, and the one that gained no
// server would vanish from this page while the other kept the card.
//
// The address is a fallback for exactly one case: a ledger row that never recorded a
// provider id. There it is the only evidence the panel holds, and without it such a row
// would be listed twice once setup had registered its server.
func gigahostServerRepresentsDeployment(server models.Server, order models.GigahostOrder) bool {
	if order.ServerID > 0 {
		return gigahostServerMatchesProviderID(server, order)
	}
	return gigahostServerSharesAddress(server, order)
}

// gigahostServerSharesAddress is the fallback for a deployment whose provider id was
// never recorded.
func gigahostServerSharesAddress(server models.Server, order models.GigahostOrder) bool {
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

// gigahostDeploymentsForServersPage reads the ledger for the Servers page.
//
// A read failure is reported as no deployments rather than as an error page: the operator
// asked for their servers, and the pre-existing grid still renders. The deployment cards
// are then simply absent, which invents nothing; a panel-wide notice for a ledger read is
// a separate change and is not part of this one.
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
