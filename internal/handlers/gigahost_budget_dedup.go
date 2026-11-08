package handlers

// Committed-spend accounting for the Gigahost monthly NOK budget.
//
// The budget compares already-committed monthly spend against the configured cap
// before a new order is placed, so every active commitment must be counted
// exactly once: a double count rejects a legitimate purchase, and a dropped
// reservation can overspend. Provider inventory and the local order ledger are
// the same money seen from two sides, so their pairing must be explicit rather
// than dependent on which side happens to carry an order id.

import (
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// localOrderMatchesServer reports whether a local order record belongs to the
// given provider inventory record: a non-empty provider order id must agree, or
// else a positive provider server id must match the recorded server id.
func localOrderMatchesServer(o GigahostOrderRecord, s gigahost.ServerInfo) bool {
	if s.OrderID != "" && o.OrderID == s.OrderID {
		return true
	}
	return s.ID > 0 && o.ServerID == s.ID
}

// matchLocalOrdersForServer marks every local order belonging to a provider
// inventory record and returns the plan id and recorded hourly rate needed to
// price that commitment. Marking matters because a provider record may carry no
// order id, leaving the positive server id as the only link between the two.
func matchLocalOrdersForServer(
	s gigahost.ServerInfo, localOrders []GigahostOrderRecord, accountedLocal []bool,
) (serverPID int, localHourly float64) {
	serverPID = s.PID
	for i, o := range localOrders {
		if !localOrderMatchesServer(o, s) {
			continue
		}
		accountedLocal[i] = true
		if serverPID == 0 && o.PlanID > 0 {
			serverPID = o.PlanID
		}
		if localHourly == 0 && o.HourlyPriceNOK > 0 {
			localHourly = o.HourlyPriceNOK
		}
	}
	return serverPID, localHourly
}

// planHourlyFromOrders returns the recorded hourly price of the first local
// order for the plan, used when no order is linked to the server yet.
func planHourlyFromOrders(localOrders []GigahostOrderRecord, planID int) float64 {
	for _, o := range localOrders {
		if o.PlanID == planID && o.HourlyPriceNOK > 0 {
			return o.HourlyPriceNOK
		}
	}
	return 0
}

// committedSpendFromServers prices active hourly provider inventory. Local orders
// priced with their server are marked in accountedLocal and provider order ids in
// accountedOrders, so the local pass cannot add the same reservation twice.
func committedSpendFromServers(
	catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo, localOrders []GigahostOrderRecord,
	accountedOrders map[string]bool, accountedLocal []bool,
) (float64, error) {
	var committed float64
	for _, s := range servers {
		if !isServerActiveForBudget(s.Status) || !s.IsHourlyVPS() {
			continue
		}
		if s.OrderID != "" {
			accountedOrders[s.OrderID] = true
		}
		serverPID, localHourly := matchLocalOrdersForServer(s, localOrders, accountedLocal)
		if localHourly == 0 {
			localHourly = planHourlyFromOrders(localOrders, serverPID)
		}
		spend := planMonthlySpend(catalog, serverPID, localHourly)
		if spend <= 0 {
			return 0, fmt.Errorf("active inventory server %d (plan %d) has unpriced spend and is absent from catalog", s.ID, serverPID)
		}
		committed += spend
	}
	return committed, nil
}

// committedSpendFromOrders prices the local order ledger, skipping reservations
// already priced with a counted provider server and duplicate order ids.
func committedSpendFromOrders(
	catalog []gigahost.HourlyPlan, localOrders []GigahostOrderRecord,
	accountedOrders map[string]bool, accountedLocal []bool,
) (float64, error) {
	var committed float64
	for i, o := range localOrders {
		if !isOrderActiveForBudget(o.Status) || accountedLocal[i] {
			continue
		}
		if o.OrderID != "" && accountedOrders[o.OrderID] {
			continue
		}
		if o.OrderID != "" {
			accountedOrders[o.OrderID] = true
		}
		spend := planMonthlySpend(catalog, o.PlanID, o.HourlyPriceNOK)
		if spend <= 0 {
			return 0, fmt.Errorf("active order %s (plan %d) has unpriced spend and is absent from catalog", o.OrderID, o.PlanID)
		}
		committed += spend
	}
	return committed, nil
}

// calculateCommittedSpend totals the monthly commitment of active hourly Gigahost
// inventory plus the local order ledger, counting each reservation once.
func calculateCommittedSpend(catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo, localOrders []GigahostOrderRecord) (float64, error) {
	accountedOrders := make(map[string]bool)
	// accountedLocal marks local orders already priced as part of a counted
	// provider server, so the same reservation is not added a second time when
	// the provider record carries no order id and only the positive provider
	// server id links the two.
	accountedLocal := make([]bool, len(localOrders))

	serverSpend, err := committedSpendFromServers(catalog, servers, localOrders, accountedOrders, accountedLocal)
	if err != nil {
		return 0, err
	}
	orderSpend, err := committedSpendFromOrders(catalog, localOrders, accountedOrders, accountedLocal)
	if err != nil {
		return 0, err
	}
	return serverSpend + orderSpend, nil
}
