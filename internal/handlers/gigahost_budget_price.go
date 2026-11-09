package handlers

// Adapters between the handler's provider types and the shared budget
// calculation in internal/service/gigahostbudget.
//
// The purchase path, the admin breakdown and the operator recovery utility all
// call the same shared functions, so display and decision cannot disagree and a
// recovery proposal is derived from the identical reasoning. Only conversion
// lives here; the policy lives in the shared package.

import (
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostevidence"
)

// Re-exported shared errors so existing callers and tests keep their oracle.
var (
	errSpendUnpriced        = gigahostbudget.ErrSpendUnpriced
	errPriceNotIdentifiable = gigahostbudget.ErrPriceNotIdentifiable
)

// budgetPlans converts catalog rows for the shared calculation.
func budgetPlans(catalog []gigahost.HourlyPlan) []gigahostbudget.Plan {
	return gigahostevidence.Plans(catalog)
}

// budgetServers converts provider inventory rows for the shared calculation.
func budgetServers(servers []gigahost.ServerInfo) []gigahostbudget.Server {
	return gigahostevidence.Servers(servers)
}

// budgetEntries converts ledger rows for the shared calculation.
func budgetEntries(orders []GigahostOrderRecord) []gigahostbudget.Entry {
	return gigahostevidence.Entries(orders)
}

// existingMonthlySpend resolves the monthly commitment of an existing hourly
// reservation through the shared resolver.
func existingMonthlySpend(catalog []gigahost.HourlyPlan, pid int, recordedHourly float64) (float64, error) {
	amount, _, err := gigahostbudget.ResolveExistingAmount(budgetPlans(catalog), pid, 0, "", recordedHourly)
	return amount, err
}

// calculateCommittedSpend totals the monthly commitment of active hourly
// Gigahost inventory plus the local order ledger, counting each reservation
// once. It is the pre-existing handler-level entry point kept for the existing
// regressions; the shared Evaluate is the single implementation.
func calculateCommittedSpend(catalog []gigahost.HourlyPlan, servers []gigahost.ServerInfo, localOrders []GigahostOrderRecord) (float64, error) {
	res, err := gigahostbudget.Evaluate(gigahostbudget.Input{
		Plans:   budgetPlans(catalog),
		Servers: budgetServers(servers),
		Entries: budgetEntries(localOrders),
	})
	if err != nil {
		return 0, err
	}
	return res.CommittedNOK, nil
}
