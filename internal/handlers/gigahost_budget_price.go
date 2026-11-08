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
)

// Re-exported shared errors so existing callers and tests keep their oracle.
var (
	errSpendUnpriced         = gigahostbudget.ErrSpendUnpriced
	errPriceNotIdentifiable  = gigahostbudget.ErrPriceNotIdentifiable
	errCurrencyNotComparable = gigahostbudget.ErrCurrencyNotComparable
)

// budgetPlans converts catalog rows for the shared calculation.
func budgetPlans(catalog []gigahost.HourlyPlan) []gigahostbudget.Plan {
	plans := make([]gigahostbudget.Plan, 0, len(catalog))
	for _, p := range catalog {
		plans = append(plans, gigahostbudget.Plan{
			ProductID:      p.ProductID,
			PriceID:        p.PriceID,
			Currency:       p.Currency,
			HourlyRateNOK:  p.HourlyRateNOK,
			MonthlyCeiling: p.MonthlyCeiling,
		})
	}
	return plans
}

// budgetServers converts provider inventory rows for the shared calculation.
func budgetServers(servers []gigahost.ServerInfo) []gigahostbudget.Server {
	out := make([]gigahostbudget.Server, 0, len(servers))
	for _, s := range servers {
		out = append(out, gigahostbudget.Server{
			ID:      s.ID,
			OrderID: s.OrderID,
			PlanID:  s.PID,
			Status:  s.Status,
			IP:      s.GetIP(),
			Hourly:  s.IsHourlyVPS(),
		})
	}
	return out
}

// budgetEntries converts ledger rows for the shared calculation.
func budgetEntries(orders []GigahostOrderRecord) []gigahostbudget.Entry {
	out := make([]gigahostbudget.Entry, 0, len(orders))
	for _, o := range orders {
		out = append(out, gigahostbudget.Entry{
			RecordID:       o.ID,
			OrderID:        o.OrderID,
			ServerID:       o.ServerID,
			Status:         o.Status,
			PlanID:         o.PlanID,
			RegionID:       o.RegionID,
			HourlyPriceNOK: o.HourlyPriceNOK,
			PriceID:        o.PriceID,
			MonthlyCapNOK:  o.MonthlyCapNOK,
			Currency:       o.Currency,
			AssignedIP:     o.AssignedIP,
			ReleasedAt:     o.ReleasedAt,
			ReleaseReason:  o.ReleaseReason,
		})
	}
	return out
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
