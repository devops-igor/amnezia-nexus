// Package gigahostevidence collects provider observations for the Gigahost
// reservation ledger.
//
// It exists so the purchase path, the administrator view and the offline
// operator utility all obtain their evidence from one implementation. The
// interpretation of that evidence stays in internal/service/gigahostbudget,
// which performs no I/O; this package performs the I/O and nothing else, so a
// wrong inference cannot be introduced here and a second, drifting collector
// cannot appear next to it.
//
// Every call here is a read. This package never orders, cancels or deletes
// anything, and it never queries an identifier the provider did not issue: a
// locally generated order id names nothing at the provider, so asking about it
// would produce an answer that means nothing.
package gigahostevidence

import (
	"context"
	"errors"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// Limits bounds one collection pass so a large legacy ledger cannot turn a
// single run into a provider hammering loop.
type Limits struct {
	// MaxOrderLookups is the maximum number of deployment-status reads one pass
	// may spend. A value <= 0 disables order lookups entirely; inventory is
	// still read by the caller.
	MaxOrderLookups int
}

// Observation is what was observed at the provider for one ledger row, kept
// together with the exact row it was observed against.
//
// Expect is the complete pre-I/O ledger row. A later write must compare against
// it inside the same transaction, because an observation only describes the row
// as it was when it was read.
type Observation struct {
	Evidence gigahostbudget.Evidence
	Expect   models.GigahostOrder
}

// Result is one completed pass.
type Result struct {
	// Observations is keyed by ledger record id.
	Observations map[int64]Observation
	// OrderLookups is how many deployment-status reads were actually issued.
	OrderLookups int
}

// Plans converts provider catalog rows for the shared calculation.
func Plans(in []gigahost.HourlyPlan) []gigahostbudget.Plan {
	out := make([]gigahostbudget.Plan, 0, len(in))
	for _, p := range in {
		out = append(out, gigahostbudget.Plan{
			ProductID:      p.ProductID,
			PriceID:        p.PriceID,
			Currency:       p.Currency,
			HourlyRateNOK:  p.HourlyRateNOK,
			MonthlyCeiling: p.MonthlyCeiling,
		})
	}
	return out
}

// Servers converts provider inventory rows for the shared calculation.
func Servers(in []gigahost.ServerInfo) []gigahostbudget.Server {
	out := make([]gigahostbudget.Server, 0, len(in))
	for _, s := range in {
		out = append(out, gigahostbudget.Server{
			ID:      s.ID,
			OrderID: s.OrderID,
			PlanID:  s.PID,
			Status:  s.Status,
			Hourly:  s.IsHourlyVPS(),
		})
	}
	return out
}

// Entries converts ledger rows for the shared calculation.
func Entries(in []models.GigahostOrder) []gigahostbudget.Entry {
	out := make([]gigahostbudget.Entry, 0, len(in))
	for _, o := range in {
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

// Collect observes the provider for every ledger row that can still take part in
// a budget decision, using only authoritative identities.
//
// A released row IS observed: its marker records a past decision, and the
// provider may since have made the obligation live again (a held order deploys
// by itself), so the observation is what lets the decision override a stale
// marker.
//
// A row whose local status already ends the attempt and that carries no release
// marker is skipped: nothing can be released there and nothing can be re-priced
// into a live obligation.
func Collect(
	ctx context.Context, client gigahost.Client, servers []gigahost.ServerInfo,
	orders []models.GigahostOrder, limits Limits,
) Result {
	res := Result{Observations: make(map[int64]Observation, len(orders))}
	if client == nil {
		return res
	}
	shared := Servers(servers)
	entries := Entries(orders)

	for i, o := range orders {
		if shouldSkip(o) {
			continue
		}
		obs := Observation{Expect: o}
		if obs.Evidence.ServerFound, obs.Evidence.ServerStatus = matchServer(entries[i], shared); !obs.Evidence.ServerFound {
			obs.Evidence.ServerStatus = ""
		}
		if canQuery(o) && res.OrderLookups < limits.MaxOrderLookups {
			res.OrderLookups++
			readDeployStatus(ctx, client, o.OrderID, &obs.Evidence)
		}
		res.Observations[o.ID] = obs
	}
	return res
}

// shouldSkip reports a row that neither the classifier nor a release can act on.
func shouldSkip(o models.GigahostOrder) bool {
	return o.ReleasedAt == "" && gigahostbudget.IsLocallyTerminal(o.Status)
}

// matchServer finds the inventory row that is the same VPS as the ledger row.
func matchServer(e gigahostbudget.Entry, servers []gigahostbudget.Server) (found bool, status string) {
	for _, s := range servers {
		if gigahostbudget.EntryMatchesServer(e, s) {
			return true, s.Status
		}
	}
	return false, ""
}

// canQuery reports whether the order id is one the provider actually issued.
func canQuery(o models.GigahostOrder) bool {
	return o.OrderID != "" && !gigahostbudget.IsSyntheticOrderID(o.OrderID)
}

// readDeployStatus records one deployment-status answer.
//
// Every outcome is mapped to a distinct observation, because they are different
// facts: a listed order, an answer with no status, an omission (which the
// contract states also covers canceled orders and deleted servers, so it proves
// nothing) and a failed call (which proves nothing at all).
func readDeployStatus(ctx context.Context, client gigahost.Client, orderID string, ev *gigahostbudget.Evidence) {
	resp, err := client.GetDeployStatus(ctx, orderID)
	switch {
	case err == nil && resp != nil && resp.Status != "":
		ev.ProviderOrderFound = true
		ev.ProviderOrderStatus = resp.Status
	case err == nil:
		// The provider listed the order without a status: not a statement
		// about billing, so nothing is concluded from it.
	case errors.Is(err, gigahost.ErrNotFound):
		ev.OrderOmittedFromDeployStatus = true
	default:
		ev.OrderQueryFailed = true
	}
}
