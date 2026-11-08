package handlers

// Order-independent monthly commitment for an EXISTING Gigahost reservation.
//
// The provider's contract for an hourly order is the per-order rate/monthly cap
// that the order call returns; a local record only carries the plan id and the
// hourly rate resolved at order time, and no server, order or billing object
// carries the catalog price id. An existing reservation therefore cannot be
// mapped back to one catalog row by identity, and picking "the first row for
// the plan" made the same reservation cost 41 or 120 NOK depending only on
// catalog order.
//
// The amount is resolved from what is unambiguously available and otherwise
// fails closed:
//  1. Catalog rows for the plan are reduced to their DISTINCT monthly amounts.
//     A single amount is the answer: catalog order cannot matter.
//  2. With several amounts, the hourly rate recorded when the order was placed
//     may select the rows carrying it. Exactly one remaining amount is the
//     answer.
//  3. Otherwise the contracted cost is not identifiable: report an error. Never
//     the cheapest row, never the first row, never zero.
//
// The pre-existing "plan absent from catalog" behavior (recorded hourly rate
// times 720, else fail closed) is deliberately unchanged.
//
// Known limitation: when the only catalog row for a plan has changed price
// since the order, step 1 reports the current catalog amount and the drift is
// not detected. Only the provider's own order-time contract can resolve that,
// which needs the order response to be persisted.

import (
	"errors"
	"fmt"
	"math"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

var (
	// errSpendUnpriced is the pre-existing fail-closed state: the plan has no
	// usable catalog price and no recorded rate to estimate one.
	errSpendUnpriced = errors.New("has unpriced spend and is absent from catalog")
	// errPriceNotIdentifiable reports that the catalog offers more than one
	// possible monthly cost for the plan and no evidence chooses between them.
	errPriceNotIdentifiable = errors.New("has more than one monthly price in the catalog and the contracted price is not identifiable")
)

// priceAmountEpsilon is the tolerance used to compare NOK amounts and hourly
// rates. Real tiers differ by a whole NOK or by at least a hundredth of a NOK
// per hour, far above this bound, so distinct prices are never merged.
const priceAmountEpsilon = 1e-6

// catalogMonthlyAmount is the monthly commitment a catalog row represents.
func catalogMonthlyAmount(p gigahost.HourlyPlan) float64 {
	if p.MonthlyCeiling > 0 {
		return p.MonthlyCeiling
	}
	if p.HourlyRateNOK > 0 {
		return p.HourlyRateNOK * 720
	}
	return 0
}

// catalogRowsForPlan returns every catalog row for one product, in catalog order.
func catalogRowsForPlan(catalog []gigahost.HourlyPlan, pid int) []gigahost.HourlyPlan {
	var rows []gigahost.HourlyPlan
	for _, p := range catalog {
		if p.ProductID == pid {
			rows = append(rows, p)
		}
	}
	return rows
}

// distinctMonthlyAmounts returns the distinct positive monthly amounts of the
// rows, in first-seen order. Unpriced rows contribute nothing.
func distinctMonthlyAmounts(rows []gigahost.HourlyPlan) []float64 {
	var amounts []float64
	for _, r := range rows {
		amount := catalogMonthlyAmount(r)
		if amount <= 0 {
			continue
		}
		seen := false
		for _, known := range amounts {
			if math.Abs(known-amount) <= priceAmountEpsilon {
				seen = true
				break
			}
		}
		if !seen {
			amounts = append(amounts, amount)
		}
	}
	return amounts
}

// rowsPricedAtHourly returns the rows whose catalog hourly rate equals the rate
// recorded when the order was placed.
func rowsPricedAtHourly(rows []gigahost.HourlyPlan, recordedHourly float64) []gigahost.HourlyPlan {
	if recordedHourly <= 0 {
		return nil
	}
	var matched []gigahost.HourlyPlan
	for _, r := range rows {
		if r.HourlyRateNOK > 0 && math.Abs(r.HourlyRateNOK-recordedHourly) <= priceAmountEpsilon {
			matched = append(matched, r)
		}
	}
	return matched
}

// existingMonthlySpend resolves the monthly commitment of an existing hourly
// reservation for plan pid, given the hourly rate recorded at order time (which
// may be zero when no local order is linked). The result is independent of
// catalog order, and an error is returned whenever the evidence cannot identify
// one contracted monthly cost.
func existingMonthlySpend(catalog []gigahost.HourlyPlan, pid int, recordedHourly float64) (float64, error) {
	rows := catalogRowsForPlan(catalog, pid)
	amounts := distinctMonthlyAmounts(rows)
	switch {
	case len(amounts) == 1:
		return amounts[0], nil
	case len(amounts) > 1:
		if selected := distinctMonthlyAmounts(rowsPricedAtHourly(rows, recordedHourly)); len(selected) == 1 {
			return selected[0], nil
		}
		return 0, fmt.Errorf("plan %d %w", pid, errPriceNotIdentifiable)
	case recordedHourly > 0:
		return recordedHourly * 720, nil
	default:
		return 0, fmt.Errorf("plan %d %w", pid, errSpendUnpriced)
	}
}
