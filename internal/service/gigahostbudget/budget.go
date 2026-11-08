// Package gigahostbudget owns the single monthly NOK budget calculation for
// Gigahost hourly VPS spend.
//
// One reservation is one VPS. Provider inventory (GET /deploy/servers) and the
// local gigahost_orders ledger are the same money seen from two sides, so the
// two are paired by identity before anything is priced. Pairing uses only
// identities that actually establish equivalence - a provider order id or a
// positive provider server id - never a coincidental plan id, price or assigned
// address, because distinct VPS share plan and price and a routed address can be
// moved between servers.
//
// Price identity: the authoritative amount for one reservation is the contract
// the provider returned when the order was placed (hourly rate, monthly cap,
// currency, price id), which the application persists for new orders. A legacy
// record without that contract is priced from the catalog ONLY when the catalog
// offers exactly one monthly amount for the plan; anything else is an error
// rather than a guess, because guessing made the same reservation cost 41 or
// 120 NOK depending only on catalog row order.
//
// Nonterminal reservations whose financial outcome is unknown (a local
// synthetic order id that never identified the provider order, or a provider
// query that failed) stay counted and are reported as unresolved. Nothing in
// this package releases spend on the strength of a synthetic identifier: a
// provider not-found answer for a local id proves nothing about whether the
// request reached the provider.
//
// The operator recovery utility (cmd/gigahost-recovery) calls the same
// Classify/Evaluate functions as the purchase path, so a dry-run proposal and
// the purchase decision cannot disagree.
package gigahostbudget

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// HoursPerMonth is the nominal month used to turn an hourly rate into the
// monthly commitment it implies. It matches the pre-existing budget estimate.
const HoursPerMonth = 720

// amountEpsilon is the tolerance used to compare NOK amounts and hourly rates.
// Real tiers differ by a whole NOK or by at least a hundredth of a NOK per
// hour, far above this bound, so distinct prices are never merged.
const amountEpsilon = 1e-6

var (
	// ErrSpendUnpriced is the pre-existing fail-closed state: the plan has no
	// usable catalog price and no recorded rate to estimate one.
	ErrSpendUnpriced = errors.New("has unpriced spend and is absent from catalog")
	// ErrPriceNotIdentifiable reports that the catalog offers more than one
	// possible monthly cost for the plan and no evidence chooses between them.
	ErrPriceNotIdentifiable = errors.New("has more than one monthly price in the catalog and the contracted price is not identifiable")
	// ErrCurrencyNotComparable reports a persisted commitment denominated in a
	// currency that cannot be compared to the NOK budget. Guessing an exchange
	// rate would silently change the amount, so this fails closed instead.
	ErrCurrencyNotComparable = errors.New("is committed in a currency other than NOK and cannot be compared to the NOK budget")
)

// State is the accounting state of one reservation.
type State string

const (
	// StateActive is a committed reservation with a known price.
	StateActive State = "active"
	// StateUnresolved is a committed reservation whose financial outcome is
	// unknown. It counts, because releasing it could overspend.
	StateUnresolved State = "unresolved"
	// StateObsolete is a reservation proven to carry no commitment: either a
	// terminal provider/local status, or conclusive provider evidence.
	StateObsolete State = "obsolete"
	// StateReleased was explicitly released (automatic reconciliation with
	// conclusive evidence, or an operator acknowledgement).
	StateReleased State = "released"
	// StateDuplicate is another representation of a VPS that is already
	// counted once under a different record or inventory row.
	StateDuplicate State = "duplicate"
)

// Counts reports whether the reservation consumes budget.
func (s State) Counts() bool {
	return s == StateActive || s == StateUnresolved
}

// PriceSource names the evidence an amount was derived from.
type PriceSource string

const (
	// PriceContract is the per-order contract persisted at order time.
	PriceContract PriceSource = "persisted_contract"
	// PriceCatalog is the single monthly amount the catalog offers for a plan.
	PriceCatalog PriceSource = "catalog_single_amount"
	// PriceRecorded is the hourly rate recorded at order time, times 720, used
	// only when the plan is absent from the catalog (pre-existing behavior).
	PriceRecorded PriceSource = "recorded_hourly_rate"
	// PriceNone marks a reservation that contributes no amount.
	PriceNone PriceSource = "none"
)

// Plan is one provider catalog row (an orderable product price).
type Plan struct {
	ProductID      int
	PriceID        int
	Currency       string
	HourlyRateNOK  float64
	MonthlyCeiling float64
}

// MonthlyAmount is the monthly commitment this catalog row represents.
func (p Plan) MonthlyAmount() float64 {
	if p.MonthlyCeiling > 0 {
		return p.MonthlyCeiling
	}
	if p.HourlyRateNOK > 0 {
		return p.HourlyRateNOK * HoursPerMonth
	}
	return 0
}

// nokComparable reports whether the row is priced in NOK. An empty currency is
// treated as NOK (the provider default and the pre-existing assumption); an
// explicit non-NOK currency is not silently converted.
func (p Plan) nokComparable() bool {
	return p.Currency == "" || strings.EqualFold(p.Currency, "NOK")
}

// Server is one provider inventory row (GET /deploy/servers).
type Server struct {
	ID      int64
	OrderID string
	PlanID  int
	Status  string
	Hourly  bool
}

// Entry is one local gigahost_orders ledger row.
type Entry struct {
	RecordID       int64
	OrderID        string
	ServerID       int64
	Status         string
	PlanID         int
	RegionID       int
	HourlyPriceNOK float64
	PriceID        int
	// MonthlyCapNOK is the monthly cap the provider contracted at order time,
	// persisted for records created after checkpoint A. Zero means unknown.
	MonthlyCapNOK float64
	Currency      string
	AssignedIP    string
	// ReleasedAt is set when the reservation was explicitly released. The
	// original status is preserved; the marker alone removes it from budget.
	ReleasedAt    string
	ReleaseReason string
}

// Request is the order attempting to use the budget. Nil for reporting only.
type Request struct {
	PlanID         int
	PriceID        int
	HourlyPriceNOK float64
}

// Input is everything one budget decision is derived from.
type Input struct {
	CapNOK  float64
	Plans   []Plan
	Servers []Server
	Entries []Entry
	Request *Request
	// Evidence carries provider observations keyed by Entry.RecordID. The
	// caller performs the I/O; this package only interprets it.
	Evidence map[int64]Evidence
}

// Reservation is one evaluated commitment, kept in the result so an operator
// and the admin UI can see exactly what formed the total.
type Reservation struct {
	Source      string // "inventory" or "ledger"
	RecordID    int64  // ledger row id, 0 for inventory-only
	Identity    string // non-secret description of the identity link
	Status      string
	AmountNOK   float64
	PriceSource PriceSource
	State       State
	Reason      string
	Explanation string
}

// Result is the shared budget contract: the cap, every commitment that formed
// it, the request, and the decision with its explanation.
type Result struct {
	CapNOK       float64
	CommittedNOK float64
	RequestedNOK float64
	ProjectedNOK float64
	RemainingNOK float64
	Allowed      bool
	Reason       string
	Reservations []Reservation
	// Unresolved lists the counted reservations whose outcome is unknown.
	Unresolved []Reservation
	// IncompleteTotal reports that at least one counted reservation exists
	// whose amount could not be determined, so CommittedNOK is a lower bound.
	// A total that silently omitted such a reservation would understate spend.
	IncompleteTotal bool
}

// ReasonBudgetExceeded is the machine reason for a denied request.
const ReasonBudgetExceeded = "budget_exceeded"

// Evaluate prices every reservation once and decides the request.
//
// It returns an error only when an active commitment cannot be priced, because
// spending an unknown amount must fail closed. A denied request is a Result
// with Allowed=false, not an error.
func Evaluate(in Input) (Result, error) {
	entries := append([]Entry(nil), in.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].RecordID < entries[j].RecordID })

	seen := make(map[string]struct{})
	consumed := make([]bool, len(entries))
	reservations, err := inventoryReservations(in, entries, consumed, seen)
	if err != nil {
		return Result{}, err
	}
	ledger, err := ledgerReservations(in, entries, consumed, seen)
	if err != nil {
		return Result{}, err
	}
	reservations = append(reservations, ledger...)

	res := Result{CapNOK: in.CapNOK, Reservations: reservations}
	for _, r := range res.Reservations {
		if !r.State.Counts() {
			continue
		}
		res.CommittedNOK += r.AmountNOK
		if r.State == StateUnresolved {
			res.Unresolved = append(res.Unresolved, r)
		}
	}
	return decide(res, in)
}

// pairEntriesWithServers maps each ledger row to at most one inventory row.
// Inventory identity is the strongest evidence available, so it is resolved
// before anything is priced.
func pairEntriesWithServers(entries []Entry, servers []Server) []int {
	serverOf := make([]int, len(entries))
	for i := range entries {
		serverOf[i] = -1
		for j := range servers {
			if EntryMatchesServer(entries[i], servers[j]) {
				serverOf[i] = j
				break
			}
		}
	}
	return serverOf
}

// inventoryReservations prices counted provider inventory and marks the ledger
// rows it consumed. A ledger row is consumed only when its inventory row is
// counted, so an inactive server never releases a local reservation.
func inventoryReservations(in Input, entries []Entry, consumed []bool, seen map[string]struct{}) ([]Reservation, error) {
	serverOf := pairEntriesWithServers(entries, in.Servers)
	var out []Reservation
	for j := range in.Servers {
		s := in.Servers[j]
		if !IsServerActiveForBudget(s.Status) || !s.Hourly {
			continue
		}
		var members []int
		for i := range entries {
			if serverOf[i] == j {
				members = append(members, i)
			}
		}
		canonical, rest := pickCanonical(members, entries)
		r, err := inventoryReservation(in.Plans, in.Entries, s, canonical, entries)
		if err != nil {
			return nil, fmt.Errorf("active inventory server %d: %w", s.ID, err)
		}
		out = append(out, r)
		if key := serverIdentityKey(s); key != "" {
			seen[key] = struct{}{}
		}
		for _, i := range rest {
			out = append(out, duplicateReservation(entries[i], r.Identity))
		}
		for _, i := range members {
			consumed[i] = true
		}
	}
	return out, nil
}

// ledgerReservations prices the ledger rows no counted inventory row represents.
func ledgerReservations(in Input, entries []Entry, consumed []bool, seen map[string]struct{}) ([]Reservation, error) {
	var out []Reservation
	for i := range entries {
		if consumed[i] {
			continue
		}
		e := entries[i]
		verdict := Classify(e, in.Evidence[e.RecordID])
		base := Reservation{
			Source:      "ledger",
			RecordID:    e.RecordID,
			Identity:    entryIdentity(e),
			Status:      e.Status,
			State:       verdict.State,
			Reason:      verdict.Reason,
			Explanation: verdict.Explanation,
			PriceSource: PriceNone,
		}
		if !verdict.State.Counts() {
			out = append(out, base)
			continue
		}
		key := entryIdentityKey(e)
		if key != "" {
			if _, dup := seen[key]; dup {
				out = append(out, duplicateReservation(e, key))
				continue
			}
			seen[key] = struct{}{}
		}
		amount, src, why, err := priceExisting(in.Plans, e.PlanID, e.MonthlyCapNOK, e.Currency, e.HourlyPriceNOK)
		if err != nil {
			return nil, fmt.Errorf("active order %s: %w", entryIdentity(e), err)
		}
		base.AmountNOK = amount
		base.PriceSource = src
		base.Explanation = joinExplanation(verdict.Explanation, why)
		out = append(out, base)
	}
	return out, nil
}

// decide applies the request to the priced commitments.
func decide(res Result, in Input) (Result, error) {
	if in.Request == nil {
		res.Allowed = true
		return res, nil
	}
	requested, err := requestedAmount(in.Plans, *in.Request)
	if err != nil {
		return Result{}, err
	}
	res.RequestedNOK = requested
	res.ProjectedNOK = res.CommittedNOK + requested
	if res.CapNOK > 0 {
		res.RemainingNOK = res.CapNOK - res.CommittedNOK
	}
	res.Allowed = res.CapNOK <= 0 || res.ProjectedNOK <= res.CapNOK
	if !res.Allowed {
		res.Reason = ReasonBudgetExceeded
	}
	return res, nil
}

// Report classifies every ledger row without ever failing.
//
// Evaluate is deliberately strict: an active commitment it cannot price aborts
// the decision, because spending an unknown amount must fail closed. An operator
// report must instead be able to say "this reservation exists and its price is
// unknown", so this function prices what it can and marks what it cannot.
func Report(in Input) (Result, error) {
	res, err := Evaluate(in)
	if err == nil {
		return res, nil
	}

	// Price per row instead of as a whole, so one unpriceable legacy record does
	// not hide every other reservation from the operator.
	out := Result{CapNOK: in.CapNOK, Allowed: true}
	accounted := make(map[string]struct{})
	for _, e := range in.Entries {
		verdict := Classify(e, in.Evidence[e.RecordID])
		r := Reservation{
			Source:      "ledger",
			RecordID:    e.RecordID,
			Identity:    entryIdentity(e),
			Status:      e.Status,
			State:       verdict.State,
			Reason:      verdict.Reason,
			Explanation: verdict.Explanation,
			PriceSource: PriceNone,
		}
		if verdict.State.Counts() {
			amount, src, why, priceErr := priceExisting(in.Plans, e.PlanID, e.MonthlyCapNOK, e.Currency, e.HourlyPriceNOK)
			if priceErr != nil {
				r.Explanation = joinExplanation(verdict.Explanation, "price unknown: "+priceErr.Error())
				r.Reason = "price_unidentifiable"
				// The reservation still counts, but as an explicitly unknown
				// amount: reporting it as zero would understate committed spend.
				r.State = StateUnresolved
				out.IncompleteTotal = true
			} else {
				r.AmountNOK = amount
				r.PriceSource = src
				r.Explanation = joinExplanation(verdict.Explanation, why)
			}
			key := entryIdentityKey(e)
			if key != "" {
				if _, dup := accounted[key]; dup {
					r.State = StateDuplicate
					r.AmountNOK = 0
					r.Explanation = "already counted under the same identity"
					out.Reservations = append(out.Reservations, r)
					continue
				}
				accounted[key] = struct{}{}
			}
			out.CommittedNOK += r.AmountNOK
			if r.State == StateUnresolved {
				out.Unresolved = append(out.Unresolved, r)
			}
		}
		out.Reservations = append(out.Reservations, r)
	}
	return out, nil
}

// pickCanonical chooses the ledger row that represents the reservation when
// several rows describe the same VPS, and returns the redundant rows. The
// preference is evidence strength: a real provider order id plus a persisted
// contract, then a persisted contract, then a real provider order id, then the
// oldest row. The order is total, so the choice cannot depend on input order.
func pickCanonical(members []int, entries []Entry) (int, []int) {
	if len(members) == 0 {
		return -1, nil
	}
	sorted := append([]int(nil), members...)
	rank := func(i int) int {
		e := entries[i]
		real := !IsSyntheticOrderID(e.OrderID) && e.OrderID != ""
		switch {
		case real && e.MonthlyCapNOK > 0:
			return 0
		case e.MonthlyCapNOK > 0:
			return 1
		case real:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(sorted, func(a, b int) bool {
		ra, rb := rank(sorted[a]), rank(sorted[b])
		if ra != rb {
			return ra < rb
		}
		return entries[sorted[a]].RecordID < entries[sorted[b]].RecordID
	})
	canonical := sorted[0]
	return canonical, sorted[1:]
}

// inventoryReservation prices one counted provider server.
func inventoryReservation(plans []Plan, all []Entry, s Server, canonical int, entries []Entry) (Reservation, error) {
	pid := s.PlanID
	hourly := 0.0
	capNOK := 0.0
	currency := ""
	priceID := 0
	if canonical >= 0 {
		e := entries[canonical]
		if pid == 0 {
			pid = e.PlanID
		}
		if e.HourlyPriceNOK > 0 {
			hourly = e.HourlyPriceNOK
		}
		if e.MonthlyCapNOK > 0 {
			capNOK = e.MonthlyCapNOK
			currency = e.Currency
			priceID = e.PriceID
		}
	}
	if hourly == 0 {
		hourly = planHourly(all, pid)
	}
	amount, src, why, err := priceExisting(plans, pid, capNOK, currency, hourly)
	if err != nil {
		return Reservation{}, err
	}
	explanation := fmt.Sprintf("counted once as provider server %d", s.ID)
	if src == PriceContract {
		explanation += fmt.Sprintf(" with the persisted contract for price id %d", priceID)
	}
	return Reservation{
		Source:      "inventory",
		RecordID:    recordIDOf(canonical, entries),
		Identity:    serverIdentity(s),
		Status:      s.Status,
		AmountNOK:   amount,
		PriceSource: src,
		State:       StateActive,
		Explanation: joinExplanation(explanation, why),
	}, nil
}

// duplicateReservation reports an additional representation of an already
// counted VPS. It contributes no amount.
func duplicateReservation(e Entry, identity string) Reservation {
	return Reservation{
		Source:      "ledger",
		RecordID:    e.RecordID,
		Identity:    entryIdentity(e),
		Status:      e.Status,
		State:       StateDuplicate,
		Reason:      "same_vps_as_counted_reservation",
		Explanation: fmt.Sprintf("same reservation as %s; counted once", identity),
		PriceSource: PriceNone,
	}
}

func recordIDOf(i int, entries []Entry) int64 {
	if i < 0 {
		return 0
	}
	return entries[i].RecordID
}

func planHourly(entries []Entry, planID int) float64 {
	for _, e := range entries {
		if e.PlanID == planID && e.HourlyPriceNOK > 0 {
			return e.HourlyPriceNOK
		}
	}
	return 0
}

// requestedAmount resolves the monthly ceiling of the order being requested.
// The catalog row selected by product id and price id is the only authoritative
// source: a client-supplied rate is never used to price a new commitment.
func requestedAmount(plans []Plan, req Request) (float64, error) {
	for _, p := range plans {
		if p.ProductID != req.PlanID || (req.PriceID != 0 && p.PriceID != req.PriceID) {
			continue
		}
		amount := p.MonthlyAmount()
		if amount <= 0 {
			return 0, fmt.Errorf("requested plan %d %w", req.PlanID, ErrSpendUnpriced)
		}
		if !p.nokComparable() {
			return 0, fmt.Errorf("requested plan %d %w", req.PlanID, ErrCurrencyNotComparable)
		}
		return amount, nil
	}
	return 0, fmt.Errorf("requested plan %d %w", req.PlanID, ErrSpendUnpriced)
}

// ResolveExistingAmount resolves the monthly commitment of one existing
// reservation.
//
// Evidence order, first applicable wins:
//  1. the provider contract persisted at order time (authoritative per order);
//  2. the single distinct monthly amount the catalog offers for the plan;
//  3. the recorded hourly rate times 720 when the plan is absent from catalog.
//
// More than one catalog amount with no persisted contract is an error: the
// contracted amount is unknown, and neither the cheapest nor the first row is
// evidence. A catalog hourly rate equal to the recorded rate is NOT an
// identity: two products can share a rate, and a rate is not a contract.
func ResolveExistingAmount(plans []Plan, pid int, capNOK float64, currency string, recordedHourly float64) (float64, PriceSource, error) {
	amount, src, _, err := priceExisting(plans, pid, capNOK, currency, recordedHourly)
	return amount, src, err
}

// priceExisting is the resolver with the reason sentence kept for the ledger
// explanation.
func priceExisting(plans []Plan, pid int, capNOK float64, currency string, recordedHourly float64) (float64, PriceSource, string, error) {
	if capNOK > 0 {
		if currency != "" && !strings.EqualFold(currency, "NOK") {
			return 0, PriceNone, "", fmt.Errorf("plan %d %w", pid, ErrCurrencyNotComparable)
		}
		return capNOK, PriceContract, "contract persisted at order time", nil
	}
	amounts := distinctMonthlyAmounts(catalogRowsForPlan(plans, pid))
	switch {
	case len(amounts) == 1:
		return amounts[0], PriceCatalog, "single monthly amount in the catalog", nil
	case len(amounts) > 1:
		return 0, PriceNone, "", fmt.Errorf("plan %d %w", pid, ErrPriceNotIdentifiable)
	case recordedHourly > 0:
		return recordedHourly * HoursPerMonth, PriceRecorded, "plan absent from catalog; recorded hourly rate times 720", nil
	default:
		return 0, PriceNone, "", fmt.Errorf("plan %d %w", pid, ErrSpendUnpriced)
	}
}

func catalogRowsForPlan(plans []Plan, pid int) []Plan {
	var rows []Plan
	for _, p := range plans {
		if p.ProductID == pid {
			rows = append(rows, p)
		}
	}
	return rows
}

func distinctMonthlyAmounts(rows []Plan) []float64 {
	var amounts []float64
	for _, r := range rows {
		amount := r.MonthlyAmount()
		if amount <= 0 {
			continue
		}
		seen := false
		for _, known := range amounts {
			if math.Abs(known-amount) <= amountEpsilon {
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

func joinExplanation(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += "; "
		}
		out += p
	}
	return out
}
