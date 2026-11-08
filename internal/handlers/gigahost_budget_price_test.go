package handlers

// Real-consumer regression for price-identity finding B3: the monthly
// commitment of an EXISTING Gigahost reservation must resolve to the same
// amount under every ordering of the provider catalog, and must fail closed
// when the available evidence cannot identify one contracted monthly cost.
//
// The test drives the production purchase path (GigahostOrderHandler), because
// the defect is a financial decision: the same existing server was priced at
// 41 NOK or 120 NOK depending only on which catalog row happened to come
// first, which flipped a legitimate order between "allowed" and "budget
// exceeded" and, in the ambiguous shape, could let an unidentified commitment
// through.
//
// Guards that must stay intact and are asserted here: no provider order is
// dispatched when the price cannot be identified, no purchase intent is
// persisted, and a distinguishable price still permits the order at an exact
// budget boundary.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// priceIdentityPlan builds a catalog row for a Gigahost product.
func priceIdentityPlan(pid, priceID int, hourly, monthlyCap float64) gigahost.HourlyPlan {
	return gigahost.HourlyPlan{
		ProductID: pid, PriceID: priceID, Currency: "NOK",
		HourlyRateNOK: hourly, MonthlyCeiling: monthlyCap, InStock: true,
		Regions: []gigahost.Region{{ID: 1, Available: true}},
	}
}

// catalogPermutations returns every ordering of the rows.
func catalogPermutations(rows []gigahost.HourlyPlan) [][]gigahost.HourlyPlan {
	if len(rows) <= 1 {
		return [][]gigahost.HourlyPlan{append([]gigahost.HourlyPlan(nil), rows...)}
	}
	var perms [][]gigahost.HourlyPlan
	for i := range rows {
		rest := append(append([]gigahost.HourlyPlan(nil), rows[:i]...), rows[i+1:]...)
		for _, tail := range catalogPermutations(rest) {
			perms = append(perms, append([]gigahost.HourlyPlan{rows[i]}, tail...))
		}
	}
	return perms
}

// existingPriceOutcome is everything the test observes about one order attempt.
type existingPriceOutcome struct {
	code         int
	body         string
	posts        int32
	ordersStored int
	committed    float64
	committedErr error
}

// runExistingPriceOrder places one order for 59 NOK/month plan 101 while the
// provider inventory already holds one active hourly server for plan 202 whose
// local order recorded recordedHourly. existingRows are that plan's catalog
// rows in the given order.
func runExistingPriceOrder(t *testing.T, budget float64, existingRows []gigahost.HourlyPlan, recordedHourly float64) existingPriceOutcome {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": budget}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	localOrder := GigahostOrderRecord{
		OrderID: "known_local", ServerID: 1, Status: gigahost.StatusReady, PlanID: 202, RegionID: 1,
		HourlyPriceNOK: recordedHourly, CreatedAt: now, UpdatedAt: now,
	}
	if err := h.saveGigahostOrder(ctx, &localOrder); err != nil {
		t.Fatal(err)
	}

	hourly := true
	servers := []gigahost.ServerInfo{{ID: 1, PID: 202, Status: gigahost.StatusReady, BwIsHourly: &hourly}}
	catalog := append([]gigahost.HourlyPlan{priceIdentityPlan(101, 555, 0.15, 59)}, existingRows...)

	var out existingPriceOutcome
	out.committed, out.committedErr = calculateCommittedSpend(catalog, servers, []GigahostOrderRecord{localOrder})

	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
		},
		getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
			return catalog, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			return servers, nil
		},
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady, AssignedIP: "192.0.2.10"}, nil
		},
		orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
			atomic.AddInt32(&out.posts, 1)
			return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
		},
	})

	body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.15}`
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	h.GigahostOrderHandler(w, req)
	out.code, out.body = w.Code, w.Body.String()

	stored, err := h.getGigahostOrders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out.ordersStored = len(stored)
	return out
}

// TestGigahostOrderHandler_AmbiguousExistingPriceFailsClosedInEveryCatalogOrder
// covers the reproduced B3 shape: one product with two different monthly
// amounts whose rows carry the SAME hourly rate, so nothing distinguishes
// them. The contracted cost cannot be identified, therefore no purchase may
// happen - in any catalog order.
func TestGigahostOrderHandler_AmbiguousExistingPriceFailsClosedInEveryCatalogOrder(t *testing.T) {
	cases := []struct {
		name string
		rows []gigahost.HourlyPlan
		// recorded hourly rate of the existing order
		recorded float64
	}{
		{
			name: "identical hourly rate, different monthly caps",
			rows: []gigahost.HourlyPlan{
				priceIdentityPlan(202, 666, 0.05, 41),
				priceIdentityPlan(202, 777, 0.05, 120),
			},
			recorded: 0.05,
		},
		{
			name: "different amounts, no recorded order-time rate",
			rows: []gigahost.HourlyPlan{
				priceIdentityPlan(202, 666, 0.057, 41),
				priceIdentityPlan(202, 777, 0.1667, 120),
			},
			recorded: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perms := catalogPermutations(tc.rows)
			if len(perms) != 2 {
				t.Fatalf("expected 2 catalog permutations, got %d", len(perms))
			}
			for i, rows := range perms {
				out := runExistingPriceOrder(t, 100, rows, tc.recorded)
				if out.code != http.StatusBadGateway {
					t.Errorf("permutation %d: status = %d, want %d (body: %s)", i, out.code, http.StatusBadGateway, out.body)
				}
				if !strings.Contains(out.body, "not identifiable") {
					t.Errorf("permutation %d: error must state the contracted price is not identifiable, got %s", i, out.body)
				}
				if out.posts != 0 {
					t.Errorf("permutation %d: provider orders dispatched = %d, want 0", i, out.posts)
				}
				if out.ordersStored != 1 {
					t.Errorf("permutation %d: stored orders = %d, want only the pre-existing one", i, out.ordersStored)
				}
			}
		})
	}
}

// TestGigahostOrderHandler_UnambiguousExistingPriceAtBudgetBoundary covers the
// resolvable shape: the distinct monthly amounts are separable because the
// order-time recorded hourly rate selects exactly one of them. 41 + 59 == the
// 100 NOK budget, so the order must succeed identically in both catalog orders.
func TestGigahostOrderHandler_UnambiguousExistingPriceAtBudgetBoundary(t *testing.T) {
	rows := []gigahost.HourlyPlan{
		priceIdentityPlan(202, 666, 0.057, 41),
		priceIdentityPlan(202, 777, 0.1667, 120),
	}
	perms := catalogPermutations(rows)
	if len(perms) != 2 {
		t.Fatalf("expected 2 catalog permutations, got %d", len(perms))
	}
	for i, perm := range perms {
		out := runExistingPriceOrder(t, 100, perm, 0.057)
		if out.code != http.StatusOK {
			t.Errorf("permutation %d: status = %d, want %d (body: %s)", i, out.code, http.StatusOK, out.body)
		}
		if out.posts != 1 {
			t.Errorf("permutation %d: provider orders dispatched = %d, want 1", i, out.posts)
		}
		if out.ordersStored != 2 {
			t.Errorf("permutation %d: stored orders = %d, want the seeded order plus the new one", i, out.ordersStored)
		}
		if out.committedErr != nil {
			t.Errorf("permutation %d: committed spend error = %v", i, out.committedErr)
		}
		if out.committed != 41 {
			t.Errorf("permutation %d: committed spend = %v, want 41", i, out.committed)
		}
	}
}

// TestExistingMonthlySpend_EveryCatalogPermutation pins the documented
// resolution policy at the smallest grain: the value and the error class must be
// identical under every ordering of the catalog rows, and every state that
// cannot identify one contracted monthly cost must fail closed.
func TestExistingMonthlySpend_EveryCatalogPermutation(t *testing.T) {
	rowPair := func(pid, priceA, priceB int, hourlyA, hourlyB, monthlyA, monthlyB float64) []gigahost.HourlyPlan {
		return []gigahost.HourlyPlan{
			priceIdentityPlan(pid, priceA, hourlyA, monthlyA),
			priceIdentityPlan(pid, priceB, hourlyB, monthlyB),
		}
	}

	cases := []struct {
		name     string
		catalog  []gigahost.HourlyPlan
		pid      int
		recorded float64
		want     float64
		wantErr  error
	}{
		{
			name:     "single catalog amount is the commitment regardless of other plans",
			catalog:  []gigahost.HourlyPlan{priceIdentityPlan(303, 1, 0.1, 72), priceIdentityPlan(202, 777, 0.1667, 120)},
			pid:      202,
			recorded: 0,
			want:     120,
		},
		{
			name:     "duplicate identical rows are one amount, not an ambiguity",
			catalog:  rowPair(202, 666, 999, 0.057, 0.057, 41, 41),
			pid:      202,
			recorded: 0,
			want:     41,
		},
		{
			name:     "two amounts, recorded rate selects exactly one",
			catalog:  rowPair(202, 666, 777, 0.057, 0.1667, 41, 120),
			pid:      202,
			recorded: 0.057,
			want:     41,
		},
		{
			name:     "two amounts, recorded rate selects the other one",
			catalog:  rowPair(202, 666, 777, 0.057, 0.1667, 41, 120),
			pid:      202,
			recorded: 0.1667,
			want:     120,
		},
		{
			name:     "same hourly rate on two rows leaves the amount unidentified",
			catalog:  rowPair(202, 666, 777, 0.05, 0.05, 41, 120),
			pid:      202,
			recorded: 0.05,
			wantErr:  errPriceNotIdentifiable,
		},
		{
			name:     "two amounts, no recorded rate leaves the amount unidentified",
			catalog:  rowPair(202, 666, 777, 0.057, 0.1667, 41, 120),
			pid:      202,
			recorded: 0,
			wantErr:  errPriceNotIdentifiable,
		},
		{
			name:     "recorded rate matching no row leaves the amount unidentified",
			catalog:  rowPair(202, 666, 777, 0.057, 0.1667, 41, 120),
			pid:      202,
			recorded: 0.1,
			wantErr:  errPriceNotIdentifiable,
		},
		{
			name:     "conflicting amounts under one price_id are still ambiguous",
			catalog:  rowPair(202, 666, 666, 0.057, 0.057, 41, 99),
			pid:      202,
			recorded: 0,
			wantErr:  errPriceNotIdentifiable,
		},
		{
			name:     "monthly cap absent falls back to hourly x 720",
			catalog:  []gigahost.HourlyPlan{priceIdentityPlan(5, 1, 0.1, 0)},
			pid:      5,
			recorded: 0,
			want:     72,
		},
		{
			name:     "plan absent from catalog uses the recorded rate times 720",
			catalog:  []gigahost.HourlyPlan{priceIdentityPlan(303, 1, 0.1, 72)},
			pid:      202,
			recorded: 0.05,
			want:     36,
		},
		{
			name:     "plan absent with nothing recorded fails closed",
			catalog:  []gigahost.HourlyPlan{priceIdentityPlan(303, 1, 0.1, 72)},
			pid:      202,
			recorded: 0,
			wantErr:  errSpendUnpriced,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			perms := catalogPermutations(tc.catalog)
			for i, perm := range perms {
				got, err := existingMonthlySpend(perm, tc.pid, tc.recorded)
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("permutation %d: error = %v, want %v", i, err, tc.wantErr)
					}
					if got != 0 {
						t.Fatalf("permutation %d: amount = %v, want 0 alongside the error", i, got)
					}
					continue
				}
				if err != nil {
					t.Fatalf("permutation %d: unexpected error: %v", i, err)
				}
				if got != tc.want {
					t.Fatalf("permutation %d: amount = %v, want %v", i, got, tc.want)
				}
			}
		})
	}
}

// TestCalculateCommittedSpend_LedgerPathsKeepReservationsDistinct covers the
// order-ledger pass that shares the resolver: an unidentifiable price fails the
// whole calculation closed (so no order can proceed), while distinct
// reservations with identifiable prices still sum exactly once in any catalog
// order.
func TestCalculateCommittedSpend_LedgerPathsKeepReservationsDistinct(t *testing.T) {
	localOrder := func(orderID string, planID int, hourly float64) GigahostOrderRecord {
		now := time.Now().UTC()
		return GigahostOrderRecord{
			OrderID: orderID, Status: gigahost.StatusReady, PlanID: planID, RegionID: 1,
			HourlyPriceNOK: hourly, CreatedAt: now, UpdatedAt: now,
		}
	}

	ambiguousRows := []gigahost.HourlyPlan{
		priceIdentityPlan(202, 666, 0.05, 41),
		priceIdentityPlan(202, 777, 0.05, 120),
	}

	t.Run("unidentifiable ledger price fails the whole calculation closed", func(t *testing.T) {
		for i, rows := range catalogPermutations(ambiguousRows) {
			committed, err := calculateCommittedSpend(rows, nil, []GigahostOrderRecord{localOrder("a", 202, 0.05)})
			if !errors.Is(err, errPriceNotIdentifiable) {
				t.Fatalf("permutation %d: error = %v, want %v", i, err, errPriceNotIdentifiable)
			}
			if committed != 0 {
				t.Fatalf("permutation %d: committed = %v, want 0 alongside the error", i, committed)
			}
		}
	})

	t.Run("distinct reservations each count once in every catalog order", func(t *testing.T) {
		rows := []gigahost.HourlyPlan{
			priceIdentityPlan(202, 666, 0.057, 41),
			priceIdentityPlan(202, 777, 0.1667, 120),
			priceIdentityPlan(303, 1, 0.1, 72),
		}
		orders := []GigahostOrderRecord{
			localOrder("a", 202, 0.057),
			localOrder("b", 202, 0.1667),
			localOrder("c", 303, 0.1),
		}
		for i, perm := range catalogPermutations(rows) {
			committed, err := calculateCommittedSpend(perm, nil, orders)
			if err != nil {
				t.Fatalf("permutation %d: unexpected error: %v", i, err)
			}
			if committed != 41+120+72 {
				t.Fatalf("permutation %d: committed = %v, want 233", i, committed)
			}
		}
	})
}
