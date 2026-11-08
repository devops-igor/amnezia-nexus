package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestGigahostOrderHandler_BudgetDeduplicatesServerIDOnlyMatch is the regression
// for the reproduced server-ID double-counting defect (finding B2):
//
// A provider inventory record may legitimately arrive without an order_id while
// still carrying a positive provider server id. The committed-spend calculation
// prices that server from its matching local order but only remembered order
// IDs, so the surviving local order was added a second time and the same VPS was
// reserved twice against the monthly budget.
//
// The test drives the real production consumer (GigahostOrderHandler) so the
// assertion covers ordering, reconciliation and the purchase boundary, not just
// the arithmetic helper. Every case must keep the existing guards intact:
// distinct servers/reservations still count, matching order IDs still dedupe,
// unknown reservations stay reserved, and no cheaper price is selected to make
// the budget pass.
func TestGigahostOrderHandler_BudgetDeduplicatesServerIDOnlyMatch(t *testing.T) {
	hourly := true

	// Plan 101 (selected for the new request) costs 59 NOK/month.
	plan101 := gigahost.HourlyPlan{
		ProductID: 101, PriceID: 555, Currency: "NOK", HourlyRateNOK: 0.15,
		MonthlyCeiling: 59, InStock: true,
		Regions: []gigahost.Region{{ID: 1, Available: true}},
	}
	// Plan 202 (already running) costs 41 NOK/month.
	plan202 := gigahost.HourlyPlan{
		ProductID: 202, PriceID: 666, Currency: "NOK", HourlyRateNOK: 0.05,
		MonthlyCeiling: 41, InStock: true,
		Regions: []gigahost.Region{{ID: 1, Available: true}},
	}
	catalog := []gigahost.HourlyPlan{plan101, plan202}

	localOrder := func(orderID string, serverID int64, status string, planID int, regionID int, hourlyPrice float64) GigahostOrderRecord {
		now := time.Now().UTC()
		return GigahostOrderRecord{
			OrderID: orderID, ServerID: serverID, Status: status, PlanID: planID,
			RegionID: regionID, HourlyPriceNOK: hourlyPrice, CreatedAt: now, UpdatedAt: now,
		}
	}

	cases := []struct {
		name string
		// budget in NOK/month
		budget float64
		// provider inventory and local order ledger
		servers []gigahost.ServerInfo
		orders  []GigahostOrderRecord
		// expected result of the order attempt
		wantCode      int
		wantPosts     int
		wantCommitted float64
	}{
		{
			// The reproduced defect: the provider record has no order_id, so the
			// local order for the SAME positive server id must not be added again.
			// One 41 commitment + the new 59 request == the 100 budget, so the
			// order is allowed.
			name:          "provider_without_order_id_and_matching_local_server_id_counts_once",
			budget:        100,
			servers:       []gigahost.ServerInfo{{ID: 1, PID: 202, Status: gigahost.StatusReady, BwIsHourly: &hourly}},
			orders:        []GigahostOrderRecord{localOrder("known_local", 1, gigahost.StatusReady, 202, 1, 0.05)},
			wantCode:      http.StatusOK,
			wantPosts:     1,
			wantCommitted: 41,
		},
		{
			// Distinct servers are distinct reservations: dropping the second one
			// would under-count committed spend.
			name:   "distinct_server_reservations_still_count",
			budget: 100,
			servers: []gigahost.ServerInfo{
				{ID: 1, PID: 202, Status: gigahost.StatusReady, BwIsHourly: &hourly},
			},
			orders: []GigahostOrderRecord{
				localOrder("known_local", 1, gigahost.StatusReady, 202, 1, 0.05),
				localOrder("other_local", 2, gigahost.StatusReady, 202, 1, 0.05),
			},
			wantCode:      http.StatusBadRequest,
			wantPosts:     0,
			wantCommitted: 82,
		},
		{
			// Matching order IDs keep deduplicating exactly as before.
			name:   "matching_order_id_still_deduplicated",
			budget: 100,
			servers: []gigahost.ServerInfo{
				{ID: 1, OrderID: "shared_order", PID: 202, Status: gigahost.StatusReady, BwIsHourly: &hourly},
			},
			orders: []GigahostOrderRecord{
				localOrder("shared_order", 1, gigahost.StatusReady, 202, 1, 0.05),
			},
			wantCode:      http.StatusOK,
			wantPosts:     1,
			wantCommitted: 41,
		},
		{
			// A provider server that is NOT active inventory is not a commitment,
			// so the local reservation must survive: deduplicating here would
			// silently release spend.
			name:   "inactive_provider_server_keeps_local_reservation",
			budget: 90,
			servers: []gigahost.ServerInfo{
				{ID: 1, PID: 202, Status: gigahost.StatusFailed, BwIsHourly: &hourly},
			},
			orders: []GigahostOrderRecord{
				localOrder("known_local", 1, gigahost.StatusReady, 202, 1, 0.05),
			},
			wantCode:      http.StatusBadRequest,
			wantPosts:     0,
			wantCommitted: 41,
		},
		{
			// Hourly-excluded (dedicated) provider records are outside the hourly
			// budget, so their local reservation must also survive.
			name:   "non_hourly_provider_server_keeps_local_reservation",
			budget: 90,
			servers: []gigahost.ServerInfo{
				{ID: 1, PID: 202, Status: gigahost.StatusReady, SrvType: "dedicated"},
			},
			orders: []GigahostOrderRecord{
				localOrder("known_local", 1, gigahost.StatusReady, 202, 1, 0.05),
			},
			wantCode:      http.StatusBadRequest,
			wantPosts:     0,
			wantCommitted: 41,
		},
		{
			// An unresolved purchase stays reserved whether or not a provider
			// server already matches another local order.
			name:   "unknown_local_reservation_remains_reserved",
			budget: 100,
			servers: []gigahost.ServerInfo{
				{ID: 1, PID: 202, Status: gigahost.StatusReady, BwIsHourly: &hourly},
			},
			orders: []GigahostOrderRecord{
				localOrder("known_local", 1, gigahost.StatusReady, 202, 1, 0.05),
				localOrder("unknown_probe", 0, gigahost.StatusUnknown, 101, 2, 0.15),
			},
			wantCode:      http.StatusBadRequest,
			wantPosts:     0,
			wantCommitted: 100,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := context.Background()

			if err := db.SetSetting(ctx, "gigahost", map[string]any{"monthly_budget_nok": tc.budget}); err != nil {
				t.Fatal(err)
			}
			for i := range tc.orders {
				if err := h.saveGigahostOrder(ctx, &tc.orders[i]); err != nil {
					t.Fatal(err)
				}
			}

			// Exact committed spend, before the new request is considered.
			committed, err := calculateCommittedSpend(catalog, tc.servers, tc.orders)
			if err != nil {
				t.Fatalf("unexpected committed spend error: %v", err)
			}
			if committed != tc.wantCommitted {
				t.Errorf("committed spend = %v, want %v", committed, tc.wantCommitted)
			}

			posts := 0
			h.SetGigahostClient(&mockGigahostClient{
				getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
					return &gigahost.AccountInfo{Balance: 500.0, Currency: "NOK"}, nil
				},
				getCatalogFn: func(context.Context) ([]gigahost.HourlyPlan, error) {
					return catalog, nil
				},
				getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
					return tc.servers, nil
				},
				getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
					return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusReady, AssignedIP: "192.0.2.10"}, nil
				},
				orderServerSafeFn: func(context.Context, gigahost.OrderRequest) (*gigahost.OrderResponse, error) {
					posts++
					return &gigahost.OrderResponse{OrderID: "70001", Status: gigahost.StatusPending}, nil
				},
			})

			body := `{"pid":101,"price_id":555,"region_id":1,"os_id":12,"hourly_price_nok":0.15}`
			req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
			w := httptest.NewRecorder()
			h.GigahostOrderHandler(w, req)

			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
			if posts != tc.wantPosts {
				t.Errorf("provider orders dispatched = %d, want %d", posts, tc.wantPosts)
			}
			if tc.wantCode == http.StatusBadRequest && !strings.Contains(w.Body.String(), "Monthly budget cap exceeded") {
				t.Errorf("expected budget cap rejection, got %s", w.Body.String())
			}
		})
	}
}
