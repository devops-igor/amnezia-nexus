package gigahost_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

const testAPIKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestClient_HTTP402PreservesOrderIDs(t *testing.T) {
	cases := []struct {
		name          string
		statusCode    int
		responseBody  string
		wantOrderIDs  []int64
		wantFirstID   string
		expectPartial bool
	}{
		{
			name:          "402 payment required with root order_ids array",
			statusCode:    http.StatusPaymentRequired,
			responseBody:  `{"error":"Payment required before deployment","order_ids":[10099, 10100]}`,
			wantOrderIDs:  []int64{10099, 10100},
			wantFirstID:   "10099",
			expectPartial: true,
		},
		{
			name:          "402 payment required with data.order_ids array",
			statusCode:    http.StatusPaymentRequired,
			responseBody:  `{"meta":{"status":402},"data":{"message":"Invoice pending","order_ids":[20045]}}`,
			wantOrderIDs:  []int64{20045},
			wantFirstID:   "20045",
			expectPartial: true,
		},
		{
			name:          "402 payment required with single data.order_id",
			statusCode:    http.StatusPaymentRequired,
			responseBody:  `{"meta":{"status":402},"data":{"order_id":30012,"message":"Requires manual review"}}`,
			wantOrderIDs:  []int64{30012},
			wantFirstID:   "30012",
			expectPartial: true,
		},
		{
			name:          "402 payment required with root order_id string",
			statusCode:    http.StatusPaymentRequired,
			responseBody:  `{"message":"Payment required","order_id":"40055"}`,
			wantOrderIDs:  []int64{40055},
			wantFirstID:   "40055",
			expectPartial: true,
		},
		{
			name:          "402 without order IDs returns standard APIError",
			statusCode:    http.StatusPaymentRequired,
			responseBody:  `{"error":"Insufficient funds on account"}`,
			expectPartial: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/servers" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"meta":{"status":200},"data":[]}`))
					return
				}
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			c, err := gigahost.NewClient(gigahost.Config{
				BaseURL: server.URL,
				APIKey:  testAPIKey,
			})
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			req := gigahost.OrderRequest{
				PID:           101,
				PriceID:       555,
				RegionID:      1,
				OSID:          12,
				BillingPeriod: gigahost.BillingPeriodHourly,
				Quantity:      1,
			}

			resp, err := c.OrderServerSafe(context.Background(), req)
			if tc.expectPartial {
				if err == nil {
					t.Fatalf("expected error on 402, got nil resp=%+v", resp)
				}
				var partialErr *gigahost.OrderPartialError
				if !errors.As(err, &partialErr) {
					t.Fatalf("expected error to be *gigahost.OrderPartialError, got %T: %v", err, err)
				}
				if partialErr.StatusCode != tc.statusCode {
					t.Errorf("expected StatusCode %d, got %d", tc.statusCode, partialErr.StatusCode)
				}
				if len(partialErr.OrderIDs) != len(tc.wantOrderIDs) {
					t.Fatalf("expected %d order IDs, got %v", len(tc.wantOrderIDs), partialErr.OrderIDs)
				}
				for i, id := range tc.wantOrderIDs {
					if partialErr.OrderIDs[i] != id {
						t.Errorf("order ID[%d] = %d, want %d", i, partialErr.OrderIDs[i], id)
					}
				}
				if partialErr.FirstOrderID() != tc.wantFirstID {
					t.Errorf("FirstOrderID() = %q, want %q", partialErr.FirstOrderID(), tc.wantFirstID)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error on 402 without order_ids, got nil")
				}
				var partialErr *gigahost.OrderPartialError
				if errors.As(err, &partialErr) {
					t.Errorf("did not expect *gigahost.OrderPartialError when no order_ids returned, got: %v", partialErr)
				}
			}
		})
	}
}

func TestClient_CatalogHourlyAndStockFiltering(t *testing.T) {
	catalogJSON := `{
		"meta": {"status": 200},
		"data": {
			"tiers": [
				{
					"group_id": 1,
					"products": [
						{
							"product_id": 1,
							"product_name": "Hourly In-Stock Plan",
							"allow_hourly": true,
							"allow_recurring": true,
							"price_id": 100,
							"rate_hourly": 0.20,
							"rate_monthly": 120,
							"in_stock": true,
							"region_ids": [1]
						},
						{
							"product_id": 2,
							"product_name": "Recurring Only Plan",
							"allow_hourly": false,
							"allow_recurring": true,
							"price_id": 200,
							"rate_hourly": 0.0,
							"rate_monthly": 300,
							"in_stock": true,
							"region_ids": [1]
						},
						{
							"product_id": 3,
							"product_name": "Hourly Out-of-Stock Plan",
							"allow_hourly": true,
							"allow_recurring": true,
							"price_id": 300,
							"rate_hourly": 0.50,
							"rate_monthly": 350,
							"in_stock": false,
							"region_ids": [1]
						},
						{
							"product_id": 4,
							"product_name": "Hourly Zero PriceID Plan",
							"allow_hourly": true,
							"allow_recurring": false,
							"price_id": 0,
							"rate_hourly": 0.10,
							"rate_monthly": 70,
							"in_stock": true,
							"region_ids": [1]
						}
					]
				}
			],
			"regions": [{"region_id": "1", "region_name": "Norway"}],
			"currency": "NOK"
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogJSON))
	}))
	defer server.Close()

	c, err := gigahost.NewClient(gigahost.Config{
		BaseURL: server.URL,
		APIKey:  testAPIKey,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	plans, err := c.GetCatalog(context.Background())
	if err != nil {
		t.Fatalf("GetCatalog failed: %v", err)
	}

	if len(plans) != 1 {
		t.Fatalf("expected exactly 1 hourly plan exposed, got %d", len(plans))
	}
	if plans[0].ProductID != 1 {
		t.Errorf("expected product_id 1, got %d", plans[0].ProductID)
	}
	if plans[0].PriceID != 100 {
		t.Errorf("expected price_id 100, got %d", plans[0].PriceID)
	}
	if !plans[0].InStock {
		t.Errorf("expected exposed plan to be in stock")
	}
}

func TestClient_HasCredit_Verification(t *testing.T) {
	cases := []struct {
		name       string
		account    *gigahost.AccountInfo
		wantCredit bool
	}{
		{
			name:       "nil account has no credit",
			account:    nil,
			wantCredit: false,
		},
		{
			name: "account with balance only",
			account: &gigahost.AccountInfo{
				Balance: 50.0,
			},
			wantCredit: true,
		},
		{
			name: "account with credit only",
			account: &gigahost.AccountInfo{
				Credit: 10.0,
			},
			wantCredit: true,
		},
		{
			name: "account with credit NOK only",
			account: &gigahost.AccountInfo{
				CreditNOK: 25.0,
			},
			wantCredit: true,
		},
		{
			name: "account qualifying for arrears",
			account: &gigahost.AccountInfo{
				QualifiesArrears: true,
			},
			wantCredit: true,
		},
		{
			name: "account with cust_id but zero balance/credit/arrears has no credit",
			account: &gigahost.AccountInfo{
				CustID:   "cust_12345",
				ID:       "id_67890",
				CustName: "Zero Balance Inc",
				Balance:  0.0,
				Credit:   0.0,
			},
			wantCredit: false,
		},
		{
			name: "account with negative balance and zero credit",
			account: &gigahost.AccountInfo{
				CustID:  "cust_overdue",
				Balance: -15.5,
				Credit:  0.0,
			},
			wantCredit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.account.HasCredit()
			if got != tc.wantCredit {
				t.Errorf("HasCredit() = %v, want %v", got, tc.wantCredit)
			}
		})
	}
}

func TestClient_CatalogEligibilityParsing(t *testing.T) {
	catalogJSON := `{
		"meta": {"status": 200},
		"data": {
			"tiers": [
				{
					"group_id": 1,
					"products": [
						{
							"product_id": 101,
							"product_name": "Standard Hourly",
							"allow_hourly": true,
							"price_id": 555,
							"rate_hourly": 0.14375,
							"rate_monthly": 90,
							"in_stock": true,
							"region_ids": [1]
						}
					]
				}
			],
			"eligibility": {
				"qualifies_arrears": true,
				"credit_nok": 1000.50
			},
			"regions": [{"region_id": "1", "region_name": "Norway"}],
			"currency": "NOK"
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(catalogJSON))
	}))
	defer server.Close()

	c, err := gigahost.NewClient(gigahost.Config{
		BaseURL: server.URL,
		APIKey:  "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	plans, err := c.GetCatalog(context.Background())
	if err != nil {
		t.Fatalf("GetCatalog failed: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if !plans[0].Eligibility.QualifiesArrears {
		t.Errorf("expected plan eligibility QualifiesArrears to be true")
	}
	if plans[0].Eligibility.CreditNOK != 1000.50 {
		t.Errorf("expected CreditNOK 1000.50, got %v", plans[0].Eligibility.CreditNOK)
	}
}

func TestClient_HasEligibility_Evaluation(t *testing.T) {
	cases := []struct {
		name     string
		account  *gigahost.AccountInfo
		catalog  *gigahost.Catalog
		expected bool
	}{
		{
			name:     "nil account and nil catalog",
			account:  nil,
			catalog:  nil,
			expected: false,
		},
		{
			name:     "documented account with 0 balance and catalog qualifies_arrears",
			account:  &gigahost.AccountInfo{CustID: "1111", CustName: "Example AS", Balance: 0},
			catalog:  &gigahost.Catalog{Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true}},
			expected: true,
		},
		{
			name:     "documented account with 0 balance and catalog credit_nok",
			account:  &gigahost.AccountInfo{CustID: "1111", Balance: 0},
			catalog:  &gigahost.Catalog{Eligibility: gigahost.CatalogEligibility{CreditNOK: 500}},
			expected: true,
		},
		{
			name:     "account with positive balance and empty catalog eligibility",
			account:  &gigahost.AccountInfo{CustID: "1111", Balance: 150},
			catalog:  &gigahost.Catalog{Eligibility: gigahost.CatalogEligibility{}},
			expected: true,
		},
		{
			name:     "account with credit and empty catalog eligibility",
			account:  &gigahost.AccountInfo{CustID: "1111", Credit: 50},
			catalog:  &gigahost.Catalog{Eligibility: gigahost.CatalogEligibility{}},
			expected: true,
		},
		{
			name:     "zero balance and zero catalog eligibility",
			account:  &gigahost.AccountInfo{CustID: "1111", Balance: 0, Credit: 0},
			catalog:  &gigahost.Catalog{Eligibility: gigahost.CatalogEligibility{QualifiesArrears: false, CreditNOK: 0}},
			expected: false,
		},
		{
			name:    "plan-level eligibility inside catalog",
			account: &gigahost.AccountInfo{CustID: "1111", Balance: 0},
			catalog: &gigahost.Catalog{
				Plans: []gigahost.HourlyPlan{
					{ProductID: 101, Eligibility: gigahost.CatalogEligibility{QualifiesArrears: true}},
				},
			},
			expected: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gigahost.HasEligibility(tc.account, tc.catalog)
			if got != tc.expected {
				t.Errorf("HasEligibility() = %v, want %v", got, tc.expected)
			}
		})
	}
}
