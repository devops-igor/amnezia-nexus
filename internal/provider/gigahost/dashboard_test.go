package gigahost

// The account summary is used for one fact only: the account-wide server count that
// certifies an inventory listing as the account's whole enumeration. Its decode is
// pinned here so "the provider did not say" can never be read as "the account has no
// servers", and a contradictory count is refused rather than guessed.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeDashboard_ServiceCounts(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		present bool
		wantSum int
		wantErr bool
	}{
		{
			name:    "documented shape",
			body:    `{"meta":{"status":200},"data":{"services":{"virtual":3,"dedicated":1,"dns_zones":12},"billing":{"unpaid":1}}}`,
			present: true,
			wantSum: 4,
		},
		{
			name:    "counts as numeric text",
			body:    `{"data":{"services":{"virtual":"3","dedicated":"1"}}}`,
			present: true,
			wantSum: 4,
		},
		{
			name:    "a missing count counts as zero",
			body:    `{"data":{"services":{"virtual":2}}}`,
			present: true,
			wantSum: 2,
		},
		{
			name:    "no services object attests nothing",
			body:    `{"data":{"billing":{"unpaid":1}}}`,
			present: false,
		},
		{
			name:    "empty data attests nothing",
			body:    `{"data":{}}`,
			present: false,
		},
		{
			name:    "a count that is not a number is refused",
			body:    `{"data":{"services":{"virtual":"many"}}}`,
			wantErr: true,
		},
		{
			name:    "a negative count is refused",
			body:    `{"data":{"services":{"virtual":-1}}}`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dashboard, err := decodeDashboard([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("payload was accepted as %+v", dashboard)
				}
				return
			}
			if err != nil {
				t.Fatalf("documented payload refused: %v", err)
			}
			if dashboard.ServicesPresent != tc.present {
				t.Fatalf("services present = %v, want %v", dashboard.ServicesPresent, tc.present)
			}
			if got := dashboard.Services.ServerCount(); got != tc.wantSum {
				t.Fatalf("server count = %d, want %d", got, tc.wantSum)
			}
		})
	}
}

func TestGetDashboard_ReadsTheAccountSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dashboard" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"services":{"virtual":7,"dedicated":2}}}`))
	}))
	defer server.Close()

	client, err := NewClient(Config{BaseURL: server.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := client.GetDashboard(context.Background())
	if err != nil {
		t.Fatalf("account summary read failed: %v", err)
	}
	if !dashboard.ServicesPresent || dashboard.Services.ServerCount() != 9 {
		t.Fatalf("service counts = %+v (present=%v), want 9", dashboard.Services, dashboard.ServicesPresent)
	}

	// A provider error is an error, never an empty account.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()
	brokenClient, err := NewClient(Config{BaseURL: broken.URL, APIKey: "flux_live_" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokenClient.GetDashboard(context.Background()); err == nil {
		t.Fatal("a failed account summary read was treated as an answer")
	}
}
