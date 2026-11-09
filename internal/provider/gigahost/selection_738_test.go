package gigahost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// catalogSelectionDoc is the documented GET /deploy/servers body shape: tiers of
// products with region_ids, dc_ids/dc_stock, region list and datacenter list. It
// is transcribed from the provider API documentation, so a regression in parsing
// these documented fields shows up as a test failure rather than as an order the
// provider rejects.
const catalogSelectionDoc = `{
  "meta": {"status": 200, "status_message": "200 OK"},
  "data": {
    "tiers": [
      {
        "group_id": 1,
        "group_name": "Cloud Servers",
        "in_stock": true,
        "quantity": 0,
        "products": [
          {
            "product_id": 101,
            "product_name": "Cloud 2",
            "type": "vm",
            "in_stock": true,
            "quantity": 0,
            "built_to_order": false,
            "waitlist_eligible": false,
            "allow_hourly": true,
            "allow_recurring": true,
            "rate_hourly": 0.14375,
            "rate_monthly": 90,
            "price_id": 555,
            "region_ids": [1, 2],
            "dc_ids": [1, 2],
            "dc_stock": {"1": true, "2": false},
            "vm_cores": "2", "vm_memory": "4", "vm_storage": "80", "vm_bw": "5",
            "specs": {"cpu_cores": 2, "ram_gb": 4, "disks": [{"size_gb": 80}], "bw": 5}
          }
        ]
      }
    ],
    "regions": [
      {"region_id": "1", "region_name": "Norway", "region_name_short": "NO", "region_country": "NO"},
      {"region_id": "2", "region_name": "Sweden", "region_name_short": "SE", "region_country": "SE"}
    ],
    "datacenters": [
      {"dc_id": 1, "dc_name": "DC1", "region_id": 1, "region_name": "Norway", "region_location": "Sandefjord", "region_country": "NO"},
      {"dc_id": 2, "dc_name": "DC2", "region_id": 2, "region_name": "Sweden", "region_location": "Stockholm", "region_country": "SE"}
    ],
    "currency": "NOK",
    "eligibility": {"qualifies_arrears": true, "credit_nok": 0}
  }
}`

// distroListDoc and distroImagesDoc are the documented GET /reinstall/distro and
// GET /reinstall/distro/{dist_id} bodies, including the string-encoded numeric
// and boolean fields the provider actually sends.
const distroListDoc = `{"meta":{"status":200},"data":[
  {"dist_id":"1","type_id":"1","dist_name":"Debian","dist_value":"debian","dist_active":"1"},
  {"dist_id":"9","type_id":"2","dist_name":"Ubuntu","dist_value":"ubuntu","dist_active":"1"},
  {"dist_id":"20","type_id":"3","dist_name":"Retired","dist_value":"retired","dist_active":"0"}
]}`

const distroImagesDoc = `{"meta":{"status":200},"data":[
  {"os_id":"%s","dist_id":"%s","os_name":"%s","os_release":"%s","os_dist":"12","os_arch":"amd64",
   "os_custom_partition":"0","os_single_disk_only":"0","os_support_raid":"1",
   "os_dedicated_only":"%s","os_minram":"%s","os_slow_install":"0"}
]}`

// selectionProvider serves the documented catalog and image bodies.
func selectionProvider(t *testing.T, imagesByDist map[string]string, distErr bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/deploy/servers":
			_, _ = w.Write([]byte(catalogSelectionDoc))
		case r.URL.Path == "/reinstall/distro":
			_, _ = w.Write([]byte(distroListDoc))
		case strings.HasPrefix(r.URL.Path, "/reinstall/distro/"):
			if distErr {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"meta":{"status":500,"message":"upstream failure"}}`))
				return
			}
			body, ok := imagesByDist[strings.TrimPrefix(r.URL.Path, "/reinstall/distro/")]
			if !ok {
				_, _ = w.Write([]byte(`{"meta":{"status":200},"data":[]}`))
				return
			}
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestGetCatalog_ParsesDocumentedPlacementAndStock(t *testing.T) {
	server := selectionProvider(t, nil, false)
	defer server.Close()

	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	plans, err := c.GetCatalog(context.Background())
	if err != nil {
		t.Fatalf("GetCatalog: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(plans))
	}
	plan := plans[0]
	if plan.Type != "vm" {
		t.Errorf("plan type = %q, want the documented vm", plan.Type)
	}
	if plan.HourlyRateNOK != 0.14375 || plan.MonthlyCeiling != 90 || plan.Currency != "NOK" {
		t.Errorf("price = %v/%v %s, want 0.14375/90 NOK", plan.HourlyRateNOK, plan.MonthlyCeiling, plan.Currency)
	}
	if len(plan.Regions) != 2 {
		t.Fatalf("regions = %d, want the two documented region_ids", len(plan.Regions))
	}
	if plan.Regions[0].Name != "Norway" || plan.Regions[1].Name != "Sweden" {
		t.Errorf("region names = %q/%q, want Norway/Sweden", plan.Regions[0].Name, plan.Regions[1].Name)
	}
	// dc_stock decides per-region stock: DC1 in region 1 has stock, DC2 in region 2
	// does not.
	if plan.Regions[0].InStock == nil || !*plan.Regions[0].InStock {
		t.Errorf("region 1 stock = %v, want true", plan.Regions[0].InStock)
	}
	if plan.Regions[1].InStock == nil || *plan.Regions[1].InStock {
		t.Errorf("region 2 stock = %v, want false", plan.Regions[1].InStock)
	}
	if len(plan.Datacenters) != 2 {
		t.Fatalf("datacenters = %d, want the two documented dc_ids", len(plan.Datacenters))
	}
	if plan.Datacenters[0].Name != "DC1" || !plan.Datacenters[0].InStock {
		t.Errorf("dc1 = %+v, want DC1 in stock", plan.Datacenters[0])
	}
	if plan.Datacenters[1].Name != "DC2" || plan.Datacenters[1].InStock {
		t.Errorf("dc2 = %+v, want DC2 out of stock", plan.Datacenters[1])
	}
}

// TestGetCatalog_MissingDCStockIsUnknownNotSoldOut pins the difference between "the
// catalog carried no stock fact" and "the catalog said sold out": an absent
// dc_stock must leave the region's stock unknown so it is still offered.
func TestGetCatalog_MissingDCStockIsUnknownNotSoldOut(t *testing.T) {
	doc := strings.Replace(catalogSelectionDoc, `"dc_stock": {"1": true, "2": false},`, "", 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(doc))
	}))
	defer server.Close()

	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	plans, err := c.GetCatalog(context.Background())
	if err != nil {
		t.Fatalf("GetCatalog: %v", err)
	}
	if len(plans) != 1 || len(plans[0].Regions) != 2 {
		t.Fatalf("unexpected catalog shape: %+v", plans)
	}
	for _, r := range plans[0].Regions {
		if r.InStock != nil {
			t.Errorf("region %d stock = %v, want unknown when dc_stock is absent", r.ID, *r.InStock)
		}
		if !r.Sellable() {
			t.Errorf("region %d must still be sellable when stock is unknown", r.ID)
		}
	}
}

func TestGetOperatingSystems_DocumentedFields(t *testing.T) {
	images := map[string]string{
		"1": `{"meta":{"status":200},"data":[` +
			sprintfImages("12", "1", "Debian 12 Bookworm", "debian", "0", "0") + `]}`,
		"9": `{"meta":{"status":200},"data":[` +
			sprintfImages("72", "9", "Ubuntu 24.04 LTS", "ubuntu", "0", "0") + `,` +
			sprintfImages("90", "9", "Ubuntu dedicated", "ubuntu", "1", "0") + `]}`,
	}

	server := selectionProvider(t, images, false)
	defer server.Close()

	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	systems, err := c.GetOperatingSystems(context.Background())
	if err != nil {
		t.Fatalf("GetOperatingSystems: %v", err)
	}
	// The inactive distribution must be skipped, so only the three active images report.
	if len(systems) != 3 {
		t.Fatalf("images = %d, want the 3 active images: %+v", len(systems), systems)
	}
	byID := map[int]OperatingSystem{}
	for _, os := range systems {
		byID[os.OSID] = os
	}
	debian, ok := byID[12]
	if !ok {
		t.Fatalf("missing the documented Debian image: %+v", systems)
	}
	if debian.Name != "Debian 12 Bookworm" || debian.Arch != "amd64" || debian.DedicatedOnly {
		t.Errorf("debian image = %+v, want the documented plain amd64 image", debian)
	}
	if debian.DistName != "Debian" {
		t.Errorf("dist name = %q, want it filled from the distribution list", debian.DistName)
	}
	dedicated, ok := byID[90]
	if !ok {
		t.Fatalf("missing the documented dedicated-only image: %+v", systems)
	}
	if !dedicated.DedicatedOnly {
		t.Errorf(`os_dedicated_only "1" must decode to true, got %+v`, dedicated)
	}
}

func TestGetOperatingSystems_DistroFailureIsAnError(t *testing.T) {
	server := selectionProvider(t, nil, true)
	defer server.Close()

	c, err := NewClient(Config{BaseURL: server.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetOperatingSystems(context.Background()); err == nil {
		t.Fatal("expected an error when a distribution read fails, got nil")
	}
}

func TestOperatingSystem_CompatibleWith(t *testing.T) {
	cloudPlan := HourlyPlan{ProductID: 101, Type: "vm", RAMMB: 4 * 1024, DiskGB: 80}
	dedicatedPlan := HourlyPlan{ProductID: 120, Type: "dedicated", RAMMB: 64 * 1024, DiskGB: 960}

	cases := []struct {
		name      string
		image     OperatingSystem
		plan      HourlyPlan
		wantErr   bool
		wantInErr string
	}{
		{name: "plain image on a cloud plan", image: OperatingSystem{OSID: 12}, plan: cloudPlan},
		{name: "dedicated-only image on a dedicated plan", image: OperatingSystem{OSID: 90, DedicatedOnly: true}, plan: dedicatedPlan},
		{
			name: "dedicated-only image on a cloud plan", image: OperatingSystem{OSID: 90, DedicatedOnly: true}, plan: cloudPlan,
			wantErr: true, wantInErr: "dedicated-only",
		},
		{
			name: "8 GB image on a 4 GB plan", image: OperatingSystem{OSID: 93, MinRAMGB: 8}, plan: cloudPlan,
			wantErr: true, wantInErr: "needs 8 GB RAM",
		},
		{name: "8 GB image on a 64 GB plan", image: OperatingSystem{OSID: 93, MinRAMGB: 8}, plan: dedicatedPlan},
		{
			name: "image without an id", image: OperatingSystem{}, plan: cloudPlan,
			wantErr: true, wantInErr: "no os_id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.image.CompatibleWith(tc.plan)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an incompatibility error, got nil")
				}
				if !errors.Is(err, ErrOSNotAvailable) {
					t.Errorf("error = %v, want it to wrap ErrOSNotAvailable", err)
				}
				if !strings.Contains(err.Error(), tc.wantInErr) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantInErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected incompatibility: %v", err)
			}
		})
	}
}

func TestHourlyPlan_InstallableImagesNarrowsToDocumentedRequirements(t *testing.T) {
	cloudPlan := HourlyPlan{ProductID: 101, Type: "vm", RAMMB: 4 * 1024, DiskGB: 80}
	catalog := []OperatingSystem{
		{OSID: 12, Name: "Debian 12"},
		{OSID: 72, Name: "Ubuntu 24.04"},
		{OSID: 90, Name: "Ubuntu dedicated", DedicatedOnly: true},
		{OSID: 93, Name: "Debian 8 GB", MinRAMGB: 8},
	}
	options := cloudPlan.InstallableImages(catalog)
	if len(options) != 2 || options[0].OSID != 12 || options[1].OSID != 72 {
		t.Fatalf("installable images = %+v, want only the two plain images", options)
	}
}

func TestOrderRequest_RejectsNonPositiveSelection(t *testing.T) {
	// The provider identity guard is retained: an order with a missing selection
	// key never reaches the HTTP call.
	c := &client{baseURL: "http://127.0.0.1:1", apiKey: testAPIKey, unknownOrders: map[string]time.Time{}}
	_, err := c.OrderServer(context.Background(), OrderRequest{
		PID: 101, PriceID: 555, RegionID: 0, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	})
	if !errors.Is(err, ErrInvalidOrderParam) {
		t.Fatalf("error = %v, want ErrInvalidOrderParam", err)
	}
}

// sprintfImages renders one documented image entry for the distro image body.
func sprintfImages(osID, distID, name, release, dedicatedOnly, minRAM string) string {
	return `{"os_id":"` + osID + `","dist_id":"` + distID + `","os_name":"` + name +
		`","os_release":"` + release + `","os_dist":"12","os_arch":"amd64",` +
		`"os_custom_partition":"0","os_single_disk_only":"0","os_support_raid":"1",` +
		`"os_dedicated_only":"` + dedicatedOnly + `","os_minram":"` + minRAM + `","os_slow_install":"0"}`
}

// TestOperatingSystem_JSONDecodesDocumentedStrings pins the wire format: the
// provider sends ids and flags as strings, and a number-typed struct would leave
// every image looking unusable.
func TestOperatingSystem_JSONDecodesDocumentedStrings(t *testing.T) {
	raw := `{"os_id":"147","dist_id":"1","os_name":"AlmaLinux 9 64-bit","os_arch":"amd64",
	         "os_dedicated_only":"0","os_minram":"0","os_limited_support":"1"}`
	var os OperatingSystem
	if err := json.Unmarshal([]byte(raw), &os); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if os.OSID != 147 || os.DistID != 1 {
		t.Errorf("ids = %d/%d, want the documented 147/1", os.OSID, os.DistID)
	}
	if os.DedicatedOnly {
		t.Errorf(`os_dedicated_only "0" decoded to true`)
	}
	if !os.LimitedSupport {
		t.Errorf(`os_limited_support "1" decoded to false`)
	}
}
