package gigahost

// Explicit datacenter placement on the provider wire (#739).
//
// The provider documents two different POST /deploy/servers shapes for
// placement: region_id alone means "place the server in any datacenter in that
// region", and dc_id alone means "pin it to one datacenter (region_id is then
// taken from the datacenter and can be left out)". These tests assert the actual
// bytes this client sends for each, captured from a real HTTP request by the
// fixture server, rather than the shape of a Go struct.
//
// The catalog fixture is the documented tiered body with TWO regions and THREE
// datacenters (two of them inside one region), which is what makes the
// plan/datacenter/region association observable instead of incidental.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// placementCatalogDoc is a documented GET /deploy/servers body with a multi-region,
// multi-datacenter plan plus one datacenter covered by every stock shape:
//
//	dc 1 - region 1, explicitly in stock;
//	dc 2 - region 1, explicitly out of stock;
//	dc 3 - region 2, explicitly in stock.
//
// Product 102 keeps a dc_stock map that omits one of its dc_ids, so "unknown" is
// observable next to "sold out", and lists dc 99 which appears in no datacenters[]
// entry, so an id without a region relationship is observable too.
const placementCatalogDoc = `{
  "meta": {"status": 200},
  "data": {
    "tiers": [
      {
        "group_id": 1,
        "group_name": "Cloud Servers",
        "in_stock": true,
        "products": [
          {
            "product_id": 101,
            "product_name": "Cloud 2",
            "type": "vm",
            "in_stock": true,
            "built_to_order": false,
            "allow_hourly": true,
            "rate_hourly": 0.14375,
            "rate_monthly": 90,
            "price_id": 555,
            "region_ids": [1, 2],
            "dc_ids": [1, 2, 3],
            "dc_stock": {"1": true, "2": false, "3": true},
            "specs": {"cpu_cores": 2, "ram_gb": 4, "disks": [{"size_gb": 80}], "bw": 5}
          },
          {
            "product_id": 102,
            "product_name": "Cloud 4",
            "type": "vm",
            "in_stock": true,
            "built_to_order": false,
            "allow_hourly": true,
            "rate_hourly": 0.2875,
            "rate_monthly": 180,
            "price_id": 556,
            "region_ids": [1],
            "dc_ids": [1, 4, 99],
            "dc_stock": {"1": true},
            "specs": {"cpu_cores": 4, "ram_gb": 8, "disks": [{"size_gb": 160}], "bw": 10}
          },
          {
            "product_id": 120,
            "product_name": "Dedicated 64",
            "type": "dedicated",
            "in_stock": false,
            "built_to_order": true,
            "allow_hourly": true,
            "rate_hourly": 0.9,
            "rate_monthly": 560,
            "price_id": 560,
            "region_ids": [1],
            "dc_ids": [1, 2],
            "dc_stock": {"1": true, "2": true},
            "specs": {"cpu_cores": 12, "ram_gb": 64, "disks": [{"size_gb": 960}], "bw": 100}
          }
        ]
      }
    ],
    "regions": [
      {"region_id": "1", "region_name": "Norway", "region_name_short": "NO", "region_country": "NO"},
      {"region_id": "2", "region_name": "Sweden", "region_name_short": "SE", "region_country": "SE"}
    ],
    "datacenters": [
      {"dc_id": 1, "dc_name": "DC1", "region_id": 1, "region_location": "Sandefjord", "region_country": "NO"},
      {"dc_id": 2, "dc_name": "DC2", "region_id": 1, "region_location": "Oslo", "region_country": "NO"},
      {"dc_id": 3, "dc_name": "DC3", "region_id": 2, "region_location": "Stockholm", "region_country": "SE"}
    ],
    "currency": "NOK",
    "eligibility": {"qualifies_arrears": true, "credit_nok": 0}
  }
}`

// placementServer serves the placement catalog and records every order body it
// receives. It is a real HTTP server, so the assertions are about the bytes that
// crossed the wire.
type placementServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
	// orderStatus is the HTTP status used to answer POST /deploy/servers.
	orderStatus int
	orderBody   string
}

const placementOKOrderBody = `{"meta":{"status":200},"data":{"order_id":"ord_1","status":"pending"}}`

const placementSoldOutDCBody = `{"meta":{"status":400,"status_message":"400 Bad Request",` +
	`"message":"Product is out of stock in the selected datacenter."}}`

const placementUnknownDCBody = `{"meta":{"status":400,"status_message":"400 Bad Request",` +
	`"message":"Product is not available in the selected datacenter."}}`

func newPlacementServer(t *testing.T) *placementServer {
	t.Helper()
	ps := &placementServer{orderStatus: http.StatusOK, orderBody: placementOKOrderBody}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/deploy/servers" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(placementCatalogDoc))
		case r.URL.Path == "/deploy/servers" && r.Method == http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading captured order body: %v", err)
			}
			ps.mu.Lock()
			ps.bodies = append(ps.bodies, string(body))
			status, respBody := ps.orderStatus, ps.orderBody
			ps.mu.Unlock()
			w.WriteHeader(status)
			_, _ = w.Write([]byte(respBody))
		case r.URL.Path == "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ps.Close)
	return ps
}

// orderBodies returns every captured POST body, in order.
func (p *placementServer) orderBodies() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.bodies...)
}

// setOrderAnswer changes what POST /deploy/servers answers.
func (p *placementServer) setOrderAnswer(status int, body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.orderStatus, p.orderBody = status, body
}

// newPlacementClient builds a real client against the fixture server.
func newPlacementClient(t *testing.T, ps *placementServer) Client {
	t.Helper()
	c, err := NewClient(Config{BaseURL: ps.URL, APIKey: testAPIKey})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestPlacementCatalog_TriStateStockAndRegionSummary pins the parsing side of the
// contract: a datacenter the catalog reported is known, one it left out of
// dc_stock is unknown (not sold out), an id without a datacenter record keeps no
// region, and a region's summary is only "sold out" when every datacenter in it
// is explicitly sold out.
func TestPlacementCatalog_TriStateStockAndRegionSummary(t *testing.T) {
	ps := newPlacementServer(t)
	client := newPlacementClient(t, ps)

	plans, err := client.GetCatalog(context.Background())
	if err != nil {
		t.Fatalf("GetCatalog: %v", err)
	}
	byID := map[int]HourlyPlan{}
	for _, p := range plans {
		byID[p.ProductID] = p
	}

	plan, ok := byID[101]
	if !ok {
		t.Fatalf("plan 101 missing from catalog: %+v", plans)
	}
	if len(plan.Datacenters) != 3 {
		t.Fatalf("plan 101 datacenters = %d, want the 3 documented dc_ids", len(plan.Datacenters))
	}
	dcByID := map[int]Datacenter{}
	for _, dc := range plan.Datacenters {
		dcByID[dc.ID] = dc
	}
	if dc := dcByID[1]; dc.InStock == nil || !dc.Stocked() || dc.RegionID != 1 || dc.Name != "DC1" {
		t.Errorf("dc 1 = %+v, want DC1 in region 1 explicitly in stock", dc)
	}
	if dc := dcByID[2]; dc.InStock == nil || dc.Stocked() || dc.RegionID != 1 {
		t.Errorf("dc 2 = %+v, want DC2 in region 1 explicitly sold out", dc)
	}
	if dc := dcByID[3]; dc.InStock == nil || !dc.Stocked() || dc.RegionID != 2 || dc.Name != "DC3" {
		t.Errorf("dc 3 = %+v, want DC3 in region 2 explicitly in stock", dc)
	}

	// Region 1 holds one stocked and one sold-out datacenter: the plan is
	// sellable there, and the summary must not read as sold out.
	regionByID := map[int]Region{}
	for _, r := range plan.Regions {
		regionByID[r.ID] = r
	}
	if r := regionByID[1]; r.InStock == nil || !*r.InStock || !r.Sellable() {
		t.Errorf("region 1 stock = %v, want true and sellable", r.InStock)
	}
	if r := regionByID[2]; r.InStock == nil || !*r.InStock {
		t.Errorf("region 2 stock = %v, want true", r.InStock)
	}

	// Plan 102 omits dc 4 from dc_stock and lists dc 99 with no datacenter record.
	plan2, ok := byID[102]
	if !ok {
		t.Fatalf("plan 102 missing from catalog: %+v", plans)
	}
	dcByID = map[int]Datacenter{}
	for _, dc := range plan2.Datacenters {
		dcByID[dc.ID] = dc
	}
	if dc, ok := dcByID[4]; !ok || dc.InStock != nil {
		t.Errorf("dc 4 = %+v (present %v), want an unknown stock fact, not sold out", dc, ok)
	}
	if dc, ok := dcByID[99]; !ok || dc.RegionID != 0 {
		t.Errorf("dc 99 = %+v (present %v), want a record with no proven region", dc, ok)
	}
	// dc 1 is stocked and dc 99 proves nothing, so the region summary stays
	// positive rather than being pulled down by the unknown.
	if len(plan2.Regions) != 1 || plan2.Regions[0].InStock == nil || !*plan2.Regions[0].InStock {
		t.Errorf("plan 102 region stock = %+v, want true", plan2.Regions)
	}
}

// TestPlacementCatalog_RegionSoldOutOnlyWhenEveryDatacenterIs pins the difference
// between "one datacenter sold out" and "the region is sold out", and pins that a
// region whose only datacenter reports no stock fact stays unknown rather than
// sold out.
func TestPlacementCatalog_RegionSoldOutOnlyWhenEveryDatacenterIs(t *testing.T) {
	doc := strings.Replace(placementCatalogDoc,
		`"dc_stock": {"1": true, "2": false, "3": true},`,
		`"dc_stock": {"1": false, "2": false, "3": true},`, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers" {
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
			return
		}
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
	byID := map[int]HourlyPlan{}
	for _, p := range plans {
		byID[p.ProductID] = p
	}

	// Plan 101: every datacenter of region 1 is explicitly sold out.
	plan := byID[101]
	regionByID := map[int]Region{}
	for _, r := range plan.Regions {
		regionByID[r.ID] = r
	}
	if r := regionByID[1]; r.InStock == nil || *r.InStock || r.Sellable() {
		t.Errorf("region 1 stock = %v, want explicitly sold out", r.InStock)
	}
	if r := regionByID[2]; r.InStock == nil || !*r.InStock {
		t.Errorf("region 2 stock = %v, want true", r.InStock)
	}

	// Plan 102 lists dc 4, which dc_stock never mentions: unknown, not sold out.
	// Its region summary is proven by its other stocked datacenter (dc 1), so the
	// unknown entry alone must not drag the region down to sold out.
	plan2 := byID[102]
	if len(plan2.Regions) != 1 {
		t.Fatalf("plan 102 regions = %+v, want 1", plan2.Regions)
	}
	if plan2.Regions[0].InStock == nil || !*plan2.Regions[0].InStock {
		t.Errorf("plan 102 region stock = %v, want true from its explicitly stocked datacenter", plan2.Regions[0].InStock)
	}
}

// TestPlacementCatalog_RegionUnknownWhenOnlyDatacenterIsUnreported pins the case
// where a region mixes an explicitly sold-out datacenter with one the catalog did
// not report: the region's summary must be UNKNOWN rather than sold out, because
// an absent stock fact is not a sold-out fact and a region-only order is still
// documented as valid there.
func TestPlacementCatalog_RegionUnknownWhenOnlyDatacenterIsUnreported(t *testing.T) {
	doc := `{
  "meta": {"status": 200},
  "data": {
    "tiers": [{"group_id": 1, "group_name": "Cloud", "in_stock": true, "products": [{
      "product_id": 201, "product_name": "Cloud 2", "type": "vm", "in_stock": true,
      "allow_hourly": true, "rate_hourly": 0.14, "rate_monthly": 90, "price_id": 600,
      "region_ids": [1], "dc_ids": [2, 4], "dc_stock": {"2": false},
      "specs": {"cpu_cores": 2, "ram_gb": 4, "disks": [{"size_gb": 80}], "bw": 5}
    }]}],
    "regions": [{"region_id": "1", "region_name": "Norway", "region_country": "NO"}],
    "datacenters": [
      {"dc_id": 2, "dc_name": "DC2", "region_id": 1, "region_location": "Oslo"},
      {"dc_id": 4, "dc_name": "DC4", "region_id": 1, "region_location": "Bergen"}
    ],
    "currency": "NOK",
    "eligibility": {"qualifies_arrears": true}
  }
}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers" {
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
			return
		}
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
	if len(plans) != 1 || len(plans[0].Regions) != 1 {
		t.Fatalf("unexpected catalog shape: %+v", plans)
	}
	if got := plans[0].Regions[0].InStock; got != nil {
		t.Errorf("region 1 stock = %v, want unknown: dc 2 is sold out and dc 4 was never reported", *got)
	}
	if !plans[0].Regions[0].Sellable() {
		t.Error("an unknown region stock must stay orderable for provider-chosen placement")
	}
}

// TestPlacementCatalog_DropsIdWithoutIdentity pins that a dc_ids entry which is
// not a positive integer produces no datacenter at all. Publishing an id of 0
// would offer a placement the operator can neither identify nor order.
func TestPlacementCatalog_DropsIdWithoutIdentity(t *testing.T) {
	doc := `{
  "meta": {"status": 200},
  "data": {
    "tiers": [{"group_id": 1, "group_name": "Cloud", "in_stock": true, "products": [{
      "product_id": 202, "product_name": "Cloud 2", "type": "vm", "in_stock": true,
      "allow_hourly": true, "rate_hourly": 0.14, "rate_monthly": 90, "price_id": 601,
      "region_ids": [1], "dc_ids": [1, 0, "not-a-number"], "dc_stock": {"1": true, "0": true},
      "specs": {"cpu_cores": 2, "ram_gb": 4, "disks": [{"size_gb": 80}], "bw": 5}
    }]}],
    "regions": [{"region_id": "1", "region_name": "Norway", "region_country": "NO"}],
    "datacenters": [{"dc_id": 1, "dc_name": "DC1", "region_id": 1, "region_location": "Sandefjord"}],
    "currency": "NOK",
    "eligibility": {"qualifies_arrears": true}
  }
}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers" {
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
			return
		}
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
	if len(plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(plans))
	}
	datacenters := plans[0].Datacenters
	if len(datacenters) != 1 || datacenters[0].ID != 1 {
		t.Fatalf("datacenters = %+v, want only the identifiable dc 1", datacenters)
	}
	for _, dc := range datacenters {
		if dc.ID <= 0 {
			t.Errorf("datacenter %+v has no usable identity but was published", dc)
		}
	}
}

// TestOrderServer_ExplicitPlacementSendsDCOOnly pins the documented dc-only shape
// on the wire: dc_id present, region_id absent, one POST.
func TestOrderServer_ExplicitPlacementSendsDCOOnly(t *testing.T) {
	ps := newPlacementServer(t)
	client := newPlacementClient(t, ps)

	resp, err := client.OrderServer(context.Background(), OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	})
	if err != nil {
		t.Fatalf("OrderServer: %v", err)
	}
	if resp.OrderID != "ord_1" {
		t.Errorf("order id = %q, want the fixture's ord_1", resp.OrderID)
	}

	bodies := ps.orderBodies()
	if len(bodies) != 1 {
		t.Fatalf("provider order POSTs = %d, want exactly 1", len(bodies))
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &sent); err != nil {
		t.Fatalf("decoding the captured body %q: %v", bodies[0], err)
	}
	if got, ok := sent["dc_id"]; !ok || got != float64(1) {
		t.Errorf("captured body %s must carry dc_id 1", bodies[0])
	}
	if _, ok := sent["region_id"]; ok {
		t.Errorf("captured body %s must NOT carry region_id when dc_id is given", bodies[0])
	}
	if sent["pid"] != float64(101) || sent["price_id"] != float64(555) || sent["os_id"] != float64(12) {
		t.Errorf("captured body %s lost a documented selection field", bodies[0])
	}
	if sent["billing_period"] != BillingPeriodHourly || sent["quantity"] != float64(1) {
		t.Errorf("captured body %s lost a documented billing field", bodies[0])
	}
}

// TestOrderServer_RegionOnlyBodyIsUnchanged pins backward compatibility at the
// byte level: a request without dc_id must produce exactly the body this client
// produced before dc_id existed, so nothing about region-only ordering changed.
func TestOrderServer_RegionOnlyBodyIsUnchanged(t *testing.T) {
	const want = `{"pid":101,"price_id":555,"region_id":1,"os_id":12,` +
		`"billing_period":"hourly","quantity":1}`

	ps := newPlacementServer(t)
	client := newPlacementClient(t, ps)

	if _, err := client.OrderServer(context.Background(), OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	}); err != nil {
		t.Fatalf("OrderServer: %v", err)
	}

	bodies := ps.orderBodies()
	if len(bodies) != 1 {
		t.Fatalf("provider order POSTs = %d, want exactly 1", len(bodies))
	}
	if bodies[0] != want {
		t.Errorf("region-only body =\n  %s\nwant the pre-change body\n  %s", bodies[0], want)
	}
}

// TestOrderServer_PlacementRequirementRefusesLocally pins the client's own guard:
// a request that names neither a region nor a datacenter cannot be placed, so it
// fails before any request is made.
func TestOrderServer_PlacementRequirementRefusesLocally(t *testing.T) {
	ps := newPlacementServer(t)
	client := newPlacementClient(t, ps)

	_, err := client.OrderServer(context.Background(), OrderRequest{
		PID: 101, PriceID: 555, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	})
	if err == nil {
		t.Fatal("expected a placement error when neither region_id nor dc_id is given")
	}
	if !strings.Contains(err.Error(), "region_id or dc_id") {
		t.Errorf("error = %v, want it to name the placement requirement", err)
	}
	if got := len(ps.orderBodies()); got != 0 {
		t.Errorf("provider order POSTs = %d, want 0", got)
	}
}

// TestOrderServerSafe_DefinitivePlacement400IsNotRetried pins the error contract
// the handler relies on: a documented 400 for a pinned datacenter is one POST, the
// error is NOT classified as uncertain (so nothing is marked unknown and no later
// attempt is blocked as a possible duplicate), and the provider's own message
// survives so the operator learns why.
func TestOrderServerSafe_DefinitivePlacement400IsNotRetried(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "chosen datacenter sold out while others have capacity",
			body: placementSoldOutDCBody,
			want: "Product is out of stock in the selected datacenter.",
		},
		{
			name: "product not offered in the chosen datacenter",
			body: placementUnknownDCBody,
			want: "Product is not available in the selected datacenter.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPlacementServer(t)
			ps.setOrderAnswer(http.StatusBadRequest, tc.body)
			client := newPlacementClient(t, ps)

			_, err := client.OrderServerSafe(context.Background(), OrderRequest{
				PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12,
				BillingPeriod: BillingPeriodHourly, Quantity: 1,
			})
			if err == nil {
				t.Fatal("expected the provider's 400 to be reported")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want the provider's documented message %q", err, tc.want)
			}
			if isUncertainOrderError(err) {
				t.Errorf("error = %v, must NOT be classified as uncertain: a definitive 400 creates no order", err)
			}
			if got := len(ps.orderBodies()); got != 1 {
				t.Errorf("provider order POSTs = %d, want exactly 1 (no retry, no region-only fallback)", got)
			}

			// A definitive refusal must not poison the dedupe ledger: the same
			// selection is allowed to be attempted again after the operator
			// corrects it, so no unknown entry may be recorded.
			ps.setOrderAnswer(http.StatusOK, placementOKOrderBody)
			if _, retryErr := client.OrderServerSafe(context.Background(), OrderRequest{
				PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12,
				BillingPeriod: BillingPeriodHourly, Quantity: 1,
			}); retryErr != nil {
				t.Errorf("a corrected retry after a definitive 400 must be allowed, got %v", retryErr)
			}
			if got := len(ps.orderBodies()); got != 2 {
				t.Errorf("provider order POSTs after the retry = %d, want 2", got)
			}
		})
	}
}

// TestOrderServerSafe_AmbiguousPlacementResponseStaysProtected pins the opposite
// contract: an ambiguous response (5xx) is recorded as unknown and the SAME
// selection is then refused client-side with zero further POSTs, so an uncertain
// pinned order cannot be duplicated.
func TestOrderServerSafe_AmbiguousPlacementResponseStaysProtected(t *testing.T) {
	ps := newPlacementServer(t)
	ps.setOrderAnswer(http.StatusInternalServerError, `{"meta":{"status":500,"message":"upstream failure"}}`)
	client := newPlacementClient(t, ps)

	req := OrderRequest{
		PID: 101, PriceID: 555, RegionID: 1, DCID: 2, OSID: 12,
		BillingPeriod: BillingPeriodHourly, Quantity: 1,
	}
	if _, err := client.OrderServerSafe(context.Background(), req); err == nil {
		t.Fatal("expected an uncertain error on a 5xx order response")
	}
	if got := len(ps.orderBodies()); got != 1 {
		t.Fatalf("provider order POSTs = %d, want 1", got)
	}

	_, err := client.OrderServerSafe(context.Background(), req)
	if err == nil {
		t.Fatal("a prior unknown outcome must refuse the repeat")
	}
	var uncertain *OrderUncertainError
	if !errors.As(err, &uncertain) {
		t.Errorf("repeat refusal = %v, want an OrderUncertainError", err)
	}
	if got := len(ps.orderBodies()); got != 1 {
		t.Errorf("provider order POSTs after the repeat = %d, want 1 (no duplicate purchase)", got)
	}
}
