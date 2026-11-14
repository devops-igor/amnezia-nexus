package handlers

// Explicit datacenter placement through the real order consumer (#739).
//
// Unlike the mocked-provider harness in this package, these tests wire the REAL
// handler to the REAL provider client and a local HTTP server, so the assertions
// cover the whole path: payload decode -> catalog revalidation -> managed-key
// association -> order dispatch -> the actual bytes of the POST /deploy/servers
// body. A test-only fake cannot prove that path: it replaces the very component
// whose serialization is under test.
//
// The provider fixture serves a documented multi-region, multi-datacenter catalog,
// the documented image endpoints and a real key list, and records every order body.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// placementHandlerCatalog is the documented GET /deploy/servers body the fixture
// serves. Three products cover the three behaviours the contract depends on:
//
//	101 vm          region 1+2, dc 1/2 in region 1, dc 3 in region 2, all reported;
//	102 vm          region 1, dc 1 stocked and dc 4 never reported (unknown);
//	120 dedicated   built to order, dc 1/2 both stocked (dc_id is ignored by the
//	                provider for these, so pinning one must be refused here).
//
// dc 99 appears in plan 102's dc_ids but in no datacenters[] entry, so an id with
// no proven region is observable.
var placementHandlerCatalog = struct {
	mu    sync.Mutex
	stock string
}{
	stock: `"dc_stock": {"1": true, "2": false, "3": true},`,
}

const placementHandlerDocPrefix = `{
  "meta": {"status": 200},
  "data": {
    "tiers": [
      {"group_id": 1, "group_name": "Cloud Servers", "in_stock": true, "products": [
        {
          "product_id": 101, "product_name": "Cloud 2", "type": "vm",
          "in_stock": true, "built_to_order": false, "allow_hourly": true,
          "rate_hourly": 0.14375, "rate_monthly": 90, "price_id": 555,
          "region_ids": [1, 2], "dc_ids": [1, 2, 3],
          %s
          "specs": {"cpu_cores": 2, "ram_gb": 4, "disks": [{"size_gb": 80}], "bw": 5}
        },
        {
          "product_id": 102, "product_name": "Cloud 4", "type": "vm",
          "in_stock": true, "built_to_order": false, "allow_hourly": true,
          "rate_hourly": 0.2875, "rate_monthly": 180, "price_id": 556,
          "region_ids": [1], "dc_ids": [1, 4, 5, 99],
          "dc_stock": {"1": true},
          "specs": {"cpu_cores": 4, "ram_gb": 8, "disks": [{"size_gb": 160}], "bw": 10}
        },
        {
          "product_id": 103, "product_name": "Cloud 1", "type": "vm",
          "in_stock": true, "built_to_order": false, "allow_hourly": true,
          "rate_hourly": 0.0719, "rate_monthly": 45, "price_id": 557,
          "region_ids": [1], "dc_ids": [1],
          "dc_stock": {"1": true},
          "specs": {"cpu_cores": 1, "ram_gb": 2, "disks": [{"size_gb": 40}], "bw": 2}
        },
        {
          "product_id": 120, "product_name": "Dedicated 64", "type": "dedicated",
          "in_stock": false, "built_to_order": true, "allow_hourly": true,
          "rate_hourly": 0.9, "rate_monthly": 560, "price_id": 560,
          "region_ids": [1], "dc_ids": [1, 2],
          "dc_stock": {"1": true, "2": true},
          "specs": {"cpu_cores": 12, "ram_gb": 64, "disks": [{"size_gb": 960}], "bw": 100}
        }
      ]}
    ],
    "regions": [
      {"region_id": "1", "region_name": "Norway", "region_name_short": "NO", "region_country": "NO"},
      {"region_id": "2", "region_name": "Sweden", "region_name_short": "SE", "region_country": "SE"}
    ],
    "datacenters": [
      {"dc_id": 1, "dc_name": "DC1", "region_id": 1, "region_location": "Sandefjord", "region_country": "NO"},
      {"dc_id": 2, "dc_name": "DC2", "region_id": 1, "region_location": "Oslo", "region_country": "NO"},
      {"dc_id": 3, "dc_name": "DC3", "region_id": 2, "region_location": "Stockholm", "region_country": "SE"},
      {"dc_id": 4, "dc_name": "DC4", "region_id": 1, "region_location": "Bergen", "region_country": "NO"},
      {"dc_id": 5, "dc_name": "DC5", "region_id": 3, "region_location": "Helsinki", "region_country": "FI"}
    ],
    "currency": "NOK",
    "eligibility": {"qualifies_arrears": true, "credit_nok": 0}
  }
}`

const placementHandlerDistroDoc = `{"meta":{"status":200},"data":[
  {"dist_id":"1","dist_name":"Debian","dist_value":"debian","dist_active":"1"}
]}`

const placementHandlerImagesDoc = `{"meta":{"status":200},"data":[
  {"os_id":"12","dist_id":"1","os_name":"Debian 12","os_arch":"amd64","os_dedicated_only":"0","os_minram":"0","dist_name":"Debian"}
]}`

// placementHandlerProvider is the local Gigahost HTTP fixture. It records the raw
// body of every order POST and tracks the managed key list so the real credential
// association path runs exactly as it does in production.
type placementHandlerProvider struct {
	*httptest.Server
	mu         sync.Mutex
	orderBodys []string
	keys       []gigahost.SSHKeyInfo
	nextKeyID  int
	orderState int
	orderBody  string
	// catalogCalls counts GET /deploy/servers reads so a test can flip stock
	// between the display read and the order-time revalidation.
	catalogCalls int
	// catalogOverride, when set, replaces the catalog body entirely.
	catalogOverride string
	// imageState, when non-zero, is the status code served for image reads.
	imageState int
}

// placementHandlerOrderOK is the documented successful POST /deploy/servers reply.
const placementHandlerOrderOK = `{"meta":{"status":200},"data":{"order_id":"ord_739","status":"pending"}}`

func newPlacementHandlerProvider(t *testing.T) *placementHandlerProvider {
	t.Helper()
	p := &placementHandlerProvider{orderState: http.StatusOK, orderBody: placementHandlerOrderOK, nextKeyID: 41}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/deploy/servers" && r.Method == http.MethodGet:
			p.mu.Lock()
			p.catalogCalls++
			override := p.catalogOverride
			stock := placementHandlerCatalog.stock
			p.mu.Unlock()
			if override != "" {
				_, _ = w.Write([]byte(override))
				return
			}
			_, _ = w.Write([]byte(strings.Replace(placementHandlerDocPrefix, "%s", stock, 1)))
		case r.URL.Path == "/reinstall/distro":
			if status := p.imageStatus(); status != 0 {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"meta":{"status":500,"message":"upstream failure"}}`))
				return
			}
			_, _ = w.Write([]byte(placementHandlerDistroDoc))
		case strings.HasPrefix(r.URL.Path, "/reinstall/distro/"):
			_, _ = w.Write([]byte(placementHandlerImagesDoc))
		case r.URL.Path == "/account" && r.Method == http.MethodGet:
			p.mu.Lock()
			keys := append([]gigahost.SSHKeyInfo(nil), p.keys...)
			p.mu.Unlock()
			payload, err := json.Marshal(map[string]any{"data": map[string]any{
				"cust_id": "cust-1", "balance": 500, "currency": "NOK", "sshkeys": keys,
			}})
			if err != nil {
				t.Errorf("encoding the fixture account: %v", err)
				return
			}
			_, _ = w.Write(payload)
		case r.URL.Path == "/account/sshkey" && r.Method == http.MethodPost:
			var body struct {
				Name string `json:"name"`
				Data string `json:"data"`
			}
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("decoding the fixture key registration %q: %v", raw, err)
			}
			p.mu.Lock()
			p.nextKeyID++
			p.keys = append(p.keys, gigahost.SSHKeyInfo{
				KeyID:   itoa(p.nextKeyID),
				KeyName: body.Name,
				KeyData: body.Data,
			})
			p.mu.Unlock()
			_, _ = w.Write([]byte(`{"meta":{"status":200}}`))
		case r.URL.Path == "/servers":
			_, _ = w.Write([]byte(`{"meta":{"page":1,"total_pages":1,"total":0},"data":[]}`))
		case r.URL.Path == "/deploy/servers" && r.Method == http.MethodPost:
			raw, _ := io.ReadAll(r.Body)
			p.mu.Lock()
			p.orderBodys = append(p.orderBodys, string(raw))
			state, body := p.orderState, p.orderBody
			p.mu.Unlock()
			w.WriteHeader(state)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

// imageStatus reports an injected image-read failure status, if any.
func (p *placementHandlerProvider) imageStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.imageState
}

// orders returns the captured order bodies, in order.
func (p *placementHandlerProvider) orders() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.orderBodys...)
}

// answerOrder changes what POST /deploy/servers replies with.
func (p *placementHandlerProvider) answerOrder(status int, body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.orderState, p.orderBody = status, body
}

// failImages makes the image catalog unreadable.
func (p *placementHandlerProvider) failImages(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.imageState = status
}

// setCatalog replaces the served catalog body.
func (p *placementHandlerProvider) setCatalog(body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.catalogOverride = body
}

// itoa avoids importing strconv in this test file's small helper.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var digits []byte
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

// placementHarness is the real handler wired to the real client.
type placementHarness struct {
	h *Handlers
	p *placementHandlerProvider
}

func newPlacementHarness(t *testing.T) *placementHarness {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	p := newPlacementHandlerProvider(t)
	client, err := gigahost.NewClient(gigahost.Config{BaseURL: p.URL, APIKey: testGigahostAPIKey})
	if err != nil {
		t.Fatalf("creating the real provider client: %v", err)
	}
	h.SetGigahostClient(client)
	return &placementHarness{h: h, p: p}
}

// testGigahostAPIKey is a well-formed key for the fixture; the local server never
// authenticates it.
const testGigahostAPIKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// orderPayload is one order request body.
type orderPayload struct {
	PID      int `json:"pid"`
	PriceID  int `json:"price_id"`
	RegionID int `json:"region_id"`
	DCID     int `json:"dc_id,omitempty"`
	OSID     int `json:"os_id"`
}

// order posts one order as a distinct admin and returns the recorder.
func (s *placementHarness) order(t *testing.T, admin string, payload orderPayload) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encoding the order payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(string(body)))
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: admin, Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	s.h.GigahostOrderHandler(w, req)
	return w
}

// catalog reads the catalog through the real handler, as the UI does before an
// operator chooses a placement.
func (s *placementHarness) catalog(t *testing.T) []gigahost.HourlyPlan {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/hosting/gigahost/catalog", nil)
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: "admin-catalog", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	s.h.GigahostCatalogHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("catalog status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		Plans []gigahost.HourlyPlan `json:"plans"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding the catalog response: %v (body: %s)", err, w.Body.String())
	}
	return resp.Plans
}

// decodedOrder decodes a captured order body for assertions.
func decodedOrder(t *testing.T, body string) map[string]any {
	t.Helper()
	var sent map[string]any
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatalf("decoding the captured order body %q: %v", body, err)
	}
	return sent
}

// TestGigahostPlacement_ExplicitSelectionPurchasesOnce drives the whole consumer:
// an explicit datacenter the provider published must reach exactly one purchase,
// and that purchase must carry dc_id and no region_id.
func TestGigahostPlacement_ExplicitSelectionPurchasesOnce(t *testing.T) {
	s := newPlacementHarness(t)

	w := s.order(t, "admin-explicit", orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12})
	if w.Code != http.StatusOK {
		t.Fatalf("explicit order status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	bodies := s.p.orders()
	if len(bodies) != 1 {
		t.Fatalf("provider order POSTs = %d, want exactly 1", len(bodies))
	}
	sent := decodedOrder(t, bodies[0])
	if sent["dc_id"] != float64(1) {
		t.Errorf("captured body %s must pin dc_id 1", bodies[0])
	}
	if _, ok := sent["region_id"]; ok {
		t.Errorf("captured body %s must omit region_id for a pinned order", bodies[0])
	}

	// The durable ledger keeps the region the operator chose: the duplicate guard
	// and the audit trail key on it even though the wire carries only dc_id.
	orders, err := s.h.getGigahostOrders(context.Background())
	if err != nil {
		t.Fatalf("reading persisted orders: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("persisted orders = %d, want 1", len(orders))
	}
	if orders[0].RegionID != 1 || orders[0].PlanID != 101 {
		t.Errorf("persisted selection = plan %d region %d, want 101/1", orders[0].PlanID, orders[0].RegionID)
	}
}

// TestGigahostPlacement_RegionOnlySelectionIsUnchanged proves backward
// compatibility through the real consumer: the same request without dc_id reaches
// one purchase and serializes the documented region-only shape.
func TestGigahostPlacement_RegionOnlySelectionIsUnchanged(t *testing.T) {
	s := newPlacementHarness(t)

	w := s.order(t, "admin-region", orderPayload{PID: 101, PriceID: 555, RegionID: 1, OSID: 12})
	if w.Code != http.StatusOK {
		t.Fatalf("region-only order status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	bodies := s.p.orders()
	if len(bodies) != 1 {
		t.Fatalf("provider order POSTs = %d, want exactly 1", len(bodies))
	}
	sent := decodedOrder(t, bodies[0])
	if sent["region_id"] != float64(1) {
		t.Errorf("captured body %s must carry region_id 1", bodies[0])
	}
	if _, ok := sent["dc_id"]; ok {
		t.Errorf("captured body %s must omit dc_id for provider-chosen placement", bodies[0])
	}
}

// TestGigahostPlacement_UnselectablePlacementRefusesBeforePurchase is the negative
// control table: every way an explicit datacenter choice can disagree with the
// provider must be refused with zero purchases, each with its own reason.
func TestGigahostPlacement_UnselectablePlacementRefusesBeforePurchase(t *testing.T) {
	cases := []struct {
		name      string
		payload   orderPayload
		wantInMsg string
	}{
		{
			name:      "datacenter the plan does not offer",
			payload:   orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 9, OSID: 12},
			wantInMsg: "datacenter 9 is not offered for plan 101",
		},
		{
			name:      "datacenter listed with no datacenter record",
			payload:   orderPayload{PID: 102, PriceID: 556, RegionID: 1, DCID: 99, OSID: 12},
			wantInMsg: "datacenter 99 has no documented region",
		},
		{
			name:      "datacenter in a region the plan does not serve",
			payload:   orderPayload{PID: 102, PriceID: 556, RegionID: 1, DCID: 5, OSID: 12},
			wantInMsg: "datacenter 5 is in region 3, which plan 102 does not serve",
		},
		{
			name:      "datacenter whose region differs from the requested region",
			payload:   orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 3, OSID: 12},
			wantInMsg: "datacenter 3 is in region 2, not the requested region 1",
		},
		{
			name:      "datacenter explicitly sold out",
			payload:   orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 2, OSID: 12},
			wantInMsg: "datacenter 2 is out of stock for plan 101",
		},
		{
			name:      "datacenter with unreported stock",
			payload:   orderPayload{PID: 102, PriceID: 556, RegionID: 1, DCID: 4, OSID: 12},
			wantInMsg: "stock for datacenter 4 is not reported",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPlacementHarness(t)
			w := s.order(t, "admin-refuse", tc.payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantInMsg) {
				t.Errorf("body = %s, want it to contain %q", w.Body.String(), tc.wantInMsg)
			}
			if got := len(s.p.orders()); got != 0 {
				t.Errorf("provider order POSTs = %d, want 0", got)
			}
		})
	}
}

// TestGigahostPlacement_StockLostAfterDisplayRefuses pins the revalidation
// requirement: the placement the operator could see in the catalog is re-read from
// the provider at order time, and stock that disappeared in between refuses the
// order with zero purchases rather than being bought or silently downgraded to
// region-only.
func TestGigahostPlacement_StockLostAfterDisplayRefuses(t *testing.T) {
	s := newPlacementHarness(t)

	// The operator's view: dc 1 is selectable.
	plans := s.catalog(t)
	if !datacenterSelectable(plans, 101, 1) {
		t.Fatalf("fixture precondition failed: dc 1 should be selectable for plan 101: %+v", plans)
	}

	// The provider sells the last unit while the operator is choosing.
	placementHandlerCatalog.mu.Lock()
	previous := placementHandlerCatalog.stock
	placementHandlerCatalog.stock = `"dc_stock": {"1": false, "2": false, "3": true},`
	placementHandlerCatalog.mu.Unlock()
	t.Cleanup(func() {
		placementHandlerCatalog.mu.Lock()
		placementHandlerCatalog.stock = previous
		placementHandlerCatalog.mu.Unlock()
	})

	w := s.order(t, "admin-stock-loss", orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 after stock loss (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "datacenter 1 is out of stock for plan 101") {
		t.Errorf("body = %s, want the datacenter-specific out-of-stock refusal", w.Body.String())
	}
	if got := len(s.p.orders()); got != 0 {
		t.Errorf("provider order POSTs = %d, want 0", got)
	}
}

// TestGigahostPlacement_CatalogAndImageFailuresRefuse proves an unreadable catalog
// or image set is a hard refusal before any purchase: the selection cannot be
// revalidated, so nothing may be ordered from it.
func TestGigahostPlacement_CatalogAndImageFailuresRefuse(t *testing.T) {
	t.Run("catalog unreadable", func(t *testing.T) {
		s := newPlacementHarness(t)
		s.p.setCatalog(`{"meta":{"status":500,"message":"upstream failure"}}`)
		w := s.order(t, "admin-cat-fail", orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12})
		if w.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 (body: %s)", w.Code, w.Body.String())
		}
		if got := len(s.p.orders()); got != 0 {
			t.Errorf("provider order POSTs = %d, want 0", got)
		}
	})

	t.Run("image catalog unreadable", func(t *testing.T) {
		s := newPlacementHarness(t)
		s.p.failImages(http.StatusInternalServerError)
		w := s.order(t, "admin-img-fail", orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12})
		if w.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502 (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "catalog_check_failed") {
			t.Errorf("body = %s, want catalog_check_failed", w.Body.String())
		}
		if got := len(s.p.orders()); got != 0 {
			t.Errorf("provider order POSTs = %d, want 0", got)
		}
	})
}

// TestGigahostPlacement_ProviderSoldOutAtOrderTimeIsOnePost pins the last guard:
// when the provider itself refuses a pinned datacenter with its documented 400,
// the handler reports a safe failure after exactly ONE POST — no retry and no
// region-only fallback, which would place the server somewhere the operator did
// not choose.
//
// The response shape is the pre-existing one for a provider order error (202 with
// status "unknown", which is what a region-only order already produced before this
// change) while the durable row records "failed". This test pins that parity
// rather than inventing a new outcome: what #739 changes is only that the single
// request is the pinned one.
func TestGigahostPlacement_ProviderSoldOutAtOrderTimeIsOnePost(t *testing.T) {
	cases := []struct {
		name    string
		payload orderPayload
	}{
		{
			name:    "pinned datacenter",
			payload: orderPayload{PID: 101, PriceID: 555, RegionID: 1, DCID: 1, OSID: 12},
		},
		{
			name:    "provider-chosen region, unchanged baseline",
			payload: orderPayload{PID: 101, PriceID: 555, RegionID: 1, OSID: 12},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPlacementHarness(t)
			s.p.answerOrder(http.StatusBadRequest,
				`{"meta":{"status":400,"status_message":"400 Bad Request",`+
					`"message":"Product is out of stock in the selected datacenter."}}`)

			w := s.order(t, "admin-provider-400", tc.payload)
			if w.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want the pre-existing 202 for a provider order error (body: %s)",
					w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "unknown") {
				t.Errorf("body = %s, want the outcome marked unknown rather than retried", w.Body.String())
			}

			bodies := s.p.orders()
			if len(bodies) != 1 {
				t.Fatalf("provider order POSTs = %d, want exactly 1", len(bodies))
			}
			// The one request that was sent must still be the shape the operator
			// chose: a fallback to region-only would show up here as a region_id on
			// a pinned order, or as a second body.
			sent := decodedOrder(t, bodies[0])
			if tc.payload.DCID > 0 {
				if sent["dc_id"] != float64(tc.payload.DCID) {
					t.Errorf("captured body %s must still pin dc_id %d", bodies[0], tc.payload.DCID)
				}
				if _, ok := sent["region_id"]; ok {
					t.Errorf("captured body %s must not carry a fallback region_id", bodies[0])
				}
			} else if sent["region_id"] != float64(tc.payload.RegionID) {
				t.Errorf("captured body %s must still carry region_id %d", bodies[0], tc.payload.RegionID)
			}

			orders, err := s.h.getGigahostOrders(context.Background())
			if err != nil {
				t.Fatalf("reading persisted orders: %v", err)
			}
			if len(orders) != 1 {
				t.Fatalf("persisted orders = %d, want 1", len(orders))
			}
			if orders[0].Status != gigahost.StatusFailed {
				t.Errorf("persisted status = %q, want %q for a definitive refusal", orders[0].Status, gigahost.StatusFailed)
			}
		})
	}
}

// TestValidatePlanPlacement_BuiltToOrderPlanRefusesPinning covers the one
// documented behaviour the hourly catalog can never surface: the provider lists
// built-to-order products as sold out (in_stock false), and the hourly plan filter
// requires in_stock, so such a plan cannot reach the order path. The validator
// still refuses a pin on it, because ordering would let the provider silently pick
// a different datacenter inside the region.
func TestValidatePlanPlacement_BuiltToOrderPlanRefusesPinning(t *testing.T) {
	inStock := true
	plan := &gigahost.HourlyPlan{
		ProductID: 120, PriceID: 560, Type: "dedicated", BuiltToOrder: true,
		Regions:     []gigahost.Region{{ID: 1, Available: true, InStock: &inStock}},
		Datacenters: []gigahost.Datacenter{{ID: 1, Name: "DC1", RegionID: 1, InStock: &inStock}},
	}

	err := validatePlanPlacement(plan, OrderServerPayload{PID: 120, PriceID: 560, RegionID: 1, DCID: 1, OSID: 12})
	if err == nil {
		t.Fatal("pinning a built-to-order plan must be refused: the provider would ignore dc_id")
	}
	if !strings.Contains(err.Error(), "built to order") {
		t.Errorf("error = %v, want it to name the built-to-order reason", err)
	}

	// The same plan with provider-chosen placement is untouched by this validator,
	// which is the documented and only supported way to order it.
	if err := validatePlanPlacement(plan, OrderServerPayload{PID: 120, PriceID: 560, RegionID: 1, OSID: 12}); err != nil {
		t.Errorf("provider-chosen placement on a built-to-order plan must not be refused here, got %v", err)
	}
}

// datacenterSelectable reports whether the catalog view offers an explicitly
// stocked datacenter for a plan, which is the precondition a UI choice relies on.
func datacenterSelectable(plans []gigahost.HourlyPlan, pid, dcID int) bool {
	for _, p := range plans {
		if p.ProductID != pid {
			continue
		}
		for _, dc := range p.Datacenters {
			if dc.ID == dcID {
				return dc.Stocked() && dc.RegionID > 0 && !p.BuiltToOrder
			}
		}
	}
	return false
}
