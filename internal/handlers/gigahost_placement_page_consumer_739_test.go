package handlers

// Joined page-to-provider placement test (#739 B2).
//
// This is the end of the chain the rest of the issue establishes one link at a
// time: the page's own script builds a payload, and that payload reaches the real
// order handler and the real provider client, whose HTTP body is captured.
//
// The page half is not reimplemented: the test reads templates/settings.html,
// extracts the shipped script, and runs it in JSDOM with the shipped placement
// module, then takes the payload it actually posted and sends exactly that body to
// GigahostOrderHandler. A payload shape the handler rejects, or a handler that
// posts something other than what the page chose, therefore fails here.
//
// The provider is the fixture from the placement consumer test in this package: a
// local HTTP server recording every POST /deploy/servers body.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// TestGigahostPlacement_PagePayloadReachesProvider proves the two documented
// payload shapes the page produces are the shapes the provider receives, with
// exactly one purchase call each.
func TestGigahostPlacement_PagePayloadReachesProvider(t *testing.T) {
	cases := []struct {
		name string
		// placementValue is what the operator chooses in the page's select: the
		// region-managed sentinel, or one datacenter id.
		placementValue string
		wantPin        bool
	}{
		{name: "region-managed placement", placementValue: "", wantPin: false},
		{name: "explicit datacenter pin", placementValue: "1", wantPin: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPlacementHarness(t)

			// The page's own script builds the payload from its own selectors.
			body := pageOrderPayload(t, tc.placementValue)

			var sent map[string]any
			if err := json.Unmarshal([]byte(body), &sent); err != nil {
				t.Fatalf("the page produced an undecodable payload %q: %v", body, err)
			}
			if sent["pid"] != float64(101) || sent["price_id"] != float64(555) || sent["os_id"] != float64(12) {
				t.Fatalf("page payload lost a documented field: %s", body)
			}

			// Send exactly what the page produced into the real handler.
			rec := s.orderRaw(t, "admin-page-"+tc.name, body)
			if rec.Code != http.StatusOK {
				t.Fatalf("handler status = %d for the page's payload %s (body: %s)",
					rec.Code, body, rec.Body.String())
			}

			wantBody, wantBody2 := pagePayloadExpectation(t, tc.wantPin)
			_ = wantBody2
			if got := strings.Contains(body, wantBody); !got {
				t.Errorf("page payload %s does not carry the expected placement field %s", body, wantBody)
			}

			orders := s.p.orders()
			if len(orders) != 1 {
				t.Fatalf("provider POSTs = %d, want exactly 1", len(orders))
			}
			providerBody := decodedOrder(t, orders[0])
			if tc.wantPin {
				if providerBody["dc_id"] != float64(1) {
					t.Errorf("provider body %s must pin dc_id 1", orders[0])
				}
				if _, ok := providerBody["region_id"]; ok {
					t.Errorf("provider body %s must omit region_id for a pinned order", orders[0])
				}
			} else {
				if providerBody["region_id"] != float64(1) {
					t.Errorf("provider body %s must carry region_id 1", orders[0])
				}
				if _, ok := providerBody["dc_id"]; ok {
					t.Errorf("provider body %s must omit dc_id for provider-chosen placement", orders[0])
				}
			}
		})
	}
}

// TestGigahostPlacement_PageRefusalSendsNothing proves that a page selection the
// module refuses never reaches the provider: the page refuses before posting, and
// even if such a body were posted the handler would refuse it with zero purchases.
func TestGigahostPlacement_PageRefusalSendsNothing(t *testing.T) {
	// The page refuses these locally, so it posts nothing at all.
	for _, placement := range []string{"2", "4", "3", "invalid-2"} {
		t.Run("page refuses "+placement, func(t *testing.T) {
			body := pageOrderPayload(t, placement)
			if body != "" {
				t.Fatalf("the page posted an order for placement %q: %s", placement, body)
			}
		})
	}

	// Defence in depth: the same choices, if they did reach the handler, are refused
	// there too. This is the layer that must hold when the page is stale, tampered or
	// bypassed entirely.
	cases := []struct {
		name   string
		body   string
		reason string
	}{
		{
			name:   "pin on a sold-out datacenter",
			body:   `{"pid":101,"price_id":555,"region_id":1,"dc_id":2,"os_id":12}`,
			reason: "out of stock",
		},
		{
			name: "pin on a datacenter with unreported stock",
			// dc 4 belongs to plan 102, whose dc_stock omits it.
			body:   `{"pid":102,"price_id":556,"region_id":1,"dc_id":4,"os_id":12}`,
			reason: "stock for datacenter 4 is not reported",
		},
		{
			name:   "pin on a datacenter in another region",
			body:   `{"pid":101,"price_id":555,"region_id":1,"dc_id":3,"os_id":12}`,
			reason: "not the requested region",
		},
		{
			name:   "pin on a datacenter the plan does not list",
			body:   `{"pid":101,"price_id":555,"region_id":1,"dc_id":99,"os_id":12}`,
			reason: "not offered for plan",
		},
	}

	for _, tc := range cases {
		t.Run("handler refuses "+tc.name, func(t *testing.T) {
			s := newPlacementHarness(t)
			rec := s.orderRaw(t, "admin-refuse", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.reason) {
				t.Errorf("body = %s, want it to name %q", rec.Body.String(), tc.reason)
			}
			if got := len(s.p.orders()); got != 0 {
				t.Errorf("provider POSTs = %d, want 0", got)
			}
		})
	}
}

// pageOrderPayload runs the shipped settings page in JSDOM with the shipped
// placement module and the placement fixture catalog, chooses placementValue in
// the placement select, and returns the order body the page actually posted - or
// "" when the page refused to post at all.
func pageOrderPayload(t *testing.T, placementValue string) string {
	t.Helper()
	node := gigahostOrderStatusNode(t)

	template, err := web.TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	module, err := web.StaticFS.ReadFile("static/js/gigahost_placement.js")
	if err != nil {
		t.Fatalf("read placement module: %v", err)
	}
	// The page calls the catalog-freshness module from its own catalog read, so the
	// harness loads it too, exactly as the page does.
	catalogStatus, err := web.StaticFS.ReadFile("static/js/gigahost_catalog_status.js")
	if err != nil {
		t.Fatalf("read catalog status module: %v", err)
	}
	pageJS, err := pageScriptForTest(string(template))
	if err != nil {
		t.Fatalf("extract the page script: %v", err)
	}

	pageEncoded, _ := json.Marshal(pageJS)
	moduleEncoded, _ := json.Marshal(string(module))
	catalogStatusEncoded, _ := json.Marshal(string(catalogStatus))
	idsEncoded, _ := json.Marshal(pageElementIDsForTest(pageJS))
	placementEncoded, _ := json.Marshal(placementValue)

	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const dom = new JSDOM('<!doctype html><html><body></body></html>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;

const ids = %s;
for (const id of ids) {
  const el = w.document.createElement('input');
  el.id = id;
  w.document.body.appendChild(el);
}
// The ordering controls must be the interactive types the page binds.
function mk(tag, id) {
  const old = w.document.getElementById(id);
  if (old) old.remove();
  const el = w.document.createElement(tag);
  el.id = id;
  w.document.body.appendChild(el);
}
for (const [tag, id] of [['select','deployPlanSelect'],['select','deployRegionSelect'],
                         ['select','deployPlacementSelect'],['p','deployPlacementHint'],
                         ['select','deployOSSelect'],['button','btnDeployVPS'],
                         ['button','btnRefreshCatalog'],['div','deployVPSSpinner'],
                         ['div','deployCatalogLoading']]) { mk(tag, id); }

// The committed provider catalog shape, restricted to one in-stock datacenter so
// each case pins or does not pin a single known id.
const plan = {
  product_id: 101, price_id: 555, name: 'Cloud 2', type: 'vm',
  built_to_order: false, in_stock: true,
  currency: 'NOK', hourly_rate_nok: 0.14375, monthly_ceiling_nok: 90,
  regions: [{id:1,name:'Norway',country:'NO',available:true,in_stock:true}],
  datacenters: [
    {id:1,name:'DC1',region_id:1,location:'Sandefjord',country:'NO',in_stock:true},
    {id:2,name:'DC2',region_id:1,location:'Oslo',country:'NO',in_stock:false},
    {id:4,name:'DC4',region_id:1,location:'Bergen',country:'NO',in_stock:null},
    {id:3,name:'DC3',region_id:2,location:'Stockholm',country:'SE',in_stock:true}
  ],
  os_options: [{os_id:12,os_name:'Debian 12'}]
};

const posts = [];
w.API = {
  get: async url => (url.indexOf('/catalog') !== -1) ? {plans:[plan]} : {orders:[], setup_intents:[]},
  post: async (url, body) => { posts.push({url, body}); return {message:'ok'}; },
  delete: async () => ({status:'ok'}),
};
w.UI = {toast: () => {}};
w.confirm = () => true;
w.startGigahostOrderStatusRefresh = () => {};
w.loadRecentOrders = () => {};
w.loadSetupIntents = () => {};
w.saveSettings = () => {};
w.checkUpstreamStatus = () => {};
w.setupIntentsInFlight = new Set();

w.eval(%s);   // catalog-freshness module
w.eval(%s);   // placement module
w.eval(%s);   // the page script

(async () => {
  await w.loadGigahostCatalog();
  await new Promise(r => setTimeout(r, 0));

  const placeSel = w.document.getElementById('deployPlacementSelect');
  // The page's own sentinel is whatever its first option carries; an empty
  // placementValue in the Go test means "keep that default".
  const wanted = %s;
  placeSel.value = wanted === '' ? placeSel.options[0].value : wanted;
  placeSel.dispatchEvent(new w.Event('change', {bubbles:true}));

  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));

  const orders = posts.filter(p => p.url.indexOf('/order') !== -1);
  if (orders.length === 0) { console.log('NO_ORDER'); }
  else if (orders.length > 1) { console.error('MULTIPLE_ORDERS: ' + orders.length); process.exit(1); }
  else { console.log('ORDER_BODY:' + JSON.stringify(orders[0].body)); }
  dom.window.close();
})().catch(e => { console.error('FAILED: ' + (e && e.stack || e)); process.exit(1); });
`, string(idsEncoded), string(catalogStatusEncoded), string(moduleEncoded), string(pageEncoded), string(placementEncoded))

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	out, runErr := cmd.CombinedOutput()
	text := string(out)
	if runErr != nil {
		t.Fatalf("running the page: %v\n%s", runErr, text)
	}
	if strings.Contains(text, "NO_ORDER") {
		return ""
	}
	const marker = "ORDER_BODY:"
	idx := strings.Index(text, marker)
	if idx < 0 {
		t.Fatalf("the page neither ordered nor reported a refusal:\n%s", text)
	}
	line := strings.SplitN(text[idx+len(marker):], "\n", 2)[0]
	return strings.TrimSpace(line)
}

// pageScriptForTest returns the last inline <script> body of a template.
func pageScriptForTest(html string) (string, error) {
	const open, closeTag = "<script", "</script>"
	var last string
	for offset := 0; ; {
		start := strings.Index(html[offset:], open)
		if start < 0 {
			break
		}
		start += offset
		tagEnd := strings.Index(html[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagEnd += start
		bodyStart := tagEnd + 1
		end := strings.Index(html[bodyStart:], closeTag)
		if end < 0 {
			break
		}
		end += bodyStart
		if !strings.Contains(html[start:tagEnd], "src=") {
			last = html[bodyStart:end]
		}
		offset = end + len(closeTag)
	}
	if strings.TrimSpace(last) == "" {
		return "", fmt.Errorf("no inline script block with content found")
	}
	return last, nil
}

// pageElementIDsForTest returns the element ids a page script binds.
func pageElementIDsForTest(js string) []string {
	const marker = "getElementById('"
	var ids []string
	seen := make(map[string]struct{})
	for offset := 0; ; {
		start := strings.Index(js[offset:], marker)
		if start < 0 {
			break
		}
		start += offset + len(marker)
		end := strings.Index(js[start:], "'")
		if end < 0 {
			break
		}
		id := js[start : start+end]
		if _, ok := seen[id]; !ok && id != "" {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
		offset = start + end
	}
	return ids
}

// pagePayloadExpectation returns the placement field a payload must carry.
func pagePayloadExpectation(t *testing.T, pinned bool) (string, string) {
	t.Helper()
	if pinned {
		return `"dc_id":1`, `"region_id"`
	}
	return `"region_id":1`, `"dc_id"`
}

// orderRaw posts one order body as an admin and returns the recorder, so a body
// produced by another system (here, the page) can be exercised verbatim.
func (s *placementHarness) orderRaw(t *testing.T, admin, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/hosting/gigahost/order", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(),
		&models.SessionData{UserID: admin, Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	s.h.GigahostOrderHandler(w, req)
	return w
}
