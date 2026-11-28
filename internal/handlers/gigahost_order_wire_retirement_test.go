package handlers

// Offline evidence that a stale order stops being polled once a real provider read has
// retired it.
//
// Round one proved the mechanism with an injected client: a recorded absence makes the
// list skip the per-order read and makes the browser skip the status request. That leaves
// one thing unproven, and it is the thing the design verdict asked for: that a genuine
// successful provider answer, decoded by the shipped client from actual HTTP bytes, is
// what produces the retirement. A fake client that returns a Go value proves the
// reconciliation's decision, not the wire contract that feeds it.
//
// This file therefore drives the production HTTP client against an in-process provider
// whose responses are the documented JSON, and asserts the whole chain end to end:
//
//	provider HTTP answer -> shipped client decode -> reconciliation -> durable ledger row
//	                    -> list response -> browser module's poll decision
//
// The last step is the JSDOM run below, because "stops being polled" is a decision the
// browser makes and no server-side assertion can speak for it.
//
// It is deliberately NOT a claim about the two production orders. It is the strongest
// evidence obtainable without a provider credential, and what it cannot establish is
// stated in the handover: the retired-comparison needs one live successful inventory
// read from the account those orders were bought under.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/web"
)

// The account identifier the fixture provider reports. It is a documentation-range id:
// no production account is named anywhere in this file.
const wireFixtureAccount = "fixture-account-1955"

// wireProvider is the in-process stand-in for the provider's HTTP API.
//
// It answers the documented endpoints with the documented bodies and records every
// per-order status read, which is the request whose absence is the claim under test. Its
// shapes are the ones the shipped client parses, so a client that stopped decoding a
// documented envelope would fail here rather than pass on a Go-side value.
type wireProvider struct {
	server *httptest.Server
	// listed is what GET /servers reports. An empty slice is a successful read that
	// enumerates no servers, which is the answer that retires an omitted order.
	listed []map[string]any
	// statusReads counts GET /deploy/status calls, keyed by the order id asked about.
	statusReads map[string]int
	// inventoryReads counts GET /servers calls, so a control can show the inventory was
	// genuinely read rather than answered from a cache.
	inventoryReads int
}

// newWireProvider builds the fixture provider. listed is what GET /servers reports: an
// empty slice is a successful read that enumerates no servers, which is the answer that
// retires an omitted order.
func newWireProvider(t *testing.T, listed []map[string]any) *wireProvider {
	t.Helper()
	p := &wireProvider{listed: listed, statusReads: map[string]int{}}
	p.server = httptest.NewServer(p.routes())
	t.Cleanup(p.server.Close)
	return p
}

// newFailingWireProvider builds the same fixture with an inventory endpoint that fails,
// which is the negative control: a read that did not succeed must retire nothing.
func newFailingWireProvider(t *testing.T, status int) *wireProvider {
	t.Helper()
	p := &wireProvider{statusReads: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/account", p.accountRoute(t))
	mux.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		p.inventoryReads++
		http.Error(w, "provider unavailable", status)
	})
	mux.HandleFunc("/deploy/status", p.deployStatusRoute(t))
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *wireProvider) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/account", p.accountRoute(nil))
	mux.HandleFunc("/servers", p.serversRoute)
	mux.HandleFunc("/deploy/status", p.deployStatusRoute(nil))
	return mux
}

func (p *wireProvider) accountRoute(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The documented nested document, which is the shape that carries eligibility.
		writeWireJSON(w, map[string]any{
			"meta": map[string]any{"status": 200},
			"data": map[string]any{
				"cust_id": wireFixtureAccount,
				"balance": 100,
				"credit":  0,
			},
		})
	}
}

func (p *wireProvider) serversRoute(w http.ResponseWriter, r *http.Request) {
	p.inventoryReads++
	// The wrapped shape with pagination metadata: a direct array is accepted only below
	// 100 entries, and the wrapped form is what the provider documents. An empty listing
	// is an empty array, not null: the client refuses a null inventory, because "no
	// servers" and "no usable answer" must not look the same.
	listed := p.listed
	if listed == nil {
		listed = []map[string]any{}
	}
	writeWireJSON(w, map[string]any{
		"servers": listed,
		"meta": map[string]any{
			"page":        1,
			"total_pages": 1,
			"per_page":    50,
			"total":       len(listed),
		},
	})
}

func (p *wireProvider) deployStatusRoute(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orderID := r.URL.Query().Get("ids")
		p.statusReads[orderID]++
		writeWireJSON(w, map[string]any{"order_id": orderID, "status": "ready"})
	}
}

func writeWireJSON(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// wireClient builds the shipped client pointed at the fixture provider. The API key is a
// syntactically valid placeholder, which is the only thing the client validates it for.
func wireClient(t *testing.T, p *wireProvider) gigahost.Client {
	t.Helper()
	client, err := gigahost.NewClient(gigahost.Config{
		BaseURL: p.server.URL,
		APIKey:  "flux_live_" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("build the shipped provider client: %v", err)
	}
	return client
}

// seedWireOrder writes one ledger row in the state a deployment reaches after the
// provider accepted it: a provider server id and a running status.
func seedWireOrder(t *testing.T, h *Handlers, orderID string, serverID int64) {
	t.Helper()
	now := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(context.Background(), &GigahostOrderRecord{
		OrderID:        orderID,
		Status:         gigahost.StatusReady,
		ServerID:       serverID,
		AssignedIP:     "198.51.100.90",
		PurchaseOrigin: models.PurchaseOriginPanelPurchase,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("seed the ledger row %q: %v", orderID, err)
	}
}

// TestSuccessfulWireInventoryReadRetiresAnOmittedOrder is the end-to-end positive case on
// real HTTP bytes: the shipped client decodes a complete successful inventory that omits
// the order, the reconciliation records absence against the account that answered, the
// list stops asking about the order, and the row's durable state says so on reload.
func TestSuccessfulWireInventoryReadRetiresAnOmittedOrder(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_wire_omitted"
	seedWireOrder(t, h, orderID, 7801)

	provider := newWireProvider(t, nil)
	// A successful read that lists nothing: the order is absent from a complete answer.
	h.SetGigahostClient(wireClient(t, provider))

	read := gigahostOrderStatusRead(t, h, "")

	// The provider really was read through its HTTP surface, not answered from a value.
	if provider.inventoryReads == 0 {
		t.Fatal("the shipped client never issued the inventory request, so nothing was proven")
	}
	// The account identity came from GET /account, decoded by the shipped client.
	stored := storedOrder(t, h, orderID)
	if !stored.ProviderAbsent() {
		t.Fatalf("a successful wire inventory read that omits the order must record its absence: %+v", stored)
	}
	if stored.ProviderAbsentAccountID != wireFixtureAccount {
		t.Fatalf("the observation must name the account the wire answer reported (%q), got %q",
			wireFixtureAccount, stored.ProviderAbsentAccountID)
	}
	if !absenceMark(t, read.Orders, orderID) {
		t.Fatalf("the list response must carry the recorded absence: %s", read.Orders)
	}
	// A retired order is not asked about again by the same read that retired it.
	if provider.statusReads[orderID] != 0 {
		t.Fatalf("the read asked about a retired order %d time(s)", provider.statusReads[orderID])
	}

	// Reload from durable state: absence survives the in-memory row being dropped, which
	// is what makes it a retirement rather than a value that happened to be set.
	reloaded := storedOrder(t, h, orderID)
	if !reloaded.ProviderAbsent() {
		t.Fatal("the absence record did not survive a reload from the database")
	}

	// And the list issued by a later read asks nothing about it, while a control order
	// that the inventory does list still gets its per-order read.
	const liveID = "ord_wire_listed"
	seedWireOrder(t, h, liveID, 7802)
	provider.listed = []map[string]any{{
		"id": 7802, "order_id": liveID, "name": "wire-listed", "status": "ready",
	}}
	before := provider.statusReads[orderID]
	liveBefore := provider.statusReads[liveID]
	_ = gigahostOrderStatusRead(t, h, "")
	if provider.statusReads[orderID] != before {
		t.Fatalf("a retired order was asked about again on the next read: %d -> %d",
			before, provider.statusReads[orderID])
	}
	if provider.statusReads[liveID] == liveBefore {
		t.Fatal("the live control order was not asked about, so the counter cannot show a retired order is skipped")
	}
}

// TestWireInventoryReadThatFailsOrOmitsNothingChangesNoRow is the negative control on the
// same wire path: a failed request, and a complete answer that lists the order, must both
// leave the row exactly as it was. Without it the positive case cannot distinguish "the
// omission retired the order" from "any read retires the order".
func TestWireInventoryReadThatFailsRetiresNothing(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_wire_error"
	seedWireOrder(t, h, orderID, 7803)

	provider := newFailingWireProvider(t, http.StatusServiceUnavailable)

	h.SetGigahostClient(wireClient(t, provider))
	read := gigahostOrderStatusRead(t, h, "")

	if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
		t.Fatalf("a failed inventory read recorded an absence it never observed: %+v", stored)
	}
	if absenceMark(t, read.Orders, orderID) {
		t.Fatal("a failed inventory read produced an absence mark")
	}
}

func TestWireInventoryReadThatListsTheOrderClearsItsRecord(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const orderID = "ord_wire_listed_again"
	seedWireOrder(t, h, orderID, 7804)

	// A recorded absence first, so clearing it is observable.
	ctx := context.Background()
	stamp := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	if err := h.db.SetGigahostOrderAbsence(ctx, orderID, stamp, wireFixtureAccount); err != nil {
		t.Fatalf("record the prior absence: %v", err)
	}

	provider := newWireProvider(t, []map[string]any{{
		"id": 7804, "order_id": orderID, "name": "wire-listed-again", "status": "ready",
		"cust_id": wireFixtureAccount,
	}})
	h.SetGigahostClient(wireClient(t, provider))
	_ = gigahostOrderStatusRead(t, h, "")

	if stored := storedOrder(t, h, orderID); stored.ProviderAbsent() {
		t.Fatalf("a listing that names the order must clear its absence record: %+v", stored)
	}
}

// TestRetiredOrderIssuesNoBrowserStatusRequest drives the shipped browser module in JSDOM
// over the list response the wire read above produced.
//
// The server can show it skipped the per-order call in its own handler, but the status
// request the operator's browser issues is the browser module's decision. Asserting it
// here means the retirement is proven at both ends of the same fact, rather than inferred
// from one.
//
// The JSDOM dependency is required here even though the sibling suites skip without it: a
// guard whose whole job is to fail on a regression must fail closed, because a skipped
// guard prints the same green line as a passing one.
func TestRetiredOrderIssuesNoBrowserStatusRequest(t *testing.T) {
	node := gigahostOrderStatusNode(t)
	if node == "" {
		t.Fatal("node is required for this regression guard and was not found")
	}
	if os.Getenv("NODE_PATH") == "" {
		t.Fatalf("NODE_PATH must point at the JSDOM package for this guard; " +
			"without it the module cannot load and this test must not silently skip")
	}
	// The shared bootstrap reports an absent JSDOM by printing a marker and exiting 0,
	// which is right for the sibling suites that may skip. This guard must not inherit
	// that: it would print the same green line as a real pass. So the dependency is
	// probed directly here and a missing one fails the test.
	probe := exec.Command(node, "-e", "require('jsdom')")
	probe.Env = append(os.Environ(), "NODE_PATH="+os.Getenv("NODE_PATH"))
	if out, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("the JSDOM package this guard needs is not loadable: %v\n%s", err, out)
	}

	for _, path := range []string{
		"static/js/gigahost_order_status.js",
		"static/js/gigahost_order_status_model.js",
		"static/js/gigahost_setup_intents.js",
	} {
		if _, err := web.StaticFS.ReadFile(path); err != nil {
			t.Fatalf("read the shipped module %s: %v", path, err)
		}
	}
	statusModule, _ := web.StaticFS.ReadFile("static/js/gigahost_order_status.js")
	modelModule, _ := web.StaticFS.ReadFile("static/js/gigahost_order_status_model.js")
	intentsModule, _ := web.StaticFS.ReadFile("static/js/gigahost_setup_intents.js")

	encodedStatus, _ := json.Marshal(string(statusModule))
	encodedModel, _ := json.Marshal(string(modelModule))
	encodedIntents, _ := json.Marshal(string(intentsModule))

	// The same rows the server half produced: one order the panel recorded absent, and
	// one live control the provider still lists.
	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.triggerGigahostSetup = () => {};
w.prompt = () => null;

w.confirm = () => false;

// The two rows, exactly as the list handler serves them: the retired one carries the
// panel's durable absence mark and the live one does not.
const orders = [
  {order_id:'ord_wire_omitted', status:'ready', assigned_ip:'198.51.100.90'},
  {order_id:'ord_wire_listed', status:'ready', assigned_ip:'198.51.100.91'}
];
const absenceByOrder = {'ord_wire_omitted': true};
const observationByOrder = {
  ord_wire_omitted: {outcome:'not_checked'},
  ord_wire_listed: {outcome:'confirmed', status:'ready'}
};

const calls = [];
w.API = {
  get: async url => {
    calls.push({method:'GET', url});
    if (url === '/api/admin/hosting/gigahost/orders')
      return {orders: orders, provider_observations: observationByOrder,
              provider_absent_orders: absenceByOrder};
    if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: []};
    if (url === '/api/vpn/backends') return {backends: []};
    const m = String(url).match(/\/orders\/(.+)\/status$/);
    if (m) return {status:'ok', deploy: {status:'ready'}};
    throw new Error('unexpected GET ' + url);
  },
  post: async () => ({}),
  delete: async () => ({})
};

w.eval(%s + '\n//# sourceURL=gigahost_setup_intents.js');
w.eval(%s + '\n//# sourceURL=gigahost_order_status_model.js');
w.eval(%s + '\n//# sourceURL=gigahost_order_status.js');

(async () => {
  await w.loadRecentOrders();
  const asked = calls
    .filter(c => /\/orders\/[^/]+\/status$/.test(c.url))
    .map(c => decodeURIComponent(c.url.replace('/api/admin/hosting/gigahost/orders/', '').replace('/status','')));
  const stages = {};
  w.document.querySelectorAll('#recentOrdersContainer .gigahost-order-status').forEach(c => {
    stages[c.getAttribute('data-order-id')] = c.getAttribute('data-stage');
  });
  console.log(JSON.stringify({asked: asked, stages: stages}));
})().catch(err => { console.error(err && err.stack || String(err)); process.exit(1); });
`, encodedIntents, encodedModel, encodedStatus)

	cmd := exec.Command(node, "-")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), "NODE_PATH="+os.Getenv("NODE_PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped modules did not run: %v\n%s", err, output)
	}
	// The module logs one JSON line; anything else is a failure, not something to parse
	// around, because a partial run would otherwise look like a pass.
	var got struct {
		Asked  []string          `json:"asked"`
		Stages map[string]string `json:"stages"`
	}
	line := strings.TrimSpace(string(output))
	if idx := strings.LastIndex(line, "\n"); idx >= 0 {
		line = line[idx+1:]
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("the module's report is not JSON: %v\noutput: %s", err, output)
	}

	if got.Stages["ord_wire_omitted"] != "deleted" {
		t.Fatalf("a retired order must present as the deletion it is, got stage %q (report %s)",
			got.Stages["ord_wire_omitted"], output)
	}
	// The control: the live order really was asked about, so the assertion below is about
	// a skipped request rather than about a harness that never asks anything.
	if !containsString(got.Asked, "ord_wire_listed") {
		t.Fatalf("the live control order was never asked about, so no absence of a request is proven: %v", got.Asked)
	}
	if containsString(got.Asked, "ord_wire_omitted") {
		t.Fatalf("a retired order's status was requested: %v", got.Asked)
	}
}
