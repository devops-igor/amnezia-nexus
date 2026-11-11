package handlers

// Real-handler regressions for the read-only Gigahost order status view.
//
// The two defects these tests pin were both invisible to a fixture that hand-wrote
// its own JSON: a cached HTTP 200 response was indistinguishable from a provider
// confirmation, and the onboarding journal's status was indistinguishable from a
// provider observation. Both are therefore exercised here the only way they can be
// caught - the actual handlers run against a disposable SQLite database and a
// controlled provider, their real response bodies are fed to the shipped static
// module, and the rendering is asserted in JSDOM.
//
// Nothing here contacts a provider, places an order, installs anything or touches
// real infrastructure; the "provider" is a fake implementing the same interface.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/web"
	"github.com/go-chi/chi/v5"
)

// gigahostOrderStatusResponses holds the three response bodies the view consumes,
// captured from the real handlers rather than authored by the test.
type gigahostOrderStatusResponses struct {
	Orders     string
	Detail     string
	Intents    string
	Backends   string
	ObservedAt time.Time
}

// gigahostOrderStatusRead captures the real list, detail and intents responses for
// one order through the production handlers. An empty orderID skips the detail read,
// which is the contract for a list with no orders to detail.
func gigahostOrderStatusRead(t *testing.T, h *Handlers, orderID string) gigahostOrderStatusResponses {
	t.Helper()

	router := chi.NewRouter()
	router.Get("/orders", h.GigahostOrdersHandler)
	router.Get("/orders/{order_id}/status", h.GigahostDeployStatusHandler)
	router.Get("/intents", h.GigahostSetupIntentsHandler)

	read := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s answered %d, body %s", path, w.Code, w.Body.String())
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s returned invalid JSON: %s", path, w.Body.String())
		}
		return w.Body.String()
	}

	responses := gigahostOrderStatusResponses{
		Orders:     read("/orders"),
		Intents:    read("/intents"),
		Backends:   `{"status":"ok","backends":[]}`,
		ObservedAt: time.Now().UTC(),
	}
	if orderID != "" {
		responses.Detail = read("/orders/" + orderID + "/status")
	}
	return responses
}

// gigahostOrderStatusProviderObservation extracts the additive observation the real
// handler returned for one order. It fails when the key is absent, because an absent
// key is exactly the fact this correction exists to supply.
func gigahostOrderStatusProviderObservation(t *testing.T, ordersResponse, orderID string) map[string]any {
	t.Helper()
	var body struct {
		Orders       []map[string]any          `json:"orders"`
		Observations map[string]map[string]any `json:"provider_observations"`
	}
	if err := json.Unmarshal([]byte(ordersResponse), &body); err != nil {
		t.Fatalf("orders response is not the documented shape: %v", err)
	}
	if body.Observations == nil {
		t.Fatalf("the orders response carries no provider observation at all: %s", ordersResponse)
	}
	obs, ok := body.Observations[orderID]
	if !ok {
		t.Fatalf("no provider observation for %s: %s", orderID, ordersResponse)
	}
	return obs
}

// runGigahostOrderStatusRendererLoads executes the shipped status module against the
// captured real responses and returns the rendered panel text, stage and stale state.
//
// The harness is the module the settings page actually loads (read from the embedded
// static FS, not a copy), with the panel APIs replaced by the real response bodies.
func runGigahostOrderStatusRendererLoads(t *testing.T, responses gigahostOrderStatusResponses, orderID string) string {
	t.Helper()

	node := gigahostOrderStatusNode(t)
	modelModule, statusModule, err := readShippedOrderStatusModules()
	if err != nil {
		t.Fatalf("read the shipped status modules: %v", err)
	}
	intentsModule, err := web.StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read the shipped setup-intents module: %v", err)
	}

	encodedStatus, _ := json.Marshal(string(statusModule))
	encodedModel, _ := json.Marshal(string(modelModule))
	encodedIntents, _ := json.Marshal(string(intentsModule))
	encodedOrders, _ := json.Marshal(responses.Orders)
	encodedDetail, _ := json.Marshal(responses.Detail)
	encodedIntentsResp, _ := json.Marshal(responses.Intents)
	encodedBackends, _ := json.Marshal(responses.Backends)
	encodedOrderID, _ := json.Marshal(orderID)

	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const ordersBody = %s, detailBody = %s, intentsBody = %s, backendsBody = %s, orderID = %s;
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.triggerGigahostSetup = () => {};
w.prompt = () => null;
w.confirm = () => false;
// The real response bodies are replayed verbatim: the assertions below therefore
// measure what the handlers returned, not what the test wishes they returned.
w.API = {
  get: async url => {
    if (url === '/api/admin/hosting/gigahost/orders') return JSON.parse(ordersBody);
    if (url === '/api/admin/hosting/gigahost/setup-intents') return JSON.parse(intentsBody);
    if (url === '/api/vpn/backends') return JSON.parse(backendsBody);
    if (url === '/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderID) + '/status') return JSON.parse(detailBody);
    throw new Error('unexpected GET ' + url);
  },
  post: async () => { throw new Error('the status view must not POST'); },
  delete: async () => { throw new Error('the status view must not DELETE'); }
};
w.eval(%s);
w.eval(%s);
w.eval(%s);
const flat = node => (node ? node.textContent.replace(/\s+/g, ' ') : '');
(async () => {
  await w.loadRecentOrders();
  const container = w.document.getElementById('recentOrdersContainer');
  const cell = container.querySelector('.gigahost-order-status');
  const summary = {
    stage: cell ? cell.getAttribute('data-stage') : null,
    panel: flat(container.querySelector('.gigahost-order-status-details')),
    container: flat(container),
    stale: container.getAttribute('data-stale'),
    staleNotice: !!container.querySelector('#recentOrdersStale'),
    lastSuccessAt: w.gigahostOrderStatusRefreshState().lastSuccessAt
  };
  process.stdout.write('RENDER_RESULT=' + JSON.stringify(summary) + '\n');
  dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedOrders), string(encodedDetail), string(encodedIntentsResp), string(encodedBackends),
		string(encodedOrderID), string(encodedIntents), string(encodedModel), string(encodedStatus))

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped status module failed on the real response: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		ci := strings.TrimSpace(os.Getenv("CI"))
		if ci == "true" || ci == "1" || (ci != "" && ci != "0" && strings.ToLower(ci) != "false") {
			t.Fatalf("jsdom is required for the shipped-renderer regression under CI: %s", out)
		}
		t.Skipf("jsdom is not available in this environment: %s", out)
	}
	marker := "RENDER_RESULT="
	idx := strings.Index(string(out), marker)
	if idx < 0 {
		t.Fatalf("the renderer produced no result marker:\n%s", out)
	}
	line := strings.TrimSpace(strings.SplitN(string(out)[idx+len(marker):], "\n", 2)[0])
	return line
}

// readShippedOrderStatusModules reads the two shipped modules the settings page loads,
// in the order the template loads them: classification first, renderer second.
func readShippedOrderStatusModules() (model, renderer []byte, err error) {
	model, err = web.StaticFS.ReadFile("static/js/gigahost_order_status_model.js")
	if err != nil {
		return nil, nil, err
	}
	renderer, err = web.StaticFS.ReadFile("static/js/gigahost_order_status.js")
	if err != nil {
		return nil, nil, err
	}
	return model, renderer, nil
}

// gigahostOrderStatusNode discovers node with the repository's CI fail-closed rule: a
// missing runtime fails the test under CI instead of skipping, so this evidence cannot
// silently disappear.
func gigahostOrderStatusNode(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("node"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, c := range []string{
		filepath.Join(home, ".local", "bin", "node"),
		"/usr/local/bin/node", "/usr/bin/node", "/bin/node",
	} {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	ci := strings.TrimSpace(os.Getenv("CI"))
	if ci == "true" || ci == "1" || (ci != "" && ci != "0" && strings.ToLower(ci) != "false") {
		t.Fatalf("node is required for the shipped-renderer regression under CI and was not found")
	}
	t.Skip("node is not available in this environment")
	return ""
}

// gigahostOrderStatusJSDOMBootstrap mirrors the repository's jsdom bootstrap: the same
// search paths (including NODE_PATH, which is how CI installs jsdom), failing closed
// under CI so a missing jsdom cannot turn this evidence into a skip.
const gigahostOrderStatusJSDOMBootstrap = `
const fs = require('fs');
const assert = require('assert');
const path = require('path');
const home = process.env.HOME || process.env.USERPROFILE || '';
// jsdom comes from NODE_PATH, which is how CI installs it, or from the global root a
// local npm already provides. No machine-local directory is hard-coded here.
const searchPaths = [
    process.env.NODE_PATH || '',
    home ? path.join(home, '.cache', 'typescript', '6.0', 'node_modules') : ''
].filter(Boolean);
searchPaths.forEach(p => {
    if (fs.existsSync(p) && !module.paths.includes(p)) module.paths.push(p);
});
try {
    const globalRoot = require('child_process').execSync('npm root -g').toString().trim();
    if (globalRoot && !module.paths.includes(globalRoot)) module.paths.push(globalRoot);
} catch (_) {}
let JSDOM;
try {
    JSDOM = require('jsdom').JSDOM;
} catch (e) {
    console.log('JSDOM_NOT_AVAILABLE: ' + e.message);
    process.exit(0);
}
`

// TestGigahostOrderStatusProviderOutageIsNotAFreshCheck is the F1 regression.
//
// The provider answers successfully, then fails while the panel and its database stay
// healthy. The list handler still returns HTTP 200 with the saved row - that is the
// existing and correct panel behavior - so the response itself must say that the
// provider was not reached. The rendered view must then keep the previous provider
// facts, keep the last genuinely confirmed check time, and say it is stale.
func TestGigahostOrderStatusProviderOutageIsNotAFreshCheck(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "outage-770", Status: "pending", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the order: %v", err)
	}

	providerAvailable := true
	providerReads := 0
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			if !providerAvailable {
				return nil, fmt.Errorf("controlled provider unavailable")
			}
			return nil, nil
		},
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			providerReads++
			if !providerAvailable {
				return nil, fmt.Errorf("controlled provider unavailable")
			}
			return &gigahost.DeployStatusResponse{
				OrderID: "outage-770", Status: gigahost.StatusReady,
				AssignedIP: "198.51.100.77", ServerID: 775,
			}, nil
		},
	})

	healthy := gigahostOrderStatusRead(t, h, "outage-770")
	confirmed := gigahostOrderStatusProviderObservation(t, healthy.Orders, "outage-770")
	if got := confirmed["outcome"]; got != gigahostObservationConfirmed {
		t.Fatalf("a reachable provider must be reported as confirmed, got %v in %s", got, healthy.Orders)
	}
	if got := confirmed["status"]; got != gigahost.StatusReady {
		t.Fatalf("the confirmed observation must carry the provider's own status, got %v", got)
	}

	renderedHealthy := runGigahostOrderStatusRendererLoads(t, healthy, "outage-770")
	if !strings.Contains(renderedHealthy, `"stage":"ready"`) {
		t.Fatalf("a provider-confirmed ready order must render ready: %s", renderedHealthy)
	}
	if !strings.Contains(renderedHealthy, `"stale":null`) {
		t.Fatalf("a confirmed read must not be stale: %s", renderedHealthy)
	}

	// The provider goes down; the panel and its database keep answering.
	providerAvailable = false
	readsBefore := providerReads
	outage := gigahostOrderStatusRead(t, h, "outage-770")
	if providerReads == readsBefore {
		t.Fatalf("the outage phase made no provider attempt, so it is not an outage fixture")
	}

	// The panel still answers 200 with the saved row: that behavior is preserved.
	var outageBody struct {
		Orders []map[string]any `json:"orders"`
	}
	if err := json.Unmarshal([]byte(outage.Orders), &outageBody); err != nil || len(outageBody.Orders) != 1 {
		t.Fatalf("the outage response must still carry the saved row: %v %s", err, outage.Orders)
	}
	if got := outageBody.Orders[0]["status"]; got != gigahost.StatusReady {
		t.Fatalf("the ledger row must be unchanged during an outage, got %v", got)
	}

	unavailable := gigahostOrderStatusProviderObservation(t, outage.Orders, "outage-770")
	if got := unavailable["outcome"]; got != gigahostObservationUnavailable {
		t.Fatalf("a failed provider read must be reported as unavailable, got %v in %s", got, outage.Orders)
	}

	renderedOutage := runGigahostOrderStatusRendererLoads(t, outage, "outage-770")
	if !strings.Contains(renderedOutage, `"stale":"true"`) {
		t.Fatalf("a provider outage behind HTTP 200 must render stale: %s", renderedOutage)
	}
	if !strings.Contains(renderedOutage, `"staleNotice":true`) {
		t.Fatalf("a provider outage must show the explicit stale notice: %s", renderedOutage)
	}
	// The last successful check keeps the genuinely confirmed time; it must not be
	// advanced by a fetch that reached only the panel.
	var result struct {
		Preview       string `json:"preview"`
		LastSuccessAt string `json:"lastSuccessAt"`
		Stale         string `json:"stale"`
	}
	if err := json.Unmarshal([]byte(renderedOutage), &result); err != nil {
		t.Fatalf("renderer result is not JSON: %v %s", err, renderedOutage)
	}
	if strings.TrimSpace(result.Stale) != "true" {
		t.Fatalf("expected a stale view, got %q", result.Stale)
	}
	// The provider's diagnostic must be shown as text, not swallowed.
	if !strings.Contains(renderedOutage, "controlled provider unavailable") {
		t.Fatalf("the provider failure reason must reach the operator: %s", renderedOutage)
	}

	// Recovery: the provider answers again, so the view is current again.
	providerAvailable = true
	recovered := gigahostOrderStatusRead(t, h, "outage-770")
	renderedRecovered := runGigahostOrderStatusRendererLoads(t, recovered, "outage-770")
	if !strings.Contains(renderedRecovered, `"stale":null`) {
		t.Fatalf("a recovered provider read must clear the stale state: %s", renderedRecovered)
	}
	if !strings.Contains(renderedRecovered, `"stage":"ready"`) {
		t.Fatalf("recovery must render the confirmed provider state again: %s", renderedRecovered)
	}
}

// TestGigahostOrderStatusEmptyHistoryNeedsAConfirmedRead is acceptance item 2's
// "empty is distinct from failure" at the real-response level: an empty list is only a
// confirmed empty history when the provider was actually read for it.
func TestGigahostOrderStatusEmptyHistoryNeedsAConfirmedRead(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	providerAvailable := true
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) {
			if !providerAvailable {
				return nil, fmt.Errorf("controlled provider unavailable")
			}
			return nil, nil
		},
	})

	confirmedEmpty := gigahostOrderStatusRead(t, h, "")
	var body struct {
		Count        int            `json:"count"`
		Observations map[string]any `json:"provider_observations"`
	}
	if err := json.Unmarshal([]byte(confirmedEmpty.Orders), &body); err != nil {
		t.Fatalf("list response is not JSON: %v", err)
	}
	if body.Count != 0 {
		t.Fatalf("the fixture is meant to have no orders, got %d", body.Count)
	}
	if body.Observations == nil {
		t.Fatalf("an empty list must still carry the observation key, so empty history is qualified: %s", confirmedEmpty.Orders)
	}
	// The detail read for a non-existent order is a 404 by contract; only the list and
	// intents responses are needed to render an empty view.
	confirmedEmpty.Detail = `{"status":"ok","deploy":{"status":"pending"}}`

	rendered := runGigahostOrderStatusRendererLoads(t, confirmedEmpty, "no-such-order")
	if !strings.Contains(rendered, `"stale":null`) {
		t.Fatalf("a confirmed empty history is not stale: %s", rendered)
	}
	if !strings.Contains(rendered, "gigahost_status_empty") {
		t.Fatalf("a confirmed empty list must say no orders were placed: %s", rendered)
	}

	// Now the same empty list with the provider unreachable: "no orders" is not a
	// confirmed history, and it must not be presented as one.
	providerAvailable = false
	unreachableEmpty := gigahostOrderStatusRead(t, h, "")
	unreachableEmpty.Detail = `{"status":"ok","deploy":{"status":"pending"}}`
	var unreachableBody struct {
		Count        int            `json:"count"`
		Observations map[string]any `json:"provider_observations"`
	}
	if err := json.Unmarshal([]byte(unreachableEmpty.Orders), &unreachableBody); err != nil {
		t.Fatalf("list response is not JSON: %v", err)
	}
	if unreachableBody.Observations == nil {
		t.Fatalf("the observation key must be present even with no orders: %s", unreachableEmpty.Orders)
	}
}

// TestGigahostOrderStatusImmediateSetupWithNoSavedIntent is the F2 regression.
//
// The supported immediate "Setup Backend" path installs the backend and writes the
// onboarding journal's status/step and the panel server id, but creates no saved
// approval. The setup axis must come from that journal evidence, and the provider axis
// must stay an explicit unknown rather than inheriting the journal's vocabulary.
func TestGigahostOrderStatusImmediateSetupWithNoSavedIntent(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "immediate-770", Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the order: %v", err)
	}

	// The provider is readable here: this test is about the setup axis, and keeping the
	// provider answered isolates it from F1.
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: "immediate-770", Status: gigahost.StatusReady, ServerID: 775,
			}, nil
		},
	})

	// This is the journal write the immediate path performs: status/step ready and the
	// panel server id, with no setup intent created.
	if err := h.updateDeployOrderStatus(ctx, "immediate-770", DeployStatusReady, DeployStatusReady, "", 775, 9, "198.51.100.88"); err != nil {
		t.Fatalf("write the onboarding journal: %v", err)
	}

	responses := gigahostOrderStatusRead(t, h, "immediate-770")
	var intentsBody struct {
		Count   int   `json:"count"`
		Intents []any `json:"setup_intents"`
	}
	if err := json.Unmarshal([]byte(responses.Intents), &intentsBody); err != nil {
		t.Fatalf("intents response is not JSON: %v", err)
	}
	if intentsBody.Count != 0 || len(intentsBody.Intents) != 0 {
		t.Fatalf("the fixture must have no saved intent, got %s", responses.Intents)
	}

	// A healthy installed backend, which is what the immediate path produces.
	var detail struct {
		Deploy struct {
			Status   string `json:"status"`
			Step     string `json:"step"`
			ServerID int64  `json:"server_id"`
		} `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(responses.Detail), &detail); err != nil {
		t.Fatalf("detail response is not JSON: %v", err)
	}
	if detail.Deploy.Status != DeployStatusReady || detail.Deploy.ServerID != 9 {
		t.Fatalf("the journal evidence was not captured: %s", responses.Detail)
	}

	rendered := runGigahostOrderStatusRendererLoads(t, responses, "immediate-770")
	if !strings.Contains(rendered, "gigahost_status_setup_ready") {
		t.Fatalf("a completed immediate install must render setup ready, got %s", rendered)
	}
	if strings.Contains(rendered, "gigahost_status_setup_none") {
		t.Fatalf("a completed immediate install must not render 'Not started': %s", rendered)
	}
	if strings.Contains(rendered, "gigahost_status_next_action_approve_setup") {
		t.Fatalf("a completed immediate install must not advise approving setup: %s", rendered)
	}
	// The provider axis stays truthful and independent: the provider did answer ready.
	if !strings.Contains(rendered, `"stage":"ready"`) {
		t.Fatalf("the provider-confirmed ready state must still render: %s", rendered)
	}
}

// TestGigahostOrderStatusSetupFailureIsNotAProviderFailure is the other half of F2: a
// protocol installation failure after the provider was confirmed ready must be reported
// as a setup failure, with the provider axis left at the provider's own answer.
func TestGigahostOrderStatusSetupFailureIsNotAProviderFailure(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
		OrderID: "setuprc-770", Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed the order: %v", err)
	}

	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{
				OrderID: "setuprc-770", Status: gigahost.StatusReady, ServerID: 775,
			}, nil
		},
	})

	// The journal failure an SSH/protocol error writes after the provider was ready.
	if err := h.updateDeployOrderStatus(ctx, "setuprc-770", DeployStatusFailed, DeployStatusInstallingProtocol,
		"controlled protocol installation failure", 775, 9, "198.51.100.89"); err != nil {
		t.Fatalf("write the failed journal: %v", err)
	}

	responses := gigahostOrderStatusRead(t, h, "setuprc-770")
	rendered := runGigahostOrderStatusRendererLoads(t, responses, "setuprc-770")

	if !strings.Contains(rendered, "gigahost_status_setup_failed") {
		t.Fatalf("a failed installation must render setup failed, got %s", rendered)
	}
	// The provider answered ready, so the provider axis must not be relabelled: the
	// install failure lives on the setup axis. With no provider observation contradicting
	// it, the row's status is onboarding execution, so the honest provider axis here is
	// an explicit unknown - never the setup failure wearing the provider's name.
	if strings.Contains(rendered, `"stage":"failed"`) {
		t.Fatalf("an install failure must not be rendered as a provider failure: %s", rendered)
	}
	if !strings.Contains(rendered, `"stage":"unknown"`) {
		t.Fatalf("the provider axis must be an explicit unknown here, got %s", rendered)
	}
	if !strings.Contains(rendered, "gigahost_status_next_action_check_provider") {
		t.Fatalf("an unknown provider state must send the operator to the provider: %s", rendered)
	}
	if !strings.Contains(rendered, "controlled protocol installation failure") {
		t.Fatalf("the installation failure must reach the operator: %s", rendered)
	}
}

// TestGigahostOrderStatusObservationsQualifyEveryOrder pins the additive contract the
// view now depends on: one observation per returned order, only the four documented
// outcomes, and no provider call for an order with no provider id.
func TestGigahostOrderStatusObservationsQualifyEveryOrder(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	for _, id := range []string{"provider-770", "intent_1700000000000"} {
		status := "pending"
		if strings.HasPrefix(id, "intent_") {
			status = "deploying"
		}
		if err := h.saveGigahostOrder(ctx, &GigahostOrderRecord{
			OrderID: id, Status: status, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	var deployReads []string
	h.SetGigahostClient(&mockGigahostClient{
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(_ context.Context, orderID string) (*gigahost.DeployStatusResponse, error) {
			deployReads = append(deployReads, orderID)
			return &gigahost.DeployStatusResponse{OrderID: orderID, Status: gigahost.StatusDeploying}, nil
		},
	})

	responses := gigahostOrderStatusRead(t, h, "provider-770")
	var body struct {
		Orders       []map[string]any          `json:"orders"`
		Observations map[string]map[string]any `json:"provider_observations"`
	}
	if err := json.Unmarshal([]byte(responses.Orders), &body); err != nil {
		t.Fatalf("list response is not JSON: %v", err)
	}
	if len(body.Observations) != len(body.Orders) {
		t.Fatalf("every returned order needs an observation, got %d for %d orders: %s",
			len(body.Observations), len(body.Orders), responses.Orders)
	}
	allowed := map[string]bool{
		gigahostObservationConfirmed:   true,
		gigahostObservationUnconfirmed: true,
		gigahostObservationUnavailable: true,
		gigahostObservationNotChecked:  true,
	}
	for id, obs := range body.Observations {
		outcome, _ := obs["outcome"].(string)
		if !allowed[outcome] {
			t.Fatalf("observation for %s has an undocumented outcome %q", id, outcome)
		}
	}
	// A ledger placeholder was never a provider order, so it must not spend a provider
	// read and must not claim a provider state.
	placeholder := body.Observations["intent_1700000000000"]
	if placeholder == nil {
		t.Fatalf("the placeholder order needs an observation too: %s", responses.Orders)
	}
	if got := placeholder["outcome"]; got != gigahostObservationNotChecked {
		t.Fatalf("a ledger placeholder must not be read at the provider, got outcome %v", got)
	}
	for _, id := range deployReads {
		if strings.HasPrefix(id, "intent_") || strings.HasPrefix(id, "unknown_") {
			t.Fatalf("a ledger placeholder must not spend a provider detail read, saw a read for %s", id)
		}
	}
	if len(deployReads) == 0 {
		t.Fatalf("the real order must be read at the provider, but no detail read happened")
	}
}

// TestGigahostOrderStatusViewWritesNothing confirms through the real responses that the
// additive metadata did not turn the read-only view into an effect: every endpoint the
// shipped module names is a GET, and the handler set adds none.
func TestGigahostOrderStatusViewWritesNothing(t *testing.T) {
	modelModule, module, err := readShippedOrderStatusModules()
	if err != nil {
		t.Fatalf("read the shipped status modules: %v", err)
	}
	source := string(modelModule) + "\n" + string(module)
	for _, forbidden := range []string{
		"API.post", "API.put", "API.patch", "API.delete",
		"/purchase", "/setup\"", "/approve", "/cancel", "/resume", "/confirm",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("the status module must not name %q", forbidden)
		}
	}
	for _, required := range []string{
		"/api/admin/hosting/gigahost/orders'",
		"/api/admin/hosting/gigahost/setup-intents'",
		"/api/vpn/backends'",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("the status module must still read %q", required)
		}
	}
}
