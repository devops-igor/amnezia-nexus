package handlers

// A provider-final failure is an ended order, and a setup-journal failure is not.
//
// The two look identical in the ledger's status column: both read `failed`. They are
// different facts, and the difference is the panel's own onboarding journal - a recorded
// step, or the panel server registration it mirrors. Without it the provider ended
// provisioning before any panel work existed, so there is no deployment to retry onto and
// nothing a status request could describe.
//
// Treating both as recoverable was the defect: a provider-final failure offered Retry on
// the grid and in the history list, and the history kept requesting the order's status.
// Every case here therefore asserts the four surfaces that must agree - the Go grid card,
// the shipped history renderer's stage, its action set, and the number of status requests
// the view actually issued - against a journal-backed control that must keep its Retry.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/web"
)

// statusRequestLog is the view's own record of which order-status URLs it requested. It is
// the observable proof of polling: a stage assertion alone cannot distinguish "not polled"
// from "polled and rendered the same".
const statusRequestLog = `
const statusRequests = [];
w.API = {
  get: async url => {
    const m = url.match(/^\/api\/admin\/hosting\/gigahost\/orders\/(.+)\/status$/);
    if (m) statusRequests.push(decodeURIComponent(m[1]));
    if (url === '/api/admin/hosting/gigahost/orders') return JSON.parse(ordersBody);
    if (url === '/api/admin/hosting/gigahost/setup-intents') return JSON.parse(intentsBody);
    if (url === '/api/vpn/backends') return JSON.parse(backendsBody);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (detailsBody && Object.prototype.hasOwnProperty.call(detailsBody, id)) return JSON.parse(detailsBody[id]);
      if (detailBody && id === orderID) return JSON.parse(detailBody);
    }
    throw new Error('unexpected GET ' + url);
  },
  post: async () => { throw new Error('the status view must not POST'); },
  delete: async () => { throw new Error('the status view must not DELETE'); }
};
`

// runOrderStatusProductionPath renders the shipped history view over the responses the
// real handlers produced and reports the row plus every status URL the view requested.
func runOrderStatusProductionPath(t *testing.T, responses gigahostOrderStatusResponses, orderID string) (deletedDeploymentRender, []string) {
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
	detailModule, err := readShippedStatusDetailModule()
	if err != nil {
		t.Fatalf("read the status detail module: %v", err)
	}
	encoded := func(v any) string {
		blob, _ := json.Marshal(v)
		return string(blob)
	}
	encodedOrders := encoded(responses.Orders)
	encodedDetail := encoded(responses.Detail)
	encodedDetails := encoded(responses.Details)
	encodedIntentsResp := encoded(responses.Intents)
	encodedBackends := encoded(responses.Backends)
	encodedOrderID := encoded(orderID)
	encodedIntents := encoded(string(intentsModule))
	encodedModel := encoded(string(modelModule))
	encodedStatusDetail := encoded(string(detailModule))
	encodedStatus := encoded(string(statusModule))

	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const ordersBody = %s, detailBody = %s, detailsBody = %s, intentsBody = %s, backendsBody = %s, orderID = %s;
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.triggerGigahostSetup = () => {};
w.prompt = () => null;
w.confirm = () => false;
%s
w.eval(%s);
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
    identity: flat(container.querySelector('.gigahost-order-identity')),
    label: (cell && cell.querySelector('.gigahost-order-status-toggle'))
      ? cell.querySelector('.gigahost-order-status-toggle').getAttribute('aria-label')
      : null,
    actions: Array.from(container.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => flat(b)),
    rows: Array.from(container.querySelectorAll('.gigahost-order-row')).map(row => {
      const status = row.querySelector('.gigahost-order-status');
      const toggle = row.querySelector('.gigahost-order-status-toggle');
      return {
        orderId: status ? status.getAttribute('data-order-id') : null,
        stage: status ? status.getAttribute('data-stage') : null,
        identity: flat(row.querySelector('.gigahost-order-identity')),
        label: toggle ? toggle.getAttribute('aria-label') : null,
        actions: Array.from(row.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => flat(b))
      };
    }),
    statusRequests: statusRequests
  };
  process.stdout.write('RENDER_RESULT=' + JSON.stringify(summary) + '\n');
  dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, encodedOrders, encodedDetail, encodedDetails, encodedIntentsResp, encodedBackends, encodedOrderID,
		statusRequestLog, encodedIntents, encodedModel, encodedStatusDetail, encodedStatus)

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped status module failed on the real response: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		t.Fatalf("jsdom is required for this regression and is not available: %s", out)
	}
	marker := "RENDER_RESULT="
	idx := strings.Index(string(out), marker)
	if idx < 0 {
		t.Fatalf("the renderer produced no result marker:\n%s", out)
	}
	line := strings.TrimSpace(strings.SplitN(string(out)[idx+len(marker):], "\n", 2)[0])
	var summary struct {
		deletedDeploymentRender
		StatusRequests []string `json:"statusRequests"`
	}
	if err := json.Unmarshal([]byte(line), &summary); err != nil {
		t.Fatalf("the renderer summary is not JSON: %v %s", err, line)
	}
	return summary.deletedDeploymentRender, summary.StatusRequests
}

// TestProviderFinalFailureIsEndedOnEverySurface is the F1007-02 regression.
//
// The order holds a provider order id, status failed, no step, no panel server and no
// inventory omission - exactly the state a provider produces when provisioning ends
// before the panel does anything. Every surface must present it as over, and the history
// view must not request its status at all.
func TestProviderFinalFailureIsEndedOnEverySurface(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	const orderID = "ord_f1007_02_final"
	now := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: orderID, Status: "failed", PlanID: 1, RegionID: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	// The provider is reachable throughout: nothing here is explained by an outage, and a
	// status request would succeed, so a request that happens is a decision this view made.
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{CustID: existenceAccount}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(_ context.Context, id string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: id, Status: "failed", Error: "provisioning failed"}, nil
		},
	})

	// Surface 1: the Servers grid card.
	card := deploymentCard(t, renderServersPage(t, h), orderID)
	if !badgeWithState(card, "badge-danger", "deleted", "Deleted") {
		t.Fatalf("a provider-final failure must be presented as the ending it is, got card: %s", card)
	}
	if strings.Contains(card, "triggerGigahostSetup") || strings.Contains(card, "server-actions") {
		t.Fatalf("a provider-final failure must offer no control, got card: %s", card)
	}
	if strings.Contains(card, "Not usable yet") {
		t.Fatalf("an ended order must not read as one waiting for setup: %s", card)
	}

	// Surfaces 2-4: the shipped history view - stage, actions, and the requests it issued.
	read := gigahostOrderStatusRead(t, h, orderID)
	read.Details = map[string]string{orderID: read.Detail}
	rendered, requests := runOrderStatusProductionPath(t, read, orderID)

	if len(rendered.Rows) != 1 {
		t.Fatalf("the ended order must still be listed, got %+v", rendered.Rows)
	}
	row := rendered.Rows[0]
	if row.Stage != "deleted" {
		t.Errorf("history stage = %q, want %q for a provider-final failure", row.Stage, "deleted")
	}
	if len(row.Actions) != 0 {
		t.Errorf("a provider-final failure must offer no action, got %v", row.Actions)
	}
	for _, request := range requests {
		if request == orderID {
			t.Errorf("the history view requested the status of an ended order: %v", requests)
		}
	}
}

// TestRecoverableSetupFailureKeepsItsRetry is the paired control. The same status column -
// `failed` - with the panel's own onboarding journal behind it is an install the operator
// ran and may retry, so it must keep both its own stage and its Retry action.
//
// The fixture is chosen to make the difference visible: without this control, a
// correction that simply treated every `failed` row as ended would also pass the test
// above.
func TestRecoverableSetupFailureKeepsItsRetry(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	const orderID = "ord_f1007_02_journal"
	now := time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: orderID, Status: "failed", PlanID: 1, RegionID: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	// The onboarding journal: an install this panel ran, recorded its step, and failed.
	// No panel server id, so this row is still a deployment card rather than a registered
	// server card.
	if err := h.updateDeployOrderStatus(ctx, orderID, DeployStatusFailed, DeployStatusInstallingProtocol,
		"install of awg failed", 0, 0, "198.51.100.44"); err != nil {
		t.Fatalf("write the onboarding journal: %v", err)
	}
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{CustID: existenceAccount}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(_ context.Context, id string) (*gigahost.DeployStatusResponse, error) {
			return &gigahost.DeployStatusResponse{OrderID: id, Status: gigahost.StatusReady, AssignedIP: "198.51.100.44"}, nil
		},
	})

	card := deploymentCard(t, renderServersPage(t, h), orderID)
	if !badgeWithState(card, "badge-danger", "failed", "Failed") {
		t.Fatalf("a journal-backed failure keeps its own state, got card: %s", card)
	}
	if !strings.Contains(card, "triggerGigahostSetup('"+orderID+"')") {
		t.Fatalf("a recoverable setup failure must still offer Retry, got card: %s", card)
	}

	read := gigahostOrderStatusRead(t, h, orderID)
	read.Details = map[string]string{orderID: read.Detail}
	rendered, _ := runOrderStatusProductionPath(t, read, orderID)
	if len(rendered.Rows) != 1 {
		t.Fatalf("the recoverable failure must still be listed, got %+v", rendered.Rows)
	}
	row := rendered.Rows[0]
	// The provider axis is presented as unknown rather than inheriting the install outcome's
	// name - that is the pre-existing rule for a journal-only failure, and it is what keeps a
	// setup failure from wearing the provider's vocabulary. What this correction must not
	// change is the action: the operator's Retry survives.
	if row.Stage != "unknown" {
		t.Errorf("history stage = %q, want %q for a journal-backed failure", row.Stage, "unknown")
	}
	if len(row.Actions) == 0 {
		t.Errorf("a recoverable setup failure lost its Retry action: %+v", row)
	}
}

// TestProviderFinalFailureIsNotPolledEvenWhenTheDetailReadFails pins the second half of
// the defect against a failing detail read.
//
// The polling decision is taken before any per-order request, from the list row alone, so
// it must not depend on the deploy DTO answering. Here that read fails for every order,
// which is the shape that used to leave the row classified as actionable and re-requested.
func TestProviderFinalFailureIsNotPolledEvenWhenTheDetailReadFails(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	const orderID = "ord_f1007_02_no_detail"
	now := time.Date(2026, 11, 28, 9, 30, 0, 0, time.UTC)
	insertServersPageOrder(t, db, models.GigahostOrder{
		OrderID: orderID, Status: "failed", PlanID: 1, RegionID: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	h.SetGigahostClient(&mockGigahostClient{
		getAccountFn: func(context.Context) (*gigahost.AccountInfo, error) {
			return &gigahost.AccountInfo{CustID: existenceAccount}, nil
		},
		getServersFn: func(context.Context) ([]gigahost.ServerInfo, error) { return nil, nil },
		getDeployStatusFn: func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
			return nil, gigahost.ErrNotFound
		},
	})

	read := gigahostOrderStatusRead(t, h, "")
	if read.Detail != "" || len(read.Details) != 0 {
		t.Fatalf("this fixture supplies no detail body: %+v", read)
	}
	rendered, requests := runOrderStatusProductionPath(t, read, "")
	for _, request := range requests {
		if request == orderID {
			t.Errorf("an ended order's status was requested although no detail read could answer: %v", requests)
		}
	}
	if len(rendered.Rows) != 1 || rendered.Rows[0].Stage != "deleted" || len(rendered.Rows[0].Actions) != 0 {
		t.Fatalf("a provider-final failure must read as ended with no action: %+v", rendered.Rows)
	}
}
