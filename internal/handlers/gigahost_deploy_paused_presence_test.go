package handlers

// A saved setup that registered a server and paused before admission journals the
// registered identity on the *setup intent*; the order ledger still carries 0,
// because the ledger's mirror is written only when the install completes. The
// presence fact therefore has to be resolved from the durable registered identity
// rather than from the ledger's copy, and both surfaces that offer to contact that
// server have to read it: the Recent Deployments row and the saved-jobs list.
//
// The fixture is a real paused job - a real approval, a real tracker pass, a real
// install pass that fails enablement on its own error path, and a real registration.
// What is modelled is the operator's view, not the install mechanics: nothing here
// contacts a provider or a host, and the absence mark is the same durable write the
// provider inventory performs.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// savedSetupView is the part of the shipped saved-jobs renderer these tests read.
type savedSetupView struct {
	Text    string   `json:"text"`
	Buttons []string `json:"buttons"`
	Badges  []string `json:"badges"`
}

// runGigahostSetupIntentsRendererLoads executes the shipped saved-jobs module against
// a real list response and returns what it rendered.
//
// The module is the one the settings page loads (read from the embedded static FS,
// not a copy) and the response is the one the handler produced, so a field the
// handler does not send cannot be invented here.
func runGigahostSetupIntentsRendererLoads(t *testing.T, intentsResponse string) savedSetupView {
	t.Helper()

	node := gigahostOrderStatusNode(t)
	module, err := web.StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read the shipped setup-intents module: %v", err)
	}
	encodedModule, _ := json.Marshal(string(module))
	encodedBody, _ := json.Marshal(intentsResponse)

	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const intentsBody = %s;
const dom = new JSDOM('<div id="setupIntentsContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.confirm = () => false;
// Rendering is read-only: any write attempt is a failure, not a side effect.
w.API = {
  get: async () => JSON.parse(intentsBody),
  post: async () => { throw new Error('rendering must not POST'); },
  delete: async () => { throw new Error('rendering must not DELETE'); }
};
w.eval(%s);
const flat = node => (node ? node.textContent.replace(/\s+/g, ' ') : '');
(async () => {
  await w.loadSetupIntents();
  const container = w.document.getElementById('setupIntentsContainer');
  process.stdout.write('INTENTS_RESULT=' + JSON.stringify({
    text: flat(container),
    buttons: Array.from(container.querySelectorAll('button')).map(flat),
    badges: Array.from(container.querySelectorAll('.badge')).map(flat)
  }) + '\n');
  dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedBody), string(encodedModule))

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped saved-jobs module failed on the real response: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		t.Fatalf("jsdom is required for this regression and is not available: %s", out)
	}
	const marker = "INTENTS_RESULT="
	idx := strings.Index(string(out), marker)
	if idx < 0 {
		t.Fatalf("the saved-jobs renderer produced no result marker:\n%s", out)
	}
	line := strings.TrimSpace(strings.SplitN(string(out)[idx+len(marker):], "\n", 2)[0])
	var view savedSetupView
	if err := json.Unmarshal([]byte(line), &view); err != nil {
		t.Fatalf("the saved-jobs renderer summary is not JSON: %v %s", err, line)
	}
	return view
}

// savedJobsPresenceWatch is one run of the shipped saved-jobs module against a
// sequence of list responses, with the view's own timer under test.
type savedJobsPresenceWatch struct {
	// First is what the list showed after the first render.
	First savedSetupView `json:"first"`
	// After is what the same DOM showed once the view's own refresh had run.
	After savedSetupView `json:"after"`
	// ReadsBefore, ReadsAfter and ReadsSettled count the list reads at three points:
	// after the first render, after one refresh interval, and after three of them.
	// They are the observable proof that the view re-read at all, and that it stopped.
	ReadsBefore  int `json:"readsBefore"`
	ReadsAfter   int `json:"readsAfter"`
	ReadsSettled int `json:"readsSettled"`
}

// runSavedJobsPresenceWatch renders the shipped saved-jobs module, lets it render the
// first response, then advances its own timer and reports what the same DOM shows.
//
// The interval is read from the module rather than restated here, so the check fails
// loudly if the view stops scheduling a refresh instead of quietly ticking for a
// duration nobody owns.
func runSavedJobsPresenceWatch(t *testing.T, responses []string) savedJobsPresenceWatch {
	t.Helper()

	node := gigahostOrderStatusNode(t)
	module, err := web.StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read the shipped setup-intents module: %v", err)
	}
	interval := regexp.MustCompile(`const SETUP_INTENTS_PRESENCE_REFRESH_MS = (\d+);`).
		FindSubmatch(module)
	if interval == nil {
		t.Fatalf("the saved-jobs module no longer states the interval it re-observes a " +
			"paused job at, so this check cannot advance the view's own timer")
	}

	encodedModule, _ := json.Marshal(string(module))
	encodedResponses, _ := json.Marshal(responses)

	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const responses = %s;
const interval = %s;
let index = 0;
let reads = 0;
const dom = new JSDOM('<div id="setupIntentsContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.confirm = () => false;
// Rendering is read-only: any write attempt is a failure, not a side effect.
w.API = {
  get: async () => {
    reads += 1;
    const body = responses[Math.min(index, responses.length - 1)];
    index += 1;
    return JSON.parse(body);
  },
  post: async () => { throw new Error('rendering must not POST'); },
  delete: async () => { throw new Error('rendering must not DELETE'); }
};

class FakeClock {
  constructor() { this.now = 0; this.timers = []; this.nextId = 1; }
  setTimeout(fn, delay, ...args) { const id = this.nextId++; this.timers.push({id, fn, time: this.now + Math.max(0, delay||0), args}); return id; }
  clearTimeout(id) { this.timers = this.timers.filter(t => t.id !== id); }
  setInterval(fn, delay, ...args) { return this.setTimeout(fn, delay, ...args); }
  clearInterval(id) { this.clearTimeout(id); }
  async tick(ms) {
    const target = this.now + ms;
    for (let guard = 0; guard < 100; guard++) {
      await flush();
      const due = this.timers.filter(t => t.time <= target).sort((a,b)=>a.time-b.time||a.id-b.id);
      if (!due.length) break;
      const next = due[0];
      this.now = next.time;
      this.clearTimeout(next.id);
      next.fn(...next.args);
    }
    this.now = target;
    await flush();
  }
}
const clock = new FakeClock();
['setTimeout','clearTimeout','setInterval','clearInterval'].forEach(m => { w[m] = clock[m].bind(clock); });
const flush = async () => { for (let i = 0; i < 12; i++) await new Promise(r => setImmediate(r)); };

w.eval(%s);

const flat = node => (node ? node.textContent.replace(/\s+/g, ' ') : '');
const snap = () => {
  const container = w.document.getElementById('setupIntentsContainer');
  return {
    text: flat(container),
    buttons: Array.from(container.querySelectorAll('button')).map(flat),
    badges: Array.from(container.querySelectorAll('.badge')).map(flat)
  };
};

(async () => {
  await w.loadSetupIntents();
  const first = snap();
  const readsBefore = reads;
  await clock.tick(interval);
  const after = snap();
  const readsAfter = reads;
  // Two more intervals: a list that still offers a contact action keeps watching,
  // and one that offers none must have stopped.
  await clock.tick(interval * 2);
  process.stdout.write('PRESENCE_RESULT=' + JSON.stringify({
    first: first, after: after,
    readsBefore: readsBefore, readsAfter: readsAfter, readsSettled: reads
  }) + '\n');
  dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedResponses), string(interval[1]), string(encodedModule))

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped saved-jobs module failed under its own refresh: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		t.Fatalf("jsdom is required for this regression and is not available: %s", out)
	}
	const marker = "PRESENCE_RESULT="
	idx := strings.Index(string(out), marker)
	if idx < 0 {
		t.Fatalf("the saved-jobs watch produced no result marker:\n%s", out)
	}
	line := strings.TrimSpace(strings.SplitN(string(out)[idx+len(marker):], "\n", 2)[0])
	var watch savedJobsPresenceWatch
	if err := json.Unmarshal([]byte(line), &watch); err != nil {
		t.Fatalf("the saved-jobs watch summary is not JSON: %v %s", err, line)
	}
	return watch
}

// TestPausedSavedJobsStopsOfferingResumeWhenTheMarkArrives is F995-01's same-DOM half.
//
// The row-level regression above renders the list fresh with the mark already
// recorded, so it cannot see the state the operator is actually in when the provider's
// inventory pass records the absence while Settings is open. The Recent Deployments
// list re-reads the order, hides its actions and keeps polling; the saved-jobs list
// only ever scheduled a poll for a job the panel was still provisioning, so a
// paused-only list kept offering Resume for a server it could no longer reach until the
// page was reloaded.
//
// The fixture is the same real paused job, and the second response is the real
// saved-jobs body the handler produces after the mark - not a hand-built one, so a
// field the handler stops sending cannot be invented here.
func TestPausedSavedJobsStopsOfferingResumeWhenTheMarkArrives(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	const orderID = "ord_995_paused_live"
	const providerServerID = int64(6199)

	intent := env.pauseAtEnablement(orderID, providerServerID, "198.51.100.199")
	if intent.NexusServerID <= 0 {
		t.Fatalf("the fixture must journal the registered panel server on the intent, got %d", intent.NexusServerID)
	}
	server := env.registeredServer(providerServerID)
	if server == nil || server.ID != intent.NexusServerID {
		t.Fatalf("the fixture must register the panel server %d, got %+v", intent.NexusServerID, server)
	}

	open := gigahostOrderStatusRead(t, env.h, orderID)

	// Positive control: the second read carries the same list, so the same DOM must
	// still offer Resume. Without it, a view that never offers the action would pass
	// the assertion below for the wrong reason.
	kept := runSavedJobsPresenceWatch(t, []string{open.Intents, open.Intents})
	if !slices.Contains(kept.First.Buttons, "setup_intents_resume") {
		t.Fatalf("the control must offer Resume before the mark, got %v", kept.First.Buttons)
	}
	if kept.ReadsAfter <= kept.ReadsBefore {
		t.Fatalf("the saved list must re-read while it still offers a contact action: reads %d then %d",
			kept.ReadsBefore, kept.ReadsAfter)
	}
	if !slices.Contains(kept.After.Buttons, "setup_intents_resume") {
		t.Fatalf("a paused job whose server is still listed must keep Resume, got %v", kept.After.Buttons)
	}

	// The provider's own inventory now confirms the registered server is gone, while
	// the operator is still looking at the list rendered a moment ago.
	markServerProviderAbsent(t, env.h, server.ID)
	marked := gigahostOrderStatusRead(t, env.h, orderID)
	if !strings.Contains(marked.Intents, `"provider_absent":true`) {
		t.Fatalf("the saved-jobs response must carry the recorded absence: %s", marked.Intents)
	}

	stopped := runSavedJobsPresenceWatch(t, []string{open.Intents, marked.Intents})
	if !slices.Contains(stopped.First.Buttons, "setup_intents_resume") {
		t.Fatalf("the list must offer Resume before the mark arrives, got %v", stopped.First.Buttons)
	}
	if stopped.ReadsAfter <= stopped.ReadsBefore {
		t.Fatalf("the saved list did not re-read itself while Resume was offered: reads %d then %d",
			stopped.ReadsBefore, stopped.ReadsAfter)
	}
	for _, forbidden := range []string{"setup_intents_resume", "setup_intents_confirm_host"} {
		if slices.Contains(stopped.After.Buttons, forbidden) {
			t.Fatalf("the same DOM still offers %q after the mark arrived: %v", forbidden, stopped.After.Buttons)
		}
	}
	if !strings.Contains(stopped.After.Text, "gigahost_status_stage_deleted") {
		t.Fatalf("the row must say why it offers nothing: %q", stopped.After.Text)
	}
	if !strings.Contains(stopped.After.Text, "#"+orderID) {
		t.Fatalf("the marked row lost its order identity: %q", stopped.After.Text)
	}
	// Nothing is left to contact, so the view stops asking: the refresh is one timer
	// owned by this list, not a permanent poll of a settled page.
	if stopped.ReadsSettled != stopped.ReadsAfter {
		t.Fatalf("a list that offers no contact action kept polling: %d reads, then %d",
			stopped.ReadsAfter, stopped.ReadsSettled)
	}
}

// TestPausedSavedSetupSuppressesContactActionsWhenItsServerIsGone is F995-01.
//
// The fixture is the shipped paused-job shape: the server is registered, the intent
// carries its panel id, the ledger does not. With nothing recorded against the
// server the row keeps its ordinary treatment (that is the control, and it is what
// makes the suppression observable). Once the provider inventory confirms the server
// is gone, no surface may offer an action that would contact it, and the order must
// stay identifiable on both.
func TestPausedSavedSetupSuppressesContactActionsWhenItsServerIsGone(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	const orderID = "ord_995_paused"
	const providerServerID = int64(6195)

	intent := env.pauseAtEnablement(orderID, providerServerID, "198.51.100.195")
	if intent.NexusServerID <= 0 {
		t.Fatalf("the fixture must journal the registered panel server on the intent, got %d", intent.NexusServerID)
	}
	server := env.registeredServer(providerServerID)
	if server == nil || server.ID != intent.NexusServerID {
		t.Fatalf("the fixture must register the panel server %d, got %+v", intent.NexusServerID, server)
	}
	// The premise of the defect: the order ledger has not been given the identity yet,
	// so a view that consults only the ledger cannot see the absence.
	_, ledgerServerID, _, _, err := env.h.getDeployOrderByID(context.Background(), orderID)
	if err != nil {
		t.Fatalf("read the ledger row: %v", err)
	}
	if ledgerServerID != 0 {
		t.Fatalf("fixture premise: a paused job's ledger row must not carry the identity yet, got %d", ledgerServerID)
	}

	// Control: nothing is recorded against the server, so the paused job keeps its
	// ordinary treatment on both surfaces.
	unmarked := gigahostOrderStatusRead(t, env.h, orderID)
	unmarked.Details = map[string]string{orderID: unmarked.Detail}
	row := renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, unmarked, orderID))
	if row.Stage == "deleted" {
		t.Fatalf("a paused job with no recorded absence must not render deleted: %+v", row)
	}
	if !slices.Contains(row.Actions, "deploy_setup_btn") {
		t.Fatalf("the control must offer the immediate setup action, got %v", row.Actions)
	}
	if !slices.Contains(row.Actions, "setup_intents_approve") {
		t.Fatalf("the control must offer the saved approval action, got %v", row.Actions)
	}
	unmarkedJobs := runGigahostSetupIntentsRendererLoads(t, unmarked.Intents)
	if !slices.Contains(unmarkedJobs.Buttons, "setup_intents_resume") {
		t.Fatalf("the control must offer Resume for a paused job, got %v", unmarkedJobs.Buttons)
	}

	// The provider's own inventory now confirms the registered server is gone.
	markServerProviderAbsent(t, env.h, server.ID)

	marked := gigahostOrderStatusRead(t, env.h, orderID)
	marked.Details = map[string]string{orderID: marked.Detail}

	// The deploy read must resolve the identity the intent journals, not the ledger's 0.
	var deployRead struct {
		Deploy struct {
			ProviderAbsent bool  `json:"provider_absent"`
			ServerID       int64 `json:"server_id"`
		} `json:"deploy"`
	}
	if err := json.Unmarshal([]byte(marked.Detail), &deployRead); err != nil {
		t.Fatalf("the deploy read is not the documented shape: %v %s", err, marked.Detail)
	}
	if !deployRead.Deploy.ProviderAbsent {
		t.Fatalf("the deploy read must report the absence recorded against the identity the intent registered: %s", marked.Detail)
	}

	// The saved-jobs list carries the same presence fact for the same row.
	var intentsBody struct {
		Intents []map[string]any `json:"setup_intents"`
	}
	if err := json.Unmarshal([]byte(marked.Intents), &intentsBody); err != nil {
		t.Fatalf("the saved-jobs response is not the documented shape: %v %s", err, marked.Intents)
	}
	var seen bool
	for _, entry := range intentsBody.Intents {
		if entry["order_id"] != orderID {
			continue
		}
		seen = true
		if got, _ := entry["provider_absent"].(bool); !got {
			t.Fatalf("the saved job must carry the recorded absence: %v", entry)
		}
	}
	if !seen {
		t.Fatalf("the paused job is missing from the saved-jobs response: %s", marked.Intents)
	}

	// Recent Deployments: every contact action is gone, the identity is not.
	row = renderDeletedDeployment(t, runGigahostOrderStatusRendererLoads(t, marked, orderID))
	for _, forbidden := range []string{"deploy_setup_btn", "deploy_retry_btn", "setup_intents_approve"} {
		if slices.Contains(row.Actions, forbidden) {
			t.Fatalf("a saved job whose registered server is gone must not offer %q, got %v", forbidden, row.Actions)
		}
	}
	if len(row.Actions) != 0 {
		t.Fatalf("a saved job whose registered server is gone must offer no contact action, got %v", row.Actions)
	}
	if !strings.Contains(row.Identity, "#"+orderID) {
		t.Fatalf("the deleted saved job lost its order identity: %q", row.Identity)
	}

	// The saved-jobs list: Resume is gone, the job is still identifiable.
	jobs := runGigahostSetupIntentsRendererLoads(t, marked.Intents)
	for _, forbidden := range []string{"setup_intents_resume", "setup_intents_confirm_host"} {
		if slices.Contains(jobs.Buttons, forbidden) {
			t.Fatalf("a saved job whose registered server is gone must not offer %q, got %v", forbidden, jobs.Buttons)
		}
	}
	if len(jobs.Buttons) != 0 {
		t.Fatalf("a paused saved job whose registered server is gone must offer no contact action, got %v", jobs.Buttons)
	}
	if !strings.Contains(jobs.Text, "#"+orderID) {
		t.Fatalf("the saved job lost its order identity: %q", jobs.Text)
	}
	if !strings.Contains(jobs.Text, "gigahost_status_stage_deleted") {
		t.Fatalf("the saved job must say why it offers nothing: %q", jobs.Text)
	}
}
