package handlers

// A saved job's watch has to survive one failed read.
//
// The list is answered by the panel from its own database, so a rejected request says
// nothing about which jobs exist. Rendering "no saved jobs" for it hid a paused job that
// was still there, and because the refresh timer had already cleared itself before the read
// it also stopped the view from ever reading again: the absence mark the panel records
// afterwards could not reach that DOM without a page reload.
//
// The fixture is the shipped paused job (a real approval, a real tracker pass, a real
// install pass that pauses on its own error path, a real registration) and the responses
// are the real saved-jobs bodies the handler produces before and after the mark. Nothing
// here contacts a provider or a host, and nothing is installed.

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// savedWatchSnapshots is one run of the shipped saved-jobs module through a failed read,
// a recovery and a restored document, with its own timer under test.
type savedWatchSnapshots struct {
	First        savedSetupView `json:"first"`
	AfterFailure savedSetupView `json:"afterFailure"`
	AfterRecover savedSetupView `json:"afterRecover"`
	AfterRestore savedSetupView `json:"afterRestore"`
	// Reads* count the list reads at each point, so "the view re-read on its own" is
	// observable rather than inferred from the rendering.
	ReadsFirst     int `json:"readsFirst"`
	ReadsFailure   int `json:"readsFailure"`
	ReadsRecover   int `json:"readsRecover"`
	ReadsRestore   int `json:"readsRestore"`
	ReadsAfterSpam int `json:"readsAfterSpam"`
	ReadsSettled   int `json:"readsSettled"`
	RetryMax       int `json:"retryMax"`
	// Stale is the container's own record that its freshness is unproven.
	Stale          string `json:"stale"`
	StaleAfterMark string `json:"staleAfterMark"`
}

// savedWatchPayload is one list response the fake endpoint answers with: a real body, or a
// rejected read.
type savedWatchPayload struct {
	Body string `json:"body,omitempty"`
	Fail bool   `json:"fail,omitempty"`
}

// runSavedWatchThroughAFailure drives the shipped module: it renders the first response,
// lets the view's own watch fire into a rejected read, lets the retry it arms deliver the
// next response, dispatches a page restore, and then measures how far a permanently failing
// read is retried.
func runSavedWatchThroughAFailure(t *testing.T, payloads []savedWatchPayload) savedWatchSnapshots {
	t.Helper()

	node := gigahostOrderStatusNode(t)
	module, err := web.StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read the shipped setup-intents module: %v", err)
	}
	interval := savedWatchConstant(t, module, "SETUP_INTENTS_PRESENCE_REFRESH_MS")
	retryMax := savedWatchConstant(t, module, "SETUP_INTENTS_RETRY_MAX")

	encodedModule, _ := json.Marshal(string(module))
	encodedPayloads, _ := json.Marshal(payloads)

	script := gigahostOrderStatusJSDOMBootstrap + fmt.Sprintf(`
const payloads = %s;
const interval = %d;
const retryMax = %d;
let index = 0;
let reads = 0;
let failing = false;
const dom = new JSDOM('<div id="setupIntentsContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.UI = {toast:()=>{}};
w.confirm = () => false;
// Reading is the only request this view makes; any write attempt is a failure.
w.API = {
  get: async () => {
    reads += 1;
    if (failing) { const e = new Error('controlled read failure'); e.status = 503; throw e; }
    const step = payloads[Math.min(index, payloads.length - 1)];
    index += 1;
    if (step.fail) { const e = new Error('controlled read failure'); e.status = 503; throw e; }
    return JSON.parse(step.body);
  },
  post: async () => { throw new Error('the saved list must not POST while rendering'); },
  delete: async () => { throw new Error('the saved list must not DELETE while rendering'); }
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
    badges: Array.from(container.querySelectorAll('.badge')).map(flat),
    stale: container.getAttribute('data-stale') || ''
  };
};
// A page transition the way the browser reports one: pagehide, then a restore that carries
// persisted=true, which is what distinguishes it from the initial load.
const transition = (name, persisted) => {
  const event = new w.Event(name);
  Object.defineProperty(event, 'persisted', {value: persisted});
  return event;
};

(async () => {
  await w.loadSetupIntents();
  const first = snap();
  const readsFirst = reads;

  // The view's own watch fires into a rejected read.
  await clock.tick(interval);
  const afterFailure = snap();
  const readsFailure = reads;

  // The retry the failed read armed delivers the next response, with no explicit load.
  await clock.tick(interval);
  const afterRecover = snap();
  const readsRecover = reads;

  // Navigating away and back restores this document; the watch was cleared by pagehide, so
  // the restore has to re-observe the list itself.
  w.dispatchEvent(transition('pagehide', false));
  w.dispatchEvent(transition('pageshow', true));
  await flush();
  const afterRestore = snap();
  const readsRestore = reads;

  // A panel that keeps failing must cost a bounded number of requests, not a permanent
  // poll. Re-arm the ordinary watch first, then let every read fail.
  index = 0;
  await w.loadSetupIntents();
  failing = true;
  const beforeSpam = reads;
  await clock.tick(interval * (retryMax + 4));
  const readsAfterSpam = reads;
  await clock.tick(interval * 4);
  const readsSettled = reads;

  process.stdout.write('WATCH_RESULT=' + JSON.stringify({
    first: first, afterFailure: afterFailure, afterRecover: afterRecover, afterRestore: afterRestore,
    readsFirst: readsFirst, readsFailure: readsFailure, readsRecover: readsRecover,
    readsRestore: readsRestore, readsAfterSpam: readsAfterSpam, readsSettled: readsSettled,
    retryMax: retryMax, stale: afterFailure.stale, staleAfterMark: afterRecover.stale
  }) + '\n');
  dom.window.close();
})().catch(err => { console.error(err); process.exit(1); });
`, string(encodedPayloads), interval, retryMax, string(encodedModule))

	cmd := exec.Command(node)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped saved-jobs module failed while recovering: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		t.Fatalf("jsdom is required for this regression and is not available: %s", out)
	}
	const marker = "WATCH_RESULT="
	idx := strings.Index(string(out), marker)
	if idx < 0 {
		t.Fatalf("the saved-jobs watch produced no result marker:\n%s", out)
	}
	line := strings.TrimSpace(strings.SplitN(string(out)[idx+len(marker):], "\n", 2)[0])
	var watch savedWatchSnapshots
	if err := json.Unmarshal([]byte(line), &watch); err != nil {
		t.Fatalf("the saved-jobs watch summary is not JSON: %v %s", err, line)
	}
	return watch
}

// savedWatchConstant reads one numeric constant out of the shipped module, so this check
// fails loudly if the view stops stating the pace or the bound it is verified against
// instead of quietly ticking for a duration nobody owns.
func savedWatchConstant(t *testing.T, module []byte, name string) int {
	t.Helper()
	match := regexp.MustCompile(`const ` + name + ` = (\d+);`).FindSubmatch(module)
	if match == nil {
		t.Fatalf("the saved-jobs module no longer states %s, so this check cannot advance the "+
			"view's own timer", name)
	}
	var value int
	if _, err := fmt.Sscanf(string(match[1]), "%d", &value); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return value
}

// TestSavedWatchSurvivesARejectedReadAndKeepsTheJob is F995-01's failed-read regression.
func TestSavedWatchSurvivesARejectedReadAndKeepsTheJob(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	const orderID = "ord_995_saved_watch"
	const providerServerID = int64(6215)

	intent := env.pauseAtEnablement(orderID, providerServerID, "198.51.100.215")
	server := env.registeredServer(providerServerID)
	if server == nil || server.ID != intent.NexusServerID {
		t.Fatalf("the fixture must register the panel server %d, got %+v", intent.NexusServerID, server)
	}

	unmarked := gigahostOrderStatusRead(t, env.h, orderID)
	markServerProviderAbsent(t, env.h, server.ID)
	marked := gigahostOrderStatusRead(t, env.h, orderID)
	if !strings.Contains(marked.Intents, `"provider_absent":true`) {
		t.Fatalf("the marked response must carry the recorded absence: %s", marked.Intents)
	}

	watch := runSavedWatchThroughAFailure(t, []savedWatchPayload{
		{Body: unmarked.Intents},
		{Fail: true},
		{Body: marked.Intents},
	})

	// The control: the fixture starts from a paused job that does offer Resume, so the
	// disappearance below is a change and not a list that never offered the action.
	if !savedWatchHasLabel(watch.First.Buttons, "setup_intents_resume") {
		t.Fatalf("the fixture must offer Resume before the failure, got %v", watch.First.Buttons)
	}
	if watch.ReadsFailure <= watch.ReadsFirst {
		t.Fatalf("the view did not re-read on its own watch: reads %d then %d",
			watch.ReadsFirst, watch.ReadsFailure)
	}

	// A rejected read is not an empty list: the row and its action survive, and the
	// container says its freshness is unproven instead of claiming there are no jobs.
	for _, forbidden := range []string{"setup_intents_none"} {
		if strings.Contains(watch.AfterFailure.Text, forbidden) {
			t.Fatalf("a failed read was presented as %q: %q", forbidden, watch.AfterFailure.Text)
		}
	}
	if !strings.Contains(watch.AfterFailure.Text, "#"+orderID) {
		t.Fatalf("a failed read dropped the visible job: %q", watch.AfterFailure.Text)
	}
	if !savedWatchHasLabel(watch.AfterFailure.Buttons, "setup_intents_resume") {
		t.Fatalf("a failed read removed the action while nothing said the job had changed: %v",
			watch.AfterFailure.Buttons)
	}
	if watch.Stale != "true" {
		t.Fatalf("a failed read must record that its freshness is unproven, got %q", watch.Stale)
	}

	// The retry the failure armed delivers the marked response with no explicit load, and
	// that response removes the stale action.
	if watch.ReadsRecover <= watch.ReadsFailure {
		t.Fatalf("the failed read did not rearm the watch: reads %d then %d",
			watch.ReadsFailure, watch.ReadsRecover)
	}
	for _, forbidden := range []string{"setup_intents_resume", "setup_intents_confirm_host"} {
		if savedWatchHasLabel(watch.AfterRecover.Buttons, forbidden) {
			t.Fatalf("the same DOM still offers %q after the mark arrived: %v",
				forbidden, watch.AfterRecover.Buttons)
		}
	}
	if strings.Contains(watch.AfterRecover.Text, "setup_intents_none") {
		t.Fatalf("the recovered list was presented as empty: %q", watch.AfterRecover.Text)
	}
	if !strings.Contains(watch.AfterRecover.Text, "#"+orderID) {
		t.Fatalf("the marked job lost its identity: %q", watch.AfterRecover.Text)
	}
	if !strings.Contains(watch.AfterRecover.Text, "gigahost_status_stage_deleted") {
		t.Fatalf("the recovered row must say why it offers nothing: %q", watch.AfterRecover.Text)
	}
	if watch.StaleAfterMark != "" {
		t.Fatalf("a successful read must clear the stale record, got %q", watch.StaleAfterMark)
	}

	// A restored document re-observes the list: pagehide cleared the watch, and this DOM
	// was not rendered again.
	if watch.ReadsRestore <= watch.ReadsRecover {
		t.Fatalf("a restored document did not re-observe the list: reads %d then %d",
			watch.ReadsRecover, watch.ReadsRestore)
	}
	if savedWatchHasLabel(watch.AfterRestore.Buttons, "setup_intents_resume") {
		t.Fatalf("the restored list offers Resume again: %v", watch.AfterRestore.Buttons)
	}

	// A panel that keeps failing is retried a bounded number of times, and then the view
	// stops asking instead of holding a permanent poll.
	if grew := watch.ReadsAfterSpam - (watch.ReadsRestore + 1); grew > watch.RetryMax+1 {
		t.Fatalf("a permanently failing read was retried %d times, more than the bounded few the view states (%d) plus the watch's own read",
			grew, watch.RetryMax)
	}
	if watch.ReadsSettled != watch.ReadsAfterSpam {
		t.Fatalf("the bounded retries did not stop: %d reads, then %d",
			watch.ReadsAfterSpam, watch.ReadsSettled)
	}
}

// TestSavedWatchKeepsResumeWhenTheRecoveredListIsUnmarked is the negative control: the
// retry after a failure must render what the panel actually answered, so an unmarked list
// keeps Resume.
func TestSavedWatchKeepsResumeWhenTheRecoveredListIsUnmarked(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	const orderID = "ord_995_saved_control"
	const providerServerID = int64(6216)

	env.pauseAtEnablement(orderID, providerServerID, "198.51.100.216")
	unmarked := gigahostOrderStatusRead(t, env.h, orderID)

	watch := runSavedWatchThroughAFailure(t, []savedWatchPayload{
		{Body: unmarked.Intents},
		{Fail: true},
		{Body: unmarked.Intents},
	})

	if !savedWatchHasLabel(watch.First.Buttons, "setup_intents_resume") {
		t.Fatalf("the fixture must offer Resume before the failure, got %v", watch.First.Buttons)
	}
	if watch.ReadsRecover <= watch.ReadsFailure {
		t.Fatalf("the failed read did not rearm the watch: reads %d then %d",
			watch.ReadsFailure, watch.ReadsRecover)
	}
	if !savedWatchHasLabel(watch.AfterRecover.Buttons, "setup_intents_resume") {
		t.Fatalf("an unmarked list must keep Resume after a recovered read, got %v",
			watch.AfterRecover.Buttons)
	}
	if watch.StaleAfterMark != "" {
		t.Fatalf("a successful read must clear the stale record, got %q", watch.StaleAfterMark)
	}
}

// savedWatchHasLabel reports whether one rendered label list holds want. It is local to this
// file because the helpers elsewhere are compiled only under a feature tag.
func savedWatchHasLabel(labels []string, want string) bool {
	for _, label := range labels {
		if label == want {
			return true
		}
	}
	return false
}
