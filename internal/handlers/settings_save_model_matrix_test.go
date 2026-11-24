package handlers

// One oracle over the eight settings cards crossed with every way a save can end
// (#888). Earlier rounds each fixed the case a review named and left its class.
// This file states the contract once and checks every cell.
//
// For every card and every outcome:
//   - a failed, refused, conflicted or slow save never discards the draft and
//     never marks it clean; only a completed save of what is on screen does;
//   - busy clears on every terminal outcome, and the commit follows the dirty state;
//   - the card has exactly one status region and one alert region, with roles that
//     never change, and an outcome is written to the region that matches it;
//   - focus moves only when the operation lost it. A deliberate move to another
//     control, in this card or any other, is never undone;
//   - the stored record is read back separately from the screen.
//
// Every cell runs on its own freshly loaded page, against the real settings and
// notification handlers. The policy endpoints are answered by the harness double.
// A cell that cannot occur is reported as "na" with its reason, not left out.

import (
	"encoding/json"
	"strings"
	"testing"
)

// settingsMatrixOutcomes are the columns, in the order they run. Cells that must
// prove "nothing was written" run before the ones that write, so a leaked write
// shows as a change instead of hiding behind an earlier success.
var settingsMatrixOutcomes = []string{
	"refused", "transport", "conflict", "late-fail-cross",
	"success", "repeat", "late-ok-cross", "late-ok-own",
}

// settingsMatrixCards are the cards the Settings page renders. The policy card is
// not one of them since #987: it is the Routing page's card, and it keeps the same
// matrix there (routingMatrixCards) rather than losing the coverage it had here.
var settingsMatrixCards = []string{
	"appearanceCard", "captchaCard", "sslCard", "limitsCard", "telegramCard",
	"gigahostCard", "notificationsCard",
}

// routingMatrixCards are the cards the Routing page renders.
var routingMatrixCards = []string{"policyRoutingCard"}

// matrixCell is one result row the scenario prints.
type matrixCell struct {
	Card     string   `json:"card"`
	Outcome  string   `json:"outcome"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason"`
	Failures []string `json:"failures"`
}

// settingsMatrixHelpers builds fresh pages and describes each card's primary field.
const settingsMatrixHelpers = `
const MX_CARDS = {
  appearanceCard:    {id: 'app_title', mk: n => 'cell-' + n, stored: s => s.appearance.title, other: 'ssl_domain'},
  captchaCard:       {id: 'captcha_enabled', check: true, stored: s => s.captcha.enabled, other: 'app_title'},
  sslCard:           {id: 'ssl_domain', mk: n => 'cell-' + n + '.example.test', stored: s => s.ssl.domain, other: 'app_title'},
  limitsCard:        {id: 'max_connections_per_user', mk: n => String(100 + n), stored: s => String(s.limits.max_connections_per_user), other: 'app_title'},
  telegramCard:      {id: 'telegram_chat_id', mk: n => '-100cell' + n, stored: s => s.telegram.chat_id, other: 'app_title'},
  gigahostCard:      {id: 'gigahost_api_key', secret: true, mk: n => 'flux_live_cell_' + n + '_0123456789', stored: s => s.gigahost.api_key, other: 'app_title'},
  notificationsCard: {id: 'notifications_cooldown', mk: n => String(100 + n), other: 'app_title', own: true},
  policyRoutingCard: {id: 'policy_proxy_exceptions', mk: n => '198.51.' + n + '.0/24', other: 'app_title', own: true}
};
let mxN = 0;
const mxText = el => el.textContent.replace(/\s+/g, ' ').trim();

function mxIsWrite(u, o) {
  const m = String((o && o.method) || 'GET').toUpperCase();
  const path = String(u).split('?')[0];
  return (m === 'POST' && (path === '/api/settings/save' || path === '/api/notifications/settings')) ||
         (m === 'PUT' && path === '/api/vpn/policy');
}

// mxPage loads a fresh copy of the page. mode is 'ok', 'refuse' (the server says
// no) or 'fail' (no answer arrives). gate holds a write until released.
async function mxPage() {
  const vc2 = new VirtualConsole();
  vc2.on('jsdomError', () => {});
  const dom2 = new JSDOM(CFG.page, {runScripts: 'outside-only', url: CFG.base + CFG.path, virtualConsole: vc2});
  const w2 = dom2.window;
  w2.I18N = CFG.dict;
  w2._ = k => w2.I18N[k] || k;
  const p = {w: w2, doc: w2.document, mode: 'ok', gate: null, writes: 0, held: 0, toasts: 0};
  w2.fetch = async (u, o) => {
    if (mxIsWrite(u, o)) {
      p.writes++;
      if (p.mode === 'fail') throw new TypeError('Failed to fetch');
      if (p.gate) { p.held++; await p.gate; }
      if (p.mode === 'refuse') return jsonResponse({error: 'validation_failed', detail: 'refused by the matrix'}, 422);
    }
    const fake = policyAnswer(u, o);
    if (fake) return fake;
    return realFetch(CFG.base + u, o);
  };
  for (const s of CFG.scripts) { w2.eval(s.source); }
  const toast = w2.UI.toast;
  w2.UI.toast = (...a) => { p.toasts++; return toast(...a); };
  await new Promise(r => { if (w2.document.readyState === 'complete') r(); else w2.addEventListener('load', r); });
  await sleep(900);
  return p;
}

const mxField = (p, cfg) => cfg.upstream ? p.card.querySelector('[data-upstream-field="port"]') : p.doc.getElementById(cfg.id);
const mxValue = (p, cfg) => { const el = mxField(p, cfg); return cfg.check ? el.checked : el.value; };
const mxCommit = p => p.card.querySelector('[data-commit]');
const mxDirty = p => mxText(p.card.querySelector('[data-dirty]'));
function mxFire(el, ...types) { for (const t of types) el.dispatchEvent(new el.ownerDocument.defaultView.Event(t, {bubbles: true})); }

// mxEdit stages one change in the card's primary field and returns the value left
// on screen. A checkbox is toggled, so the draft always differs from what loaded.
function mxEdit(p, cfg, n) {
  const el = mxField(p, cfg);
  if (cfg.check) el.checked = !el.checked; else el.value = cfg.mk(n);
  mxFire(el, 'input', 'change');
  return cfg.check ? el.checked : el.value;
}

// mxStored reads the one stored fact a card owns, as a plain string, from the real
// handlers (or the policy double), never from what the page shows.
async function mxStored(cfg) {
  if (cfg.stored) return String(cfg.stored(await stored()));
  if (cfg.id === 'notifications_cooldown') {
    return String((await (await realFetch(CFG.base + '/api/notifications/settings')).json()).cooldown_seconds);
  }
  if (cfg.id === 'policy_proxy_exceptions') return policyDouble.record.proxy_exceptions.join('\n');
  throw new Error('no stored fact is defined for card ' + cfg.id);
}

// mxRegions checks the card's two result regions: exactly one of each, fixed
// roles, and the text in the one that matches the outcome.
function mxRegions(p, ok, want, outcome) {
  const st = p.card.querySelectorAll('[data-status]');
  const er = p.card.querySelectorAll('[data-error]');
  ok(st.length === 1 && er.length === 1, 'exactly one status region and one alert region, got ' + st.length + ':' + er.length);
  if (st.length !== 1 || er.length !== 1) return;
  ok(st[0].getAttribute('role') === 'status' && er[0].getAttribute('role') === 'alert', 'region roles must not change');
  const s = mxText(st[0]), e = mxText(er[0]);
  if (want === 'status') ok(s !== '' && e === '', 'a success is announced in the status region only: status=' + JSON.stringify(s) + ' alert=' + JSON.stringify(e));
  if (want === 'alert') ok(e !== '' && s === '', 'a failure is announced in the alert region only: status=' + JSON.stringify(s) + ' alert=' + JSON.stringify(e));
  const got = (want === 'status' ? st[0] : er[0]).getAttribute('data-outcome');
  if (outcome) ok(got === outcome, 'the outcome is recorded as ' + outcome + ', got ' + got);
}

function mxIdle(p, ok) {
  const commit = mxCommit(p);
  ok(p.card.getAttribute('aria-busy') === 'false', 'busy must clear on every outcome');
  const sp = commit.querySelector('.spinner');
  ok(!sp || sp.classList.contains('hidden'), 'the spinner must clear');
  ok(p.toasts === 0, 'no page toast was raised: ' + p.toasts);
}
`

// settingsMatrixCells is the body of every cell. Each one loads its own page,
// drives one card to one outcome and reports failures instead of throwing, so a
// single run lists every broken cell at once.
const settingsMatrixCells = `
const MX_RESULTS = [];

async function mxCell(cardId, outcome) {
  const cfg = MX_CARDS[cardId];
  const failures = [];
  const ok = (cond, msg) => { if (!cond) failures.push(msg); };
  let status = 'run', reason = '';
  const p = await mxPage();
  p.card = p.doc.getElementById(cardId);
  try {
    if (!p.card) throw new Error('card is not on the page');
    const commit = mxCommit(p);
    ok(commit.disabled === true, 'a loaded card has nothing staged, so its commit is disabled');
    const before = await mxStored(cfg);
    // The cross-card focus case needs an editable field in a DIFFERENT card on the
    // page under test. The policy card lives on /routing, where the appearance card
    // is not rendered, so its neighbour is the override textarea beside it.
    const other = p.doc.getElementById(cfg.other) ? p.doc.getElementById(cfg.other)
        : p.doc.getElementById('policy_inventory_override');
    if (!other) throw new Error('no field in another card to move to on this page');
    const draft = mxEdit(p, cfg, ++mxN);
    ok(mxDirty(p) !== '', 'editing marks the card unsaved');
    ok(commit.disabled === false, 'a staged card offers its commit');

    if (outcome === 'refused' || outcome === 'transport') {
      p.mode = outcome === 'refused' ? 'refuse' : 'fail';
      commit.focus();
      commit.click();
      await until(() => p.card.getAttribute('aria-busy') === 'false' && mxText(p.card.querySelector('[data-error]')) !== '', cardId + ' ' + outcome + ' to settle');
      await settled();
      ok(mxValue(p, cfg) === draft, 'the draft is still in the editor');
      ok(mxDirty(p) !== '', 'a ' + outcome + ' save does not mark the card clean');
      ok(commit.disabled === false, 'the operator can try again');
      mxRegions(p, ok, 'alert', outcome === 'refused' ? 'refused' : 'failed');
      mxIdle(p, ok);
      ok(p.doc.activeElement === commit, 'focus was on the commit and stays there after a failure');
      ok(await mxStored(cfg) === before, 'nothing was stored');

    } else if (outcome === 'conflict') {
      // No card has a read-before-write over a whole record any more: the
      // resolver list that did was removed with the encrypted upstream editor.
      // Every remaining card writes its own section or fields, so two tabs
      // cannot make one overwrite the other (covered by the two-client
      // interleaving tests).
      status = 'na';
      reason = 'a conflict needs a read-before-write against a record another tab can change. No surviving card replaces a whole record: every one writes its own section or fields, and two tabs cannot make one overwrite the other (covered by the two-client interleaving tests).';

    } else if (outcome === 'success') {
      commit.focus();
      commit.click();
      await until(() => p.card.getAttribute('aria-busy') === 'false' && mxText(p.card.querySelector('[data-status]')) !== '', cardId + ' success to settle');
      await settled();
      mxRegions(p, ok, 'status', 'saved');
      mxIdle(p, ok);
      ok(mxDirty(p) === '', 'a completed save of what is on screen is clean');
      ok(commit.disabled === true, 'nothing left to commit');
      // A write-only secret is shown masked after a save and is never read back.
      if (cfg.secret) {
        ok(mxValue(p, cfg) === '********', 'a saved secret goes back to its mask');
        ok(await mxStored(cfg) === '********', 'the stored secret is reported masked, and is set');
      } else {
        ok(String(mxValue(p, cfg)) === String(draft), 'the saved value is on screen');
        ok(await mxStored(cfg) === String(draft), 'the stored record holds what was sent: ' + await mxStored(cfg) + ' vs ' + draft);
      }
      ok(p.doc.activeElement !== p.doc.body, 'focus did not fall to the page');
      ok(p.card.contains(p.doc.activeElement), 'focus the operation lost comes back to the card it was in');

    } else if (outcome === 'repeat') {
      let release;
      p.gate = new Promise(r => { release = r; });
      commit.focus();
      commit.click();
      commit.click();
      p.card.querySelector('form') && mxFire(p.card.querySelector('form'), 'submit');
      await until(() => p.held >= 1, 'the first write to reach the barrier');
      await sleep(150);
      ok(p.writes === 1, 'a repeated submit while one runs is one write, got ' + p.writes);
      ok(p.card.getAttribute('aria-busy') === 'true', 'busy while the request runs');
      ok(commit.disabled === true, 'the commit is disabled while busy');
      release();
      await until(() => p.card.getAttribute('aria-busy') === 'false', 'the write to finish');
      await settled();
      ok(p.writes === 1, 'still one write after it finished, got ' + p.writes);
      mxRegions(p, ok, 'status', 'saved');
      mxIdle(p, ok);

    } else if (outcome === 'late-ok-cross' || outcome === 'late-fail-cross') {
      const fail = outcome === 'late-fail-cross';
      let release;
      p.gate = new Promise(r => { release = r; });
      p.mode = fail ? 'refuse' : 'ok';
      commit.focus();
      commit.click();
      await until(() => p.held >= 1, 'the write to reach the barrier');
      // The operator moves on to an input in a different card and keeps typing.
      other.focus();
      other.value = 'typed-while-waiting';
      mxFire(other, 'input');
      ok(p.doc.activeElement === other, 'the operator moved focus to another card');
      release();
      await until(() => p.card.getAttribute('aria-busy') === 'false', 'the write to finish');
      await settled();
      ok(p.doc.activeElement === other, 'a late ' + (fail ? 'failure' : 'success') + ' must not take focus from the control the operator chose');
      ok(other.value === 'typed-while-waiting', 'what was typed there is still there');
      mxRegions(p, ok, fail ? 'alert' : 'status', fail ? 'refused' : 'saved');
      mxIdle(p, ok);
      if (fail) ok(mxDirty(p) !== '', 'the refused draft is still unsaved');

    } else if (outcome === 'late-ok-own') {
      let release;
      p.gate = new Promise(r => { release = r; });
      commit.focus();
      commit.click();
      await until(() => p.held >= 1, 'the write to reach the barrier');
      const field = mxField(p, cfg);
      if (cfg.upstream) {
        // This editor chose the other answer to a slow save: its rows are locked for
        // the whole request, so nothing can be typed that the answer could overwrite.
        ok(field.disabled === true, 'the rows are disabled while the request runs');
        release();
        await until(() => p.card.getAttribute('aria-busy') === 'false', 'the write to finish');
        await settled();
        ok(field.disabled === false, 'and editable again afterwards');
        ok(mxDirty(p) === '', 'a completed save of what was sent is clean');
      } else {
        // Typed in the same card after the request was built: it must survive the answer.
        let later;
        if (cfg.check) { field.checked = !field.checked; later = field.checked; }
        else { later = cfg.mk(++mxN); field.value = later; }
        mxFire(field, 'input', 'change');
        release();
        await until(() => p.card.getAttribute('aria-busy') === 'false', 'the write to finish');
        await settled();
        ok(mxValue(p, cfg) === later, 'what was typed after the request was built is still on screen');
        ok(mxDirty(p) !== '', 'the newer edit is still marked unsaved');
      }
      mxRegions(p, ok, 'status', 'saved');
      mxIdle(p, ok);
    }
  } catch (err) {
    failures.push('cell threw: ' + (err && err.message || err));
  } finally {
    p.w.close();
  }
  MX_RESULTS.push({card: cardId, outcome, status, reason, failures});
}
`

// settingsMatrixDriver runs the cells for the cards and outcomes the Go test names.
const settingsMatrixDriver = `
const MX_PLAN = JSON.parse(process.env.MX_PLAN);
for (const outcome of MX_PLAN.outcomes) {
  for (const cardId of MX_PLAN.cards) { await mxCell(cardId, outcome); }
}
console.log('MX_JSON=' + JSON.stringify(MX_RESULTS));
`

// runMatrix runs the plan on the page those cards render and returns every cell.
func runMatrix(t *testing.T, path string, outcomes, cards []string) []matrixCell {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	plan, err := json.Marshal(map[string][]string{"outcomes": outcomes, "cards": cards})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MX_PLAN", string(plan))
	out := runSettingsScenarioWith(t, h, settingsHarnessOptions{liveNotifications: true, path: path},
		settingsMatrixHelpers+settingsMatrixCells+settingsMatrixDriver)
	i := strings.LastIndex(out, "MX_JSON=")
	if i < 0 {
		t.Fatalf("the matrix printed no result:\n%s", out)
	}
	line := out[i+len("MX_JSON="):]
	if j := strings.Index(line, "\n"); j >= 0 {
		line = line[:j]
	}
	var cells []matrixCell
	if err := json.Unmarshal([]byte(line), &cells); err != nil {
		t.Fatalf("decode matrix result: %v\n%s", err, line)
	}
	return cells
}

// TestSettingsSaveModel_Matrix is the class-level oracle. Each cell is a subtest,
// so a broken cell names its card and its outcome. It runs on every page that holds
// a card with a commit control: the cards that stayed in Settings and the policy
// card that moved to Routing.
func TestSettingsSaveModel_Matrix(t *testing.T) {
	pages := []struct {
		path  string
		cards []string
	}{
		{"/settings", settingsMatrixCards},
		{"/routing", routingMatrixCards},
	}
	var cells []matrixCell
	want := 0
	for _, page := range pages {
		cells = append(cells, runMatrix(t, page.path, settingsMatrixOutcomes, page.cards)...)
		want += len(settingsMatrixOutcomes) * len(page.cards)
	}
	if len(cells) != want {
		t.Fatalf("matrix ran %d cells, want %d", len(cells), want)
	}
	ran, na := 0, 0
	for _, c := range cells {
		t.Run(c.Outcome+"/"+c.Card, func(t *testing.T) {
			if c.Status == "na" {
				na++
				if c.Reason == "" {
					t.Error("a cell reported as not applicable must say why")
				}
				t.Logf("na: %s", c.Reason)
				return
			}
			ran++
			for _, f := range c.Failures {
				t.Error(f)
			}
		})
	}
	t.Logf("matrix: %d cells run, %d not applicable, %d total", ran, na, len(cells))
}
