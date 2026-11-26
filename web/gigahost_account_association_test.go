package web

// Behavioural DOM test for the one-time provider account association, run against
// the SHIPPED controller and the SHIPPED settings markup.
//
// The section is extracted from web/templates/settings/gigahost.html rather than
// rebuilt here, so the ids, the hidden defaults and the live region this test drives
// are the ones the page delivers. The controller is read from StaticFS. What the
// assertions describe is therefore the real pairing, not a copy of it.
//
// The controls that must be proved, not assumed:
//
//   - a count the panel reported is the count rendered, and the confirmation is
//     offered only when that count is non-zero;
//   - the choice about servers the account no longer lists appears only when such a
//     server exists, and changing it re-renders from the same preview instead of
//     re-reading the provider;
//   - the confirmation posts the administrator's own choice, including an explicit
//     false when the choice was not made;
//   - a second click while a request is open issues no second request, because a
//     repeated association is a statement nobody made;
//   - a refused request is reported as a failure and never as an outcome, and it
//     does not leave the confirmation offered.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// associationSection extracts the association section from the shipped settings
// card by matching nested divs, so the harness loads the markup the page emits.
func associationSection(t *testing.T) string {
	t.Helper()
	card, err := TemplatesFS.ReadFile("templates/settings/gigahost.html")
	if err != nil {
		t.Fatalf("read the gigahost settings card: %v", err)
	}
	start := strings.Index(string(card), `<div id="gigahostAssociationSection"`)
	if start < 0 {
		t.Fatal("the gigahost settings card carries no association section")
	}
	depth := 0
	for i := start; i < len(card); i++ {
		switch {
		case strings.HasPrefix(string(card[i:]), "<div"):
			depth++
		case strings.HasPrefix(string(card[i:]), "</div>"):
			depth--
			if depth == 0 {
				return string(card[start : i+len("</div>")])
			}
		}
	}
	t.Fatal("the association section is not closed")
	return ""
}

// tagCarryingID returns the shipped tag that carries the given id.
func tagCarryingID(t *testing.T, markup, id string) string {
	t.Helper()
	re := regexp.MustCompile(`<[^>]*\bid="` + regexp.QuoteMeta(id) + `"[^>]*>`)
	tag := re.FindString(markup)
	if tag == "" {
		t.Fatalf("no shipped element carries id %q", id)
	}
	return tag
}

// hasClassToken reports whether a shipped tag's class attribute carries one token,
// so "hidden" as a class is distinguished from "hidden" appearing in prose.
func hasClassToken(tag, token string) bool {
	re := regexp.MustCompile(`\bclass="([^"]*)"`)
	match := re.FindStringSubmatch(tag)
	if match == nil {
		return false
	}
	for _, field := range strings.Fields(match[1]) {
		if field == token {
			return true
		}
	}
	return false
}

func TestGigahostAccountAssociationTemplateWiring(t *testing.T) {
	controls := []string{
		`id="gigahostAssociationSection"`,
		`id="btnGigahostAssociationPreview"`,
		`id="btnGigahostAssociationConfirm"`,
		`id="gigahostAssociationOutcome"`,
		`id="gigahostAssociationIncludeUnlisted"`,
		`id="gigahostAssociationUnlistedChoice"`,
		`role="status"`,
		`data-dirty-ignore`,
	}
	section := associationSection(t)
	for _, control := range controls {
		if !strings.Contains(section, control) {
			t.Fatalf("the association section is missing %s:\n%s", control, section)
		}
	}

	// The controls that must not be offered before a check carry the shared .hidden
	// class in the shipped markup. The class, not the bare attribute, is what hides
	// them: the switch and the button each carry their own display rule, which the
	// user-agent [hidden] rule loses to.
	for _, id := range []string{
		"gigahostAssociationUnlistedChoice",
		"gigahostAssociationOutcome",
		"btnGigahostAssociationConfirm",
	} {
		if tag := tagCarryingID(t, section, id); !hasClassToken(tag, "hidden") {
			t.Fatalf("the control %q is offered before any check; its shipped tag is %s", id, tag)
		}
	}
	if tag := tagCarryingID(t, section, "btnGigahostAssociationPreview"); hasClassToken(tag, "hidden") {
		t.Fatalf("the check button is hidden in the shipped markup: %s", tag)
	}
	if !strings.Contains(section, `id="gigahostAssociationIncludeUnlisted" type="checkbox"`) &&
		!strings.Contains(section, `type="checkbox" id="gigahostAssociationIncludeUnlisted"`) {
		t.Fatal("the unlisted choice is not a checkbox, so it cannot be an explicit consent")
	}

	templates := settingsTemplateText(t)
	if !strings.Contains(templates, versionedTemplateAsset("/static/js/gigahost_account_association.js")) {
		t.Fatal("settings.html does not load the account association controller")
	}
}

func TestGigahostAccountAssociationController(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)

	source, err := StaticFS.ReadFile("static/js/gigahost_account_association.js")
	if err != nil {
		t.Fatalf("read the association controller: %v", err)
	}
	encodedModule, _ := json.Marshal(string(source))
	encodedSection, _ := json.Marshal(associationSection(t))

	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="associationRoot">' + %s + '</div>', {runScripts:'outside-only'});
const w = dom.window;
const translations = {
  gigahost_association_nothing: 'nothing-to-associate',
  gigahost_association_preview: '%%d of %%d can be associated',
  gigahost_association_preview_unlisted: '%%d are no longer listed',
  gigahost_association_preview_unattributed: '%%d unattributed: %%s',
  gigahost_association_done: '%%d associated',
  gigahost_association_done_unlisted: '%%d will be marked deleted next',
  gigahost_association_done_none: 'nothing-further',
  gigahost_association_failed: 'failed: %%s',
  gigahost_association_reason_provider_refused: 'refused',
  gigahost_association_reason_provider_unanswered: 'did-not-answer',
  gigahost_association_reason_provider_unnamed: 'unnamed',
  gigahost_association_reason_write_failed: 'not-recorded'
};
w._ = key => translations[key] || key;

const calls = [];
let failNext = null;
let holdNext = null;
w.API = {
  get: async url => {
    calls.push({method:'GET', url});
    if (holdNext) { const release = holdNext; holdNext = null; await release; }
    if (failNext) { const e = new Error(failNext); failNext = null; throw e; }
    return {preview_id: 'preview-1', candidates: 3, attributable: 1, unlisted: 1, unattributed: 1,
            already_bound: 4, reasons: [{reason:'provider_refused', count:1}]};
  },
  post: async (url, body) => {
    calls.push({method:'POST', url, body});
    if (holdNext) { const release = holdNext; holdNext = null; await release; }
    if (failNext) { const e = new Error(failNext); failNext = null; throw e; }
    return {associated: 2, unlisted: 1, already_bound: 4, unattributed: 1,
            reasons: [{reason:'provider_unnamed', count:1}]};
  }
};

w.eval(%s);

const byMethod = m => calls.filter(c => c.method === m);
const text = id => w.document.getElementById(id).textContent;
const hidden = id => w.document.getElementById(id).classList.contains('hidden');
const flush = () => new Promise(res => setTimeout(res, 0));
const click = id => w.document.getElementById(id).click();

(async()=>{
  // 1. The pure text rules, before any DOM state is involved.
  assert.equal(w.gigahostAssociationFormat('%%d of %%d', [2, 3]), '2 of 3');
  assert.equal(w.gigahostAssociationFormat('no placeholders', ['x']), 'no placeholders');
  assert.equal(w.gigahostAssociationWanted({attributable: 2, unlisted: 1}, false), 2);
  assert.equal(w.gigahostAssociationWanted({attributable: 2, unlisted: 1}, true), 3);
  assert.equal(w.gigahostAssociationWanted(null, true), 0);
  assert.deepEqual(w.gigahostAssociationRequest('preview-1', true), {preview_id:'preview-1', include_unlisted: true});
  assert.deepEqual(w.gigahostAssociationRequest('preview-1', false), {preview_id:'preview-1', include_unlisted: false});
  assert.deepEqual(w.gigahostAssociationRequest('preview-1', 'yes'), {preview_id:'preview-1', include_unlisted: false});
  assert.deepEqual(w.gigahostAssociationRequest(), {preview_id:'', include_unlisted: false});
  assert.equal(
    w.gigahostAssociationPreviewText({candidates:0, attributable:0, unlisted:0, unattributed:0}, false),
    'nothing-to-associate');
  assert.equal(
    w.gigahostAssociationPreviewText(
      {candidates:3, attributable:2, unlisted:1, unattributed:0}, true),
    '3 of 3 can be associated 1 are no longer listed');
  assert.equal(
    w.gigahostAssociationPreviewText(
      {candidates:3, attributable:2, unlisted:0, unattributed:1,
       reasons:[{reason:'provider_refused', count:1}]}, false),
    '2 of 3 can be associated 1 unattributed: refused');
  assert.equal(w.gigahostAssociationOutcomeText({associated:0}), 'nothing-further');
  assert.equal(w.gigahostAssociationOutcomeText(null), 'nothing-further');
  assert.equal(w.gigahostAssociationOutcomeText({associated:0, unattributed:0, reasons:[]}), 'nothing-further');
  // A zero-write result that still has rows to reconcile must not read as completion.
  assert.equal(
    w.gigahostAssociationOutcomeText({associated:0, unattributed:2,
      reasons:[{reason:'write_failed', count:2}]}),
    '2 unattributed: not-recorded');
  assert.equal(
    w.gigahostAssociationOutcomeText({associated:0, unattributed:1,
      reasons:[{reason:'provider_unanswered', count:1}]}),
    '1 unattributed: did-not-answer');
  assert.notEqual(
    w.gigahostAssociationOutcomeText({associated:0, unattributed:1,
      reasons:[{reason:'provider_unanswered', count:1}]}),
    'nothing-further');
  assert.equal(w.gigahostAssociationOutcomeText({associated:2, unlisted:1}), '2 associated 1 will be marked deleted next');
  assert.equal(
    w.gigahostAssociationOutcomeText({associated:2, unlisted:0, unattributed:1,
      reasons:[{reason:'provider_unanswered', count:1}]}),
    '2 associated 1 unattributed: did-not-answer');

  // 2. The controller binds the shipped markup: nothing is offered before a check.
  const state = w.initGigahostAssociation();
  assert.ok(state, 'the controller returned no state for the shipped markup');
  assert.ok(hidden('btnGigahostAssociationConfirm'), 'the confirmation is offered before any check');
  assert.ok(hidden('gigahostAssociationUnlistedChoice'), 'the unlisted choice is offered before any check');
  assert.equal(byMethod('GET').length, 0);

  // 3. The check renders the panel's own counts and offers both controls.
  click('btnGigahostAssociationPreview');
  await flush();
  assert.equal(byMethod('GET').length, 1);
  assert.equal(byMethod('GET')[0].url, '/api/admin/hosting/gigahost/account-association');
  assert.equal(text('gigahostAssociationOutcome'), '1 of 3 can be associated 1 are no longer listed 1 unattributed: refused');
  assert.ok(!hidden('btnGigahostAssociationConfirm'), 'the confirmation stayed hidden with rows to associate');
  assert.ok(!hidden('gigahostAssociationUnlistedChoice'), 'the unlisted choice stayed hidden with an unlisted row');

  // 4. Choosing the unlisted rows re-renders the same preview, with no second read.
  const checkbox = w.document.getElementById('gigahostAssociationIncludeUnlisted');
  checkbox.checked = true;
  checkbox.dispatchEvent(new w.Event('change'));
  assert.equal(byMethod('GET').length, 1, 'changing the choice re-read the provider');
  assert.equal(text('gigahostAssociationOutcome'), '2 of 3 can be associated 1 are no longer listed 1 unattributed: refused');

  // 5. The confirmation posts exactly the choice the administrator made.
  click('btnGigahostAssociationConfirm');
  await flush();
  assert.equal(byMethod('POST').length, 1);
  assert.equal(byMethod('POST')[0].url, '/api/admin/hosting/gigahost/account-association');
  assert.deepEqual(byMethod('POST')[0].body, {preview_id: 'preview-1', include_unlisted: true});
  assert.equal(text('gigahostAssociationOutcome'), '2 associated 1 will be marked deleted next 1 unattributed: unnamed');
  assert.ok(hidden('btnGigahostAssociationConfirm'), 'the confirmation is still offered after the action ran');
  assert.ok(hidden('gigahostAssociationUnlistedChoice'), 'the choice is still offered after the action ran');
  assert.strictEqual(checkbox.checked, false, 'the spent unlisted consent is left checked');

  // 5b. A fresh preview never inherits the previous opt-in: that consent was given
  //     for counts the new screen has replaced, and carrying it forward would
  //     re-authorise the absent-marking consequence without a fresh answer.
  click('btnGigahostAssociationPreview');
  await flush();
  checkbox.checked = true;
  checkbox.dispatchEvent(new w.Event('change'));
  assert.strictEqual(checkbox.checked, true, 'the operator opt-in did not stick to its own preview');
  click('btnGigahostAssociationPreview');
  await flush();
  assert.strictEqual(checkbox.checked, false, 'a fresh preview kept the previous opt-in');
  assert.ok(!hidden('gigahostAssociationUnlistedChoice'), 'the fresh preview hid the choice it should offer');
  const postsBeforeSecondConfirm = byMethod('POST').length;
  click('btnGigahostAssociationConfirm');
  await flush();
  assert.equal(byMethod('POST').length, postsBeforeSecondConfirm + 1, 'the fresh preview offered no confirmation');
  assert.deepEqual(byMethod('POST').slice(-1)[0].body,
    {preview_id: 'preview-1', include_unlisted: false},
    'a fresh preview posted the previous opt-in');

  // 6. Two requests must not overlap. The guard is asserted through the controller
  //    entry point itself, because the button also carries a disabled state that
  //    would hide a missing guard from a click-only test.
  let release;
  const beforeGuard = byMethod('GET').length;
  holdNext = new Promise(res => { release = res; });
  w.runGigahostAssociationPreview(state);
  w.runGigahostAssociationPreview(state);
  await flush();
  assert.equal(byMethod('GET').length, beforeGuard + 1, 'the in-flight guard issued a second request');
  release();
  await flush();
  assert.equal(byMethod('GET').length, beforeGuard + 1);

  // 6b. The same protection at the control: a second click while the request is open
  //     issues nothing.
  holdNext = new Promise(res => { release = res; });
  const beforeClick = byMethod('GET').length;
  click('btnGigahostAssociationPreview');
  click('btnGigahostAssociationPreview');
  await flush();
  assert.equal(byMethod('GET').length, beforeClick + 1, 'a second click during an open request issued another request');
  release();
  await flush();

  // 7. A refused request is reported as a failure, and no confirmation is offered.
  failNext = 'provider unavailable';
  click('btnGigahostAssociationPreview');
  await flush();
  assert.equal(text('gigahostAssociationOutcome'), 'failed: provider unavailable');
  assert.ok(hidden('btnGigahostAssociationConfirm'), 'a failed check offered the confirmation');

  // 8. A refused action is reported as a failure too, and is never rendered as an
  //    outcome count.
  w.document.getElementById('gigahostAssociationIncludeUnlisted').checked = false;
  click('btnGigahostAssociationPreview');
  await flush();
  failNext = 'write refused';
  click('btnGigahostAssociationConfirm');
  await flush();
  assert.equal(text('gigahostAssociationOutcome'), 'failed: write refused');
  assert.deepEqual(byMethod('POST').slice(-1)[0].body, {preview_id: 'preview-1', include_unlisted: false});

  // 9. An empty plan offers nothing to confirm and says so.
  w.API.get = async url => {
    calls.push({method:'GET', url});
    return {candidates: 0, attributable: 0, unlisted: 0, unattributed: 0, already_bound: 5, reasons: []};
  };
  click('btnGigahostAssociationPreview');
  await flush();
  assert.equal(text('gigahostAssociationOutcome'), 'nothing-to-associate');
  assert.ok(hidden('btnGigahostAssociationConfirm'), 'an empty plan offered the confirmation');

  // 10. Initialising twice does not bind the controls twice: one click, one request.
  const before = byMethod('GET').length;
  w.initGigahostAssociation();
  click('btnGigahostAssociationPreview');
  await flush();
  assert.equal(byMethod('GET').length, before + 1);

  console.log('ASSOCIATION_CONTROLLER_OK');
  dom.window.close();
})().catch(err => { console.log('ASSOCIATION_CONTROLLER_FAILED: ' + err.message); process.exit(1); });
`, string(encodedSection), string(encodedModule))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "ASSOCIATION_CONTROLLER_OK") {
		t.Fatalf("association controller check failed: %v\n%s", err, out)
	}
}
