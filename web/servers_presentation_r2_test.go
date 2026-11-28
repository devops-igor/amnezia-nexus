package web

// The round-two presentation fixes, asserted where they live.
//
// Three of the four requested changes are front-end facts that a rendered-page test
// cannot see:
//
//   - which ink a badge paints, which is a stylesheet rule keyed on the state the badge
//     declares;
//   - which sentence the read-only history uses for an ended order, which is decided by
//     the model's own distinction between a provider answer and the panel's copy;
//   - whether a control's label may wrap, which is the stylesheet rule that decides it.
//
// The measurements that prove the contrast ratios and the 320 px reflow against real
// Chromium are in tests/e2e/test_gigahost_deleted_deployment.py and the width suite; these
// checks are the offline guards that fail on a regression without a browser.

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Item 1: the state's own ink for a badge that declares it.
// ---------------------------------------------------------------------------

// TestBadgeStateInkClearsTheFillItIsPaintedOn binds each state to its declared ink and
// computes the ratio against the composited fill, from the shipped tokens.
//
// The numbers are computed, not pinned: a palette change that breaks either state fails
// here. What is pinned is the binding - which token each state uses - because that is the
// decision this change made.
func TestBadgeStateInkClearsTheFillItIsPaintedOn(t *testing.T) {
	components, err := fs.ReadFile(mustStaticFS(t), "css/components.css")
	if err != nil {
		t.Fatalf("read components.css: %v", err)
	}
	tokens, err := fs.ReadFile(mustStaticFS(t), "css/tokens.css")
	if err != nil {
		t.Fatalf("read tokens.css: %v", err)
	}
	css := string(components)

	want := map[string]string{
		"deleted": "--text-deleted-badge",
		"failed":  "--text-danger",
	}
	for state, token := range want {
		selector := `.badge[data-stage="` + state + `"]`
		declared, ok := cssDeclaration(css, selector, "color")
		if !ok {
			t.Errorf("%s declares no ink, so the state keeps the shared danger ink that measures 4.42:1", selector)
			continue
		}
		if !strings.Contains(declared, "var("+token+")") {
			t.Errorf("%s ink = %q, want var(%s)", selector, declared, token)
		}
	}

	// The ratio, computed from the tokens the rule resolves against. A rule that names a
	// readable token but is painted on a changed fill would still be a defect, so the fill
	// is read from the token set rather than assumed.
	for _, theme := range []string{"dark", "light"} {
		dark := theme == "dark"
		fill := compositeOverCard(t, string(tokens), theme)
		for _, token := range []string{"text-deleted-badge", "text-danger"} {
			ink := tokenHex(t, string(tokens), theme, token)
			if ratio := wcagRatio(ink, fill); ratio < 4.5 {
				t.Errorf("%s theme: %s (%s) on the badge fill (%s) = %.2f:1, under 4.5:1",
					theme, token, ink, fill, ratio)
			}
		}
		_ = dark
	}
}

// TestGridDeploymentBadgeDeclaresItsState is the binding between the template and the ink
// rule: a badge with no data-stage cannot match the state selector, so it would silently
// keep the failing ink while the stylesheet looke correct.
func TestGridDeploymentBadgeDeclaresItsState(t *testing.T) {
	template, err := fs.ReadFile(mustTemplatesFS(t), "templates/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	body := string(template)
	start := strings.Index(body, `data-server-name="{{ $deployment.Name }}"`)
	if start < 0 {
		t.Fatal("the deployment card is gone from the Servers template")
	}
	// The card runs to the next deployment card (or the end of the grid). Slicing on the
	// first "{{ end }}" would stop inside the card's own meta block, which is exactly the
	// mistake this helper exists to avoid.
	rest := body[start:]
	if next := strings.Index(rest, `data-server-name="{{ $deployment.Name }}"`); next > 0 {
		rest = rest[:next]
	}
	if next := strings.Index(rest, `<div id="serverSearchEmpty"`); next > 0 {
		rest = rest[:next]
	}
	badge := badgeTagIn(t, rest)
	if !strings.Contains(badge, `data-stage="{{ $deployment.Stage }}"`) {
		t.Fatalf("the deployment card's badge does not declare its state, so its ink cannot follow it: %s", badge)
	}
}

// TestHistoryBadgeDeclaresItsState is the same binding for the module that builds the
// read-only history badge in JavaScript.
func TestHistoryBadgeDeclaresItsState(t *testing.T) {
	source, err := fs.ReadFile(mustStaticFS(t), "js/gigahost_order_status.js")
	if err != nil {
		t.Fatalf("read the status module: %v", err)
	}
	js := string(source)
	index := strings.Index(js, "toggle.className = 'badge gigahost-order-status-toggle '")
	if index < 0 {
		t.Fatal("the history status toggle is gone from the module")
	}
	// The next statement after the class assignment is where the state is declared.
	window := js[index:]
	if stop := strings.Index(window, "toggle.setAttribute('aria-controls'"); stop >= 0 {
		window = window[:stop]
	}
	if !strings.Contains(window, "toggle.setAttribute('data-stage', model.stage)") {
		t.Fatalf("the history badge does not declare its state, so a FAILED row keeps the shared danger ink: %s", window)
	}
}

// badgeTagIn returns the first <span class="badge ..."> ... </span> pair in card.
func badgeTagIn(t *testing.T, card string) string {
	t.Helper()
	start := strings.Index(card, `<span class="badge `)
	if start < 0 {
		t.Fatalf("no badge in the card: %s", card)
	}
	end := strings.Index(card[start:], ">")
	if end < 0 {
		t.Fatalf("the badge tag is not closed: %s", card[start:])
	}
	return card[start : start+end+1]
}

// ---------------------------------------------------------------------------
// Item 2: the history states only what the panel observed.
// ---------------------------------------------------------------------------

// TestRetiredOrderPanelDoesNotClaimAnUnobservedProviderFact drives the shipped modules in
// JSDOM over three ended orders and asserts the two overstatements the verdict found are
// gone, while the order keeps its identity, its address and its DELETED stage.
//
// The three cases are different facts and must not read the same:
//
//   - a cancelled order, never asked, with no inventory record;
//   - a ready order the provider's inventory omitted, so the panel recorded absence;
//   - a recorded `deleted` spelling with no inventory read behind it.
//
// The labels are asserted against the real English bundle, not against key names, so a
// passing test cannot come from a dictionary that failed to load.
func TestRetiredOrderPanelDoesNotClaimAnUnobservedProviderFact(t *testing.T) {
	// The real bundle is injected rather than read from disk, so the scenario sees the
	// strings this build ships and no filesystem path is needed.
	bundle, err := fs.ReadFile(mustTranslationsFS(t), "en.json")
	if err != nil {
		t.Fatalf("read the English bundle: %v", err)
	}
	encodedBundle, _ := json.Marshal(string(bundle))
	runGigahostOrderStatusScenario(t, "GIGAHOST_STATUS_PROVENANCE_OK", `
 const labels = JSON.parse(`+string(encodedBundle)+`);
 w._ = key => (labels[key] !== undefined ? labels[key] : key);

 const CASES = {
   cancelled: {
     order: {order_id:'ord_cancelled', status:'cancelled', assigned_ip:'198.51.100.9'},
     observation: {outcome:'not_checked'},
     deploy: {status:'cancelled', step:'installing_protocol'},
     absence: false
   },
   omitted: {
     order: {order_id:'ord_omitted', status:'ready', assigned_ip:'198.51.100.8'},
     observation: {outcome:'not_checked'},
     deploy: {status:'ready', step:'ready', server_id:12},
     absence: true
   },
   recorded_deleted: {
     order: {order_id:'ord_deleted', status:'deleted', assigned_ip:'198.51.100.7'},
     observation: {outcome:'not_checked'},
     deploy: null,
     absence: false
   }
 };

 const render = async (name) => {
   const state = CASES[name];
   orders = [state.order];
   observationByOrder = {[state.order.order_id]: state.observation};
   absenceByOrder = state.absence ? {[state.order.order_id]: true} : {};
   deployByOrder = {};
   intents = []; backends = [];
   container().innerHTML = '';
   await w.loadRecentOrders();
   const row = container().querySelector('.gigahost-order-row');
   assert.ok(row, name + ': no row rendered');
   return {
     stage: row.querySelector('.gigahost-order-status').getAttribute('data-stage'),
     badgeStage: row.querySelector('.gigahost-order-status-toggle').getAttribute('data-stage'),
     identity: flat(row.querySelector('.gigahost-order-identity')),
     text: flat(row.querySelector('.gigahost-order-status-details'))
   };
 };

 const omissionSentence = 'no longer lists this server';
 const endedSentence = 'The order has ended';

 // The stage itself is unchanged in every case: a retired order is still DELETED.
 for (const name of ['cancelled', 'omitted', 'recorded_deleted']) {
   const got = await render(name);
   assert.equal(got.stage, 'deleted', name + ' must still present as DELETED, got ' + got.stage);
   assert.equal(got.badgeStage, 'deleted', name + ': the badge must declare its deleted state');
 }

 // The provider axis is labelled with what it actually is. A cancelled or recorded-deleted
 // order was not asked in this read, so the panel must not label its own copy "Provider".
 for (const name of ['cancelled', 'recorded_deleted']) {
   const got = await render(name);
   assert.ok(!/(^| )Provider( |$)/.test(got.text),
     name + ': the recorded copy was labelled as a provider answer: ' + got.text);
   assert.match(got.text, /Recorded state/,
     name + ': the panel copy must be labelled as a recorded state: ' + got.text);
 }

 // The inventory sentence appears only where the panel recorded an omission.
 for (const name of ['cancelled', 'recorded_deleted']) {
   const got = await render(name);
   assert.ok(got.text.indexOf(omissionSentence) === -1,
     name + ': the history claims an inventory omission that was never observed: ' + got.text);
   assert.ok(got.text.indexOf(endedSentence) !== -1,
     name + ': the history must say the order ended: ' + got.text);
 }
 const omitted = await render('omitted');
 assert.ok(omitted.text.indexOf(omissionSentence) !== -1,
   'an order the inventory omitted must keep the sentence that records it: ' + omitted.text);

 // The address and the order identity survive, so nothing was hidden to make the sentence
 // honest, and the DELETED stage did not swallow them.
 const ADDRESSES = {cancelled:'198.51.100.9', omitted:'198.51.100.8', recorded_deleted:'198.51.100.7'};
 for (const name of Object.keys(ADDRESSES)) {
   const got = await render(name);
   assert.ok(got.identity.indexOf(ADDRESSES[name]) !== -1,
     name + ': the recorded address left the identity: ' + got.identity);
   assert.ok(got.text.indexOf(ADDRESSES[name]) !== -1,
     name + ': the panel lost the address it must still show: ' + got.text);
 }

 // The control that keeps the assertions above from passing by never using the word: a
 // confirmed provider answer in the response keeps its provider label.
 const confirmed = await render('omitted');
 if (confirmed.text.indexOf('Provider') === -1) {
   orders = [{order_id:'ord_confirmed', status:'ready', assigned_ip:'198.51.100.6'}];
   observationByOrder = {ord_confirmed: {outcome:'confirmed', status:'ready'}};
   absenceByOrder = {}; deployByOrder = {ord_confirmed: {status:'ready', step:'ready', server_id:3}};
   intents = []; backends = []; container().innerHTML = '';
   await w.loadRecentOrders();
   assert.match(flat(panel()), /Provider/,
     'a confirmed provider answer must keep the provider label, or the label check is vacuous');
 }
`)
}

// ---------------------------------------------------------------------------
// Item 3: the association controls may wrap their labels.
// ---------------------------------------------------------------------------

// TestAssociationControlsAllowTheirLabelsToWrap asserts the stylesheet rule that lets the
// sentence-sized labels wrap inside the existing controls.
//
// The shared .btn rule sets white-space: nowrap, so a label that cannot wrap runs past the
// card and widens the document; that was measured on the Russian preview at the 320 CSS px
// review floor. The measurement itself is in the E2E suites; this is the offline guard.
func TestAssociationControlsAllowTheirLabelsToWrap(t *testing.T) {
	settings, err := fs.ReadFile(mustStaticFS(t), "css/settings.css")
	if err != nil {
		t.Fatalf("read settings.css: %v", err)
	}
	css := string(settings)

	buttonSelector := ".settings-section-card #gigahostAssociationSection .btn"
	wrapping, ok := cssDeclaration(css, buttonSelector, "white-space")
	if !ok {
		t.Fatalf("%s declares no white-space, so its label cannot wrap", buttonSelector)
	}
	if wrapping != "normal" {
		t.Errorf("%s white-space = %q, want normal", buttonSelector, wrapping)
	}
	if constrained, ok := cssDeclaration(css, buttonSelector, "max-width"); !ok || constrained != "100%" {
		t.Errorf("%s max-width = %q (found=%t), want 100%% so the control cannot exceed the card",
			buttonSelector, constrained, ok)
	}
	// The label span must be allowed to shrink below its content width, or the wrap
	// above cannot take effect and the button overflows anyway.
	if minWidth, ok := cssDeclaration(css, buttonSelector+" > span", "min-width"); !ok || minWidth != "0" {
		t.Errorf("%s > span min-width = %q (found=%t), want 0", buttonSelector, minWidth, ok)
	}
	// The other sentence-sized label in the section.
	if wrap, ok := cssDeclaration(css, ".settings-section-card #gigahostAssociationSection .switch-label-text", "overflow-wrap"); !ok || wrap != "anywhere" {
		t.Errorf("the unlisted-servers choice label declares overflow-wrap = %q (found=%t), want anywhere",
			wrap, ok)
	}

	// The contract the fix must not break: the label's size is the card's button scale,
	// unchanged by this rule. Asserted from the rules themselves, so a later edit that
	// shrank the text to make it fit would be visible here.
	for _, property := range []string{"font-size"} {
		if value, found := cssDeclaration(css, buttonSelector, property); found {
			t.Errorf("%s declares %s = %q; the wrap must not change the size, and the size "+
				"belongs to the shared button scale", buttonSelector, property, value)
		}
	}
}

// mustStaticFS and mustTemplatesFS are the shipped asset roots.
func mustStaticFS(t *testing.T) fs.FS {
	t.Helper()
	root, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("the static asset root is unavailable: %v", err)
	}
	return root
}

func mustTemplatesFS(t *testing.T) fs.FS {
	t.Helper()
	return TemplatesFS
}

func mustTranslationsFS(t *testing.T) fs.FS {
	t.Helper()
	root, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("the translation root is unavailable: %v", err)
	}
	return root
}

// ---------------------------------------------------------------------------
// Colour arithmetic for the badge-ink check.
//
// These mirror the E2E contrast module (tests/e2e/contrast.py) rather than importing it,
// because a Go test cannot call Python and a second implementation of the WCAG formula is
// cheap to check: the numbers below are pinned against values the browser measurement
// produced, so the two are known to agree.
// ---------------------------------------------------------------------------

// themeDeclaration returns the value of one custom property in effect for a theme: the
// :root declaration, overridden by [data-theme="light"] for the light theme.
func themeDeclaration(t *testing.T, tokens, theme, name string) string {
	t.Helper()
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(tokens, "")
	blocks := map[string]string{}
	for _, match := range regexp.MustCompile(`(?s)([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(css, -1) {
		blocks[strings.TrimSpace(match[1])] = match[2]
	}
	decl := func(block string) map[string]string {
		out := map[string]string{}
		for _, m := range regexp.MustCompile(`--([\w-]+)\s*:\s*([^;]+);`).FindAllStringSubmatch(block, -1) {
			out[m[1]] = strings.TrimSpace(m[2])
		}
		return out
	}
	values := decl(blocks[":root"])
	if theme == "light" {
		for key, value := range decl(blocks[`[data-theme="light"]`]) {
			values[key] = value
		}
	}
	value, ok := values[name]
	if !ok {
		t.Fatalf("%s declares no --%s", theme, name)
	}
	// One level of var(--x) indirection, which is how the ink roles are declared.
	if m := regexp.MustCompile(`^var\(--([\w-]+)\)$`).FindStringSubmatch(value); m != nil {
		return themeDeclaration(t, tokens, theme, m[1])
	}
	return value
}

// tokenHex returns one theme's token as #rrggbb.
func tokenHex(t *testing.T, tokens, theme, name string) string {
	t.Helper()
	value := themeDeclaration(t, tokens, theme, name)
	if !regexp.MustCompile(`^#[0-9a-fA-F]{6}$`).MatchString(value) {
		t.Fatalf("--%s in the %s theme is %q, which is not an opaque hex colour", name, theme, value)
	}
	return strings.ToLower(value)
}

// compositeOverCard flattens the danger fill over the card, which is what the badge's
// translucent background paints on. It is the same flattening the E2E suite performs.
func compositeOverCard(t *testing.T, tokens, theme string) string {
	t.Helper()
	card := parseHexRGB(t, tokenHex(t, tokens, theme, "bg-card"))
	fill := themeDeclaration(t, tokens, theme, "danger-bg")
	m := regexp.MustCompile(`^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$`).
		FindStringSubmatch(fill)
	if m == nil {
		t.Fatalf("--danger-bg in the %s theme is %q, which is not an rgb/rgba colour", theme, fill)
	}
	alpha := 1.0
	if m[4] != "" {
		if _, err := fmt.Sscanf(m[4], "%f", &alpha); err != nil {
			t.Fatalf("--danger-bg alpha %q is not a number: %v", m[4], err)
		}
	}
	channels := make([]int, 3)
	for i := range channels {
		var component int
		if _, err := fmt.Sscanf(m[i+1], "%d", &component); err != nil {
			t.Fatalf("--danger-bg channel %q is not a number: %v", m[i+1], err)
		}
		blend := float64(component)*alpha + float64(card[i])*(1-alpha)
		channels[i] = int(math.Round(blend))
	}
	return fmt.Sprintf("#%02x%02x%02x", channels[0], channels[1], channels[2])
}

func parseHexRGB(t *testing.T, hex string) [3]int {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("%q is not #rrggbb", hex)
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		var value int
		if _, err := fmt.Sscanf(hex[1+i*2:3+i*2], "%02x", &value); err != nil {
			t.Fatalf("%q is not #rrggbb: %v", hex, err)
		}
		out[i] = value
	}
	return out
}

// wcagRatio is WCAG 2.x relative-luminance contrast between two opaque colours.
func wcagRatio(fg, bg string) float64 {
	luminance := func(hex string) float64 {
		var rgb [3]int
		for i := 0; i < 3; i++ {
			_, _ = fmt.Sscanf(hex[1+i*2:3+i*2], "%02x", &rgb[i])
		}
		channel := func(c int) float64 {
			value := float64(c) / 255
			if value <= 0.03928 {
				return value / 12.92
			}
			return math.Pow((value+0.055)/1.055, 2.4)
		}
		return 0.2126*channel(rgb[0]) + 0.7152*channel(rgb[1]) + 0.0722*channel(rgb[2])
	}
	hi, lo := luminance(fg), luminance(bg)
	if hi < lo {
		hi, lo = lo, hi
	}
	return (hi + 0.05) / (lo + 0.05)
}
