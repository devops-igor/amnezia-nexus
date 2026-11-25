package handlers

// Behaviour of the Settings page's in-page navigation (#887, grouped page).
//
// The page is rendered by the real handler and its scripts run in JSDOM, so this
// exercises the controller the browser runs rather than a copy of its logic. The
// one thing JSDOM cannot provide is layout: every element reports a zero-sized
// rectangle. The scenario therefore supplies the group geometry it wants to test
// (the same rectangles a browser would report for a scrolled page) and dispatches
// the real scroll event, so the assertion is about the marking rule and not about
// a stubbed copy of it. The browser measurement of the same acceptance criteria
// is recorded in the round's handover, because geometry itself is not what JSDOM
// can prove.

import (
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// TestSettingsNavMarksTheGroupInView covers SET2-07 (the sub-navigation exists,
// names the groups and every link resolves), SET2-08 (exactly one link is current
// and it follows the scroll position) and SET2-09 (following a link moves focus
// to the group's heading).
func TestSettingsNavMarksTheGroupInView(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	out := runSettingsScenario(t, h, `
const nav = doc.getElementById('settingsSubnav');
if (!nav) throw new Error('the page has no sub-navigation');
if (!nav.closest('main')) throw new Error('the sub-navigation is not inside main');
const navLabel = (nav.getAttribute('aria-label') || '').trim();
if (!navLabel) throw new Error('the sub-navigation has no accessible name');
const navLinks = Array.from(nav.querySelectorAll('a'));
if (navLinks.length !== 3) throw new Error('expected three group links, got ' + navLinks.length);
for (const link of navLinks) {
  const href = link.getAttribute('href') || '';
  if (href.charAt(0) !== '#') throw new Error('link is not an in-page anchor: ' + href);
  if (!doc.getElementById(href.slice(1))) throw new Error('link points at nothing: ' + href);
  if (!link.textContent.trim()) throw new Error('link has no text: ' + href);
}

// The groups the page actually renders, in document order.
const groupEls = Array.from(doc.querySelectorAll('.settings-group'));
if (groupEls.length !== 3) throw new Error('expected three groups, got ' + groupEls.length);

// Layout is what a browser supplies; JSDOM reports zero for every rectangle.
// setTops gives each group the top edge the scrolled page would have.
function setTops(tops) {
  groupEls.forEach(g => {
    const top = Object.prototype.hasOwnProperty.call(tops, g.id) ? tops[g.id] : 50000;
    g.getBoundingClientRect = () => ({
      top: top, bottom: top + 400, left: 0, right: 1000,
      width: 1000, height: 400, x: 0, y: top
    });
  });
}
function scroll() {
  w.dispatchEvent(new w.Event('scroll'));
}
function marked() {
  return Array.from(doc.querySelectorAll('[aria-current="true"]')).map(a => a.getAttribute('href'));
}
function current() {
  const hrefs = marked();
  if (hrefs.length !== 1) {
    throw new Error('expected exactly one current link, found ' + hrefs.length + ' (' + hrefs.join(',') + ')');
  }
  return hrefs[0];
}

// At the top of the page the first group is the one in view.
setTops({'group-portal': 0, 'group-notifications': 1200, 'group-system': 2600});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-portal', 'the first mark', 2000);
if (doc.querySelector('a[href="#group-portal"]').getAttribute('aria-current') !== 'true') {
  throw new Error('the current link is not the one whose group is in view');
}

// A group whose heading is on the settle line counts as in view: following its
// own link lands it there, and the scroll position that produces it is fractional
// (a smooth scroll settles on a sub-pixel offset), so a comparison against the
// exact value would leave the previous group marked after the jump.
setTops({'group-portal': -2400, 'group-notifications': -1200, 'group-system': 88.4});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-system', 'the exact-hit mark', 2000);

// Scrolled into the last group: that group is current, and the first one is no
// longer marked, so the state never accumulates.
setTops({'group-portal': -2400, 'group-notifications': -1200, 'group-system': 900});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-system', 'the last group mark', 2000);
if (doc.querySelector('a[href="#group-portal"]').hasAttribute('aria-current')) {
  throw new Error('the previous group stayed marked');
}

// Following a link moves focus to the group's own heading, not to the next link.
const system = doc.querySelector('a[href="#group-system"]');
system.click();
await until(() => doc.activeElement && doc.activeElement.id === 'group-system-title',
  'focus to move into the group', 2000);
if (doc.activeElement.tagName !== 'H2') throw new Error('focus landed on ' + doc.activeElement.tagName);
if (doc.activeElement.getAttribute('tabindex') !== '-1') {
  throw new Error('the focused heading is not the programmatic focus target');
}

// The same handoff for a link the reader reaches a second time, so an inspect
// action cannot close what it was asked to reveal.
system.click();
await sleep(50);
if (!doc.activeElement || doc.activeElement.id !== 'group-system-title') {
  throw new Error('a repeated follow moved focus away from the heading');
}
`)

	if !strings.Contains(out, "SETTINGS_SCENARIO_OK") {
		t.Fatalf("the scenario did not run to completion:\n%s", out)
	}
}

// TestSettingsNavHasNoLinkToTheMovedGroup covers the other half of SET2-07 for the
// policy surface: the group it used to point at does not render for any role, so no
// link may point at it — a navigation entry whose target does not exist is a dead
// end, and one left behind is how a reader concludes the surface simply vanished.
// The durable route to it is the sidebar's Routing entry.
func TestSettingsNavHasNoLinkToTheMovedGroup(t *testing.T) {
	for _, role := range []models.UserRole{models.RoleAdmin, models.RoleSupport} {
		t.Run(string(role), func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			page := renderSettingsPageFor(t, h, role)

			for _, gone := range []string{`href="#group-network"`, `href="#group-network-title"`, `id="group-network"`} {
				if strings.Contains(page, gone) {
					t.Errorf("%s's settings page still carries %q", role, gone)
				}
			}
			if !strings.Contains(page, `href="#group-portal"`) || !strings.Contains(page, `href="#group-system"`) {
				t.Error("the settings page does not link the groups it does render")
			}
			if role == models.RoleAdmin && !strings.Contains(page, `href="/routing"`) {
				t.Error("the settings page offers no route to the surface that moved")
			}
		})
	}
}

// TestSettingsLegacyPolicyFragmentsHandOff pins the bookmark contract for the
// anchors the policy surface used to have here (#987). The hook is driven with a
// location stub, which is what lets every case be stated in one run: the four
// allowed fragments replace the document with a fixed same-origin path, every other
// Settings hash is left to the browser, and the hook only acts on this document.
//
// Whether the browser then really lands on /routing, and whether Back returns to
// the page the reader came from rather than bouncing, is geometry and history —
// neither is JSDOM's to prove. The Chromium suite
// (tests/e2e/test_settings_navigation.py) asserts that half against the real
// navigation.
func TestSettingsLegacyPolicyFragmentsHandOff(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	out := runSettingsScenario(t, h, `
const nav = w.SettingsNav;
if (!nav || typeof nav.handOffLegacyFragment !== 'function') {
  throw new Error('the handoff hook is not exported');
}

// What the browser would tell the hook, and what the hook does with it. assign is
// recorded as well, so a hook that pushed a history entry instead of replacing one
// is caught: that is the shape that makes Back bounce.
function stub(pathname, hash) {
  const calls = {replace: [], assign: []};
  const loc = {
    pathname: pathname,
    hash: hash,
    replace(u) { calls.replace.push(u); },
    assign(u) { calls.assign.push(u); }
  };
  return {loc, calls};
}

function check(pathname, hash, wantHandled, wantTarget) {
  const s = stub(pathname, hash);
  const handled = nav.handOffLegacyFragment(s.loc);
  const label = pathname + (hash || '(no hash)');
  if (handled !== wantHandled) throw new Error(label + ' handled=' + handled + ', want ' + wantHandled);
  if (wantHandled) {
    if (s.calls.replace.length !== 1) {
      throw new Error(label + ' made ' + s.calls.replace.length + ' replace calls, want exactly 1');
    }
    if (s.calls.replace[0] !== wantTarget) {
      throw new Error(label + ' replaced the document with ' + s.calls.replace[0] + ', want ' + wantTarget);
    }
    if (s.calls.assign.length !== 0) {
      throw new Error(label + ' pushed a history entry instead of replacing it');
    }
    // The target is one of the fixed literals, never built from the fragment.
    if (wantTarget.indexOf('#') === 0) throw new Error('the handoff target is derived from the hash');
  } else {
    if (s.calls.replace.length !== 0) {
      throw new Error(label + ' was sent to ' + s.calls.replace[0] + ' although it is not an old policy anchor');
    }
    if (s.calls.assign.length !== 0) throw new Error(label + ' navigated unexpectedly');
  }
}

// The four allowed fragments, each on its own literal target. The group fragment is
// consumed rather than forwarded: the group does not exist on the new page.
check('/settings', '#group-network', true, '/routing');
check('/settings', '#group-network-title', true, '/routing');
check('/settings', '#policyRoutingCard', true, '/routing#policyRoutingCard');
check('/settings', '#policyClientCard', true, '/routing#policyClientCard');

// Ordinary group anchors, an empty hash and unknown fragments keep the reader here.
for (const ordinary of ['#group-portal', '#group-notifications', '#group-system',
                        '#policy_enabled', '#routing', '']) {
  check('/settings', ordinary, false);
}

// The hook is Settings-only: the same fragment on another page is not a redirect,
// so a page that happens to name a policy id is never sent somewhere else.
check('/vpn', '#group-network', false);
check('/routing', '#policyRoutingCard', false);
`)
	if !strings.Contains(out, "SETTINGS_SCENARIO_OK") {
		t.Fatalf("the handoff scenario did not run to completion:\n%s", out)
	}
}

// TestSettingsHandoffRunsBeforeThePageSettles pins the wiring: the check is called
// once at parse time, so a bookmarked fragment is on its way before the reader can
// act on the page, and once from the hashchange listener, so changing the fragment on
// an open Settings page hands off too. Both call sites pass the window's own
// location; neither builds a URL from the fragment.
func TestSettingsHandoffRunsBeforeThePageSettles(t *testing.T) {
	source, err := web.StaticFS.ReadFile("static/js/settings_nav.js")
	if err != nil {
		t.Fatalf("read settings_nav.js: %v", err)
	}
	js := string(source)
	if got := strings.Count(js, "handOffLegacyFragment(root.location)"); got != 2 {
		t.Errorf("settings_nav.js calls the handoff %d times, want once at parse time and once on hashchange", got)
	}
	if !strings.Contains(js, "loc.replace(LEGACY_POLICY_FRAGMENTS[hash])") {
		t.Error("the handoff does not replace the document with the allowlisted constant")
	}
	if strings.Contains(js, "loc.replace(hash)") || strings.Contains(js, "loc.replace('#") {
		t.Error("the handoff derives its target from the fragment")
	}
}
