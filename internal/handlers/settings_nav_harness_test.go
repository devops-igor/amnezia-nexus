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
if (navLinks.length !== 4) throw new Error('expected four group links, got ' + navLinks.length);
for (const link of navLinks) {
  const href = link.getAttribute('href') || '';
  if (href.charAt(0) !== '#') throw new Error('link is not an in-page anchor: ' + href);
  if (!doc.getElementById(href.slice(1))) throw new Error('link points at nothing: ' + href);
  if (!link.textContent.trim()) throw new Error('link has no text: ' + href);
}

// The groups the page actually renders, in document order.
const groupEls = Array.from(doc.querySelectorAll('.settings-group'));
if (groupEls.length !== 4) throw new Error('expected four groups, got ' + groupEls.length);

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
setTops({'group-portal': 0, 'group-notifications': 1200, 'group-network': 2600, 'group-system': 3800});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-portal', 'the first mark', 2000);
if (doc.querySelector('a[href="#group-portal"]').getAttribute('aria-current') !== 'true') {
  throw new Error('the current link is not the one whose group is in view');
}

// A group whose heading is on the settle line counts as in view: following its
// own link lands it there, and the scroll position that produces it is fractional
// (a smooth scroll settles on a sub-pixel offset), so a comparison against the
// exact value would leave the previous group marked after the jump.
setTops({'group-portal': -2400, 'group-notifications': -1200, 'group-network': -100, 'group-system': 88.4});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-system', 'the exact-hit mark', 2000);

// Scrolled into the network group: that group is current, and the first one is
// no longer marked, so the state never accumulates.
setTops({'group-portal': -2400, 'group-notifications': -1200, 'group-network': -100, 'group-system': 900});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-network', 'the network mark', 2000);
if (doc.querySelector('a[href="#group-portal"]').hasAttribute('aria-current')) {
  throw new Error('the previous group stayed marked');
}

// Activating a link marks its group at once, before the page has travelled there.
// The marker must follow the reader's choice rather than the pixels the scroll has
// not reached: otherwise the previous group stays marked for the whole animation,
// which is what a browser test saw when it read the state mid-scroll.
setTops({'group-portal': 0, 'group-notifications': 1200, 'group-network': 2600, 'group-system': 3800});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-portal', 'the reset mark', 2000);
doc.querySelector('a[href="#group-network"]').click();
if (marked().length !== 1 || marked()[0] !== '#group-network') {
  throw new Error('activating a link left the marker on ' + marked().join(',') +
    ' while the page had not scrolled to it');
}

// Once the page has arrived, the geometry agrees and the marker is unchanged.
setTops({'group-portal': -2400, 'group-notifications': -1200, 'group-network': 88, 'group-system': 900});
scroll();
await until(() => marked().length === 1 && marked()[0] === '#group-network', 'the arrival mark', 2000);

// Following a link moves focus to the group's own heading, not to the next link.
const network = doc.querySelector('a[href="#group-network"]');
network.click();
await until(() => doc.activeElement && doc.activeElement.id === 'group-network-title',
  'focus to move into the group', 2000);
if (doc.activeElement.tagName !== 'H2') throw new Error('focus landed on ' + doc.activeElement.tagName);
if (doc.activeElement.getAttribute('tabindex') !== '-1') {
  throw new Error('the focused heading is not the programmatic focus target');
}

// The same handoff for a link the reader reaches a second time, so an inspect
// action cannot close what it was asked to reveal.
network.click();
await sleep(50);
if (!doc.activeElement || doc.activeElement.id !== 'group-network-title') {
  throw new Error('a repeated follow moved focus away from the heading');
}
`)

	if !strings.Contains(out, "SETTINGS_SCENARIO_OK") {
		t.Fatalf("the scenario did not run to completion:\n%s", out)
	}
}

// TestSettingsNavIsAbsentForARoleWithoutTheNetworkGroup covers the other half of
// SET2-07: a role that renders no Network policy group must not be offered a link
// to it, because that link would have no target.
func TestSettingsNavIsAbsentForARoleWithoutTheNetworkGroup(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	page := renderSettingsPageFor(t, h, models.RoleSupport)

	if strings.Contains(page, `href="#group-network"`) {
		t.Error("the support page links to the Network policy group, which it does not render")
	}
	if !strings.Contains(page, `href="#group-portal"`) || !strings.Contains(page, `href="#group-system"`) {
		t.Error("the support page does not link the groups it does render")
	}
	if strings.Contains(page, `id="group-network"`) {
		t.Error("the support page renders the admin-only group")
	}
}
