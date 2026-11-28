package web

import (
	"io/fs"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

// #1006 merged the three VPN documents back into one page at /vpn, so this file
// asserts the merge instead of the split it replaces:
//
//   - the single document carries all three sections in the approved order, and no
//     retired template is still shipped or still linked;
//   - the shell has exactly one VPN entry, marked current by the handler that
//     rendered the page;
//   - the retired child routes redirect into a section, proven by request;
//   - a fragment resolves locally to its owning section, with the old id families
//     and the dialog-opener mappings intact.

// vpnSectionMarkers names an id that only one section of the merged page owns.
var vpnSectionMarkers = map[string]string{
	"overview":    "vpn-signal-backends-value",
	"backends":    "vpnBackendsTable",
	"diagnostics": "vpnSessionsTable",
}

// TestVPNMergedPageRendersEverySection proves the one document carries all three
// sections, including the surfaces the split had put on separate pages.
func TestVPNMergedPageRendersEverySection(t *testing.T) {
	body, err := fs.ReadFile(TemplatesFS, "templates/vpn.html")
	if err != nil {
		t.Fatalf("read vpn.html: %v", err)
	}
	markup := string(body)
	for section, id := range vpnSectionMarkers {
		if !strings.Contains(markup, `id="`+id+`"`) {
			t.Errorf("vpn.html must render #%s, which belongs to %s", id, section)
		}
	}
	// The merger keeps every surface the three documents had; these are the ones a
	// reader would notice missing first.
	for _, id := range []string{
		"editEndpointModal", "vpn-configuration", "vpn-forwarder-card",
		"vpn-add-backend-btn", "addBackendModal", "vpn-advanced-entry",
		"vpn-diagnostics", "vpn-fwd-problem-list", "active-problems",
	} {
		if !strings.Contains(markup, `id="`+id+`"`) {
			t.Errorf("vpn.html must render #%s", id)
		}
	}
}

// TestVPNRetiredTemplatesAreGone proves the split's documents are not shipped: a
// template nobody renders but that still embeds two copies of the page is exactly
// the drift a later edit would keep alive.
func TestVPNRetiredTemplatesAreGone(t *testing.T) {
	for _, retired := range []string{"templates/vpn_backends.html", "templates/vpn_diagnostics.html"} {
		if _, err := fs.ReadFile(TemplatesFS, retired); err == nil {
			t.Errorf("%s is still shipped; the merged page is the only VPN template", retired)
		}
	}
}

// TestVPNMergedPageSectionOrder pins the approved order and the heading structure:
// one H1, three section H2s in document order, and the states the design fixes -
// the endpoint disclosure closed and the Advanced Diagnostics panel closed.
func TestVPNMergedPageSectionOrder(t *testing.T) {
	body, err := fs.ReadFile(TemplatesFS, "templates/vpn.html")
	if err != nil {
		t.Fatalf("read vpn.html: %v", err)
	}
	markup := string(body)
	if got := strings.Count(markup, "<h1 "); got != 1 {
		t.Errorf("vpn.html must have exactly one H1, found %d", got)
	}

	order := []string{`id="overview"`, `id="backends"`, `id="diagnostics"`}
	last := -1
	for _, marker := range order {
		i := strings.Index(markup, marker)
		if i < 0 {
			t.Fatalf("vpn.html must render %s", marker)
		}
		if i < last {
			t.Errorf("sections are out of order: %s appears before the section before it", marker)
		}
		last = i
	}

	// Both disclosures are closed on ordinary arrival, without script.
	if !strings.Contains(markup, `id="vpn-configuration"`) {
		t.Fatal("the endpoint disclosure must exist")
	}
	configOpen := strings.Contains(markup, `<details class="card vpn-config" id="vpn-configuration" open`)
	if configOpen {
		t.Error("the endpoint disclosure must be closed on arrival")
	}
	entryIdx := strings.Index(markup, `id="vpn-advanced-entry"`)
	if entryIdx < 0 {
		t.Fatal("the Advanced Diagnostics trigger must exist")
	}
	entryTag := markup[entryIdx:]
	if end := strings.Index(entryTag, ">"); end > 0 {
		entryTag = entryTag[:end]
	}
	if !strings.Contains(entryTag, `aria-expanded="false"`) {
		t.Errorf("the diagnostics trigger must default to aria-expanded=false: %s", entryTag)
	}
	if !strings.Contains(entryTag, `aria-controls="vpn-diagnostics"`) {
		t.Errorf("the diagnostics trigger must name the panel it controls: %s", entryTag)
	}
	if !strings.Contains(markup, `id="vpn-diagnostics" aria-labelledby="vpn-diagnostics-title" hidden`) {
		t.Error("the Advanced Diagnostics panel must be closed on arrival")
	}
}

// vpnNavLinks returns the sidebar/drawer anchors whose href begins with /vpn.
func vpnNavLinks(t *testing.T, doc *xhtml.Node) []*xhtml.Node {
	t.Helper()
	var links []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode && n.Data == "a" {
			if href := getHTMLNodeAttr(n, "href"); href == "/vpn" || strings.HasPrefix(href, "/vpn/") {
				links = append(links, n)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

func vpnNodeHasClass(n *xhtml.Node, class string) bool {
	for _, attr := range n.Attr {
		if attr.Key != "class" {
			continue
		}
		for _, c := range strings.Fields(attr.Val) {
			if c == class {
				return true
			}
		}
	}
	return false
}

// TestVPNMergedPageNavigationMarker proves the shell offers ONE VPN entry and
// marks it current, and that nothing in the shell links a retired child route.
func TestVPNMergedPageNavigationMarker(t *testing.T) {
	rendered := renderVPNPage(t, "vpn")
	doc, err := xhtml.Parse(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("parse rendered vpn: %v", err)
	}

	var sidebar, bottom []*xhtml.Node
	for _, link := range vpnNavLinks(t, doc) {
		href := getHTMLNodeAttr(link, "href")
		if href != "/vpn" {
			t.Errorf("the shell must not link the retired route %s", href)
		}
		if vpnNodeHasClass(link, "sidebar-nav-link") {
			sidebar = append(sidebar, link)
		}
		if vpnNodeHasClass(link, "bottom-bar-link") {
			bottom = append(bottom, link)
		}
	}
	if len(sidebar) != 1 {
		t.Fatalf("the sidebar must carry exactly one VPN entry, found %d", len(sidebar))
	}
	if !vpnNodeHasClass(sidebar[0], "active") {
		t.Error("the VPN sidebar entry must be current on /vpn")
	}
	if aria := getHTMLNodeAttr(sidebar[0], "aria-current"); aria != "page" {
		t.Errorf("the VPN sidebar entry must carry aria-current=page, got %q", aria)
	}
	// The entry is named by the shell's own VPN label, not by a section label: the
	// render uses a func map that echoes keys, so the key itself is the evidence.
	if !strings.Contains(rendered, `<span class="nav-label">nav_vpn</span>`) {
		t.Error("the single VPN sidebar entry must be labelled with nav_vpn")
	}
	if len(bottom) != 1 {
		t.Fatalf("the phone shortcut must carry exactly one VPN entry, found %d", len(bottom))
	}
}

// vpnLegacyFragmentCases walks the contract's id families: which section owns an
// id, and which id the landing should actually focus.
var vpnLegacyFragmentCases = []struct{ name, hash, section, target string }{
	// Overview-owned.
	{"overview heading", "#overview", "overview", "overview"},
	{"overview configuration", "#vpn-configuration", "overview", "vpn-configuration"},
	{"overview signal", "#vpn-sessions", "overview", "vpn-sessions"},
	{"overview listener", "#vpn-listen-port", "overview", "vpn-listen-port"},
	{"overview endpoint", "#vpn-public-endpoint", "overview", "vpn-public-endpoint"},
	{"overview endpoint dialog canonicalises to its opener", "#editEndpointModal", "overview", "vpn-edit-endpoint-btn"},
	{"health card", "#vpn-forwarder-card", "overview", "vpn-forwarder-card"},
	{"health heading", "#vpn-health-title", "overview", "vpn-health-title"},
	// Backends: the inventory, its table and the add dialog.
	{"backends heading", "#backends", "backends", "backends"},
	{"inventory heading", "#backends", "backends", "backends"},
	{"inventory table", "#vpnBackendsTable", "backends", "vpnBackendsTable"},
	{"inventory container", "#vpnTableContainer", "backends", "vpnTableContainer"},
	{"persistent add action", "#vpn-add-backend-btn", "backends", "vpn-add-backend-btn"},
	{"add modal canonicalises to its opener", "#addBackendModal", "backends", "vpn-add-backend-btn"},
	{"server select canonicalises to its opener", "#vpnServerSelect", "backends", "vpn-add-backend-btn"},
	{"loading row falls back to the heading", "#vpn-backends-loading", "backends", "backends"},
	// Diagnostics: problems, sessions and the disclosure.
	{"diagnostics heading", "#diagnostics", "diagnostics", "diagnostics"},
	{"active problems", "#active-problems", "diagnostics", "active-problems"},
	{"sessions heading", "#vpn-troubleshooting-title", "diagnostics", "vpn-troubleshooting-title"},
	{"sessions table", "#vpnSessionsTable", "diagnostics", "vpnSessionsTable"},
	{"sessions loading falls back to its heading", "#vpn-sessions-loading", "diagnostics", "vpn-troubleshooting-title"},
	{"disclosure entry", "#vpn-advanced-entry", "diagnostics", "vpn-advanced-entry"},
	{"disclosure itself", "#vpn-diagnostics", "diagnostics", "vpn-diagnostics"},
	{"nested diagnostic section", "#vpn-traffic-performance", "diagnostics", "vpn-traffic-performance"},
	{"nested fold", "#vpn-fwd-routes-details", "diagnostics", "vpn-fwd-routes-details"},
	{"reason history", "#vpn-reason-history", "diagnostics", "vpn-reason-history"},
	{"per-backend fold", "#vpn-per-backend", "diagnostics", "vpn-per-backend"},
	{"chart tooltip falls back to its section", "#vpn-chart-tooltip", "diagnostics", "vpn-traffic-performance-title"},
	{"stale banner falls back to its heading", "#vpnSessionsStaleBanner", "diagnostics", "vpn-troubleshooting-title"},
}

// TestVPNLegacyFragmentsResolveLocally asserts the local resolver: every id family
// keeps its owner, the canonical target is the id the landing should focus, and an
// unknown or malformed fragment resolves to nothing at all rather than guessing.
func TestVPNLegacyFragmentsResolveLocally(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	nodePath := fixture.RequireJSDOM()

	var b strings.Builder
	b.WriteString("\nconst resolve = w.vpnResolveFragment;\n")
	for _, tc := range vpnLegacyFragmentCases {
		quoted := strings.ReplaceAll(tc.hash, "\\", "\\\\")
		b.WriteString("{\n  const r = resolve('" + quoted + "');\n")
		b.WriteString("  assert(r, 'the fragment " + tc.hash + " must resolve');\n")
		b.WriteString("  assert.strictEqual(r.section, '" + tc.section + "', '" + tc.hash + " section owner');\n")
		b.WriteString("  assert.strictEqual(r.target, '" + tc.target + "', '" + tc.hash + " canonical landing target');\n")
		b.WriteString("  assert.strictEqual(r.id, '" + strings.TrimPrefix(tc.hash, "#") + "', '" + tc.hash + " keeps its own id');\n")
		b.WriteString("}\n")
	}
	b.WriteString(`
// Unknown and malformed fragments do nothing: no section is invented and the page
// stays usable where the browser put it.
for (const bad of ['#not-a-real-id', '#%', '#', '#vpn-', '#%E0%A4%A', '#a#b']) {
    assert.strictEqual(resolve(bad), null, 'unknown/malformed fragment must not resolve: ' + bad);
}
// The session signal and the sessions table are different owners.
assert.strictEqual(resolve('#vpn-sessions').section, 'overview', 'the session signal is an Overview value');
assert.strictEqual(resolve('#vpnSessionsTable').section, 'diagnostics', 'the sessions table is in Diagnostics');
// A section id is a landing of its own, in the section it names.
for (const section of ['overview', 'backends', 'diagnostics']) {
    const r = resolve('#' + section);
    assert(r, section + ' must resolve as a section landing');
    assert.strictEqual(r.section, section, section + ' must resolve to itself');
}
console.log('VPN_LOCAL_FRAGMENT_RESOLVER_OK');
`)
	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: b.String()})
	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("local resolver script failed: %v\nOutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "VPN_LOCAL_FRAGMENT_RESOLVER_OK") {
		t.Fatalf("local resolver script did not report its token:\n%s", out)
	}
}

// TestVPNMergedPageConsumesTheSectionMarker proves the page side of a retired
// route's redirect. The redirect itself is proven by request in the router package,
// which owns the handler; here the question is what the page does with the marker
// that arrives on its query string.
//
// The marker is transient: it names a section, it is consumed with replaceState,
// and the address bar is rewritten to the canonical fragment. An inherited legacy
// fragment wins over the marker's default section, so a deep link still lands on
// the block it named; an unrecognised marker is ignored and the page stays usable.
func TestVPNMergedPageConsumesTheSectionMarker(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	nodePath := fixture.RequireJSDOM()

	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: `
(() => {
    const consume = w.vpnConsumeSectionMarker;

    // 1. A plain arrival from /vpn/backends: the marker names the section and the
    //    canonical URL is written with that section's fragment.
    w.history.replaceState(null, '', '/vpn?section=backends');
    let r = consume();
    assert(r, 'a section marker must be consumed');
    assert.strictEqual(r.section, 'backends', 'the marker names its section');
    assert.strictEqual(w.location.pathname, '/vpn', 'the canonical path is written');
    assert.strictEqual(w.location.search, '', 'the transient marker is removed');
    assert.strictEqual(w.location.hash, '#backends', 'the canonical fragment is written');

    // 2. A legacy deep link inherited from the retired route: the fragment the
    //    browser carried wins over the marker's default section.
    w.history.replaceState(null, '', '/vpn?section=backends#vpnSessionsTable');
    r = consume();
    assert.strictEqual(r.section, 'backends', 'the marker still names the originating section');
    assert.strictEqual(w.location.hash, '#vpnSessionsTable', 'the inherited fragment is preserved');

    // 3. An unrecognised marker value is not a destination: it is left alone and the
    //    page is not moved.
    w.history.replaceState(null, '', '/vpn?section=nowhere');
    assert.strictEqual(consume(), null, 'an unknown section must not be consumed');
    assert.strictEqual(w.location.search, '?section=nowhere', 'the unknown marker is left as it is');

    // 4. No marker at all on an ordinary canonical visit.
    w.history.replaceState(null, '', '/vpn');
    assert.strictEqual(consume(), null, 'a canonical visit has nothing to consume');

    console.log('VPN_SECTION_MARKER_OK');
})();
`})
	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("section marker script failed: %v\nOutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "VPN_SECTION_MARKER_OK") {
		t.Fatalf("section marker script did not report its token:\n%s", out)
	}
}
