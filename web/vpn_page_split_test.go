package web

import (
	"io/fs"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

// The VPN subject is three documents. These tests assert the split itself:
//
//   - each document renders exactly its own blocks and none of its siblings';
//   - the sidebar marks exactly the document that rendered, and the mobile
//     shortcut stands for the overview alone;
//   - a legacy fragment is handed to the document that now owns its id;
//   - each document's controller requests only its own endpoints.

// vpnPageBlockMarkers names, for each document, a marker id that only that
// document renders.
var vpnPageBlockMarkers = map[string][]string{
	"vpn":             {"vpn-signal-backends-value", "vpn-configuration", "editEndpointModal"},
	"vpn_backends":    {"vpnBackendsTable", "addBackendModal", "vpn-backends-title"},
	"vpn_diagnostics": {"vpn-forwarder-card", "vpn-diagnostics", "vpnSessionsTable"},
}

func TestVPNPageSplitBlocksAreExclusive(t *testing.T) {
	for page, own := range vpnPageBlockMarkers {
		t.Run(page, func(t *testing.T) {
			body, err := fs.ReadFile(TemplatesFS, "templates/"+page+".html")
			if err != nil {
				t.Fatalf("read %s.html: %v", page, err)
			}
			markup := string(body)
			for _, id := range own {
				if !strings.Contains(markup, `id="`+id+`"`) {
					t.Errorf("%s.html must render #%s", page, id)
				}
			}
			for otherPage, markers := range vpnPageBlockMarkers {
				if otherPage == page {
					continue
				}
				for _, id := range markers {
					if strings.Contains(markup, `id="`+id+`"`) {
						t.Errorf("%s.html must not render #%s; it belongs to %s", page, id, otherPage)
					}
				}
			}
		})
	}
}

// TestVPNPageSplitHeadingLevels pins the document structure: one H1 per document,
// and the table cards' titles are H2 rather than the H3 they were under the old
// single-page H1.
func TestVPNPageSplitHeadingLevels(t *testing.T) {
	for _, page := range []string{"vpn", "vpn_backends", "vpn_diagnostics"} {
		body, err := fs.ReadFile(TemplatesFS, "templates/"+page+".html")
		if err != nil {
			t.Fatalf("read %s.html: %v", page, err)
		}
		markup := string(body)
		if got := strings.Count(markup, "<h1 "); got != 1 {
			t.Errorf("%s.html must have exactly one H1, found %d", page, got)
		}
	}
	backends, err := fs.ReadFile(TemplatesFS, "templates/vpn_backends.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(backends), `<h2 class="card-title" id="vpn-backends-title"`) {
		t.Error("the inventory card title must be an H2 under the document H1")
	}
	diagnostics, err := fs.ReadFile(TemplatesFS, "templates/vpn_diagnostics.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(diagnostics), `<h2 class="card-title" id="vpn-troubleshooting-title"`) {
		t.Error("the sessions card title must be an H2 under the document H1")
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

// TestVPNPageSplitNavigationMarker proves the server marks exactly the document it
// rendered: one current VPN entry in the sidebar/drawer, and the bottom-bar
// shortcut current only on the overview.
func TestVPNPageSplitNavigationMarker(t *testing.T) {
	expected := map[string]string{
		"vpn":             "/vpn",
		"vpn_backends":    "/vpn/backends",
		"vpn_diagnostics": "/vpn/diagnostics",
	}
	for page, href := range expected {
		t.Run(page, func(t *testing.T) {
			rendered := renderVPNPage(t, page)
			doc, err := xhtml.Parse(strings.NewReader(rendered))
			if err != nil {
				t.Fatalf("parse rendered %s: %v", page, err)
			}

			current := make([]string, 0, 1)
			for _, link := range vpnNavLinks(t, doc) {
				if !vpnNodeHasClass(link, "active") && !vpnNodeHasClass(link, "bottom-bar-link") {
					continue
				}
				if !vpnNodeHasClass(link, "active") {
					continue
				}
				linkHref := getHTMLNodeAttr(link, "href")
				if vpnNodeHasClass(link, "sidebar-nav-link") {
					current = append(current, linkHref)
					if aria := getHTMLNodeAttr(link, "aria-current"); aria != "page" {
						t.Errorf("the current sidebar entry %s must carry aria-current=page", linkHref)
					}
				}
				if vpnNodeHasClass(link, "bottom-bar-link") {
					if page != "vpn" {
						t.Errorf("the bottom shortcut must not be current on %s", page)
					}
					if aria := getHTMLNodeAttr(link, "aria-current"); aria != "page" {
						t.Errorf("the bottom shortcut must carry aria-current=page on the overview")
					}
				}
			}
			if len(current) != 1 || current[0] != href {
				t.Fatalf("the sidebar marks %v current, want exactly [%s]", current, href)
			}

			// Every other VPN link is not current and claims no current page.
			for _, link := range vpnNavLinks(t, doc) {
				linkHref := getHTMLNodeAttr(link, "href")
				if linkHref == href {
					continue
				}
				if aria := getHTMLNodeAttr(link, "aria-current"); aria == "page" {
					t.Errorf("%s claims aria-current=page on %s", linkHref, page)
				}
			}
		})
	}
}

// TestVPNLegacyFragmentHandoff walks the contract's link table: each id family
// resolves to the document that owns it, with the query preserved, and an id the
// overview owns (or an unknown/malformed one) does no handoff at all.
func TestVPNLegacyFragmentHandoff(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	nodePath := fixture.RequireJSDOM()

	cases := []struct{ name, hash, want string }{
		// Overview-owned: no handoff.
		{"overview configuration", "#vpn-configuration", ""},
		{"overview signal", "#vpn-sessions", ""},
		{"overview listener", "#vpn-listen-port", ""},
		{"overview endpoint", "#vpn-public-endpoint", ""},
		{"overview modal canonicalises to its opener", "#editEndpointModal", ""},
		// Backend inventory.
		{"inventory heading", "#vpn-backends-title", "/vpn/backends#vpn-backends-title"},
		{"inventory table", "#vpnBackendsTable", "/vpn/backends#vpnBackendsTable"},
		{"inventory container", "#vpnTableContainer", "/vpn/backends#vpnTableContainer"},
		{"persistent add action", "#vpn-add-backend-btn", "/vpn/backends#vpn-add-backend-btn"},
		{"add modal canonicalises to its opener", "#addBackendModal", "/vpn/backends#vpn-add-backend-btn"},
		{"server select canonicalises to its opener", "#vpnServerSelect", "/vpn/backends#vpn-add-backend-btn"},
		{"loading row falls back to the heading", "#vpn-backends-loading", "/vpn/backends#vpn-backends-title"},
		// Diagnostics: health and the disclosure.
		{"health card", "#vpn-forwarder-card", "/vpn/diagnostics#vpn-forwarder-card"},
		{"health heading", "#vpn-health-title", "/vpn/diagnostics#vpn-health-title"},
		{"disclosure entry", "#vpn-advanced-entry", "/vpn/diagnostics#vpn-advanced-entry"},
		{"disclosure itself", "#vpn-diagnostics", "/vpn/diagnostics#vpn-diagnostics"},
		{"nested diagnostic section", "#vpn-traffic-performance", "/vpn/diagnostics#vpn-traffic-performance"},
		{"nested fold", "#vpn-fwd-routes-details", "/vpn/diagnostics#vpn-fwd-routes-details"},
		{"reason history", "#vpn-reason-history", "/vpn/diagnostics#vpn-reason-history"},
		{"per-backend fold", "#vpn-per-backend", "/vpn/diagnostics#vpn-per-backend"},
		{"chart tooltip", "#vpn-chart-tooltip", "/vpn/diagnostics#vpn-chart-tooltip"},
		// Diagnostics: sessions.
		{"sessions heading", "#vpn-troubleshooting-title", "/vpn/diagnostics#vpn-troubleshooting-title"},
		{"sessions table", "#vpnSessionsTable", "/vpn/diagnostics#vpnSessionsTable"},
		{"sessions loading falls back to its heading", "#vpn-sessions-loading", "/vpn/diagnostics#vpn-troubleshooting-title"},
	}

	var b strings.Builder
	b.WriteString(`
const dest = w.vpnLegacyHandoffDestination;
`)
	for _, tc := range cases {
		quoted := strings.ReplaceAll(tc.hash, "\\", "\\\\")
		if tc.want == "" {
			b.WriteString("assert.strictEqual(dest('/vpn', '', '" + quoted + "'), null, 'no handoff for " + tc.name + "');\n")
		} else {
			b.WriteString("assert.strictEqual(dest('/vpn', '', '" + quoted + "'), '" + tc.want + "', 'handoff for " + tc.name + "');\n")
			// The query string is preserved ahead of the fragment.
			b.WriteString("assert.strictEqual(dest('/vpn', '?tab=2', '" + quoted + "'), '" +
				strings.Replace(tc.want, "#", "?tab=2#", 1) + "', 'query preserved for " + tc.name + "');\n")
		}
	}
	b.WriteString(`
// Unknown and malformed fragments do nothing, and a child page never redirects.
assert.strictEqual(dest('/vpn', '', '#not-a-real-id'), null, 'unknown id does nothing');
assert.strictEqual(dest('/vpn', '', '#%'), null, 'malformed escape does nothing');
assert.strictEqual(dest('/vpn', '', '#'), null, 'empty hash does nothing');
assert.strictEqual(dest('/vpn/backends', '', '#vpnSessionsTable'), null, 'a child page never hands off');
assert.strictEqual(dest('/vpn/diagnostics', '', '#vpnBackendsTable'), null, 'nor does diagnostics');
// The session signal and the sessions table are different owners.
assert.strictEqual(dest('/vpn', '', '#vpn-sessions'), null, 'the overview keeps its session signal');
assert.strictEqual(dest('/vpn', '', '#vpnSessionsTable'), '/vpn/diagnostics#vpnSessionsTable', 'the table moves');
console.log('VPN_LEGACY_HANDOFF_OK');
`)

	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: b.String()})
	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("legacy handoff script failed: %v\nOutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "VPN_LEGACY_HANDOFF_OK") {
		t.Fatalf("legacy handoff script did not report its token:\n%s", out)
	}
}

// TestVPNPagePayloads proves each document's controller requests only its own
// endpoints through the real loader functions.
func TestVPNPagePayloads(t *testing.T) {
	cases := []struct {
		page   string
		load   string
		want   []string
		forbid []string
	}{
		{
			page:   "vpn",
			load:   "w.vpnLoadOverview()",
			want:   []string{"/api/vpn/status", "/api/vpn/config"},
			forbid: []string{"/api/vpn/backends", "/api/vpn/sessions", "/api/servers"},
		},
		{
			page:   "vpn_backends",
			load:   "w.vpnLoadBackends()",
			want:   []string{"/api/vpn/backends"},
			forbid: []string{"/api/vpn/status", "/api/vpn/config", "/api/vpn/sessions"},
		},
		{
			page:   "vpn_diagnostics",
			load:   "w.vpnLoadDiagnostics()",
			want:   []string{"/api/vpn/status", "/api/vpn/sessions"},
			forbid: []string{"/api/vpn/backends", "/api/vpn/config", "/api/servers"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.page, func(t *testing.T) {
			fixture := NewVPNTestFixtureForPage(t, tc.page)
			nodePath := fixture.RequireJSDOM()
			script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: `
(async () => {
const calls = [];
w.API = {
    get: async function (url) { calls.push(String(url).split('?')[0]); return {}; },
    post: async function (url) { calls.push(String(url).split('?')[0]); return {}; },
    request: async function (url) { calls.push(String(url).split('?')[0]); return {}; },
};
await ` + tc.load + `;
for (const path of ` + jsonStringSlice(tc.want) + `) {
    assert(calls.includes(path), 'the page must request ' + path + '; requested ' + JSON.stringify(calls));
}
for (const path of ` + jsonStringSlice(tc.forbid) + `) {
    assert(!calls.includes(path), 'the page must not request ' + path + '; requested ' + JSON.stringify(calls));
}
// No duplicate burst: a loader must not ask for the same endpoint twice.
const counts = {};
for (const path of calls) { counts[path] = (counts[path] || 0) + 1; }
for (const path of Object.keys(counts)) {
    assert.strictEqual(counts[path], 1, 'duplicate request for ' + path + ': ' + JSON.stringify(calls));
}
console.log('VPN_PAYLOAD_OK');
})().catch(e => { console.error(e); process.exit(1); });
`})
			out, err := execNodeScript(nodePath, script)
			if err != nil {
				t.Fatalf("payload script failed: %v\nOutput:\n%s", err, out)
			}
			if !strings.Contains(string(out), "VPN_PAYLOAD_OK") {
				t.Fatalf("payload script did not report its token:\n%s", out)
			}
		})
	}
}

// jsonStringSlice renders a Go string slice as a JS array literal.
func jsonStringSlice(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, `"`+v+`"`)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

// TestVPNOverviewEndpointDialog covers the endpoint dialog on the document that
// owns it: it opens from the configuration strip with the CONFIGURED value, saves
// a trimmed value, refreshes only the overview, and leaves the form intact with
// its message when the write is refused.
func TestVPNOverviewEndpointDialog(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	nodePath := fixture.RequireJSDOM()

	script := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{ExtraJS: `
(async () => {
const opened = [], closed = [], refreshed = [], requests = [];
w.openModal = (id) => opened.push(id);
w.closeModal = (id) => closed.push(id);
w.UI = { toast: () => {}, confirm: async () => true, escapeHtml: (s) => String(s == null ? '' : s) };
w.vpnLoadOverview = async () => { refreshed.push('overview'); };
w.API = {
    get: async () => ({}),
    post: async () => ({}),
    request: async (url, opts) => { requests.push({ url, opts }); return {}; },
};

// The dialog prefills the configured value, not the detected fallback.
w.vpnConfiguredPublicEndpoint = 'vpn.old.domain:51820';
w.vpnOpenEditEndpointModal();
assert(opened.includes('editEndpointModal'), 'the endpoint dialog opens');
const input = w.document.getElementById('vpnPublicEndpointInput');
assert.strictEqual(input.value, 'vpn.old.domain:51820', 'the input holds the configured value');

input.value = '  vpn.new.domain:51820 ';
await w.vpnSubmitEditEndpoint();
assert.strictEqual(requests.length, 1, 'one PUT is sent');
assert.strictEqual(requests[0].url, '/api/vpn/config', 'to the existing config route');
assert.strictEqual(requests[0].opts.method, 'PUT', 'with the existing verb');
assert.strictEqual(requests[0].opts.body.public_endpoint, 'vpn.new.domain:51820', 'and the trimmed value');
assert(closed.includes('editEndpointModal'), 'success closes the dialog');
assert.deepStrictEqual(refreshed, ['overview'], 'success refreshes the overview only');

// Refusal: the dialog stays open, the form keeps its value, and the error shows.
w.API.request = async () => { throw { data: { detail: 'endpoint refused' } }; };
input.value = 'vpn.bad.domain';
await w.vpnSubmitEditEndpoint();
assert(!closed.includes('editEndpointModal') || closed.length === 1, 'a refusal does not report success');
assert.strictEqual(input.value, 'vpn.bad.domain', 'the form keeps what the operator typed');
const errBox = w.document.getElementById('vpnEndpointModalError');
assert.strictEqual(errBox.style.display, 'block', 'the refusal is shown inline');
assert(errBox.textContent.includes('endpoint refused'), 'with the API message');
assert.strictEqual(w.document.getElementById('vpnEditEndpointSubmitBtn').disabled, false, 'the form stays operable');
console.log('VPN_ENDPOINT_DIALOG_OK');
})().catch(e => { console.error(e); process.exit(1); });
`})
	out, err := execNodeScript(nodePath, script)
	if err != nil {
		t.Fatalf("endpoint dialog script failed: %v\nOutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "VPN_ENDPOINT_DIALOG_OK") {
		t.Fatalf("endpoint dialog script did not report its token:\n%s", out)
	}
}
