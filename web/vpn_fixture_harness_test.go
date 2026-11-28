package web

// JSDOM evaluation harness for the VPN page.
//
// This is a MOVE, not a rewrite: the harness, its options and its boot helpers were
// extracted verbatim from vpn_fixture_test.go when that file crossed the repository's
// per-file review ceiling. Nothing about the harness changed, so every case that used
// it keeps the same behaviour.
//
// What it does is stated once, here, because several cases depend on it:
//
//   - the page is rendered from the SHIPPED template with a locale dictionary, so a
//     user-visible string the markup asks for is the string the operator would see;
//   - the shell's eager modules are evaluated in dependency order and the deferred
//     ones are appended as well, because a harness has no network to fetch them from;
//   - host stubs (API, telemetry, UI, window) are installed before any module runs;
//   - PreludeJS runs after the stubs and before the modules, which is the only window
//     in which a case can put its boundaries in place for the boot's FIRST tick;
//   - ExtraJS runs last, which is where a case's assertions belong.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

// JSDOMHarnessOptions configures a JSDOM evaluation harness.
type JSDOMHarnessOptions struct {
	HTML             string
	Language         string
	Direction        string
	IncludeFakeClock bool
	IncludeFetchMock bool
	// IncludeNexusTable installs the real tables.js before the companion modules,
	// the position base.html gives it. Without it no NexusTable exists, so no row
	// is ever hidden by a search term, a status filter or pagination: a test of a
	// reveal that then asserted focus on a "visible" row would be asserting
	// against a table that never hid anything.
	IncludeNexusTable bool
	// IncludeRealTelemetry installs the shipped polling engine instead of the inert
	// stub. A case whose subject is the boot's registered streams needs the real
	// scheduler; every other case keeps the stub, which is also what makes the harness
	// idle when the assertions finish.
	IncludeRealTelemetry bool
	// PreludeJS runs AFTER the host stubs (API, telemetry, UI, window) and BEFORE
	// the VPN modules are evaluated. A case whose subject is the page BOOT needs
	// its boundaries in place before the boot takes its first tick: the boot runs at
	// module evaluation, so a stub installed afterwards is a stub the first sample
	// never saw. A case that drives one controller directly does not need it.
	PreludeJS string
	ExtraJS   string
}

// NewVPNTestFixture initializes a VPN test fixture with loaded templates, styles, and parsed DOM.
// In CI environments, missing Node binary fails closed with t.Fatalf.
func NewVPNTestFixture(t *testing.T) *VPNTestFixture {
	t.Helper()
	return newVPNTestFixtureWithFS(t, StaticFS, "vpn")
}

// NewVPNTestFixtureForPage builds the fixture around one VPN page name. #1006 merged
// the three documents into one, so every name renders the SAME template; the names
// survive because they also select which section's controllers the harness loads.
func NewVPNTestFixtureForPage(t *testing.T, page string) *VPNTestFixture {
	t.Helper()
	return newVPNTestFixtureWithFS(t, StaticFS, page)
}

// vpnTemplateNameForPage is the one place a fixture page name maps to a file.
func vpnTemplateNameForPage(page string) string {
	switch page {
	case "vpn", "vpn_backends", "vpn_diagnostics":
		return "vpn.html"
	default:
		return page + ".html"
	}
}

func readFixtureStaticAsset(staticFS fs.FS, path string) ([]byte, error) {
	if staticFS == nil {
		return nil, os.ErrNotExist
	}
	return fs.ReadFile(staticFS, path)
}

func newVPNTestFixtureWithFS(t *testing.T, staticFS fs.FS, page string) *VPNTestFixture {
	t.Helper()
	if page == "" {
		page = "vpn"
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("filesystem sub-FS initialization failed: %v", err)
	}
	templateName := vpnTemplateNameForPage(page)
	vpnBytes, err := fs.ReadFile(tmplFS, templateName)
	if err != nil {
		t.Fatalf("failed reading fixture files: %v", err)
	}
	cssBytes, err := readFixtureStaticAsset(staticFS, "static/css/style.css")
	if err != nil {
		t.Fatalf("failed reading fixture files: %v", err)
	}
	doc, err := xhtml.Parse(strings.NewReader(string(vpnBytes)))
	if err != nil {
		t.Fatalf("failed to parse %s: %v", templateName, err)
	}
	nodePath, err := findNodeBinary()
	if err != nil && isCIEnvironment() {
		t.Fatalf("node binary is required under CI: %v", err)
	}
	sessionsPath := "static/js/vpn/sessions.js"
	sessionsBytes, err := readFixtureStaticAsset(staticFS, sessionsPath)
	if err != nil {
		t.Fatalf("failed to read static sessions asset %s: %v", sessionsPath, err)
	}
	if len(strings.TrimSpace(string(sessionsBytes))) == 0 {
		t.Fatalf("failed to read static sessions asset %s: %v", sessionsPath, errors.New("empty content"))
	}
	sessionsJS := string(sessionsBytes)

	problemsPath := "static/js/vpn/health_problems.js"
	problemsBytes, err := readFixtureStaticAsset(staticFS, problemsPath)
	if err != nil {
		t.Fatalf("failed to read static health problems asset %s: %v", problemsPath, err)
	}
	if len(strings.TrimSpace(string(problemsBytes))) == 0 {
		t.Fatalf("failed to read static health problems asset %s: %v", problemsPath, errors.New("empty content"))
	}
	healthProblemsJS := string(problemsBytes)

	summaryPath := "static/js/vpn/health_summary.js"
	summaryBytes, err := readFixtureStaticAsset(staticFS, summaryPath)
	if err != nil {
		t.Fatalf("failed to read static health summary asset %s: %v", summaryPath, err)
	}
	if len(strings.TrimSpace(string(summaryBytes))) == 0 {
		t.Fatalf("failed to read static health summary asset %s: %v", summaryPath, errors.New("empty content"))
	}
	healthSummaryJS := string(summaryBytes)

	chartsPath := "static/js/vpn/charts.js"
	chartsBytes, err := readFixtureStaticAsset(staticFS, chartsPath)
	if err != nil {
		t.Fatalf("failed to read static charts asset %s: %v", chartsPath, err)
	}
	if len(strings.TrimSpace(string(chartsBytes))) == 0 {
		t.Fatalf("failed to read static charts asset %s: %v", chartsPath, errors.New("empty content"))
	}
	chartsJS := string(chartsBytes)

	backendsPath := "static/js/vpn/backends.js"
	backendsBytes, err := readFixtureStaticAsset(staticFS, backendsPath)
	if err != nil {
		t.Fatalf("failed to read static backends asset %s: %v", backendsPath, err)
	}
	if len(strings.TrimSpace(string(backendsBytes))) == 0 {
		t.Fatalf("failed to read static backends asset %s: %v", backendsPath, errors.New("empty content"))
	}
	backendsJS := string(backendsBytes)

	readModule := func(name string) string {
		path := "static/js/vpn/" + name
		body, err := readFixtureStaticAsset(staticFS, path)
		if err != nil {
			t.Fatalf("failed to read static page asset %s: %v", path, err)
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			t.Fatalf("failed to read static page asset %s: %v", path, errors.New("empty content"))
		}
		return string(body)
	}
	commonJS := readModule("common.js")
	overviewJS := readModule("overview.js")
	backendsPageJS := readModule("backends_page.js")
	diagnosticsPageJS := readModule("diagnostics_page.js")
	anchorHandoffJS := readModule("anchor_handoff.js")
	pageBootJS := readModule("page.js")
	pageJS := overviewJS
	switch page {
	case "vpn_backends":
		pageJS = backendsPageJS
	case "vpn_diagnostics":
		pageJS = diagnosticsPageJS
	}

	tablesBytes, err := readFixtureStaticAsset(staticFS, "static/js/tables.js")
	if err != nil {
		t.Fatalf("failed to read static tables asset %s: %v", "static/js/tables.js", err)
	}
	if len(strings.TrimSpace(string(tablesBytes))) == 0 {
		t.Fatalf("failed to read static tables asset %s: %v", "static/js/tables.js", errors.New("empty content"))
	}
	tablesJS := string(tablesBytes)

	return &VPNTestFixture{
		t:                 t,
		NodePath:          nodePath,
		OwnerPage:         page,
		TemplateHTML:      string(vpnBytes),
		StyleCSS:          string(cssBytes),
		SessionsJS:        sessionsJS,
		HealthProblemsJS:  healthProblemsJS,
		HealthSummaryJS:   healthSummaryJS,
		ChartsJS:          chartsJS,
		BackendsJS:        backendsJS,
		CommonJS:          commonJS,
		OverviewJS:        overviewJS,
		BackendsPageJS:    backendsPageJS,
		DiagnosticsPageJS: diagnosticsPageJS,
		AnchorHandoffJS:   anchorHandoffJS,
		PageBootJS:        pageBootJS,
		PageJS:            pageJS,
		TablesJS:          tablesJS,
		ParsedDOM:         doc,
		MockFetches:       make(map[string]string),
	}
}

// WithT returns a shallow copy of the fixture bound to the active subtest *testing.T.
func (f *VPNTestFixture) WithT(t *testing.T) *VPNTestFixture {
	if t != nil {
		t.Helper()
	}
	clone := *f
	clone.t = t
	return &clone
}

func (f *VPNTestFixture) RequireNode() string {
	f.t.Helper()
	if f.NodePath == "" {
		f.NodePath = requireNode(f.t)
	}
	return f.NodePath
}

func (f *VPNTestFixture) RequireJSDOM() string {
	f.t.Helper()
	f.NodePath = requireJSDOM(f.t)
	return f.NodePath
}

func (f *VPNTestFixture) MockEndpoint(endpoint, responseJSON string) {
	f.MockFetches[endpoint] = responseJSON
}

func (f *VPNTestFixture) FindByID(id string) *xhtml.Node {
	return findHTMLNodeByID(f.ParsedDOM, id)
}

func (f *VPNTestFixture) FindByTag(tag string) []*xhtml.Node {
	return findHTMLNodesByTag(f.ParsedDOM, tag)
}

func (f *VPNTestFixture) ValidateDashboardOrder() error {
	return validateVPNDashboardDOMOrder(f.ParsedDOM)
}

func (f *VPNTestFixture) Locale(lang string) map[string]string {
	f.t.Helper()
	return vpnDiagnosticsLocale(f.t, lang)
}

func (f *VPNTestFixture) TranslationsJS(lang string) string {
	f.t.Helper()
	return vpnDiagnosticsTranslationsJS(f.t, lang)
}

func (f *VPNTestFixture) RenderedHTML(lang string) string {
	f.t.Helper()
	return vpnDiagnosticsRenderedHTML(f.t, f.TemplateHTML, f.Locale(lang))
}

// vpnCompanionBoundaryMarker separates template HTML from companion JS modules in CombinedSource.
const vpnCompanionBoundaryMarker = "\n/* --- VPN COMPANION MODULES BOUNDARY --- */\n"

// CompanionScripts returns the JS modules the harness evaluates, in order.
//
// The assembled page mirrors what the shell SHIPS: the eager chain runs for every
// case, and the deferred controllers are appended as well, because a harness has no
// network and nothing to fetch them from. Two consequences are stated rather than
// hidden:
//
//   - the page boot's loader sees each deferred module already registered in
//     common.js's registry, so a case that drives activation performs no injection and
//     its assertions are about behaviour, not about script injection;
//   - a case whose subject IS the injection asserts the REQUEST, by replacing
//     vpnLoadModule for the duration of that case.
//
// A section-named page gets its own controllers without the boot, so a case that
// drives one controller is not running the other sections' polls underneath its
// assertion. The asset-identity and template checks derive the real split from the
// shipped template, so drift between this order and the shell is caught there.
func (f *VPNTestFixture) CompanionScripts() string {
	switch f.OwnerPage {
	case "vpn_backends":
		return f.CommonJS + "\n" + f.BackendsJS + "\n" + f.PageJS
	case "vpn_diagnostics":
		return f.CommonJS + "\n" + f.HealthProblemsJS + "\n" + f.HealthSummaryJS + "\n" + f.ChartsJS + "\n" + f.SessionsJS + "\n" + f.PageJS
	default:
		// The whole page, in dependency order, ending with the boot that activates it.
		return f.AnchorHandoffJS + "\n" + f.CommonJS + "\n" +
			f.OverviewJS + "\n" + f.BackendsJS + "\n" + f.BackendsPageJS + "\n" +
			f.HealthProblemsJS + "\n" + f.HealthSummaryJS + "\n" + f.ChartsJS + "\n" +
			f.SessionsJS + "\n" + f.DiagnosticsPageJS + "\n" + f.PageBootJS
	}
}

// CombinedSource returns the concatenated vpn.html template, sessions.js, health_problems.js, health_summary.js, charts.js, backends.js, and page.js scripts.
func (f *VPNTestFixture) CombinedSource() string {
	return f.TemplateHTML + vpnCompanionBoundaryMarker + f.CompanionScripts()
}

// CombinedVPNSessionsSource returns the concatenated vpn.html template, sessions.js, health_problems.js, health_summary.js, charts.js, backends.js, and page.js scripts.
func (f *VPNTestFixture) CombinedVPNSessionsSource() string {
	return f.CombinedSource()
}

func (f *VPNTestFixture) BuildJSDOMHarness(opts JSDOMHarnessOptions) string {
	f.t.Helper()
	lang, dir := opts.Language, opts.Direction
	if lang == "" {
		lang = "en"
	}
	if dir == "" {
		dir = "ltr"
	}
	telemetrySrc := []byte(nil)
	if opts.IncludeRealTelemetry {
		var readErr error
		telemetrySrc, readErr = fs.ReadFile(StaticFS, "static/js/telemetry.js")
		if readErr != nil {
			f.t.Fatalf("failed to read the polling engine for the harness: %v", readErr)
		}
	}
	htmlBody := opts.HTML
	if htmlBody == "" {
		htmlBody = f.RenderedHTML(lang)
	}
	tablesScript := ""
	if opts.IncludeNexusTable {
		if len(strings.TrimSpace(f.TablesJS)) == 0 {
			f.t.Fatalf("failed to read static tables asset %s: %v", "js/tables.js", errors.New("empty content"))
		}
		// tables.js is a UMD module: under CommonJS it assigns module.exports and
		// never touches the global object. In a script tag the module system is
		// absent, so it takes the `root.NexusTable = NexusTable` branch. The tag is
		// emitted literally instead of as an addScript argument so the wrapped
		// global assignment below is not needed to fake that branch.
		tablesScript = f.TablesJS
	}
	var b strings.Builder
	b.WriteString(jsdomBootstrapSnippet + "\n")
	if opts.IncludeFakeClock {
		b.WriteString(jsdomFakeClockSnippet + "\n")
	}
	if opts.IncludeFetchMock && len(f.MockFetches) > 0 {
		b.WriteString(buildFetchMockSnippet(f.MockFetches) + "\n")
	}
	// Every module the fixture loaded must be non-empty, whichever document loads
	// it: a truncated asset is a defect on any page, and a harness that validated
	// only its owner's chain would happily hand an empty module to a test.
	for _, module := range []struct{ name, label, body string }{
		{"static/js/vpn/anchor_handoff.js", "anchor handoff", f.AnchorHandoffJS},
		{"static/js/vpn/backends.js", "backends", f.BackendsJS},
		{"static/js/vpn/backends_page.js", "backends page", f.BackendsPageJS},
		{"static/js/vpn/charts.js", "charts", f.ChartsJS},
		{"static/js/vpn/common.js", "common", f.CommonJS},
		{"static/js/vpn/diagnostics_page.js", "diagnostics page", f.DiagnosticsPageJS},
		{"static/js/vpn/health_problems.js", "health problems", f.HealthProblemsJS},
		{"static/js/vpn/health_summary.js", "health summary", f.HealthSummaryJS},
		{"static/js/vpn/overview.js", "page", f.PageJS},
		{"static/js/vpn/page.js", "page boot", f.PageBootJS},
		{"static/js/vpn/sessions.js", "sessions", f.SessionsJS},
	} {
		if len(strings.TrimSpace(module.body)) == 0 {
			f.t.Fatalf("failed to read static %s asset %s: %v", module.label, module.name, errors.New("empty content"))
		}
	}
	if len(strings.TrimSpace(f.CompanionScripts())) == 0 {
		f.t.Fatalf("failed to read the VPN modules for page %q: %v", f.OwnerPage, errors.New("empty content"))
	}
	docHTML := fmt.Sprintf("<!DOCTYPE html><html dir=\"%s\"><head><style>%s</style></head><body>%s</body></html>",
		dir, f.StyleCSS, htmlBody)
	b.WriteString(fmt.Sprintf(`
const virtualConsole = new (require('jsdom').VirtualConsole)();
virtualConsole.on('jsdomError', (err) => {
    console.error(err.stack || err.message);
    process.exit(1);
});
const dom = new JSDOM(%q, { virtualConsole, pretendToBeVisual: true, runScripts: 'dangerously', url: 'https://review.invalid' });
const w = dom.window;
// JSDOM has no layout, so every observed element would report as not intersecting.
// This stub records the targets and the callback the page registered, and never
// fires on its own - the honest model of a section that is out of view. A case that
// wants the real passive-activation path calls w.__vpnIntersect(target), which
// delivers the entry to the callback the SHIPPED boot registered for THAT element;
// a case that wants the explicit path calls w.vpnMountSection, as a jump does.
w.__vpnObserved = [];
w.__vpnObserverCallback = null;
w.__vpnIntersect = function (target) {
    const cb = w.__vpnObserverCallback;
    if (!cb) throw new Error('the page boot registered no IntersectionObserver callback');
    if (!w.__vpnObserved.includes(target)) {
        throw new Error('the boot never observed ' + (target && target.id) + ', so the page cannot be scrolled into it');
    }
    cb([{ target: target, isIntersecting: true }], {});
};
w.IntersectionObserver = class {
    constructor(cb) { this.cb = cb; this.targets = []; w.__vpnObserverCallback = cb; }
    observe(el) { this.targets.push(el); w.__vpnObserved.push(el); }
    unobserve(el) { this.targets = this.targets.filter(t => t !== el); }
    disconnect() { this.targets = []; }
};
w.API = {
    get: async () => ({}),
    post: async () => ({}),
    request: async () => ({}),
};
w.NexusTelemetry = {
    poll: () => {},
    stop: () => {},
};
w.Telemetry = {
    formatBytes: (n) => String(n),
};
w.UI = {
    escapeHtml: (s) => (s == null ? '' : String(s)),
    toast: () => {},
    confirm: async () => true,
};
if (typeof fakeClock !== 'undefined') {
    w.fakeClock = fakeClock;
    ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'].forEach(m => { w[m] = fakeClock[m].bind(fakeClock); });
}
if (typeof installFetchMock === 'function') { installFetchMock(w); }
// A case whose subject is the page boot installs its boundaries here: the boot runs at
// module evaluation below, so this is the last moment a prelude can be in place for the
// first sample it takes. The prelude is evaluated as a page script, where the host's
// alias for the window does not exist, so it is handed a local one first.
(function (prelude, telemetryCode) {
    const p = w.document.createElement('script');
    p.textContent = "var w = window;" + String.fromCharCode(10) + prelude;
    w.document.body.appendChild(p);
    // The REAL polling engine, so a case is about the streams the boot registers rather
    // than about a stub whose poll never calls its fetcher. It is opt-in: the real
    // engine schedules intervals, so a case that does not need it must keep the stub or
    // the harness would never be idle.
    if (telemetryCode) {
        const t = w.document.createElement('script');
        t.textContent = telemetryCode;
        w.document.body.appendChild(t);
    }
})(%q, %q);
function addScript(code) { const s = w.document.createElement('script'); s.textContent = code; w.document.body.appendChild(s); }
addScript(%q + "\nwindow.translations = translations;\nwindow._ = _;\n");
addScript(%q);
addScript(%q);
['vpnCachedServers', 'vpnCurrentBackends', 'vpnConfiguredPublicEndpoint', 'vpnTableInstance', 'vpnShowAllRoutes', 'vpnLastStatus'].forEach(prop => {
    Object.defineProperty(w, prop, {
        get() { return w.eval(prop); },
        set(v) { w['__' + prop + 'Ref'] = v; w.eval(prop + ' = window.__' + prop + 'Ref;'); },
        configurable: true
    });
});
`, docHTML, opts.PreludeJS, string(telemetrySrc), f.TranslationsJS(lang), tablesScript, f.CompanionScripts()))
	if opts.ExtraJS != "" {
		b.WriteString("\n" + opts.ExtraJS)
	}
	return b.String()
}

func (f *VPNTestFixture) RunJSDOM(script string) string {
	f.t.Helper()
	return runJSDOMTestScript(f.t, f.RequireNode(), script)
}

func (f *VPNTestFixture) RunJSDOMForT(t *testing.T, script string) string {
	t.Helper()
	return f.WithT(t).RunJSDOM(script)
}

func runJSDOMTestScript(t *testing.T, nodePath, testScript string) string {
	t.Helper()
	out, err := execNodeScript(nodePath, testScript)
	if err != nil {
		t.Fatalf("JSDOM execution failed: %v\nOutput:\n%s", err, string(out))
	}
	outStr := string(out)
	if strings.Contains(outStr, "JSDOM_NOT_AVAILABLE") {
		if os.Getenv("CI") != "" {
			t.Fatalf("jsdom is not available in CI environment: %s", outStr)
		}
		t.Skip("jsdom is not available in Node environment")
	}
	return outStr
}
