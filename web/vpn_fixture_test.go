package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

// isCIEnvironment returns true if executing in a continuous integration environment.
func isCIEnvironment() bool {
	ci := strings.TrimSpace(os.Getenv("CI"))
	return ci == "true" || ci == "1" || (ci != "" && ci != "0" && strings.ToLower(ci) != "false")
}

func findNodeBinary() (string, error) {
	if p, err := exec.LookPath("node"); err == nil {
		return p, nil
	}
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".local", "bin", "node"),
		"/usr/local/bin/node", "/usr/bin/node", "/bin/node",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("node binary not found in PATH or standard locations")
}

func execNodeScript(nodePath, script string) ([]byte, error) {
	cmd := exec.Command(nodePath)
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

// requireNode discovers the node binary with a strict CI fail-closed invariant:
// in CI it fails the test immediately with t.Fatalf; in local environments it skips.
func requireNode(t *testing.T) string {
	t.Helper()
	nodePath, err := findNodeBinary()
	if err != nil {
		if isCIEnvironment() {
			t.Fatalf("node binary is required under CI: %v", err)
		}
		t.Skipf("skipping test: node binary not found (%v)", err)
	}
	return nodePath
}

// requireJSDOM ensures both Node and JSDOM are available, failing closed under CI.
func requireJSDOM(t *testing.T) string {
	t.Helper()
	nodePath := requireNode(t)
	out, err := execNodeScript(nodePath, jsdomBootstrapSnippet+`console.log("JSDOM_READY");`)
	if err != nil {
		if isCIEnvironment() {
			t.Fatalf("jsdom probe failed in CI environment: %v\nOutput:\n%s", err, string(out))
		}
		t.Skipf("skipping test: jsdom probe failed: %v", err)
	}
	outStr := string(out)
	if strings.Contains(outStr, "JSDOM_NOT_AVAILABLE") {
		if isCIEnvironment() {
			t.Fatalf("jsdom is not available in CI environment: %s", outStr)
		}
		t.Skip("jsdom is not available in Node environment")
	}
	return nodePath
}

const jsdomBootstrapSnippet = `
const fs = require('fs');
const assert = require('assert');
const path = require('path');

const home = process.env.HOME || process.env.USERPROFILE || '';
const searchPaths = [
    home ? path.join(home, '.hermes', 'hermes-agent', 'node_modules') : '',
    home ? path.join(home, '.cache', 'typescript', '6.0', 'node_modules') : '',
    process.env.NODE_PATH || ''
].filter(Boolean);
searchPaths.forEach(p => {
    if (fs.existsSync(p) && !module.paths.includes(p)) {
        module.paths.push(p);
    }
});

try {
    const globalRoot = require('child_process').execSync('npm root -g').toString().trim();
    if (globalRoot && !module.paths.includes(globalRoot)) {
        module.paths.push(globalRoot);
    }
} catch (_) {}

let JSDOM;
try {
    JSDOM = require('jsdom').JSDOM;
} catch (e) {
    console.log('JSDOM_NOT_AVAILABLE: ' + e.message);
    process.exit(0);
}
`

const jsdomFakeClockSnippet = `
class FakeClock {
    constructor() { this.now = 0; this.timers = []; this.nextId = 1; }
    setTimeout(fn, delay, ...args) { const id = this.nextId++; this.timers.push({ id, fn, time: this.now + Math.max(0, delay || 0), args, interval: 0 }); return id; }
    clearTimeout(id) { this.timers = this.timers.filter(t => t.id !== id); }
    setInterval(fn, delay, ...args) { const id = this.nextId++; const interval = Math.max(1, delay || 1); this.timers.push({ id, fn, time: this.now + interval, args, interval }); return id; }
    clearInterval(id) { this.clearTimeout(id); }
    tick(ms) {
        const target = this.now + ms;
        while (true) {
            const due = this.timers.filter(t => t.time <= target).sort((a, b) => a.time - b.time || a.id - b.id);
            if (due.length === 0) break;
            const next = due[0];
            this.now = next.time;
            if (next.interval > 0) next.time = this.now + next.interval; else this.clearTimeout(next.id);
            next.fn(...next.args);
        }
        this.now = target;
    }
}
const fakeClock = new FakeClock();
`

func buildFetchMockSnippet(mocks map[string]string) string {
	if len(mocks) == 0 {
		return ""
	}
	encoded, _ := json.Marshal(mocks)
	return fmt.Sprintf(`
const __vpnMockEndpoints = %s;
function installFetchMock(w) {
    w.fetch = async function(url) {
        const u = String(url);
        if (Object.prototype.hasOwnProperty.call(__vpnMockEndpoints, u)) {
            const body = __vpnMockEndpoints[u];
            return { ok: true, status: 200, text: async () => body, json: async () => JSON.parse(body), headers: new Map([['content-type', 'application/json']]) };
        }
        throw new Error('VPNTestFixture: unhandled fetch mock request to ' + u);
    };
}
`, string(encoded))
}

// VPNTestFixture provides a centralized harness for testing VPN dashboard templates and scripts.
type VPNTestFixture struct {
	t        *testing.T
	NodePath string
	// OwnerPage is the VPN document under test: "vpn" (overview), "vpn_backends"
	// or "vpn_diagnostics". TemplateHTML and CompanionScripts follow it, so a test
	// renders exactly the document and the modules that page ships.
	OwnerPage         string
	TemplateHTML      string
	StyleCSS          string
	SessionsJS        string
	HealthProblemsJS  string
	HealthSummaryJS   string
	ChartsJS          string
	BackendsJS        string
	CommonJS          string
	OverviewJS        string
	BackendsPageJS    string
	DiagnosticsPageJS string
	AnchorHandoffJS   string
	// PageBootJS is the merged page's boot: the jump rail, section activation and the
	// local fragment landing.
	PageBootJS string
	// PageJS is the concatenation of this delivery's page controllers. The single
	// page controller was split into one per document; the field remains so that
	// tests which scan "the page's own controller" see all three.
	PageJS      string
	ParsedDOM   *xhtml.Node
	MockFetches map[string]string
	// TablesJS is the real NexusTable controller, loaded only when a harness asks
	// for it. It must be read separately because the fixture's own script list is
	// the page's VPN modules and tables.js ships in base.html's head.
	TablesJS string
}

func extractJSFunction(source, funcName string) (string, error) {
	cleanName := strings.TrimSpace(funcName)
	if strings.HasPrefix(cleanName, "async function ") {
		cleanName = strings.TrimSpace(strings.TrimPrefix(cleanName, "async function "))
	} else if strings.HasPrefix(cleanName, "function ") {
		cleanName = strings.TrimSpace(strings.TrimPrefix(cleanName, "function "))
	}
	if cleanName == "" {
		return "", fmt.Errorf("function %s not found in source", funcName)
	}

	pattern := `(?m)\b(?:async\s+)?function\s+` + regexp.QuoteMeta(cleanName) + `(?:\s*\(|[\s\r\n])`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid function pattern for %s: %w", funcName, err)
	}

	locs := re.FindAllStringIndex(source, -1)
	if len(locs) == 0 {
		return "", fmt.Errorf("function %s not found in source", funcName)
	}

	for _, loc := range locs {
		startIdx := loc[0]
		braceStart := strings.Index(source[startIdx:], "{")
		if braceStart == -1 {
			continue
		}
		braceStart += startIdx
		depth := 1
		idx := braceStart + 1
		for idx < len(source) && depth > 0 {
			if source[idx] == '{' {
				depth++
			} else if source[idx] == '}' {
				depth--
			}
			idx++
		}
		if depth == 0 {
			return source[startIdx:idx], nil
		}
	}

	return "", fmt.Errorf("function %s not found in source", funcName)
}

func vpnDOMMock(t *testing.T, source string) string {
	t.Helper()
	var ids []string
	for _, match := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(source, -1) {
		ids = append(ids, match[1])
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		t.Fatal(err)
	}
	return "const templateIDs = " + string(encoded) + ";\n" + `const assert = require('assert');
class Element {
 constructor() { this.children=[];this._text='';this._html='';this.style={};this.className='';this.title='';this.open=false;this.attributes={};this.parentNode=null; }
 addEventListener(event, fn) {}
 removeEventListener(event, fn) {}
 set textContent(s) { this._text=String(s);this._html='';this.children=[]; }
 get textContent() {
   if (this._text) return this._text;
   if (this.children && this.children.length > 0) return this.children.map(c => c.textContent).join('');
   if (this._html) return this._html.replace(/<[^>]*>/g, '');
   return '';
 }
 set innerHTML(s) { this._html=String(s);this._text='';this.children=[]; }
 get innerHTML() {
   if (this._html) return this._html;
   if (this.children && this.children.length > 0) return this.children.map(c => c.innerHTML).join('');
   return '';
 }
 appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
 insertBefore(child, ref) {
   child.parentNode = this;
   const idx = ref ? this.children.indexOf(ref) : -1;
   if (idx >= 0) {
     this.children.splice(idx, 0, child);
   } else {
     this.children.push(child);
   }
   return child;
 }
 remove() {
   if (this.parentNode && Array.isArray(this.parentNode.children)) {
     const idx = this.parentNode.children.indexOf(this);
     if (idx >= 0) this.parentNode.children.splice(idx, 1);
   }
 }
 get nextElementSibling() {
   if (!this.parentNode || !Array.isArray(this.parentNode.children)) return null;
   const idx = this.parentNode.children.indexOf(this);
   if (idx >= 0 && idx + 1 < this.parentNode.children.length) {
     return this.parentNode.children[idx + 1];
   }
   return null;
 }
 get nextSibling() { return this.nextElementSibling; }
 get firstChild() { return this.children && this.children.length > 0 ? this.children[0] : null; }
 get lastChild() { return this.children && this.children.length > 0 ? this.children[this.children.length - 1] : null; }
 get classList() {
   const self = this;
   return {
     add(...classes) {
       const set = new Set((self.className || '').split(/\s+/).filter(Boolean));
       for (const c of classes) set.add(c);
       self.className = Array.from(set).join(' ');
     },
     remove(...classes) {
       const set = new Set((self.className || '').split(/\s+/).filter(Boolean));
       for (const c of classes) set.delete(c);
       self.className = Array.from(set).join(' ');
     },
     contains(c) {
       return (self.className || '').split(/\s+/).filter(Boolean).includes(c);
     },
     toggle(c, force) {
       const set = new Set((self.className || '').split(/\s+/).filter(Boolean));
       const has = set.has(c);
       const want = force !== undefined ? !!force : !has;
       if (want) set.add(c); else set.delete(c);
       self.className = Array.from(set).join(' ');
       return want;
     }
   };
 }
 set id(val) { this._id = String(val); elements.set(String(val), this); }
 get id() { return this._id || this.attributes['id'] || ''; }
 setAttribute(k,v) { this.attributes[k]=String(v); if (k === 'id') { this._id = String(v); elements.set(String(v), this); } }
 getAttribute(k) { return this.attributes[k]; }
 querySelector() { return null; }
 querySelectorAll() { return []; }
}
const elements = new Map();
const dynamicIDs = new Set(['vpnSessionsStaleBanner']);
const document = {
 reset() { elements.clear(); for (const id of templateIDs) elements.set(id,new Element()); },
 getElementById(id) {
   if (elements.has(id)) return elements.get(id);
   if (dynamicIDs.has(id)) return null;
   assert(elements.has(id), 'DOM id missing from actual template: '+id);
   return null;
 },
 createElement() { return new Element(); },
 createTextNode(s) { const el = new Element(); el.textContent = String(s); return el; },
 addEventListener(event, fn) {},
 removeEventListener(event, fn) {},
};
document.reset();
if (typeof window === 'undefined') {
  global.window = global;
}
window.document = document;
`
}

func vpnDiagnosticsLocale(t *testing.T, lang string) map[string]string {
	t.Helper()
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(transFS, lang+".json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		t.Fatalf("invalid locale object: %s", lang)
	}
	dict := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := keyToken.(string)
		if !ok {
			t.Fatalf("invalid locale key in %s", lang)
		}
		if _, exists := dict[key]; exists {
			t.Fatalf("duplicate locale key %s/%s", lang, key)
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		dict[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	return dict
}

func vpnDiagnosticsTranslationsJS(t *testing.T, lang string) string {
	t.Helper()
	encoded, err := json.Marshal(vpnDiagnosticsLocale(t, lang))
	if err != nil {
		t.Fatal(err)
	}
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatal(err)
	}
	ui, err := fs.ReadFile(staticFS, "js/ui.js")
	if err != nil {
		t.Fatal(err)
	}
	escape, err := extractJSFunction(string(ui), "function escapeHtml")
	if err != nil {
		t.Fatal(err)
	}
	return "const translations = " + string(encoded) + ";\nconst _ = key => translations[key] || key;\n" + escape + "\n"
}

func vpnDiagnosticsRenderedHTML(t *testing.T, source string, dict map[string]string) string {
	t.Helper()
	parsed, err := template.New("vpn.html").Funcs(withAssetURL(template.FuncMap{
		"_": func(key string) string {
			if value, ok := dict[key]; ok {
				return value
			}
			return key
		},
	})).Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := parsed.ExecuteTemplate(&rendered, "content", nil); err != nil {
		t.Fatal(err)
	}
	return rendered.String()
}

func vpnDiagnosticsStaticOracle(rendered string, dict map[string]string) error {
	// Every relocated diagnostic value must keep its localized label, now as a
	// <dt>/<dd> pair inside Advanced Diagnostics rather than a dense panel row.
	fields := map[string]string{
		"vpn-diag-ewma5m":          "vpn_diag_avg_5m",
		"vpn-diag-ewma1h":          "vpn_diag_avg_1h",
		"vpn-diag-queue-occ":       "vpn_forwarder_queue",
		"vpn-diag-queue-peak":      "vpn_forwarder_peak",
		"vpn-diag-drops-client":    "vpn_diag_drops_outbound",
		"vpn-diag-drops-return":    "vpn_diag_drops_inbound",
		"vpn-diag-drops-total":     "vpn_diag_total_drop_rate",
		"vpn-diag-engine-status":   "vpn_diag_engine",
		"vpn-diag-hs-freshness":    "vpn_diag_handshake_freshness",
		"vpn-diag-routing-counts":  "vpn_diag_route_integrity",
		"vpn-diag-res-cpu":         "vpn_diag_cpu_usage",
		"vpn-diag-res-mem":         "vpn_diag_memory",
		"vpn-diag-res-fd":          "vpn_diag_file_descriptors",
		"vpn-diag-lat-percentiles": "vpn_diag_forward_p95_recent",
		// The four aggregate rows restored in round 3 must carry localized labels
		// too, so a hardcoded English heading fails here in every non-English locale.
		"vpn-diag-packet-rate":        "vpn_diag_packet_rate",
		"vpn-diag-lat-max":            "vpn_diag_max_duration",
		"vpn-diag-queue-dwell":        "vpn_diag_queue_above_50",
		"vpn-diag-write-stalls-total": "vpn_diag_write_stalls_cumulative",
	}
	labels := make(map[string]string)
	fieldPattern := regexp.MustCompile(`<dt>([^<]+)</dt><dd[^>]*id="([^"]+)"`)
	for _, match := range fieldPattern.FindAllStringSubmatch(rendered, -1) {
		labels[match[2]] = html.UnescapeString(match[1])
	}
	// The throughput row labels itself by composing two existing members rather
	// than a dedicated row key. Asserted as the composition, not the single key:
	// the current / cumulative distinction has to stay explicit in every locale.
	wantThroughputLabel := dict["vpn_fwd_kpi_throughput"] + " (" + dict["vpn_fwd_horizon_current"] + ")"
	if labels["vpn-diag-throughput"] != wantThroughputLabel {
		return fmt.Errorf("static label vpn-diag-throughput: got %q, want %q",
			labels["vpn-diag-throughput"], wantThroughputLabel)
	}
	for id, key := range fields {
		if labels[id] != dict[key] {
			return fmt.Errorf("static label %s: got %q, want %q", id, labels[id], dict[key])
		}
	}

	// Every chart caption must be localized, bound to ITS chart. A caption replaced
	// by hardcoded English has to fail here; asserting only that the four signals are
	// localized let that regression through.
	captions := map[string]string{
		"throughput": "vpn_fwd_kpi_throughput",
		"drops":      "vpn_diag_drop_rate",
		"latency":    "vpn_diag_latency_p95",
		"queue":      "vpn_diag_queue_utilization",
	}
	captionPattern := regexp.MustCompile(`<figcaption class="vpn-chart-caption">\s*<span>([^<]+)</span>\s*<span id="vpn-chart-([a-z]+)-badges"`)
	seenCaptions := make(map[string]bool)
	for _, match := range captionPattern.FindAllStringSubmatch(rendered, -1) {
		caption, chart := html.UnescapeString(match[1]), match[2]
		key, ok := captions[chart]
		if !ok {
			return fmt.Errorf("unexpected chart caption for %s: %q", chart, caption)
		}
		if caption != dict[key] {
			return fmt.Errorf("chart caption %s: got %q, want %q", chart, caption, dict[key])
		}
		seenCaptions[chart] = true
	}
	for chart := range captions {
		if !seenCaptions[chart] {
			return fmt.Errorf("chart %s has no localized caption in the rendered template", chart)
		}
	}

	// The health summary must live inside the polite atomic live region, and that
	// region must also contain the problem announcement. Asserting the semantic
	// containment rather than one exact attribute string keeps this true when the
	// region's wrapper changes.
	liveRegion := regexp.MustCompile(`<div class="vpn-health-live" id="vpn-fwd-health-live" role="status" aria-atomic="true">([\s\S]*?)</div>`)
	live := liveRegion.FindStringSubmatch(rendered)
	if len(live) != 2 {
		return errors.New("the health block must expose one polite atomic live region")
	}
	if !strings.Contains(live[1], `id="vpn-fwd-headline-summary"`) {
		return errors.New("the health summary must be inside the live region")
	}
	if !strings.Contains(live[1], `id="vpn-fwd-problem-announcement"`) {
		return errors.New("the problem announcement must be inside the live region")
	}
	if !strings.Contains(rendered, `id="vpn-advanced-entry"`) {
		return errors.New("Advanced Diagnostics entry is missing")
	}
	if !strings.Contains(rendered, html.EscapeString(dict["vpn_diagnostics_traffic"])) {
		return errors.New("traffic section heading is not localized")
	}
	if !strings.Contains(rendered, "<summary>\n                <span>"+html.EscapeString(dict["vpn_diag_loss_backend_history"])) &&
		!strings.Contains(rendered, html.EscapeString(dict["vpn_diag_loss_backend_history"])) {
		return errors.New("history details heading is not localized")
	}
	return nil
}

// splitVPNTemplateAndCompanionScripts cleanly splits a combined VPN source into template HTML
// and companion scripts using the explicit companion boundary marker. If absent, it fails closed
// with an explicit error instead of silently treating HTML as JavaScript.
func splitVPNTemplateAndCompanionScripts(source string) (templateSource, companionScripts string, err error) {
	if idx := strings.Index(source, vpnCompanionBoundaryMarker); idx >= 0 {
		templateSource = source[:idx]
		companionScripts = strings.TrimPrefix(source[idx+len(vpnCompanionBoundaryMarker):], "\n")
		return templateSource, companionScripts, nil
	}
	return "", "", errors.New("template marker not found in source")
}

// assembleVPNHealthScript builds an executable health diagnostics test script from explicit template HTML and companion scripts.
func assembleVPNHealthScript(t *testing.T, templateHTML, companionScripts, lang, assertions string) (string, error) {
	t.Helper()
	if !strings.Contains(companionScripts, "function vpnRenderForwarderHealth") {
		return "", errors.New("source lacks function vpnRenderForwarderHealth")
	}
	script := vpnDOMMock(t, templateHTML) + "\n" + vpnDiagnosticsTranslationsJS(t, lang)
	return script + "\n" + companionScripts + "\n" + assertions, nil
}

// AssembleHealthScript builds a health diagnostics test script from explicit fixture components.
func (f *VPNTestFixture) AssembleHealthScript(lang, assertions string) (string, error) {
	return assembleVPNHealthScript(f.t, f.TemplateHTML, f.CompanionScripts(), lang, assertions)
}

func vpnDiagnosticsHealthScript(t *testing.T, source, assertions string) string {
	t.Helper()
	script, err := vpnDiagnosticsHealthScriptLocale(t, source, "en", assertions)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func vpnDiagnosticsHealthScriptLocale(t *testing.T, source, lang, assertions string) (string, error) {
	t.Helper()
	if !strings.Contains(source, "function vpnRenderForwarderHealth") {
		return "", errors.New("source lacks function vpnRenderForwarderHealth")
	}

	templateSource, companionScripts, err := splitVPNTemplateAndCompanionScripts(source)
	if err != nil {
		return "", err
	}

	return assembleVPNHealthScript(t, templateSource, companionScripts, lang, assertions)
}
