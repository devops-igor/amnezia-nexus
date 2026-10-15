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
	t            *testing.T
	NodePath     string
	TemplateHTML string
	StyleCSS     string
	SessionsJS   string
	ParsedDOM    *xhtml.Node
	MockFetches  map[string]string
}

// JSDOMHarnessOptions configures a JSDOM evaluation harness.
type JSDOMHarnessOptions struct {
	HTML             string
	Language         string
	Direction        string
	IncludeFakeClock bool
	IncludeFetchMock bool
	ExtractedFuncs   []string
	ExtraJS          string
}

// NewVPNTestFixture initializes a VPN test fixture with loaded templates, styles, and parsed DOM.
// In CI environments, missing Node binary fails closed with t.Fatalf.
func NewVPNTestFixture(t *testing.T) *VPNTestFixture {
	t.Helper()
	tmplFS, err1 := GetTemplatesSubFS()
	staticFS, err2 := GetStaticSubFS()
	if err := errors.Join(err1, err2); err != nil {
		t.Fatalf("filesystem sub-FS initialization failed: %v", err)
	}
	vpnBytes, err1 := fs.ReadFile(tmplFS, "vpn.html")
	cssBytes, err2 := fs.ReadFile(staticFS, "css/style.css")
	if err := errors.Join(err1, err2); err != nil {
		t.Fatalf("failed reading fixture files: %v", err)
	}
	doc, err := xhtml.Parse(strings.NewReader(string(vpnBytes)))
	if err != nil {
		t.Fatalf("failed to parse vpn.html: %v", err)
	}
	nodePath, err := findNodeBinary()
	if err != nil && isCIEnvironment() {
		t.Fatalf("node binary is required under CI: %v", err)
	}
	sessionsBytes, _ := fs.ReadFile(staticFS, "js/vpn/sessions.js")
	sessionsJS := string(sessionsBytes)
	return &VPNTestFixture{
		t:            t,
		NodePath:     nodePath,
		TemplateHTML: string(vpnBytes),
		StyleCSS:     string(cssBytes),
		SessionsJS:   sessionsJS,
		ParsedDOM:    doc,
		MockFetches:  make(map[string]string),
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
	return vpnDiagnosticsTranslationsJS(f.t, f.TemplateHTML, lang)
}

func (f *VPNTestFixture) RenderedHTML(lang string) string {
	f.t.Helper()
	return vpnDiagnosticsRenderedHTML(f.t, f.TemplateHTML, f.Locale(lang))
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
	htmlBody := opts.HTML
	if htmlBody == "" {
		if idx := strings.Index(f.TemplateHTML, "<script>"); idx >= 0 {
			htmlBody = f.TemplateHTML[:idx]
		} else {
			htmlBody = f.TemplateHTML
		}
	}
	var b strings.Builder
	b.WriteString(jsdomBootstrapSnippet + "\n")
	if opts.IncludeFakeClock {
		b.WriteString(jsdomFakeClockSnippet + "\n")
	}
	if opts.IncludeFetchMock && len(f.MockFetches) > 0 {
		b.WriteString(buildFetchMockSnippet(f.MockFetches) + "\n")
	}
	var extracted strings.Builder
	for _, fn := range opts.ExtractedFuncs {
		code, err := extractJSFunction(f.TemplateHTML, "function "+fn)
		if err != nil {
			f.t.Fatalf("extractJSFunction %s failed: %v", fn, err)
		}
		extracted.WriteString(code + "\n")
	}
	docHTML := fmt.Sprintf("<!DOCTYPE html><html dir=\"%s\"><head><style>%s</style></head><body>%s</body></html>",
		dir, f.StyleCSS, htmlBody)
	b.WriteString(fmt.Sprintf(`
const dom = new JSDOM(%q, { pretendToBeVisual: true, runScripts: 'outside-only', url: 'https://review.invalid' });
const w = dom.window;
if (typeof fakeClock !== 'undefined') {
    w.fakeClock = fakeClock;
    ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'].forEach(m => { w[m] = fakeClock[m].bind(fakeClock); });
}
if (typeof installFetchMock === 'function') { installFetchMock(w); }
if (%t) { w.eval(%q); }
w.eval(%q + "\nwindow.translations = translations;\nwindow._ = _;\n" + %q);
`, docHTML, f.SessionsJS != "", f.SessionsJS, f.TranslationsJS(lang), extracted.String()))
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

func findHTMLNodeByID(n *xhtml.Node, id string) *xhtml.Node {
	if id == "" {
		return nil
	}
	if n == nil {
		return nil
	}
	if n.Type == xhtml.ElementNode {
		for _, attr := range n.Attr {
			if attr.Key == "id" && attr.Val == id {
				return n
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if res := findHTMLNodeByID(c, id); res != nil {
			return res
		}
	}
	return nil
}

func getHTMLNodeAttr(n *xhtml.Node, key string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func findHTMLNodesByTag(n *xhtml.Node, tag string) []*xhtml.Node {
	var results []*xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(curr *xhtml.Node) {
		if curr == nil {
			return
		}
		if curr != n && curr.Type == xhtml.ElementNode && curr.Data == tag {
			results = append(results, curr)
			return
		}
		for c := curr.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return results
}

func getHTMLNodeText(n *xhtml.Node) string {
	var b strings.Builder
	var walk func(*xhtml.Node)
	walk = func(curr *xhtml.Node) {
		if curr == nil {
			return
		}
		if curr.Type == xhtml.TextNode {
			b.WriteString(curr.Data)
		}
		for c := curr.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(b.String())
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

func hasHTMLClass(n *xhtml.Node, className string) bool {
	if n == nil {
		return false
	}
	for _, c := range strings.Fields(getHTMLNodeAttr(n, "class")) {
		if c == className {
			return true
		}
	}
	return false
}

func findClosestEnclosingCard(n *xhtml.Node) *xhtml.Node {
	for curr := n.Parent; curr != nil; curr = curr.Parent {
		if curr.Type == xhtml.ElementNode && hasHTMLClass(curr, "card") {
			return curr
		}
	}
	return nil
}

func isHTMLDescendant(ancestor, node *xhtml.Node) bool {
	if ancestor == nil || node == nil {
		return false
	}
	for curr := node.Parent; curr != nil; curr = curr.Parent {
		if curr == ancestor {
			return true
		}
	}
	return false
}

func countHTMLNodesByID(root *xhtml.Node, id string) int {
	count := 0
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil {
			return
		}
		if n.Type == xhtml.ElementNode && getHTMLNodeAttr(n, "id") == id {
			count++
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	return count
}

func findTopLevelStatsGrid(doc *xhtml.Node) *xhtml.Node {
	var walk func(*xhtml.Node) *xhtml.Node
	walk = func(n *xhtml.Node) *xhtml.Node {
		if n == nil {
			return nil
		}
		if n.Type == xhtml.ElementNode && hasHTMLClass(n, "stats-grid") {
			// Top-level KPI grid must not be enclosed inside another card (e.g. forwarder card)
			if findClosestEnclosingCard(n) == nil {
				return n
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if found := walk(c); found != nil {
				return found
			}
		}
		return nil
	}
	return walk(doc)
}

func validateVPNDashboardDOMOrder(doc *xhtml.Node) error {
	if doc == nil {
		return errors.New("nil document")
	}

	// 1. Top-level KPI grid container (.stats-grid)
	topGrid := findTopLevelStatsGrid(doc)
	if topGrid == nil {
		return errors.New("top-level .stats-grid container not found")
	}

	// 2. #vpnBackendsTable and closest enclosing outer .card
	if count := countHTMLNodesByID(doc, "vpnBackendsTable"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpnBackendsTable element, found %d", count)
	}
	backendsTable := findHTMLNodeByID(doc, "vpnBackendsTable")
	if backendsTable == nil {
		return errors.New("#vpnBackendsTable not found")
	}
	backendsCard := findClosestEnclosingCard(backendsTable)
	if backendsCard == nil {
		return errors.New("closest enclosing .card for #vpnBackendsTable not found")
	}

	// 3. #vpnSessionsTable and closest enclosing outer .card
	if count := countHTMLNodesByID(doc, "vpnSessionsTable"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpnSessionsTable element, found %d", count)
	}
	sessionsTable := findHTMLNodeByID(doc, "vpnSessionsTable")
	if sessionsTable == nil {
		return errors.New("#vpnSessionsTable not found")
	}
	sessionsCard := findClosestEnclosingCard(sessionsTable)
	if sessionsCard == nil {
		return errors.New("closest enclosing .card for #vpnSessionsTable not found")
	}

	// 4. #vpn-forwarder-card
	if count := countHTMLNodesByID(doc, "vpn-forwarder-card"); count != 1 {
		return fmt.Errorf("expected exactly 1 #vpn-forwarder-card element, found %d", count)
	}
	forwarderCard := findHTMLNodeByID(doc, "vpn-forwarder-card")
	if forwarderCard == nil {
		return errors.New("#vpn-forwarder-card not found")
	}

	sections := []*xhtml.Node{topGrid, backendsCard, sessionsCard, forwarderCard}
	sectionNames := []string{"stats-grid", "backends card", "sessions card", "vpn-forwarder-card"}

	// Assert distinct elements
	for i := 0; i < len(sections); i++ {
		for j := i + 1; j < len(sections); j++ {
			if sections[i] == sections[j] {
				return fmt.Errorf("sections %s and %s resolve to identical element", sectionNames[i], sectionNames[j])
			}
		}
	}

	// Assert no section is a descendant of another
	for i := 0; i < len(sections); i++ {
		for j := 0; j < len(sections); j++ {
			if i != j && isHTMLDescendant(sections[i], sections[j]) {
				return fmt.Errorf("section %s is nested within / descendant of section %s", sectionNames[j], sectionNames[i])
			}
		}
	}

	// Assert all 4 section containers share the exact same immediate parent element
	parent := topGrid.Parent
	if parent == nil {
		return errors.New("top-level .stats-grid has nil parent")
	}
	for i, s := range sections {
		if s.Parent != parent {
			return fmt.Errorf("section %s does not share immediate parent with stats-grid", sectionNames[i])
		}
	}

	// Sibling index sequence in parent container strictly:
	// stats-grid -> backends card -> sessions card -> vpn-forwarder-card
	getSiblingIndex := func(target *xhtml.Node) int {
		idx := 0
		for c := parent.FirstChild; c != nil; c = c.NextSibling {
			if c == target {
				return idx
			}
			idx++
		}
		return -1
	}

	idxStats := getSiblingIndex(topGrid)
	idxBackends := getSiblingIndex(backendsCard)
	idxSessions := getSiblingIndex(sessionsCard)
	idxForwarder := getSiblingIndex(forwarderCard)

	if idxStats == -1 || idxBackends == -1 || idxSessions == -1 || idxForwarder == -1 {
		return errors.New("failed to resolve sibling indices in immediate parent")
	}

	if !(idxStats < idxBackends && idxBackends < idxSessions && idxSessions < idxForwarder) {
		return fmt.Errorf("invalid sibling order: stats-grid=%d, backends-card=%d, sessions-card=%d, vpn-forwarder-card=%d (expected stats < backends < sessions < forwarder)",
			idxStats, idxBackends, idxSessions, idxForwarder)
	}

	return nil
}

func extractJSFunction(source, funcName string) (string, error) {
	startIdx := strings.Index(source, funcName)
	if startIdx == -1 {
		// Fallback: search static JS files in StaticFS (e.g. static/js/vpn/sessions.js)
		if entries, err := fs.ReadDir(StaticFS, "static/js/vpn"); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".js") {
					if content, err := fs.ReadFile(StaticFS, "static/js/vpn/"+entry.Name()); err == nil {
						if strings.Index(string(content), funcName) != -1 {
							return extractJSFunction(string(content), funcName)
						}
					}
				}
			}
		}
		return "", fmt.Errorf("function %s not found in source", funcName)
	}
	braceStart := strings.Index(source[startIdx:], "{")
	if braceStart == -1 {
		return "", fmt.Errorf("opening brace for %s not found", funcName)
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
	if depth != 0 {
		return "", fmt.Errorf("unbalanced braces in function %s", funcName)
	}
	return source[startIdx:idx], nil
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
 createTextNode(s) { const el = new Element(); el.textContent = String(s); return el; }
};
document.reset();
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

func vpnDiagnosticsTranslationsJS(t *testing.T, source, lang string) string {
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
	result := "const translations = " + string(encoded) + ";\nconst _ = key => translations[key] || key;\n" + escape + "\n"
	for _, name := range []string{"vpnDiagText", "vpnStatusLabel", "vpnLossReasonLabels"} {
		// The original template has no interpolation helper; baseline repro still
		// executes its real renderer instead of failing only on missing source.
		if !strings.Contains(source, "function "+name+"(") {
			continue
		}
		function, err := extractJSFunction(source, "function "+name)
		if err != nil {
			t.Fatal(err)
		}
		result += function + "\n"
	}
	return result
}

func vpnDiagnosticsRenderedHTML(t *testing.T, source string, dict map[string]string) string {
	t.Helper()
	parsed, err := template.New("vpn.html").Funcs(template.FuncMap{
		"_": func(key string) string {
			if value, ok := dict[key]; ok {
				return value
			}
			return key
		},
	}).Parse(source)
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
	fields := map[string]string{
		"vpn-diag-throughput":     "vpn_fwd_kpi_throughput",
		"vpn-diag-ewma5m":         "vpn_diag_avg_5m",
		"vpn-diag-ewma1h":         "vpn_diag_avg_1h",
		"vpn-diag-queue-occ":      "vpn_diag_occupancy",
		"vpn-diag-queue-peak":     "vpn_forwarder_peak",
		"vpn-diag-lat-max":        "vpn_diag_max_duration",
		"vpn-diag-drops-client":   "vpn_diag_drops_outbound",
		"vpn-diag-drops-return":   "vpn_diag_drops_inbound",
		"vpn-diag-drops-total":    "vpn_diag_total_drop_rate",
		"vpn-diag-engine-status":  "vpn_diag_engine",
		"vpn-diag-hs-freshness":   "vpn_diag_handshake_freshness",
		"vpn-diag-routing-counts": "vpn_diag_route_integrity",
		"vpn-diag-res-cpu":        "vpn_diag_cpu_usage",
		"vpn-diag-res-mem":        "vpn_diag_memory",
		"vpn-diag-res-fd":         "vpn_diag_file_descriptors",
	}
	labels := make(map[string]string)
	fieldPattern := regexp.MustCompile(`<div class="flex justify-between"><span class="text-muted">([^<]+)</span><span class="font-mono" id="([^"]+)"`)
	for _, match := range fieldPattern.FindAllStringSubmatch(rendered, -1) {
		labels[match[2]] = html.UnescapeString(match[1])
	}
	for id, key := range fields {
		if labels[id] != dict[key]+":" {
			return fmt.Errorf("static label %s: got %q, want %q", id, labels[id], dict[key]+":")
		}
	}
	for id, key := range map[string]string{
		"throughput": "vpn_fwd_kpi_throughput", "queue": "vpn_diag_queue_utilization",
		"drops": "vpn_diag_drop_rate", "latency": "vpn_diag_latency_p95",
	} {
		pattern := regexp.MustCompile(`<div style="font-size: 0.75rem; color: var\(--text-muted\);">([^<]+)</div>\s*<div id="vpn-chart-` + id + `-badges"`)
		match := pattern.FindStringSubmatch(rendered)
		expected := dict[key]
		if len(match) != 2 || html.UnescapeString(match[1]) != expected {
			return fmt.Errorf("static chart %s is not localized", id)
		}
	}
	if !strings.Contains(rendered, "<details><summary>"+html.EscapeString(dict["vpn_diag_loss_backend_history"])+"</summary>") {
		return errors.New("history details heading is not localized")
	}
	return nil
}

func vpnDiagnosticsHealthScript(t *testing.T, source, assertions string) string {
	t.Helper()
	return vpnDiagnosticsHealthScriptLocale(t, source, "en", assertions)
}

func vpnDiagnosticsHealthScriptLocale(t *testing.T, source, lang, assertions string) string {
	t.Helper()
	script := vpnDOMMock(t, source) + vpnDiagnosticsTranslationsJS(t, source, lang)
	for _, name := range []string{"vpnFormatPeerKey", "vpnRenderForwarderHealth"} {
		function, err := extractJSFunction(source, "function "+name)
		if err != nil {
			t.Fatal(err)
		}
		script += "\n" + function
	}
	return script + "\nlet vpnLastStatus=null;let vpnShowAllRoutes=false;\n" + assertions
}

func TestVPNTestFixture(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	if fixture.TemplateHTML == "" {
		t.Fatal("expected non-empty TemplateHTML")
	}
	if fixture.StyleCSS == "" {
		t.Fatal("expected non-empty StyleCSS")
	}
	if fixture.ParsedDOM == nil {
		t.Fatal("expected non-nil ParsedDOM")
	}

	t.Run("DOMQueryHelpers", func(t *testing.T) {
		fx := fixture.WithT(t)
		topCard := fx.FindByID("vpn-forwarder-card")
		if topCard == nil {
			t.Fatal("expected to find #vpn-forwarder-card")
		}
		tables := fx.FindByTag("table")
		if len(tables) == 0 {
			t.Fatal("expected at least one table in vpn.html")
		}
		if err := fx.ValidateDashboardOrder(); err != nil {
			t.Fatalf("dashboard DOM order validation failed: %v", err)
		}
		if none := fx.FindByID(""); none != nil {
			t.Fatalf("expected FindByID(\"\") to return nil, got %v", none)
		}
	})

	t.Run("LocalizationInjection", func(t *testing.T) {
		fx := fixture.WithT(t)
		enDict := fx.Locale("en")
		if len(enDict) == 0 {
			t.Fatal("expected non-empty en locale dict")
		}
		rendered := fx.RenderedHTML("en")
		if len(rendered) == 0 {
			t.Fatal("expected non-empty rendered HTML")
		}
		if err := vpnDiagnosticsStaticOracle(rendered, enDict); err != nil {
			t.Fatalf("static oracle failed: %v", err)
		}
	})

	t.Run("JSDOMFakeClockAndMockFetch", func(t *testing.T) {
		fx := fixture.WithT(t)
		fx.MockEndpoint("/api/vpn/status", `{"forwarder_available": true, "status": "HEALTHY"}`)
		testScript := fx.BuildJSDOMHarness(JSDOMHarnessOptions{
			IncludeFakeClock: true,
			IncludeFetchMock: true,
			ExtraJS: `
(async () => {
    let timerFired = false;
    w.fakeClock.setTimeout(() => { timerFired = true; }, 500);
    assert.strictEqual(timerFired, false, 'timer should not fire before tick');
    w.fakeClock.tick(500);
    assert.strictEqual(timerFired, true, 'timer should fire after tick');
    const res = await w.fetch('/api/vpn/status');
    const data = await res.json();
    assert.strictEqual(data.forwarder_available, true, 'mock fetch must return payload');
    assert.strictEqual(data.status, 'HEALTHY', 'mock fetch payload match');
    console.log('FIXTURE_JSDOM_PASS');
})().catch(e => { console.error(e); process.exit(1); });
`,
		})
		out := fx.RunJSDOM(testScript)
		if !strings.Contains(out, "FIXTURE_JSDOM_PASS") {
			t.Fatalf("expected FIXTURE_JSDOM_PASS, got: %s", out)
		}
	})

	t.Run("BacktickPreservationInHarness", func(t *testing.T) {
		fx := fixture.WithT(t)
		harness := fx.BuildJSDOMHarness(JSDOMHarnessOptions{
			HTML: `<div id="backtick-test">` + "`literal_backtick`" + `</div>`,
		})
		if strings.Contains(harness, `\`+"`") {
			t.Fatalf("BuildJSDOMHarness must not escape backticks with backslashes; found backslash-escaped backtick")
		}
		if !strings.Contains(harness, "`literal_backtick`") {
			t.Fatalf("BuildJSDOMHarness must contain raw backtick literal")
		}
	})

	t.Run("WithTSubtestBinding", func(t *testing.T) {
		fx := fixture.WithT(t)
		if fx.t != t {
			t.Fatalf("expected fx.t to be subtest t, got %v", fx.t)
		}
	})

	t.Run("FailClosedCIInvariant", func(t *testing.T) {
		origCI := os.Getenv("CI")
		defer os.Setenv("CI", origCI)
		os.Setenv("CI", "")
		if isCIEnvironment() {
			t.Fatal("expected isCIEnvironment() to be false when CI=''")
		}
		for _, v := range []string{"true", "1", "TRUE"} {
			os.Setenv("CI", v)
			if !isCIEnvironment() {
				t.Fatalf("expected isCIEnvironment() to be true when CI=%q", v)
			}
		}
	})
}
