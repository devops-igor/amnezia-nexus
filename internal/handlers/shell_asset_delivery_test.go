package handlers

// Cache identity for the assets this delivery changed.
//
// /static is served with Cache-Control: public, max-age=86400, so a browser
// keeps an asset whose URL does not change. The release version moves only when
// a release moves it; an asset edited inside one release therefore keeps the URL
// its predecessor served, and a returning browser runs the previous bytes
// against the new markup. A delivery routes such an asset through asset_url,
// whose query is the digest of that asset's own bytes.
//
// These checks read the RENDERED output of the shipped shells, because that is
// what the browser receives. A scan of the template text cannot tell which
// identity a page actually emits, and a guard that enumerated only the modules
// one surface loads could not see a dependency the layout adds — the shape of
// this defect, where the page's new behaviour sat on the table engine while the
// layout still requested that engine at its predecessor's bare URL.
//
// Three checks, because each catches what the others cannot:
//
//   - an enumeration renders every shell the production engine can execute, as
//     an anonymous visitor and as an administrator, and requires every reference
//     to an asset this delivery changed to carry the digest of the bytes this
//     build ships; a bare reference to anything else fails unless it is a named
//     asset this delivery did not touch;
//   - a byte-change check renders base.html twice with one asset's bytes
//     different and requires that asset's URL to move while other delivered
//     URLs stay put, so the query is shown to be an identity rather than a
//     constant that happens to be right today;
//   - a control applies the same rule to a render with one reference reverted to
//     the bare form and to the release-version form, and requires it to be
//     reported — the enumeration is otherwise indistinguishable from a check
//     that can never fail.

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// untouchedBareShellAssets are the /static scripts a shipped shell requests with
// no cache identity at all, and that this delivery did not change. They are
// listed so the enumeration above can tell "served bare because untouched" from
// "served bare because the delivery forgot it": an asset whose bytes this
// delivery changed may not appear here, and a newly introduced bare reference
// has to be reviewed and named here before the enumeration accepts it.
//
// An asset that moves to asset_url leaves this list. An asset that appears here
// without review is exactly what the enumeration exists to stop.
var untouchedBareShellAssets = []string{
	"/static/js/captcha.js",
	"/static/js/qrcode.min.js",
	"/static/js/telemetry.js",
	"/static/js/users.js",
}

// shellRenderContexts are the sessions every shell is rendered with. A block
// gated on a role could hold the only reference to an asset, so rendering only
// one context would leave that reference unchecked.
var shellRenderContexts = []struct {
	name string
	sess *models.SessionData
}{
	{name: "anonymous"},
	{name: "admin", sess: &models.SessionData{
		UserID:   "shell-asset-admin",
		Username: "admin",
		Role:     models.RoleAdmin,
	}},
}

// shippedAssetDigest is the query a URL for path must carry: the SHA-256 of the
// bytes this build embeds for it, in hex. It is computed here from the shipped
// bytes rather than read back from the helper, so a helper that returned a
// constant could not satisfy it.
func shippedAssetDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := web.StaticFS.ReadFile(strings.TrimPrefix(path, "/"))
	if err != nil {
		t.Fatalf("read the delivered asset %s: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// renderEveryShippedShell renders every shell the production template engine
// holds, with each context, and returns shell → context → markup. The shells are
// taken from the engine's own set rather than a list kept here, so a page added
// to loadTemplates is enumerated without anyone having to remember it, and a
// page that stops rendering fails loudly instead of dropping out of the scan.
func renderEveryShippedShell(t *testing.T) map[string]map[string]string {
	t.Helper()
	_, db, _ := setupTestHandlers(t)
	engine := GetTemplateEngine()

	const wantShells = 12
	if len(engine.templates) < wantShells {
		t.Fatalf("the template engine holds %d shells, want at least %d; an enumeration over a "+
			"shrunken set would pass while checking almost nothing", len(engine.templates), wantShells)
	}

	rendered := make(map[string]map[string]string, len(engine.templates))
	for shell := range engine.templates {
		rendered[shell] = make(map[string]string, len(shellRenderContexts))
		for _, ctx := range shellRenderContexts {
			req := httptest.NewRequest(http.MethodGet, "/shell-asset-identity", nil)
			if ctx.sess != nil {
				req = req.WithContext(middleware.WithSession(req.Context(), ctx.sess))
			}
			w := httptest.NewRecorder()
			if err := RenderTemplate(w, req, db, shell, nil); err != nil {
				t.Fatalf("render %s (%s): %v", shell, ctx.name, err)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("render %s (%s) = %d, want 200", shell, ctx.name, w.Code)
			}
			body := w.Body.String()
			if strings.Contains(body, "{{") {
				t.Fatalf("%s (%s) leaked an unrendered template action, so its asset links cannot be "+
					"read; body begins: %.200q", shell, ctx.name, body)
			}
			rendered[shell][ctx.name] = body
		}
	}
	return rendered
}

// shellAssetFindings reports every script or stylesheet reference in one rendered
// shell that breaks the delivery contract: a changed asset requested at anything
// other than the digest of its bytes, or a bare reference to an asset no one has
// declared untouched. The enumeration and its control both judge a render with
// this one rule, so the control proves the rule rather than a second copy of it.
func shellAssetFindings(t *testing.T, shell, markup string) []string {
	t.Helper()
	links := collectShellLinks(t, markup)
	var findings []string
	for _, url := range append(append([]string{}, links.stylesheets...), links.scripts...) {
		path, _, hasQuery := strings.Cut(url, "?")
		if slices.Contains(web.DeliveredAssets, path) {
			want := path + "?v=" + shippedAssetDigest(t, path)
			if !hasQuery || url != want {
				findings = append(findings, shell+": this delivery changed the bytes of "+path+
					", but the shell requests it at "+quoteURL(url)+"; it must be requested at "+
					quoteURL(want)+", because the URL the predecessor served is what a browser "+
					"inside the one-day freshness window still holds the old bytes under")
			}
			continue
		}
		if hasQuery {
			// An unchanged asset keeps whatever identity it already carries.
			continue
		}
		if slices.Contains(untouchedBareShellAssets, path) {
			continue
		}
		findings = append(findings, shell+": "+path+" is requested with no cache identity, and it is "+
			"not a declared-untouched asset; either this delivery changed it, in which case it "+
			"belongs in web.DeliveredAssets and must be requested through asset_url, or it is "+
			"predecessor content that has to be named in untouchedBareShellAssets")
	}
	return findings
}

// quoteURL keeps a message readable without letting a stray quote split it.
func quoteURL(url string) string {
	return `"` + strings.ReplaceAll(url, `"`, `\"`) + `"`
}

// requireDisjointAssetLists stops one asset from being both changed and
// untouched. The two lists answer different questions; an entry in both would be
// exempted by whichever branch the findings rule happened to read first.
func requireDisjointAssetLists(t *testing.T) {
	t.Helper()
	for _, path := range untouchedBareShellAssets {
		if slices.Contains(web.DeliveredAssets, path) {
			t.Fatalf("%s is listed both as untouched and as changed by this delivery; one of the two "+
				"lists is wrong and the enumeration would answer from whichever it reads first", path)
		}
	}
}

// shellAssetEvidence is what one pass over every rendered shell observed, so the
// assertions below read evidence rather than repeat the walk.
type shellAssetEvidence struct {
	// referenced maps each delivered asset to the shells that request it.
	referenced map[string][]string
	// observedBare is the set of /static paths some shell requests with no query.
	observedBare map[string]bool
	// checked counts the asset references examined.
	checked int
}

// collectShellAssetEvidence reads every reference in every rendered shell once,
// records which shells load each delivered asset, and reports each reference
// that breaks the delivery rule through the one rule function.
func collectShellAssetEvidence(t *testing.T, rendered map[string]map[string]string) shellAssetEvidence {
	t.Helper()
	ev := shellAssetEvidence{referenced: map[string][]string{}, observedBare: map[string]bool{}}
	for shell, contexts := range rendered {
		if len(contexts) != len(shellRenderContexts) {
			t.Fatalf("%s was rendered %d time(s), want %d", shell, len(contexts), len(shellRenderContexts))
		}
		for ctxName, markup := range contexts {
			links := collectShellLinks(t, markup)
			ev.checked += len(links.stylesheets) + len(links.scripts)
			for _, url := range append(append([]string{}, links.stylesheets...), links.scripts...) {
				path, _, hasQuery := strings.Cut(url, "?")
				if !hasQuery {
					ev.observedBare[path] = true
				}
				if slices.Contains(web.DeliveredAssets, path) && !slices.Contains(ev.referenced[path], shell) {
					ev.referenced[path] = append(ev.referenced[path], shell)
				}
			}
			for _, finding := range shellAssetFindings(t, shell+" ("+ctxName+")", markup) {
				t.Error(finding)
			}
		}
	}
	return ev
}

// templateAssetRef is one /static script or stylesheet reference a shipped
// template source names.
type templateAssetRef struct {
	// template is the template file that names it.
	template string
	// path is the asset path without a query.
	path string
}

// templateAssetReferences returns every /static script and stylesheet reference
// in every shipped template, in either identity form. It goes through the tag
// classification the settings surface already uses, so the two scanners cannot
// disagree about what a tag names.
func templateAssetReferences(t *testing.T) []templateAssetRef {
	t.Helper()
	templatesFS, err := web.GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	var refs []templateAssetRef
	walkErr := fs.WalkDir(templatesFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		body, readErr := fs.ReadFile(templatesFS, p)
		if readErr != nil {
			return readErr
		}
		for _, tag := range assetTagRef.FindAllString(string(body), -1) {
			ref, ok := classifyAssetRef(tag, tagAssetValueOf(tag))
			if !ok {
				continue
			}
			refs = append(refs, templateAssetRef{template: p, path: ref.path})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk templates: %v", walkErr)
	}
	if len(refs) == 0 {
		t.Fatal("no template names a /static script or stylesheet, so this coverage check examined nothing")
	}
	return refs
}

// executableTemplateNames returns the template files the production engine
// actually parsed. The engine's own trees report them, so a template added to
// the directory but never loaded is recognisable without a list kept here that
// would silently fall out of step with loadTemplates.
func executableTemplateNames() map[string]bool {
	names := map[string]bool{}
	for _, tmpl := range GetTemplateEngine().templates {
		for _, defined := range strings.Fields(tmpl.DefinedTemplates()) {
			names[strings.Trim(defined, `",`)] = true
		}
	}
	return names
}

// tagAssetValueOf returns the src or stylesheet href a tag carries, which is what
// classifyAssetRef compares when the tag is not a content-derived action. Only a
// script or a stylesheet link is an asset for this purpose: a favicon is not a
// cached code path, and accepting it would force an unrelated asset into the rule.
func tagAssetValueOf(tag string) string {
	if strings.HasPrefix(tag, "<script") {
		if m := scriptSrcAttr.FindStringSubmatch(tag); m != nil {
			return m[1]
		}
		return ""
	}
	rel := linkRelAttr.FindStringSubmatch(tag)
	href := linkHrefAttr.FindStringSubmatch(tag)
	if rel == nil || href == nil || !stylesheetRelRe.MatchString(strings.ToLower(rel[1])) {
		return ""
	}
	return href[1]
}

// TestEveryShellAssetReferenceIsExecutedAndRendered is the coverage proof for the
// enumeration above, and it is reference-level rather than path-level: a check
// that only asks "is this asset rendered somewhere" passes while a SECOND
// reference to the same asset sits in a template nothing executes. Both facts
// have to hold for each reference:
//
//   - the template that names it is one the engine parsed, so the reference is
//     not dead text in a file no shell loads;
//   - the reference is reached by a real render, so its identity form is the one
//     the enumeration above actually read.
func TestEveryShellAssetReferenceIsExecutedAndRendered(t *testing.T) {
	refs := templateAssetReferences(t)
	executable := executableTemplateNames()
	if len(executable) == 0 {
		t.Fatal("the engine reported no template names, so the executed check would refuse every reference")
	}

	rendered := map[string]bool{}
	for _, contexts := range renderEveryShippedShell(t) {
		for _, markup := range contexts {
			links := collectShellLinks(t, markup)
			for _, url := range append(append([]string{}, links.stylesheets...), links.scripts...) {
				path, _, _ := strings.Cut(url, "?")
				rendered[path] = true
			}
		}
	}

	for _, ref := range refs {
		base := ref.template
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if !executable[base] {
			t.Errorf("%s names %s, but the template engine never parses that file, so this reference "+
				"is executed by nothing and the enumeration cannot see it", ref.template, ref.path)
			continue
		}
		if !rendered[ref.path] {
			t.Errorf("%s names %s, but no rendered shell requests it; the reference is not reached by "+
				"any render this enumeration performs, so its identity form is unchecked", ref.template, ref.path)
		}
	}
}

// TestEveryShippedShellRequestsDeliveredAssetsUnderTheirBytes is the delivery
// enumeration: every shell the production engine executes, in every rendered
// context, requests each asset this delivery changed at the digest of its bytes.
func TestEveryShippedShellRequestsDeliveredAssetsUnderTheirBytes(t *testing.T) {
	requireDisjointAssetLists(t)
	ev := collectShellAssetEvidence(t, renderEveryShippedShell(t))

	if ev.checked == 0 {
		t.Fatal("no shell referenced a /static script or stylesheet, so the enumeration examined nothing")
	}

	// The untouched list is an allowlist, so an entry no shell actually emits is a
	// standing permission for a bare reference nobody reviewed: rename a file and
	// the old name could reappear, served bare, and be accepted without comment.
	// Every entry has to be observed bare in a real render.
	for _, path := range untouchedBareShellAssets {
		if !ev.observedBare[path] {
			t.Errorf("%s is declared untouched but no rendered shell requests it without a cache "+
				"identity; the entry grants a standing exemption to a reference that no longer exists", path)
		}
	}

	// A delivered asset no shell references would carry an identity nothing
	// checks, and the list would look complete while describing a file nobody
	// loads. Every entry must be reachable from a rendered shell.
	for _, path := range web.DeliveredAssets {
		if len(ev.referenced[path]) == 0 {
			t.Errorf("%s is listed as a delivered asset, but no rendered shell requests it; "+
				"either it moved out of the shells or the list has grown a file this build does "+
				"not serve", path)
		}
	}
}

// renderBaseShellWithIdentityRoot renders the shipped base.html with asset_url
// bound to root, so a check can vary one asset's bytes and read the URL the same
// template logic emits. Every other reference in the file is a literal path that
// needs no lookup.
func renderBaseShellWithIdentityRoot(t *testing.T, root fs.FS) string {
	t.Helper()
	templatesFS, err := web.GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	funcs := baseFuncMap()
	funcs["asset_url"] = func(path string) (string, error) {
		return web.AssetURLFor(root, path)
	}
	tmpl, err := template.New("base.html").Funcs(funcs).ParseFS(templatesFS, "base.html")
	if err != nil {
		t.Fatalf("parse base.html: %v", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, map[string]any{
		"lang":              "en",
		"active_page":       "vpn",
		"csrf_token":        "csrf-test-token",
		"translations_json": "{}",
		"app_version":       config.AppVersion,
		"app_codename":      config.AppCodename,
		"current_user":      map[string]any{"Username": "admin", "Role": "admin"},
		"site_settings":     map[string]any{"Title": "Amnezia", "Subtitle": "Nexus"},
	}); err != nil {
		t.Fatalf("execute base.html: %v", err)
	}
	return buf.String()
}

// urlForAsset is the URL a render requests path at, or "" when it requests none.
func urlForAsset(t *testing.T, markup, path string) string {
	t.Helper()
	links := collectShellLinks(t, markup)
	found := ""
	for _, url := range append(append([]string{}, links.stylesheets...), links.scripts...) {
		base, _, _ := strings.Cut(url, "?")
		if base != path {
			continue
		}
		if found != "" {
			t.Fatalf("%s is requested twice (%q and %q); the check below would be ambiguous", path, found, url)
		}
		found = url
	}
	return found
}

// deliveredStaticCopy holds the delivered bytes of paths as a mutable root, so a
// check can change exactly one of them and leave the rest shipped.
func deliveredStaticCopy(t *testing.T, paths ...string) fstest.MapFS {
	t.Helper()
	root := fstest.MapFS{}
	for _, path := range paths {
		body, err := web.StaticFS.ReadFile(strings.TrimPrefix(path, "/"))
		if err != nil {
			t.Fatalf("read the delivered asset %s: %v", path, err)
		}
		root[strings.TrimPrefix(path, "/")] = &fstest.MapFile{Data: body}
	}
	return root
}

// TestDeliveredAssetURLMovesWithTheBytes is the identity regression on a real
// shell render: base.html is rendered twice with the table engine's bytes
// changed in between, and its URL must move while the other delivered URL the
// file emits stays put. Pinning the current query would pass for both contents;
// varying the bytes is what shows the query follows the bytes.
func TestDeliveredAssetURLMovesWithTheBytes(t *testing.T) {
	const changed = "/static/js/tables.js"
	const other = "/static/css/vpn.css"

	// Include every shell asset resolved through asset_url, even when its URL
	// is not one of the two this byte-mutation check follows.
	root := deliveredStaticCopy(t, changed, other, "/static/css/settings.css",
		"/static/css/layout.css", "/static/js/ui.js")
	before := renderBaseShellWithIdentityRoot(t, root)
	beforeURL := urlForAsset(t, before, changed)
	if beforeURL == "" {
		t.Fatalf("base.html does not request %s at all, so its cache identity is not exercised", changed)
	}
	if want := changed + "?v=" + shippedAssetDigest(t, changed); beforeURL != want {
		t.Fatalf("base.html requests %s at %q, want %q (the digest of the shipped bytes)", changed, beforeURL, want)
	}

	// The production helper and the fixture root must agree on the shipped
	// bytes, or the byte-change below would prove a second implementation.
	production, err := web.AssetURL(changed)
	if err != nil {
		t.Fatalf("AssetURL(%s): %v", changed, err)
	}
	if production != beforeURL {
		t.Fatalf("the page requests %s at %q but the production helper emits %q", changed, beforeURL, production)
	}

	otherBefore := urlForAsset(t, before, other)
	if otherBefore == "" {
		t.Fatalf("base.html does not request %s, so the unchanged-URL control below proves nothing", other)
	}

	// Change exactly one asset's bytes, the way editing that file does.
	name := strings.TrimPrefix(changed, "/")
	root[name] = &fstest.MapFile{Data: append(append([]byte{}, root[name].Data...), []byte("\n// delivered change\n")...)}

	after := renderBaseShellWithIdentityRoot(t, root)
	afterURL := urlForAsset(t, after, changed)
	t.Logf("%s before the byte change: %s", changed, beforeURL)
	t.Logf("%s after  the byte change: %s", changed, afterURL)
	if afterURL == beforeURL {
		t.Fatalf("%s is requested at %q before and after its bytes changed, so the URL is not derived "+
			"from the bytes: a browser keeps the predecessor copy under it", changed, beforeURL)
	}
	changedSum := sha256.Sum256(root[name].Data)
	if want := changed + "?v=" + hex.EncodeToString(changedSum[:]); afterURL != want {
		t.Fatalf("%s is requested at %q after its bytes changed, want %q", changed, afterURL, want)
	}
	if got := urlForAsset(t, after, other); got != otherBefore {
		t.Fatalf("%s moved from %q to %q when another asset's bytes changed; an unchanged asset must "+
			"keep its URL or every visit refetches the whole set", other, otherBefore, got)
	}
}

// TestShellAssetEnumerationRejectsABareOrReleaseVersionedDeliveredAsset is the
// control for the enumeration above. It takes the real rendered base.html,
// rewrites the one reference the delivery fixed back into the form a predecessor
// emitted, and requires the enumeration's rule to report it. Without this the
// enumeration could be green because it examines nothing.
func TestShellAssetEnumerationRejectsABareOrReleaseVersionedDeliveredAsset(t *testing.T) {
	const changed = "/static/js/tables.js"

	rendered := renderEveryShippedShell(t)["base.html"]["admin"]
	if rendered == "" {
		t.Fatal("base.html was not rendered, so this control has nothing to mutate")
	}

	identified := urlForAsset(t, rendered, changed)
	if identified == "" || !strings.HasPrefix(identified, changed+"?v=") {
		t.Fatalf("base.html requests %s at %q, not under a cache identity; the delivery this control "+
			"guards is not in place", changed, identified)
	}

	// Positive control: the unmutated render is accepted, so a rejection below
	// is attributable to the mutation rather than to the rule failing always.
	if findings := shellAssetFindings(t, "base.html", rendered); len(findings) != 0 {
		t.Fatalf("the shipped render is reported as broken, so the control below would prove nothing: %v", findings)
	}

	reverted := map[string]string{
		"no cache identity":   `src="` + changed + `"`,
		"the release version": `src="` + changed + `?v=` + config.AppVersion + `"`,
	}
	for name, replacement := range reverted {
		mutated := strings.Replace(rendered, `src="`+identified+`"`, replacement, 1)
		if mutated == rendered {
			t.Fatalf("could not rewrite the %s reference to %s; the control would pass without "+
				"exercising the rule", changed, name)
		}
		findings := shellAssetFindings(t, "base.html", mutated)
		if len(findings) == 0 {
			t.Fatalf("a shell requesting %s under %s was accepted; the enumeration cannot fail on "+
				"the defect it exists to catch", changed, name)
		}
		if !strings.Contains(strings.Join(findings, "\n"), changed) {
			t.Fatalf("the finding for the %s form does not name %s: %v", name, changed, findings)
		}
	}
}

// TestRegeneratedStylesheetBundleHasNoShellReader pins why one changed file is
// absent from web.DeliveredAssets. The build regenerates the concatenated
// /static/css/style.css from the modular sheets, so its bytes move with this
// delivery, but every shell links the modular files and nothing requests the
// bundle. It therefore has no browser-facing URL to identify. The day a shell
// starts loading it, this check fails and the bundle has to join
// web.DeliveredAssets instead of being served bare.
func TestRegeneratedStylesheetBundleHasNoShellReader(t *testing.T) {
	const bundle = "/static/css/style.css"

	if _, err := web.StaticFS.ReadFile(strings.TrimPrefix(bundle, "/")); err != nil {
		t.Fatalf("the build ships %s: %v", bundle, err)
	}
	if slices.Contains(web.DeliveredAssets, bundle) {
		t.Fatalf("%s is listed as a delivered asset; it has no shell reader, so that entry would be "+
			"checked by nothing", bundle)
	}

	for shell, contexts := range renderEveryShippedShell(t) {
		for ctxName, markup := range contexts {
			links := collectShellLinks(t, markup)
			for _, url := range append(append([]string{}, links.stylesheets...), links.scripts...) {
				path, _, _ := strings.Cut(url, "?")
				if path == bundle {
					t.Fatalf("%s (%s) now requests %s; the bundle's bytes move with the build, so it "+
						"must be requested through asset_url and listed in web.DeliveredAssets",
						shell, ctxName, bundle)
				}
			}
		}
	}
}

// renderServerShellWithIdentityRoot renders the shipped server page with
// asset_url bound to root, so a check can vary the controller's bytes and read
// the URL the same template logic emits. It parses the set the production engine
// parses for a layout page — the shell, the layout partials and the page — so a
// section defined elsewhere cannot silently drop out of the render.
func renderServerShellWithIdentityRoot(t *testing.T, root fs.FS) string {
	t.Helper()
	templatesFS, err := web.GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	files := make([]string, 0, len(web.LayoutPartials)+2)
	files = append(files, "base.html")
	files = append(files, web.LayoutPartials...)
	files = append(files, "server.html")

	funcs := baseFuncMap()
	funcs["asset_url"] = func(path string) (string, error) {
		return web.AssetURLFor(root, path)
	}
	tmpl, err := template.New("base.html").Funcs(funcs).ParseFS(templatesFS, files...)
	if err != nil {
		t.Fatalf("parse the server page template set: %v", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, map[string]any{
		"lang":              "en",
		"active_page":       "servers",
		"csrf_token":        "csrf-test-token",
		"translations_json": "{}",
		"app_version":       config.AppVersion,
		"app_codename":      config.AppCodename,
		"current_user":      map[string]any{"Username": "admin", "Role": "admin"},
		"site_settings":     map[string]any{"Title": "Amnezia", "Subtitle": "Nexus"},
		"server": map[string]any{
			"ID": 1, "Name": "asset-identity-server", "Host": "127.0.0.1",
			"SSHPort": 22, "SSHUser": "root",
		},
		"server_id": 1,
		"users":     []any{},
	}); err != nil {
		t.Fatalf("execute the server page: %v", err)
	}
	return buf.String()
}

// TestServerPageControllerURLMovesWithTheBytes is the identity regression for the
// server page's controller, and it is the case the release version cannot pass.
//
// The controller writes the current panel (aria-current) and this delivery
// changed its bytes inside one release, so the URL a browser cached the
// predecessor under is the URL this build would serve it at if the page still
// asked for ?v=<release>. A returning browser then keeps a controller that cannot
// move aria-current while the page it runs against is the new one, and the
// programmatic current tab stays on the first panel after a switch.
//
// Three facts, each failing for a different reason:
//
//   - the rendered page requests the controller at the digest of its own bytes,
//     not at the release version;
//   - changing those bytes moves the URL on the rendered page, while the other
//     delivered URL the page emits stays put;
//   - the delivery rule rejects the predecessor's forms (bare and
//     release-versioned) for this asset on this rendered page, so the assertions
//     above cannot be green because the rule ignores the reference.
func TestServerPageControllerURLMovesWithTheBytes(t *testing.T) {
	const controller = "/static/js/server_actions.js"
	const other = "/static/css/vpn.css"

	// The page inherits the shell's links, so the root has to hold every asset
	// base.html and server.html ask for through the identity. Only the
	// controller's URL is followed here.
	root := deliveredStaticCopy(t, controller, other, "/static/css/settings.css",
		"/static/js/tables.js", "/static/js/server_telemetry.js", "/static/css/layout.css",
		"/static/js/ui.js")
	before := renderServerShellWithIdentityRoot(t, root)
	beforeURL := urlForAsset(t, before, controller)
	if beforeURL == "" {
		t.Fatalf("the server page does not request %s at all, so its cache identity is not "+
			"exercised", controller)
	}
	if release := controller + "?v=" + config.AppVersion; beforeURL == release {
		t.Fatalf("the server page requests its controller at the release version (%s): a browser "+
			"that cached the predecessor under that URL keeps the old controller against the new "+
			"page, and the predecessor cannot write the current panel for assistive technology",
			beforeURL)
	}
	if want := controller + "?v=" + shippedAssetDigest(t, controller); beforeURL != want {
		t.Fatalf("the server page requests %s at %q, want %q (the digest of the shipped bytes)",
			controller, beforeURL, want)
	}
	if !slices.Contains(web.DeliveredAssets, controller) {
		t.Fatalf("%s carries a content identity but is absent from web.DeliveredAssets; the shell "+
			"enumeration consumes that list, so no check would notice this page losing it again",
			controller)
	}

	// The production helper and the fixture root must agree on the shipped bytes,
	// or the byte change below would prove a second implementation.
	production, err := web.AssetURL(controller)
	if err != nil {
		t.Fatalf("AssetURL(%s): %v", controller, err)
	}
	if production != beforeURL {
		t.Fatalf("the page requests %s at %q but the production helper emits %q",
			controller, beforeURL, production)
	}

	otherBefore := urlForAsset(t, before, other)
	if otherBefore == "" {
		t.Fatalf("the server page does not request %s, so the unchanged-URL control below proves "+
			"nothing", other)
	}

	// Change exactly one asset's bytes, the way editing that file does.
	name := strings.TrimPrefix(controller, "/")
	root[name] = &fstest.MapFile{
		Data: append(append([]byte{}, root[name].Data...), []byte("\n// delivered change\n")...),
	}

	after := renderServerShellWithIdentityRoot(t, root)
	afterURL := urlForAsset(t, after, controller)
	t.Logf("%s before the byte change: %s", controller, beforeURL)
	t.Logf("%s after  the byte change: %s", controller, afterURL)
	if afterURL == beforeURL {
		t.Fatalf("%s is requested at %q before and after its bytes changed, so the URL is not "+
			"derived from the bytes: a browser keeps the predecessor controller under it",
			controller, beforeURL)
	}
	changedSum := sha256.Sum256(root[name].Data)
	if want := controller + "?v=" + hex.EncodeToString(changedSum[:]); afterURL != want {
		t.Fatalf("%s is requested at %q after its bytes changed, want %q", controller, afterURL, want)
	}
	if got := urlForAsset(t, after, other); got != otherBefore {
		t.Fatalf("%s moved from %q to %q when another asset's bytes changed; an unchanged asset "+
			"must keep its URL or every visit refetches the whole set", other, otherBefore, got)
	}

	// Positive control: the shipped render is accepted, so a rejection below is
	// attributable to the mutation rather than to the rule failing always.
	if findings := shellAssetFindings(t, "server.html", before); len(findings) != 0 {
		t.Fatalf("the shipped server page is reported as broken, so the control below would prove "+
			"nothing: %v", findings)
	}

	reverted := map[string]string{
		"no cache identity":   `src="` + controller + `"`,
		"the release version": `src="` + controller + `?v=` + config.AppVersion + `"`,
	}
	for name, replacement := range reverted {
		mutated := strings.Replace(before, `src="`+beforeURL+`"`, replacement, 1)
		if mutated == before {
			t.Fatalf("could not rewrite the controller reference to %s; the control would pass "+
				"without exercising the rule", name)
		}
		findings := shellAssetFindings(t, "server.html", mutated)
		if len(findings) == 0 {
			t.Fatalf("the server page requesting %s under %s was accepted; the delivery rule cannot "+
				"fail on the defect this test exists to catch", controller, name)
		}
		if !strings.Contains(strings.Join(findings, "\n"), controller) {
			t.Fatalf("the finding for the %s form does not name %s: %v", name, controller, findings)
		}
	}
}
