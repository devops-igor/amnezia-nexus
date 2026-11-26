package web

// Cache identity for the assets this change delivered.
//
// /static is served with Cache-Control: public, max-age=86400, so a browser
// reuses an asset whose URL does not change. The release version in a query is
// an identity for the assets a release changed and nothing else: this change
// replaced the six VPN modules and the stylesheet every shell links while the
// release stayed put, so ?v=<release> is exactly the URL the predecessor served.
// A returning browser therefore ran the predecessor controller against markup
// that no longer carries the elements it dereferences.
//
// asset_url derives the query from the asset's own bytes instead. These checks
// hold that identity to what it claims:
//
//   - a render check reads the shipped vpn.html scripts block and requires each
//     module's URL to carry the digest of the bytes this build ships, in the
//     dependency order the page needs;
//   - a byte-change check renders the same shipped template twice, changing one
//     asset's bytes between the two renders, and requires that asset's URL to
//     move and every other URL to stay put. A test that pinned the emitted query
//     would pass for both contents and prove nothing, so this one varies the
//     bytes and reads the URL;
//   - an enumeration check walks every template and reads every reference to a
//     delivered asset, so a shell that keeps the release-versioned or bare form
//     fails here even if no other test renders that page.

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// vpnDeliveredAssets is the delivery's own list of changed assets, taken from
// the single definition AssetURL's consumers read. This package keeps no second
// copy: a copy that omitted an asset would answer "every asset is identified"
// while the omitted one was served bare, which is precisely how the table engine
// the VPN page depends on stayed outside the previous guard.
var vpnDeliveredAssets = DeliveredAssets

// vpnScriptDependencyOrderByPage is the synchronous chain each VPN document
// loads. Each module calls the one before it (or a shared helper above it), so
// the order is a contract and not a preference. The single page became three
// documents, so the chain is per document.
var vpnScriptDependencyOrderByPage = map[string][]string{
	"vpn": {
		"/static/js/vpn/anchor_handoff.js",
		"/static/js/vpn/common.js",
		"/static/js/vpn/overview.js",
	},
	"vpn_backends": {
		"/static/js/vpn/common.js",
		"/static/js/vpn/backends.js",
		"/static/js/vpn/backends_page.js",
	},
	"vpn_diagnostics": {
		"/static/js/vpn/common.js",
		"/static/js/vpn/health_problems.js",
		"/static/js/vpn/health_summary.js",
		"/static/js/vpn/charts.js",
		"/static/js/vpn/sessions.js",
		"/static/js/vpn/diagnostics_page.js",
	},
}

// vpnPagesInOrder keeps page iteration deterministic.
var vpnPagesInOrder = []string{"vpn", "vpn_backends", "vpn_diagnostics"}

// deliveredAssetDigest is the query a URL for path must carry: the SHA-256 of
// the bytes this build embeds for it, in hex. It is computed here from the
// shipped bytes rather than read back from the helper, so a helper that returned
// a constant could not satisfy it.
func deliveredAssetDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := fs.ReadFile(StaticFS, strings.TrimPrefix(path, "/"))
	if err != nil {
		t.Fatalf("read the delivered asset %s: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// assetResolverFor returns the template action the page uses, bound to root.
// AssetURL reads the embedded build; binding the same function to another root
// is what lets the byte-change check vary one asset's bytes while every other
// part of the render stays the shipped one. It calls the production derivation
// rather than restating it: a second spelling of the query is the drift that
// lets a page emit a URL no test computes.
func assetResolverFor(root fs.FS) func(string) (string, error) {
	return func(path string) (string, error) {
		return AssetURLFor(root, path)
	}
}

// shellFuncMapWith is the fixture's helper set with the asset resolver replaced.
func shellFuncMapWith(assetURL func(string) (string, error)) template.FuncMap {
	fm := getVPNFuncMap()
	fm["asset_url"] = assetURL
	return fm
}

// shellTemplateData is the minimum a shell needs to render.
func shellTemplateData() map[string]any {
	return map[string]any{
		"title":             "Shell Test",
		"lang":              "en",
		"active_page":       "vpn",
		"csrf_token":        "csrf-test-token",
		"translations_json": "{}",
		"app_version":       vpnTestAppVersion,
		"current_user":      map[string]any{"Username": "admin", "Role": "admin"},
		"site_settings": map[string]any{
			"Title":    "Amnezia",
			"Subtitle": "Nexus",
		},
	}
}

// renderFileWith renders one shipped template with the supplied helper set.
func renderFileWith(t *testing.T, name string, funcs template.FuncMap) string {
	t.Helper()
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	tmpl, err := template.New(name).Funcs(funcs).ParseFS(templatesFS, name)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, shellTemplateData()); err != nil {
		t.Fatalf("execute %s: %v", name, err)
	}
	return buf.String()
}

// renderVPNScriptsBlockWith renders the shipped scripts block, resolving the
// delivered assets against root.
func renderVPNScriptsBlockWith(t *testing.T, root fs.FS, page string) string {
	t.Helper()
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	tmpl, err := template.New(page+".html").Funcs(shellFuncMapWith(assetResolverFor(root))).ParseFS(templatesFS, page+".html")
	if err != nil {
		t.Fatalf("parse %s.html: %v", page, err)
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "scripts", nil); err != nil {
		t.Fatalf("execute scripts block: %v", err)
	}
	return buf.String()
}

// scriptSrcs returns the src of every script element, in document order.
func scriptSrcs(t *testing.T, markup string) []string {
	t.Helper()
	var srcs []string
	for _, tag := range assetTagPattern.FindAllString(markup, -1) {
		if !strings.HasPrefix(tag, "<script") {
			continue
		}
		if m := tagSrcPattern.FindStringSubmatch(tag); m != nil {
			srcs = append(srcs, m[1])
		}
	}
	return srcs
}

// deliveredStaticCopy is the set of delivered assets the scripts block asks for,
// as mutable bytes, so one of them can be changed while the rest stay shipped.
func deliveredStaticCopy(t *testing.T, paths ...string) fstest.MapFS {
	t.Helper()
	root := fstest.MapFS{}
	for _, path := range paths {
		name := strings.TrimPrefix(path, "/")
		body, err := fs.ReadFile(StaticFS, name)
		if err != nil {
			t.Fatalf("read the delivered asset %s: %v", path, err)
		}
		root[name] = &fstest.MapFile{Data: body}
	}
	return root
}

// TestVPNScriptsCarryTheAssetBytes reads the shipped scripts block and requires
// each module's URL to be its path with the digest of the bytes this build
// ships, in the dependency order the page needs. The resolver the fixture binds
// here is checked against the production helper below, so this is not a
// different mechanism from the one the page uses.
func TestVPNScriptsCarryTheAssetBytes(t *testing.T) {
	for _, page := range vpnPagesInOrder {
		t.Run(page, func(t *testing.T) {
			block := renderVPNScriptsBlockWith(t, StaticFS, page)
			srcs := scriptSrcs(t, block)
			wantOrder := vpnScriptDependencyOrderByPage[page]

			if len(srcs) != len(wantOrder) {
				t.Fatalf("the %s scripts block loads %d module(s) %v, want %d in dependency order %v",
					page, len(srcs), srcs, len(wantOrder), wantOrder)
			}

			for i, path := range wantOrder {
				emitted := srcs[i]
				want := path + "?v=" + deliveredAssetDigest(t, path)
				if emitted != want {
					t.Fatalf("module %d is requested at %q, want %q; a browser that cached this module "+
						"under another URL — the release-version URL the predecessor also served, or the "+
						"bare path — keeps running the previous bytes against this markup",
						i, emitted, want)
				}

				production, err := AssetURL(path)
				if err != nil {
					t.Fatalf("AssetURL(%s): %v", path, err)
				}
				if production != want {
					t.Fatalf("the page must request %s at %q, but the production helper emits %q",
						path, want, production)
				}
				if strings.HasSuffix(want, "v="+vpnTestAppVersion) {
					t.Fatalf("%s is identified by the release version, so two deliveries inside one release "+
						"would emit the same URL for different bytes", path)
				}
			}
		})
	}
}

// TestVPNScriptURLMovesWithTheAssetBytes is the delivery regression: it renders
// the shipped template twice, changing one module's bytes in between, and
// requires that module's URL to move while the other five stay put. Pinning the
// current query would pass for both contents; varying the bytes is what shows
// the query is an identity rather than a constant.
func TestVPNScriptURLMovesWithTheAssetBytes(t *testing.T) {
	const changed = "/static/js/vpn/charts.js"
	const page = "vpn_diagnostics"
	order := vpnScriptDependencyOrderByPage[page]

	root := deliveredStaticCopy(t, order...)
	before := scriptSrcs(t, renderVPNScriptsBlockWith(t, root, page))
	if len(before) != len(order) {
		t.Fatalf("the scripts block loads %d module(s) %v, want %d", len(before), before, len(order))
	}

	// Change exactly one module's bytes, the way an edit to that file would.
	name := strings.TrimPrefix(changed, "/")
	original := root[name].Data
	root[name] = &fstest.MapFile{Data: append(append([]byte{}, original...), []byte("\n// delivered change\n")...)}

	after := scriptSrcs(t, renderVPNScriptsBlockWith(t, root, page))
	if len(after) != len(before) {
		t.Fatalf("the scripts block loads %d module(s) after the byte change, want %d: %v", len(after), len(before), after)
	}

	for i, path := range order {
		moved := before[i] != after[i]
		if path == changed {
			if !moved {
				t.Fatalf("%s carries %q before and after its bytes changed, so the URL is not derived "+
					"from the bytes: a browser keeps the predecessor module under it", changed, before[i])
			}
			if want := path + "?v=" + deliveredAssetDigestOf(t, root, path); after[i] != want {
				t.Fatalf("%s is requested at %q after its bytes changed, want %q", changed, after[i], want)
			}
			continue
		}
		if moved {
			t.Fatalf("%s carries %q before and %q after another module's bytes changed; an unchanged "+
				"asset must keep its URL or every visit refetches the whole chain", path, before[i], after[i])
		}
	}
}

// deliveredAssetDigestOf is the digest of the bytes root holds for path.
func deliveredAssetDigestOf(t *testing.T, root fs.FS, path string) string {
	t.Helper()
	body, err := fs.ReadFile(root, strings.TrimPrefix(path, "/"))
	if err != nil {
		t.Fatalf("read %s from the fixture root: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// TestVPNStylesheetURLMovesWithTheAssetBytes is the same regression for the
// stylesheet the shells link: base.html is rendered twice with vpn.css's bytes
// changed in between, and only that link may move.
func TestVPNStylesheetURLMovesWithTheAssetBytes(t *testing.T) {
	const changed = "/static/css/vpn.css"
	// The whole delivered set is copied, not just the stylesheet: base.html also
	// requests the table engine through asset_url now, and AssetURL refuses a path
	// the root does not hold. Copying only the asset under test would make this
	// check fail for a reason unrelated to the stylesheet it exercises.
	root := deliveredStaticCopy(t, DeliveredAssets...)

	before := stylesheetHrefs(t, renderFileWith(t, "base.html", shellFuncMapWith(assetResolverFor(root))))
	if got := stylesheetHrefFor(t, before, changed); got != changed+"?v="+deliveredAssetDigest(t, changed) {
		t.Fatalf("base.html links %s at %q, want the digest of the delivered bytes", changed, got)
	}

	name := strings.TrimPrefix(changed, "/")
	root[name] = &fstest.MapFile{Data: append(append([]byte{}, root[name].Data...), []byte("\n/* delivered change */\n")...)}

	after := stylesheetHrefs(t, renderFileWith(t, "base.html", shellFuncMapWith(assetResolverFor(root))))
	moved := stylesheetHrefFor(t, after, changed)
	if moved == stylesheetHrefFor(t, before, changed) {
		t.Fatalf("%s carries the same URL %q before and after its bytes changed, so a returning "+
			"browser keeps the predecessor stylesheet against this markup", changed, moved)
	}
	if want := changed + "?v=" + deliveredAssetDigestOf(t, root, changed); moved != want {
		t.Fatalf("%s is linked at %q after its bytes changed, want %q", changed, moved, want)
	}

	for i := range before {
		if before[i] == stylesheetHrefFor(t, before, changed) {
			continue
		}
		if before[i] != after[i] {
			t.Fatalf("an unchanged stylesheet moved from %q to %q when another stylesheet's bytes "+
				"changed; every visit would then refetch the whole cascade", before[i], after[i])
		}
	}
}

// stylesheetHrefs returns the href of every local stylesheet link, in order.
func stylesheetHrefs(t *testing.T, markup string) []string {
	t.Helper()
	var hrefs []string
	for _, tag := range assetTagPattern.FindAllString(markup, -1) {
		notStylesheet := !strings.HasPrefix(tag, "<link") ||
			!stylesheetRelRe2.MatchString(tag)
		if notStylesheet {
			continue
		}
		if m := tagHrefPattern.FindStringSubmatch(tag); m != nil && strings.HasPrefix(m[1], "/static/") {
			hrefs = append(hrefs, m[1])
		}
	}
	return hrefs
}

// stylesheetHrefFor is the href in hrefs that names path, whatever its query.
func stylesheetHrefFor(t *testing.T, hrefs []string, path string) string {
	t.Helper()
	found := ""
	for _, href := range hrefs {
		base, _, _ := strings.Cut(href, "?")
		if base != path {
			continue
		}
		if found != "" {
			t.Fatalf("%s is linked twice (%q and %q)", path, found, href)
		}
		found = href
	}
	if found == "" {
		t.Fatalf("%s is not linked at all; the renderer cannot cache-identify it (links: %v)", path, hrefs)
	}
	return found
}

var (
	// assetTagPattern matches one script or stylesheet-bearing link tag.
	assetTagPattern = regexp.MustCompile(`<script\b[^>]*>|<link\b[^>]*>`)
	tagSrcPattern   = regexp.MustCompile(`\ssrc="([^"]*)"`)
	tagHrefPattern  = regexp.MustCompile(`\shref="([^"]*)"`)
	// stylesheetRelRe2 finds a stylesheet rel attribute. It is a second spelling
	// of the same rule the handlers package scans templates with, kept local
	// because that scanner is not exported and this package cannot import it.
	stylesheetRelRe2 = regexp.MustCompile(`\srel="(?:[^"]*\s)?stylesheet(?:\s[^"]*)?"`)
	// assetURLActionPattern is the content-derived form a template may use; its
	// argument is the asset path.
	assetURLActionPattern = regexp.MustCompile(`\{\{\s*asset_url\s+"(/static/[^"]+)"\s*\}\}`)
	releaseVersionQuery   = regexp.MustCompile(`^\?v=\{\{\s*\.app_version\s*\}\}$`)
)

// contentIdentitySentinel stands in for a content-derived query when a test
// parses template source rather than rendered output. The action's asset path is
// quoted, so the tag it appears in is not itself valid HTML; substituting a plain
// sentinel query lets the attribute parsers in this package see which asset the
// tag names without teaching them the template language. It is deliberately not
// a version: the identity itself is compared with the real bytes by
// TestVPNScriptsCarryTheAssetBytes and its siblings, never with this string.
const contentIdentitySentinel = "?v=@content-identity@"

// normalizeAssetActions rewrites every content-derived action in template source
// to path+sentinel, so attribute-level parsers can read the tag.
func normalizeAssetActions(src string) string {
	return assetURLActionPattern.ReplaceAllString(src, "${1}"+contentIdentitySentinel)
}

// tagAssetValue returns the attribute value a script or stylesheet tag names,
// or "" for any other tag. The two tag shapes differ only in which attribute
// carries the path, so the check is one lookup rather than a branch per form.
func tagAssetValue(tag string) string {
	if strings.HasPrefix(tag, "<script") {
		if m := tagSrcPattern.FindStringSubmatch(tag); m != nil {
			return m[1]
		}
		return ""
	}
	if !stylesheetRelRe2.MatchString(tag) {
		return ""
	}
	if m := tagHrefPattern.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

// classifyAssetTag reports the /static asset one template tag names, with the
// identity form the tag declared for it. This is the single place a tag is
// classified: the content-derived action names its asset as a quoted argument
// rather than an attribute value, so it must be read from the whole tag before
// the plain attribute forms, and both callers below would otherwise repeat that
// order and drift.
func classifyAssetTag(tag string) (path string, form assetReferenceForm, declared string, ok bool) {
	if m := assetURLActionPattern.FindStringSubmatch(tag); m != nil {
		return m[1], refAssetBytes, m[0], true
	}
	value := tagAssetValue(tag)
	if value == "" {
		return "", refBare, "", false
	}
	base, query, hasQuery := strings.Cut(value, "?")
	if !strings.HasPrefix(base, "/static/") {
		return "", refBare, "", false
	}
	if hasQuery && releaseVersionQuery.MatchString("?"+query) {
		return base, refReleaseVersion, value, true
	}
	return base, refBare, value, true
}

// templateAssetForms maps every /static asset a template source names to the
// identity form that template declared for it. A path named twice with different
// forms is an error, since a template that does that cannot be reasoned about.
func templateAssetForms(t *testing.T, src string) map[string]assetReferenceForm {
	t.Helper()
	forms := make(map[string]assetReferenceForm)
	for _, tag := range assetTagPattern.FindAllString(src, -1) {
		path, form, _, ok := classifyAssetTag(tag)
		if !ok {
			continue
		}
		if seen, dup := forms[path]; dup && seen != form {
			t.Errorf("%s is named twice with different identities (%s and %s)", path, seen, form)
		}
		forms[path] = form
	}
	return forms
}

// assetReferenceForm is how one template declares the cache identity of an asset.
type assetReferenceForm int

const (
	// refBare is the predecessor form with no identity at all.
	refBare assetReferenceForm = iota
	// refReleaseVersion is ?v={{ .app_version }}, which moves only on a release.
	refReleaseVersion
	// refAssetBytes is {{ asset_url "/static/…" }}, which moves with the bytes.
	refAssetBytes
)

func (f assetReferenceForm) String() string {
	switch f {
	case refReleaseVersion:
		return "?v={{ .app_version }}"
	case refAssetBytes:
		return `{{ asset_url "…" }}`
	default:
		return "no cache identity"
	}
}

// vpnAssetReference is one reference to a delivered asset found in a template.
type vpnAssetReference struct {
	template string
	path     string
	form     assetReferenceForm
	declared string
}

// scanVPNAssetReferences walks every shipped template and returns each reference
// to a delivered asset with the identity form that template declared. A shell
// that loads one of these assets is in the result whether or not any test
// renders that page.
func scanVPNAssetReferences(t *testing.T) []vpnAssetReference {
	t.Helper()
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	var refs []vpnAssetReference
	var scanned int
	walkErr := fs.WalkDir(templatesFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		body, readErr := fs.ReadFile(templatesFS, p)
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, tag := range assetTagPattern.FindAllString(string(body), -1) {
			path, form, declared, ok := classifyAssetTag(tag)
			if !ok || !slices.Contains(vpnDeliveredAssets, path) {
				continue
			}
			refs = append(refs, vpnAssetReference{template: p, path: path, form: form, declared: declared})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk templates: %v", walkErr)
	}
	if scanned == 0 {
		t.Fatal("the template walk read nothing, so every reference would pass unexamined")
	}
	return refs
}

// TestEveryShellLoadsDeliveredAssetsUnderTheirBytes enumerates the shells that
// reference each delivered asset and requires every one of them to use the
// content-derived form, so a shell added later cannot silently keep the stale
// link. It also pins the shells this build links, because a scan that reaches
// nothing else still looks clean.
func TestEveryShellLoadsDeliveredAssetsUnderTheirBytes(t *testing.T) {
	refs := scanVPNAssetReferences(t)
	if len(refs) == 0 {
		t.Fatal("no template references a delivered asset, so nothing was checked")
	}

	byAsset := map[string][]vpnAssetReference{}
	for _, ref := range refs {
		byAsset[ref.path] = append(byAsset[ref.path], ref)
		if ref.form != refAssetBytes {
			t.Errorf("%s links %s as %q (%s); a browser that cached the predecessor copy under that "+
				"URL keeps running it against this markup",
				ref.template, ref.path, ref.declared, ref.form)
		}
	}

	// The shells this delivery must cover. vpn.css is linked by every shell that
	// can be reached before or after signing in; the table engine and the modules
	// only by the layout and the page. This pin is not the identity rule — the
	// identity rule reads web.DeliveredAssets — it exists so a shell that stops
	// linking an asset cannot make that asset silently disappear from this scan.
	wantShells := map[string][]string{
		"/static/css/vpn.css":  {"base.html", "login.html", "setup.html", "change_password.html"},
		"/static/js/tables.js": {"base.html"},
	}
	for _, page := range vpnPagesInOrder {
		for _, path := range vpnScriptDependencyOrderByPage[page] {
			wantShells[path] = append(wantShells[path], page+".html")
		}
	}

	for path, shells := range wantShells {
		var got []string
		for _, ref := range byAsset[path] {
			got = append(got, ref.template)
		}
		for _, shell := range shells {
			if !slices.Contains(got, shell) {
				t.Errorf("expected %s to link %s, but it does not (linking templates: %v); a shell that "+
					"stops linking it is one this enumeration would otherwise stop checking", shell, path, got)
			}
		}
	}

	for _, path := range vpnDeliveredAssets {
		if len(byAsset[path]) == 0 {
			t.Errorf("no template links %s, so its cache identity is unchecked and the scan may have "+
				"lost the reference entirely", path)
		}
	}
}
