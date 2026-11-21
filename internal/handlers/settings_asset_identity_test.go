package handlers

// Cache identity for the settings surface.
//
// /static is served with a one-day lifetime, so a controller whose URL does not
// change keeps running in a browser that already holds it. The resolver
// controller did exactly that: an earlier build discarded a conflicted draft and
// rewrote the alert container that now holds both fixed result regions, and a
// returning administrator reached it with no unusual input. No script or
// stylesheet a settings template loads may go without a cache identity.
//
// The release version is the identity of the whole build: it covers the assets a
// release changed, and nothing else. A controller edited between releases keeps
// the predecessor's ?v=<release> URL, so a returning browser runs the old bytes
// against the new markup. A template that loads such an asset asks for its URL
// with asset_url, whose query is derived from that asset's own bytes; the sources
// a release version still covers keep ?v={{ .app_version }}.
//
// Three checks, because each catches what the others cannot:
//
//   - a source scan covers every settings template, including the ones no test
//     renders, names the controllers the surface must load so a rename or a
//     dropped tag cannot make an empty match look clean, and records which
//     identity form each reference declared;
//   - a render check proves the page emits the identity its template declared, so
//     the effective URL of every controller moves when that identity moves;
//   - two checks on the content-derived mechanism itself: the controller the new
//     markup expects is requested under the digest of the bytes this build ships
//     rather than under the release constant the predecessor also served, and two
//     different contents never share one identity.

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// settingsSurfaceControllers are the controllers the settings surface loads.
var settingsSurfaceControllers = []string{
	"/static/js/settings_cards.js",
	"/static/js/settings_save.js",
	"/static/js/notifications_settings.js",
	"/static/js/settings.js",
	"/static/js/policy_routing.js",
	"/static/js/policy_client_diag_filter.js",
	"/static/js/policy_client_diag.js",
	"/static/js/gigahost_catalog_status.js",
	"/static/js/gigahost_setup.js",
	"/static/js/gigahost_setup_intents.js",
	"/static/js/gigahost_order_status_model.js",
	"/static/js/gigahost_order_status.js",
	"/static/js/gigahost_placement.js",
}

// isSettingsSurfaceTemplate reports whether a template belongs to the settings
// surface: the /settings shell and its policy sub-pages, the save controls, and
// the card partials under settings/. The rule is the name, so a template added
// later is scanned without an exemption list to maintain.
func isSettingsSurfaceTemplate(p string) bool {
	base := p
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if !strings.HasSuffix(base, ".html") {
		return false
	}
	return strings.HasPrefix(base, "settings") || strings.HasPrefix(p, "settings/")
}

// assetIdentity is how a settings template declares the cache identity of one
// asset. The release version is the identity of the whole build, so it moves only
// on a release; the asset's own bytes move whenever the delivered file changes.
type assetIdentity int

const (
	// identityUnversioned is the predecessor URL: no identity at all.
	identityUnversioned assetIdentity = iota
	// identityReleaseVersion is ?v={{ .app_version }}.
	identityReleaseVersion
	// identityAssetBytes is {{ asset_url "/static/…" }}.
	identityAssetBytes
)

func (id assetIdentity) String() string {
	switch id {
	case identityReleaseVersion:
		return "?v={{ .app_version }}"
	case identityAssetBytes:
		return `{{ asset_url "…" }}`
	default:
		return "no cache identity"
	}
}

// settingsAssetRef is one /static asset a settings template loads, with the
// identity mechanism the template declared for it.
type settingsAssetRef struct {
	// path is the asset path without a query, e.g. "/static/js/a.js".
	path string
	// identity is the form the template declared for this reference.
	identity assetIdentity
	// declared is the reference as the template spells it, for messages.
	declared string
}

var (
	// assetTagRef matches one script or stylesheet tag, in document order.
	assetTagRef     = regexp.MustCompile(`<script\b[^>]*>|<link\b[^>]*>`)
	scriptSrcAttr   = regexp.MustCompile(`\ssrc="([^"]*)"`)
	linkHrefAttr    = regexp.MustCompile(`\shref="([^"]*)"`)
	linkRelAttr     = regexp.MustCompile(`\srel="([^"]*)"`)
	stylesheetRelRe = regexp.MustCompile(`(^|\s)stylesheet(\s|$)`)
	// assetURLAction is the content-derived form a template may use. Its argument
	// is the asset path; the query is derived from that asset's bytes.
	assetURLAction = regexp.MustCompile(`\{\{\s*asset_url\s+"(/static/[^"]+)"\s*\}\}`)
)

// settingsSurfaceAssets returns every /static asset a settings template loads —
// the src of each script, the href of each stylesheet link — with the identity
// the template declared for it, in the order the template names them.
func settingsSurfaceAssets(src string) []settingsAssetRef {
	var refs []settingsAssetRef
	for _, tag := range assetTagRef.FindAllString(src, -1) {
		if strings.HasPrefix(tag, "<script") {
			if m := scriptSrcAttr.FindStringSubmatch(tag); m != nil {
				if ref, ok := classifyAssetRef(tag, m[1]); ok {
					refs = append(refs, ref)
				}
			}
			continue
		}
		rel := linkRelAttr.FindStringSubmatch(tag)
		href := linkHrefAttr.FindStringSubmatch(tag)
		if rel == nil || href == nil || !stylesheetRelRe.MatchString(strings.ToLower(rel[1])) {
			continue
		}
		if ref, ok := classifyAssetRef(tag, href[1]); ok {
			refs = append(refs, ref)
		}
	}
	return refs
}

// classifyAssetRef reports the local /static asset one tag's src or href names,
// and the identity the tag declared for it. The content-derived action is read
// from the whole tag, because its asset path is an argument rather than a plain
// attribute value.
func classifyAssetRef(tag, value string) (settingsAssetRef, bool) {
	if m := assetURLAction.FindStringSubmatch(tag); m != nil {
		return settingsAssetRef{path: m[1], identity: identityAssetBytes, declared: m[0]}, true
	}
	if !strings.HasPrefix(value, "/static/") {
		return settingsAssetRef{}, false
	}
	path, query, hasQuery := strings.Cut(value, "?")
	if hasQuery && versionAction.MatchString("?"+query) {
		return settingsAssetRef{path: path, identity: identityReleaseVersion, declared: value}, true
	}
	return settingsAssetRef{path: path, identity: identityUnversioned, declared: value}, true
}

// settingsSurfaceScan is what a walk over the settings templates found.
type settingsSurfaceScan struct {
	// templates are the template paths that were read.
	templates []string
	// assets are the distinct /static assets those templates load, each with the
	// identity the first template to name it declared.
	assets []settingsAssetRef
	// unversioned are "template: reference" for every reference that declares no
	// cache identity at all.
	unversioned []string
}

// scanSettingsSurface reads every settings template and records the assets it
// loads, so the assertions below stay separate from the walk.
func scanSettingsSurface(t *testing.T) settingsSurfaceScan {
	t.Helper()
	templates, err := web.GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	var scan settingsSurfaceScan
	seen := map[string]bool{}
	walkErr := fs.WalkDir(templates, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isSettingsSurfaceTemplate(p) {
			return err
		}
		body, readErr := fs.ReadFile(templates, p)
		if readErr != nil {
			return readErr
		}
		scan.templates = append(scan.templates, p)
		for _, ref := range settingsSurfaceAssets(string(body)) {
			if !seen[ref.path] {
				seen[ref.path] = true
				scan.assets = append(scan.assets, ref)
			}
			if ref.identity == identityUnversioned {
				scan.unversioned = append(scan.unversioned, p+": "+ref.declared)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk templates: %v", walkErr)
	}
	return scan
}

// TestSettingsAssetScannerFindsScriptsAndStylesheets keeps the scan above honest
// before it is trusted over the real templates: it must see a stylesheet link as
// well as a script, ignore a non-local or non-stylesheet reference, ignore an
// inline script that has no src at all, and report which identity each reference
// declared.
func TestSettingsAssetScannerFindsScriptsAndStylesheets(t *testing.T) {
	src := strings.Join([]string{
		`<link rel="icon" href="/static/favicon.ico">`,
		`<link rel="stylesheet" href="/static/css/settings.css?v={{ .app_version }}">`,
		`<link rel="stylesheet" href="https://cdn.example/x.css">`,
		`<script src="/static/js/a.js?v={{ .app_version }}"></script>`,
		`<script src="{{ asset_url "/static/js/b.js" }}"></script>`,
		`<script src="https://cdn.example/c.js"></script>`,
		`<script>inline()</script>`,
		`<script src="/static/js/d.js"></script>`,
	}, "\n")
	want := []settingsAssetRef{
		{path: "/static/css/settings.css", identity: identityReleaseVersion},
		{path: "/static/js/a.js", identity: identityReleaseVersion},
		{path: "/static/js/b.js", identity: identityAssetBytes},
		{path: "/static/js/d.js", identity: identityUnversioned},
	}
	got := settingsSurfaceAssets(src)
	if len(got) != len(want) {
		t.Fatalf("settingsSurfaceAssets found %d references %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i].path != want[i].path || got[i].identity != want[i].identity {
			t.Errorf("reference %d = %s with %s, want %s with %s",
				i, got[i].path, got[i].identity, want[i].path, want[i].identity)
		}
	}
}

func TestSettingsTemplatesVersionEveryAsset(t *testing.T) {
	scan := scanSettingsSurface(t)

	// An empty or partial scan proves nothing, so pin the templates that must be
	// in it: the shell and the three policy sub-pages that hold the controllers.
	for _, required := range []string{
		"settings.html", "settings_policy.html",
		"settings_policy_client.html",
	} {
		if !slices.Contains(scan.templates, required) {
			t.Fatalf("the scan did not reach %s (scanned %v); an unversioned asset there would pass", required, scan.templates)
		}
	}
	scanned := map[string]settingsAssetRef{}
	for _, ref := range scan.assets {
		scanned[ref.path] = ref
	}
	for _, controller := range settingsSurfaceControllers {
		if _, ok := scanned[controller]; !ok {
			t.Errorf("no settings template loads %s; the controller list and the templates have diverged", controller)
		}
	}

	if len(scan.unversioned) > 0 {
		t.Fatalf("every script and stylesheet a settings template loads must carry a cache identity: "+
			"?v={{ .app_version }} where the release version still covers the asset, or "+
			`{{ asset_url "/static/…" }} where the asset's bytes changed without a release. `+
			"Without one, a browser keeps the previous build's copy for up to a day and runs it "+
			"against this markup:\n%s", strings.Join(scan.unversioned, "\n"))
	}
}

// versionedAssetURL is the URL a template that carries {{ .app_version }} emits
// for path. It is the release version, so it moves only when a release moves the
// version: an asset edited between releases keeps its predecessor's URL, which is
// why an asset that changed without a release is referenced through asset_url
// instead.
func versionedAssetURL(path string) string {
	return path + "?v=" + config.AppVersion
}

// deliveredAssetDigest is the reference computation for a content-derived URL:
// the SHA-256 of the bytes this build embeds for path, in hex. It is computed
// here rather than read from the helper under test, so neither a helper that
// returned a constant nor a template that skipped the helper can satisfy it.
func deliveredAssetDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := web.StaticFS.ReadFile(strings.TrimPrefix(path, "/"))
	if err != nil {
		t.Fatalf("read the embedded asset %s: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// expectedAssetURL is the URL the page must emit for a reference the template
// declared: the release version, or the digest of the delivered bytes. A form
// this helper does not know fails the test instead of passing unexamined.
func expectedAssetURL(t *testing.T, ref settingsAssetRef) string {
	t.Helper()
	switch ref.identity {
	case identityReleaseVersion:
		return versionedAssetURL(ref.path)
	case identityAssetBytes:
		return ref.path + "?v=" + deliveredAssetDigest(t, ref.path)
	default:
		t.Fatalf("%s has %s in the template (%q), so the page cannot cache-identify it",
			ref.path, ref.identity, ref.declared)
		return ""
	}
}

// declaredAssetQueries maps every asset a settings template loads to the query
// that template declared for it: the release version, or the digest of the
// asset's bytes. A script no settings template loads keeps the release version,
// which is where the layout's own api.js comes from.
func declaredAssetQueries(t *testing.T) map[string]string {
	t.Helper()
	queries := make(map[string]string)
	for _, ref := range scanSettingsSurface(t).assets {
		queries[ref.path] = strings.TrimPrefix(expectedAssetURL(t, ref), ref.path)
	}
	return queries
}

// TestSettingsPageLoadsEveryControllerUnderItsAssetIdentity proves the page emits
// the identity its own template declared for every controller, so a controller
// whose identity moves cannot stay behind a cached URL. The declared form is read
// from the shipped templates rather than from a list kept here: a second copy of
// "which controller uses which form" is the drift this check exists to prevent.
func TestSettingsPageLoadsEveryControllerUnderItsAssetIdentity(t *testing.T) {
	scan := scanSettingsSurface(t)
	declared := make(map[string]settingsAssetRef, len(scan.assets))
	for _, ref := range scan.assets {
		declared[ref.path] = ref
	}

	body := renderSettingsPage(t, models.RoleAdmin)
	links := collectShellLinks(t, body)

	effective := make(map[string]string, len(links.scripts))
	for _, src := range links.scripts {
		path, _, hasQuery := strings.Cut(src, "?")
		if hasQuery {
			effective[path] = src
		}
	}

	for _, controller := range settingsSurfaceControllers {
		ref, ok := declared[controller]
		if !ok {
			t.Errorf("no settings template declares %s, so nothing pins its cache identity", controller)
			continue
		}
		want := expectedAssetURL(t, ref)
		got, ok := effective[controller]
		if !ok {
			t.Errorf("%s is served unversioned; a browser that cached the previous build's copy "+
				"runs it against this markup", controller)
			continue
		}
		if got != want {
			t.Errorf("%s carries %q, want %q (declared in the template as %s)",
				controller, got, want, ref.declared)
		}
		if strings.Contains(body, `src="`+controller+`"`) {
			t.Errorf("the page still emits the unversioned %s URL, which is the URL the previous "+
				"release served and a warm cache still holds", controller)
		}
	}
}

// TestSettingsControllerURLCarriesTheAssetBytes is the delivery regression for the
// controller this change rewrote. The release constant did not move in this
// change, so ?v=<release> is exactly the URL the predecessor served, and a
// returning browser may still hold the predecessor's eight-cell renderer under
// it. The page must therefore request the controller under the digest of the
// bytes this build ships.
func TestSettingsControllerURLCarriesTheAssetBytes(t *testing.T) {
	const controller = "/static/js/policy_client_diag.js"
	body := renderSettingsPage(t, models.RoleAdmin)

	emitted := ""
	for _, src := range collectShellLinks(t, body).scripts {
		if path, _, _ := strings.Cut(src, "?"); path == controller {
			emitted = src
		}
	}

	digest := deliveredAssetDigest(t, controller)
	want := controller + "?v=" + digest
	if emitted != want {
		t.Fatalf("the page requests %s at %q, want %q; a browser that cached this controller under "+
			"another URL — the release-version URL the predecessor also served, or the bare path — "+
			"keeps running the previous bytes against the new markup", controller, emitted, want)
	}
	if digest == config.AppVersion {
		t.Fatalf("the asset identity %q equals the release version, so it would follow the build "+
			"rather than the bytes", digest)
	}
}

// TestSettingsAssetVersionMovesWithTheAssetBytes states the property the cache
// identity rests on: one identity never covers two different contents, so no
// cached copy can be served as the other. A test that only compared the URL with
// the release constant would pass for both contents and prove nothing here.
func TestSettingsAssetVersionMovesWithTheAssetBytes(t *testing.T) {
	const name = "js/policy_client_diag.js"
	predecessor := fstest.MapFS{name: &fstest.MapFile{Data: []byte("renderEightCells();\n")}}
	current := fstest.MapFS{name: &fstest.MapFile{Data: []byte("renderFourCells();\n")}}

	before, err := web.AssetVersion(predecessor, name)
	if err != nil {
		t.Fatalf("AssetVersion(predecessor): %v", err)
	}
	after, err := web.AssetVersion(current, name)
	if err != nil {
		t.Fatalf("AssetVersion(current): %v", err)
	}
	if before == after {
		t.Fatalf("two different contents produced one identity %q, so a cached copy of either is "+
			"served as the other", before)
	}
	again, err := web.AssetVersion(current, name)
	if err != nil {
		t.Fatalf("AssetVersion(current) a second time: %v", err)
	}
	if again != after {
		t.Fatalf("the same bytes produced %q and then %q, so an unchanged asset would lose its "+
			"cached copy on every build", after, again)
	}
	if _, err := web.AssetVersion(current, "js/absent.js"); err == nil {
		t.Fatal("an asset this build does not ship produced an identity instead of an error")
	}
}
