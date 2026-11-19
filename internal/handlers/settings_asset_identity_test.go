package handlers

// Cache identity for the settings surface.
//
// /static is served with a one-day lifetime, so a controller whose URL does not
// change keeps running in a browser that already holds it. The resolver
// controller did exactly that: an earlier build discarded a conflicted draft and
// rewrote the alert container that now holds both fixed result regions, and a
// returning administrator reached it with no unusual input. One rule, no
// exemptions: every script and stylesheet a settings template loads carries the
// release version as its query.
//
// Two checks, because each catches what the other cannot:
//
//   - a source scan covers every settings template, including the ones no test
//     renders, and names the controllers the surface must load so a rename or a
//     dropped tag cannot make an empty match look clean;
//   - a render check proves the page really emits the current version, so the
//     effective URL of every controller differs from the URL the previous
//     release served and a warm cache cannot satisfy the new markup.

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

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
	"/static/js/policy_upstream.js",
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

var (
	// assetTagRef matches one script or stylesheet tag, in document order.
	assetTagRef     = regexp.MustCompile(`<script\b[^>]*>|<link\b[^>]*>`)
	scriptSrcAttr   = regexp.MustCompile(`\ssrc="([^"]*)"`)
	linkHrefAttr    = regexp.MustCompile(`\shref="([^"]*)"`)
	linkRelAttr     = regexp.MustCompile(`\srel="([^"]*)"`)
	stylesheetRelRe = regexp.MustCompile(`(^|\s)stylesheet(\s|$)`)
)

// settingsSurfaceAssets returns every /static asset a settings template loads:
// the src of each script, and the href of each stylesheet link, in the order the
// template names them.
func settingsSurfaceAssets(src string) []string {
	var refs []string
	for _, tag := range assetTagRef.FindAllString(src, -1) {
		if strings.HasPrefix(tag, "<script") {
			if m := scriptSrcAttr.FindStringSubmatch(tag); m != nil && strings.HasPrefix(m[1], "/static/") {
				refs = append(refs, m[1])
			}
			continue
		}
		rel := linkRelAttr.FindStringSubmatch(tag)
		href := linkHrefAttr.FindStringSubmatch(tag)
		if rel == nil || href == nil || !stylesheetRelRe.MatchString(strings.ToLower(rel[1])) {
			continue
		}
		if strings.HasPrefix(href[1], "/static/") {
			refs = append(refs, href[1])
		}
	}
	return refs
}

// isVersionedAssetRef reports whether an asset reference carries the release
// version as its query, in the one accepted spelling.
func isVersionedAssetRef(ref string) bool {
	_, query, hasQuery := strings.Cut(ref, "?")
	return hasQuery && versionAction.MatchString("?"+query)
}

// settingsSurfaceScan is what a walk over the settings templates found.
type settingsSurfaceScan struct {
	// templates are the template paths that were read.
	templates []string
	// assets are the distinct /static paths those templates load.
	assets []string
	// unversioned are "template: url" for every reference without the release
	// version query.
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
			path, _, _ := strings.Cut(ref, "?")
			if !seen[path] {
				seen[path] = true
				scan.assets = append(scan.assets, path)
			}
			if !isVersionedAssetRef(ref) {
				scan.unversioned = append(scan.unversioned, p+": "+ref)
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
// well as a script, ignore a non-local or non-stylesheet reference, and ignore
// an inline script that has no src at all.
func TestSettingsAssetScannerFindsScriptsAndStylesheets(t *testing.T) {
	src := strings.Join([]string{
		`<link rel="icon" href="/static/favicon.ico">`,
		`<link rel="stylesheet" href="/static/css/settings.css?v={{ .app_version }}">`,
		`<link rel="stylesheet" href="https://cdn.example/x.css">`,
		`<script src="/static/js/a.js?v={{ .app_version }}"></script>`,
		`<script src="https://cdn.example/b.js"></script>`,
		`<script>inline()</script>`,
		`<script src="/static/js/c.js"></script>`,
	}, "\n")
	got := settingsSurfaceAssets(src)
	want := []string{
		"/static/css/settings.css?v={{ .app_version }}",
		"/static/js/a.js?v={{ .app_version }}",
		"/static/js/c.js",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("settingsSurfaceAssets found %v, want %v", got, want)
	}
	// The same judgement the guard applies: the stylesheet and the first script
	// carry the action, the last script does not.
	var unversioned []string
	for _, ref := range got {
		if !isVersionedAssetRef(ref) {
			unversioned = append(unversioned, ref)
		}
	}
	if !slices.Equal(unversioned, []string{"/static/js/c.js"}) {
		t.Fatalf("unversioned refs = %v, want the one bare script", unversioned)
	}
}

func TestSettingsTemplatesVersionEveryAsset(t *testing.T) {
	scan := scanSettingsSurface(t)

	// An empty or partial scan proves nothing, so pin the templates that must be
	// in it: the shell and the three policy sub-pages that hold the controllers.
	for _, required := range []string{
		"settings.html", "settings_policy.html",
		"settings_policy_client.html", "settings_policy_upstream.html",
	} {
		if !slices.Contains(scan.templates, required) {
			t.Fatalf("the scan did not reach %s (scanned %v); an unversioned asset there would pass", required, scan.templates)
		}
	}
	for _, controller := range settingsSurfaceControllers {
		if !slices.Contains(scan.assets, controller) {
			t.Errorf("no settings template loads %s; the controller list and the templates have diverged", controller)
		}
	}

	if len(scan.unversioned) > 0 {
		t.Fatalf("every script and stylesheet a settings template loads must carry "+
			"?v={{ .app_version }}, or a browser keeps the previous build's copy for up to a day "+
			"and runs it against this markup:\n%s", strings.Join(scan.unversioned, "\n"))
	}
}

// versionedAssetURL is the URL a settings template must emit for path. The
// source carries {{ .app_version }}, so the rendered query is the release
// version and it changes with the build that changed the asset.
func versionedAssetURL(path string) string {
	return path + "?v=" + config.AppVersion
}

// versionedSrcAttr is the rendered src attribute for a settings controller,
// spelled the way a template that carries {{ .app_version }} renders it.
func versionedSrcAttr(path string) string {
	return `src="` + versionedAssetURL(path) + `"`
}

func TestSettingsPageLoadsEveryControllerAtTheCurrentBuildVersion(t *testing.T) {
	if config.AppVersion == "" {
		t.Fatal("config.AppVersion is empty, so a missing version could not be told from a present one")
	}
	body := renderSettingsPage(t, models.RoleAdmin)
	links := collectShellLinks(t, body)

	effective := map[string]string{}
	for _, src := range links.scripts {
		path, query, hasQuery := strings.Cut(src, "?")
		if hasQuery {
			effective[path] = "?" + query
		}
	}

	for _, controller := range settingsSurfaceControllers {
		want := "?v=" + config.AppVersion
		got, ok := effective[controller]
		if !ok {
			t.Errorf("%s is served unversioned; a browser that cached the previous build's copy "+
				"runs it against this markup", controller)
			continue
		}
		if got != want {
			t.Errorf("%s carries %q, want %q", controller, got, want)
		}
		if strings.Contains(body, `src="`+controller+`"`) {
			t.Errorf("the page still emits the unversioned %s URL, which is the URL the previous "+
				"release served and a warm cache still holds", controller)
		}
	}
}

// TestCachedResolverControllerURLDiffersFromTheLiveBaseURL states the cache
// identity contract for the controller the earlier build made incompatible. The
// previous release served it at the bare path with a one-day lifetime, so the
// two URLs must differ: equal URLs mean a cached copy satisfies the new markup.
func TestCachedResolverControllerURLDiffersFromTheLiveBaseURL(t *testing.T) {
	const liveBaseResolverURL = "/static/js/policy_upstream.js"
	if config.AppVersion == "" {
		t.Fatal("config.AppVersion is empty, so an unchanged URL could not be detected")
	}
	body := renderSettingsPage(t, models.RoleAdmin)

	current := versionedAssetURL(liveBaseResolverURL)
	if !strings.Contains(body, `src="`+current+`"`) {
		t.Fatalf("the current page does not load the resolver controller at %q", current)
	}
	if strings.Contains(body, `src="`+liveBaseResolverURL+`"`) {
		t.Fatalf("the current page still loads %q; a browser holding that cached copy keeps "+
			"the previous controller, which discards a conflicted draft and removes both "+
			"fixed result regions", liveBaseResolverURL)
	}
	if current == liveBaseResolverURL {
		t.Fatal("the version query produced the live-base URL, so it carries no cache identity")
	}
}
