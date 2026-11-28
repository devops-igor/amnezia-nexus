package handlers

// Cache-busting contract for the page shells.
//
// /static/* is served with Cache-Control: public, max-age=86400, so a browser
// that already holds a stylesheet keeps using it for up to a day unless the URL
// changes. The URL changes only if the version query is the release version. A
// literal such as ?v=1.1.0 never changes, so a corrected stylesheet can sit
// behind a stale cache entry.
//
// Two checks, because each catches what the other cannot:
//
//   - a source scan: no template may spell a version query as anything but
//     {{ .app_version }}. A render check alone cannot see a hardcoded value that
//     happens to equal the current version (api.js?v=2.5.0 did), and it would
//     pass the day before the next release breaks it;
//   - a render check: the four shells (the layout that every signed-in page
//     extends, and the three standalone pages) really emit the current version
//     on every stylesheet and every versioned script, and nothing else about
//     those links differs.

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// versionQuery finds every version query; versionAction is the only accepted
// continuation of one.
var (
	versionQuery  = regexp.MustCompile(`\?v=`)
	versionAction = regexp.MustCompile(`^\?v=\{\{\s*\.app_version\s*\}\}`)
)

// hardcodedAssetVersions returns "line N: text" for every version query in src
// that is not followed by the app_version action.
func hardcodedAssetVersions(src string) []string {
	var offenders []string
	for i, line := range strings.Split(src, "\n") {
		for _, loc := range versionQuery.FindAllStringIndex(line, -1) {
			if !versionAction.MatchString(line[loc[0]:]) {
				offenders = append(offenders, "line "+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
				break
			}
		}
	}
	return offenders
}

func TestAssetVersionScannerRecognisesOnlyTheAppVersionAction(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"action", `<link href="/static/css/a.css?v={{ .app_version }}">`, 0},
		{"action without spaces", `<script src="/x.js?v={{.app_version}}"></script>`, 0},
		{"literal version", `<link href="/static/css/a.css?v=1.1.0">`, 1},
		{"literal matching the release", `<script src="/x.js?v=2.5.0"></script>`, 1},
		{"other action", `<link href="/a.css?v={{ .something_else }}">`, 1},
		{"empty value", `<link href="/a.css?v=">`, 1},
		{"no query", `<link href="/static/css/a.css">`, 0},
		{"one bad line among good ones", "a?v={{ .app_version }}\nb?v=9\nc?v={{ .app_version }}", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hardcodedAssetVersions(tc.src); len(got) != tc.want {
				t.Fatalf("hardcodedAssetVersions(%q) = %v, want %d offender(s)", tc.src, got, tc.want)
			}
		})
	}
}

func TestNoTemplateHardcodesAnAssetVersion(t *testing.T) {
	templates, err := web.GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS: %v", err)
	}
	var scanned []string
	var offenders []string
	walkErr := fs.WalkDir(templates, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		body, readErr := fs.ReadFile(templates, path)
		if readErr != nil {
			return readErr
		}
		scanned = append(scanned, path)
		for _, o := range hardcodedAssetVersions(string(body)) {
			offenders = append(offenders, path+": "+o)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk templates: %v", walkErr)
	}
	for _, shell := range []string{"base.html", "login.html", "setup.html", "change_password.html"} {
		if !slices.Contains(scanned, shell) {
			t.Fatalf("the scan did not reach %s (scanned %d files); an empty scan proves nothing", shell, len(scanned))
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("a hardcoded asset version never changes, so a corrected asset can stay cached for "+
			"up to a day; use ?v={{ .app_version }}:\n%s", strings.Join(offenders, "\n"))
	}
}

// shellLinks are the local stylesheet and script references in a rendered page.
type shellLinks struct {
	stylesheets []string
	scripts     []string
}

func collectShellLinks(t *testing.T, body string) shellLinks {
	t.Helper()
	var links shellLinks
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return links
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		attrs := map[string]string{}
		for _, a := range tok.Attr {
			attrs[strings.ToLower(a.Key)] = a.Val
		}
		switch {
		case strings.EqualFold(tok.Data, "link") && strings.EqualFold(attrs["rel"], "stylesheet"):
			if strings.HasPrefix(attrs["href"], "/static/") {
				links.stylesheets = append(links.stylesheets, attrs["href"])
			}
		case strings.EqualFold(tok.Data, "script"):
			if strings.HasPrefix(attrs["src"], "/static/") {
				links.scripts = append(links.scripts, attrs["src"])
			}
		}
	}
}

func renderLoginPage(t *testing.T) string {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	w := httptest.NewRecorder()
	h.LoginHandler(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", w.Code)
	}
	return w.Body.String()
}

func renderSetupPage(t *testing.T) string {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	w := httptest.NewRecorder()
	h.SetupPageHandler(w, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /setup on an empty database = %d, want 200", w.Code)
	}
	return w.Body.String()
}

func renderChangePasswordPage(t *testing.T) string {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	w := httptest.NewRecorder()
	h.ChangePasswordPageHandler(w, httptest.NewRequest(http.MethodGet, "/change-password", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /change-password = %d, want 200", w.Code)
	}
	return w.Body.String()
}

// shellDeclaredAsset is one asset a shell template links, with the identity the
// template declared for it.
type shellDeclaredAsset struct {
	query    string
	identity assetIdentity
}

// shellDeclaredAssets maps every /static asset one shell template declares to
// the identity that template declared for it. The declared form is read from the
// shipped template rather than from a list kept here, so a second copy of "which
// asset uses which form" cannot drift from the page.
func shellDeclaredAssets(t *testing.T, shell string) map[string]shellDeclaredAsset {
	t.Helper()
	body, err := web.TemplatesFS.ReadFile("templates/" + shell)
	if err != nil {
		t.Fatalf("read %s: %v", shell, err)
	}
	assets := make(map[string]shellDeclaredAsset)
	for _, ref := range settingsSurfaceAssets(string(body)) {
		declared := shellDeclaredAsset{identity: ref.identity}
		if ref.identity != identityUnversioned {
			declared.query = strings.TrimPrefix(expectedAssetURL(t, ref), ref.path)
		}
		assets[ref.path] = declared
	}
	return assets
}

// renderVPNPageFor returns one of the three VPN documents through its production
// handler, so the render is the application's own path and not a test assembly.
// renderVPNPageFor returns the VPN page through its production handler, so the
// render is the application's own path and not a test assembly.
//
// #1006 merged the three documents into one, so the page name is kept only to
// reject a caller that still believes there is more than one: the retired handlers
// answer a redirect now, and asking one of them for markup would silently assert
// against a 302 body.
func renderVPNPageFor(t *testing.T, page string) string {
	t.Helper()
	if page != "vpn" {
		t.Fatalf("renderVPNPageFor(%q): the VPN subject is one page; %q is a retired child route", page, page)
	}
	h, _, _ := setupTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/vpn", nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "vpn-asset-admin",
		Role:   models.RoleAdmin,
	})
	ctx = middleware.WithCSRFToken(ctx, "csrf-test-token")
	w := httptest.NewRecorder()
	h.VPNPageHandler(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /vpn (%s) = %d, want 200", page, w.Code)
	}
	return w.Body.String()
}

// TestVPNPageServesEveryModuleUnderItsAssetBytes is the delivery check on the
// real documents: every module a VPN page loads is requested at the digest of the
// bytes this build ships, in the order the page depends on it. The reference URL
// comes from the production helper, so a template that stopped calling it fails
// here even though the template text would still name each module.
func TestVPNPageServesEveryModuleUnderItsAssetBytes(t *testing.T) {
	pages := []struct {
		name  string
		order []string
	}{
		{"vpn", []string{
			"/static/js/vpn/anchor_handoff.js",
			"/static/js/vpn/common.js",
			"/static/js/vpn/overview.js",
			"/static/js/vpn/backends.js",
			"/static/js/vpn/backends_page.js",
			"/static/js/vpn/health_problems.js",
			"/static/js/vpn/health_summary.js",
			"/static/js/vpn/charts.js",
			"/static/js/vpn/sessions.js",
			"/static/js/vpn/diagnostics_page.js",
			"/static/js/vpn/page.js",
		}},
	}
	for _, page := range pages {
		t.Run(page.name, func(t *testing.T) {
			wantOrder := page.order
			assertPageLoadsModulesUnderTheirBytes(t, page.name, wantOrder)
		})
	}
}

// assertPageLoadsModulesUnderTheirBytes renders one document and checks the chain.
func assertPageLoadsModulesUnderTheirBytes(t *testing.T, page string, wantOrder []string) {
	t.Helper()
	emitted := map[string]string{}
	var gotOrder []string
	for _, src := range collectShellLinks(t, renderVPNPageFor(t, page)).scripts {
		path, _, hasQuery := strings.Cut(src, "?")
		if !slices.Contains(wantOrder, path) {
			continue
		}
		emitted[path] = src
		if !hasQuery {
			t.Errorf("%s is requested bare, so a browser that cached the predecessor copy keeps running it", path)
			continue
		}
		gotOrder = append(gotOrder, path)
	}

	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("the page loads %v; the modules form a synchronous chain and the page must load %v", gotOrder, wantOrder)
	}
	for _, path := range wantOrder {
		want, err := web.AssetURL(path)
		if err != nil {
			t.Fatalf("AssetURL(%s): %v", path, err)
		}
		if got := emitted[path]; got != want {
			t.Errorf("%s is served at %q, want %q", path, got, want)
		}
		if strings.HasSuffix(emitted[path], "?v="+config.AppVersion) {
			t.Errorf("%s is identified by the release version, which did not move in this delivery", path)
		}
	}
}

func TestShellsRenderTheCurrentAppVersionOnVersionedAssets(t *testing.T) {
	if config.AppVersion == "" {
		t.Fatal("config.AppVersion is empty, so a missing value could not be told from a present one")
	}
	want := "?v=" + config.AppVersion

	// The stylesheet set and order are not part of this change, so they are
	// pinned here to prove the links differ in the identity query and nothing
	// else.
	wantStylesheets := []string{
		"/static/css/tokens.css", "/static/css/base.css", "/static/css/layout.css",
		"/static/css/components.css", "/static/css/tables.css", "/static/css/server.css",
		"/static/css/vpn.css", "/static/css/settings.css",
	}

	shells := []struct {
		name   string
		render func(t *testing.T) string
		// versionedScripts are the script paths that carry the release version as
		// their query today.
		versionedScripts []string
	}{
		{"base.html (layout, via /settings)", func(t *testing.T) string { return renderSettingsPage(t, models.RoleAdmin) },
			// The layout's own versioned script, then every settings controller. Each
			// one's query is the identity the template that loads it declares — the
			// release version, or the digest of the asset's bytes — so the two checks
			// read the same templates and cannot drift.
			append([]string{"/static/js/api.js"}, settingsSurfaceControllers...)},
		{"login.html", renderLoginPage, []string{"/static/js/api.js"}},
		{"setup.html", renderSetupPage, nil},
		{"change_password.html", renderChangePasswordPage, nil},
	}

	for _, shell := range shells {
		t.Run(shell.name, func(t *testing.T) {
			body := shell.render(t)
			if strings.Contains(body, "{{") || strings.Contains(body, "&lt;no value&gt;") || strings.Contains(body, "<no value>") {
				t.Fatal("the rendered shell leaks a template action or an empty value")
			}
			links := collectShellLinks(t, body)

			// Each shell declares exactly one identity per asset it links. A
			// stylesheet or controller this change replaced carries the digest of
			// its own bytes, because the release version is the URL its
			// predecessor also served.
			declared := shellDeclaredAssets(t, strings.Fields(shell.name)[0])

			var gotPaths []string
			for _, href := range links.stylesheets {
				path, query, _ := strings.Cut(href, "?")
				gotPaths = append(gotPaths, path)
				declaration, ok := declared[path]
				if !ok {
					t.Errorf("stylesheet %s is linked but no shell template declares its identity", path)
					continue
				}
				// The assets this change replaced must be cache-identified;
				// the others keep the identity they already carry, including the
				// layout's own bare scripts, which are not part of this change.
				if path == "/static/css/vpn.css" && declaration.identity != identityAssetBytes {
					t.Errorf("stylesheet %s is declared as %s; this delivery changed its bytes without "+
						"moving the release, so it must be identified by the bytes themselves", path, declaration.identity)
				}
				if declaration.identity == identityUnversioned {
					continue
				}
				if "?"+query != declaration.query {
					t.Errorf("stylesheet %s carries %q, want %q (declared in the template)", path, "?"+query, declaration.query)
				}
			}
			if !slices.Equal(gotPaths, wantStylesheets) {
				t.Errorf("stylesheet links changed:\n got: %v\nwant: %v", gotPaths, wantStylesheets)
			}

			seen := map[string]string{}
			for _, src := range links.scripts {
				path, query, hasQuery := strings.Cut(src, "?")
				if !hasQuery {
					continue
				}
				seen[path] = "?" + query
			}
			// A settings controller is compared with the identity its own template
			// declares. A script this delivery changed carries the digest of its
			// bytes — the layout's table engine is one, and it must not be held to
			// the release version the predecessor also served. Anything else must
			// carry the release version.
			controllers := declaredAssetQueries(t)
			for path, query := range seen {
				wantQuery, ok := controllers[path]
				if !ok && slices.Contains(web.DeliveredAssets, path) {
					delivered := expectedAssetURL(t, settingsAssetRef{path: path, identity: identityAssetBytes})
					wantQuery = strings.TrimPrefix(delivered, path)
					ok = true
				}
				if !ok {
					wantQuery = want
				}
				if query != wantQuery {
					t.Errorf("script %s carries %q, want %q", path, query, wantQuery)
				}
			}
			for _, path := range shell.versionedScripts {
				if _, ok := seen[path]; !ok {
					t.Errorf("script %s lost its cache-identity query (versioned scripts seen: %v)", path, seen)
				}
			}
		})
	}
}
