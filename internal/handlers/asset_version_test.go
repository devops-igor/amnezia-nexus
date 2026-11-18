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

func TestShellsRenderTheCurrentAppVersionOnVersionedAssets(t *testing.T) {
	if config.AppVersion == "" {
		t.Fatal("config.AppVersion is empty, so a missing value could not be told from a present one")
	}
	want := "?v=" + config.AppVersion

	// The stylesheet set and order are not part of this change, so they are
	// pinned here to prove the links differ in the version query and nothing else.
	wantStylesheets := []string{
		"/static/css/tokens.css", "/static/css/base.css", "/static/css/layout.css",
		"/static/css/components.css", "/static/css/tables.css", "/static/css/server.css",
		"/static/css/vpn.css", "/static/css/settings.css",
	}

	shells := []struct {
		name   string
		render func(t *testing.T) string
		// versionedScripts are the script paths that carry a version query today.
		versionedScripts []string
	}{
		{"base.html (layout, via /settings)", func(t *testing.T) string { return renderSettingsPage(t, models.RoleAdmin) },
			[]string{"/static/js/api.js", "/static/js/notifications_settings.js", "/static/js/settings.js", "/static/js/policy_routing.js"}},
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

			var gotPaths []string
			for _, href := range links.stylesheets {
				path, query, _ := strings.Cut(href, "?")
				gotPaths = append(gotPaths, path)
				if "?"+query != want {
					t.Errorf("stylesheet %s carries %q, want %q", path, "?"+query, want)
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
				if "?"+query != want {
					t.Errorf("script %s carries %q, want %q", path, "?"+query, want)
				}
			}
			for _, path := range shell.versionedScripts {
				if _, ok := seen[path]; !ok {
					t.Errorf("script %s lost its version query (versioned scripts seen: %v)", path, seen)
				}
			}
		})
	}
}
