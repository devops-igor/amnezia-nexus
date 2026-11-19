package handlers

// Structural contract for the rendered /settings page (#887, mechanical half).
//
// These assertions parse the HTML an administrator actually receives, so they
// describe the document rather than the template source:
//
//   - one h1 for the page, and a heading outline that never skips a level;
//   - the cards are children of one grid (or the full-width cards that follow
//     it), the stylesheet makes that grid one column and two stretched columns
//     from 1024px, and no settings template carries an inline style attribute;
//   - every card category toggle carries an id and a name, and the icon-only
//     catalog refresh button carries an accessible name in every locale;
//   - the fields that start collapsed use the hidden attribute, which the page
//     script still overrides through the style property.

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

func parseSettingsDocument(t *testing.T, body string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse rendered settings page: %v", err)
	}
	return doc
}

// walkLive visits every element outside a <template>, whose content is inert
// until script clones it.
func walkLive(n *html.Node, visit func(*html.Node)) {
	if n.Type == html.ElementNode {
		if n.Data == "template" {
			return
		}
		visit(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkLive(c, visit)
	}
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func elementByID(doc *html.Node, id string) *html.Node {
	var found *html.Node
	walkLive(doc, func(n *html.Node) {
		if v, ok := attr(n, "id"); ok && v == id {
			found = n
		}
	})
	return found
}

func textOf(n *html.Node) string {
	var b strings.Builder
	var rec func(*html.Node)
	rec = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			rec(c)
		}
	}
	rec(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

func TestSettingsPageHeadingOutline(t *testing.T) {
	for _, role := range []models.UserRole{models.RoleAdmin, models.RoleSupport} {
		t.Run(string(role), func(t *testing.T) {
			doc := parseSettingsDocument(t, renderSettingsPage(t, role))

			var levels []int
			var names []string
			walkLive(doc, func(n *html.Node) {
				if len(n.Data) == 2 && n.Data[0] == 'h' && n.Data[1] >= '1' && n.Data[1] <= '6' {
					levels = append(levels, int(n.Data[1]-'0'))
					names = append(names, textOf(n))
				}
			})

			h1 := 0
			for _, l := range levels {
				if l == 1 {
					h1++
				}
			}
			if h1 != 1 {
				t.Fatalf("settings page has %d h1 elements, want exactly 1 (outline: %v)", h1, levels)
			}
			if levels[0] != 1 {
				t.Errorf("first heading is h%d (%q), want the h1", levels[0], names[0])
			}
			prev := 0
			for i, l := range levels {
				if l > prev+1 {
					t.Errorf("heading %q is h%d after h%d: the outline skips a level", names[i], l, prev)
				}
				prev = l
			}
		})
	}
}

func TestSettingsPageCardsShareOneGrid(t *testing.T) {
	doc := parseSettingsDocument(t, renderSettingsPage(t, models.RoleAdmin))

	grids := 0
	cards := 0
	var gridRoot *html.Node
	walkLive(doc, func(n *html.Node) {
		if cls, _ := attr(n, "class"); containsClass(cls, "settings-grid") {
			grids++
			gridRoot = n
		}
		if cls, _ := attr(n, "class"); containsClass(cls, "settings-section-card") {
			cards++
			// A card is either a direct child of the grid, or one of the
			// full-width standalone cards that follow it in the page content.
			// Anything else is a wrapper column pairing cards of unrelated height.
			p := n.Parent
			inGrid := p != nil && hasClass(p, "settings-grid")
			followsGrid := p != nil && gridRoot != nil && p == gridRoot.Parent
			if !inGrid && !followsGrid {
				id, _ := attr(n, "id")
				t.Errorf("card %q sits in a wrapper that is neither the grid nor the page content", id)
			}
		}
	})
	if grids != 1 {
		t.Errorf("found %d .settings-grid containers, want 1", grids)
	}
	if cards < 9 {
		t.Errorf("found %d settings cards, want the full admin set", cards)
	}
}

func hasClass(n *html.Node, class string) bool {
	cls, _ := attr(n, "class")
	return containsClass(cls, class)
}

func containsClass(list, class string) bool {
	for _, c := range strings.Fields(list) {
		if c == class {
			return true
		}
	}
	return false
}

// settingsTemplateSource returns every template that renders on the settings
// page: the shell, each section file under templates/settings/, and the four
// standalone card partials.
func settingsTemplateSource(t *testing.T) string {
	t.Helper()
	names := []string{
		"templates/settings.html",
		"templates/settings_notifications.html",
		"templates/settings_save_controls.html",
		"templates/settings_policy.html",
		"templates/settings_policy_upstream.html",
		"templates/settings_policy_client.html",
	}
	entries, err := web.TemplatesFS.ReadDir("templates/settings")
	if err != nil || len(entries) == 0 {
		t.Fatalf("list settings sections: %v (%d entries)", err, len(entries))
	}
	for _, e := range entries {
		names = append(names, "templates/settings/"+e.Name())
	}
	var b strings.Builder
	for _, name := range names {
		body, err := web.TemplatesFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.WriteString("\n")
		b.Write(body)
	}
	return b.String()
}

// TestSettingsPageLayoutIsNotInline fails when a layout rule returns to a style
// attribute in any template that renders on the settings page.
func TestSettingsPageLayoutIsNotInline(t *testing.T) {
	source := settingsTemplateSource(t)
	for _, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "style=") {
			t.Errorf("inline style in a settings template: %s", strings.TrimSpace(line))
		}
	}
	if strings.Contains(source, "minmax(380px") {
		t.Error("the settings grid must not carry a fixed 380px column minimum")
	}
}

// cssRule returns the declaration block that follows the first occurrence of
// selector at or after from, or "" when there is none.
func cssRule(css, selector string, from int) (string, int) {
	i := strings.Index(css[from:], selector+" {")
	if i < 0 {
		return "", -1
	}
	i += from
	open := i + len(selector) + 2
	end := strings.Index(css[open:], "}")
	if end < 0 {
		return "", -1
	}
	return css[open : open+end], open + end
}

// TestSettingsGridStylesheetRule pins the layout rule the browser measurement in
// tests/e2e/test_settings.py exercises: one column by default, two columns that
// stretch to the taller card from 1024px, and a track that can shrink below its
// content so a long word cannot widen the page.
func TestSettingsGridStylesheetRule(t *testing.T) {
	raw, err := web.StaticFS.ReadFile("static/css/settings.css")
	if err != nil {
		t.Fatalf("read settings.css: %v", err)
	}
	css := string(raw)

	base, after := cssRule(css, ".settings-grid", 0)
	if after < 0 {
		t.Fatal("settings.css has no .settings-grid rule")
	}
	if !strings.Contains(base, "grid-template-columns: minmax(0, 1fr)") {
		t.Errorf("base .settings-grid is not a single shrinkable column:\n%s", base)
	}

	media := strings.Index(css[after:], "@media (min-width: 1024px)")
	if media < 0 {
		t.Fatal("settings.css has no @media (min-width: 1024px) block for the grid")
	}
	wide, _ := cssRule(css, "    .settings-grid", after+media)
	if wide == "" {
		t.Fatal("the 1024px block does not restyle .settings-grid")
	}
	if !strings.Contains(wide, "repeat(2, minmax(0, 1fr))") {
		t.Errorf("wide .settings-grid is not two shrinkable columns:\n%s", wide)
	}
	if !strings.Contains(wide, "align-items: stretch") {
		t.Errorf("wide .settings-grid does not stretch a row to its taller card:\n%s", wide)
	}
	if strings.Contains(base, "align-items: start") {
		t.Error("base .settings-grid must not align cards to the start; paired cards would differ in height")
	}
}

// TestSettingsStylesheetIsRegistered keeps the dedicated sheet in the shared
// cascade list that every shell template links, in the same position.
func TestSettingsStylesheetIsRegistered(t *testing.T) {
	for _, shell := range []string{"base.html", "login.html", "setup.html", "change_password.html"} {
		body, err := web.TemplatesFS.ReadFile("templates/" + shell)
		if err != nil {
			t.Fatalf("read %s: %v", shell, err)
		}
		vpn := strings.Index(string(body), "/static/css/vpn.css")
		settings := strings.Index(string(body), "/static/css/settings.css")
		if settings < 0 || vpn < 0 || settings < vpn {
			t.Errorf("%s must link settings.css directly after vpn.css", shell)
		}
	}
}

func TestSettingsPageControlsHaveAccessibleNames(t *testing.T) {
	doc := parseSettingsDocument(t, renderSettingsPage(t, models.RoleAdmin))

	wantCategories := []string{"server_health", "backend_health", "provisioning", "updates", "failover"}
	seen := map[string]bool{}
	ids := map[string]int{}
	walkLive(doc, func(n *html.Node) {
		if id, ok := attr(n, "id"); ok {
			ids[id]++
		}
		if n.Data != "input" || !hasClass(n, "notification-category") {
			return
		}
		cat, _ := attr(n, "data-category")
		seen[cat] = true
		id, ok := attr(n, "id")
		if !ok || id != "notifications_category_"+cat {
			t.Errorf("category toggle %q has id %q, want notifications_category_%s", cat, id, cat)
		}
		if lbl := enclosingLabel(n); lbl == nil || textOf(lbl) == "" {
			t.Errorf("category toggle %q has no label text", cat)
		}
	})
	for _, cat := range wantCategories {
		if !seen[cat] {
			t.Errorf("category toggle %q is missing", cat)
		}
	}
	for id, n := range ids {
		if n > 1 {
			t.Errorf("id %q is used %d times on the page", id, n)
		}
	}

	group := elementByID(doc, "notificationCategoriesLabel")
	if group == nil || group.Parent == nil {
		t.Fatal("the categories label has no id for the group to reference")
	}
	if role, _ := attr(group.Parent, "role"); role != "group" {
		t.Errorf("category toggles are in a %q container, want role=group", role)
	}
	if by, _ := attr(group.Parent, "aria-labelledby"); by != "notificationCategoriesLabel" {
		t.Errorf("category group aria-labelledby = %q, want notificationCategoriesLabel", by)
	}

	refresh := elementByID(doc, "btnRefreshCatalog")
	if refresh == nil {
		t.Fatal("catalog refresh button is missing")
	}
	if name, _ := attr(refresh, "aria-label"); strings.TrimSpace(name) == "" {
		t.Error("the icon-only catalog refresh button has no aria-label")
	}

	// A bare icon link names its destination through aria-label too.
	for _, id := range []string{"repoLink-amneziawg-go", "repoLink-amneziawg-tools", "repoLink-docker-base-image"} {
		link := elementByID(doc, id)
		if link == nil {
			t.Fatalf("release link #%s is missing", id)
		}
		if name, _ := attr(link, "aria-label"); strings.TrimSpace(name) == "" {
			t.Errorf("release link #%s has no aria-label", id)
		}
	}
}

func enclosingLabel(n *html.Node) *html.Node {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && p.Data == "label" {
			return p
		}
	}
	return nil
}

func TestSettingsPageCollapsedFieldsUseHiddenAttribute(t *testing.T) {
	doc := parseSettingsDocument(t, renderSettingsPage(t, models.RoleAdmin))
	for _, id := range []string{
		"sslFields", "telegramFields", "upstreamUpdateBanner",
		"deployCatalogStale", "deployCatalogLoading", "deployPlacementHint",
	} {
		n := elementByID(doc, id)
		if n == nil {
			t.Errorf("#%s is missing", id)
			continue
		}
		if _, ok := attr(n, "hidden"); !ok {
			t.Errorf("#%s does not start hidden", id)
		}
		if style, ok := attr(n, "style"); ok {
			t.Errorf("#%s carries an inline style %q", id, style)
		}
	}
}

func TestSettingsPageNewKeysExistInEveryLocale(t *testing.T) {
	keys := []string{
		"deploy_vps_refresh_catalog", "upstream_releases_link",
		// The per-card save model (#888).
		"settings_unsaved", "settings_applies_now", "settings_save_read_failed", "settings_test_saves_first",
	}
	for _, locale := range []string{"en", "ru", "fr", "zh", "fa"} {
		raw, err := web.TranslationsFS.ReadFile("translations/" + locale + ".json")
		if err != nil {
			t.Fatalf("read %s: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("decode %s: %v", locale, err)
		}
		for _, key := range keys {
			if strings.TrimSpace(dict[key]) == "" {
				t.Errorf("%s.json is missing %q", locale, key)
			}
		}
	}
	// The English text must not be copied into the other locales.
	en, _ := web.TranslationsFS.ReadFile("translations/en.json")
	ru, _ := web.TranslationsFS.ReadFile("translations/ru.json")
	var enDict, ruDict map[string]string
	_ = json.Unmarshal(en, &enDict)
	_ = json.Unmarshal(ru, &ruDict)
	for _, key := range keys {
		if enDict[key] == ruDict[key] {
			t.Errorf("ru.json %q is the English text", key)
		}
	}
}
