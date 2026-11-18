package handlers

// Structural contract for the rendered /settings page (#887, mechanical half).
//
// These assertions parse the HTML an administrator actually receives, so they
// describe the document rather than the template source:
//
//   - one h1 for the page, and a heading outline that never skips a level;
//   - the cards are direct children of one single-column grid, with no inline
//     style attribute anywhere in the page shell or its section files;
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

func TestSettingsPageCardsShareOneColumnGrid(t *testing.T) {
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

// settingsTemplateSource returns the page shell followed by every section file
// under templates/settings/. The four standalone card partials are not part of
// this contract: they keep their inline styles until their own cleanup.
func settingsTemplateSource(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	shell, err := web.TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings shell: %v", err)
	}
	b.Write(shell)
	entries, err := web.TemplatesFS.ReadDir("templates/settings")
	if err != nil || len(entries) == 0 {
		t.Fatalf("list settings sections: %v (%d entries)", err, len(entries))
	}
	for _, e := range entries {
		body, err := web.TemplatesFS.ReadFile("templates/settings/" + e.Name())
		if err != nil {
			t.Fatalf("read section %s: %v", e.Name(), err)
		}
		b.WriteString("\n")
		b.Write(body)
	}
	return b.String()
}

// TestSettingsPageLayoutIsNotInline fails when a layout rule returns to a style
// attribute in the page shell or any of its section files.
func TestSettingsPageLayoutIsNotInline(t *testing.T) {
	source := settingsTemplateSource(t)
	if strings.Contains(source, "style=") {
		for _, line := range strings.Split(source, "\n") {
			if strings.Contains(line, "style=") {
				t.Errorf("inline style in the settings page source: %s", strings.TrimSpace(line))
			}
		}
	}
	if strings.Contains(source, "minmax(380px") {
		t.Error("the settings grid must not carry a fixed 380px column minimum")
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
	keys := []string{"deploy_vps_refresh_catalog", "upstream_releases_link"}
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
