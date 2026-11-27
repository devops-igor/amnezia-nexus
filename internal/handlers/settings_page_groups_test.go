package handlers

// Grouping and in-page navigation of the rendered /settings page (#884, #887).
//
// The structural contract the grouped page has to keep, asserted on the HTML an
// administrator and a support user actually receive:
//
//   - one <section> per group, in the accepted order, each owning one grid, with
//     every card a direct child of a grid and each group's card list in order;
//   - each group named by its own heading, which is also the section's accessible
//     name, with the one-line purpose beside it;
//   - the heading levels that make the outline skimmable: group h2, card h3, a
//     named sub-area h4;
//   - one nav landmark inside main whose links each resolve to a rendered group.
//
// The behaviour the markup cannot state (which link is current, where focus goes
// when a link is followed) is covered by the JSDOM scenario in
// settings_nav_harness_test.go, and the measured geometry and accessibility tree
// by the round's browser evidence.

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// settingsGroupSpec is one group of the accepted information architecture: the
// id the sub-navigation points at, the translation key of its name, and the
// cards it owns, in document order (design sections 3.2 and 4.1).
type settingsGroupSpec struct {
	id      string
	nameKey string
	cards   []string
}

// settingsGroupsForAdmin is the structure an administrator receives: three groups,
// eight cards. The policy surface is not one of them any more: it is the Routing page
// (#987), and its two cards left with it. The hosting card left with the hosting
// block, which now renders on the Servers page beside the grid it acts on.
var settingsGroupsForAdmin = []settingsGroupSpec{
	{id: "group-portal", nameKey: "settings_group_portal", cards: []string{
		"appearanceCard", "sslCard", "captchaCard", "limitsCard",
	}},
	{id: "group-notifications", nameKey: "settings_group_notifications", cards: []string{
		"telegramCard", "notificationsCard",
	}},
	{id: "group-system", nameKey: "settings_group_system", cards: []string{
		"upstreamCard", "backupCard",
	}},
}

// settingsGroupsForSupport is the same page rendered for a role the route refuses:
// the administrative cards that need that role are absent, and no group is left
// without cards (design section 4.5).
var settingsGroupsForSupport = []settingsGroupSpec{
	{id: "group-portal", nameKey: "settings_group_portal", cards: []string{
		"appearanceCard", "sslCard", "captchaCard", "limitsCard",
	}},
	{id: "group-notifications", nameKey: "settings_group_notifications", cards: []string{
		"telegramCard",
	}},
	{id: "group-system", nameKey: "settings_group_system", cards: []string{
		"upstreamCard", "backupCard",
	}},
}

func elementByClass(doc *html.Node, class string) *html.Node {
	var found *html.Node
	walkLive(doc, func(n *html.Node) {
		if found == nil && n.Type == html.ElementNode && hasClass(n, class) {
			found = n
		}
	})
	return found
}

// nearestAncestorWithClass returns the closest ancestor element carrying class,
// or nil when there is none before the document root.
func nearestAncestorWithClass(n *html.Node, class string) *html.Node {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && hasClass(p, class) {
			return p
		}
	}
	return nil
}

// directChildCards returns the ids of the settings cards that are direct children
// of n, in document order. A card nested in a wrapper is not a grid item, which
// is the shape this page must not have.
func directChildCards(n *html.Node) []string {
	if n == nil {
		return nil
	}
	var ids []string
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && hasClass(c, "settings-section-card") {
			id, _ := attr(c, "id")
			ids = append(ids, id)
		}
	}
	return ids
}

// firstChildWithClass returns the first direct child element of n carrying class.
func firstChildWithClass(n *html.Node, class string) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && hasClass(c, class) {
			return c
		}
	}
	return nil
}

// englishTranslation returns one message from the English bundle, so the tests
// compare the page against the dictionary the render used instead of a copy of
// the string.
func englishTranslation(t *testing.T, key string) string {
	t.Helper()
	raw, err := web.TranslationsFS.ReadFile("translations/en.json")
	if err != nil {
		t.Fatalf("read en.json: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("decode en.json: %v", err)
	}
	text, ok := dict[key]
	if !ok {
		t.Fatalf("en.json has no %q", key)
	}
	return text
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestSettingsPageGroupsOwnTheirGrids pins the structural consequence of the
// grouping: one grid per group, each grid inside exactly one group inside main,
// every card a direct child of a grid, and each group's card list in order. A
// card that loses its group, changes group, or changes position inside one is
// reported, and so is a group that renders for a role that may not see it.
func TestSettingsPageGroupsOwnTheirGrids(t *testing.T) {
	for _, tc := range []struct {
		role   models.UserRole
		groups []settingsGroupSpec
	}{
		{models.RoleAdmin, settingsGroupsForAdmin},
		{models.RoleSupport, settingsGroupsForSupport},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			doc := parseSettingsDocument(t, renderSettingsPage(t, tc.role))
			main := elementByClass(doc, "app-main")
			if main == nil {
				t.Fatal("the settings page has no .app-main landmark")
			}

			// Every grid belongs to exactly one group, and that group is in main.
			grids := 0
			walkLive(doc, func(n *html.Node) {
				if !hasClass(n, "settings-grid") {
					return
				}
				grids++
				group := n.Parent
				if group == nil || !hasClass(group, "settings-group") {
					t.Error("a .settings-grid is not a direct child of a .settings-group")
					return
				}
				if group.Parent != main {
					t.Error("a .settings-group is not a direct child of the page's main landmark")
				}
				if group.Parent != nil && hasClass(group.Parent, "settings-group") {
					t.Error("a .settings-group is nested inside another one")
				}
			})
			if grids != len(tc.groups) {
				t.Fatalf("the page renders %d .settings-grid containers, want one per group (%d)", grids, len(tc.groups))
			}

			var groupOrder []string
			walkLive(doc, func(n *html.Node) {
				if n.Type == html.ElementNode && hasClass(n, "settings-group") {
					id, _ := attr(n, "id")
					groupOrder = append(groupOrder, id)
				}
			})
			var wantOrder []string
			for _, spec := range tc.groups {
				wantOrder = append(wantOrder, spec.id)
			}
			if !equalStrings(groupOrder, wantOrder) {
				t.Errorf("groups render in order %v, want %v", groupOrder, wantOrder)
			}

			listed := map[string]bool{}
			for _, spec := range tc.groups {
				group := elementByID(doc, spec.id)
				if group == nil {
					t.Errorf("group %q is missing", spec.id)
					continue
				}
				grid := firstChildWithClass(group, "settings-grid")
				if grid == nil {
					t.Errorf("group %q has no .settings-grid child", spec.id)
					continue
				}
				got := directChildCards(grid)
				if !equalStrings(got, spec.cards) {
					t.Errorf("%s holds cards %v, want %v", spec.id, got, spec.cards)
				}
				for _, id := range spec.cards {
					listed[id] = true
				}
			}

			// No card may sit outside a group, and no card may be absent from the
			// expected lists: either would mean a section silently left the page.
			walkLive(doc, func(n *html.Node) {
				if n.Type != html.ElementNode || !hasClass(n, "settings-section-card") {
					return
				}
				id, _ := attr(n, "id")
				if nearestAncestorWithClass(n, "settings-group") == nil {
					t.Errorf("card %q is not inside any group", id)
				}
				if !listed[id] {
					t.Errorf("card %q is not listed in any group's expected sections", id)
				}
			})
			for id := range listed {
				if card := elementByID(doc, id); card == nil {
					t.Errorf("group list names %q, but the page does not render it", id)
				}
			}
		})
	}
}

// TestSettingsPageGroupsAreNamedAndLabelled pins the names an operator navigates
// by: each group carries the translated heading as its first element, and the
// section's accessible name comes from that heading rather than from a list kept
// beside it.
func TestSettingsPageGroupsAreNamedAndLabelled(t *testing.T) {
	doc := parseSettingsDocument(t, renderSettingsPage(t, models.RoleAdmin))

	for _, spec := range settingsGroupsForAdmin {
		group := elementByID(doc, spec.id)
		if group == nil {
			t.Errorf("group %q is missing", spec.id)
			continue
		}
		heading := firstChildWithClass(group, "settings-group-title")
		if heading == nil {
			t.Errorf("%s has no .settings-group-title", spec.id)
			continue
		}
		if heading.Data != "h2" {
			t.Errorf("%s heading is a <%s>, want the group level to be h2", spec.id, heading.Data)
		}
		if got, want := textOf(heading), englishTranslation(t, spec.nameKey); got != want {
			t.Errorf("%s heading reads %q, want %q", spec.id, got, want)
		}
		headingID, _ := attr(heading, "id")
		if headingID != spec.id+"-title" {
			t.Errorf("%s heading id is %q, want %q", spec.id, headingID, spec.id+"-title")
		}
		if focusable, _ := attr(heading, "tabindex"); focusable != "-1" {
			t.Errorf("%s heading is not programmatically focusable (tabindex=%q): following its link "+
				"would leave focus in the sub-navigation", spec.id, focusable)
		}
		if by, _ := attr(group, "aria-labelledby"); by != headingID {
			t.Errorf("%s aria-labelledby = %q, want %q (its own heading)", spec.id, by, headingID)
		}
		// The one-line purpose sits with the heading, so the cluster reads as a
		// subject rather than as a run of cards.
		desc := ""
		for c := heading.NextSibling; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode {
				if hasClass(c, "card-subtitle") {
					desc = textOf(c)
				}
				break
			}
		}
		if strings.TrimSpace(desc) == "" {
			t.Errorf("%s has no description under its heading", spec.id)
		}
	}
}

// TestSettingsPageCardHeadingsSitBelowTheGroupHeading pins the heading levels the
// grouping introduces: the page keeps one h1, each group heading is an h2, each
// card title is an h3, and a named sub-area inside a card is an h4. The outline
// check above proves there is no skip; this one proves which level carries what,
// because a card title that stayed h2 would sit beside its own group.
func TestSettingsPageCardHeadingsSitBelowTheGroupHeading(t *testing.T) {
	for _, role := range []models.UserRole{models.RoleAdmin, models.RoleSupport} {
		t.Run(string(role), func(t *testing.T) {
			doc := parseSettingsDocument(t, renderSettingsPage(t, role))

			cards := 0
			walkLive(doc, func(n *html.Node) {
				if n.Type != html.ElementNode || !hasClass(n, "card-title") {
					return
				}
				if inDialog(n) {
					return
				}
				card := nearestAncestorWithClass(n, "settings-section-card")
				if card == nil {
					t.Errorf("card title %q is not inside a settings card", textOf(n))
					return
				}
				cards++
				if n.Data != "h3" {
					id, _ := attr(card, "id")
					t.Errorf("%s title is a <%s>, want h3 below the group's h2", id, n.Data)
				}
			})
			if cards < 7 {
				t.Fatalf("found %d card titles, want the whole rendered set", cards)
			}

			// A named sub-area inside a card is one level below the card title.
			for _, class := range []string{"settings-subheading", "settings-list-title", "settings-subsection-title"} {
				count := 0
				walkLive(doc, func(n *html.Node) {
					if n.Type != html.ElementNode || !hasClass(n, class) || inDialog(n) {
						return
					}
					count++
					if n.Data != "h4" {
						t.Errorf(".%s %q is a <%s>, want h4 below the card's h3", class, textOf(n), n.Data)
					}
				})
				// The admin session is the one that renders the policy, notification
				// history and hosting sub-areas at all.
				// The four policy readouts that carried a .settings-subheading left
				// with the surface (#987); the remaining sub-areas are unaffected.
				want := 0
				if role == models.RoleAdmin {
					want = map[string]int{
						"settings-subheading": 0,
						// The hosting card's two named sub-areas moved with the card to
						// the Servers page, so the only heading left in this document
						// with either class is the notification history's list title.
						"settings-list-title":       1,
						"settings-subsection-title": 0,
					}[class]
				}
				if count != want {
					t.Errorf("found %d .%s headings, want %d", count, class, want)
				}
			}
		})
	}
}

func inDialog(n *html.Node) bool {
	for p := n; p != nil; p = p.Parent {
		if p.Type == html.ElementNode {
			if role, _ := attr(p, "role"); role == "dialog" {
				return true
			}
		}
	}
	return false
}

// TestSettingsPageEvidenceTablesHaveAccessibleNames covers the naming half of
// design section 10.2: each evidence table inside a settings card is named by the
// label of the sub-area it belongs to, so a screen-reader user hears which table
// they have entered instead of "table".
//
// The two policy tables are the only evidence tables either page renders, and they
// moved to the Routing page with their card (#987). Both pages are therefore
// checked, and the count each must reach is stated: a page whose tables silently
// stopped rendering would otherwise satisfy a walk that found nothing.
func TestSettingsPageEvidenceTablesHaveAccessibleNames(t *testing.T) {
	for _, page := range []struct {
		name    string
		body    string
		atLeast int
	}{
		{"settings", renderSettingsPage(t, models.RoleAdmin), 0},
		{"routing", renderRoutingPage(t, models.RoleAdmin), 2},
	} {
		t.Run(page.name, func(t *testing.T) {
			assertEvidenceTablesNamed(t, parseSettingsDocument(t, page.body), page.atLeast)
		})
	}
}

// assertEvidenceTablesNamed walks the tables inside settings cards and fails any
// that no sub-area label names.
func assertEvidenceTablesNamed(t *testing.T, doc *html.Node, atLeast int) {
	t.Helper()

	tables := 0
	walkLive(doc, func(n *html.Node) {
		if n.Type != html.ElementNode || n.Data != "table" || inDialog(n) {
			return
		}
		if nearestAncestorWithClass(n, "settings-section-card") == nil {
			return
		}
		tables++
		named := false
		if by, ok := attr(n, "aria-labelledby"); ok {
			for _, id := range strings.Fields(by) {
				if label := elementByID(doc, id); label != nil && textOf(label) != "" {
					named = true
				}
			}
		}
		for c := n.FirstChild; c != nil && !named; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "caption" && textOf(c) != "" {
				named = true
			}
		}
		if !named {
			t.Error("a table inside a settings card has no accessible name from its sub-area label")
		}
	})
	if tables < atLeast {
		t.Fatalf("found %d evidence tables inside settings cards, want at least %d", tables, atLeast)
	}
}

// TestSettingsPageSubNavigationLinksEveryGroup pins the in-page navigation: one
// nav landmark inside main with a translated name, one link per rendered group,
// every link resolving to that group, and the link text naming the group it goes
// to. A group that loses its link, or a link whose target does not exist, fails
// here without a browser.
func TestSettingsPageSubNavigationLinksEveryGroup(t *testing.T) {
	for _, tc := range []struct {
		role   string
		groups []settingsGroupSpec
	}{
		{"admin", settingsGroupsForAdmin},
		{"support", settingsGroupsForSupport},
	} {
		t.Run(tc.role, func(t *testing.T) {
			doc := parseSettingsDocument(t, renderSettingsPage(t, models.UserRole(tc.role)))
			main := elementByClass(doc, "app-main")
			if main == nil {
				t.Fatal("the settings page has no .app-main landmark")
			}

			var nav *html.Node
			navs := 0
			walkLive(main, func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "nav" {
					navs++
					nav = n
				}
			})
			if navs != 1 {
				t.Fatalf("main holds %d nav landmarks, want exactly the sub-navigation", navs)
			}
			if label, _ := attr(nav, "aria-label"); strings.TrimSpace(label) != englishTranslation(t, "settings_nav_label") {
				t.Errorf("sub-navigation aria-label = %q, want the translated name %q",
					label, englishTranslation(t, "settings_nav_label"))
			}

			var hrefs, texts, classes []string
			walkLive(nav, func(n *html.Node) {
				if n.Type != html.ElementNode || n.Data != "a" {
					return
				}
				href, _ := attr(n, "href")
				class, _ := attr(n, "class")
				hrefs = append(hrefs, href)
				texts = append(texts, textOf(n))
				classes = append(classes, class)
			})
			if len(hrefs) != len(tc.groups) {
				t.Fatalf("the sub-navigation has %d links, want one per rendered group (%d)", len(hrefs), len(tc.groups))
			}
			// A navigation link is not a control with a surface: it carries no
			// button class, because every button variant paints a fill or a
			// border that reads as four chips on the page. The settings sheet
			// owns the link's size, alignment and states instead.
			for i, class := range classes {
				if !containsClass(class, "settings-subnav-link") {
					t.Errorf("link %d has class %q, want settings-subnav-link", i, class)
				}
				for _, token := range strings.Fields(class) {
					if token == "btn" || strings.HasPrefix(token, "btn-") {
						t.Errorf("link %d carries the button class %q, which paints a fill the navigation must not have", i, token)
					}
				}
			}
			for i, spec := range tc.groups {
				if hrefs[i] != "#"+spec.id {
					t.Errorf("link %d points at %q, want #%s", i, hrefs[i], spec.id)
				}
				if got, want := texts[i], englishTranslation(t, spec.nameKey); got != want {
					t.Errorf("link %d reads %q, want the group name %q", i, got, want)
				}
				target := elementByID(doc, spec.id)
				if target == nil {
					t.Errorf("link %d points at #%s, which the page does not render", i, spec.id)
					continue
				}
				if !hasClass(target, "settings-group") {
					t.Errorf("#%s is not a group, so following the link does not land on a group", spec.id)
				}
			}

			// The navigation sits before the first group, so the page is read in
			// the order it is navigated in.
			seenNav, seenGroup := -1, -1
			index := 0
			walkLive(doc, func(n *html.Node) {
				index++
				if seenNav < 0 && n == nav {
					seenNav = index
				}
				if seenGroup < 0 && n.Type == html.ElementNode && hasClass(n, "settings-group") {
					seenGroup = index
				}
			})
			if seenNav < 0 || seenGroup < 0 || seenNav > seenGroup {
				t.Errorf("the sub-navigation must come before the first group (nav at %d, group at %d)", seenNav, seenGroup)
			}
		})
	}
}
