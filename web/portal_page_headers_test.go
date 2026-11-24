package web

// Structural contract for the portal pages' single page-level heading and for
// the control size scale those pages share (#967).
//
// The assertions parse the document an operator actually receives, so they
// describe the page rather than the template source: exactly one h1, it is the
// first heading, the outline never skips a level, and the heading carries the
// same shape the Settings page already ships. Two source-level checks cover the
// shapes the static document cannot show: a header rendered as a non-heading
// element, and an inline height on a control, which would put that control off
// the scale without changing any class.

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// portalPage is a page that renders inside the shared shell and therefore owes
// one page-level heading.
//
// Two properties are recorded per page because they are facts about that page,
// not preferences:
//
//   - TitleIsSectionTitle: the page's heading is the shared page-title shape
//     (h1.section-title). The server detail page names the server in its card
//     header instead, so its h1 is the page heading but is not that shape.
//   - TitleIsFirstHeading: no section heading renders above the title. The
//     connections page renders its server-status card, an h2, above the page
//     title; reordering that is a page-layout decision and is reported rather
//     than taken here.
type portalPage struct {
	Template            string
	TitleIsSectionTitle bool
	TitleIsFirstHeading bool
	Note                string
}

var portalPages = []portalPage{
	{Template: "index.html", TitleIsSectionTitle: true, TitleIsFirstHeading: true},
	{Template: "users.html", TitleIsSectionTitle: true, TitleIsFirstHeading: true},
	{Template: "vpn.html", TitleIsSectionTitle: true, TitleIsFirstHeading: true},
	{Template: "routing.html", TitleIsSectionTitle: true, TitleIsFirstHeading: true},
	{Template: "leaderboard.html", TitleIsSectionTitle: true, TitleIsFirstHeading: true},
	{
		Template:            "my_connections.html",
		TitleIsSectionTitle: true,
		TitleIsFirstHeading: false,
		Note:                "the server-status card renders its h2 above the page title; the order is a page-layout decision",
	},
	{
		Template:            "server.html",
		TitleIsSectionTitle: false,
		TitleIsFirstHeading: true,
		Note:                "the page heading is the server's name in its card header, not the shared page-title shape",
	},
}

func portalTemplateFuncMap() template.FuncMap {
	return withAssetURL(template.FuncMap{
		"_":            func(key string, args ...any) string { return key },
		"has_role":     func(u any, roles ...string) bool { return true },
		"is_admin":     func(u any) bool { return true },
		"json":         func(v any) (string, error) { return "{}", nil },
		"format_bytes": func(b any) string { return "0 B" },
		"upper":        func(s any) string { return strings.ToUpper(fmt.Sprint(s)) },
		"lower":        func(s any) string { return strings.ToLower(fmt.Sprint(s)) },
		"safe_js":      func(s any) template.JS { return template.JS(fmt.Sprint(s)) },
		"str":          func(v any) string { return fmt.Sprint(v) },
		"proto_title":  func(p any) string { return fmt.Sprint(p) },
		"is_installed": func(v any) bool { return true },
		"format_time":  func(t any) string { return "" },
		"slice_str":    func(s string, start, end int) string { return "" },
		"get": func(target any, key any, fallback ...any) any {
			if len(fallback) > 0 {
				return fallback[0]
			}
			return nil
		},
	})
}

func renderPortalPage(t *testing.T, name string) string {
	t.Helper()

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	// The same set the application renders this page from: the shell, every section
	// partial, and the page itself. Parsing only base.html and the page would fail on any
	// page that includes a section defined elsewhere, which is a property of the page's
	// template set rather than a fact about this test.
	files := make([]string, 0, len(LayoutPartials)+2)
	files = append(files, "base.html")
	files = append(files, LayoutPartials...)
	files = append(files, name)
	tmpl, err := template.New("base.html").Funcs(portalTemplateFuncMap()).ParseFS(templatesFS, files...)
	if err != nil {
		t.Fatalf("parse the template set for %s: %v", name, err)
	}

	data := map[string]any{
		"title":             "Portal Test",
		"lang":              "en",
		"active_page":       strings.TrimSuffix(name, ".html"),
		"csrf_token":        "csrf-test-token",
		"translations_json": "{}",
		"app_version":       "9.9.9-test",
		"current_user":      map[string]any{"ID": "1", "Username": "admin", "Role": "admin"},
		"site_settings":     map[string]any{"Title": "Amnezia", "Subtitle": "Nexus"},
		"server":            map[string]any{"ID": 1, "Name": "srv", "Host": "127.0.0.1", "SSHPort": 22, "SSHUser": "root"},
		"servers": []any{
			map[string]any{"ID": 1, "Name": "srv", "Host": "127.0.0.1", "Status": "online"},
		},
		"users":       []any{},
		"connections": []any{},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute base.html and %s: %v", name, err)
	}
	return buf.String()
}

// portalWalk visits element nodes outside a <template>, whose content is inert
// until script clones it.
func portalWalk(n *html.Node, visit func(*html.Node)) {
	if n.Type == html.ElementNode {
		if n.Data == "template" {
			return
		}
		visit(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		portalWalk(c, visit)
	}
}

func portalAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func portalHasClass(n *html.Node, class string) bool {
	return containsClassToken(portalAttr(n, "class"), class)
}

func containsClassToken(list, class string) bool {
	for _, c := range strings.Fields(list) {
		if c == class {
			return true
		}
	}
	return false
}

func portalText(n *html.Node) string {
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

// TestPortalPagesHaveOnePageHeading asserts the rendered heading outline. A page
// whose title is not a heading has no page-level heading at all, which is what
// the portal carried before this shape was shared.
func TestPortalPagesHaveOnePageHeading(t *testing.T) {
	for _, page := range portalPages {
		t.Run(page.Template, func(t *testing.T) {
			doc, err := html.Parse(strings.NewReader(renderPortalPage(t, page.Template)))
			if err != nil {
				t.Fatalf("parse rendered %s: %v", page.Template, err)
			}

			var levels []int
			var names []string
			var headings []*html.Node
			portalWalk(doc, func(n *html.Node) {
				if len(n.Data) == 2 && n.Data[0] == 'h' && n.Data[1] >= '1' && n.Data[1] <= '6' {
					levels = append(levels, int(n.Data[1]-'0'))
					names = append(names, portalText(n))
					headings = append(headings, n)
				}
			})
			if len(levels) == 0 {
				t.Fatal("the page renders no headings")
			}

			titleAt := -1
			for i, l := range levels {
				if l == 1 {
					titleAt = i
				}
			}
			h1 := 0
			for _, l := range levels {
				if l == 1 {
					h1++
				}
			}
			if h1 != 1 {
				t.Fatalf("the page has %d h1 elements, want exactly 1 (outline: %v)", h1, levels)
			}
			if page.TitleIsFirstHeading && titleAt != 0 {
				t.Errorf("the first heading is h%d (%q), want the page's h1", levels[0], names[0])
			}
			if !page.TitleIsFirstHeading {
				// The recorded exception must still describe the page: an exception
				// nobody can observe is one that has outlived its reason.
				if titleAt == 0 {
					t.Errorf("the recorded exception no longer applies (%s): the page title is now the first heading", page.Note)
				}
				if strings.TrimSpace(page.Note) == "" {
					t.Error("a heading-order exception needs its recorded reason")
				}
			}

			// From the page title onwards the outline must not skip a level. The
			// levels above it belong to the pages whose Note records them.
			prev := 0
			for i := titleAt; i < len(levels); i++ {
				if levels[i] > prev+1 {
					t.Errorf("heading %q is h%d after h%d: the outline skips a level", names[i], levels[i], prev)
				}
				prev = levels[i]
			}

			pageHeading := headings[titleAt]
			if page.TitleIsSectionTitle && !portalHasClass(pageHeading, "section-title") {
				t.Errorf("the page heading carries class %q, want section-title as well", portalAttr(pageHeading, "class"))
			}
			if strings.TrimSpace(portalText(pageHeading)) == "" {
				t.Error("the page heading has no text")
			}
			if inShell(pageHeading) {
				t.Error("the page heading is inside the shell rather than the page")
			}
		})
	}
}

// inShell reports whether the node sits inside the shell's own chrome: the
// sidebar, the mobile bars, or one of the dialogs the shell renders.
func inShell(n *html.Node) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type != html.ElementNode {
			continue
		}
		for _, class := range []string{"app-sidebar", "mobile-topbar", "mobile-bottom-bar"} {
			if portalHasClass(p, class) {
				return true
			}
		}
		if id := portalAttr(p, "id"); id == "langModal" || id == "nexusConfirmModal" {
			return true
		}
	}
	return false
}

// insidePortalPage reports whether the node is inside the shell's content area,
// which is the scope the shared control scale is declared on.
func insidePortalPage(n *html.Node) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && portalHasClass(p, "portal-page") {
			return true
		}
	}
	return false
}

// TestVPNPageTitleUsesTheSharedHeadingShape pins the shape the merged Settings
// page renders: the icon is wrapped in an .icon span inside the heading, so the
// heading's own text is the page title and not the icon's accessible name.
func TestVPNPageTitleUsesTheSharedHeadingShape(t *testing.T) {
	doc, err := html.Parse(strings.NewReader(renderPortalPage(t, "vpn.html")))
	if err != nil {
		t.Fatalf("parse rendered vpn.html: %v", err)
	}

	var title *html.Node
	portalWalk(doc, func(n *html.Node) {
		if n.Data == "h1" && portalHasClass(n, "section-title") {
			title = n
		}
	})
	if title == nil {
		t.Fatal("the VPN page has no h1.section-title")
	}

	var iconSpan *html.Node
	for c := title.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "span" && portalHasClass(c, "icon") {
			iconSpan = c
		}
	}
	if iconSpan == nil {
		t.Fatal("the VPN page heading does not wrap its icon in an .icon span")
	}
	if findElementByTagAndClass(iconSpan, "svg", "icon") == nil {
		t.Error("the .icon span does not contain the heading's svg")
	}
}

// TestPortalTemplatesCarryNoHeaderlessTitle fails when a page returns to a title
// that is not a heading.
func TestPortalTemplatesCarryNoHeaderlessTitle(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	for _, page := range portalPages {
		body, err := fs.ReadFile(templatesFS, page.Template)
		if err != nil {
			t.Fatalf("read %s: %v", page.Template, err)
		}
		if strings.Contains(string(body), `<div class="section-title`) {
			t.Errorf("%s renders its title as a div.section-title instead of a heading", page.Template)
		}
	}
}

// TestPortalPagesDoNotSizeControlsInline fails when a rendered control carries a
// height or vertical padding of its own. An inline declaration outranks the
// shared scale, so that control would keep its own height while every other one
// moved, which is how one page came to show six different button heights.
func TestPortalPagesDoNotSizeControlsInline(t *testing.T) {
	blocked := []string{"padding", "height", "font-size", "line-height"}
	for _, page := range portalPages {
		t.Run(page.Template, func(t *testing.T) {
			doc, err := html.Parse(strings.NewReader(renderPortalPage(t, page.Template)))
			if err != nil {
				t.Fatalf("parse rendered %s: %v", page.Template, err)
			}
			portalWalk(doc, func(n *html.Node) {
				if !portalHasClass(n, "btn") || !insidePortalPage(n) {
					return
				}
				style := portalAttr(n, "style")
				for _, property := range blocked {
					if strings.Contains(style, property) {
						t.Errorf("%s control sizes itself inline (%s): %s %q", n.Data, property, style, portalText(n))
					}
				}
			})
		})
	}
}

// TestPortalButtonScaleMatchesTheSettingsSteps pins the two-step scale and the
// shell marker that scopes it. The expected heights are derived from the spacing
// tokens, so a token change is reported here rather than silently moving the
// scale.
func TestPortalButtonScaleMatchesTheSettingsSteps(t *testing.T) {
	tokenSheet, err := StaticFS.ReadFile("static/css/tokens.css")
	if err != nil {
		t.Fatalf("read tokens.css: %v", err)
	}
	px := map[string]string{}
	for _, name := range []string{"space-sm", "space-xl"} {
		value := tokenValue(t, string(tokenSheet), name)
		px[name] = value
	}
	if px["space-sm"] != "8px" || px["space-xl"] != "32px" {
		t.Fatalf("the scale's steps moved: --space-sm=%s --space-xl=%s (expected 8px and 32px)", px["space-sm"], px["space-xl"])
	}

	shell, err := TemplatesFS.ReadFile("templates/base.html")
	if err != nil {
		t.Fatalf("read base.html: %v", err)
	}
	if !strings.Contains(string(shell), `class="app-main portal-page"`) {
		t.Error("the shell's content area does not carry the marker the scale is scoped to")
	}

	sheet, err := StaticFS.ReadFile("static/css/vpn.css")
	if err != nil {
		t.Fatalf("read vpn.css: %v", err)
	}
	css := string(sheet)
	large := portalCSSRule(css, ".portal-page .btn")
	if large == "" {
		t.Fatal("vpn.css has no .portal-page .btn rule")
	}
	if !strings.Contains(large, "min-height: calc(var(--space-xl) + var(--space-sm))") {
		t.Errorf("the page-level step is not the sum of the two tokens:\n%s", large)
	}
	if !strings.Contains(large, "padding-block: 0") {
		t.Errorf("the page-level step keeps a vertical padding, so content decides the height:\n%s", large)
	}
	small := portalCSSRule(css, ".portal-page .btn-sm")
	if small == "" || !strings.Contains(small, "min-height: var(--space-xl)") {
		t.Errorf("the compact step is not the 32px token:\n%s", small)
	}
	icon := portalCSSRule(css, ".portal-page .btn-icon")
	if icon == "" || !strings.Contains(icon, "height: var(--space-xl)") || !strings.Contains(icon, "min-height: var(--space-xl)") {
		t.Errorf("an icon-only control is not the compact step, or is not square:\n%s", icon)
	}
	// The interactive target the VPN health surface is tested for is named, so a
	// control that must keep it cannot be shrunk by the scale instead.
	for _, selector := range []string{".portal-page .vpn-diag-entry", ".portal-page .vpn-issue-action", ".portal-page .vpn-windows .btn"} {
		if !strings.Contains(css, selector) {
			t.Errorf("the 44px interactive target is not preserved in the scale for %s", selector)
		}
	}
	if !strings.Contains(css, "min-block-size: 44px") {
		t.Error("the 44px interactive target is no longer declared")
	}
}

// portalCSSRule returns the declaration block that follows the first occurrence
// of selector, or "" when the sheet has no such rule.
func portalCSSRule(css, selector string) string {
	i := strings.Index(css, selector+" {")
	if i < 0 {
		return ""
	}
	open := i + len(selector) + 2
	end := strings.Index(css[open:], "}")
	if end < 0 {
		return ""
	}
	return css[open : open+end]
}

// portalDeclarations returns the declarations of the first rule whose selector
// list contains selector exactly, or "" when the sheet has no such rule. Unlike
// portalCSSRule this copes with a grouped selector list, which is how the
// component steps are declared, and it drops comments first so a rule preceded by
// one is still found by its selector.
func portalDeclarations(css, selector string) string {
	for _, rule := range strings.Split(stripCSSComments(css), "}") {
		open := strings.Index(rule, "{")
		if open < 0 {
			continue
		}
		for _, candidate := range strings.Split(rule[:open], ",") {
			if strings.TrimSpace(candidate) == selector {
				return rule[open+1:]
			}
		}
	}
	return ""
}

// stripCSSComments removes /* ... */ blocks, so a selector is matched against its
// own text rather than against the tail of the comment above it. The web package
// already ships that helper for the settings stylesheet tests; this file uses it
// rather than declaring a second one.

// TestPortalComponentControlsUseTheScaleSteps covers the controls that are not in
// the .btn family: a tab, a chip, a table page control, the search field's clear
// affordance and a dialog's close button are pressed too, and each of them used
// to set its own padding or its own height. The steps are read from the sheet, so
// a rule that drifts off a step is reported here rather than only in a browser.
func TestPortalComponentControlsUseTheScaleSteps(t *testing.T) {
	sheet, err := StaticFS.ReadFile("static/css/vpn.css")
	if err != nil {
		t.Fatalf("read vpn.css: %v", err)
	}
	css := string(sheet)

	largeStep := "min-height: calc(var(--space-xl) + var(--space-sm))"
	compactFloor := []string{".portal-page .tab", ".portal-page .config-tab", ".portal-page .filter-chip"}
	compactFixed := []string{".portal-page .modal-close", ".portal-page .page-btn"}

	if decls := portalDeclarations(css, ".portal-page .nav-tab"); !strings.Contains(decls, largeStep) || !strings.Contains(decls, "padding-block: 0") {
		t.Errorf("the page-level tab bar is not on the large step:\n%s", decls)
	}
	for _, selector := range compactFloor {
		decls := portalDeclarations(css, selector)
		if !strings.Contains(decls, "min-height: var(--space-xl)") || !strings.Contains(decls, "padding-block: 0") {
			t.Errorf("%s is not on the compact step:\n%s", selector, decls)
		}
	}
	for _, selector := range compactFixed {
		decls := portalDeclarations(css, selector)
		if !strings.Contains(decls, "height: var(--space-xl)") || !strings.Contains(decls, "min-height: var(--space-xl)") {
			t.Errorf("%s states its own height and is not on the compact step:\n%s", selector, decls)
		}
	}

	// The clear affordance is inset in the search field: the step alone would push a
	// 32px control past the field's lower edge, so its own centring has to be part of
	// the rule.
	clear := portalDeclarations(css, ".portal-page .table-search-clear")
	for _, want := range []string{"width: var(--space-xl)", "height: var(--space-xl)", "min-height: var(--space-xl)", "inset-block-start: 50%", "translate: 0 -50%", "inset-inline-end"} {
		if !strings.Contains(clear, want) {
			t.Errorf("the search clear affordance is missing %q, so it does not stay inside its field:\n%s", want, clear)
		}
	}
}

// TestPortalComponentControlsDoNotSizeThemselvesInline is the same guard as
// TestPortalPagesDoNotSizeControlsInline for the components that are not in the
// .btn family: an inline height or vertical padding on one of them outranks the
// scale in exactly the same way.
func TestPortalComponentControlsDoNotSizeThemselvesInline(t *testing.T) {
	components := []string{"nav-tab", "tab", "config-tab", "filter-chip", "page-btn", "modal-close", "table-search-clear"}
	blocked := []string{"padding", "height", "font-size", "line-height"}
	for _, page := range portalPages {
		t.Run(page.Template, func(t *testing.T) {
			doc, err := html.Parse(strings.NewReader(renderPortalPage(t, page.Template)))
			if err != nil {
				t.Fatalf("parse rendered %s: %v", page.Template, err)
			}
			portalWalk(doc, func(n *html.Node) {
				if !insidePortalPage(n) {
					return
				}
				matched := ""
				for _, component := range components {
					if portalHasClass(n, component) {
						matched = component
					}
				}
				if matched == "" {
					return
				}
				style := portalAttr(n, "style")
				for _, property := range blocked {
					if strings.Contains(style, property) {
						t.Errorf("%s control sizes itself inline (%s): %s %q", matched, property, style, portalText(n))
					}
				}
			})
		})
	}
}

// TestPortalNamedInteractiveTargetsKeepFortyFour pins the exceptions: the VPN
// health surface's controls and its two disclosure summaries carry the 44px
// interactive target an acceptance test requires. They are named in one rule, and
// none of them may also appear in a rule that states a 32 or 40 px height, which
// would shrink the target back.
func TestPortalNamedInteractiveTargetsKeepFortyFour(t *testing.T) {
	sheet, err := StaticFS.ReadFile("static/css/vpn.css")
	if err != nil {
		t.Fatalf("read vpn.css: %v", err)
	}
	css := string(sheet)

	named := []string{
		".portal-page .vpn-diag-entry",
		".portal-page .vpn-issue-action",
		".portal-page .vpn-windows .btn",
		".portal-page .vpn-config > summary",
		".portal-page .vpn-diag-fold > summary",
	}
	for _, selector := range named {
		decls := portalDeclarations(css, selector)
		if !strings.Contains(decls, "min-block-size: 44px") {
			t.Errorf("%s does not state the 44px interactive target:\n%s", selector, decls)
		}
	}

	// A selector named above must not also be scaled: that is how an exception
	// silently stops being one.
	for _, rule := range strings.Split(css, "}") {
		open := strings.Index(rule, "{")
		if open < 0 {
			continue
		}
		decls := rule[open+1:]
		scales := strings.Contains(decls, "min-height: var(--space-xl)") ||
			strings.Contains(decls, "min-height: calc(var(--space-xl) + var(--space-sm))")
		if !scales {
			continue
		}
		for _, selector := range named {
			for _, candidate := range strings.Split(rule[:open], ",") {
				if strings.TrimSpace(candidate) == selector {
					t.Errorf("%s is also given a scale step, which would shrink the 44px target", selector)
				}
			}
		}
	}
}

// TestPageOwnedDialogsCarryTheMarker pins the scope change: a page's own dialogs
// are rendered from its scripts block, which sits outside <main>. The shell wraps
// that block in the same marker, so the page scale reaches those dialogs. Without
// the marker a dialog's controls keep whatever height the component sheet gives
// them, and nothing in the page's content area shows the difference.
func TestPageOwnedDialogsCarryTheMarker(t *testing.T) {
	shellDialogs := map[string]bool{"langModal": true, "nexusConfirmModal": true}
	seen := 0
	for _, page := range portalPages {
		t.Run(page.Template, func(t *testing.T) {
			doc, err := html.Parse(strings.NewReader(renderPortalPage(t, page.Template)))
			if err != nil {
				t.Fatalf("parse rendered %s: %v", page.Template, err)
			}
			portalWalk(doc, func(n *html.Node) {
				if !portalHasClass(n, "modal-backdrop") {
					return
				}
				if shellDialogs[portalAttr(n, "id")] || inShell(n) {
					return
				}
				seen++
				if !insidePortalPage(n) {
					t.Errorf("%s renders the %q dialog outside the page marker, so the scale cannot reach its controls",
						page.Template, portalAttr(n, "id"))
				}
			})
		})
	}
	// A check that found no page-owned dialog would pass while proving nothing.
	if seen == 0 {
		t.Fatal("no page-owned dialog was found in any rendered page; the check covers nothing")
	}
}

// TestPortalOffScaleExceptionsAreNamed pins the controls that stay off the two
// steps. Each one is a pressed control that cannot take a step without breaking the
// row, the line or the track it lives in, so it keeps its own geometry and states
// why. None of them may also be given a step, which is how an exception silently
// stops being one.
func TestPortalOffScaleExceptionsAreNamed(t *testing.T) {
	sheet, err := StaticFS.ReadFile("static/css/vpn.css")
	if err != nil {
		t.Fatalf("read vpn.css: %v", err)
	}
	css := string(sheet)

	exceptions := []struct {
		selector string
		wants    []string
		reason   string
	}{
		{".portal-page .data-table th.sortable", []string{"height: auto"}, "a header cell's height is the row's"},
		{".portal-page .switch", []string{"width: 44px", "height: 24px"}, "a toggle track has track geometry"},
		{".portal-page .client-meta > span[onclick]", []string{"min-height: 0"}, "a script-generated count action is text in a line"},
		{".portal-page .cell-detail-toggle", []string{"min-height: 0"}, "a flow disclosure is text in a table cell"},
	}

	for _, exception := range exceptions {
		decls := portalDeclarations(css, exception.selector)
		if decls == "" {
			t.Errorf("%s is off the scale with no recorded rule (%s)", exception.selector, exception.reason)
			continue
		}
		for _, want := range exception.wants {
			if !strings.Contains(decls, want) {
				t.Errorf("%s does not state %q, so its geometry is not pinned:\n%s", exception.selector, want, decls)
			}
		}
	}

	for _, rule := range strings.Split(stripCSSComments(css), "}") {
		open := strings.Index(rule, "{")
		if open < 0 {
			continue
		}
		decls := rule[open+1:]
		selectors := strings.Split(rule[:open], ",")
		scales := strings.Contains(decls, "min-height: var(--space-xl)") ||
			strings.Contains(decls, "min-height: calc(var(--space-xl) + var(--space-sm))") ||
			strings.Contains(decls, "height: var(--space-xl)") ||
			strings.Contains(decls, "height: calc(var(--space-xl) + var(--space-sm))")
		if scales {
			for _, exception := range exceptions {
				for _, candidate := range selectors {
					if strings.TrimSpace(candidate) == exception.selector {
						t.Errorf("%s is a recorded exception but is also given a scale step", exception.selector)
					}
				}
			}
			continue
		}
		// The other direction: a rule that removes the floor inside the page scale
		// may only name a recorded exception. Anything else there would silently take
		// a control off the scale while the rule above still claims to set it.
		if !strings.Contains(decls, "min-height: 0") {
			continue
		}
		inPageScale := false
		for _, candidate := range selectors {
			if strings.HasPrefix(strings.TrimSpace(candidate), ".portal-page") {
				inPageScale = true
			}
		}
		if !inPageScale {
			continue
		}
		for _, candidate := range selectors {
			trimmed := strings.TrimSpace(candidate)
			recorded := false
			for _, exception := range exceptions {
				if trimmed == exception.selector {
					recorded = true
				}
			}
			if !recorded {
				t.Errorf("%s removes the height floor inside the page scale but is not a recorded exception", trimmed)
			}
		}
	}
}

// tokenValue returns a custom property's value from a :root block.
func tokenValue(t *testing.T, css, name string) string {
	t.Helper()
	_, after, found := strings.Cut(css, "--"+name+":")
	if !found {
		t.Fatalf("tokens.css does not define --%s", name)
	}
	value, _, found := strings.Cut(after, ";")
	if !found {
		t.Fatalf("--%s has no terminating semicolon", name)
	}
	return strings.TrimSpace(value)
}
