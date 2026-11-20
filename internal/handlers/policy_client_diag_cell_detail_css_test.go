package handlers

// The flows table's cell disclosure is only discoverable because the stylesheet
// draws it: an unstyled opener reads as ordinary cell text, which is what the
// review found before this rule existed. These assertions sit on the stylesheet the
// same way TestSettingsGridStylesheetRule does - read the shipped CSS and inspect
// the declarations - so a rule deleted, emptied or reduced to a colour in a later
// tidy fails here instead of shipping an affordance nobody can see.

import (
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/web"
)

func TestPolicyClientDiagCellDetailStyles(t *testing.T) {
	raw, err := web.StaticFS.ReadFile("static/css/settings.css")
	if err != nil {
		t.Fatalf("read settings.css: %v", err)
	}
	css := string(raw)

	toggle, _ := cssRule(css, ".settings-section-card .cell-detail-toggle", 0)
	if toggle == "" {
		t.Fatal("settings.css no longer defines .settings-section-card .cell-detail-toggle, so the " +
			"opener reads as plain cell text " +
			"and nothing tells an operator the cell opens")
	}
	for _, want := range []string{"cursor: pointer", "text-decoration: underline dotted"} {
		if !strings.Contains(toggle, want) {
			t.Errorf(".cell-detail-toggle does not declare %q; that cue is what makes the text look "+
				"actionable:\n%s", want, toggle)
		}
	}
	// The cue must not move the layout: no property that changes the glyph box, the
	// padding or the line height belongs on an inline opener inside a table cell.
	for _, forbidden := range []string{"padding", "border", "font-size", "line-height", "margin", "display"} {
		if declaresPropertyOrLonghand(toggle, forbidden) {
			t.Errorf(".cell-detail-toggle declares %s, which can shift the row height or the column "+
				"width:\n%s", forbidden, toggle)
		}
	}

	detail, _ := cssRule(css, ".settings-section-card .cell-detail", 0)
	if detail == "" {
		t.Fatal("settings.css no longer defines .settings-section-card .cell-detail, so the revealed " +
			"text runs on as ordinary " +
			"cell text instead of reading as a detail block")
	}
	for _, want := range []string{
		"display: block",
		"color: var(--text-secondary)",
		"white-space: normal",
		"overflow-wrap: break-word",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf(".cell-detail does not declare %q:\n%s", want, detail)
		}
	}
	// The revealed text must wrap, not truncate, and must use the token that passes
	// contrast on the table surfaces in both themes.
	// overflow-wrap is the wrapping this rule requires, so only the truncating
	// properties are refused here, matched exactly rather than as overflow's longhands.
	for _, forbidden := range []string{"text-overflow", "overflow", "overflow-x", "overflow-y"} {
		if declaresProperty(detail, forbidden) {
			t.Errorf(".cell-detail declares %s, so the revealed text can be cut off instead of wrapped:\n%s",
				forbidden, detail)
		}
	}
	if strings.Contains(detail, "var(--text-muted)") {
		t.Errorf(".cell-detail uses --text-muted, which does not reach 4.5:1 on the table surfaces "+
			"(2.95:1 dark, 2.56:1 light):\n%s", detail)
	}

	// The collapsed state has to be stated by the author sheet too: the block rule
	// above beats the browser's own [hidden] styling, because an author declaration
	// wins over the user-agent rule. Without this companion a collapsed region keeps
	// display:block and can take space in the table.
	//
	// This names the missing rule; which author declaration actually wins is checked
	// in TestPolicyClientDiagCellDetailAuthorCascade, because a cascade is not a
	// string match. jsdom applies the hidden attribute itself, so a computed-style
	// check here would pass either way - that is why the cascade lives in the web
	// package, where the sheet can be evaluated as a browser evaluates it.
	for _, file := range []string{"static/css/settings.css", "static/css/style.css"} {
		raw, err := web.StaticFS.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		hiddenRule, _ := cssRule(string(raw), ".settings-section-card .cell-detail[hidden]", 0)
		if hiddenRule == "" || !strings.Contains(hiddenRule, "display: none") {
			t.Errorf("%s does not state display: none for .settings-section-card .cell-detail[hidden], "+
				"so a collapsed detail keeps the block layout:\n%q", file, hiddenRule)
		}
	}
}

// declaresProperty reports whether a declaration block declares exactly this
// property.
func declaresProperty(block, prop string) bool {
	for _, declaration := range strings.Split(block, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(declaration), ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == prop {
			return true
		}
	}
	return false
}

// declaresPropertyOrLonghand also matches the property's longhands, so a rule
// cannot slip a layout-affecting value past the guard by spelling it border-bottom.
func declaresPropertyOrLonghand(block, prop string) bool {
	for _, declaration := range strings.Split(block, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(declaration), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == prop || strings.HasPrefix(name, prop+"-") {
			return true
		}
	}
	return false
}
