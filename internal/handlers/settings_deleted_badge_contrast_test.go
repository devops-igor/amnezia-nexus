package handlers

// The DELETED badge is normal text at 12 px (0.75rem in the card rule), so its ink
// has to reach 4.5:1 against the fill it is drawn on. In the dark theme the shared
// danger token measured 4.42:1 on that fill.
//
// The correction is scoped to this one state rather than applied to the shared badge
// class or the shared token, because the same badge is used by other dialogs that
// were never measured. The ink is also this state's own role: the notification
// feedback line and the policy readout answers own the reserved status ink, so
// painting a badge with it would spread that role to a third surface. This test
// therefore asserts four things from the shipped stylesheets: the scoped rule exists
// and uses the state's own token, the ratio it produces is at least 4.5:1 in both
// themes, the shared danger badge is still exactly what it was, and the badge no
// longer reaches for the reserved status ink.
//
// The ratio is computed from the declared values with the WCAG 2 relative-luminance
// formula, and a translucent fill is composited over the card colour first - which is
// the sampling method the design review used (a pixel sampled inside the label
// region).

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/web"
)

// deletedBadgeSelector is the rule scoped to the deleted order-status badge.
const deletedBadgeSelector = `.settings-section-card .gigahost-order-status[data-stage="deleted"] .gigahost-order-status-toggle`

// savedDeletedBadgeSelector is the same state on the saved-setup-approvals surface,
// which draws the state as a plain badge rather than as a progression toggle.
const savedDeletedBadgeSelector = `.settings-section-card .gigahost-order-state .badge[data-stage="deleted"]`

// deletedBadgeInk is the ink role that belongs to the deleted stage alone.
const deletedBadgeInk = "--text-deleted-badge"

func TestDeletedBadgeMeetsContrastInBothThemes(t *testing.T) {
	settingsCSS := readShippedCSS(t, "static/css/settings.css")
	tokensCSS := readShippedCSS(t, "static/css/tokens.css")
	componentsCSS := readShippedCSS(t, "static/css/components.css")

	rule, _ := cssRule(settingsCSS, deletedBadgeSelector, 0)
	if rule == "" {
		t.Fatalf("settings.css no longer scopes a rule to %s", deletedBadgeSelector)
	}
	requireInkOnlyBadgeRule(t, rule, deletedBadgeSelector)

	// The saved setup approvals show the same ended deployment on a second surface. The
	// badge there is the shared .badge-danger, so the fill and the border already come
	// from the shared danger tokens; only the ink is the state's own, and it is the same
	// ink the progression badge uses. Without this rule the saved badge painted the
	// shared danger ink on that fill, which is the pairing measured below.
	savedRule, _ := cssRule(settingsCSS, savedDeletedBadgeSelector, 0)
	if savedRule == "" {
		t.Fatalf("settings.css no longer scopes a rule to %s", savedDeletedBadgeSelector)
	}
	requireInkOnlyBadgeRule(t, savedRule, savedDeletedBadgeSelector)

	dark := cssCustomProperties(tokensCSS, ":root")
	light := cssCustomProperties(tokensCSS, `[data-theme="light"]`)

	// The saved badge's fill is the shared danger fill, which is what the ratio below
	// composites over the card colour. Asserting it here keeps the ratio attached to the
	// surface it describes rather than to the other badge's rule.
	savedBadge, _ := cssRule(componentsCSS, ".badge-danger", 0)
	if !declaresPropertyValue(savedBadge, "background", "var(--danger-bg)") {
		t.Fatalf("the saved deleted badge's fill is not the danger fill the ratio assumes:\n%s", savedBadge)
	}

	assertInkMeetsNormalTextMinimum(t, dark, light, deletedBadgeSelector)
	assertInkMeetsNormalTextMinimum(t, dark, light, savedDeletedBadgeSelector)

	// The shared badge class is untouched: every other consumer still paints --danger
	// on --danger-bg, so this correction cannot restyle another dialog.
	shared, _ := cssRule(componentsCSS, ".badge-danger", 0)
	if !declaresPropertyValue(shared, "color", "var(--danger)") {
		t.Fatalf("the shared .badge-danger ink changed; other dialogs were not measured:\n%s", shared)
	}
	if !declaresPropertyValue(shared, "background", "var(--danger-bg)") {
		t.Fatalf("the shared .badge-danger fill changed; other dialogs were not measured:\n%s", shared)
	}
	if got, want := dark["--danger"], "#f43f5e"; strings.TrimSpace(got) != want {
		t.Fatalf("the shared danger token changed in the dark theme: %q, want %q", got, want)
	}
	if got, want := dark["--danger-bg"], "rgba(244, 63, 94, 0.12)"; strings.TrimSpace(got) != want {
		t.Fatalf("the shared danger fill changed in the dark theme: %q, want %q", got, want)
	}
}

// readShippedCSS reads one shipped stylesheet from the embedded assets.
func readShippedCSS(t *testing.T, path string) string {
	t.Helper()
	raw, err := web.StaticFS.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// requireInkOnlyBadgeRule fails unless the scoped rule paints the state's own ink and
// leaves the fill alone. Changing the fill would take the state out of the shared danger
// family, which is what makes the badge mean "this ended badly" in the first place.
func requireInkOnlyBadgeRule(t *testing.T, rule, selector string) {
	t.Helper()
	if !declaresPropertyValue(rule, "color", "var("+deletedBadgeInk+")") {
		t.Fatalf("%s must use the state's own ink %s:\n%s", selector, deletedBadgeInk, rule)
	}
	if declaresPropertyValue(rule, "color", "var(--text-danger)") {
		t.Fatalf("%s reaches for the reserved status ink again:\n%s", selector, rule)
	}
	if declaresProperty(rule, "background") || declaresProperty(rule, "background-color") {
		t.Fatalf("%s must change only the ink, so the shared fill keeps its meaning:\n%s", selector, rule)
	}
}

// assertInkMeetsNormalTextMinimum checks the state's ink against the composited danger
// fill in both themes, once for each surface that draws it.
func assertInkMeetsNormalTextMinimum(t *testing.T, dark, light map[string]string, surface string) {
	t.Helper()
	for _, theme := range []struct {
		name  string
		token map[string]string
	}{
		{name: "dark", token: dark},
		{name: "light", token: light},
	} {
		card := requireHexToken(t, theme.name, theme.token, "--bg-card")
		fillRGB, fillAlpha := requireRGBAToken(t, theme.name, theme.token, "--danger-bg")
		ink := requireHexToken(t, theme.name, theme.token, deletedBadgeInk)
		fill := compositeOver(fillRGB, fillAlpha, card)
		if ratio := contrastRatio(ink, fill); ratio < 4.5 {
			t.Errorf("the %s badge on %s measures %.2f:1 (ink %s on fill %s), below the 4.5:1 "+
				"normal-text minimum", theme.name, surface, ratio, ink, fill)
		}
	}
}

// declaresPropertyValue reports whether a declaration block assigns prop exactly value.
func declaresPropertyValue(block, prop, value string) bool {
	for _, declaration := range strings.Split(block, ";") {
		name, got, ok := strings.Cut(strings.TrimSpace(declaration), ":")
		if !ok {
			continue
		}
		if strings.TrimSpace(name) == prop && strings.TrimSpace(got) == value {
			return true
		}
	}
	return false
}

// cssCustomProperties reads the custom-property declarations of one block.
func cssCustomProperties(css, selector string) map[string]string {
	block, _ := cssRule(stripCSSComments(css), selector, 0)
	properties := map[string]string{}
	for _, declaration := range strings.Split(block, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(declaration), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.HasPrefix(name, "--") {
			properties[name] = strings.TrimSpace(value)
		}
	}
	return properties
}

// stripCSSComments removes every /* ... */ span, so prose in a block's comments
// is not read as a declaration. A comment that names a ratio carries a colon, and
// the last colon-separated piece of it would otherwise be glued to the property
// that follows, hiding the declaration from the caller.
func stripCSSComments(css string) string {
	for {
		start := strings.Index(css, "/*")
		if start < 0 {
			return css
		}
		end := strings.Index(css[start:], "*/")
		if end < 0 {
			return css[:start]
		}
		css = css[:start] + css[start+end+2:]
	}
}

// requireHexToken returns the hex value of one custom property.
func requireHexToken(t *testing.T, theme string, token map[string]string, name string) string {
	t.Helper()
	value, ok := token[name]
	if !ok {
		t.Fatalf("%s theme declares no %s", theme, name)
	}
	if _, ok := parseHexRGB(value); !ok {
		t.Fatalf("%s theme's %s is not a hex colour: %q", theme, name, value)
	}
	return value
}

// requireRGBAToken returns the components and alpha of one rgba() custom property.
func requireRGBAToken(t *testing.T, theme string, token map[string]string, name string) ([3]float64, float64) {
	t.Helper()
	value, ok := token[name]
	if !ok {
		t.Fatalf("%s theme declares no %s", theme, name)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(strings.ReplaceAll(value, " ", ""), "rgba("), ")")
	parts := strings.Split(inner, ",")
	if len(parts) != 4 {
		t.Fatalf("%s theme's %s is not an rgba() colour: %q", theme, name, value)
	}
	var rgb [3]float64
	for i := 0; i < 3; i++ {
		component, err := strconv.ParseFloat(parts[i], 64)
		if err != nil {
			t.Fatalf("%s theme's %s component %d is not a number: %q", theme, name, i, value)
		}
		rgb[i] = component
	}
	alpha, err := strconv.ParseFloat(parts[3], 64)
	if err != nil {
		t.Fatalf("%s theme's %s alpha is not a number: %q", theme, name, value)
	}
	return rgb, alpha
}

// parseHexRGB parses a #rrggbb colour into its channels.
func parseHexRGB(value string) ([3]float64, bool) {
	var rgb [3]float64
	text := strings.TrimSpace(value)
	if len(text) != 7 || text[0] != '#' {
		return rgb, false
	}
	for i := 0; i < 3; i++ {
		component, err := strconv.ParseInt(text[1+i*2:3+i*2], 16, 64)
		if err != nil {
			return rgb, false
		}
		rgb[i] = float64(component)
	}
	return rgb, true
}

// compositeOver composites a translucent rgb() colour over an opaque hex background
// and returns the resulting opaque hex colour.
func compositeOver(rgb [3]float64, alpha float64, background string) string {
	bg, ok := parseHexRGB(background)
	if !ok {
		return background
	}
	var out [3]float64
	for i := 0; i < 3; i++ {
		out[i] = math.Round(alpha*rgb[i] + (1-alpha)*bg[i])
	}
	return "#" + hexPair(out[0]) + hexPair(out[1]) + hexPair(out[2])
}

// hexPair renders one 0..255 channel as two lowercase hex digits.
func hexPair(value float64) string {
	text := strconv.FormatInt(int64(value), 16)
	if len(text) < 2 {
		return "0" + text
	}
	return text
}

// contrastRatio computes the WCAG 2 contrast ratio between two opaque colours.
func contrastRatio(a, b string) float64 {
	luminanceA, okA := relativeLuminance(a)
	luminanceB, okB := relativeLuminance(b)
	if !okA || !okB {
		return 0
	}
	high, low := math.Max(luminanceA, luminanceB), math.Min(luminanceA, luminanceB)
	return (high + 0.05) / (low + 0.05)
}

// relativeLuminance computes WCAG relative luminance for an opaque hex colour.
func relativeLuminance(hex string) (float64, bool) {
	rgb, ok := parseHexRGB(hex)
	if !ok {
		return 0, false
	}
	return 0.2126*linearChannel(rgb[0]) + 0.7152*linearChannel(rgb[1]) + 0.0722*linearChannel(rgb[2]), true
}

// linearChannel converts one sRGB channel to its linear value.
func linearChannel(value float64) float64 {
	channel := value / 255
	if channel <= 0.04045 {
		return channel / 12.92
	}
	return math.Pow((channel+0.055)/1.055, 2.4)
}
