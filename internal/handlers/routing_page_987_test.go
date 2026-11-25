package handlers

// Contract for the Routing page (#987): the policy surface that used to be a
// Settings section renders at GET /routing, reached from the sidebar, with every
// hook it had, in the reading order the design settled, and with nothing left
// behind on the Settings page that the move should have taken with it.
//
// The assertions parse the HTML an administrator actually receives, so they
// describe the document rather than the template source. The behaviour of the
// readouts themselves is covered where it already was (web/policy_*_ui_test.go),
// against the same partials, which this move did not rewrite.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// renderRoutingPageFor renders /routing for the supplied role through the real
// page handler, with the handler fixture's database.
func renderRoutingPageFor(t *testing.T, h *Handlers, role models.UserRole) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/routing", nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "user-1",
		Username: string(role),
		Role:     role,
	})
	ctx = middleware.WithCSRFToken(ctx, "csrf-test-token")
	w := httptest.NewRecorder()
	h.RoutingPageHandler(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /routing as %s = %d, want 200", role, w.Code)
	}
	return w.Body.String()
}

// renderRoutingPage renders /routing for the supplied role.
func renderRoutingPage(t *testing.T, role models.UserRole) string {
	t.Helper()
	h, _, _ := setupTestHandlers(t)
	return renderRoutingPageFor(t, h, role)
}

// routingSurfaceIDs is every hook the move had to carry, taken from the design
// contract's element matrix. A renamed id breaks a controller, a focus target or
// a test that names it, so the list is asserted against the rendered page rather
// than trusted.
var routingSurfaceIDs = []string{
	// The card, its badge and its feedback regions.
	"policyRoutingCard", "policyStatusBadge", "policyAlert",
	// The glyph sprite's symbols.
	"policy-glyph-check", "policy-glyph-warning", "policy-glyph-cross", "policy-glyph-info",
	// P1 · Policy status.
	"policyPanelStatus", "policyStatusTitle", "policyStatusAnswer", "policyStatusAnswerIcon",
	"policyStatusAnswerHeadline", "policyStatusAnswerBody", "policyStatusActions",
	"policyStatusActionError", "policyStatusActionSettings", "policySyncState",
	"policyLastSuccess", "policyRuleDetails", "policyRuleCount",
	// P4 · Latest sync error.
	"policyPanelSyncError", "policySyncErrorTitle", "policySyncErrorAnswer",
	"policySyncErrorAnswerIcon", "policySyncErrorAnswerHeadline", "policySyncErrorAnswerBody",
	"policySyncErrorActions", "policySyncNowBtn", "policyErrorDetails", "policyLastError",
	// P2 · Direct-routing address inventory.
	"policyPanelInventory", "policyInventoryTitle", "policyInventoryAnswer",
	"policyInventoryAnswerIcon", "policyInventoryAnswerHeadline", "policyInventoryAnswerBody",
	"policyInventoryActions", "policyInventoryActionStatus", "policyInventoryActionOverride",
	"policyInventoryAge", "policyInventoryLimit", "policyInventoryOverrideStatus",
	"policyInventoryDetails", "policyInventorySource", "policyInventoryPrefixes",
	"policyInventoryRetrieved", "policyInventoryDigestRow", "policyInventoryDigest",
	"policyInventoryNotice",
	// P3 · CDN exclusion set.
	"policyPanelCdn", "policyCdnTitle", "policyCdnAnswer", "policyCdnAnswerIcon",
	"policyCdnAnswerHeadline", "policyCdnAnswerBody", "policyCdnActions",
	"policyCdnActionDiagnosis", "policyCdnNetworksDetails", "policyCdnDisclosureLabel",
	"policyCdnSource", "policyCdnCount", "policyCdnEntries", "policyCdnNotice",
	// The configuration form.
	"policyRoutingForm", "policy_enabled", "policyDirectEgressNotice",
	"policyProxyExceptionsLabel", "policy_proxy_exceptions", "policyProxyExceptionsHint",
	"policyLegacyNotice", "policy_inventory_override", "policy_sync_interval",
	"policySaveBtn", "policySaveBtnText", "policySaveSpinner", "policySyncBtn",
	"policySyncBtnText", "policySyncSpinner", "policySyncUnavailableHint",
	// The per-client diagnosis card.
	"policyClientCard", "policyClientTitle", "policyClientRefreshBtn", "policyClientRefreshText",
	"policyClientRefreshSpinner", "policyClientAlert", "policyClientSelect",
	"policyClientSelectHint", "policyClientDiagnoseBtn", "policyClientDiagnoseText",
	"policyClientDiagnoseSpinner", "policyClientStatus", "policyClientResult",
	"policyClientSessionValue", "policyClientStateValue", "policyClientGenerationValue",
	"policyClientEvaluatedValue", "policyClientDestinationFilter", "policyClientFilterHint",
	"policyClientFilterFoot", "policyClientFlowsLabel", "policyClientFlowRows",
	"policyClientFlowFoot", "policyClientNotCovered", "policyClientLimitations",
	"policyClientDropsLabel", "policyClientDropRows", "policyClientDropFoot",
	"policyClientDropCoverage",
}

// documentOrder returns the byte offsets of each id's first occurrence, which is
// enough to state the order blocks render in without relying on nesting: the
// contract settles the reading order, not only the presence.
func documentOrder(t *testing.T, body string, ids ...string) []int {
	t.Helper()
	out := make([]int, len(ids))
	for i, id := range ids {
		at := strings.Index(body, `id="`+id+`"`)
		if at < 0 {
			t.Fatalf("the page does not render #%s", id)
		}
		out[i] = at
	}
	return out
}

// TestRoutingPageRendersTheWholePolicySurface pins the move: every hook the
// contract lists renders here, exactly once, and the Settings page keeps none of
// them. A copied rather than moved surface shows up as a duplicate id in the
// first half and a leftover in the second.
func TestRoutingPageRendersTheWholePolicySurface(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)

	for _, id := range routingSurfaceIDs {
		if got := strings.Count(body, `id="`+id+`"`); got != 1 {
			t.Errorf("#%s renders %d times on /routing, want exactly 1", id, got)
		}
	}

	doc := parseSettingsDocument(t, body)
	seen := map[string]int{}
	walkLive(doc, func(n *html.Node) {
		if id, ok := attr(n, "id"); ok {
			seen[id]++
		}
	})
	for id, count := range seen {
		if count > 1 {
			t.Errorf("id %q appears %d times in the rendered document", id, count)
		}
	}
}

// TestRoutingPageReadsInTheSettledOrder pins the order the design contract settles:
// the state a reader needs first, then the configuration that changes it, then the
// per-client evidence. Reading order is DOM order, so it is asserted on the
// document rather than explained in a comment.
func TestRoutingPageReadsInTheSettledOrder(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)

	blocks := []string{
		"policyRoutingCard",    // 2 · the card, its header and its feedback region
		"policyPanelStatus",    // 3 · is split egress active?
		"policyPanelSyncError", // 4 · did the last sync fail?
		"policyPanelInventory", // 5 · is the shipped list current?
		"policyPanelCdn",       // 6 · can a CDN stay on the proxy path?
		"policyRoutingForm",    // 7 · the controls, after the answers
		"policyClientCard",     // 8 · per-client diagnosis
	}
	at := documentOrder(t, body, blocks...)
	for i := 1; i < len(at); i++ {
		if at[i] <= at[i-1] {
			t.Errorf("%s renders before %s; the page no longer reads in the settled order", blocks[i], blocks[i-1])
		}
	}

	// The persistent feedback region sits under the card header and above the first
	// readout: a result that arrives while the operator reads is not pushed to the
	// bottom of a long page.
	feedback := documentOrder(t, body, "policyRoutingCard", "policyAlert", "policyPanelStatus")
	if !(feedback[0] < feedback[1] && feedback[1] < feedback[2]) {
		t.Errorf("the feedback region is not between the card header and the first readout: %v", feedback)
	}
}

// TestRoutingPageHeadingLevels pins the promoted outline: one h1 names the page,
// each card is an h2 and each named sub-area inside a card is an h3. A card title
// left at the level it had inside a Settings group would sit beside its own page
// heading.
func TestRoutingPageHeadingLevels(t *testing.T) {
	doc := parseSettingsDocument(t, renderRoutingPage(t, models.RoleAdmin))

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
		t.Fatalf("the routing page has %d h1 elements, want exactly 1 (outline: %v)", h1, levels)
	}
	prev := 0
	for i, l := range levels {
		if l > prev+1 {
			t.Errorf("heading %q is h%d after h%d: the outline skips a level", names[i], l, prev)
		}
		prev = l
	}

	for _, id := range []string{"policyRoutingCard", "policyClientCard"} {
		card := elementByID(doc, id)
		if card == nil {
			t.Fatalf("#%s is missing", id)
		}
		heading := nearestDescendantWithClass(card, "card-title")
		if heading == nil {
			t.Errorf("#%s has no card title", id)
			continue
		}
		if heading.Data != "h2" {
			t.Errorf("%s card title is a <%s>, want h2 under the page's h1", id, heading.Data)
		}
	}
	for _, id := range []string{"policyStatusTitle", "policySyncErrorTitle", "policyInventoryTitle", "policyCdnTitle",
		"policyClientFlowsLabel", "policyClientDropsLabel"} {
		n := elementByID(doc, id)
		if n == nil {
			t.Errorf("#%s is missing", id)
			continue
		}
		if n.Data != "h3" {
			t.Errorf("#%s is a <%s>, want h3 one level below its card's h2", id, n.Data)
		}
	}
}

// nearestDescendantWithClass returns the first descendant element of n carrying
// class, in document order.
func nearestDescendantWithClass(n *html.Node, class string) *html.Node {
	var found *html.Node
	walkLive(n, func(c *html.Node) {
		if found == nil && c != n && hasClass(c, class) {
			found = c
		}
	})
	return found
}

// TestRoutingPageLoadsItsControllersOnceAndInOrder pins the asset half of the
// move: the save model loads before the controller that reports through it, the
// panels renderer before the controller that drives it, the diagnosis filter
// before the diagnosis controller, and none of them twice. The Settings page
// orchestrator is not part of this page.
func TestRoutingPageLoadsItsControllersOnceAndInOrder(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)
	scripts := collectShellLinks(t, body).scripts

	position := map[string]int{}
	for i, src := range scripts {
		path, _, _ := strings.Cut(src, "?")
		if _, seen := position[path]; seen {
			t.Errorf("%s is loaded %d times; one script may not be instantiated twice", path, 2)
		}
		position[path] = i
	}

	for _, need := range []string{
		"/static/js/settings_cards.js",
		"/static/js/policy_panels.js",
		"/static/js/policy_routing.js",
		"/static/js/policy_client_diag_filter.js",
		"/static/js/policy_client_diag.js",
	} {
		if _, ok := position[need]; !ok {
			t.Errorf("/routing does not load %s", need)
		}
	}
	before := func(first, second string) {
		a, okA := position[first]
		b, okB := position[second]
		if okA && okB && a > b {
			t.Errorf("%s loads after %s; the module it calls is not available when it runs", first, second)
		}
	}
	before("/static/js/settings_cards.js", "/static/js/policy_panels.js")
	before("/static/js/settings_cards.js", "/static/js/policy_routing.js")
	before("/static/js/policy_panels.js", "/static/js/policy_routing.js")
	before("/static/js/policy_client_diag_filter.js", "/static/js/policy_client_diag.js")

	for _, notHere := range []string{
		"/static/js/settings_nav.js", "/static/js/settings_save.js", "/static/js/settings.js",
		"/static/js/notifications_settings.js", "/static/js/gigahost_setup.js",
	} {
		if _, ok := position[notHere]; ok {
			t.Errorf("/routing loads %s, which belongs to the Settings page's own work", notHere)
		}
	}
}

// TestRoutingPageTitleAndHeadingUseTheNavigationLabel pins the one new key: the
// browser title and the page heading name the page the way the sidebar does, so a
// reader who arrives by either route sees the same word.
func TestRoutingPageTitleAndHeadingUseTheNavigationLabel(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)
	label := englishTranslation(t, "nav_routing")

	doc := parseSettingsDocument(t, body)
	title := ""
	walkLive(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			title = textOf(n)
		}
	})
	if !strings.Contains(title, label) {
		t.Errorf("the browser title is %q, want it to name the page %q", title, label)
	}
	h1 := ""
	walkLive(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "h1" {
			h1 = textOf(n)
		}
	})
	if h1 != label {
		t.Errorf("the page heading reads %q, want the navigation label %q", h1, label)
	}
}

// TestRoutingPageProxyFieldKeepsItsAccessibleName carries the accessible-name
// assertion for the PROXY field over from the Settings page test it used to live
// in: the field is named by the visible legend, not by nothing.
func TestRoutingPageProxyFieldKeepsItsAccessibleName(t *testing.T) {
	doc := parseSettingsDocument(t, renderRoutingPage(t, models.RoleAdmin))

	exceptions := elementByID(doc, "policy_proxy_exceptions")
	if exceptions == nil {
		t.Fatal("the policy exceptions textarea is missing from the routing page")
	}
	if name := referencedName(doc, exceptions); name == "" {
		t.Errorf("the policy exceptions textarea has no accessible name (attrs: %v)", exceptions.Attr)
	}
	if by, _ := attr(exceptions, "aria-labelledby"); by != "policyProxyExceptionsLabel" {
		t.Errorf("the exceptions textarea is labelled by %q, want the visible legend", by)
	}
}

// TestRoutingCardsAreFragmentTargets covers the destination half of the old
// bookmark handoff: /settings#policyRoutingCard and /settings#policyClientCard are
// forwarded here, and a fragment only lands usefully on an element the browser can
// also focus. Both cards therefore carry tabindex="-1", and the stylesheet keeps
// their top edge clear of the sticky bar a phone renders.
func TestRoutingCardsAreFragmentTargets(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)
	doc := parseSettingsDocument(t, body)

	for _, id := range []string{"policyRoutingCard", "policyClientCard"} {
		card := elementByID(doc, id)
		if card == nil {
			t.Fatalf("#%s is missing", id)
		}
		if tabindex, _ := attr(card, "tabindex"); tabindex != "-1" {
			t.Errorf("#%s has tabindex=%q, so a fragment lands without moving focus", id, tabindex)
		}
	}
	for _, selector := range []string{"#policyRoutingCard,", "#policyClientCard {"} {
		if !strings.Contains(body, selector) {
			t.Errorf("the card stylesheet no longer carries the fragment-target rule (%q)", selector)
		}
	}
	if !strings.Contains(body, "scroll-margin-top: 76px;") {
		t.Error("the fragment targets lost their scroll margin, so a phone's sticky bar covers the card heading")
	}
}

// TestRoutingSurfaceRendersOnlyForAdministrators pins the markup half of the role
// matrix: the partials are admin-gated, so a page rendered for another role carries
// no policy card, no policy id and no policy controller. The route refuses those
// roles before the handler runs (internal/router), and this proves the markup does
// not depend on that alone.
func TestRoutingSurfaceRendersOnlyForAdministrators(t *testing.T) {
	for _, role := range []models.UserRole{models.RoleSupport, models.RoleUser} {
		t.Run(string(role), func(t *testing.T) {
			body := renderRoutingPage(t, role)
			for _, absent := range []string{
				`id="policyRoutingCard"`, `id="policyClientCard"`,
				`id="policyRoutingForm"`, "static/js/policy_routing.js",
				"static/js/policy_panels.js",
			} {
				if strings.Contains(body, absent) {
					t.Errorf("%s received the admin-only policy surface (%q)", role, absent)
				}
			}
		})
	}
}

// TestSettingsPageKeepsOnlyItsThreeGroups pins the other side of the move: the page
// an administrator receives renders Portal, Notifications and System, and nothing of
// the policy surface. A leftover include, asset load or group would show here.
func TestSettingsPageKeepsOnlyItsThreeGroups(t *testing.T) {
	body := renderSettingsPage(t, models.RoleAdmin)

	for _, gone := range []string{
		`id="group-network"`, `id="group-network-title"`, `href="#group-network"`,
		`id="policyRoutingCard"`, `id="policyClientCard"`, `id="policyRoutingForm"`,
		`id="policyPanelStatus"`, `id="policyClientTitle"`,
		"static/js/policy_routing.js", "static/js/policy_panels.js",
		"static/js/policy_client_diag.js", "static/js/policy_client_diag_filter.js",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("the Settings page still carries %q after the move", gone)
		}
	}

	doc := parseSettingsDocument(t, body)
	var groups []string
	walkLive(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && hasClass(n, "settings-group") {
			id, _ := attr(n, "id")
			groups = append(groups, id)
		}
	})
	want := []string{"group-portal", "group-notifications", "group-system"}
	if !equalStrings(groups, want) {
		t.Errorf("the Settings page renders groups %v, want %v", groups, want)
	}

	// The cards that stayed are still there, so the move took the policy surface and
	// nothing else.
	for _, kept := range []string{
		"appearanceCard", "sslCard", "captchaCard", "limitsCard",
		"telegramCard", "notificationsCard", "upstreamCard", "gigahostCard", "backupCard",
	} {
		if !strings.Contains(body, `id="`+kept+`"`) {
			t.Errorf("the Settings page lost #%s, which the move should not have touched", kept)
		}
	}
}

// TestSidebarRoutingEntry is the navigation half of the role matrix: an admin sees
// a Routing entry after VPN and before Settings, it is current on /routing and not
// on Settings, it is a real anchor, and no other role is offered it.
func TestSidebarRoutingEntry(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	entryOf := func(body string) (*html.Node, int) {
		doc := parseSettingsDocument(t, body)
		var found *html.Node
		at := -1
		index := 0
		walkLive(doc, func(n *html.Node) {
			index++
			if n.Type != html.ElementNode || n.Data != "a" {
				return
			}
			if href, _ := attr(n, "href"); href == "/routing" {
				if found == nil {
					found = n
					at = index
				}
			}
		})
		return found, at
	}
	orderOf := func(body, href string) int {
		doc := parseSettingsDocument(t, body)
		index := 0
		at := -1
		walkLive(doc, func(n *html.Node) {
			index++
			if at >= 0 || n.Type != html.ElementNode || n.Data != "a" {
				return
			}
			if got, _ := attr(n, "href"); got == href {
				at = index
			}
		})
		return at
	}

	routingBody := renderRoutingPageFor(t, h, models.RoleAdmin)
	settingsBody := renderSettingsPageFor(t, h, models.RoleAdmin)
	supportBody := renderRoutingPageFor(t, h, models.RoleSupport)
	userBody := renderRoutingPageFor(t, h, models.RoleUser)

	t.Run("current on its own page", func(t *testing.T) {
		entry, _ := entryOf(routingBody)
		if entry == nil {
			t.Fatal("the admin sidebar has no Routing entry on /routing")
		}
		if !hasClass(entry, "sidebar-nav-link") || !hasClass(entry, "nav-link") {
			t.Errorf("the entry carries class %q, want the sidebar link classes",
				mustAttr(entry, "class"))
		}
		if !hasClass(entry, "active") {
			t.Error("the Routing entry is not marked current on /routing")
		}
		if current, _ := attr(entry, "aria-current"); current != "page" {
			t.Errorf("the Routing entry carries aria-current=%q, want \"page\"", current)
		}
		if label := textOf(entry); label != englishTranslation(t, "nav_routing") {
			t.Errorf("the entry reads %q, want the navigation label", label)
		}
		icon := nearestDescendantWithClass(entry, "nav-icon")
		if icon == nil {
			t.Error("the entry has no .nav-icon")
		}
		if svg := nearestDescendantWithClass(entry, "icon"); svg == nil || !strings.Contains(renderNode(svg), "#icon-globe") {
			t.Error("the entry does not use the globe icon")
		}
	})

	t.Run("present but not current on another page", func(t *testing.T) {
		entry, _ := entryOf(settingsBody)
		if entry == nil {
			t.Fatal("the admin sidebar has no Routing entry on /settings")
		}
		if hasClass(entry, "active") {
			t.Error("the Routing entry is marked current while the reader is on Settings")
		}
		if _, ok := attr(entry, "aria-current"); ok {
			t.Error("the Routing entry carries aria-current while the reader is on Settings")
		}
	})

	t.Run("peer of VPN, before Settings", func(t *testing.T) {
		vpn := orderOf(routingBody, "/vpn")
		routing := orderOf(routingBody, "/routing")
		settings := orderOf(routingBody, "/settings")
		if vpn < 0 || routing < 0 || settings < 0 {
			t.Fatalf("sidebar entries missing (vpn=%d routing=%d settings=%d)", vpn, routing, settings)
		}
		if !(vpn < routing && routing < settings) {
			t.Errorf("sidebar order is VPN=%d Routing=%d Settings=%d, want VPN then Routing then Settings", vpn, routing, settings)
		}
		// A peer, not a nested item: the entry is a sibling of the VPN link, not a
		// child of it. Nesting would also make one hover state cover both.
		doc := parseSettingsDocument(t, routingBody)
		vpnLink := findAnchor(doc, "/vpn")
		routingLink := findAnchor(doc, "/routing")
		if vpnLink != nil && routingLink != nil {
			for p := routingLink.Parent; p != nil; p = p.Parent {
				if p == vpnLink {
					t.Error("the Routing entry is nested inside the VPN entry")
					break
				}
			}
		}
	})

	t.Run("no VPN highlight on the routing page", func(t *testing.T) {
		doc := parseSettingsDocument(t, routingBody)
		vpnLink := findAnchor(doc, "/vpn")
		if vpnLink == nil {
			t.Fatal("the admin sidebar has no VPN entry")
		}
		if hasClass(vpnLink, "active") {
			t.Error("the VPN entry is marked current on /routing")
		}
	})

	t.Run("absent for the other roles", func(t *testing.T) {
		for role, body := range map[string]string{"support": supportBody, "user": userBody} {
			if entry, _ := entryOf(body); entry != nil {
				t.Errorf("%s is offered the Routing entry, which they cannot open", role)
			}
		}
	})
}

// mustAttr returns an attribute's value or "" for messages.
func mustAttr(n *html.Node, key string) string {
	v, _ := attr(n, key)
	return v
}

// findAnchor returns the first anchor whose href is exactly href.
func findAnchor(doc *html.Node, href string) *html.Node {
	var found *html.Node
	walkLive(doc, func(n *html.Node) {
		if found != nil || n.Type != html.ElementNode || n.Data != "a" {
			return
		}
		if got, _ := attr(n, "href"); got == href {
			found = n
		}
	})
	return found
}

// renderNode renders a single node back to text, for assertions about its markup.
func renderNode(n *html.Node) string {
	var b strings.Builder
	if err := html.Render(&b, n); err != nil {
		return ""
	}
	return b.String()
}

// TestClosedMobileDrawerIsNotAFocusStop covers the other half of adding a link to
// the drawer: below 1024px the sidebar is moved off screen with a transform, which
// leaves its links in the tab order. The shell makes the closed drawer inert from
// the drawer's own lifecycle and clears it on open or on a desktop width.
func TestClosedMobileDrawerIsNotAFocusStop(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)
	shell := renderSettingsPage(t, models.RoleAdmin)
	for name, page := range map[string]string{"routing": body, "settings": shell} {
		if !strings.Contains(page, "window.syncDrawerInert") {
			t.Errorf("%s does not define the drawer inert lifecycle", name)
		}
		if !strings.Contains(page, "sidebar.setAttribute('inert', '')") {
			t.Errorf("%s never marks the closed drawer inert, so an offscreen link stays tabbable", name)
		}
		if !strings.Contains(page, "sidebar.removeAttribute('inert')") {
			t.Errorf("%s never clears the inert state, so the opened drawer would be unusable", name)
		}
		// The state is decided by the layout width and the drawer's own open state,
		// never by a second controller.
		if !strings.Contains(page, "window.innerWidth < 1024 && !sidebar.classList.contains('drawer-open')") {
			t.Errorf("%s decides the inert state from something other than the drawer lifecycle", name)
		}
	}
}

// TestActiveNavMatchingStopsAtAPathSegment pins the enhancement's boundary: /routing
// is not a prefix of another page, and a link is not painted current because some
// unrelated path merely starts with it.
func TestActiveNavMatchingStopsAtAPathSegment(t *testing.T) {
	body := renderRoutingPage(t, models.RoleAdmin)
	if !strings.Contains(body, "path.startsWith(base + '/')") {
		t.Error("the active-link enhancement matches raw prefixes, so an unrelated page can be painted current")
	}
	if strings.Contains(body, "path.startsWith(href)) link.classList.add('active')") {
		t.Error("the raw prefix match is still present")
	}
}
