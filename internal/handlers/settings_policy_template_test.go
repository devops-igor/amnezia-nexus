package handlers

// Template contract for the admin policy routing section (#679).
//
// The section is a partial (web/templates/settings_policy.html) included by
// settings.html. These assertions run the real template engine over the embedded
// templates, so they describe what the browser receives rather than what the
// markup source says:
//
//   - an administrator gets the section, the five list sources, the two actions
//     and the status/counter elements the controller writes;
//   - a support operator, who may open /settings, must not receive it at all
//     (authoritative authorization is still the admin-only API middleware);
//   - the controller asset is loaded only in the admin render, so it cannot act
//     against a page that carries no form;
//   - every translation key the partial uses exists in all five locales and the
//     "Russia outside" source is never offered.
//
// The section intentionally contains no inline script and no inline event
// handler; the only behaviour is web/static/js/policy_routing.js.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/web"
)

// policySectionIDs are the element ids the shipped controller writes to. The
// JSDOM test in web/policy_routing_ui_test.go re-derives this list from the
// module source, so a rename on either side fails there as well.
var policySectionIDs = []string{
	"policyRoutingCard",
	"policyRoutingForm",
	"policyAlert",
	"policyStatusBadge",
	"policy_enabled",
	"policy_proxy_exceptions",
	"policySaveBtn",
	"policySyncBtn",
	"policy_sync_interval",
	// The four readouts (#971). Each panel is a question, an answer inset, its
	// supporting facts and the disclosures that hold the detail.
	"policyPanelStatus",
	"policyStatusTitle",
	"policyStatusAnswer",
	"policyStatusAnswerIcon",
	"policyStatusAnswerHeadline",
	"policyStatusAnswerBody",
	"policyStatusActions",
	"policyStatusActionError",
	"policyStatusActionSettings",
	"policySyncState",
	"policyLastSuccess",
	"policyRuleDetails",
	"policyRuleCount",
	"policyPanelInventory",
	"policyInventoryTitle",
	"policyInventoryAnswer",
	"policyInventoryAnswerIcon",
	"policyInventoryAnswerHeadline",
	"policyInventoryAnswerBody",
	"policyInventoryActions",
	"policyInventoryActionStatus",
	"policyInventoryActionOverride",
	"policyInventoryAge",
	"policyInventoryLimit",
	"policyInventoryOverrideStatus",
	"policyInventoryDetails",
	"policyInventorySource",
	"policyInventoryPrefixes",
	"policyInventoryRetrieved",
	"policyInventoryDigestRow",
	"policyInventoryDigest",
	"policyInventoryNotice",
	"policy_inventory_override",
	"policyPanelCdn",
	"policyCdnTitle",
	"policyCdnAnswer",
	"policyCdnAnswerIcon",
	"policyCdnAnswerHeadline",
	"policyCdnAnswerBody",
	"policyCdnActions",
	"policyCdnActionDiagnosis",
	"policyCdnNetworksDetails",
	"policyCdnSource",
	"policyCdnCount",
	"policyCdnEntries",
	"policyCdnExclusionDetails",
	"policyCdnSourceDetails",
	"policyCdnNotice",
	"policyPanelSyncError",
	"policySyncErrorTitle",
	"policySyncErrorAnswer",
	"policySyncErrorAnswerIcon",
	"policySyncErrorAnswerHeadline",
	"policySyncErrorAnswerBody",
	"policySyncErrorActions",
	"policySyncNowBtn",
	"policyErrorDetails",
	"policyLastError",
	// The in-page action in P3 focuses the diagnosis card's heading, so the
	// target has to exist in the same render.
	"policyClientTitle",
}

// renderSettingsPage renders /settings for the supplied role through the real
// page handler.
func renderSettingsPage(t *testing.T, role models.UserRole) string {
	t.Helper()
	h, _, _ := setupTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "user-1",
		Username: string(role),
		Role:     role,
	})
	ctx = middleware.WithCSRFToken(ctx, "csrf-test-token")
	w := httptest.NewRecorder()
	h.SettingsPageHandler(w, req.WithContext(ctx))

	if w.Code != http.StatusOK {
		t.Fatalf("GET /settings as %s = %d, want 200", role, w.Code)
	}
	return w.Body.String()
}

func TestSettingsTemplatePolicyRoutingSection(t *testing.T) {
	adminBody := renderSettingsPage(t, models.RoleAdmin)

	t.Run("AdminSeesSectionAndControls", func(t *testing.T) {
		for _, id := range policySectionIDs {
			if !strings.Contains(adminBody, `id="`+id+`"`) {
				t.Errorf("admin settings page is missing #%s", id)
			}
		}
		for _, token := range []string{
			`name="policy_enabled"`,
			`name="policy_proxy_exceptions"`,
			`type="submit"`,
			`id="policySaveBtn"`,
			`id="policySyncBtn"`,
		} {
			if !strings.Contains(adminBody, token) {
				t.Errorf("admin settings page is missing %q", token)
			}
		}
	})

	// A visible control must do what it says, so the page offers exactly the two
	// inputs that reach a packet decision and nothing that configures a source.
	t.Run("NoSourceOrDomainControls", func(t *testing.T) {
		for _, removed := range []string{
			`name="policy_preset"`,
			`name="policy_custom_urls"`,
			`name="policy_excluded_domains"`,
			`id="policyActivePreset"`,
			`id="policySourceStats"`,
		} {
			if strings.Contains(adminBody, removed) {
				t.Errorf("admin settings page still renders the removed control %q", removed)
			}
		}
	})

	t.Run("TrafficCountersRemoved", func(t *testing.T) {
		// The owner removed the counters panel from this page (#971). The four
		// readouts that stayed must not render, fetch or translate it, and the
		// retired elements must be gone from the markup rather than hidden.
		for _, removed := range []string{
			`id="policyProxyBytes"`,
			`id="policyDirectBytes"`,
			`id="policyProxyDrops"`,
			`id="policyDirectDrops"`,
			`id="policyCountersTitle"`,
			`policy_counters_title`,
			`policy_counter_proxy_bytes`,
			`policy_counter_direct_bytes`,
			`policy_counter_proxy_drops`,
			`policy_counter_direct_drops`,
		} {
			if strings.Contains(adminBody, removed) {
				t.Errorf("the section still renders the removed traffic counters (%s)", removed)
			}
		}
		for _, asset := range []string{"static/js/policy_routing.js", "static/js/policy_panels.js"} {
			body, err := web.StaticFS.ReadFile(asset)
			if err != nil {
				t.Fatalf("read %s: %v", asset, err)
			}
			for _, removed := range []string{
				"/api/vpn/policy/stats",
				"renderPolicyCounters",
				"policyFormatBytes",
				"policy_counter_proxy_bytes",
			} {
				if strings.Contains(string(body), removed) {
					t.Errorf("%s still carries the removed counters path (%s)", asset, removed)
				}
			}
		}
		// The endpoint itself stays: it is a published API, not a page readout, and
		// removing it would change a contract this delivery is not authorized to
		// touch. The retired keys must be gone from every bundle, though, so no
		// later surface can render a counter label the page no longer explains.
		for _, locale := range []string{"en", "ru", "fr", "zh", "fa"} {
			raw, err := web.TranslationsFS.ReadFile("translations/" + locale + ".json")
			if err != nil {
				t.Fatalf("read %s.json: %v", locale, err)
			}
			var dict map[string]string
			if err := json.Unmarshal(raw, &dict); err != nil {
				t.Fatalf("decode %s.json: %v", locale, err)
			}
			for _, key := range []string{
				"policy_counters_title", "policy_counter_proxy_bytes", "policy_counter_direct_bytes",
				"policy_counter_proxy_drops", "policy_counter_direct_drops",
				"policy_inventory_override_active", "policy_inventory_stale", "policy_inventory_age_value",
			} {
				if _, ok := dict[key]; ok {
					t.Errorf("%s.json still defines %q, whose only consumer was removed", locale, key)
				}
			}
		}
	})

	t.Run("ExplainRemoved", func(t *testing.T) {
		for _, removed := range []string{
			`id="policy_explain_value"`,
			`id="policyExplainBtn"`,
			`id="policyExplainResult"`,
			`id="policyExplainDetail"`,
			"policy_explain_",
		} {
			if strings.Contains(adminBody, removed) {
				t.Errorf("admin settings page still contains removed Explain surface %q", removed)
			}
		}
	})

	t.Run("RussiaOutsideIsNeverOffered", func(t *testing.T) {
		// The backend models no Russian egress, so the UI must not render a source
		// that could not be honoured.
		for _, forbidden := range []string{`value="russia_outside"`, "russia_outside"} {
			if strings.Contains(adminBody, forbidden) {
				t.Errorf("settings page offers the unavailable %q source", forbidden)
			}
		}
	})

	t.Run("ControllerURLIsCacheBusted", func(t *testing.T) {
		// /static/* is served with a 24-hour max-age. The controller must carry an
		// identity query, or a browser keeps the pre-update script and silently
		// omits the newer form fields from the save payload.
		//
		// The identity must follow the delivered bytes, not the release version: this
		// change rewrote the controller without moving the release, so a
		// ?v=<release> URL is exactly the URL the predecessor served and a returning
		// browser would keep the incompatible script.
		const controller = "/static/js/policy_routing.js"
		src := ""
		for _, candidate := range collectShellLinks(t, adminBody).scripts {
			if path, _, _ := strings.Cut(candidate, "?"); path == controller {
				src = candidate
			}
		}
		if src == "" {
			t.Fatalf("admin settings page does not load %s at all", controller)
		}
		if !strings.Contains(src, "?v=") {
			t.Errorf("admin settings page loads %q with no cache identity; a cached script can omit new fields", src)
		}
		if want := controller + "?v=" + deliveredAssetDigest(t, controller); src != want {
			t.Errorf("admin settings page loads %q, want %q so the identity follows the delivered bytes", src, want)
		}
		if src == versionedAssetURL(controller) {
			t.Errorf("admin settings page loads %q, which is the release-version URL the predecessor also "+
				"served; a returning browser keeps the incompatible controller", src)
		}
	})

	t.Run("ControllerLoadedOnlyForAdmins", func(t *testing.T) {
		adminPrefix := fmt.Sprintf(`src="%s?v=`, "/static/js/policy_routing.js")
		if !strings.Contains(adminBody, adminPrefix) {
			t.Errorf("admin settings page does not load the policy controller (%q missing)", adminPrefix)
		}
		supportBody := renderSettingsPage(t, models.RoleSupport)
		if strings.Contains(supportBody, `id="policyRoutingCard"`) {
			t.Error("support operator received the admin-only policy section")
		}
		if strings.Contains(supportBody, adminPrefix) || strings.Contains(supportBody, `src="/static/js/policy_routing.js"`) {
			t.Error("support operator's page loads the policy controller")
		}
	})

	t.Run("CSRFMetaPreserved", func(t *testing.T) {
		if !strings.Contains(adminBody, `name="csrf-token"`) {
			t.Error("settings page lost the csrf-token meta element")
		}
	})

	t.Run("SaveShipsInertUntilTheRecordLoads", func(t *testing.T) {
		// The button is inert in the markup as well as in the controller, so the
		// form's default values cannot be persisted before the stored record has been
		// read, even in the window between parse and DOMContentLoaded.
		tag := regexp.MustCompile(`<button[^>]*id="policySaveBtn"[^>]*>`).FindString(adminBody)
		if tag == "" {
			t.Fatal("admin settings page has no #policySaveBtn")
		}
		if !strings.Contains(tag, " disabled") {
			t.Errorf("the Save button must ship disabled, got %q", tag)
		}
	})

	t.Run("AccessibleControlsAndLiveRegion", func(t *testing.T) {
		// The master toggle is a native checkbox exposed as a switch (the fallback
		// the switch pattern prescribes where the switch attribute is unsupported),
		// its operational notice is programmatically associated, the preset rows are
		// one labelled group, and every result is announced through a live region.
		for _, token := range []string{
			`role="switch"`,
			`aria-describedby="policyDirectEgressNotice"`,
			`id="policyDirectEgressNotice"`,
			`<fieldset `,
			`<legend `,
			`role="status"`,
			`aria-live="polite"`,
		} {
			if !strings.Contains(adminBody, token) {
				t.Errorf("admin settings page is missing %q", token)
			}
		}
		// A <button> accepts phrasing content only, so its spinner must not be a
		// flow-level element.
		for _, id := range []string{"policySaveSpinner", "policySyncSpinner"} {
			if !strings.Contains(adminBody, `<span class="spinner hidden" id="`+id+`"`) {
				t.Errorf("#%s must be a span inside the button, not a div", id)
			}
		}
	})

	t.Run("NoInlineScriptOrHandlerInSection", func(t *testing.T) {
		partial, err := web.TemplatesFS.ReadFile("templates/settings_policy.html")
		if err != nil {
			t.Fatalf("read settings_policy.html: %v", err)
		}
		source := string(partial)
		if strings.Contains(source, "onclick=") || strings.Contains(source, "onchange=") || strings.Contains(source, "onsubmit=") {
			t.Error("policy section must not use inline event handlers")
		}
		// Exactly the external assets, in the order the page needs them: the
		// readouts module is evaluated before the controller that calls it, and
		// neither is an inline body.
		if got := strings.Count(source, "<script"); got != 2 {
			t.Errorf("policy section has %d script tags, want exactly 2 external assets", got)
		}
		if strings.Contains(source, "<script>") {
			t.Error("policy section must not contain an inline script body")
		}
		readouts := strings.Index(source, "policy_panels.js")
		controller := strings.Index(source, "policy_routing.js")
		if readouts < 0 || controller < 0 || readouts > controller {
			t.Errorf("the policy readouts module must load before the controller (readouts at %d, controller at %d)", readouts, controller)
		}
	})
}

// TestPolicySectionTranslationKeysInEveryLocale pins the keys the partial uses
// against the five shipped dictionaries. The javascript part of the section uses
// a few more keys; those are checked by the JSDOM contract test, which fails on a
// key the dictionary does not resolve.
func TestPolicySectionTranslationKeysInEveryLocale(t *testing.T) {
	partial, err := web.TemplatesFS.ReadFile("templates/settings_policy.html")
	if err != nil {
		t.Fatalf("read settings_policy.html: %v", err)
	}

	keys := map[string]bool{}
	for _, chunk := range strings.Split(string(partial), `{{ _ "`)[1:] {
		key := chunk
		if idx := strings.Index(key, `"`); idx >= 0 {
			key = key[:idx]
		}
		if strings.HasPrefix(key, "policy_") {
			keys[key] = true
		}
	}
	if len(keys) < 20 {
		t.Fatalf("found only %d policy translation keys in the partial; the extraction is wrong", len(keys))
	}

	// Keys the two scripts resolve at run time. The JSDOM harness stubs the
	// translator, so it cannot notice a key missing from a dictionary; the keys
	// are read from the shipped modules here rather than copied by hand, which
	// is what kept a renamed readout key in the list after its branch was gone.
	scriptKeyPattern := regexp.MustCompile(`(?:policyText|panelText)\(\s*'([a-z0-9_]+)'`)
	for _, asset := range []string{"static/js/policy_routing.js", "static/js/policy_panels.js"} {
		body, err := web.StaticFS.ReadFile(asset)
		if err != nil {
			t.Fatalf("read %s: %v", asset, err)
		}
		found := 0
		for _, match := range scriptKeyPattern.FindAllStringSubmatch(string(body), -1) {
			keys[match[1]] = true
			found++
		}
		if found < 10 {
			t.Fatalf("%s: found only %d translation keys; the extraction is wrong", asset, found)
		}
	}
	// A pluralised readout composes its key from a base, so the two forms are not
	// literals in the module and have to be named here.
	for _, base := range []string{"policy_days", "policy_inventory_override_count", "policy_cdn_count_answer"} {
		keys[base+"_one"] = true
		keys[base+"_other"] = true
	}

	locales := []string{"en.json", "ru.json", "fr.json", "fa.json", "zh.json"}
	bundles := map[string]map[string]string{}
	for _, locale := range locales {
		raw, err := web.TranslationsFS.ReadFile("translations/" + locale)
		if err != nil {
			t.Fatalf("read %s: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("parse %s: %v", locale, err)
		}
		bundles[locale] = dict
		for key := range keys {
			value, ok := dict[key]
			if !ok {
				t.Errorf("%s is missing key %q used by the policy section", locale, key)
				continue
			}
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s has an empty value for %q", locale, key)
			}
		}
	}

	// Locale parity: the five bundles stay key-for-key identical. A key added to
	// one bundle only renders as its own name to the operators of the other four,
	// and no per-key lookup above notices a key the *other* bundles gained.
	english := bundles["en.json"]
	for _, locale := range locales[1:] {
		dict := bundles[locale]
		for key := range english {
			if _, ok := dict[key]; !ok {
				t.Errorf("%s is missing %q, which en.json defines; the bundles have drifted apart", locale, key)
			}
		}
		for key := range dict {
			if _, ok := english[key]; !ok {
				t.Errorf("%s defines %q, which en.json does not; the bundles have drifted apart", locale, key)
			}
		}
	}

	// The Russian dictionary is the one the task requires explicitly; assert a
	// real translation rather than the English text copied across.
	raw, err := web.TranslationsFS.ReadFile("translations/ru.json")
	if err != nil {
		t.Fatalf("read ru.json: %v", err)
	}
	var ru map[string]string
	if err := json.Unmarshal(raw, &ru); err != nil {
		t.Fatalf("parse ru.json: %v", err)
	}
	if got := ru["policy_title"]; got == "" || got == "Policy Routing (Split Egress)" {
		t.Errorf("ru.json policy_title is not translated: %q", got)
	}
	if got := ru["policy_status_disabled"]; got == "" || got == "Disabled" {
		t.Errorf("ru.json policy_status_disabled is not translated: %q", got)
	}
}

// TestPolicySectionRenderingDoesNotLeakIntoOtherPages guards the include: only
// settings.html renders the section.
func TestPolicySectionRenderingDoesNotLeakIntoOtherPages(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/vpn", nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "admin-1",
		Username: "admin",
		Role:     models.RoleAdmin,
	})
	w := httptest.NewRecorder()
	h.VPNPageHandler(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /vpn = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), fmt.Sprintf(`id="%s"`, "policyRoutingCard")) {
		t.Error("policy section leaked into a page that does not include it")
	}
}

// TestPolicyControlsCarryTheRenamedLabels pins the two renamed control labels and
// the text beside them, because these are operator-facing statements about which
// rule wins: the copy has to agree with the accepted decision order in
// internal/vpn/forwarder/routing_decision.go, not just with itself. The retired
// texts are asserted absent from the dictionaries.
func TestPolicyControlsCarryTheRenamedLabels(t *testing.T) {
	page := renderSettingsPage(t, models.RoleAdmin)
	for _, want := range []string{
		"Always PROXY (IPv4)",
		"Always DIRECT (IPv4)",
		// The PROXY hint states the precedence and its own limit.
		"Addresses on this PROXY list take precedence over the DIRECT list",
		"refused before either list applies",
		// The DIRECT hint names what can supersede a DIRECT listing.
		"Prefixes on this DIRECT list route direct unless",
		"an entry on the PROXY list, a CDN exclusion, or a non-TCP/UDP flow",
		"prohibited, internal and invalid destinations are refused before any list applies",
		"changes apply to new connections only",
		// The notice under both controls names which list it means, and states the
		// same guard and transport limit as the hints rather than a bare promise.
		"A destination on the PROXY list uses PROXY",
		"an allocation match outside the CDN exclusion set uses DIRECT unless",
		"or the flow is not TCP or UDP",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the rendered policy section does not carry %q", want)
		}
	}
	for _, gone := range []string{
		"PROXY exceptions (IPv4)",
		"Address inventory override",
		"Clearing this field changes new routing decisions only",
		// One input deciding everything was the false claim this round removed.
		"shipped allocation set decides everything else",
		"observed through the gateway DNS",
	} {
		if strings.Contains(page, gone) {
			t.Errorf("the rendered policy section still carries the retired text %q", gone)
		}
	}

	// The same four keys exist in all five bundles, the non-English ones are real
	// translations rather than copies, and the retired note is gone everywhere.
	keys := []string{
		"policy_proxy_exceptions_label", "policy_proxy_exceptions_hint",
		"policy_inventory_override_label", "policy_inventory_override_hint",
	}
	var english map[string]string
	for _, locale := range []string{"en", "ru", "fr", "zh", "fa"} {
		raw, err := web.TranslationsFS.ReadFile("translations/" + locale + ".json")
		if err != nil {
			t.Fatalf("read %s.json: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("decode %s.json: %v", locale, err)
		}
		if locale == "en" {
			english = dict
		}
		for _, key := range keys {
			value := strings.TrimSpace(dict[key])
			if value == "" {
				t.Errorf("%s.json has no %q", locale, key)
				continue
			}
			if locale != "en" && value == english[key] {
				t.Errorf("%s.json %q is the English text", locale, key)
			}
		}
		if _, ok := dict["policy_inventory_override_clear_hint"]; ok {
			t.Errorf("%s.json still carries the retired clear-field note", locale)
		}
	}
	if english["policy_proxy_exceptions_label"] != "Always PROXY (IPv4)" ||
		english["policy_inventory_override_label"] != "Always DIRECT (IPv4)" {
		t.Errorf("the English labels are %q / %q, want the renamed controls",
			english["policy_proxy_exceptions_label"], english["policy_inventory_override_label"])
	}
}

// TestPolicyPlaceholderExamplesDoNotImplyAnImpossibleRoute pins the two example
// placeholders. They may be syntax examples or real routable values, but they must
// never be destinations the router refuses on either list: the previous round
// shipped TEST-NET ranges, and ValidateDirectDestination refuses those, so the
// placeholder promised a routing outcome that could never happen. An entry that is
// not an address at all has to match the documented shape instead, so a typo cannot
// pass as a "syntax example".
func TestPolicyPlaceholderExamplesDoNotImplyAnImpossibleRoute(t *testing.T) {
	raw, err := web.TranslationsFS.ReadFile("translations/en.json")
	if err != nil {
		t.Fatalf("read en.json: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("decode en.json: %v", err)
	}

	maskShape := regexp.MustCompile(`^x\.x\.x\.x(/[0-9]{1,2})?$`)
	lastAddr := func(p netip.Prefix) netip.Addr {
		a := p.Masked().Addr().As4()
		for i := p.Bits(); i < 32; i++ {
			a[i/8] |= 1 << (7 - uint(i%8))
		}
		return netip.AddrFrom4(a)
	}

	checked := 0
	for _, key := range []string{"policy_proxy_exceptions_placeholder", "policy_inventory_override_placeholder"} {
		for _, line := range strings.Split(dict[key], "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			checked++
			prefix, err := netip.ParsePrefix(line)
			if err != nil {
				addr, addrErr := netip.ParseAddr(line)
				if addrErr != nil {
					if !maskShape.MatchString(line) {
						t.Errorf("%s: %q is neither an address, a prefix, nor the documented x.x.x.x shape", key, line)
					}
					continue
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			// First and last address cover every refused range in the list, so a
			// prefix that would be refused anywhere inside it is caught here.
			if forwarder.IsProhibitedIPv4Destination(prefix.Masked().Addr()) ||
				forwarder.IsProhibitedIPv4Destination(lastAddr(prefix)) {
				t.Errorf("%s: %q is a destination the router refuses on either list", key, line)
			}
		}
	}
	if checked < 3 {
		t.Fatalf("found only %d example entries; the extraction is wrong", checked)
	}
}
