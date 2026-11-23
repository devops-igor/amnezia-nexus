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
	"policyLastSuccess",
	"policySyncState",
	"policyRuleCount",
	"policyLastError",
	"policyProxyBytes",
	"policyDirectBytes",
	"policyProxyDrops",
	"policyDirectDrops",
	"policy_inventory_override",
	"policyInventorySource",
	"policyInventoryPrefixes",
	"policyInventoryRetrieved",
	"policyInventoryAge",
	"policyInventoryOverrideStatus",
	"policyInventoryNotice",
	"policyCdnSource",
	"policyCdnCount",
	"policyCdnEntries",
	"policyCdnNotice",
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
		// Exactly one script tag: the external controller asset.
		if got := strings.Count(source, "<script"); got != 1 {
			t.Errorf("policy section has %d script tags, want exactly 1 external asset", got)
		}
		if strings.Contains(source, "<script>") {
			t.Error("policy section must not contain an inline script body")
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

	// Keys the controller resolves at run time. The JSDOM harness stubs the
	// translator, so it cannot notice a key missing from a dictionary; pin them
	// here with the template's own keys.
	for _, key := range []string{
		"policy_load_failed", "policy_not_ready", "policy_saved", "policy_save_failed",
		"policy_save_kept", "policy_sync_ok", "policy_sync_failed", "policy_sync_running",
		"policy_never", "policy_none", "policy_status_unknown",
		"policy_sync_state_disabled", "policy_sync_state_error",
		"policy_sync_state_pending", "policy_sync_state_synced",
		// Keys the inventory block formats at run time (issue #920). Their values
		// carry the placeholders the controller substitutes, so a missing
		// dictionary entry would leave a raw key on the page.
		"policy_inventory_age_value", "policy_inventory_stale",
		"policy_inventory_override_active", "policy_inventory_override_none",
		"policy_inventory_unusable",
		// Keys the CDN exclusion block renders at run time (issue #934). They are
		// chosen by the controller, not written in markup, so a missing dictionary
		// entry would leave a raw key on the page.
		"policy_cdn_empty", "policy_cdn_unavailable", "policy_cdn_unusable",
	} {
		keys[key] = true
	}

	locales := []string{"en.json", "ru.json", "fr.json", "fa.json", "zh.json"}
	for _, locale := range locales {
		raw, err := web.TranslationsFS.ReadFile("translations/" + locale)
		if err != nil {
			t.Fatalf("read %s: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("parse %s: %v", locale, err)
		}
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
		"prohibited or internal destinations are always refused",
		"changes apply to new connections only",
		// The notice under both controls names which list it means, and its DIRECT
		// sentence excludes the PROXY list because that rule is checked first.
		"A destination on the PROXY list uses PROXY",
		"not on the PROXY list goes DIRECT",
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

// TestPolicyExamplesDoNotContradictEachOther pins the two example placeholders
// apart. The DIRECT list is not absolute: an entry on the PROXY list wins over it,
// so an address shown as "goes direct" must not also be shown as "goes through
// PROXY" — otherwise the page states a contradiction before the operator has
// edited anything. Both examples are parsed the way the handlers parse them: a
// bare address is a /32.
func TestPolicyExamplesDoNotContradictEachOther(t *testing.T) {
	raw, err := web.TranslationsFS.ReadFile("translations/en.json")
	if err != nil {
		t.Fatalf("read en.json: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("decode en.json: %v", err)
	}

	parse := func(key string) []netip.Prefix {
		var out []netip.Prefix
		for _, line := range strings.Split(dict[key], "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if p, err := netip.ParsePrefix(line); err == nil {
				out = append(out, p.Masked())
				continue
			}
			addr, err := netip.ParseAddr(line)
			if err != nil {
				t.Fatalf("%s: %q is neither a prefix nor an address: %v", key, line, err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
		if len(out) == 0 {
			t.Fatalf("%s has no example entries, so nothing was compared", key)
		}
		return out
	}

	proxy := parse("policy_proxy_exceptions_placeholder")
	direct := parse("policy_inventory_override_placeholder")
	for _, p := range proxy {
		for _, d := range direct {
			if p.Overlaps(d) {
				t.Errorf("the examples contradict each other: %s is shown as PROXY and as DIRECT (%s)", p, d)
			}
		}
	}
}
