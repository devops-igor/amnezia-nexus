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
	"policy_preset_russia_inside",
	"policy_preset_geoblock",
	"policy_preset_antifilter_domains",
	"policy_preset_antifilter_ipv4",
	"policy_preset_custom",
	"policyCustomUrlsGroup",
	"policy_custom_urls",
	"policySaveBtn",
	"policySyncBtn",
	"policyActivePreset",
	"policyLastSuccess",
	"policySyncState",
	"policyRuleCount",
	"policyLastError",
	"policyProxyBytes",
	"policyDirectBytes",
	"policyProxyDrops",
	"policyDirectDrops",
	"policy_explain_value",
	"policyExplainBtn",
	"policyExplainResult",
	"policyExplainDetail",
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
			`name="policy_preset"`,
			`value="russia_inside"`,
			`value="geoblock"`,
			`value="antifilter_domains"`,
			`value="antifilter_ipv4"`,
			`value="custom"`,
			`type="submit"`,
			`id="policySaveBtn"`,
			`id="policySyncBtn"`,
		} {
			if !strings.Contains(adminBody, token) {
				t.Errorf("admin settings page is missing %q", token)
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

	t.Run("ControllerLoadedOnlyForAdmins", func(t *testing.T) {
		if !strings.Contains(adminBody, `src="/static/js/policy_routing.js"`) {
			t.Error("admin settings page does not load the policy controller")
		}
		supportBody := renderSettingsPage(t, models.RoleSupport)
		if strings.Contains(supportBody, `id="policyRoutingCard"`) {
			t.Error("support operator received the admin-only policy section")
		}
		if strings.Contains(supportBody, `src="/static/js/policy_routing.js"`) {
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
		"policy_save_refused", "policy_sync_ok", "policy_sync_failed", "policy_sync_running",
		"policy_never", "policy_none", "policy_rule_count_value", "policy_status_unknown",
		"policy_sync_state_disabled", "policy_sync_state_error",
		"policy_sync_state_pending", "policy_sync_state_synced",
		// The read-only decision dry run (#825): its result line, the labels it
		// resolves at run time and every cause the server can return.
		"policy_explain_running", "policy_explain_needs_value", "policy_explain_failed",
		"policy_explain_result",
		"policy_explain_prospective_rule", "policy_explain_current_prefix",
		"policy_explain_decision_direct", "policy_explain_decision_proxy",
		"policy_explain_decision_drop", "policy_explain_decision_unknown",
		"policy_explain_reason_policy_disabled", "policy_explain_reason_no_policy_snapshot",
		"policy_explain_reason_prohibited_destination", "policy_explain_reason_domain_rule",
		"policy_explain_reason_cname_rule", "policy_explain_reason_cidr_rule",
		"policy_explain_reason_cached_proxy_evidence", "policy_explain_reason_fresh_evidence_direct",
		"policy_explain_reason_expired_evidence", "policy_explain_reason_evicted_evidence",
		"policy_explain_reason_stale_evidence_generation", "policy_explain_reason_no_trusted_evidence",
		"policy_explain_reason_no_usable_address", "policy_explain_reason_name_unresolved",
		// The no-client-context result line, the label that separates policy
		// evaluation from a measured route, and the cause variant selected when
		// no session was read.
		"policy_explain_result_no_context",
		"policy_explain_policy_evaluation_label",
		"policy_explain_reason_no_trusted_evidence_no_session",
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
