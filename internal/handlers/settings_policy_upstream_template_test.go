package handlers

// Template contract for the upstream resolver editor (#865).
//
// The section is a new partial (web/templates/settings_policy_upstream.html) that
// will be included by settings.html. This file renders the partial through the
// real template engine and the real role predicate, so it describes what the
// browser receives rather than what the markup source says:
//
//   - an administrator gets the card, the row scaffold the controller clones, the
//     actions and the health elements;
//   - a support operator, who may open /settings, must not receive it at all
//     (authoritative authorization is still the admin-only API middleware);
//   - the controller asset is loaded only in the admin render;
//   - the section uses no inline script and no inline event handler;
//   - its element ids do not collide with the policy section that shares the page.
//
// What is deliberately NOT proven here: this checkpoint does not wire the section
// into web/templates/settings.html, does not register the partial in the template
// loader and does not add the policy_upstream_* keys to the translation
// dictionaries. Those three edits touch files another in-flight task owns and are
// serialized behind it. The last test states that plainly instead of implying the
// page integration was verified.

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// renderUpstreamCardForTest executes the isolated partial. The template helpers
// are the engine's own, so the role predicate under test is the shipped one; a
// translation key the dictionaries do not define resolves to the key itself,
// which is why no assertion below depends on the wording.
func renderUpstreamCardForTest(t *testing.T, role models.UserRole) (string, *template.Template) {
	t.Helper()
	tmpl, err := template.New("settings_policy_upstream.html").Funcs(baseFuncMap()).
		ParseFS(web.TemplatesFS, "templates/settings_policy_upstream.html")
	if err != nil {
		t.Fatalf("parse settings_policy_upstream.html: %v", err)
	}
	if tmpl.Lookup("settings_policy_upstream") == nil {
		t.Fatal("the partial must define the section name settings_policy_upstream")
	}
	var buf bytes.Buffer
	data := map[string]any{"current_user": &models.SessionData{UserID: "user-1", Role: role}}
	if err := tmpl.ExecuteTemplate(&buf, "settings_policy_upstream", data); err != nil {
		t.Fatalf("render settings_policy_upstream as %s: %v", role, err)
	}
	return buf.String(), tmpl
}

func TestSettingsPolicyUpstreamTemplate(t *testing.T) {
	adminBody, _ := renderUpstreamCardForTest(t, models.RoleAdmin)

	t.Run("AdminSeesCardAndRowScaffold", func(t *testing.T) {
		for _, token := range []string{
			`id="policyUpstreamCard"`,
			`id="policyUpstreamForm"`,
			`data-upstream-ready="false"`,
			`id="policyUpstreamAlert"`,
			`id="policyUpstreamRows"`,
			`id="policyUpstreamAddBtn"`,
			`id="policyUpstreamDefaultsNotice"`,
			`id="policyUpstreamPlainWarning"`,
			`id="policyUpstreamMixedWarning"`,
			`id="policyUpstreamSaveEffects"`,
			`id="policyUpstreamSaveBtn"`,
			`id="policyUpstreamDefaultsBtn"`,
			`id="policyUpstreamReloadBtn"`,
			`id="policyUpstreamHealthState"`,
			`id="policyUpstreamHealthFailure"`,
			`id="policyUpstreamRowTemplate"`,
			`data-upstream-role="row"`,
			`data-upstream-field="address"`,
			`data-upstream-field="port"`,
			`data-upstream-field="transport"`,
			`data-upstream-field="pin"`,
			`data-upstream-action="up"`,
			`data-upstream-action="down"`,
			`data-upstream-action="remove"`,
			`data-upstream-role="standby"`,
		} {
			if !strings.Contains(adminBody, token) {
				t.Errorf("admin render is missing %q", token)
			}
		}
		// The transports are a fixed set: an option the resolver cannot dial must
		// never be offered.
		for _, transport := range []string{`value="plain"`, `value="dot"`, `value="doh"`} {
			if !strings.Contains(adminBody, transport) {
				t.Errorf("admin render does not offer the %s transport", transport)
			}
		}
	})

	t.Run("SupportOperatorReceivesNothing", func(t *testing.T) {
		supportBody, _ := renderUpstreamCardForTest(t, models.RoleSupport)
		if strings.Contains(supportBody, `id="policyUpstreamCard"`) {
			t.Error("a support operator received the admin-only upstream editor")
		}
		if strings.Contains(supportBody, `id="policyUpstreamForm"`) {
			t.Error("a support operator received the upstream editor form")
		}
		if strings.Contains(supportBody, `/static/js/policy_upstream.js`) {
			t.Error("a support operator's render loads the upstream controller")
		}
	})

	t.Run("ControllerAssetLoadedForAdminsOnly", func(t *testing.T) {
		if got := strings.Count(adminBody, `src="/static/js/policy_upstream.js"`); got != 1 {
			t.Errorf("admin render loads the upstream controller %d times, want exactly 1", got)
		}
	})

	t.Run("SaveShipsInertUntilTheRecordLoads", func(t *testing.T) {
		tag := regexp.MustCompile(`<button[^>]*id="policyUpstreamSaveBtn"[^>]*>`).FindString(adminBody)
		if tag == "" {
			t.Fatal("admin render has no #policyUpstreamSaveBtn")
		}
		if !strings.Contains(tag, " disabled") {
			t.Errorf("the Save button must ship disabled, got %q", tag)
		}
		for _, id := range []string{"policyUpstreamAddBtn", "policyUpstreamDefaultsBtn", "policyUpstreamReloadBtn"} {
			tag := regexp.MustCompile(`<button[^>]*id="` + id + `"[^>]*>`).FindString(adminBody)
			if tag == "" {
				t.Fatalf("admin render has no #%s", id)
			}
			if !strings.Contains(tag, " disabled") {
				t.Errorf("#%s must ship disabled, got %q", id, tag)
			}
		}
	})

	t.Run("AccessibleResultAndHealthRegions", func(t *testing.T) {
		for _, token := range []string{
			`role="status"`,
			`aria-live="polite"`,
			`data-upstream-role="error"`,
			`role="alert"`,
		} {
			if !strings.Contains(adminBody, token) {
				t.Errorf("admin render is missing %q", token)
			}
		}
	})

	t.Run("NoInlineScriptOrHandler", func(t *testing.T) {
		partial, err := web.TemplatesFS.ReadFile("templates/settings_policy_upstream.html")
		if err != nil {
			t.Fatalf("read settings_policy_upstream.html: %v", err)
		}
		source := string(partial)
		if strings.Contains(source, "onclick=") || strings.Contains(source, "onchange=") || strings.Contains(source, "onsubmit=") {
			t.Error("the upstream section must not use inline event handlers")
		}
		if got := strings.Count(source, "<script"); got != 1 {
			t.Errorf("the upstream section has %d script tags, want exactly 1 external asset", got)
		}
		if strings.Contains(source, "<script>") {
			t.Error("the upstream section must not contain an inline script body")
		}
	})

	t.Run("IDsDoNotCollideWithThePolicySection", func(t *testing.T) {
		// Both sections render into the same settings page, so a duplicate id would
		// make one controller write into the other one's element.
		policyPartial, err := web.TemplatesFS.ReadFile("templates/settings_policy.html")
		if err != nil {
			t.Fatalf("read settings_policy.html: %v", err)
		}
		policyIDs := map[string]bool{}
		for _, match := range regexp.MustCompile(`id="([A-Za-z0-9_]+)"`).FindAllStringSubmatch(string(policyPartial), -1) {
			policyIDs[match[1]] = true
		}
		if len(policyIDs) < 10 {
			t.Fatalf("found only %d ids in the policy partial; the extraction is wrong", len(policyIDs))
		}
		upstreamIDs := regexp.MustCompile(`id="([A-Za-z0-9_]+)"`).FindAllStringSubmatch(adminBody, -1)
		if len(upstreamIDs) < 10 {
			t.Fatalf("found only %d ids in the upstream render; the extraction is wrong", len(upstreamIDs))
		}
		for _, match := range upstreamIDs {
			if policyIDs[match[1]] {
				t.Errorf("id %q is used by both the policy and the upstream section", match[1])
			}
		}
	})
}

// TestSettingsPageDoesNotYetRenderUpstreamEditor states the deferral instead of
// leaving it implicit: the shipped settings page is produced by a loader that does
// not parse the new partial and a layout that does not include the section, so the
// page integration is NOT tested by this checkpoint.
//
// This test is the trigger for the integration step: when the include, the loader
// registration and the dictionaries land, it must be replaced by page-level
// assertions (admin render contains the card and resolves every key, support render
// contains neither) rather than deleted.
func TestSettingsPageDoesNotYetRenderUpstreamEditor(t *testing.T) {
	body := renderSettingsPage(t, models.RoleAdmin)
	if !strings.Contains(body, `id="policyRoutingCard"`) {
		t.Fatal("the shipped settings page no longer renders the policy section; the fixture is wrong")
	}
	if strings.Contains(body, `id="policyUpstreamCard"`) {
		t.Error("the shipped settings page already renders the upstream editor; replace this test with the page-level integration assertions")
	}
	if strings.Contains(body, `/static/js/policy_upstream.js`) {
		t.Error("the shipped settings page already loads the upstream controller; replace this test with the page-level integration assertions")
	}
}
