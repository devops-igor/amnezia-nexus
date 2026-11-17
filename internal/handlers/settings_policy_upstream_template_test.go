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
	"encoding/json"
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
			`data-upstream-role="not-queried"`,
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

// TestSettingsPageRendersUpstreamEditor is the shipped-page assertion that replaces
// the deliberate not-yet-wired check from the module checkpoint: the real settings
// page handler now renders the card and loads the controller for an administrator,
// and a support operator receives neither.
func TestSettingsPageRendersUpstreamEditor(t *testing.T) {
	adminBody := renderSettingsPage(t, models.RoleAdmin)
	for _, token := range []string{
		`id="policyRoutingCard"`,
		`id="policyUpstreamCard"`,
		`id="policyUpstreamForm"`,
		`data-upstream-ready="false"`,
		`id="policyUpstreamRowTemplate"`,
		`id="policyUpstreamSaveBtn"`,
		`src="/static/js/policy_upstream.js"`,
	} {
		if !strings.Contains(adminBody, token) {
			t.Errorf("admin settings page is missing %q", token)
		}
	}
	if got := strings.Count(adminBody, `src="/static/js/policy_upstream.js"`); got != 1 {
		t.Errorf("admin settings page loads the upstream controller %d times, want exactly 1", got)
	}

	supportBody := renderSettingsPage(t, models.RoleSupport)
	for _, forbidden := range []string{
		`id="policyUpstreamCard"`,
		`id="policyUpstreamForm"`,
		`/static/js/policy_upstream.js`,
	} {
		if strings.Contains(supportBody, forbidden) {
			t.Errorf("support operator's settings page contains %q", forbidden)
		}
	}
}

// upstreamFailureKinds is the resolver's closed failure-kind set, as the backend
// defines it. The controller resolves each token through the dictionary.
var upstreamFailureKinds = []string{
	"timeout", "network", "servfail", "invalid_response", "tls_handshake",
	"certificate", "pin_mismatch", "http_status", "redirect", "content_type",
	"response_too_large",
}

// TestUpstreamSectionTranslationKeysInEveryLocale pins every key the section needs
// against the five shipped dictionaries, read through the real embedded files. It
// covers the template's keys and the controller's runtime keys, so a key cannot be
// added to one consumer and forgotten in the dictionaries.
func TestUpstreamSectionTranslationKeysInEveryLocale(t *testing.T) {
	partial, err := web.TemplatesFS.ReadFile("templates/settings_policy_upstream.html")
	if err != nil {
		t.Fatalf("read settings_policy_upstream.html: %v", err)
	}
	keys := map[string]bool{}
	for _, chunk := range strings.Split(string(partial), `{{ _ "`)[1:] {
		key := chunk
		if idx := strings.Index(key, `"`); idx >= 0 {
			key = key[:idx]
		}
		if !strings.HasPrefix(key, "policy_upstream_") {
			t.Errorf("the section uses key %q outside its own namespace", key)
			continue
		}
		keys[key] = true
	}
	if len(keys) < 20 {
		t.Fatalf("found only %d upstream translation keys in the partial; the extraction is wrong", len(keys))
	}

	module, err := web.StaticFS.ReadFile("static/js/policy_upstream.js")
	if err != nil {
		t.Fatalf("read upstream controller: %v", err)
	}
	lookup := regexp.MustCompile(`'policy_upstream_[a-z0-9_]*'`)
	runtimeKeys := map[string]bool{}
	for _, match := range lookup.FindAllString(string(module), -1) {
		key := strings.Trim(match, "'")
		if strings.HasSuffix(key, "_") {
			if key != "policy_upstream_failure_" {
				t.Errorf("controller builds keys with the unhandled prefix %q", key)
				continue
			}
			for _, kind := range upstreamFailureKinds {
				runtimeKeys[key+kind] = true
			}
			continue
		}
		runtimeKeys[key] = true
	}
	if len(runtimeKeys) < 15 {
		t.Fatalf("found only %d controller keys; the extraction is wrong", len(runtimeKeys))
	}
	for key := range runtimeKeys {
		keys[key] = true
	}

	locales := []string{"en.json", "ru.json", "fr.json", "fa.json", "zh.json"}
	dicts := make(map[string]map[string]string, len(locales))
	for _, locale := range locales {
		raw, err := web.TranslationsFS.ReadFile("translations/" + locale)
		if err != nil {
			t.Fatalf("read %s: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("parse %s: %v", locale, err)
		}
		dicts[locale] = dict
	}
	for _, locale := range locales {
		for key := range keys {
			value, ok := dicts[locale][key]
			if !ok {
				t.Errorf("%s is missing key %q used by the upstream section", locale, key)
				continue
			}
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s has an empty value for %q", locale, key)
			}
		}
	}

	// The dictionaries must carry real translations, not the English text copied
	// across: the three non-Latin locales are the ones a copy-paste would show up in.
	for _, key := range []string{"policy_upstream_title", "policy_upstream_not_queried_note", "policy_upstream_too_many"} {
		for _, locale := range []string{"ru.json", "fa.json", "zh.json"} {
			if dicts[locale][key] == dicts["en.json"][key] {
				t.Errorf("%s key %q is the English text copied across, not a translation", locale, key)
			}
		}
	}
}
