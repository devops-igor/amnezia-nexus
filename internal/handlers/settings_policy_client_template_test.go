package handlers

// Template contract for the admin per-client diagnosis section (#861).
//
// The section is its own partial (web/templates/settings_policy_client.html),
// included by settings.html next to the policy routing section. These assertions
// run the real template engine over the embedded templates, so they describe what
// the browser receives:
//
//   - an administrator gets the section, its picker, both actions and every
//     element the controller writes;
//   - a support operator must not receive it at all (authoritative
//     authorization is still the admin-only API middleware);
//   - the controller asset is loaded only in the admin render;
//   - the section carries no inline script and no inline event handler;
//   - every translation key the partial and the controller use exists in all
//     five locales.
//
// The section deliberately has no inline behaviour: the only script is
// web/static/js/policy_client_diag.js.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// clientDiagSectionIDs are the element ids the shipped controller reads or
// writes. web/policy_client_diag_ui_test.go re-derives the list from the module
// source, so a rename on either side fails there as well.
var clientDiagSectionIDs = []string{
	"policyClientCard",
	"policyClientRefreshBtn",
	"policyClientRefreshText",
	"policyClientRefreshSpinner",
	"policyClientAlert",
	"policyClientSelect",
	"policyClientSelectHint",
	"policyClientDiagnoseBtn",
	"policyClientDiagnoseText",
	"policyClientDestinationFilter",
	"policyClientFilterHint",
	"policyClientFilterFoot",
	"policyClientDiagnoseSpinner",
	"policyClientStatus",
	"policyClientResult",
	"policyClientSessionValue",
	"policyClientStateValue",
	"policyClientGenerationValue",
	"policyClientEvaluatedValue",
	"policyClientFlowRows",
	"policyClientFlowFoot",
	"policyClientNotCovered",
	"policyClientLimitations",
}

func TestSettingsTemplatePolicyClientSection(t *testing.T) {
	adminBody := renderRoutingPage(t, models.RoleAdmin)

	t.Run("AdminSeesSectionAndControls", func(t *testing.T) {
		for _, id := range clientDiagSectionIDs {
			if !strings.Contains(adminBody, `id="`+id+`"`) {
				t.Errorf("admin settings page is missing #%s", id)
			}
		}
		// The controller is referenced through the URL derived from the bytes this
		// build ships, so the markup cannot be satisfied by a cached predecessor.
		controllerSrc, err := web.AssetURL("/static/js/policy_client_diag.js")
		if err != nil {
			t.Fatalf("AssetURL(policy_client_diag.js): %v", err)
		}
		for _, token := range []string{
			`src="` + controllerSrc + `"`,
			`id="policyClientSelect"`,
			// Each evidence table is named by the heading of its own sub-area, so
			// the tag now also carries the reference to that heading.
			`<table class="data-table" aria-labelledby="policyClientFlowsLabel">`,
			`<table aria-labelledby="policyClientDropsLabel">`,
			`scope="col"`,
		} {
			if !strings.Contains(adminBody, token) {
				t.Errorf("admin settings page is missing %q", token)
			}
		}
	})

	t.Run("SectionLoadedOnlyForAdmins", func(t *testing.T) {
		supportBody := renderRoutingPage(t, models.RoleSupport)
		if strings.Contains(supportBody, `id="policyClientCard"`) {
			t.Error("support operator received the admin-only per-client section")
		}
		if strings.Contains(supportBody, "/static/js/policy_client_diag.js") {
			t.Error("support operator's page loads the per-client controller")
		}
	})

	t.Run("DiagnoseShipsInertAndApplicationRowIsFixed", func(t *testing.T) {
		// The action is inert until a real incarnation is selected, and the
		// application row is part of the markup so it cannot be lost by a
		// controller change.
		if !strings.Contains(adminBody, `id="policyClientDiagnoseBtn" disabled`) {
			t.Error("the diagnose button must ship disabled")
		}
		if !strings.Contains(adminBody, `id="policyClientResult" hidden`) {
			t.Error("the result container must ship hidden")
		}
	})

	t.Run("NoInlineScriptOrHandlerInSection", func(t *testing.T) {
		partial, err := web.TemplatesFS.ReadFile("templates/settings_policy_client.html")
		if err != nil {
			t.Fatalf("read settings_policy_client.html: %v", err)
		}
		source := string(partial)
		for _, forbidden := range []string{"onclick=", "onchange=", "onsubmit=", "onsubmit ", "<script>"} {
			if strings.Contains(source, forbidden) {
				t.Errorf("per-client section must not contain %q", forbidden)
			}
		}
		// Every script tag is an external asset carrying its own source — either a
		// versioned /static reference or one this build derives from the asset's
		// bytes — and the section ships no inline body.
		got := strings.Count(source, "<script")
		if want := strings.Count(source, "<script src=\""); got != want || want == 0 {
			t.Errorf("per-client section has %d script tags but %d external assets; every tag must load a shipped asset", got, want)
		}
	})

	t.Run("SectionRendersOnSettingsOnly", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		req := httptest.NewRequest(http.MethodGet, "/vpn", nil)
		ctx := middleware.WithSession(req.Context(), &models.SessionData{
			UserID:   "admin-1",
			Username: "admin",
			Role:     models.RoleAdmin,
		})
		ctx = middleware.WithCSRFToken(ctx, "csrf-test-token")
		w := httptest.NewRecorder()
		h.VPNPageHandler(w, req.WithContext(ctx))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /vpn = %d, want 200", w.Code)
		}
		if strings.Contains(w.Body.String(), `id="policyClientCard"`) {
			t.Error("per-client section leaked into a page that does not include it")
		}
	})
}

// TestPolicyClientSectionTranslationKeysInEveryLocale pins every key the partial
// and the controller resolve against the five shipped dictionaries. The JSDOM
// harness stubs the translator, so it cannot notice a missing dictionary entry;
// this test is what makes "five locales" a measured fact.
func TestPolicyClientSectionTranslationKeysInEveryLocale(t *testing.T) {
	partial, err := web.TemplatesFS.ReadFile("templates/settings_policy_client.html")
	if err != nil {
		t.Fatalf("read settings_policy_client.html: %v", err)
	}
	module, err := web.StaticFS.ReadFile("static/js/policy_client_diag.js")
	if err != nil {
		t.Fatalf("read policy_client_diag.js: %v", err)
	}
	// The destination filter is a shipped asset of the same section: its literal keys are
	// part of the contract too, so they are extracted with the controller's.
	filterModule, err := web.StaticFS.ReadFile("static/js/policy_client_diag_filter.js")
	if err != nil {
		t.Fatalf("read policy_client_diag_filter.js: %v", err)
	}
	source := string(partial) + string(module) + string(filterModule)

	// Template keys arrive as {{ _ "policy_client_x" }}; controller keys as
	// 'policy_client_x'. Both are literal in the shipped source.
	keys := map[string]bool{}
	keyPattern := regexp.MustCompile(`^policy_client_[a-z0-9_]+$`)
	for _, chunk := range strings.Split(source, "policy_client_")[1:] {
		end := strings.IndexAny(chunk, `"'`)
		if end <= 0 {
			continue
		}
		key := "policy_client_" + chunk[:end]
		// A script path such as policy_client_diag.js is not a dictionary key.
		if !keyPattern.MatchString(key) {
			continue
		}
		keys[key] = true
	}
	// Keys the controller builds from a server token at run time: the token is
	// data, but the label key family must exist for every value the server can
	// send today.
	for kind, tokens := range clientDiagTokenValues {
		for _, token := range tokens {
			keys["policy_client_"+kind+"_"+token] = true
		}
	}
	if len(keys) < 40 {
		t.Fatalf("found only %d per-client translation keys; the extraction is wrong", len(keys))
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
				t.Errorf("%s is missing key %q used by the per-client section", locale, key)
				continue
			}
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s has an empty value for %q", locale, key)
			}
		}
	}

	// The Russian dictionary must carry real translations, not copied English.
	raw, err := web.TranslationsFS.ReadFile("translations/ru.json")
	if err != nil {
		t.Fatalf("read ru.json: %v", err)
	}
	var ru map[string]string
	if err := json.Unmarshal(raw, &ru); err != nil {
		t.Fatalf("parse ru.json: %v", err)
	}
	for _, key := range []string{"policy_client_title", "policy_client_hint", "policy_client_application_not_observable"} {
		if ru[key] == "" {
			t.Errorf("ru.json %q is empty", key)
		}
	}
	if ru["policy_client_title"] == "Per-client diagnosis" {
		t.Errorf("ru.json policy_client_title is not translated: %q", ru["policy_client_title"])
	}
}

// clientDiagTokenValues are the documented token families the controller
// translates. Each family is listed separately: a state token has no decision
// label, and asserting the cross product would demand keys nobody renders. The
// families are the ones the shipped controller addresses through
// clientTokenLabel; a family whose producer is deleted is removed here, so this
// list cannot keep a key alive that nothing renders.
var clientDiagTokenValues = map[string][]string{
	"state": {
		"live", "route_generation_replaced", "route_absent", "unknown_session",
		"policy_disabled", "identity_unavailable", "inconsistent",
	},
	"decision": {"direct", "proxy", "unknown"},
	"protocol": {"tcp", "udp"},
	// The decision-reason family is deliberately absent: the controller renders
	// those tokens through its own label map, not through a
	// policy_client_reason_<token> key, and no bundle carries that family. The
	// map, the producer's tokens and the bundles are held together by
	// web/policy_client_reason_vocabulary_test.go.
	"return_evidence": {"observed", "not_observed", "not_measured", "not_recorded"},
	// What the dispatch path did with the flow's packets. The state is a token
	// family of its own because it is rendered beside the route: a DIRECT flow
	// whose writes failed reads as direct-and-failed, not as an unexplained
	// failure (issue #920).
	"dispatch": {"written_to_wan", "queued_to_backend", "failed", "not_recorded"},
	"failure": {
		"wan_write_failed", "backend_queue_full", "backend_detached",
		"backend_unavailable", "direct_egress_unavailable", "return_path_closed",
		"backend_write_failed", "short_write",
		"client_queue_full", "client_rate_limited", "packet_too_large",
		"return_path_closed", "client_write_failed", "client_short_write",
	},
	"limit": {
		"flow_evidence_install_failure_not_recorded",
		"application_success_not_observable",
		"proxy_return_not_measured",
		"session_end_not_distinguishable",
		"ipv6_not_supported",
		"not_an_atomic_cross_subsystem_snapshot", "selection_changed_during_read",
		"session_registry_unavailable", "flow_scan_window_partial",
	},
}
