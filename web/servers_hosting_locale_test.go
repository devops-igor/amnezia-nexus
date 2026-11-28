package web

// Locale coverage for the hosting surface after the block moved off Settings.
//
// The repository asserts key parity across the five bundles, and parity compares the
// locales to each other: a string that names a block the interface no longer has, copied
// into every bundle, passes parity forever. These assertions are made against the
// interface instead: the keys it renders exist and carry text in all five, and the keys
// that named the removed block are absent from all five.

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

// hostingSurfaceLocaleKeys are the strings the relocated hosting card and the deployment
// cards render.
var hostingSurfaceLocaleKeys = []string{
	"servers_hosting_title",
	"gigahost_deployment_no_panel_server",
	"gigahost_deployment_not_set_up_admin_handoff",
	"gigahost_deployment_no_address",
	"gigahost_deployment_recorded_state",
	"deploy_vps_title",
	"deploy_vps_recent_orders",
	"setup_intents_title",
	"gigahost_association_title",
	// The deployment state vocabulary the cards label their state with.
	"gigahost_status_stage_requested",
	"gigahost_status_stage_deploying",
	"gigahost_status_stage_ready",
	"gigahost_status_stage_failed",
	"gigahost_status_stage_deleted",
	"gigahost_status_stage_unknown",
}

// removedHostingBlockKeys are the strings that named the Settings hosting block. A key
// left behind is a key the interface can still say the block exists.
var removedHostingBlockKeys = []string{
	"gigahost_settings_title",
	"gigahost_deployments_desc",
	"gigahost_deployment_state_not_set_up",
	"gigahost_deployment_not_set_up",
}

// removedHostingBlockTitles are the names the removed block carried in each locale. No
// value in any bundle may still name it: a translated leftover is invisible to a
// key-parity check and visible to the reader as a surface that no longer exists.
var removedHostingBlockTitles = []string{
	"Gigahost Cloud Hosting",
	"Hébergement Gigahost Cloud",
	"Хостинг Gigahost Cloud",
	"Gigahost 云主机",
	"میزبانی ابری گیگاهوست",
}

// hostingLocaleDictionaries reads all five bundles.
func hostingLocaleDictionaries(t *testing.T) map[string]map[string]string {
	t.Helper()
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}
	dictionaries := make(map[string]map[string]string, len(requiredLocales))
	for _, locale := range requiredLocales {
		data, err := fs.ReadFile(transFS, locale+".json")
		if err != nil {
			t.Fatalf("read %s.json: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("%s.json is not valid JSON: %v", locale, err)
		}
		dictionaries[locale] = dict
	}
	return dictionaries
}

// TestHostingSurfaceStringsExistInEveryLocale asserts presence and content, not parity: a
// key copied into every bundle with an empty value labels nothing.
func TestHostingSurfaceStringsExistInEveryLocale(t *testing.T) {
	dictionaries := hostingLocaleDictionaries(t)

	for _, key := range hostingSurfaceLocaleKeys {
		for _, locale := range requiredLocales {
			value, ok := dictionaries[locale][key]
			if !ok {
				t.Errorf("%s.json is missing %q", locale, key)
				continue
			}
			if strings.TrimSpace(value) == "" {
				t.Errorf("%s.json has an empty value for %q", locale, key)
			}
		}
	}
}

// TestRemovedHostingBlockStringsAreGone asserts the removal in every bundle, by key and by
// the name the block carried.
func TestRemovedHostingBlockStringsAreGone(t *testing.T) {
	dictionaries := hostingLocaleDictionaries(t)

	for _, locale := range requiredLocales {
		for _, key := range removedHostingBlockKeys {
			if value, ok := dictionaries[locale][key]; ok {
				t.Errorf("%s.json still carries %q = %q, which names the removed hosting block", locale, key, value)
			}
		}
		for key, value := range dictionaries[locale] {
			for _, title := range removedHostingBlockTitles {
				if strings.Contains(value, title) {
					t.Errorf("%s.json names the removed hosting block in %q: %q", locale, key, value)
				}
			}
		}
	}
}

// TestNoStringPointsAtSettingsForSetup pins the sentence that sent the reader to the block
// that is gone. A pointer at a removed surface is worse than no pointer: the reader
// follows it and finds nothing.
func TestNoStringPointsAtSettingsForSetup(t *testing.T) {
	dictionaries := hostingLocaleDictionaries(t)

	for _, locale := range requiredLocales {
		for key, value := range dictionaries[locale] {
			lowered := strings.ToLower(value)
			if strings.Contains(lowered, "settings > gigahost") || strings.Contains(lowered, "/settings#gigahost") {
				t.Errorf("%s.json points at the removed hosting block in %q: %q", locale, key, value)
			}
		}
	}
}
