package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	tmplI18nRegex = regexp.MustCompile(`\{\{\s*_\s*"([^"]+)"`)
	jsI18nRegex   = regexp.MustCompile(`(?:(?:window\.)?_\s*\(\s*['"]([a-zA-Z0-9_\-]+)['"]|vpnDiagText\s*\(\s*['"]([a-zA-Z0-9_\-]+)['"])`)
	lossKeyRegex  = regexp.MustCompile(`\b\w+:\s*['"](vpn_diag_loss_[^'"]+)['"]`)
	phRegex       = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)
)

// Known server-emitted message_key and summary_key identifiers used by the VPN dashboard.
var knownDynamicVPNKeys = []string{
	"vpn_status_active",
	"vpn_problem_session_without_route",
	"vpn_problem_stale_handshake",
	"vpn_problem_route_queue_drops",
	"vpn_problem_write_stall",
	"vpn_problem_write_errors",
	"vpn_problem_route_queue_pressure",
	"vpn_diag_condition_backend_device_unattributed",
	"vpn_diag_summary_actionable_issues",
	"vpn_diag_summary_critical",
	"vpn_diag_summary_degraded",
	"vpn_diag_summary_healthy",
}

var requiredLocales = []string{"en", "fa", "fr", "ru", "zh"}

func extractVPNTranslationKeys(t *testing.T) (keys []string, staticCount int) {
	t.Helper()

	keySet := make(map[string]bool)

	// 1. Parse web/templates/vpn.html
	tmplData, err := fs.ReadFile(TemplatesFS, "templates/vpn.html")
	if err != nil {
		t.Fatalf("failed to read templates/vpn.html: %v", err)
	}
	tmplMatches := tmplI18nRegex.FindAllStringSubmatch(string(tmplData), -1)
	if len(tmplMatches) == 0 {
		t.Fatal("expected to find translation keys in templates/vpn.html, found none")
	}
	for _, m := range tmplMatches {
		keySet[m[1]] = true
	}

	// 2. Parse 6 companion scripts
	companionFiles := []string{
		"static/js/vpn/backends.js",
		"static/js/vpn/health_problems.js",
		"static/js/vpn/health_summary.js",
		"static/js/vpn/charts.js",
		"static/js/vpn/sessions.js",
		"static/js/vpn/page.js",
	}

	var healthProblemsContent string
	for _, file := range companionFiles {
		data, err := fs.ReadFile(StaticFS, file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		content := string(data)
		if strings.Contains(file, "health_problems.js") {
			healthProblemsContent = content
		}
		jsMatches := jsI18nRegex.FindAllStringSubmatch(content, -1)
		for _, m := range jsMatches {
			k := m[1]
			if k == "" {
				k = m[2]
			}
			if k != "" {
				keySet[k] = true
			}
		}
	}

	staticCount = len(keySet)

	// 3. Extract dynamic vpnLossReasonLabels from health_problems.js
	if healthProblemsContent == "" {
		t.Fatal("health_problems.js was not read")
	}
	lossMatches := lossKeyRegex.FindAllStringSubmatch(healthProblemsContent, -1)
	if len(lossMatches) == 0 {
		t.Fatal("expected to extract vpnLossReasonLabels from health_problems.js, found none")
	}
	for _, m := range lossMatches {
		keySet[m[1]] = true
	}

	// 4. Include known server-emitted message_key and summary_key identifiers
	for _, k := range knownDynamicVPNKeys {
		keySet[k] = true
	}

	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, staticCount
}

func loadLocaleDictionaries(t *testing.T) map[string]map[string]string {
	t.Helper()
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	dicts := make(map[string]map[string]string)
	for _, loc := range requiredLocales {
		fileName := loc + ".json"
		data, err := fs.ReadFile(transFS, fileName)
		if err != nil {
			t.Fatalf("failed to read translation file %s: %v", fileName, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s: %v", fileName, err)
		}
		dicts[loc] = dict
	}
	return dicts
}

func cloneDictionaries(orig map[string]map[string]string) map[string]map[string]string {
	c := make(map[string]map[string]string, len(orig))
	for loc, dict := range orig {
		copiedDict := make(map[string]string, len(dict))
		for k, v := range dict {
			copiedDict[k] = v
		}
		c[loc] = copiedDict
	}
	return c
}

func validateTranslationKeys(keys []string, dicts map[string]map[string]string) error {
	var errs []string

	for _, loc := range requiredLocales {
		dict, ok := dicts[loc]
		if !ok {
			return fmt.Errorf("missing dictionary for locale %q", loc)
		}
		for _, key := range keys {
			val, exists := dict[key]
			if !exists {
				errs = append(errs, fmt.Sprintf("locale %q missing required key %q", loc, key))
				continue
			}
			if strings.TrimSpace(val) == "" {
				errs = append(errs, fmt.Sprintf("locale %q has empty value for key %q", loc, key))
			}
		}
	}

	// Verify placeholder consistency across locales against en.json
	enDict := dicts["en"]
	if enDict != nil {
		for _, key := range keys {
			enVal, ok := enDict[key]
			if !ok {
				continue
			}
			enPlaceholders := extractPlaceholders(enVal)

			for _, loc := range requiredLocales {
				if loc == "en" {
					continue
				}
				locDict := dicts[loc]
				if locDict == nil {
					continue
				}
				locVal, ok := locDict[key]
				if !ok {
					continue
				}
				locPlaceholders := extractPlaceholders(locVal)
				if !slicesEqual(enPlaceholders, locPlaceholders) {
					errs = append(errs, fmt.Sprintf("placeholder mismatch for key %q in locale %q: en=%v, %s=%v",
						key, loc, enPlaceholders, loc, locPlaceholders))
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("translation validation failed with %d error(s):\n%s", len(errs), strings.Join(errs, "\n"))
	}
	return nil
}

func extractPlaceholders(s string) []string {
	matches := phRegex.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	var res []string
	for _, m := range matches {
		res = append(res, m[1])
	}
	sort.Strings(res)
	return res
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestVPNTranslationKeyParityAndCoverage(t *testing.T) {
	keys, staticCount := extractVPNTranslationKeys(t)

	if staticCount < 225 {
		t.Fatalf("expected at least 225 static translation keys across VPN sources, got %d", staticCount)
	}
	if len(keys) < 250 {
		t.Fatalf("expected at least 250 total translation keys (static + dynamic), got %d", len(keys))
	}

	dicts := loadLocaleDictionaries(t)

	if err := validateTranslationKeys(keys, dicts); err != nil {
		t.Fatalf("VPN translation validation failed: %v", err)
	}
}

func TestVPNTranslationParityNegativeMutations(t *testing.T) {
	keys, _ := extractVPNTranslationKeys(t)
	baseDicts := loadLocaleDictionaries(t)

	// Pre-condition: base dictionaries must pass cleanly
	if err := validateTranslationKeys(keys, baseDicts); err != nil {
		t.Fatalf("pre-condition failed: base dictionaries are invalid: %v", err)
	}

	t.Run("KeyRemovedFromSingleLocaleFails", func(t *testing.T) {
		mutated := cloneDictionaries(baseDicts)
		delete(mutated["ru"], "vpn_status_active")

		err := validateTranslationKeys(keys, mutated)
		if err == nil {
			t.Fatal("expected validation failure when 'vpn_status_active' removed from ru.json, got nil")
		}
		if !strings.Contains(err.Error(), "vpn_status_active") || !strings.Contains(err.Error(), `"ru"`) {
			t.Fatalf("expected error mentioning 'vpn_status_active' and 'ru', got: %v", err)
		}
	})

	t.Run("KeyRemovedFromAllLocalesFails", func(t *testing.T) {
		// Parity blind-spot probe: if a key is absent from ALL 5 dictionaries including en.json,
		// the validator must still fail closed because the key is required by VPN sources.
		mutated := cloneDictionaries(baseDicts)
		for _, loc := range requiredLocales {
			delete(mutated[loc], "vpn_status_active")
		}

		err := validateTranslationKeys(keys, mutated)
		if err == nil {
			t.Fatal("expected validation failure when 'vpn_status_active' removed from all locales, got nil")
		}
		if !strings.Contains(err.Error(), "vpn_status_active") {
			t.Fatalf("expected error mentioning 'vpn_status_active', got: %v", err)
		}
	})

	t.Run("BlankValueFails", func(t *testing.T) {
		mutated := cloneDictionaries(baseDicts)
		mutated["fa"]["vpn_status_active"] = "   "

		err := validateTranslationKeys(keys, mutated)
		if err == nil {
			t.Fatal("expected validation failure for whitespace-only value, got nil")
		}
		if !strings.Contains(err.Error(), "empty value") || !strings.Contains(err.Error(), "vpn_status_active") {
			t.Fatalf("expected error mentioning empty value for 'vpn_status_active', got: %v", err)
		}
	})

	t.Run("PlaceholderMismatchFails", func(t *testing.T) {
		mutated := cloneDictionaries(baseDicts)
		mutated["fr"]["vpn_diag_heap_memory"] = "Tas : {corrupted_placeholder} Mio"

		err := validateTranslationKeys(keys, mutated)
		if err == nil {
			t.Fatal("expected validation failure on placeholder mismatch, got nil")
		}
		if !strings.Contains(err.Error(), "placeholder mismatch") || !strings.Contains(err.Error(), "vpn_diag_heap_memory") {
			t.Fatalf("expected error mentioning placeholder mismatch and 'vpn_diag_heap_memory', got: %v", err)
		}
	})

	t.Run("DynamicLossReasonKeyMissingFails", func(t *testing.T) {
		mutated := cloneDictionaries(baseDicts)
		delete(mutated["zh"], "vpn_diag_loss_client_rate_limited")

		err := validateTranslationKeys(keys, mutated)
		if err == nil {
			t.Fatal("expected validation failure on missing dynamic loss reason key, got nil")
		}
		if !strings.Contains(err.Error(), "vpn_diag_loss_client_rate_limited") {
			t.Fatalf("expected error mentioning 'vpn_diag_loss_client_rate_limited', got: %v", err)
		}
	})
}
