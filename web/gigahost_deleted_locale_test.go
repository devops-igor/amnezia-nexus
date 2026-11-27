package web

// Locale coverage for the strings this change adds.
//
// The repository already asserts full key parity across the five bundles, and that
// check is what keeps a locale from missing a key somebody adds. It cannot tell a key
// that reached every bundle because a feature needed it from a key that reached every
// bundle because somebody copied the file: parity compares the locales to each other.
// This test therefore names the keys this surface renders and requires each to be
// present and non-empty in all five, so the requirement "every new user-visible string
// exists in all five locales" is asserted directly instead of inferred from symmetry.

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

// deletedDeploymentLocaleKeys are the user-visible strings the provider-absence
// presentation adds: the deleted stage label itself and the sentence that replaces the
// provisioning explanation for an address that is no longer this panel's.
var deletedDeploymentLocaleKeys = []string{
	"gigahost_status_stage_deleted",
	"gigahost_status_ip_deleted",
}

// TestDeletedDeploymentStringsExistInEveryLocale asserts presence and content, not just
// parity: a bundle that carries the key with an empty value labels nothing.
func TestDeletedDeploymentStringsExistInEveryLocale(t *testing.T) {
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

	for _, key := range deletedDeploymentLocaleKeys {
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

	// The two labels must be distinguishable in every locale: a deletion that read the
	// same word as another stage would not tell the operator what happened.
	for _, locale := range requiredLocales {
		if dictionaries[locale]["gigahost_status_stage_deleted"] == dictionaries[locale]["gigahost_status_stage_cancelled"] {
			t.Errorf("%s.json uses the same label for a deleted and a cancelled order", locale)
		}
	}
}
