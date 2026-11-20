package handlers

// The removal of DNS steering owes the operator surface two statements (#917):
//
//   - a client profile generated while steering existed may still name the old
//     resolver, so a device holding it loses DNS once that resolver stops
//     answering and has to download the profile again;
//   - allocation membership approximates where a destination is registered, not
//     where it physically is, so a direct route still leaves from the ingress
//     server's own address.
//
// These assertions render the shipped pages through the page handlers, so what
// is checked is the markup a browser receives with the locale dictionary the
// request negotiates, not the template source. config.T falls back to English
// for a key a locale lacks, so a page-only substring check would pass on the
// fallback; each locale is therefore also compared against its own dictionary
// entry and against the English wording.

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/web"
)

// noticeLocales are the five shipped dictionaries.
var noticeLocales = []string{"en", "ru", "fr", "zh", "fa"}

// removalNoticeStatements pairs a statement key with the rendered element that
// carries it and the page that owns it.
var removalNoticeStatements = []struct {
	key     string
	element string
	page    string // "settings" or "my"
}{
	{"policy_direct_egress_notice", "policyDirectEgressNotice", "settings"},
	{"profile_regenerate_notice", "profileRegenerateNotice", "my"},
}

// loadNoticeDictionaries reads the shipped locale files as they are on disk.
func loadNoticeDictionaries(t *testing.T) map[string]map[string]string {
	t.Helper()
	dicts := make(map[string]map[string]string, len(noticeLocales))
	for _, locale := range noticeLocales {
		raw, err := web.TranslationsFS.ReadFile("translations/" + locale + ".json")
		if err != nil {
			t.Fatalf("read %s.json: %v", locale, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("parse %s.json: %v", locale, err)
		}
		dicts[locale] = dict
	}
	return dicts
}

// renderSettingsInLocale renders /settings for an administrator in the given
// locale through the real page handler.
func renderSettingsInLocale(t *testing.T, h *Handlers, locale string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/settings?lang="+locale, nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "notice-admin",
		Username: "notice-admin",
		Role:     models.RoleAdmin,
	})
	ctx = middleware.WithCSRFToken(ctx, "csrf-notice")
	w := httptest.NewRecorder()
	h.SettingsPageHandler(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /settings?lang=%s = %d, want 200", locale, w.Code)
	}
	return html.UnescapeString(w.Body.String())
}

// renderMyConnectionsInLocale renders /my for a regular user in the given
// locale through the real page handler.
func renderMyConnectionsInLocale(t *testing.T, h *Handlers, locale string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/my?lang="+locale, nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "notice-user",
		Username: "notice-user",
		Role:     models.RoleUser,
	})
	w := httptest.NewRecorder()
	h.MyConnectionsPageHandler(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /my?lang=%s = %d, want 200", locale, w.Code)
	}
	return html.UnescapeString(w.Body.String())
}

// elementText returns the trimmed text content of the first element carrying
// the given id. The statement elements are single paragraphs, so the body ends
// at the first closing tag.
func elementText(t *testing.T, page, id string) string {
	t.Helper()
	marker := `id="` + id + `"`
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatalf("page does not contain an element with id %q", id)
	}
	rest := page[start:]
	open := strings.Index(rest, ">")
	if open < 0 {
		t.Fatalf("element #%s has no opening tag end", id)
	}
	closing := strings.Index(rest[open:], "</")
	if closing < 0 {
		t.Fatalf("element #%s is not closed", id)
	}
	return strings.TrimSpace(rest[open+1 : open+closing])
}

// checkNoticeStatement reports why a locale fails to show its own wording of a
// statement: the key is absent, empty, or the page carries different text
// (which is what an English fallback looks like).
func checkNoticeStatement(pageText, locale, key string, dicts map[string]map[string]string) error {
	dict, ok := dicts[locale]
	if !ok {
		return fmt.Errorf("locale %q has no dictionary", locale)
	}
	want, ok := dict[key]
	if !ok || strings.TrimSpace(want) == "" {
		return fmt.Errorf("%s.json: statement %q is missing or empty", locale, key)
	}
	if pageText != want {
		return fmt.Errorf("%s page shows %q, want the %s wording %q", locale, pageText, locale, want)
	}
	return nil
}

// cloneLocale returns a mutable copy of one locale's entries.
func cloneLocale(dicts map[string]map[string]string, locale string) map[string]string {
	clone := make(map[string]string, len(dicts[locale]))
	for key, value := range dicts[locale] {
		clone[key] = value
	}
	return clone
}

// renderNoticePages renders, for every locale, both pages that own a statement.
func renderNoticePages(t *testing.T, h *Handlers) map[string]map[string]string {
	t.Helper()
	pages := map[string]map[string]string{"settings": {}, "my": {}}
	for _, locale := range noticeLocales {
		pages["settings"][locale] = renderSettingsInLocale(t, h, locale)
		pages["my"][locale] = renderMyConnectionsInLocale(t, h, locale)
	}
	return pages
}

func TestRemovalNoticeStatementsInEveryLocale(t *testing.T) {
	dicts := loadNoticeDictionaries(t)
	h, _, _ := setupTestHandlers(t)
	pages := renderNoticePages(t, h)

	for _, statement := range removalNoticeStatements {
		t.Run(statement.element, func(t *testing.T) {
			for _, locale := range noticeLocales {
				text := elementText(t, pages[statement.page][locale], statement.element)
				if err := checkNoticeStatement(text, locale, statement.key, dicts); err != nil {
					t.Error(err)
				}
			}
		})
	}

	t.Run("NonEnglishLocalesTranslateBothStatements", func(t *testing.T) {
		for _, statement := range removalNoticeStatements {
			english := dicts["en"][statement.key]
			if strings.TrimSpace(english) == "" {
				t.Fatalf("en.json is missing %q", statement.key)
			}
			for _, locale := range noticeLocales[1:] {
				got := dicts[locale][statement.key]
				if strings.TrimSpace(got) == "" {
					t.Errorf("%s.json has no wording for %q", locale, statement.key)
					continue
				}
				if got == english {
					t.Errorf("%s.json carries the English wording for %q instead of a translation", locale, statement.key)
				}
			}
		}
	})
}

// TestRemovalNoticeCheckerRejectsLostLocaleText proves the assertions above can
// fail: a locale that loses its entry, or keeps the English sentence, must be
// reported by the same checker against the page rendered in that locale.
func TestRemovalNoticeCheckerRejectsLostLocaleText(t *testing.T) {
	dicts := loadNoticeDictionaries(t)
	h, _, _ := setupTestHandlers(t)
	pages := renderNoticePages(t, h)

	for _, statement := range removalNoticeStatements {
		pageText := elementText(t, pages[statement.page]["ru"], statement.element)

		missing := cloneLocale(dicts, "ru")
		delete(missing, statement.key)
		if err := checkNoticeStatement(pageText, "ru", statement.key, map[string]map[string]string{"ru": missing}); err == nil {
			t.Errorf("checker accepted a missing ru entry for %q", statement.key)
		}

		englishCopy := cloneLocale(dicts, "ru")
		englishCopy[statement.key] = dicts["en"][statement.key]
		if err := checkNoticeStatement(pageText, "ru", statement.key, map[string]map[string]string{"ru": englishCopy}); err == nil {
			t.Errorf("checker accepted the English wording as the ru translation of %q", statement.key)
		}
	}
}
