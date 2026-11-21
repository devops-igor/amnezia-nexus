package router

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Real-router regression for the rule-confidentiality requirement on the generic
// Settings backup export.
//
// The policy record has its own administrator-only API. The backup download is a
// second read of the same settings table, mounted under RequireAdminOrSupport, so
// it must not become the alternative read that hands operator-selected routing
// rules to Support. Restore ignores the record (allowedSettingsKeys), so
// withholding it costs no restore capability.
//
// These assertions run through the real router, the real session/CSRF/role
// middlewares and a real SQLite database: the fixture record is written by the
// production admin API and read back by the production export handler.

// backupFixtureRules are the synthetic exception prefixes the fixture
// administrator saved. They are distinct literals that must not appear anywhere in
// a Support export.
var backupFixtureRules = []string{"203.0.113.0/24", "198.51.100.0/24"}

// backupFixtureAppearance is ordinary permitted metadata: it must survive in a
// Support export, so the test can distinguish "policy record withheld" from
// "backup came back empty or broken".
const backupFixtureAppearanceTitle = "Backup Confidentiality Fixture"

// newPolicyBackupRouter prepares a real router whose database holds one ordinary
// settings section plus a nonempty policy record written through the admin API.
func newPolicyBackupRouter(t *testing.T) (*database.DB, http.Handler) {
	t.Helper()

	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	ctx := context.Background()
	if err := db.SetSetting(ctx, "appearance", models.AppearanceSettings{
		Title:    backupFixtureAppearanceTitle,
		Logo:     "shield",
		Subtitle: "Panel",
		Language: "en",
	}); err != nil {
		t.Fatalf("seed ordinary appearance settings: %v", err)
	}

	// Save the policy record through the real admin endpoint, so the fixture is
	// the record production actually persists (json tags, defaults and all).
	record := policy.DefaultSettings()
	record.ProxyExceptions = append([]string(nil), backupFixtureRules...)
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal policy record: %v", err)
	}
	wSave := httptest.NewRecorder()
	r.ServeHTTP(wSave, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if wSave.Code != http.StatusOK {
		t.Fatalf("PUT /api/vpn/policy = %d, want 200; body=%s", wSave.Code, wSave.Body.String())
	}

	// Guard the fixture itself: an empty or unpersisted record would let the
	// confidentiality assertions below pass while disclosing nothing.
	var stored policy.Settings
	if err := db.GetSetting(ctx, policy.SettingsKey, &stored); err != nil {
		t.Fatalf("read back seeded policy record: %v", err)
	}
	if len(stored.ProxyExceptions) != len(backupFixtureRules) {
		t.Fatalf("seeded policy record holds %d local entries, want %d: %+v",
			len(stored.ProxyExceptions), len(backupFixtureRules), stored)
	}

	return db, r
}

// backupExport decodes a download response into the payload and its settings map.
func backupExport(t *testing.T, body []byte) (map[string]any, map[string]any) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode backup payload: %v; body=%s", err, string(body))
	}
	settings, ok := payload["settings"].(map[string]any)
	if !ok {
		t.Fatalf("backup payload carries no settings object: %s", string(body))
	}
	return payload, settings
}

// assertNoRuleContent fails when any synthetic rule survives in a response body.
func assertNoRuleContent(t *testing.T, label string, body []byte) {
	t.Helper()
	for _, rule := range backupFixtureRules {
		if bytes.Contains(body, []byte(rule)) {
			t.Errorf("%s discloses protected policy rule %q", label, rule)
		}
	}
}

// A Support backup must stay a successful, ordinary backup while carrying none of
// the administrator's routing rules.
func TestSupportBackupOmitsPolicyRuleContent(t *testing.T) {
	_, r := newPolicyBackupRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, roleRequest(t, models.RoleSupport, http.MethodGet, "/api/settings/backup/download", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("Support backup download = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	body := w.Body.Bytes()
	payload, settings := backupExport(t, body)

	// Ordinary permitted metadata is still exported.
	appearance, ok := settings["appearance"].(map[string]any)
	if !ok {
		t.Fatalf("Support backup dropped the ordinary appearance section: %v", settings)
	}
	if title, _ := appearance["title"].(string); title != backupFixtureAppearanceTitle {
		t.Errorf("Support backup appearance title = %q, want %q", title, backupFixtureAppearanceTitle)
	}
	if version, _ := payload["format_version"].(float64); int(version) != 2 {
		t.Errorf("Support backup format_version = %v, want 2 (credential-free contract)", payload["format_version"])
	}
	if got := w.Header().Get("X-Backup-Credentials-Excluded"); got != "true" {
		t.Errorf("Support backup credentials marker = %q, want \"true\"", got)
	}

	// The administrator-only record must be absent from the exported settings.
	if _, present := settings[policy.SettingsKey]; present {
		t.Errorf("Support backup still exports the administrator-only %q record", policy.SettingsKey)
	}
	assertNoRuleContent(t, "Support backup", body)
}

// The neighbouring read of the same settings table (the general Settings API) is
// Admin-only since #909, so Support is refused outright. The refusal must carry
// no policy record or rule content. This keeps the boundary pinned on the
// adjacent path rather than only on the backup.
func TestSupportSettingsReadIsDeniedWithoutRuleContent(t *testing.T) {
	_, r := newPolicyBackupRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, roleRequest(t, models.RoleSupport, http.MethodGet, "/api/settings/", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("Support settings read = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte(policy.SettingsKey)) {
		t.Errorf("Support settings refusal exposes the %q record", policy.SettingsKey)
	}
	assertNoRuleContent(t, "Support settings refusal", w.Body.Bytes())
}

// The administrator keeps both authorized reads: the export keeps its current
// content and the dedicated policy API returns the saved rules.
func TestAdminKeepsPolicyRecordReads(t *testing.T) {
	_, r := newPolicyBackupRouter(t)

	wPolicy := httptest.NewRecorder()
	r.ServeHTTP(wPolicy, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	if wPolicy.Code != http.StatusOK {
		t.Fatalf("Admin GET /api/vpn/policy = %d, want 200; body=%s", wPolicy.Code, wPolicy.Body.String())
	}
	record := decodeJSON(t, wPolicy)
	entries, ok := record["proxy_exceptions"].([]any)
	if !ok {
		t.Fatalf("Admin policy read carries no proxy_exceptions: %v", record)
	}
	if len(entries) != len(backupFixtureRules) {
		t.Fatalf("Admin policy read returned %d proxy exceptions, want %d: %v", len(entries), len(backupFixtureRules), entries)
	}
	for i, want := range backupFixtureRules {
		if got, _ := entries[i].(string); got != want {
			t.Errorf("Admin policy proxy_exceptions[%d] = %q, want %q", i, got, want)
		}
	}

	wBackup := httptest.NewRecorder()
	r.ServeHTTP(wBackup, adminRequest(t, http.MethodGet, "/api/settings/backup/download", nil))
	if wBackup.Code != http.StatusOK {
		t.Fatalf("Admin backup download = %d, want 200; body=%s", wBackup.Code, wBackup.Body.String())
	}
	_, settings := backupExport(t, wBackup.Body.Bytes())
	if _, present := settings[policy.SettingsKey]; !present {
		t.Errorf("Admin backup no longer exports the %q record; administrators keep their current export content", policy.SettingsKey)
	}
}

// Roles below Support keep being refused, and the refusal carries no rule content.
func TestBackupDownloadRefusesNonPrivilegedCallers(t *testing.T) {
	_, r := newPolicyBackupRouter(t)

	wUser := httptest.NewRecorder()
	r.ServeHTTP(wUser, roleRequest(t, models.RoleUser, http.MethodGet, "/api/settings/backup/download", nil))
	if wUser.Code != http.StatusForbidden {
		t.Errorf("user backup download = %d, want 403; body=%s", wUser.Code, wUser.Body.String())
	}
	assertNoRuleContent(t, "user backup refusal", wUser.Body.Bytes())

	req := httptest.NewRequest(http.MethodGet, "/api/settings/backup/download", nil)
	ctx := middleware.WithCSRFToken(req.Context(), "token123")
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
	req.Header.Set(middleware.CSRFHeaderName, "token123")
	wAnon := httptest.NewRecorder()
	r.ServeHTTP(wAnon, req.WithContext(ctx))
	if wAnon.Code != http.StatusUnauthorized {
		t.Errorf("anonymous backup download = %d, want 401; body=%s", wAnon.Code, wAnon.Body.String())
	}
	assertNoRuleContent(t, "anonymous backup refusal", wAnon.Body.Bytes())
}

// The withdrawn field must not come back through a path that rebuilds the export
// from the whole settings table: assert the exported key set stays free of the
// record regardless of unrelated settings present in the same table.
func TestSupportBackupKeepsUnrelatedSettings(t *testing.T) {
	db, r := newPolicyBackupRouter(t)

	ctx := context.Background()
	if err := db.SetSetting(ctx, "limits", models.ConnectionLimits{}); err != nil {
		t.Fatalf("seed unrelated limits settings: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, roleRequest(t, models.RoleSupport, http.MethodGet, "/api/settings/backup/download", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("Support backup download = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	_, settings := backupExport(t, w.Body.Bytes())
	if _, present := settings["limits"]; !present {
		t.Errorf("Support backup dropped the unrelated limits section: %v", settings)
	}
	if _, present := settings[policy.SettingsKey]; present {
		t.Errorf("Support backup exports the administrator-only %q record", policy.SettingsKey)
	}
	if strings.Contains(w.Body.String(), backupFixtureRules[0]) {
		t.Errorf("Support backup discloses protected policy rule %q", backupFixtureRules[0])
	}
}
