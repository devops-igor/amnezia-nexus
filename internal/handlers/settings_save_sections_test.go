package handlers

// Tests for section ownership at the settings write boundary (#888).
//
// POST /api/settings/save writes only the sections the body carries. A section
// that is absent, or JSON null, is left as stored. A section sent as false, zero
// or empty is written. Multi-section writes are one transaction, and the stored
// credential behind a masked or empty field is read inside that transaction.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// postSettingsSave sends body to the real save handler as an administrator.
func postSettingsSave(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader([]byte(body)))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1", Username: "admin", Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.SaveSettingsHandler(w, req)
	return w
}

// storedSettings reads the four value sections and the credential-bearing
// telegram row straight from the database.
type storedSettings struct {
	appearance models.AppearanceSettings
	captcha    models.CaptchaSettings
	ssl        models.SSLSettings
	limits     models.ConnectionLimits
	telegram   map[string]any
}

func readStoredSettings(t *testing.T, h *Handlers) storedSettings {
	t.Helper()
	ctx := context.Background()
	s := storedSettings{telegram: map[string]any{}}
	for key, target := range map[string]any{
		"appearance": &s.appearance, "captcha": &s.captcha, "ssl": &s.ssl,
		"limits": &s.limits, "telegram": &s.telegram,
	} {
		if err := h.db.GetSetting(ctx, key, target); err != nil {
			t.Fatalf("read stored %s: %v", key, err)
		}
	}
	return s
}

// TestSaveSettings_OmittedSectionsStayAsStored: a card that posts only its own
// section must not zero the others.
func TestSaveSettings_OmittedSectionsStayAsStored(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	if err := h.db.SetSetting(context.Background(), "captcha", models.CaptchaSettings{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	before := readStoredSettings(t, h)

	w := postSettingsSave(t, h, `{"appearance":{"title":"Only Appearance","logo":"A","subtitle":"s","language":"en"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", w.Code, w.Body.String())
	}

	after := readStoredSettings(t, h)
	if after.appearance.Title != "Only Appearance" {
		t.Errorf("the section that was sent was not written: %+v", after.appearance)
	}
	if after.captcha != before.captcha || !after.captcha.Enabled {
		t.Errorf("an omitted captcha section changed: before %+v after %+v", before.captcha, after.captcha)
	}
	if after.ssl != before.ssl {
		t.Errorf("an omitted ssl section changed: before %+v after %+v", before.ssl, after.ssl)
	}
	if after.limits != before.limits {
		t.Errorf("an omitted limits section changed: before %+v after %+v", before.limits, after.limits)
	}
	if after.telegram["bot_token"] != probeBotToken {
		t.Errorf("an omitted telegram section changed: %v", after.telegram)
	}
}

// TestSaveSettings_ExplicitFalseAndZeroStillWrite: leaving a section out means
// leave it alone. Sending false, 0 or "" is a real value and is stored.
func TestSaveSettings_ExplicitFalseAndZeroStillWrite(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	ctx := context.Background()
	if err := h.db.SetSetting(ctx, "captcha", models.CaptchaSettings{Enabled: true}); err != nil {
		t.Fatal(err)
	}

	w := postSettingsSave(t, h, `{
		"captcha": {"enabled": false},
		"limits": {"max_connections_per_user": 0, "connection_rate_limit_count": 0, "connection_rate_limit_window": 0},
		"appearance": {"title": "", "logo": "", "subtitle": "", "language": "en"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", w.Code, w.Body.String())
	}

	after := readStoredSettings(t, h)
	if after.captcha.Enabled {
		t.Error("an explicit captcha false was not written")
	}
	if after.limits != (models.ConnectionLimits{}) {
		t.Errorf("explicit zero limits were not written: %+v", after.limits)
	}
	if after.appearance.Title != "" || after.appearance.Subtitle != "" {
		t.Errorf("explicit empty appearance text was not written: %+v", after.appearance)
	}
	if after.ssl.Domain != "seed.example.test" {
		t.Errorf("a section that was not sent changed: %+v", after.ssl)
	}
}

// TestSaveSettings_LegacyFullPayloadBehavesAsBefore: the page-level form sent all
// four value sections with the write-only fields empty or masked. Every section
// is written and the stored credentials are kept.
func TestSaveSettings_LegacyFullPayloadBehavesAsBefore(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)

	w := postSettingsSave(t, h, `{
		"appearance": {"title": "Legacy", "logo": "L", "subtitle": "ls", "language": "fr"},
		"captcha": {"enabled": true},
		"ssl": {"enabled": true, "domain": "legacy.example.test", "cert_path": "/c", "key_path": "/k",
			"cert_text": "", "key_text": "********", "panel_port": 6000},
		"limits": {"max_connections_per_user": 3, "connection_rate_limit_count": 2, "connection_rate_limit_window": 30},
		"telegram": {"enabled": false, "bot_token": "********", "chat_id": "-100legacy"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", w.Code, w.Body.String())
	}

	after := readStoredSettings(t, h)
	if after.appearance.Title != "Legacy" || after.appearance.Language != "fr" {
		t.Errorf("appearance: %+v", after.appearance)
	}
	if !after.captcha.Enabled {
		t.Error("captcha was not written")
	}
	if after.ssl.Domain != "legacy.example.test" || after.ssl.PanelPort != 6000 || !after.ssl.Enabled {
		t.Errorf("ssl fields: %+v", after.ssl)
	}
	if after.ssl.KeyText != probeKeyText || after.ssl.CertText != probeCertText {
		t.Errorf("an empty or masked TLS field erased the stored material: key=%q cert=%q", after.ssl.KeyText, after.ssl.CertText)
	}
	if after.limits != (models.ConnectionLimits{MaxConnectionsPerUser: 3, ConnectionRateLimitCount: 2, ConnectionRateLimitWindow: 30}) {
		t.Errorf("limits: %+v", after.limits)
	}
	if after.telegram["chat_id"] != "-100legacy" || after.telegram["bot_token"] != probeBotToken {
		t.Errorf("telegram: %v", after.telegram)
	}
}

// TestSaveSettings_NullSectionIsLeftAlone: null carries no values, so it is
// treated as not sent.
func TestSaveSettings_NullSectionIsLeftAlone(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	before := readStoredSettings(t, h)

	w := postSettingsSave(t, h, `{"captcha": null, "limits": null, "appearance": {"title":"N","logo":"","subtitle":"","language":"en"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", w.Code, w.Body.String())
	}
	after := readStoredSettings(t, h)
	if after.limits != before.limits || after.captcha != before.captcha {
		t.Errorf("a null section was written: limits %+v captcha %+v", after.limits, after.captcha)
	}
}

// TestSaveSettings_MalformedSectionWritesNothing: a section of the wrong shape is
// a validation error and no other section in the request is stored.
func TestSaveSettings_MalformedSectionWritesNothing(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	before := readStoredSettings(t, h)

	w := postSettingsSave(t, h, `{"appearance":{"title":"Should Not Land","logo":"","subtitle":"","language":"en"},"captcha":"yes"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a malformed section = %d, want 400", w.Code)
	}
	if got := readStoredSettings(t, h).appearance; got != before.appearance {
		t.Errorf("a rejected request still wrote appearance: %+v", got)
	}
}

// TestSaveSettings_WriteFaultMidwayChangesNothing: the limits row refuses the
// write, which is the last section stored. Appearance and captcha were already
// written inside the same transaction and must be rolled back.
func TestSaveSettings_WriteFaultMidwayChangesNothing(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	before := readStoredSettings(t, h)

	if _, err := h.db.ExecContext(context.Background(), `
		CREATE TRIGGER fail_limits_write BEFORE UPDATE ON settings
		WHEN NEW.key = 'limits'
		BEGIN SELECT RAISE(ABORT, 'injected limits write fault'); END`); err != nil {
		t.Fatalf("install fault: %v", err)
	}

	w := postSettingsSave(t, h, `{
		"appearance": {"title": "Half Written", "logo": "H", "subtitle": "h", "language": "en"},
		"captcha": {"enabled": true},
		"limits": {"max_connections_per_user": 99, "connection_rate_limit_count": 99, "connection_rate_limit_window": 99}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a failed write = %d, want 500: %s", w.Code, w.Body.String())
	}

	after := readStoredSettings(t, h)
	if after.appearance != before.appearance {
		t.Errorf("appearance was left half written: %+v", after.appearance)
	}
	if after.captcha != before.captcha {
		t.Errorf("captcha was left half written: %+v", after.captcha)
	}
	if after.limits != before.limits {
		t.Errorf("limits changed although its write failed: %+v", after.limits)
	}
}

// TestSaveSettings_ReadFaultChangesNothing: the stored TLS row cannot be read, so
// the credential behind an empty field is unknown. The save fails, and the
// sections sent beside it are not written.
func TestSaveSettings_ReadFaultChangesNothing(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	before := readStoredSettings(t, h)

	if _, err := h.db.ExecContext(context.Background(), `UPDATE settings SET value = 'not json' WHERE key = 'ssl'`); err != nil {
		t.Fatalf("corrupt ssl row: %v", err)
	}

	w := postSettingsSave(t, h, `{
		"appearance": {"title": "Read Fault", "logo": "R", "subtitle": "r", "language": "en"},
		"ssl": {"enabled": true, "domain": "x.example.test", "cert_text": "", "key_text": "", "panel_port": 1}
	}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("an unreadable stored row = %d, want 500: %s", w.Code, w.Body.String())
	}

	var title string
	if err := h.db.SQLDB().QueryRow(`SELECT json_extract(value, '$.title') FROM settings WHERE key = 'appearance'`).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if title != before.appearance.Title {
		t.Errorf("appearance was written although the credential read failed: %q", title)
	}
	var raw string
	if err := h.db.SQLDB().QueryRow(`SELECT value FROM settings WHERE key = 'ssl'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "not json" {
		t.Errorf("the unreadable ssl row was replaced: %q", raw)
	}
}

// TestSaveSettings_ConcurrentCardsBothSurvive: two requests for different
// sections, in flight together against one database, each keep their own change.
func TestSaveSettings_ConcurrentCardsBothSurvive(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)

	for round := 0; round < 10; round++ {
		start := make(chan struct{})
		var wg sync.WaitGroup
		codes := make([]int, 2)
		bodies := []string{
			`{"captcha":{"enabled":true}}`,
			`{"limits":{"max_connections_per_user":` + strings.Repeat("7", 1) + `,"connection_rate_limit_count":8,"connection_rate_limit_window":9}}`,
		}
		for i := range bodies {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				codes[i] = postSettingsSave(t, h, bodies[i]).Code
			}()
		}
		close(start)
		wg.Wait()
		for i, c := range codes {
			if c != http.StatusOK {
				t.Fatalf("round %d request %d = %d", round, i, c)
			}
		}
		after := readStoredSettings(t, h)
		if !after.captcha.Enabled || after.limits.MaxConnectionsPerUser != 7 {
			t.Fatalf("round %d lost a card's change: captcha %+v limits %+v", round, after.captcha, after.limits)
		}
		// Reset both so the next round starts from the same point.
		if err := h.db.SetSetting(context.Background(), "captcha", models.CaptchaSettings{}); err != nil {
			t.Fatal(err)
		}
		if err := h.db.SetSetting(context.Background(), "limits", models.ConnectionLimits{MaxConnectionsPerUser: 10, ConnectionRateLimitCount: 5, ConnectionRateLimitWindow: 60}); err != nil {
			t.Fatal(err)
		}
	}
}
