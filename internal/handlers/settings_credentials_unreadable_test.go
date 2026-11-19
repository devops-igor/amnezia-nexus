package handlers

// A stored credential that is present but cannot be decrypted is not an empty one
// (#888). The settings write path carries a blank or masked credential field
// forward from the stored row. These tests seed valid JSON holding nonempty
// ciphertext produced under a different key, which is what a configuration-key
// mismatch looks like, and check three things at the write boundary: a save that
// has to carry that credential forward is refused and changes no row; a save that
// supplies replacement material still succeeds; and a request that does not touch
// the credential is not blocked by it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

const (
	foreignSecretKey = "a-different-secret-key-for-the-unreadable-fixtures"
	foreignKeyPlain  = "-----BEGIN PRIVATE KEY-----foreign-key-plaintext"
	foreignCertPlain = "-----BEGIN CERTIFICATE-----foreign-cert-plaintext"
	foreignAPIKey    = "flux_live_foreign_key_0123456789abcdef"
)

// foreignCipher encrypts under a key this panel does not have. The result is a
// well-formed Fernet token, so it looks like a stored credential and cannot be
// read.
func foreignCipher(t *testing.T, plain string) string {
	t.Helper()
	c, err := security.EncryptCredential(plain, foreignSecretKey)
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	if !security.LooksLikeFernetToken(c) {
		t.Fatalf("fixture is not token shaped: %q", c)
	}
	if _, err := security.DecryptCredential(c, testSecretKey); err == nil {
		t.Fatal("fixture is readable under the panel key, so it does not model an unreadable credential")
	}
	return c
}

// rawSettingRows returns every settings row as written, so a test can compare the
// bytes before and after a request, not a decoded view of them.
func rawSettingRows(t *testing.T, db *database.DB) map[string]string {
	t.Helper()
	rows, err := db.SQLDB().QueryContext(context.Background(), "SELECT key, COALESCE(value, '<null>') FROM settings")
	if err != nil {
		t.Fatalf("read raw rows: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func setRawSetting(t *testing.T, db *database.DB, key, value string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value); err != nil {
		t.Fatalf("seed raw %s: %v", key, err)
	}
}

func assertRowsUnchanged(t *testing.T, before, after map[string]string) {
	t.Helper()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("row %q changed:\n  before %q\n  after  %q", k, v, after[k])
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			t.Errorf("row %q appeared", k)
		}
	}
}

// seedUnreadableTLS stores an ssl row whose key and certificate are ciphertext
// under another key, next to readable ordinary rows.
func seedUnreadableTLS(t *testing.T, h *Handlers) {
	t.Helper()
	seedSettingsForPage(t, h)
	setRawSetting(t, h.db, "ssl", `{"enabled":false,"domain":"seed.example.test","cert_path":"","key_path":"","cert_text":"`+
		foreignCipher(t, foreignCertPlain)+`","key_text":"`+foreignCipher(t, foreignKeyPlain)+`","panel_port":5000}`)
}

// TestSaveSettings_UnreadableTLSIsNotReplacedByAnEmptyValue is the review's oracle:
// a save that leaves the TLS credential blank, with a second section in the same
// request, is refused with a non-200 and every raw row is byte-identical.
func TestSaveSettings_UnreadableTLSIsNotReplacedByAnEmptyValue(t *testing.T) {
	for _, tc := range []struct{ name, ssl string }{
		{"blank", `"cert_text":"","key_text":""`},
		{"masked", `"cert_text":"********","key_text":"********"`},
		{"key_blank_cert_supplied", `"cert_text":"-----BEGIN CERTIFICATE-----new","key_text":""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			seedUnreadableTLS(t, h)
			before := rawSettingRows(t, h.db)

			w := postSettingsSave(t, h, `{
				"appearance": {"title": "Written Beside A Refused Section", "logo": "L", "subtitle": "s", "language": "en"},
				"ssl": {"enabled": true, "domain": "changed.example.test", `+tc.ssl+`, "panel_port": 6000}
			}`)
			if w.Code == http.StatusOK {
				t.Fatalf("a save that would erase an unreadable credential returned 200: %s", w.Body.String())
			}
			if w.Code != http.StatusConflict {
				t.Errorf("status = %d, want 409: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, "credential_unreadable") {
				t.Errorf("the response does not name the failure: %s", body)
			}
			if !strings.Contains(body, "Nothing was saved") || !strings.Contains(body, "enter the value again") {
				t.Errorf("the response does not say what to do: %s", body)
			}
			for _, secret := range []string{foreignKeyPlain, foreignCertPlain} {
				if strings.Contains(body, secret) {
					t.Error("the response leaks credential plaintext")
				}
			}
			assertRowsUnchanged(t, before, rawSettingRows(t, h.db))
		})
	}
}

// TestSaveSettings_ReplacementMaterialRecoversAnUnreadableTLSCredential: a request
// that supplies both fields replaces the unreadable ones and succeeds. Without
// this, the refusal above would lock the operator out.
func TestSaveSettings_ReplacementMaterialRecoversAnUnreadableTLSCredential(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedUnreadableTLS(t, h)

	w := postSettingsSave(t, h, `{
		"appearance": {"title": "Recovered", "logo": "R", "subtitle": "r", "language": "en"},
		"ssl": {"enabled": false, "domain": "recovered.example.test",
			"cert_text": "-----BEGIN CERTIFICATE-----replacement", "key_text": "-----BEGIN PRIVATE KEY-----replacement", "panel_port": 5000}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("supplying replacement material = %d, want 200: %s", w.Code, w.Body.String())
	}
	var ssl models.SSLSettings
	if err := h.db.GetSetting(context.Background(), "ssl", &ssl); err != nil {
		t.Fatal(err)
	}
	if ssl.KeyText != "-----BEGIN PRIVATE KEY-----replacement" || ssl.CertText != "-----BEGIN CERTIFICATE-----replacement" {
		t.Errorf("the replacement was not stored and readable: key=%q cert=%q", ssl.KeyText, ssl.CertText)
	}
	if got := readStoredSettings(t, h).appearance.Title; got != "Recovered" {
		t.Errorf("the section beside it was not written: %q", got)
	}
}

// TestSaveSettings_OneUnreadableTLSFieldOnlyBlocksWhenItMustBeCarried: each field is
// judged on its own. Replacing the unreadable one while the other is readable and
// blank is fine; leaving an unreadable one blank is refused.
func TestSaveSettings_OneUnreadableTLSFieldOnlyBlocksWhenItMustBeCarried(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	readable, err := security.EncryptCredential("readable-cert-plaintext", testSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	setRawSetting(t, h.db, "ssl", `{"enabled":false,"domain":"d","cert_text":"`+readable+`","key_text":"`+foreignCipher(t, foreignKeyPlain)+`","panel_port":5000}`)

	before := rawSettingRows(t, h.db)
	w := postSettingsSave(t, h, `{"ssl": {"enabled": true, "domain": "d", "cert_text": "", "key_text": "", "panel_port": 5000}}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("the unreadable key left blank = %d, want 409: %s", w.Code, w.Body.String())
	}
	assertRowsUnchanged(t, before, rawSettingRows(t, h.db))

	w = postSettingsSave(t, h, `{"ssl": {"enabled": true, "domain": "d", "cert_text": "", "key_text": "-----BEGIN PRIVATE KEY-----new", "panel_port": 5000}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("replacing only the unreadable key = %d, want 200: %s", w.Code, w.Body.String())
	}
	var ssl models.SSLSettings
	_ = h.db.GetSetting(context.Background(), "ssl", &ssl)
	if ssl.CertText != "readable-cert-plaintext" || ssl.KeyText != "-----BEGIN PRIVATE KEY-----new" {
		t.Errorf("the readable certificate was not preserved beside the replaced key: cert=%q key=%q", ssl.CertText, ssl.KeyText)
	}
}

// TestSaveSettings_UnreadableCredentialDoesNotBlockASectionThatDoesNotTouchIt: a save
// that carries no ssl section never reads the ssl row, so an appearance save works
// while the TLS material is unreadable, and the row is left byte for byte.
func TestSaveSettings_UnreadableCredentialDoesNotBlockASectionThatDoesNotTouchIt(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedUnreadableTLS(t, h)
	sslBefore := rawSettingRows(t, h.db)["ssl"]

	w := postSettingsSave(t, h, `{"appearance": {"title": "Unrelated", "logo": "U", "subtitle": "u", "language": "en"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("an unrelated save = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := rawSettingRows(t, h.db)["ssl"]; got != sslBefore {
		t.Errorf("the untouched ssl row changed:\n  before %q\n  after  %q", sslBefore, got)
	}
}

// TestSaveSettings_UnreadableGigahostKeyIsNotReplacedByAnEmptyValue is the same
// boundary for the provider key, which has its own carry-forward path.
func TestSaveSettings_UnreadableGigahostKeyIsNotReplacedByAnEmptyValue(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"blank", `"api_key":""`},
		{"masked", `"api_key":"********"`},
		{"absent", `"other":"x"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			seedSettingsForPage(t, h)
			setRawSetting(t, h.db, "gigahost", `{"api_key":"`+foreignCipher(t, foreignAPIKey)+`"}`)
			before := rawSettingRows(t, h.db)

			w := postSettingsSave(t, h, `{
				"appearance": {"title": "Beside The Provider Key", "logo": "L", "subtitle": "s", "language": "en"},
				"gigahost": {`+tc.key+`}
			}`)
			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "Gigahost API key") {
				t.Errorf("the response does not name the credential: %s", w.Body.String())
			}
			assertRowsUnchanged(t, before, rawSettingRows(t, h.db))
		})
	}
}

// TestSaveSettings_ReplacementGigahostKeyRecoversAnUnreadableOne: supplying a key
// replaces the unreadable one.
func TestSaveSettings_ReplacementGigahostKeyRecoversAnUnreadableOne(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	setRawSetting(t, h.db, "gigahost", `{"api_key":"`+foreignCipher(t, foreignAPIKey)+`"}`)

	w := postSettingsSave(t, h, `{"gigahost": {"api_key": "flux_live_replacement_key_0123456789"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("replacing the key = %d, want 200: %s", w.Code, w.Body.String())
	}
	var gh map[string]any
	if err := h.db.GetSetting(context.Background(), "gigahost", &gh); err != nil {
		t.Fatal(err)
	}
	if gh["api_key"] != "flux_live_replacement_key_0123456789" {
		t.Errorf("the replacement key was not stored and readable: %v", gh["api_key"])
	}
}

// TestSaveSettings_ReadableCredentialsAreStillCarriedForward is the control: the
// strict read must not break the ordinary case it sits in front of.
func TestSaveSettings_ReadableCredentialsAreStillCarriedForward(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)

	w := postSettingsSave(t, h, `{"ssl": {"enabled": true, "domain": "kept.example.test", "cert_text": "", "key_text": "********", "panel_port": 5000}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a readable carry-forward = %d, want 200: %s", w.Code, w.Body.String())
	}
	after := readStoredSettings(t, h).ssl
	if after.KeyText != probeKeyText || after.CertText != probeCertText || after.Domain != "kept.example.test" {
		t.Errorf("readable credentials were not carried: %+v", after)
	}
}

// postNotificationSettings sends body to the real notification save handler as an
// administrator.
func postNotificationSettings(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/settings", strings.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin-1", Username: "admin", Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.SaveNotificationSettingsHandler(w, req)
	return w
}

// TestSaveNotificationSettings_UnreadableTokenIsNotReplacedByAnEmptyValue: the
// notification save reads the stored token through the same lossy decoder, so it
// has the same hole.
func TestSaveNotificationSettings_UnreadableTokenIsNotReplacedByAnEmptyValue(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	seedSettingsForPage(t, h)
	setRawSetting(t, h.db, "notifications", `{"enabled":false,"url":"https://gotify.example.test","app_token":"`+
		foreignCipher(t, "foreign-gotify-token")+`","min_severity":"info","cooldown_seconds":60,"max_attempts":6}`)
	before := rawSettingRows(t, h.db)

	w := postNotificationSettings(t, h, `{"enabled": false, "url": "https://gotify.example.test/changed", "app_token": "",
		"min_severity": "info", "cooldown_seconds": 60, "max_attempts": 6}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	assertRowsUnchanged(t, before, rawSettingRows(t, h.db))

	w = postNotificationSettings(t, h, `{"enabled": false, "url": "https://gotify.example.test/changed", "app_token": "replacement-token",
		"min_severity": "info", "cooldown_seconds": 60, "max_attempts": 6}`)
	if w.Code != http.StatusOK {
		t.Fatalf("supplying a replacement token = %d, want 200: %s", w.Code, w.Body.String())
	}
}
