package handlers

// The rendered Settings page and the JSON settings API are two read paths over
// the same stored settings. These tests pin that the page obeys the same secret
// policy as the API: a stored credential never appears anywhere in the document,
// for either role allowed to open /settings, and the masked values the page does
// render still round-trip through save without erasing the stored secret.

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Neutral probe values. They contain only characters that HTML escaping leaves
// untouched, so an absent probe cannot be an escaping artefact.
const (
	probeBotToken = "probe-bot-token-5c1e7a"
	probeAltToken = "probe-alt-token-9d2b40"
	probeKeyText  = "probe-ssl-key-text-3f8a12"
	probeCertText = "probe-ssl-cert-text-7b6e55"
	probeGHKey    = "probe-gigahost-key-1a4c98"
)

func seedProbeSecrets(t *testing.T, h *Handlers) {
	t.Helper()
	ctx := context.Background()
	if err := h.db.SetSetting(ctx, "telegram", map[string]any{
		"enabled":   true,
		"bot_token": probeBotToken,
		"token":     probeAltToken,
		"chat_id":   "-1001234",
	}); err != nil {
		t.Fatalf("seed telegram: %v", err)
	}
	if err := h.db.SetSetting(ctx, "ssl", models.SSLSettings{
		Enabled:  true,
		Domain:   "panel.example.test",
		KeyText:  probeKeyText,
		CertText: probeCertText,
	}); err != nil {
		t.Fatalf("seed ssl: %v", err)
	}
	if err := h.db.SetSetting(ctx, "gigahost", map[string]any{"api_key": probeGHKey}); err != nil {
		t.Fatalf("seed gigahost: %v", err)
	}
}

func renderSettingsPageFor(t *testing.T, h *Handlers, role models.UserRole) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "user-1", Username: string(role), Role: role,
	})
	ctx = middleware.WithCSRFToken(ctx, "csrf-test-token")
	w := httptest.NewRecorder()
	h.SettingsPageHandler(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /settings as %s = %d, want 200", role, w.Code)
	}
	return w.Body.String()
}

// TestSettingsPageDoesNotRenderStoredSecrets asserts on the whole document, not
// on an input type or a CSS class: the secret text must be absent from the bytes
// the browser receives.
func TestSettingsPageDoesNotRenderStoredSecrets(t *testing.T) {
	probes := map[string]string{
		"telegram bot_token": probeBotToken,
		"telegram token":     probeAltToken,
		"ssl key_text":       probeKeyText,
		"ssl cert_text":      probeCertText,
		"gigahost api_key":   probeGHKey,
	}
	for _, role := range []models.UserRole{models.RoleAdmin, models.RoleSupport} {
		t.Run(string(role), func(t *testing.T) {
			h, _, _ := setupTestHandlers(t)
			seedProbeSecrets(t, h)
			body := renderSettingsPageFor(t, h, role)
			for name, probe := range probes {
				if strings.Contains(body, probe) {
					t.Errorf("%s: stored %s is present in the rendered settings page", role, name)
				}
			}
			// Ordinary settings stay visible, so the page is not simply blank.
			if !strings.Contains(body, "panel.example.test") || !strings.Contains(body, "-1001234") {
				t.Errorf("%s: non-secret settings (ssl domain, telegram chat id) are missing from the page", role)
			}
		})
	}
}

var (
	pageBotTokenInput = regexp.MustCompile(`id="telegram_bot_token"[^>]*\svalue="([^"]*)"`)
	pageCertTextArea  = regexp.MustCompile(`(?s)<textarea[^>]*id="ssl_cert_text"[^>]*>(.*?)</textarea>`)
	pageKeyTextArea   = regexp.MustCompile(`(?s)<textarea[^>]*id="ssl_key_text"[^>]*>(.*?)</textarea>`)
)

// TestSettingsPageValuesRoundTripWithoutErasingSecrets feeds exactly what the
// page rendered back through the real save handler, as the page script does, and
// requires the stored secrets to survive.
func TestSettingsPageValuesRoundTripWithoutErasingSecrets(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	seedProbeSecrets(t, h)
	body := renderSettingsPageFor(t, h, models.RoleSupport)

	m := pageBotTokenInput.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("telegram_bot_token input with a value attribute not found in page")
	}
	renderedToken := html.UnescapeString(m[1])
	if renderedToken != "********" {
		t.Fatalf("rendered bot token value = %q, want the mask sentinel", renderedToken)
	}
	certArea := pageCertTextArea.FindStringSubmatch(body)
	keyArea := pageKeyTextArea.FindStringSubmatch(body)
	if certArea == nil || keyArea == nil {
		t.Fatalf("ssl textareas not found in page")
	}

	payload := map[string]any{
		"appearance": map[string]any{"title": "Updated Title"},
		"captcha":    map[string]any{"enabled": false},
		"limits":     map[string]any{"max_connections_per_user": 20},
		"telegram":   map[string]any{"enabled": true, "bot_token": renderedToken, "chat_id": "-1001234"},
		"ssl": map[string]any{
			"enabled":   true,
			"domain":    "panel.example.test",
			"cert_text": strings.TrimSpace(html.UnescapeString(certArea[1])),
			"key_text":  strings.TrimSpace(html.UnescapeString(keyArea[1])),
		},
	}
	raw, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	setupFullSettingsRouter(h).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("save = %d, body %s", w.Code, w.Body.String())
	}

	ctx := context.Background()
	var ssl models.SSLSettings
	_ = db.GetSetting(ctx, "ssl", &ssl)
	if ssl.KeyText != probeKeyText || ssl.CertText != probeCertText {
		t.Errorf("ssl material not preserved: key=%q cert=%q", ssl.KeyText, ssl.CertText)
	}
	tg := map[string]any{}
	_ = db.GetSetting(ctx, "telegram", &tg)
	if tg["bot_token"] != probeBotToken {
		t.Errorf("telegram bot_token not preserved: %#v", tg["bot_token"])
	}
	if tg["token"] != probeAltToken {
		t.Errorf("telegram token not preserved: %#v", tg["token"])
	}
}

// TestSettingsPageAndAPIShareMaskPolicy keeps the two read paths from drifting:
// for every section that carries a secret, what the page template receives must
// equal what the API returns.
func TestSettingsPageAndAPIShareMaskPolicy(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	seedProbeSecrets(t, h)
	ctx := context.Background()

	w := httptest.NewRecorder()
	setupFullSettingsRouter(h).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	var api map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &api); err != nil {
		t.Fatalf("decode api: %v", err)
	}

	all, err := db.GetAllSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	maskSettingsSecrets(all)
	for _, section := range []string{"telegram", "ssl", "gigahost"} {
		var page map[string]any
		raw, _ := json.Marshal(all[section])
		_ = json.Unmarshal(raw, &page)
		if !reflect.DeepEqual(page, api[section]) {
			t.Errorf("section %q differs between page and API:\n page: %#v\n api:  %#v", section, page, api[section])
		}
	}
}
