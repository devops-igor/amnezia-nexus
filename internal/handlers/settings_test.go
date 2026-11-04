package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestSettingsHandlers(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	_ = db.SetSetting(ctx, "ssl", models.SSLSettings{
		KeyText:  "secret-key",
		CertText: "secret-cert",
	})

	r := setupFullSettingsRouter(h)
	adminSession := &models.SessionData{UserID: "settings-admin", Role: models.RoleAdmin}

	t.Run("GetSettingsHandler Masks Secrets", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		if ssl, ok := resp["ssl"].(map[string]any); ok {
			if ssl["key_text"] != "" || ssl["cert_text"] != "" {
				t.Errorf("expected masked ssl key and cert text")
			}
		}
	})

	t.Run("SaveSettingsHandler", func(t *testing.T) {
		body, _ := json.Marshal(models.SaveSettingsRequest{
			Appearance: models.AppearanceSettings{Title: "Amnezia Pro"},
			Captcha:    models.CaptchaSettings{Enabled: false},
			SSL:        models.SSLSettings{},
			Limits:     models.ConnectionLimits{MaxConnectionsPerUser: 15},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("SaveSettingsHandler With Telegram", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"appearance": map[string]any{"title": "TG Panel"},
			"captcha":    map[string]any{"enabled": false},
			"ssl":        map[string]any{},
			"limits":     map[string]any{"max_connections_per_user": 20},
			"telegram":   map[string]any{"bot_token": "123:abc", "chat_id": "456"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		// Verify telegram setting persisted
		var tg map[string]any
		_ = db.GetSetting(ctx, "telegram", &tg)
		if tg == nil || tg["bot_token"] != "123:abc" {
			t.Errorf("expected telegram settings persisted, got %v", tg)
		}
	})

	t.Run("DownloadBackupHandler", func(t *testing.T) {
		// Seed data so backup has content
		sBk := &models.Server{Name: "Backup-Server", Host: "1.2.3.4", SSHUser: "root", CreatedAt: time.Now()}
		sBkID, _ := db.CreateServer(ctx, sBk)
		uBk := &models.User{ID: "bk-user", Username: "bkuser", PasswordHash: "hash", Role: models.RoleUser, CreatedAt: time.Now()}
		_, _ = db.CreateUser(ctx, uBk)
		cBk := &models.UserConnection{ID: "bk-conn", UserID: uBk.ID, ServerID: sBkID, Protocol: "awg", ClientID: "bk-client", Name: "BK", CreatedAt: time.Now()}
		_, _ = db.CreateConnection(ctx, cBk)

		req := httptest.NewRequest(http.MethodGet, "/api/settings/backup/download", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", w.Header().Get("Content-Type"))
		}

		body := w.Body.String()
		if !strings.Contains(body, "Backup-Server") || !strings.Contains(body, "bkuser") || !strings.Contains(body, "bk-conn") {
			t.Errorf("expected backup to contain seeded entities")
		}
		if !strings.Contains(body, "Content-Disposition") && w.Header().Get("Content-Disposition") == "" {
			t.Logf("no content-disposition header (informational)")
		}
	})

	t.Run("RestoreBackupHandler Full JSON", func(t *testing.T) {
		nowStr := time.Now().Format(time.RFC3339)
		backup := models.BackupData{
			Settings: map[string]any{
				"appearance": map[string]any{"title": "Restored Amnezia"},
			},
			Servers: []map[string]any{
				{
					"id":        float64(10),
					"name":      "Restored Server",
					"host":      "10.0.0.99",
					"ssh_user":  "root",
					"ssh_port":  float64(22),
					"protocols": map[string]any{"awg": map[string]any{"installed": true}},
				},
			},
			Users: []map[string]any{
				{
					"id":                     "restored-u-1",
					"username":               "restoreduser",
					"role":                   "user",
					"enabled":                true,
					"email":                  "restored@example.com",
					"telegramId":             "9999",
					"description":            "restored desc",
					"share_token":            "stoken",
					"created_at":             nowStr,
					"traffic_limit":          float64(5000),
					"traffic_reset_strategy": "monthly",
					"share_enabled":          true,
					"awg_mimicry":            "auto",
				},
			},
			UserConnections: []map[string]any{
				{
					"id":          "restored-c-1",
					"user_id":     "restored-u-1",
					"server_id":   float64(10),
					"protocol":    "awg",
					"client_id":   "restored-client-1",
					"name":        "Restored Phone",
					"created_at":  nowStr,
					"awg_mimicry": "auto",
				},
			},
		}
		body, _ := json.Marshal(backup)
		req := httptest.NewRequest(http.MethodPost, "/api/settings/backup/restore", bytes.NewReader(body))
		req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
		}

		// Assert the restored entity counts programmatically.
		var resp struct {
			Status   string         `json:"status"`
			Restored map[string]int `json:"restored"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode restore response: %v (body: %s)", err, w.Body.String())
		}
		if resp.Status != "success" {
			t.Errorf("expected status success, got %q", resp.Status)
		}
		want := map[string]int{"servers": 1, "users": 1, "conns": 1, "settings": 1}
		for k, v := range want {
			if got := resp.Restored[k]; got != v {
				t.Errorf("restored[%s] = %d, want %d", k, got, v)
			}
		}
	})

	t.Run("RestoreBackupHandler Multipart", func(t *testing.T) {
		buf := new(bytes.Buffer)
		mw := multipart.NewWriter(buf)
		fw, _ := mw.CreateFormFile("file", "backup.json")
		_, _ = fw.Write([]byte(`{"settings": {"appearance": {"title": "Multipart Restored"}}}`))
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/api/settings/backup/restore", buf)
		req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
		req.Header.Set("Content-Type", mw.FormDataContentType())
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("SaveSettingsHandler Invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/settings/save", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	t.Run("RestoreBackupHandler Invalid & Empty JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/settings/backup/restore", bytes.NewReader([]byte("not-json")))
		req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}

		reqEmpty := httptest.NewRequest(http.MethodPost, "/api/settings/backup/restore", bytes.NewReader([]byte("")))
		reqEmpty = reqEmpty.WithContext(middleware.WithSession(reqEmpty.Context(), adminSession))
		wEmpty := httptest.NewRecorder()
		r.ServeHTTP(wEmpty, reqEmpty)
		if wEmpty.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", wEmpty.Code)
		}
	})

	t.Run("Helper Functions strVal int64Val boolVal mapFromInterface", func(t *testing.T) {
		if strVal(123) != "" || strVal("hello") != "hello" {
			t.Errorf("strVal failed")
		}
		if int64Val(int64(42)) != 42 || int64Val(float64(42)) != 42 || int64Val(int(42)) != 42 || int64Val("42") != 42 || int64Val(nil) != 0 {
			t.Errorf("int64Val failed")
		}
		if intVal("50") != 50 {
			t.Errorf("intVal failed")
		}
		if !boolVal(true) || boolVal(false) || !boolVal("true") || !boolVal("1") || boolVal("false") || !boolVal(float64(1)) || boolVal(float64(0)) || boolVal(nil) {
			t.Errorf("boolVal failed")
		}
		if m := mapFromInterface(map[string]any{"a": "b"}); m["a"] != "b" {
			t.Errorf("mapFromInterface failed")
		}
		if m := mapFromInterface(nil); len(m) != 0 {
			t.Errorf("mapFromInterface nil failed")
		}
	})
}

func TestSettingsSave_PreservesSSLCertAndSecrets(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	r := setupFullSettingsRouter(h)

	origKey := "PRIVATE_KEY_PLAINTEXT_SECRET"
	origCert := "CERTIFICATE_PLAINTEXT_DATA"
	origBotToken := "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"

	_ = db.SetSetting(ctx, "ssl", models.SSLSettings{
		Enabled:  true,
		Domain:   "panel.example.com",
		KeyText:  origKey,
		CertText: origCert,
	})
	_ = db.SetSetting(ctx, "telegram", map[string]any{
		"bot_token": origBotToken,
		"chat_id":   "987654321",
	})

	// 1. GET /api/settings - verify masking
	reqGet := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	wGet := httptest.NewRecorder()
	r.ServeHTTP(wGet, reqGet)

	if wGet.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /api/settings, got %d", wGet.Code)
	}

	var getResp map[string]any
	if err := json.Unmarshal(wGet.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to decode GET settings response: %v", err)
	}

	sslMap, _ := getResp["ssl"].(map[string]any)
	if sslMap["key_text"] != "" || sslMap["cert_text"] != "" {
		t.Fatalf("expected SSL KeyText/CertText to be empty string in GET response, got %v, %v", sslMap["key_text"], sslMap["cert_text"])
	}

	tgMap, _ := getResp["telegram"].(map[string]any)
	if tgMap["bot_token"] != "********" {
		t.Fatalf("expected telegram bot_token to be masked as ********, got %v", tgMap["bot_token"])
	}

	// 2. POST /api/settings/save with the masked payload (simulating frontend roundtrip)
	saveReqBody := map[string]any{
		"appearance": map[string]any{"title": "Updated Title"},
		"captcha":    map[string]any{"enabled": false},
		"ssl":        sslMap,
		"limits":     map[string]any{"max_connections_per_user": 20},
		"telegram":   tgMap,
	}
	saveJSON, _ := json.Marshal(saveReqBody)

	reqSave := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(saveJSON))
	wSave := httptest.NewRecorder()
	r.ServeHTTP(wSave, reqSave)

	if wSave.Code != http.StatusOK {
		t.Fatalf("expected 200 from POST /api/settings/save, got %d (body: %s)", wSave.Code, wSave.Body.String())
	}

	// 3. Verify in DB that original credentials were preserved and not overwritten with empty or ********
	var savedSSL models.SSLSettings
	_ = db.GetSetting(ctx, "ssl", &savedSSL)
	if savedSSL.KeyText != origKey {
		t.Errorf("expected SSL KeyText preserved %q, got %q", origKey, savedSSL.KeyText)
	}
	if savedSSL.CertText != origCert {
		t.Errorf("expected SSL CertText preserved %q, got %q", origCert, savedSSL.CertText)
	}

	var savedTG map[string]any
	_ = db.GetSetting(ctx, "telegram", &savedTG)
	if savedTG["bot_token"] != origBotToken {
		t.Errorf("expected telegram bot_token preserved %q, got %v", origBotToken, savedTG["bot_token"])
	}

	// 4. Test backup restore settings allowlist: malicious keys must be ignored
	backupData := &models.BackupData{
		Settings: map[string]any{
			"appearance":         map[string]any{"title": "Restored Title"},
			"malicious_injected": "should_be_ignored",
			"arbitrary_eval":     "evil_payload",
		},
	}
	restoredCount := h.restoreBackupSettings(ctx, backupData.Settings)
	if restoredCount != 1 {
		t.Errorf("expected only 1 allowlisted setting restored, got %d", restoredCount)
	}
	var injected any
	_ = db.GetSetting(ctx, "malicious_injected", &injected)
	if injected != nil {
		t.Errorf("expected malicious setting to not be stored, got %v", injected)
	}
}

func TestSaveSettingsHandler_GigahostRBAC(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	adminKey := "flux_live_admin_secret_key_0123456789abcdef0123456789abcdef01234567"
	supportKey := "flux_live_support_hacker_key_9999999999999999999999999999999999999"

	// Admin initially configures Gigahost setting
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"api_key": adminKey, "monthly_budget_nok": 500}); err != nil {
		t.Fatal(err)
	}

	// 1. Support user attempts to modify gigahost settings -> 403 Forbidden
	supportPayload, _ := json.Marshal(map[string]any{
		"gigahost": map[string]any{
			"api_key": supportKey,
		},
	})
	reqSupport := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(supportPayload))
	reqSupport = reqSupport.WithContext(middleware.WithSession(reqSupport.Context(), &models.SessionData{
		UserID: "support_user",
		Role:   models.RoleSupport,
	}))
	wSupport := httptest.NewRecorder()
	h.SaveSettingsHandler(wSupport, reqSupport)

	if wSupport.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for Support updating gigahost, got %d", wSupport.Code)
	}

	// Verify key was NOT overwritten
	var checkCfg map[string]any
	if err := db.GetSetting(ctx, "gigahost", &checkCfg); err != nil {
		t.Fatal(err)
	}
	if checkCfg["api_key"] != adminKey {
		t.Fatalf("Support user modified admin api_key! Got %v, want %v", checkCfg["api_key"], adminKey)
	}

	// 2. Support user can save appearance settings without gigahost -> 200 OK
	nonPrivPayload, _ := json.Marshal(map[string]any{
		"appearance": map[string]any{
			"title": "Support Theme",
		},
	})
	reqSupportOK := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(nonPrivPayload))
	reqSupportOK = reqSupportOK.WithContext(middleware.WithSession(reqSupportOK.Context(), &models.SessionData{
		UserID: "support_user",
		Role:   models.RoleSupport,
	}))
	wSupportOK := httptest.NewRecorder()
	h.SaveSettingsHandler(wSupportOK, reqSupportOK)

	if wSupportOK.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for Support updating appearance, got %d", wSupportOK.Code)
	}

	// 3. Admin user modifies gigahost settings -> 200 OK
	newAdminKey := "flux_live_new_admin_key_abcdefabcdefabcdefabcdefabcdefabcdefabcdef"
	adminPayload, _ := json.Marshal(map[string]any{
		"gigahost": map[string]any{
			"api_key": newAdminKey,
		},
	})
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/settings/save", bytes.NewReader(adminPayload))
	reqAdmin = reqAdmin.WithContext(middleware.WithSession(reqAdmin.Context(), &models.SessionData{
		UserID: "admin_user",
		Role:   models.RoleAdmin,
	}))
	wAdmin := httptest.NewRecorder()
	h.SaveSettingsHandler(wAdmin, reqAdmin)

	if wAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for Admin updating gigahost, got %d", wAdmin.Code)
	}

	if err := db.GetSetting(ctx, "gigahost", &checkCfg); err != nil {
		t.Fatal(err)
	}
	if checkCfg["api_key"] != newAdminKey {
		t.Fatalf("Admin update failed! Got %v, want %v", checkCfg["api_key"], newAdminKey)
	}
}
