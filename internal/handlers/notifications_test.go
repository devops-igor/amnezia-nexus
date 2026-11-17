package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/notifications"
)

func notificationRequest(t *testing.T, h *Handlers, method, path string, body any, role models.UserRole) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "user-" + string(role),
		Username: "tester",
		Role:     role,
	}))
	w := httptest.NewRecorder()
	switch path {
	case "/api/notifications/settings":
		if method == http.MethodGet {
			h.GetNotificationSettingsHandler(w, req)
		} else {
			h.SaveNotificationSettingsHandler(w, req)
		}
	case "/api/notifications/test":
		h.TestNotificationHandler(w, req)
	case "/api/notifications/history":
		h.GetNotificationHistoryHandler(w, req)
	default:
		t.Fatalf("unknown path %s", path)
	}
	return w
}

func TestNotificationSettingsRejectNonAdmin(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/notifications/settings"},
		{http.MethodPost, "/api/notifications/settings"},
		{http.MethodPost, "/api/notifications/test"},
		{http.MethodGet, "/api/notifications/history"},
	}
	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			w := notificationRequest(t, h, endpoint.method, endpoint.path, nil, models.RoleSupport)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestSaveNotificationSettingsMasksAndPreservesToken(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	payload := map[string]any{
		"enabled":          true,
		"url":              "https://gotify.example.test",
		"app_token":        "token-value-123",
		"min_severity":     "warning",
		"cooldown_seconds": 30,
		"max_attempts":     4,
	}
	w := notificationRequest(t, h, http.MethodPost, "/api/notifications/settings", payload, models.RoleAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("save status = %d; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token-value-123") {
		t.Fatalf("save response echoed the token: %s", w.Body.String())
	}
	var response models.NotificationSettingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode save response: %v", err)
	}
	if !response.AppTokenSet || response.CooldownSeconds != 30 || response.MaxAttempts != 4 {
		t.Fatalf("save response = %#v", response)
	}

	var stored models.NotificationSettings
	if err := db.GetSetting(context.Background(), "notifications", &stored); err != nil {
		t.Fatalf("load stored settings: %v", err)
	}
	if stored.AppToken != "token-value-123" {
		t.Fatalf("stored token = %q", stored.AppToken)
	}

	payload["app_token"] = ""
	payload["min_severity"] = "info"
	w = notificationRequest(t, h, http.MethodPost, "/api/notifications/settings", payload, models.RoleAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("second save status = %d; body=%s", w.Code, w.Body.String())
	}
	if err := db.GetSetting(context.Background(), "notifications", &stored); err != nil {
		t.Fatalf("reload stored settings: %v", err)
	}
	if stored.AppToken != "token-value-123" {
		t.Fatalf("empty token erased the stored token: %q", stored.AppToken)
	}

	w = notificationRequest(t, h, http.MethodGet, "/api/notifications/settings", nil, models.RoleAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("read status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "token-value-123") {
		t.Fatalf("read response echoed the token: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"app_token_set":true`) {
		t.Fatalf("read response does not report the stored token: %s", w.Body.String())
	}
}

func TestSaveNotificationSettingsRejectsUnsafeDestination(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	payload := map[string]any{
		"enabled":   true,
		"url":       "http://169.254.169.254",
		"app_token": "token",
	}
	w := notificationRequest(t, h, http.MethodPost, "/api/notifications/settings", payload, models.RoleAdmin)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestTestNotificationUsesDurablePathAndReportsSent(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	received := make(chan string, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-Gotify-Key")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	svc := notifications.NewService(db, notifications.Options{
		PollInterval: 10 * time.Millisecond,
		Backoff:      func(int) time.Duration { return time.Millisecond },
	})
	h.notificationSvc = svc
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = svc.Start(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("notification service did not stop")
		}
	})

	payload := map[string]any{
		"enabled":   true,
		"url":       receiver.URL,
		"app_token": "test-token",
	}
	if w := notificationRequest(t, h, http.MethodPost, "/api/notifications/settings", payload, models.RoleAdmin); w.Code != http.StatusOK {
		t.Fatalf("save status = %d; body=%s", w.Code, w.Body.String())
	}

	w := notificationRequest(t, h, http.MethodPost, "/api/notifications/test", nil, models.RoleAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("test status = %d; body=%s", w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode test response: %v", err)
	}
	if response["status"] != "sent" {
		t.Fatalf("test response = %#v, want sent", response)
	}
	select {
	case token := <-received:
		if token != "test-token" {
			t.Fatalf("receiver token = %q", token)
		}
	case <-time.After(time.Second):
		t.Fatal("test notification never reached the receiver")
	}

	w = notificationRequest(t, h, http.MethodGet, "/api/notifications/history", nil, models.RoleAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("history status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"sent"`) {
		t.Fatalf("history does not record the sent outcome: %s", w.Body.String())
	}
}

func TestNotificationHandlersFailClosedWithoutService(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.notificationSvc = nil
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/notifications/settings"},
		{http.MethodPost, "/api/notifications/settings"},
		{http.MethodPost, "/api/notifications/test"},
	}
	for _, endpoint := range endpoints {
		w := notificationRequest(t, h, endpoint.method, endpoint.path, nil, models.RoleAdmin)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s status = %d, want 503", endpoint.method, endpoint.path, w.Code)
		}
	}
}

func TestTestNotificationReportsDeliveryFailure(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(receiver.Close)
	svc := notifications.NewService(db, notifications.Options{
		PollInterval: 10 * time.Millisecond,
		Backoff:      func(int) time.Duration { return time.Millisecond },
	})
	h.notificationSvc = svc
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = svc.Start(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	payload := map[string]any{"enabled": true, "url": receiver.URL, "app_token": "bad-token", "max_attempts": 1}
	if w := notificationRequest(t, h, http.MethodPost, "/api/notifications/settings", payload, models.RoleAdmin); w.Code != http.StatusOK {
		t.Fatalf("save status = %d; body=%s", w.Code, w.Body.String())
	}
	w := notificationRequest(t, h, http.MethodPost, "/api/notifications/test", nil, models.RoleAdmin)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"failed"`) {
		t.Fatalf("failure was not reported truthfully: %s", w.Body.String())
	}
}

func TestNotificationHistoryClampsLimit(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/history?limit=9999", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "admin", Username: "admin", Role: models.RoleAdmin,
	}))
	w := httptest.NewRecorder()
	h.GetNotificationHistoryHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"events":[]`) {
		t.Fatalf("body = %s", w.Body.String())
	}
}

func TestTestNotificationWithoutDestinationIsRefused(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	w := notificationRequest(t, h, http.MethodPost, "/api/notifications/test", nil, models.RoleAdmin)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestConfirmedOrderAcceptedClassification(t *testing.T) {
	tests := []struct {
		name  string
		order *models.GigahostOrder
		want  bool
	}{
		{name: "waiting", order: &models.GigahostOrder{OrderID: "ord_1", Status: "waiting"}, want: true},
		{name: "deploying", order: &models.GigahostOrder{OrderID: "ord_2", Status: "deploying"}, want: true},
		{name: "ready", order: &models.GigahostOrder{OrderID: "ord_3", Status: "ready"}, want: true},
		{name: "intent row", order: &models.GigahostOrder{OrderID: "intent_123", Status: "waiting"}, want: false},
		{name: "unknown", order: &models.GigahostOrder{OrderID: "ord_4", Status: "unknown"}, want: false},
		{name: "failed", order: &models.GigahostOrder{OrderID: "ord_5", Status: "failed"}, want: false},
		{name: "pending order", order: &models.GigahostOrder{OrderID: "ord_6", Status: "pending_order"}, want: false},
		{name: "empty id", order: &models.GigahostOrder{Status: "waiting"}, want: false},
		{name: "nil", order: nil, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := confirmedOrderAccepted(tc.order); got != tc.want {
				t.Fatalf("confirmedOrderAccepted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPublishOrderAcceptedIsIdempotent(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	order := &models.GigahostOrder{OrderID: "ord_accepted", Status: "waiting", CreatedAt: time.Now().UTC()}
	h.publishOrderAccepted(ctx, order)
	h.publishOrderAccepted(ctx, order)

	history, err := db.ListNotificationHistory(ctx, 20)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var accepted int
	for _, item := range history {
		if item.Event.Type == "order.accepted" {
			accepted++
			if item.Event.EntityID != order.OrderID {
				t.Fatalf("accepted event entity = %q", item.Event.EntityID)
			}
		}
	}
	if accepted != 1 {
		t.Fatalf("order.accepted events = %d, want exactly 1", accepted)
	}
}

func TestNotificationSettingsPersistAcrossReopen(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "reopen.db")
	db, err := database.Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	settings := models.DefaultNotificationSettings()
	settings.Enabled = true
	settings.URL = "https://gotify.example.test"
	settings.AppToken = "persisted-token"
	if err := db.SetSetting(context.Background(), "notifications", settings); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := database.Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	var loaded models.NotificationSettings
	if err := reopened.GetSetting(context.Background(), "notifications", &loaded); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.Enabled || loaded.AppToken != "persisted-token" {
		t.Fatalf("reopened settings = %#v", loaded)
	}
}
