package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/notifications"
)

const (
	notificationTestWait   = 15 * time.Second
	notificationTokenMask  = "********"
	maxNotificationHistory = 200
)

// GetNotificationSettingsHandler returns the notification policy with the
// application token masked. The plaintext token never leaves the server.
func (h *Handlers) GetNotificationSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r, "Admin privileges required to read notification settings") {
		return
	}
	svc := h.NotificationService()
	if svc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "notifications_unavailable", "Notification service is not configured")
		return
	}
	settings, err := svc.LoadSettings(r.Context())
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to load notification settings")
		return
	}
	h.JSON(w, http.StatusOK, notificationSettingsResponse(settings))
}

// SaveNotificationSettingsHandler validates and stores the administrator-owned
// delivery policy. Delivery stays off unless the administrator explicitly
// enables it with a valid destination and token.
func (h *Handlers) SaveNotificationSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r, "Admin privileges required to configure notifications") {
		return
	}
	svc := h.NotificationService()
	if svc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "notifications_unavailable", "Notification service is not configured")
		return
	}
	var req models.SaveNotificationSettingsRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}
	ctx := r.Context()
	current, err := svc.LoadSettings(ctx)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to load notification settings")
		return
	}

	settings := notificationSettingsFromRequest(req, current)
	if err := validateNotificationSettings(&settings); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if err := h.db.SetSetting(ctx, "notifications", settings); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to save notification settings")
		return
	}
	h.audit(r, "notifications.settings.save", map[string]any{
		"enabled": settings.Enabled,
		"url_set": settings.URL != "",
	})
	h.JSON(w, http.StatusOK, notificationSettingsResponse(settings))
}

// TestNotificationHandler sends one explicit administrator test through the
// durable event path and reports the real delivery outcome.
func (h *Handlers) TestNotificationHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r, "Admin privileges required to test notifications") {
		return
	}
	svc := h.NotificationService()
	if svc == nil {
		h.JSONError(w, http.StatusServiceUnavailable, "notifications_unavailable", "Notification service is not configured")
		return
	}
	summary := h.Translate(r, "notifications_test_summary")
	detail := h.Translate(r, "notifications_test_detail")
	if summary == "" || summary == "notifications_test_summary" {
		summary = "Amnezia Nexus test notification"
	}
	if detail == "" || detail == "notifications_test_detail" {
		detail = "This is an explicit administrator test, not a real incident."
	}

	eventID, err := svc.SendTest(r.Context(), summary, detail)
	if err != nil {
		h.JSONError(w, http.StatusBadRequest, "notifications_not_configured", err.Error())
		return
	}

	waitCtx, cancel := context.WithTimeout(r.Context(), notificationTestWait)
	defer cancel()
	delivery, err := svc.WaitForDelivery(waitCtx, eventID, 100*time.Millisecond)
	if err != nil {
		// The event is durable and the dispatcher may still deliver it. Report
		// the observed state and do not claim success.
		h.JSON(w, http.StatusGatewayTimeout, map[string]any{
			"error": map[string]any{
				"code":    "delivery_pending",
				"message": "Test notification is still pending; see history for the final outcome.",
			},
			"event_id": eventID,
			"delivery": delivery,
		})
		return
	}

	h.writeTestDelivery(w, r, eventID, delivery)
}

func (h *Handlers) writeTestDelivery(w http.ResponseWriter, r *http.Request, eventID string, delivery models.NotificationDelivery) {
	response := map[string]any{
		"event_id": eventID,
		"delivery": delivery,
		"status":   delivery.Status,
	}
	switch delivery.Status {
	case models.NotificationDeliverySent:
		response["status"] = "sent"
		h.audit(r, "notifications.test.sent", map[string]any{"event_id": eventID})
		h.JSON(w, http.StatusOK, response)
	case models.NotificationDeliverySuppressed, models.NotificationDeliveryDropped:
		response["reason"] = delivery.LastError
		h.JSON(w, http.StatusOK, response)
	default:
		response["reason"] = delivery.LastError
		if delivery.LastError == "" {
			response["reason"] = "gotify did not accept the test notification"
		}
		h.JSON(w, http.StatusBadGateway, response)
	}
}

// GetNotificationHistoryHandler returns bounded, administrator-only history
// with the truthful delivery outcome of each event.
func (h *Handlers) GetNotificationHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r, "Admin privileges required to read notification history") {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > maxNotificationHistory {
		limit = maxNotificationHistory
	}
	items, err := h.db.ListNotificationHistory(r.Context(), limit)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "database_error", "Failed to load notification history")
		return
	}
	if items == nil {
		items = []models.NotificationHistoryItem{}
	}
	h.JSON(w, http.StatusOK, map[string]any{"events": items})
}

func (h *Handlers) requireAdmin(w http.ResponseWriter, r *http.Request, message string) bool {
	sess := h.GetSession(r)
	if sess == nil || !sess.IsAdmin() {
		h.JSONError(w, http.StatusForbidden, "forbidden", message)
		return false
	}
	return true
}

func validateNotificationSettings(settings *models.NotificationSettings) error {
	if err := validateNotificationDestination(settings); err != nil {
		return err
	}
	if err := validateNotificationPolicy(settings); err != nil {
		return err
	}
	return validateNotificationLimits(settings)
}

func validateNotificationDestination(settings *models.NotificationSettings) error {
	if settings.Enabled && settings.URL == "" {
		return errNotification("gotify URL is required before enabling delivery")
	}
	if settings.Enabled && settings.AppToken == "" {
		return errNotification("gotify application token is required before enabling delivery")
	}
	if settings.URL == "" {
		return nil
	}
	_, err := notifications.ValidateEndpoint(settings.URL)
	return err
}

func validateNotificationPolicy(settings *models.NotificationSettings) error {
	if settings.MinSeverity == "" {
		settings.MinSeverity = models.NotificationSeverityInfo
	}
	if !settings.MinSeverity.Valid() {
		return errNotification("invalid minimum severity")
	}
	if settings.Categories == nil {
		settings.Categories = make(map[string]bool, len(models.NotificationCategories))
	}
	for _, category := range models.NotificationCategories {
		if _, ok := settings.Categories[string(category)]; !ok {
			settings.Categories[string(category)] = true
		}
	}
	for key := range settings.Categories {
		if !models.NotificationCategory(key).Valid() {
			return errNotification("unknown notification category: " + key)
		}
	}
	return nil
}

func validateNotificationLimits(settings *models.NotificationSettings) error {
	if settings.CooldownSeconds < 0 || settings.CooldownSeconds > 86400 {
		return errNotification("cooldown must be between 0 and 86400 seconds")
	}
	if settings.CooldownSeconds == 0 {
		settings.CooldownSeconds = 60
	}
	if settings.MaxAttempts < 1 || settings.MaxAttempts > 20 {
		return errNotification("max attempts must be between 1 and 20")
	}
	return nil
}

func notificationSettingsFromRequest(req models.SaveNotificationSettingsRequest, current models.NotificationSettings) models.NotificationSettings {
	settings := models.NotificationSettings{
		Enabled:         req.Enabled,
		URL:             strings.TrimSpace(req.URL),
		AppToken:        strings.TrimSpace(req.AppToken),
		MinSeverity:     req.MinSeverity,
		Categories:      req.Categories,
		CooldownSeconds: req.CooldownSeconds,
		MaxAttempts:     req.MaxAttempts,
	}
	if settings.AppToken == "" || settings.AppToken == notificationTokenMask || strings.HasPrefix(settings.AppToken, "****") {
		settings.AppToken = current.AppToken
	}
	// Omitted numeric fields keep the stored/effective policy instead of
	// rejecting a partial save from an older client.
	if req.MaxAttempts == 0 {
		settings.MaxAttempts = current.MaxAttempts
	}
	if req.CooldownSeconds == 0 {
		settings.CooldownSeconds = current.CooldownSeconds
	}
	return settings
}

func notificationSettingsResponse(settings models.NotificationSettings) models.NotificationSettingsResponse {
	categories := make(map[string]bool, len(models.NotificationCategories))
	for _, category := range models.NotificationCategories {
		categories[string(category)] = settings.CategoryEnabled(category)
	}
	return models.NotificationSettingsResponse{
		Enabled:         settings.Enabled,
		URL:             settings.URL,
		AppTokenSet:     strings.TrimSpace(settings.AppToken) != "",
		MinSeverity:     settings.MinSeverity,
		Categories:      categories,
		CooldownSeconds: settings.CooldownSeconds,
		MaxAttempts:     settings.MaxAttempts,
	}
}

type notificationValidationError string

func (e notificationValidationError) Error() string { return string(e) }

func errNotification(message string) error { return notificationValidationError(message) }
