package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/captcha"
	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// LoginHandler renders the login HTML page or redirects authenticated users.
func (h *Handlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess != nil && sess.IsAuthenticated() {
		if sess.Role == models.RoleUser {
			http.Redirect(w, r, "/my", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	_ = RenderTemplate(w, r, h.db, "login.html", nil)
}

// LogoutHandler clears active session cookies and redirects to /login.
func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	h.audit(r, "auth.logout", nil)
	middleware.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// SetLangHandler sets preferred UI language cookie and redirects back safely.
func (h *Handlers) SetLangHandler(w http.ResponseWriter, r *http.Request) {
	lang := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "lang")))
	if !config.IsValidLanguage(lang) {
		lang = "en"
	}
	ref := CleanReferer(r.Header.Get("Referer"))

	// #nosec G124 -- Language preference cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "lang",
		Value:    lang,
		Path:     "/",
		MaxAge:   31536000,
		SameSite: http.SameSiteLaxMode,
	})
	// #nosec G124 -- Language preference cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "panel_lang",
		Value:    lang,
		Path:     "/",
		MaxAge:   31536000,
		SameSite: http.SameSiteLaxMode,
	})

	// #nosec G710,G116 -- Open redirect prevented by CleanReferer
	http.Redirect(w, r, ref, http.StatusFound)
}

// captchaStore returns the process-wide server-side captcha store, creating
// it on first use (issue #84: answers never leave the server).
func (h *Handlers) captchaStore() *captcha.Store {
	h.captchaOnce.Do(func() {
		h.captchaSt = captcha.NewStore()
	})
	return h.captchaSt
}

// CaptchaHandler issues a new slide puzzle bound to a signed session cookie.
func (h *Handlers) CaptchaHandler(w http.ResponseWriter, r *http.Request) {
	if h.cfg == nil || h.cfg.SecretKey == "" {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Session signing key not configured")
		return
	}

	challenge, err := captcha.GenerateSlide()
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to generate captcha")
		return
	}
	captchaID, err := h.captchaStore().NewSlide(challenge.TargetX, challenge.TargetY)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create captcha")
		return
	}

	// Only the opaque id is stored in the cookie; coordinates stay server-side.
	sess := h.GetSession(r)
	if sess == nil {
		sess = &models.SessionData{}
	}
	sess.CaptchaID = captchaID
	if err := middleware.SetSessionCookieForRequest(w, r, sess, h.cfg.SecretKey, 3600); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to store captcha session")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	// The browser E2E runner needs the answer for its real slider interaction.
	// Never expose it unless the explicitly enabled test environment is running.
	if strings.EqualFold(os.Getenv("E2E_TESTING"), "true") || os.Getenv("E2E_TESTING") == "1" {
		w.Header().Set("X-E2E-Captcha-Target-X", fmt.Sprint(challenge.TargetX))
	}
	h.JSON(w, http.StatusOK, map[string]any{
		"captcha_id": captchaID,
		"image":      challenge.Image,
		"thumb":      challenge.Thumb,
		"thumb_x":    challenge.ThumbX,
		"thumb_y":    challenge.ThumbY,
	})
}

// VerifyCaptchaHandler consumes one slide attempt and returns a one-time ticket.
func (h *Handlers) VerifyCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	if h.cfg == nil || h.cfg.SecretKey == "" {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Session signing key not configured")
		return
	}
	var req struct {
		CaptchaID string `json:"captcha_id"`
		Point     struct {
			X *int `json:"x"`
			Y *int `json:"y"`
		} `json:"point"`
	}
	if err := h.DecodeJSON(r, &req); err != nil || req.Point.X == nil || req.Point.Y == nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid captcha coordinates")
		return
	}
	sess := h.GetSession(r)
	if sess == nil || sess.CaptchaID == "" || (req.CaptchaID != "" && req.CaptchaID != sess.CaptchaID) {
		h.JSONError(w, http.StatusBadRequest, "invalid_captcha", h.Translate(r, "invalid_captcha"))
		return
	}
	ticket, ok, err := h.captchaStore().VerifySlide(sess.CaptchaID, *req.Point.X, *req.Point.Y)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to verify captcha")
		return
	}
	if !ok {
		h.JSONError(w, http.StatusBadRequest, "invalid_captcha", h.Translate(r, "invalid_captcha"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.JSON(w, http.StatusOK, map[string]any{"captcha_ticket": ticket})
}

// APILoginHandler handles user authentication requests.
func (h *Handlers) APILoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.cfg == nil || h.cfg.SecretKey == "" {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Session signing key not configured")
		return
	}

	var req models.LoginRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()

	// Check CAPTCHA if enabled. A settings read error must not disable the gate.
	var captchaCfg models.CaptchaSettings
	if h.db != nil {
		if err := h.db.GetSetting(ctx, "captcha", &captchaCfg); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to read captcha settings")
			return
		}
	}

	if captchaCfg.Enabled {
		sess := h.GetSession(r)
		captchaID := ""
		if sess != nil {
			captchaID = sess.CaptchaID
		}

		if captchaID == "" || req.CaptchaTicket == "" || !h.captchaStore().ConsumeTicket(captchaID, req.CaptchaTicket) {
			if sess != nil && sess.CaptchaID != "" {
				sess.CaptchaID = ""
				if err := middleware.SetSessionCookieForRequest(w, r, sess, h.cfg.SecretKey, 3600); err != nil {
					h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to clear captcha session")
					return
				}
			}
			h.JSONError(w, http.StatusBadRequest, "invalid_captcha", h.Translate(r, "invalid_captcha"))
			return
		}

		// The ticket is consumed even if credentials fail; clear the challenge id.
		if sess != nil {
			sess.CaptchaID = ""
			if err := middleware.SetSessionCookieForRequest(w, r, sess, h.cfg.SecretKey, 3600); err != nil {
				h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to clear captcha session")
				return
			}
		}
	}

	if h.db == nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Database not initialized")
		return
	}

	user, err := h.db.GetUserByUsername(ctx, req.Username)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", h.Translate(r, "invalid_login"))
		return
	}

	if !security.CheckPasswordHash(req.Password, user.PasswordHash) {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", h.Translate(r, "invalid_login"))
		return
	}

	if !user.Enabled {
		h.JSONError(w, http.StatusForbidden, "forbidden", h.Translate(r, "account_disabled"))
		return
	}

	// Create session data
	sessionVersion := user.SessionVersion
	if sessionVersion <= 0 {
		sessionVersion = 1
	}
	sessionData := &models.SessionData{
		UserID:                 user.ID,
		Username:               user.Username,
		Role:                   user.Role,
		SessionVersion:         sessionVersion,
		PasswordChangeRequired: user.PasswordChangeRequired,
		ShareAuthenticated:     make(map[string]bool),
	}

	if err := middleware.SetSessionCookieForRequest(w, r, sessionData, h.cfg.SecretKey, middleware.DefaultSessionMaxAge); err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create session")
		return
	}

	redirectURL := "/"
	if user.Role == models.RoleUser {
		redirectURL = "/my"
	}

	h.audit(r, "auth.login", map[string]any{"user_id": user.ID, "username": user.Username, "role": string(user.Role)})

	h.JSON(w, http.StatusOK, map[string]any{
		"status":                   "ok",
		"role":                     string(user.Role),
		"password_change_required": user.PasswordChangeRequired,
		"redirect":                 redirectURL,
	})
}

// APISetupHandler creates the initial administrator user on first run.
func (h *Handlers) APISetupHandler(w http.ResponseWriter, r *http.Request) {
	h.setupMu.Lock()
	defer h.setupMu.Unlock()

	var req models.SetupRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	ctx := r.Context()
	if h.db == nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Database not initialized")
		return
	}

	userCount, err := h.db.CountUsers(ctx)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to check existing users")
		return
	}

	if userCount > 0 {
		h.JSONError(w, http.StatusConflict, "setup_already_done", h.Translate(r, "setup_already_done"))
		return
	}

	hash, err := security.HashPassword(req.Password)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to hash password")
		return
	}

	adminUser := &models.User{
		ID:                     uuid.NewString(),
		Username:               req.Username,
		PasswordHash:           hash,
		Role:                   models.RoleAdmin,
		Enabled:                true,
		PasswordChangeRequired: false,
		SessionVersion:         1,
		CreatedAt:              time.Now(),
	}

	if _, err := h.db.CreateUser(ctx, adminUser); err != nil {
		if errors.Is(err, database.ErrUserAlreadyExists) || strings.Contains(err.Error(), "user already exists") || strings.Contains(err.Error(), "UNIQUE constraint") {
			h.JSONError(w, http.StatusConflict, "setup_already_done", h.Translate(r, "setup_already_done"))
			return
		}
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to create administrator account")
		return
	}

	middleware.InvalidateSetupCache()

	h.audit(r, "auth.setup", map[string]any{"user_id": adminUser.ID, "username": adminUser.Username})

	// Auto-login admin user
	sessionData := &models.SessionData{
		UserID:                 adminUser.ID,
		Username:               adminUser.Username,
		Role:                   adminUser.Role,
		SessionVersion:         1,
		PasswordChangeRequired: false,
		ShareAuthenticated:     make(map[string]bool),
	}

	if h.cfg != nil && h.cfg.SecretKey != "" {
		_ = middleware.SetSessionCookieForRequest(w, r, sessionData, h.cfg.SecretKey, middleware.DefaultSessionMaxAge)
	}

	h.JSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"role":     "admin",
		"redirect": "/",
	})
}

// APIChangePasswordHandler updates the password for the currently authenticated user.
func (h *Handlers) APIChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req models.ChangePasswordRequest
	if err := h.DecodeJSON(r, &req); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", "Invalid request body")
		return
	}

	if err := req.Validate(); err != nil {
		h.JSONError(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}

	sess := h.GetSession(r)
	if sess == nil || !sess.IsAuthenticated() {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	ctx := r.Context()
	user, err := h.db.GetUser(ctx, sess.UserID)
	if err != nil || user == nil {
		h.JSONError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	if !security.CheckPasswordHash(req.CurrentPassword, user.PasswordHash) {
		h.JSONError(w, http.StatusBadRequest, "invalid_password", h.Translate(r, "current_password_incorrect"))
		return
	}

	newHash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to hash new password")
		return
	}

	_, err = h.db.UpdateUser(ctx, user.ID, map[string]any{
		"password_hash":            newHash,
		"password_change_required": false,
	})
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update password")
		return
	}

	newVersion, err := h.db.BumpUserSessionVersion(ctx, user.ID)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to update session version")
		return
	}

	// Update session cookie with password_change_required = false and new session_version
	sess.PasswordChangeRequired = false
	sess.SessionVersion = newVersion
	if h.cfg != nil && h.cfg.SecretKey != "" {
		_ = middleware.SetSessionCookieForRequest(w, r, sess, h.cfg.SecretKey, middleware.DefaultSessionMaxAge)
	}

	h.audit(r, "auth.change_password", map[string]any{"user_id": user.ID, "username": user.Username})

	h.JSONOK(w, map[string]any{"message": "Password updated"})
}

// LogoutAllHandler invalidates all active sessions for the authenticated user and clears the session cookie.
func (h *Handlers) LogoutAllHandler(w http.ResponseWriter, r *http.Request) {
	sess := h.GetSession(r)
	if sess == nil || !sess.IsAuthenticated() {
		h.JSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	ctx := r.Context()
	if h.db != nil {
		if _, err := h.db.BumpUserSessionVersion(ctx, sess.UserID); err != nil {
			h.JSONError(w, http.StatusInternalServerError, "internal_error", "Failed to invalidate sessions")
			return
		}
	}

	h.audit(r, "auth.logout_all", map[string]any{"user_id": sess.UserID, "username": sess.Username})
	middleware.ClearSessionCookie(w)
	h.JSONOK(w, map[string]any{"message": "Logged out from all devices"})
}
