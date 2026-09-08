package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/config"
	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/middleware"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/security"
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

// CaptchaHandler generates a new visual CAPTCHA challenge.
func (h *Handlers) CaptchaHandler(w http.ResponseWriter, r *http.Request) {
	if h.cfg == nil || h.cfg.SecretKey == "" {
		h.JSONError(w, http.StatusInternalServerError, "internal_error", "Session signing key not configured")
		return
	}

	captchaAnswer := generateCaptchaDigits(4)

	// Store answer in session
	sess := h.GetSession(r)
	if sess == nil {
		sess = &models.SessionData{}
	}
	sess.CaptchaAnswer = captchaAnswer
	_ = middleware.SetSessionCookie(w, sess, h.cfg.SecretKey, false, 3600)

	// Generate image
	imgBytes := generateCaptchaImage(captchaAnswer)
	imgB64 := base64.StdEncoding.EncodeToString(imgBytes)

	// Ensure response is never cached
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// If client specifically expects JSON response
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		h.JSON(w, http.StatusOK, map[string]any{
			"captcha_id": fmt.Sprintf("captcha-%d", time.Now().UnixNano()),
			"image":      fmt.Sprintf("data:image/png;base64,%s", imgB64),
		})
		return
	}

	// Default: return raw image stream for <img> tags
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(imgBytes)
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

	// Check CAPTCHA if enabled
	var captchaCfg models.CaptchaSettings
	if h.db != nil {
		_ = h.db.GetSetting(ctx, "captcha", &captchaCfg)
	}

	if captchaCfg.Enabled {
		sess := h.GetSession(r)
		expected := ""
		if sess != nil {
			expected = sess.CaptchaAnswer
		}

		if expected == "" || req.Captcha == nil || !strings.EqualFold(strings.TrimSpace(*req.Captcha), expected) {
			// Clear captcha answer to prevent replay
			if sess != nil {
				sess.CaptchaAnswer = ""
				_ = middleware.SetSessionCookie(w, sess, h.cfg.SecretKey, false, 3600)
			}
			h.JSONError(w, http.StatusBadRequest, "invalid_captcha", h.Translate(r, "invalid_captcha"))
			return
		}

		// Clear captcha answer after successful verification
		if sess != nil {
			sess.CaptchaAnswer = ""
			_ = middleware.SetSessionCookie(w, sess, h.cfg.SecretKey, false, 3600)
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
	sessionData := &models.SessionData{
		UserID:                 user.ID,
		Username:               user.Username,
		Role:                   user.Role,
		PasswordChangeRequired: user.PasswordChangeRequired,
		ShareAuthenticated:     make(map[string]bool),
	}

	if err := middleware.SetSessionCookie(w, sessionData, h.cfg.SecretKey, false, middleware.DefaultSessionMaxAge); err != nil {
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
		PasswordChangeRequired: false,
		ShareAuthenticated:     make(map[string]bool),
	}

	if h.cfg != nil && h.cfg.SecretKey != "" {
		_ = middleware.SetSessionCookie(w, sessionData, h.cfg.SecretKey, false, middleware.DefaultSessionMaxAge)
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

	// Update session cookie with password_change_required = false
	sess.PasswordChangeRequired = false
	if h.cfg != nil && h.cfg.SecretKey != "" {
		_ = middleware.SetSessionCookie(w, sess, h.cfg.SecretKey, false, middleware.DefaultSessionMaxAge)
	}

	h.audit(r, "auth.change_password", map[string]any{"user_id": user.ID, "username": user.Username})

	h.JSONOK(w, map[string]any{"message": "Password updated"})
}

var digitBitmaps = [10][7]uint8{
	// 0
	{0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
	// 1
	{0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
	// 2
	{0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
	// 3
	{0b01110, 0b10001, 0b00001, 0b00110, 0b00001, 0b10001, 0b01110},
	// 4
	{0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
	// 5
	{0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110},
	// 6
	{0b01110, 0b10000, 0b11110, 0b10001, 0b10001, 0b10001, 0b01110},
	// 7
	{0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
	// 8
	{0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
	// 9
	{0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110},
}

var captchaPalette = []color.RGBA{
	{R: 24, G: 68, B: 154, A: 255},  // Navy Blue
	{R: 180, G: 35, B: 24, A: 255},  // Crimson Red
	{R: 21, G: 128, B: 61, A: 255},  // Forest Green
	{R: 126, G: 34, B: 206, A: 255}, // Purple
	{R: 194, G: 65, B: 12, A: 255},  // Amber / Orange
	{R: 15, G: 118, B: 110, A: 255}, // Teal
}

func captchaRandInt(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func drawCaptchaLine(img *image.RGBA, x0, y0, x1, y1 int, col color.Color) {
	dx := x1 - x0
	if dx < 0 {
		dx = -dx
	}
	dy := y1 - y0
	if dy < 0 {
		dy = -dy
	}
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx - dy
	for {
		if x0 >= 0 && x0 < img.Bounds().Dx() && y0 >= 0 && y0 < img.Bounds().Dy() {
			img.Set(x0, y0, col)
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}

func generateCaptchaDigits(n int) string {
	digits := "0123456789"
	var sb strings.Builder
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			sb.WriteByte(digits[i%len(digits)])
			continue
		}
		sb.WriteByte(digits[idx.Int64()])
	}
	return sb.String()
}

func generateCaptchaImage(text string) []byte {
	width, height := 160, 60
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Background: light clean fill
	bg := color.RGBA{R: 248, G: 250, B: 252, A: 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)

	// Add background noise dots
	dotColor := color.RGBA{R: 203, G: 213, B: 225, A: 255}
	for j := 0; j < 60; j++ {
		nx := int(captchaRandInt(int64(width)))
		ny := int(captchaRandInt(int64(height)))
		img.Set(nx, ny, dotColor)
	}

	// Add subtle background interference lines
	lineColor := color.RGBA{R: 203, G: 213, B: 225, A: 200}
	for l := 0; l < 2; l++ {
		y0 := int(captchaRandInt(int64(height)))
		y1 := int(captchaRandInt(int64(height)))
		drawCaptchaLine(img, 0, y0, width-1, y1, lineColor)
	}

	// Draw characters using 5x7 bitmap font scaled 4x
	scale := 4
	n := len(text)
	if n == 0 {
		n = 4
	}
	digitWidth := 5 * scale
	totalDigitWidth := n * digitWidth
	remainingWidth := width - totalDigitWidth
	gap := remainingWidth / (n + 1)
	if gap < 2 {
		gap = 2
	}

	baseY := (height - 7*scale) / 2

	for i, c := range text {
		startX := gap + i*(digitWidth+gap)
		jitter := int(captchaRandInt(7)) - 3 // -3 to +3 pixels
		startY := baseY + jitter

		colorIdx := int(captchaRandInt(int64(len(captchaPalette))))
		fg := captchaPalette[colorIdx]

		var bitmap [7]uint8
		if c >= '0' && c <= '9' {
			bitmap = digitBitmaps[c-'0']
		} else {
			// Fallback: simple box outline for non-digits
			bitmap = [7]uint8{0b11111, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11111}
		}

		for row := 0; row < 7; row++ {
			bits := bitmap[row]
			for col := 0; col < 5; col++ {
				if (bits>>(4-col))&1 == 1 {
					for bx := 0; bx < scale; bx++ {
						for by := 0; by < scale; by++ {
							px := startX + col*scale + bx
							py := startY + row*scale + by
							if px >= 0 && px < width && py >= 0 && py < height {
								img.Set(px, py, fg)
							}
						}
					}
				}
			}
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
