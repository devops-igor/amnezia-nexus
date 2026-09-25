package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func TestCaptchaChallengeBoundToCookie(t *testing.T) {
	t.Setenv("E2E_TESTING", "false")
	h, _, cfg := setupTestHandlers(t)
	rec := httptest.NewRecorder()
	h.CaptchaHandler(rec, httptest.NewRequest(http.MethodGet, "/api/auth/captcha", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("challenge response: %d, %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-E2E-Captcha-Target-X") != "" {
		t.Fatal("server target leaked outside E2E testing")
	}
	var payload struct {
		CaptchaID string `json:"captcha_id"`
		Image     string `json:"image"`
		Thumb     string `json:"thumb"`
		ThumbY    int    `json:"thumb_y"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CaptchaID == "" || !strings.HasPrefix(payload.Image, "data:image/jpeg;base64,") ||
		!strings.HasPrefix(payload.Thumb, "data:image/png;base64,") {
		t.Fatal("missing slide puzzle image or identifier")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("target_x")) || bytes.Contains(rec.Body.Bytes(), []byte("target_y")) {
		t.Fatal("server target leaked to client")
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no signed guest session")
	}
	data, err := security.DecodeSession(sessionCookie.Value, cfg.SecretKey)
	if err != nil || data["captcha_id"] != payload.CaptchaID {
		t.Fatalf("challenge not bound to session cookie: %v", err)
	}
}

func TestCaptchaE2ETargetMatchesDisplayedChallenge(t *testing.T) {
	t.Setenv("E2E_TESTING", "true")
	h, _, _ := setupTestHandlers(t)
	rec := httptest.NewRecorder()
	h.CaptchaHandler(rec, httptest.NewRequest(http.MethodGet, "/api/auth/captcha", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge response: %d, %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		CaptchaID string `json:"captcha_id"`
		ThumbY    int    `json:"thumb_y"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	targetX, err := strconv.Atoi(rec.Header().Get("X-E2E-Captcha-Target-X"))
	if err != nil {
		t.Fatalf("missing E2E target header: %v", err)
	}
	if _, ok, err := h.captchaStore().VerifySlide(payload.CaptchaID, targetX, payload.ThumbY); err != nil || !ok {
		t.Fatalf("E2E target does not match generated puzzle: ok=%v, err=%v", ok, err)
	}
}

func TestCaptchaVerificationAndLoginTicket(t *testing.T) {
	h, db, cfg := setupTestHandlers(t)
	hash, err := security.HashPassword("AdminPass123!")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser(context.Background(), &models.User{
		ID: "captcha-admin", Username: "admin", PasswordHash: hash,
		Role: models.RoleAdmin, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(context.Background(), "captcha", models.CaptchaSettings{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	issue := func(t *testing.T) *http.Cookie {
		t.Helper()
		id, err := h.captchaStore().NewSlide(120, 48)
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := security.EncodeSession((&models.SessionData{CaptchaID: id}).ToMap(), cfg.SecretKey)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: middleware.SessionCookieName, Value: cookie}
	}
	serveVerify := func(cookie *http.Cookie, x, y int) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"point": map[string]int{"x": x, "y": y}})
		r := httptest.NewRequest(http.MethodPost, "/api/auth/captcha/verify", bytes.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		middleware.Session(cfg.SecretKey)(http.HandlerFunc(h.VerifyCaptchaHandler)).ServeHTTP(rec, r)
		return rec
	}
	badCookie := issue(t)
	if rec := serveVerify(badCookie, 125, 48); rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-tolerance attempt: %d", rec.Code)
	}
	if rec := serveVerify(badCookie, 120, 48); rec.Code != http.StatusBadRequest {
		t.Fatal("incorrect attempt did not consume challenge")
	}
	goodCookie := issue(t)
	if rec := serveVerify(nil, 120, 48); rec.Code != http.StatusBadRequest {
		t.Fatal("verification without signed session succeeded")
	}
	rec := serveVerify(goodCookie, 120, 48)
	if rec.Code != http.StatusOK {
		t.Fatalf("verification: %d %s", rec.Code, rec.Body.String())
	}
	var verified struct {
		Ticket string `json:"captcha_ticket"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &verified); err != nil || verified.Ticket == "" {
		t.Fatal("missing verified ticket", err)
	}
	login := func(cookie *http.Cookie, ticket string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(models.LoginRequest{Username: "admin", Password: "AdminPass123!", CaptchaTicket: ticket})
		r := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		r.AddCookie(cookie)
		out := httptest.NewRecorder()
		middleware.Session(cfg.SecretKey)(http.HandlerFunc(h.APILoginHandler)).ServeHTTP(out, r)
		return out
	}
	if out := login(goodCookie, verified.Ticket); out.Code != http.StatusOK {
		t.Fatalf("login: %d %s", out.Code, out.Body.String())
	}
	if out := login(goodCookie, verified.Ticket); out.Code != http.StatusBadRequest {
		t.Fatalf("ticket replay: %d", out.Code)
	}
	otherCookie := issue(t)
	otherVerified := serveVerify(otherCookie, 120, 48)
	if otherVerified.Code != http.StatusOK {
		t.Fatal("second verification failed")
	}
	var other struct {
		Ticket string `json:"captcha_ticket"`
	}
	if err := json.Unmarshal(otherVerified.Body.Bytes(), &other); err != nil {
		t.Fatal(err)
	}
	if out := login(goodCookie, other.Ticket); out.Code != http.StatusBadRequest {
		t.Fatalf("cross-session ticket accepted: %d", out.Code)
	}
}
