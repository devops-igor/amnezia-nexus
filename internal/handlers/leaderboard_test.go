package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/middleware"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

func TestLeaderboardHandler(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	u := &models.User{
		ID:           "u-lb-1",
		Username:     "speeddemon",
		PasswordHash: "hash",
		Role:         models.RoleUser,
		Enabled:      true,
		TrafficTotal: 5000000000,
		CreatedAt:    time.Now(),
	}
	_, _ = db.CreateUser(ctx, u)

	periods := []string{"all-time", "monthly", "last-month", "invalid-period", ""}
	for _, p := range periods {
		t.Run("Period_"+p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/leaderboard?period="+p, nil)
			w := httptest.NewRecorder()
			h.LeaderboardHandler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}
		})
	}

	t.Run("Monthly Label Present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/leaderboard?period=monthly", nil)
		w := httptest.NewRecorder()
		h.LeaderboardHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		body := w.Body.String()
		if body == "" {
			t.Errorf("expected non-empty body")
		}
	})

	t.Run("Last-Month Label Present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/leaderboard?period=last-month", nil)
		w := httptest.NewRecorder()
		h.LeaderboardHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("CurrentUserRank Identified", func(t *testing.T) {
		sess := &models.SessionData{
			UserID:   u.ID,
			Username: "speeddemon",
			Role:     models.RoleUser,
		}
		req := httptest.NewRequest(http.MethodGet, "/api/leaderboard", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		h.LeaderboardHandler(w, req.WithContext(reqCtx))
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}

func TestLeaderboardHandler_LastMonth_Regression(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Create a user with heavy all-time traffic
	u := &models.User{
		ID:                   "u-regress-1",
		Username:             "speeddemon",
		PasswordHash:         "hash",
		Role:                 models.RoleUser,
		Enabled:              true,
		TrafficResetStrategy: models.ResetStrategyMonthly,
		CreatedAt:            time.Now(),
	}
	uID, err := db.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	// Give user 10 GB all-time traffic and 2 GB monthly traffic
	_ = db.UpdateUserTraffic(ctx, uID, 5000000000, 5000000000)

	now := time.Now()
	prev := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, -1, 0)
	expectedLabel := prev.Format("January 2006")

	sess := &models.SessionData{
		UserID:   uID,
		Username: "speeddemon",
		Role:     models.RoleUser,
	}

	t.Run("No snapshot returns empty entries slice not all-time traffic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/leaderboard?period=last-month", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		h.LeaderboardHandler(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		rawJSON := w.Body.String()
		// Ensure entries is serialized as [] rather than null
		if !strings.Contains(rawJSON, `"entries":[]`) {
			t.Errorf("expected JSON to contain '\"entries\":[]', got: %s", rawJSON)
		}

		var resp models.LeaderboardResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}

		if resp.Period != "last-month" {
			t.Errorf("expected period 'last-month', got %q", resp.Period)
		}
		if resp.MonthlyLabel == nil || *resp.MonthlyLabel != expectedLabel {
			t.Errorf("expected monthly_label %q, got %v", expectedLabel, resp.MonthlyLabel)
		}
		if resp.CurrentUserRank != nil {
			t.Errorf("expected CurrentUserRank nil when empty, got %v", *resp.CurrentUserRank)
		}
		if len(resp.Entries) != 0 {
			t.Errorf("expected 0 entries (no snapshot), got %d (all-time traffic leaked into last-month!)", len(resp.Entries))
		}
	})

	t.Run("Snapshot present returns snapshot data with user rank", func(t *testing.T) {
		// Insert snapshot data for the prior calendar month
		prevYear, prevMonth := prev.Year(), int(prev.Month())
		query := `INSERT INTO leaderboard_snapshots (year, month, username, rank, download, upload, total, snapshot_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := db.ExecContext(ctx, query, prevYear, prevMonth, "otheruser", 1, 10000, 10000, 20000, now.Format(time.RFC3339))
		if err != nil {
			t.Fatalf("failed to insert snapshot entry 1: %v", err)
		}
		_, err = db.ExecContext(ctx, query, prevYear, prevMonth, "speeddemon", 2, 5000, 5000, 10000, now.Format(time.RFC3339))
		if err != nil {
			t.Fatalf("failed to insert snapshot entry 2: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/leaderboard?period=last-month", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		h.LeaderboardHandler(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var resp models.LeaderboardResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}

		if len(resp.Entries) != 2 {
			t.Fatalf("expected 2 entries from snapshot, got %d", len(resp.Entries))
		}
		if resp.CurrentUserRank == nil || *resp.CurrentUserRank != 2 {
			t.Errorf("expected CurrentUserRank 2, got %v", resp.CurrentUserRank)
		}

		// Verify speeddemon has snapshot total (10000 bytes) and NOT all-time total (10,000,000,000 bytes)
		found := false
		for _, e := range resp.Entries {
			if e.Username == "speeddemon" {
				found = true
				if e.Total != 10000 {
					t.Errorf("expected speeddemon Total=10000 from snapshot, got %d", e.Total)
				}
				if e.Total == 10000000000 {
					t.Errorf("REGRESSION: last-month returned all-time total instead of snapshot!")
				}
			}
		}
		if !found {
			t.Errorf("speeddemon not found in last-month entries")
		}
	})

	t.Run("All-time still returns all-time traffic totals", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/leaderboard?period=all-time", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		h.LeaderboardHandler(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}

		var resp models.LeaderboardResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}

		if len(resp.Entries) == 0 {
			t.Fatalf("expected at least 1 entry for all-time")
		}
		if resp.Entries[0].Username != "speeddemon" || resp.Entries[0].Total != 10000000000 {
			t.Errorf("expected speeddemon total 10000000000 for all-time, got: %+v", resp.Entries[0])
		}
	})

	t.Run("HTML Page Handler renders last-month snapshot and label", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/leaderboard?period=last-month", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		h.LeaderboardPageHandler(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200 for HTML leaderboard page, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, expectedLabel) {
			t.Errorf("expected HTML body to contain monthly label %q", expectedLabel)
		}
		if !strings.Contains(body, "speeddemon") {
			t.Errorf("expected HTML body to contain speeddemon from snapshot")
		}
		if !strings.Contains(body, "otheruser") {
			t.Errorf("expected HTML body to contain otheruser from snapshot")
		}
	})
}
