package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/service/upstream"
)

type mockUpstreamService struct {
	status      *upstream.UpstreamStatus
	err         error
	lastRefresh bool
}

func (m *mockUpstreamService) Check(ctx context.Context, forceRefresh bool) (*upstream.UpstreamStatus, error) {
	m.lastRefresh = forceRefresh
	if m.err != nil {
		return nil, m.err
	}
	return m.status, nil
}

func TestGetUpstreamStatusHandler_Success(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	mockStatus := &upstream.UpstreamStatus{
		CheckedAt:       time.Now().UTC(),
		Status:          "up_to_date",
		UpdateAvailable: false,
		Components: []upstream.ComponentStatus{
			{
				Name:            "amneziawg-go",
				Repo:            "amnezia-vpn/amneziawg-go",
				PinnedVersion:   upstream.PinnedAWGGoVersion,
				LatestVersion:   upstream.PinnedAWGGoVersion,
				UpdateAvailable: false,
				ReleaseURL:      "https://github.com/amnezia-vpn/amneziawg-go/releases/tag/v3.1.20260828",
			},
		},
		BaseImage: upstream.PinnedAWGBaseImage,
	}

	mockSvc := &mockUpstreamService{status: mockStatus}
	h.SetUpstreamService(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/system/upstream-status", nil)
	w := httptest.NewRecorder()

	h.GetUpstreamStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp upstream.UpstreamStatus
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "up_to_date" {
		t.Errorf("expected Status='up_to_date', got %q", resp.Status)
	}
	if resp.UpdateAvailable != false {
		t.Errorf("expected UpdateAvailable=false")
	}
	if len(resp.Components) != 1 || resp.Components[0].Name != "amneziawg-go" {
		t.Errorf("unexpected components: %+v", resp.Components)
	}
	if mockSvc.lastRefresh != false {
		t.Errorf("expected lastRefresh=false without query param")
	}
}

func TestGetUpstreamStatusHandler_ForceRefresh(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	mockSvc := &mockUpstreamService{
		status: &upstream.UpstreamStatus{
			CheckedAt:       time.Now().UTC(),
			Status:          "update_available",
			UpdateAvailable: true,
			Components:      []upstream.ComponentStatus{},
			BaseImage:       upstream.PinnedAWGBaseImage,
		},
	}
	h.SetUpstreamService(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/system/upstream-status?refresh=true", nil)
	w := httptest.NewRecorder()

	h.GetUpstreamStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	if !mockSvc.lastRefresh {
		t.Errorf("expected lastRefresh=true when ?refresh=true is provided")
	}

	var resp upstream.UpstreamStatus
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "update_available" {
		t.Errorf("expected Status='update_available', got %q", resp.Status)
	}
}

func TestGetUpstreamStatusHandler_ServiceError(t *testing.T) {
	h, _, _ := setupTestHandlers(t)

	mockSvc := &mockUpstreamService{
		err: errors.New("github connection timeout"),
	}
	h.SetUpstreamService(mockSvc)

	req := httptest.NewRequest(http.MethodGet, "/api/system/upstream-status", nil)
	w := httptest.NewRecorder()

	h.GetUpstreamStatusHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}
}

func TestGetUpstreamStatusHandler_NilService(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	h.SetUpstreamService(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/system/upstream-status", nil)
	w := httptest.NewRecorder()

	h.GetUpstreamStatusHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", w.Code)
	}
}
