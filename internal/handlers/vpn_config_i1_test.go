package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func TestVPNUpdateConfigHandlerI1Protocol(t *testing.T) {
	for _, withService := range []bool{true, false} {
		name := "database"
		if withService {
			name = "service"
		}
		t.Run(name, func(t *testing.T) {
			f := newFlagFixture(t, withService)
			get := func() string {
				t.Helper()
				cfg, err := f.db.GetVPNConfig(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				return cfg.DataPlaneI1Protocol()
			}
			if got := get(); got != "sip" {
				t.Fatalf("default = %q", got)
			}
			f.putOK(t, `{"vpn_data_plane_i1_protocol":"dns"}`)
			if got := get(); got != "dns" {
				t.Fatalf("switched = %q", got)
			}
			f.putOK(t, `{"health_threshold_ms":750}`)
			if got := get(); got != "dns" {
				t.Fatalf("unrelated update changed protocol to %q", got)
			}
			if w := f.put(t, `{"vpn_data_plane_i1_protocol":"quic"}`); w.Code != http.StatusBadRequest {
				t.Fatalf("invalid protocol returned %d, want 400", w.Code)
			}
			if got := get(); got != "dns" {
				t.Fatalf("invalid update changed protocol to %q", got)
			}
			if w := f.put(t, `{"vpn_data_plane_i1_protocol":null}`); w.Code != http.StatusBadRequest {
				t.Fatalf("null protocol returned %d, want 400", w.Code)
			}
			if got := get(); got != "dns" {
				t.Fatalf("null update changed protocol to %q", got)
			}
			if w := f.put(t, `{"vpn_data_plane_i1_protocol":""}`); w.Code != http.StatusBadRequest {
				t.Fatalf("empty string protocol returned %d, want 400", w.Code)
			}
			if got := get(); got != "dns" {
				t.Fatalf("empty string update changed protocol to %q", got)
			}
			if w := f.put(t, `{"vpn_data_plane_i1_protocol":"SIP"}`); w.Code != http.StatusBadRequest {
				t.Fatalf("uppercase SIP returned %d, want 400", w.Code)
			}
			if got := get(); got != "dns" {
				t.Fatalf("uppercase SIP update changed protocol to %q", got)
			}
			f.putOK(t, `{"listen_port":51820}`)
			if got := get(); got != "dns" {
				t.Fatalf("absent protocol key changed protocol to %q", got)
			}
		})
	}
}

func testVPNMyConfigHandlerConcurrentConflict(t *testing.T) {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc
	counts := map[int]int{}
	for round := 0; round < 1; round++ {
		uid, err := db.CreateUser(ctx, &models.User{Username: fmt.Sprintf("myconfig-race-%d", round), Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		issue := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-config", nil)
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: uid, Role: models.RoleUser}))
			w := httptest.NewRecorder()
			h.VPNMyConfigHandler(w, req)
			return w
		}

		firstEntered := make(chan struct{})
		firstRelease := make(chan struct{})
		secondEntered := make(chan struct{})
		secondRelease := make(chan struct{})
		var hookCallCount atomic.Int32

		restoreHook := svc.SetPreAssignmentLockHookForTest(func() {
			count := hookCallCount.Add(1)
			if count == 1 {
				close(firstEntered)
				<-firstRelease
			} else if count == 2 {
				close(secondEntered)
				<-secondRelease
			}
		})

		var w1, w2 *httptest.ResponseRecorder
		var wg1, wg2 sync.WaitGroup

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			w1 = issue()
		}()
		<-firstEntered

		wg2.Add(1)
		go func() {
			defer wg2.Done()
			w2 = issue()
		}()
		<-secondEntered

		// Release Goroutine 1 to acquire assignmentMu and commit first
		close(firstRelease)
		wg1.Wait()

		// Release Goroutine 2 to acquire assignmentMu and detect concurrent creation
		close(secondRelease)
		wg2.Wait()

		restoreHook()

		cs, e := db.GetConnectionsByUserID(ctx, uid)
		if e != nil || len(cs) != 1 {
			t.Fatalf("rows=%d error=%v", len(cs), e)
		}
		for _, w := range []*httptest.ResponseRecorder{w1, w2} {
			counts[w.Code]++
			if w.Code != http.StatusOK && w.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var body map[string]any
			if e = json.Unmarshal(w.Body.Bytes(), &body); e != nil {
				t.Fatal(e)
			}
			if w.Code == http.StatusConflict {
				if body["error"] != "conflict" {
					t.Fatalf("expected error='conflict', got %v", body["error"])
				}
				detail, _ := body["detail"].(string)
				if strings.Contains(strings.ToLower(detail), "sql") || strings.Contains(strings.ToLower(detail), "internal") {
					t.Fatalf("internal detail leaked in 409 response: %q", detail)
				}
				continue
			}
			cfg, ok := body["config"].(string)
			if !ok {
				t.Fatal("missing success config")
			}
			key := vpn.ExtractClientPublicKeyFromConfig(cfg)
			if key == "" || key != cs[0].ClientID {
				t.Fatal("issued key mismatches durable row")
			}
		}
		if retry := issue(); retry.Code != http.StatusOK {
			t.Fatalf("retry=%d %s", retry.Code, retry.Body.String())
		}
	}
	if counts[http.StatusConflict] == 0 {
		t.Fatal("inconclusive: no conflicting schedule observed")
	}
}

func TestVPNMyConfigHandler_ConcurrentConflict(t *testing.T) {
	testVPNMyConfigHandlerConcurrentConflict(t)
}

// Real SQLite failures through the actual user-facing handler (no network).
// Proves dropped users and user_connections tables do not leak database schema or internal SQL diagnostics.
func TestVPNMyConfigHandler_DBErrorSanitization(t *testing.T) {
	for _, tc := range []struct {
		table        string
		expectedCode int
		expectedErr  string
		expectedMsg  string
	}{
		{
			table:        "users",
			expectedCode: http.StatusInternalServerError,
			expectedErr:  "internal_error",
			expectedMsg:  "Failed to generate VPN configuration",
		},
		{
			table:        "user_connections",
			expectedCode: http.StatusInternalServerError,
			expectedErr:  "internal_error",
			expectedMsg:  "Failed to generate VPN configuration",
		},
	} {
		t.Run(tc.table, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := context.Background()
			svc, err := vpn.NewVPNService(db, nil)
			if err != nil {
				t.Fatal(err)
			}
			h.vpnSvc = svc
			uid, err := db.CreateUser(ctx, &models.User{Username: "audit-disclosure-" + tc.table, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.ExecContext(ctx, "DROP TABLE "+tc.table); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-config", nil)
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: uid, Role: models.RoleUser}))
			w := httptest.NewRecorder()
			h.VPNMyConfigHandler(w, req)

			if w.Code != tc.expectedCode {
				t.Fatalf("expected status %d, got %d, body=%s", tc.expectedCode, w.Code, w.Body.String())
			}

			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode JSON response: %v", err)
			}
			if body["error"] != tc.expectedErr {
				t.Errorf("expected error %q, got %q", tc.expectedErr, body["error"])
			}
			if body["detail"] != tc.expectedMsg {
				t.Errorf("expected detail %q, got %q", tc.expectedMsg, body["detail"])
			}

			// Negative assertions: body must not carry database error details
			raw := strings.ToLower(w.Body.String())
			for _, leak := range []string{"sql", "sqlite", "table", "syntax", "no such table", tc.table} {
				if strings.Contains(raw, leak) {
					t.Errorf("response body leaks database diagnostic %q: %s", leak, w.Body.String())
				}
			}
		})
	}
}

// Proves that when user does not exist in the database (user == nil), handler returns HTTP 404 not_found
// with the sanitized public message and no internal leakage.
func TestVPNMyConfigHandler_UserNotFound(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-config", nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "non-existent-user-uuid",
		Role:   models.RoleUser,
	}))
	w := httptest.NewRecorder()
	h.VPNMyConfigHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["error"] != "not_found" {
		t.Errorf("expected error 'not_found', got %v", body["error"])
	}
	if body["detail"] != "Client configuration not found" {
		t.Errorf("expected detail 'Client configuration not found', got %v", body["detail"])
	}
	for _, leak := range []string{"sql", "sqlite", "uuid", "non-existent"} {
		if strings.Contains(strings.ToLower(w.Body.String()), leak) {
			t.Errorf("response body leaks %q: %s", leak, w.Body.String())
		}
	}
}

// Boundary test verifying fixed public messages and zero diagnostic leakage for all 5 mapped statuses.
func TestVPNMyConfigHandler_ErrorMappingBoundary(t *testing.T) {
	h, _, _ := setupTestHandlers(t)
	const secret = "INTERNAL_DIAGNOSTIC_SECRET_12345"

	tests := []struct {
		name         string
		err          error
		expectedCode int
		expectedErr  string
		expectedMsg  string
	}{
		{
			name:         "400 invalid parameter",
			err:          fmt.Errorf("%w: %s", vpn.ErrInvalidParameter, secret),
			expectedCode: http.StatusBadRequest,
			expectedErr:  "invalid_parameter",
			expectedMsg:  "Invalid configuration parameter",
		},
		{
			name:         "400 bad request",
			err:          fmt.Errorf("%w: %s", vpn.ErrBadRequest, secret),
			expectedCode: http.StatusBadRequest,
			expectedErr:  "bad_request",
			expectedMsg:  "Invalid configuration request",
		},
		{
			name:         "403 forbidden",
			err:          fmt.Errorf("%w: %s", vpn.ErrAccessDenied, secret),
			expectedCode: http.StatusForbidden,
			expectedErr:  "forbidden",
			expectedMsg:  "Access denied",
		},
		{
			name:         "404 not found",
			err:          fmt.Errorf("%w: %s", vpn.ErrUserNotFound, secret),
			expectedCode: http.StatusNotFound,
			expectedErr:  "not_found",
			expectedMsg:  "Client configuration not found",
		},
		{
			name:         "409 conflict sentinel",
			err:          fmt.Errorf("%w: %s", vpn.ErrConnectionCreatedConcurrently, secret),
			expectedCode: http.StatusConflict,
			expectedErr:  "conflict",
			expectedMsg:  "Connection was created concurrently; please retry",
		},
		{
			name:         "500 malformed persisted I1",
			err:          errors.New("malformed persisted portal I1: " + secret),
			expectedCode: http.StatusInternalServerError,
			expectedErr:  "internal_error",
			expectedMsg:  "Failed to generate VPN configuration",
		},
		{
			name:         "500 empty generator result",
			err:          errors.New("empty generator result for portal I1: " + secret),
			expectedCode: http.StatusInternalServerError,
			expectedErr:  "internal_error",
			expectedMsg:  "Failed to generate VPN configuration",
		},
		{
			name:         "500 internal error fallback",
			err:          errors.New("persistence failure: " + secret),
			expectedCode: http.StatusInternalServerError,
			expectedErr:  "internal_error",
			expectedMsg:  "Failed to generate VPN configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.handleVPNMyConfigError(w, tt.err)

			if w.Code != tt.expectedCode {
				t.Fatalf("expected code %d, got %d", tt.expectedCode, w.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if body["error"] != tt.expectedErr {
				t.Errorf("expected error %q, got %q", tt.expectedErr, body["error"])
			}
			if body["detail"] != tt.expectedMsg {
				t.Errorf("expected detail %q, got %q", tt.expectedMsg, body["detail"])
			}
			if strings.Contains(w.Body.String(), secret) {
				t.Errorf("response body leaks internal detail: %s", w.Body.String())
			}
		})
	}
}
