package handlers

// The server-detail reachability endpoint is a probe path of its own: an open
// server page polls it every 30 seconds, and it measures TCP latency by dialling.
// A server the provider's inventory no longer lists must not be dialled by it,
// while a listed server must still be measured in the same run.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestGetServerReachabilityHandler_ProviderAbsentSkipsDial(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	absentID, err := db.CreateServer(ctx, &models.Server{Name: "Provider absent", Host: "198.51.100.60", SSHPort: 22})
	if err != nil {
		t.Fatalf("failed to seed the absent server: %v", err)
	}
	liveID, err := db.CreateServer(ctx, &models.Server{Name: "Still listed", Host: "198.51.100.61", SSHPort: 22})
	if err != nil {
		t.Fatalf("failed to seed the listed server: %v", err)
	}
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC()); err != nil {
		t.Fatalf("failed to record the provider absence: %v", err)
	}
	// A previous observation exists and must survive: refusing to dial is not a
	// measurement, so it may not rewrite the stored status.
	if err := db.UpdateServerReachability(ctx, absentID, models.ReachabilityOnline); err != nil {
		t.Fatalf("failed to seed the sticky reachability status: %v", err)
	}

	var dialed []string
	h.dialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("connection refused by the test dialer")
	}

	call := func(serverID int64) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/servers/%d/reachability", serverID), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "admin-1",
			Role:   models.RoleAdmin,
		}))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("server_id", strconv.FormatInt(serverID, 10))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		rec := httptest.NewRecorder()
		h.GetServerReachabilityHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("reachability handler returned %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode the reachability response: %v", err)
		}
		return rec.Code, body
	}

	_, absentBody := call(absentID)
	if len(dialed) != 0 {
		t.Fatalf("the absent server was dialled %d time(s): %v", len(dialed), dialed)
	}
	if absent, ok := absentBody["provider_absent"].(bool); !ok || !absent {
		t.Fatalf("the response does not report the server as provider-absent: %+v", absentBody)
	}
	if reachable, ok := absentBody["reachable"].(bool); !ok || reachable {
		t.Fatalf("the absent server was reported reachable without a measurement: %+v", absentBody)
	}
	status, err := db.GetServerStatus(ctx, absentID)
	if err != nil {
		t.Fatalf("failed to read the absent server's status: %v", err)
	}
	if status != models.ReachabilityOnline {
		t.Fatalf("refusing to dial rewrote the stored status to %q", status)
	}

	// The same run still measures a server the provider lists, so the suppression
	// above is a decision about that row and not a disabled endpoint.
	_, liveBody := call(liveID)
	if len(dialed) != 1 {
		t.Fatalf("expected exactly one dial (the listed server), got %d: %v", len(dialed), dialed)
	}
	if _, ok := liveBody["provider_absent"]; ok {
		t.Fatalf("the listed server's response carries a provider-absent marker: %+v", liveBody)
	}
	if reachable, ok := liveBody["reachable"].(bool); !ok || reachable {
		t.Fatalf("the listed server's refused dial should be reported as unreachable: %+v", liveBody)
	}
}
