package handlers

// The server page polls the stats endpoint automatically every 30 seconds. For a
// server the provider's inventory no longer lists, the handler must answer without
// acquiring an SSH session, and the answer must say "not measured" rather than
// carry zeros that read as a sample. The connection count on a real listener is
// what proves the refusal; the response body is what the page renders from.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestServerStatsHandler_ProviderAbsentIsNotMeasured(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// One listener for both servers: every accepted connection is an SSH attempt.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var accepted int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			_ = conn.Close()
		}
	}()
	defer func() {
		_ = ln.Close()
		<-done
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("read listener port %q: %v", portStr, err)
	}

	absentID, err := db.CreateServer(ctx, &models.Server{
		Name: "provider absent", Host: "127.0.0.1", SSHPort: port, SSHUser: "root", SSHPass: "test-password",
	})
	if err != nil {
		t.Fatalf("seeding the absent server: %v", err)
	}
	liveID, err := db.CreateServer(ctx, &models.Server{
		Name: "still listed", Host: "127.0.0.1", SSHPort: port, SSHUser: "root", SSHPass: "test-password",
	})
	if err != nil {
		t.Fatalf("seeding the listed server: %v", err)
	}
	if err := db.SetServerProviderAbsence(ctx, absentID, time.Now().UTC()); err != nil {
		t.Fatalf("recording the provider absence: %v", err)
	}

	call := func(serverID int64) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/stats", serverID), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "admin-1",
			Role:   models.RoleAdmin,
		}))
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("server_id", strconv.FormatInt(serverID, 10))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		rec := httptest.NewRecorder()
		h.ServerStatsHandler(rec, req)
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding the stats response: %v (%s)", err, rec.Body.String())
		}
		return rec.Code, body
	}

	code, body := call(absentID)
	if code != http.StatusOK {
		t.Fatalf("the absent server's stats request returned %d: %v", code, body)
	}
	if measured, ok := body["not_measured"].(bool); !ok || !measured {
		t.Fatalf("the response does not report a not-measured outcome: %v", body)
	}
	if status, _ := body["status"].(string); status != models.ProviderAbsentStatus {
		t.Fatalf("the response status is %q, want %q", status, models.ProviderAbsentStatus)
	}
	if absent, ok := body["provider_absent"].(bool); !ok || !absent {
		t.Fatalf("the response does not report the server as provider-absent: %v", body)
	}
	// Nothing may be fabricated: no sample fields at all.
	for _, key := range []string{"cpu", "ram_used", "ram_total", "disk_used", "disk_total", "net_rx", "net_tx", "uptime"} {
		if _, present := body[key]; present {
			t.Fatalf("the not-measured response carries a fabricated %q field: %v", key, body)
		}
	}
	if got := atomic.LoadInt32(&accepted); got != 0 {
		t.Fatalf("the absent server's stats request opened %d SSH connection(s)", got)
	}

	// Live control: the same handler and the same address still try to connect.
	// The bare listener refuses the handshake, so the handler reports a transport
	// failure - which is only reachable after a real attempt.
	code, liveBody := call(liveID)
	if code == http.StatusOK {
		if measured, _ := liveBody["not_measured"].(bool); measured {
			t.Fatalf("the listed server was reported as not measured: %v", liveBody)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&accepted) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&accepted); got != 1 {
		t.Fatalf("expected exactly one SSH connection attempt (the listed server), got %d", got)
	}
}
