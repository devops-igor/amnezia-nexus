package vpn

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
)

// TestSessionsEnriched verifies the service-layer read path for the admin
// session visibility feature (issue #189): identity joins come from the DB,
// while live counters and last_seen are stitched from the in-memory
// SessionManager (memory authoritative, DB row the fallback).
func TestSessionsEnriched(t *testing.T) {
	ctx := context.Background()

	t.Run("nil db returns error", func(t *testing.T) {
		svc := &Service{}
		_, err := svc.SessionsEnriched(ctx)
		if err == nil || !strings.Contains(err.Error(), "database not available") {
			t.Errorf("expected database not available error, got: %v", err)
		}
	})

	t.Run("live memory counters override stale DB row", func(t *testing.T) {
		db := setupTestDB(t)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "Edge Node 1", Host: "198.51.100.10"})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		uID, err := db.CreateUser(ctx, &models.User{Username: "alice"})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: "awg-be-1",
			PublicKey:     "pubkey-be-1",
			PrivateKey:    "privkey-be-1",
			Endpoint:      "198.51.100.10:51820",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel failed: %v", err)
		}

		// Build the live session through the production path: persist the
		// row, restore it into memory via SyncFromDB (same as service
		// Start), then advance counters with UpdateActivity — exactly how
		// live traffic updates flow in production.
		staleSeen := time.Now().UTC().Add(-30 * time.Minute)
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "sess-live",
			UserID:          uID,
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-live",
			AssignedIP:      "10.100.0.31",
			ConnectedAt:     staleSeen,
			LastSeen:        staleSeen,
			RxBytes:         100,
			TxBytes:         200,
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		sessionMgr := endpoint.NewSessionManager(db, nil)
		if err := sessionMgr.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB failed: %v", err)
		}
		sessionMgr.UpdateActivity("peer-live", 99900, 199800) // rx=100000 tx=200000

		svc := &Service{db: db, sessionMgr: sessionMgr}
		sessions, err := svc.SessionsEnriched(ctx)
		if err != nil {
			t.Fatalf("SessionsEnriched failed: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
		}
		got := sessions[0]
		if got.RxBytes != 100000 || got.TxBytes != 200000 {
			t.Errorf("memory counters should win: rx=%d tx=%d, want 100000/200000", got.RxBytes, got.TxBytes)
		}
		if !got.LastSeen.After(staleSeen) {
			t.Errorf("memory last_seen should win: got %v, want > %v", got.LastSeen, staleSeen)
		}
		if got.Username != "alice" || got.ServerName != "Edge Node 1" {
			t.Errorf("identity joins should come from DB: username=%q server=%q", got.Username, got.ServerName)
		}
	})

	t.Run("session absent in memory keeps DB values", func(t *testing.T) {
		db := setupTestDB(t)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "Edge Node 2", Host: "198.51.100.11"})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		uID, err := db.CreateUser(ctx, &models.User{Username: "bob"})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: "awg-be-2",
			PublicKey:     "pubkey-be-2",
			PrivateKey:    "privkey-be-2",
			Endpoint:      "198.51.100.11:51820",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel failed: %v", err)
		}

		seen := time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "sess-db-only",
			UserID:          uID,
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-db-only",
			AssignedIP:      "10.100.0.32",
			ConnectedAt:     seen,
			LastSeen:        seen,
			RxBytes:         7,
			TxBytes:         11,
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		// Live-but-empty session manager: the DB row must survive untouched.
		svc := &Service{db: db, sessionMgr: endpoint.NewSessionManager(nil, nil)}
		sessions, err := svc.SessionsEnriched(ctx)
		if err != nil {
			t.Fatalf("SessionsEnriched failed: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
		}
		got := sessions[0]
		if got.RxBytes != 7 || got.TxBytes != 11 {
			t.Errorf("DB counters should be kept: rx=%d tx=%d, want 7/11", got.RxBytes, got.TxBytes)
		}
		if !got.LastSeen.Equal(seen) {
			t.Errorf("DB last_seen should be kept: got %v, want %v", got.LastSeen, seen)
		}
		if got.Username != "bob" {
			t.Errorf("expected username from DB join, got %q", got.Username)
		}
	})

	t.Run("nil session manager skips stitch", func(t *testing.T) {
		db := setupTestDB(t)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "Edge Node 3", Host: "198.51.100.12"})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		uID, err := db.CreateUser(ctx, &models.User{Username: "carol"})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: "awg-be-3",
			PublicKey:     "pubkey-be-3",
			PrivateKey:    "privkey-be-3",
			Endpoint:      "198.51.100.12:51820",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel failed: %v", err)
		}

		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "sess-no-mgr",
			UserID:          uID,
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-no-mgr",
			AssignedIP:      "10.100.0.33",
			RxBytes:         3,
			TxBytes:         4,
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		svc := &Service{db: db} // sessionMgr nil
		sessions, err := svc.SessionsEnriched(ctx)
		if err != nil {
			t.Fatalf("SessionsEnriched with nil sessionMgr failed: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
		}
		if sessions[0].RxBytes != 3 || sessions[0].TxBytes != 4 {
			t.Errorf("DB values should be kept when sessionMgr is nil: %+v", sessions[0])
		}
	})
}
