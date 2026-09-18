package vpn

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// TestSessionsEnriched verifies the service-layer read path for the admin
// session visibility feature (issue #189): identity joins come from the DB,
// and the live telemetry source is the forwarder's TrafficAccountant —
// displayed counters are the last-flushed DB totals plus the accountant's
// un-flushed buffered deltas, i.e. the same path production traffic
// actually flows through (RecordRx/RecordTx → periodic Flush → DB row).
func TestSessionsEnriched(t *testing.T) {
	ctx := context.Background()

	t.Run("nil db returns error", func(t *testing.T) {
		svc := &Service{}
		_, err := svc.SessionsEnriched(ctx)
		if err == nil || !strings.Contains(err.Error(), "database not available") {
			t.Errorf("expected database not available error, got: %v", err)
		}
	})

	t.Run("buffered accountant deltas add to flushed DB totals", func(t *testing.T) {
		db := setupTestDB(t)
		seedSession(t, db, "Edge Node 1", "alice", "sess-live", "peer-live", "10.100.0.31", 1000, 2000)

		// Production wiring: a real TrafficAccountant over the same DB
		// (the forwarder itself is not needed for the read path).
		accountant := forwarder.NewTrafficAccountant(db, time.Second)
		svc := &Service{db: db, accountant: accountant}

		// Buffered, un-flushed deltas — exactly what the forwarder packet
		// loops produce between periodic Flushes.
		accountant.RecordRx("sess-live", "", 500)
		accountant.RecordTx("sess-live", "", 300)

		sessions, err := svc.SessionsEnriched(ctx)
		if err != nil {
			t.Fatalf("SessionsEnriched failed: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
		}
		got := sessions[0]
		if got.RxBytes != 1500 || got.TxBytes != 2300 {
			t.Errorf("displayed counters = flushed DB + buffered: rx=%d tx=%d, want 1500/2300", got.RxBytes, got.TxBytes)
		}
		if got.Username != "alice" || got.ServerName != "Edge Node 1" {
			t.Errorf("identity joins should come from DB: username=%q server=%q", got.Username, got.ServerName)
		}
	})

	t.Run("after flush displayed counters equal the DB row", func(t *testing.T) {
		db := setupTestDB(t)
		seedSession(t, db, "Edge Node 2", "bob", "sess-flush", "peer-flush", "10.100.0.32", 1000, 2000)

		accountant := forwarder.NewTrafficAccountant(db, time.Second)
		svc := &Service{db: db, accountant: accountant}
		accountant.RecordRx("sess-flush", "", 500)
		accountant.RecordTx("sess-flush", "", 300)

		if err := accountant.Flush(ctx); err != nil {
			t.Fatalf("Flush failed: %v", err)
		}

		// UpdateVPNSessionTraffic SETs rx_bytes/tx_bytes to the drained
		// delta (absolute-set, not += — the write-path semantics tracked
		// in issue #205, intentionally out of scope here). So after this
		// flush the row holds exactly the drained deltas (500/300), the
		// buffer is empty, and SessionsEnriched must equal the DB row.
		row, err := db.GetEnrichedActiveVPNSessions(ctx)
		if err != nil || len(row) != 1 {
			t.Fatalf("post-flush row read failed: %v (%d rows)", err, len(row))
		}
		if row[0].RxBytes != 500 || row[0].TxBytes != 300 {
			t.Fatalf("post-flush DB row rx=%d tx=%d, want 500/300 per UpdateVPNSessionTraffic absolute-set semantics (issue #205)", row[0].RxBytes, row[0].TxBytes)
		}

		if rx, tx := accountant.GetSessionTraffic("sess-flush"); rx != 0 || tx != 0 {
			t.Fatalf("buffer should be drained after flush: rx=%d tx=%d", rx, tx)
		}

		sessions, err := svc.SessionsEnriched(ctx)
		if err != nil {
			t.Fatalf("SessionsEnriched failed: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
		}
		got := sessions[0]
		if got.RxBytes != 500 || got.TxBytes != 300 {
			t.Errorf("after flush displayed counters must equal DB row: rx=%d tx=%d, want 500/300", got.RxBytes, got.TxBytes)
		}
	})

	t.Run("nil accountant returns plain DB rows", func(t *testing.T) {
		db := setupTestDB(t)
		seen := time.Date(2026, 9, 18, 8, 0, 0, 0, time.UTC)
		seedSessionWithSeen(t, db, "Edge Node 3", "carol", "sess-no-acct", "peer-no-acct", "10.100.0.33", 7, 11, seen)

		// Management-only / tests without a forwarder: accountant nil
		// must be safe and return the DB rows untouched.
		svc := &Service{db: db}
		sessions, err := svc.SessionsEnriched(ctx)
		if err != nil {
			t.Fatalf("SessionsEnriched with nil accountant failed: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d: %+v", len(sessions), sessions)
		}
		got := sessions[0]
		if got.RxBytes != 7 || got.TxBytes != 11 {
			t.Errorf("DB counters should be kept when accountant is nil: rx=%d tx=%d, want 7/11", got.RxBytes, got.TxBytes)
		}
		if !got.LastSeen.Equal(seen) {
			t.Errorf("last_seen should come from the DB row: got %v, want %v", got.LastSeen, seen)
		}
		if got.Username != "carol" {
			t.Errorf("expected username from DB join, got %q", got.Username)
		}
	})
}

// seedSession creates the server/user/backend-tunnel join chain plus a
// connected vpn_sessions row with the given counters and a recent last_seen.
func seedSession(t *testing.T, db *database.DB, serverName, username, sessionID, peerKey, assignedIP string, rx, tx int64) {
	t.Helper()
	seedSessionWithSeen(t, db, serverName, username, sessionID, peerKey, assignedIP, rx, tx, time.Now().UTC().Add(-30*time.Minute))
}

// seedSessionWithSeen is seedSession with an explicit last_seen timestamp.
func seedSessionWithSeen(t *testing.T, db *database.DB, serverName, username, sessionID, peerKey, assignedIP string, rx, tx int64, seen time.Time) {
	t.Helper()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: serverName, Host: "198.51.100.10"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: username})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-" + username,
		PublicKey:     "pubkey-" + username,
		PrivateKey:    "privkey-" + username,
		Endpoint:      "198.51.100.10:51820",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessionID,
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   peerKey,
		AssignedIP:      assignedIP,
		ConnectedAt:     seen,
		LastSeen:        seen,
		RxBytes:         rx,
		TxBytes:         tx,
		Status:          "connected",
	}); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}
}
