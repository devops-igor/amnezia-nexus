package vpn

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestLiveRekeysKeepSessionBackendAndRouteAtCapacity(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, peer := setupTestVPNService(t, db, func(cfg *models.VPNConfig) {
		cfg.MaxPeersPerBackend = 1
	})
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	sess, backend, err := svc.HandleIncomingPeer(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	queue, ok := svc.forwarder.GetClientPacketChannel(peer)
	if !ok {
		t.Fatal("initial route missing")
	}
	registration := svc.forwarder.PeerRegistration(peer)
	initialSeen := sess.LastSeen
	lastGeneration := sess.Generation
	if backend.ActiveConnections != 0 { // returned tunnel is a pre-admission snapshot
		t.Fatalf("unexpected pre-admission count: %d", backend.ActiveConnections)
	}

	for i := 0; i < 5; i++ {
		rekeyed, selected, err := svc.HandleIncomingPeer(ctx, peer)
		if err != nil {
			t.Fatalf("rekey %d at capacity: %v", i, err)
		}
		if rekeyed.ID != sess.ID || rekeyed.AssignedIP != sess.AssignedIP || selected.ID != backend.ID || rekeyed.BackendTunnelID != backend.ID {
			t.Fatalf("rekey %d changed session/IP/backend: initial=%+v new=%+v selected=%+v", i, sess, rekeyed, selected)
		}
		if rekeyed.Generation <= lastGeneration {
			t.Fatalf("rekey %d did not advance handshake generation: %d -> %d", i, lastGeneration, rekeyed.Generation)
		}
		if !rekeyed.LastSeen.Equal(initialSeen) {
			t.Fatalf("handshake %d refreshed activity without authenticated transport", i)
		}
		currentQueue, routeOK := svc.forwarder.GetClientPacketChannel(peer)
		if !routeOK || currentQueue != queue || svc.forwarder.RouteSessionID(peer) != sess.ID || svc.forwarder.PeerRegistration(peer) != registration {
			t.Fatalf("rekey %d replaced the active forwarder route", i)
		}
		currentBackend, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || currentBackend.ActiveConnections != 1 {
			t.Fatalf("rekey %d changed backend count: %+v, %v", i, currentBackend, err)
		}
		if len(svc.sessionMgr.ListActiveSessions()) != 1 {
			t.Fatalf("rekey %d changed logical session cardinality", i)
		}
		sess = rekeyed
		lastGeneration = rekeyed.Generation
	}
	if metrics := svc.sessionMgr.MetricsSnapshot(); metrics["replacements_total"] != 0 {
		t.Fatalf("pure rekeys recorded session replacements: %+v", metrics)
	}
	if svc.freshSessionRegistrations.Load() != 1 {
		t.Fatalf("pure rekeys registered routes: %d", svc.freshSessionRegistrations.Load())
	}
	if persisted, err := db.GetActiveVPNSessions(ctx); err != nil || len(persisted) != 1 || persisted[0].ID != sess.ID {
		t.Fatalf("rekeys changed persisted sessions: %+v, %v", persisted, err)
	}

	// The transport receive path uses TouchSession after authentication. A
	// handshake by itself must not defer idle reaping, but transport must.
	svc.sessionMgr.SetSessionLastSeen(peer, time.Now().Add(-time.Minute))
	svc.sessionMgr.TouchSession(peer)
	if touched, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer); !ok || !touched.LastSeen.After(initialSeen) {
		t.Fatalf("authenticated activity did not refresh LastSeen: %+v", touched)
	}
}

func TestReconnectAfterTeardownUsesNormalAdmission(t *testing.T) {
	svc, _, _, _, peer := setupTestVPNService(t, setupTestDB(t))
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	initial, _, err := svc.HandleIncomingPeer(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	initialRegistration := svc.forwarder.PeerRegistration(peer)
	if err := svc.DisconnectSession(ctx, initial.ID); err != nil {
		t.Fatal(err)
	}
	reconnected, _, err := svc.HandleIncomingPeer(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if reconnected.ID == initial.ID || reconnected.Generation <= initial.Generation || svc.forwarder.PeerRegistration(peer) != initialRegistration+1 {
		t.Fatalf("reconnect skipped admission: initial=%+v new=%+v registrations=%d", initial, reconnected, svc.forwarder.PeerRegistration(peer))
	}
}

func TestRekeyWithUnusableBackendUsesNormalPlacement(t *testing.T) {
	svc, _, _, _, peer := setupTestVPNService(t, setupTestDB(t))
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	initial, backend, err := svc.HandleIncomingPeer(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, backend.ServerID, "degraded", 0); err != nil {
		t.Fatal(err)
	}
	replaced, selected, err := svc.HandleIncomingPeer(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID == initial.ID || selected.ID == backend.ID || svc.forwarder.RouteSessionID(peer) != replaced.ID {
		t.Fatalf("unusable backend was reused: initial=%+v new=%+v backend=%+v", initial, replaced, selected)
	}
}
