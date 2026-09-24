package vpn

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"golang.org/x/crypto/curve25519"
)

func TestRestartInvalidatesSessionsBeforeStartingDataPlane(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, userID, peerKey := setupTestVPNService(t, db)
	ctx := t.Context()
	defer func() { _ = svc.Stop() }()

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) != 2 {
		t.Fatalf("expected two persisted backends: tunnels=%+v err=%v", tunnels, err)
	}
	for i, tun := range tunnels {
		if err := db.UpdateBackendTunnel(ctx, tun.ID, map[string]any{"active_connections": 5 + i}); err != nil {
			t.Fatal(err)
		}
		peer := peerKey
		if i != 0 {
			peer = "old-peer-on-second-backend"
		}
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID: "old-session-" + peer, UserID: userID,
			BackendTunnelID: tun.ID, PeerPublicKey: peer,
			AssignedIP: fmt.Sprintf("10.100.0.%d", 3+i), Status: "connected",
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	status, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.RestartInvalidatedSessions != 2 || status.FreshSessionRegistrations != 0 || status.ConnectedSessions != 0 || status.ForwarderDropsNoRoute != 0 {
		t.Fatalf("unexpected startup telemetry: %+v", status)
	}
	if _, _, routes := svc.forwarder.GetStats(); routes != 0 {
		t.Fatalf("forwarder restored %d dead session routes", routes)
	}
	if svc.sessionMgr.ActiveCount() != 0 || len(svc.sessionMgr.ListActiveSessions()) != 0 || svc.HasTransportStateForPeer(peerKey) {
		t.Fatal("restart restored a session without a live transport and route")
	}
	if sessions, err := db.GetActiveVPNSessions(ctx); err != nil || len(sessions) != 0 {
		t.Fatalf("stale connected rows survived: sessions=%+v err=%v", sessions, err)
	}
	for _, tun := range tunnels {
		row, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || row == nil || row.ActiveConnections != 0 {
			t.Fatalf("backend %d retained stale DB gauge: row=%+v err=%v", tun.ID, row, err)
		}
		pooled, err := svc.pool.GetTunnelByID(tun.ID)
		if err != nil || pooled.ActiveConnections != 0 {
			t.Fatalf("backend %d retained stale pool gauge: tunnel=%+v err=%v", tun.ID, pooled, err)
		}
	}

	// The existing client authenticates normally and obtains a new session,
	// route and backend count; no portal-side manual session repair is needed.
	fresh, backend, err := svc.HandleIncomingPeer(ctx, peerKey)
	if err != nil {
		t.Fatalf("fresh peer handshake failed: %v", err)
	}
	if fresh.ID == "old-session-"+peerKey || svc.forwarder.RouteSessionID(peerKey) != fresh.ID {
		t.Fatalf("fresh handshake did not install its route: session=%+v", fresh)
	}
	status, err = svc.GetStatus(ctx)
	if err != nil || status.ConnectedSessions != 1 || status.FreshSessionRegistrations != 1 || status.RestartInvalidatedSessions != 2 {
		t.Fatalf("fresh session telemetry: status=%+v err=%v", status, err)
	}
	if row, err := db.GetBackendTunnel(ctx, backend.ID); err != nil || row == nil || row.ActiveConnections != 1 {
		t.Fatalf("new session gauge: row=%+v err=%v", row, err)
	}
	if sessions, err := db.GetActiveVPNSessions(ctx); err != nil || len(sessions) != 1 || sessions[0].ID != fresh.ID {
		t.Fatalf("active rows after fresh handshake: sessions=%+v err=%v", sessions, err)
	}
}

func TestRestartCleanupFailureDoesNotStartListener(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, userID, peerKey := setupTestVPNService(t, db)
	ctx := t.Context()
	defer func() { _ = svc.Stop() }()
	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("missing backend tunnels: tunnels=%+v err=%v", tunnels, err)
	}
	if err := db.UpdateBackendTunnel(ctx, tunnels[0].ID, map[string]any{"active_connections": 2}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "old-before-failed-start", UserID: userID,
		BackendTunnelID: tunnels[0].ID, PeerPublicKey: peerKey,
		AssignedIP: "10.100.0.11", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQLDB().ExecContext(ctx, `CREATE TRIGGER block_restart_start
		BEFORE UPDATE OF active_connections ON backend_tunnels
		BEGIN SELECT RAISE(ABORT, 'blocked restart'); END`); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx); err == nil {
		t.Fatal("Start succeeded despite failed session invalidation")
	}
	if svc.IsRunning() || svc.endpoint.IsRunning() || svc.sessionMgr.ActiveCount() != 0 {
		t.Fatal("partial startup exposed stale sessions or opened the endpoint")
	}
	if row, err := db.GetVPNSessionByPeerKey(ctx, peerKey); err != nil || row == nil {
		t.Fatalf("failed cleanup removed old session: row=%+v err=%v", row, err)
	}
	if _, err := db.SQLDB().ExecContext(ctx, "DROP TRIGGER block_restart_start"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start did not recover after cleanup error: %v", err)
	}
	if status, err := svc.GetStatus(ctx); err != nil || status.RestartInvalidatedSessions != 1 || status.ConnectedSessions != 0 {
		t.Fatalf("retry status=%+v err=%v", status, err)
	}
}

func TestRestartExistingClientRecoversThroughUDPHandshake(t *testing.T) {
	db := setupTestDB(t)
	svc, serverID, _, userID, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	defer func() { _ = svc.Stop() }()

	hpKey, err := base64.StdEncoding.DecodeString(svc.cfg.HeaderProtectionKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := base64.StdEncoding.DecodeString(svc.portalPubKey)
	if err != nil {
		t.Fatal(err)
	}
	packet, state, err := health.BuildAWGInitiationPacketObfuscated(serverPub, nil, nil, hpKey, svc.cfg.H1, svc.cfg.S1)
	if err != nil {
		t.Fatal(err)
	}
	peerBytes, err := curve25519.X25519(state.ClientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	peerKey := base64.StdEncoding.EncodeToString(peerBytes)
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: serverID, Protocol: "awg", ClientID: peerKey,
		Name: "restarting-client", ClientParams: map[string]any{"assigned_ip": "10.100.0.30"},
	}); err != nil {
		t.Fatal(err)
	}
	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("no backend tunnels: tunnels=%+v err=%v", tunnels, err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "prior-process-session", UserID: userID,
		BackendTunnelID: tunnels[0].ID, PeerPublicKey: peerKey,
		AssignedIP: "10.100.0.30", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr, ok := svc.endpoint.GetListenAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected endpoint address %T", svc.endpoint.GetListenAddr())
	}
	client, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2048)
	if n, err := client.Read(response); err != nil || n == 0 {
		t.Fatalf("old client did not receive a fresh handshake response: n=%d err=%v", n, err)
	}
	newSession, ok := svc.sessionMgr.GetSession(peerKey)
	if !ok || newSession.ID == "prior-process-session" || newSession.AssignedIP != "10.100.0.30" ||
		svc.forwarder.RouteSessionID(peerKey) != newSession.ID || !svc.HasTransportStateForPeer(peerKey) {
		t.Fatalf("client did not regain a complete data plane: session=%+v found=%v", newSession, ok)
	}
}
