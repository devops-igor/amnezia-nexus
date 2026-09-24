package vpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
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
	// A backend can still send a packet toward a peer that has not
	// reconnected. Such traffic is dropped and counted, never delivered via
	// a restored stale route; an idle zero counter alone cannot test this.
	if err := svc.forwarder.RouteBackendToClient(tunnels[0].ID, []byte{1}, "10.100.0.3"); !errors.Is(err, forwarder.ErrSessionNotRegistered) {
		t.Fatalf("stale backend return packet was routed: %v", err)
	}
	if status, err := svc.GetStatus(ctx); err != nil || status.ForwarderDropsNoRoute != 1 {
		t.Fatalf("stale packet did not count exactly one no-route drop: status=%+v err=%v", status, err)
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

func TestRestartReservesExistingClientIPBeforeNewConfigAndReconnect(t *testing.T) {
	db := setupTestDB(t)
	original, _, _, userID, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	const oldPeer = "existing-client-with-config"
	const oldIP = "10.100.0.2"
	oldConn := &models.UserConnection{
		UserID: userID, ServerID: 0, Protocol: "awg", ClientID: oldPeer,
		ClientParams: map[string]any{"assigned_ip": oldIP},
	}
	if _, err := db.CreateConnection(ctx, oldConn); err != nil {
		t.Fatal(err)
	}
	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("get backend tunnels: %v", err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "prior-client-session", UserID: userID, BackendTunnelID: tunnels[0].ID,
		PeerPublicKey: oldPeer, AssignedIP: oldIP, Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewVPNService(db, original.cfg)
	if err != nil {
		t.Fatal(err)
	}
	restarted.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if err := restarted.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Stop() }()

	newUserID, err := db.CreateUser(ctx, &models.User{Username: "fresh-client", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	newConfig, _, err := restarted.GenerateClientConfig(ctx, newUserID)
	if err != nil {
		t.Fatal(err)
	}
	newIP := extractAddressFromConfig(t, newConfig)
	if newIP == oldIP {
		t.Fatalf("new client reused existing configured IP %s", oldIP)
	}
	newConns, err := db.GetConnectionsByUserID(ctx, newUserID)
	if err != nil || len(newConns) != 1 || newConns[0].ClientParams["assigned_ip"] != newIP {
		t.Fatalf("new lease was not persisted: connections=%+v err=%v", newConns, err)
	}
	oldSession, _, err := restarted.HandleIncomingPeer(ctx, oldPeer)
	if err != nil || oldSession.AssignedIP != oldIP {
		t.Fatalf("old client lost its configured IP: session=%+v err=%v", oldSession, err)
	}
	newSession, _, err := restarted.HandleIncomingPeer(ctx, newConns[0].ClientID)
	if err != nil || newSession.AssignedIP != newIP {
		t.Fatalf("new client lost its assigned IP: session=%+v err=%v", newSession, err)
	}
	if restarted.forwarder.RouteSessionID(oldPeer) != oldSession.ID || restarted.forwarder.RouteSessionID(newConns[0].ClientID) != newSession.ID {
		t.Fatal("one of the clients lost its forwarder route")
	}
	if ip, ok := restarted.ipam.GetAssignedIP(oldPeer); !ok || ip.String() != oldIP {
		t.Fatalf("old IPAM lease changed: %v present=%t", ip, ok)
	}
	if ip, ok := restarted.ipam.GetAssignedIP(newConns[0].ClientID); !ok || ip.String() != newIP {
		t.Fatalf("new IPAM lease changed: %v present=%t", ip, ok)
	}
	if err := restarted.DisconnectSession(ctx, oldSession.ID); err != nil {
		t.Fatal(err)
	}
	thirdUserID, err := db.CreateUser(ctx, &models.User{Username: "after-disconnect", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	thirdConfig, _, err := restarted.GenerateClientConfig(ctx, thirdUserID)
	if err != nil {
		t.Fatal(err)
	}
	if thirdIP := extractAddressFromConfig(t, thirdConfig); thirdIP == oldIP || thirdIP == newIP {
		t.Fatalf("disconnected client's durable lease was reused: third=%s old=%s new=%s", thirdIP, oldIP, newIP)
	}
}

func TestRestartMigratesSessionOnlyClientIPBeforeDeletingSessions(t *testing.T) {
	db := setupTestDB(t)
	original, _, _, userID, peer := setupTestVPNService(t, db)
	ctx := t.Context()
	conn, err := db.GetConnectionByToken(ctx, peer)
	if err != nil || conn == nil || conn.ClientParams["assigned_ip"] != nil {
		t.Fatalf("expected legacy client without durable IP: conn=%+v err=%v", conn, err)
	}
	if updated, err := db.UpdateConnection(ctx, conn.ID, map[string]any{"server_id": int64(0)}); err != nil || !updated {
		t.Fatalf("mark legacy client as portal connection: updated=%t err=%v", updated, err)
	}
	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("get tunnels: %v", err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "legacy-session-only-lease", UserID: userID, BackendTunnelID: tunnels[0].ID,
		PeerPublicKey: peer, AssignedIP: "10.100.0.2", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewVPNService(db, original.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Stop() }()
	conn, err = db.GetConnectionByToken(ctx, peer)
	if err != nil || conn == nil || conn.ClientParams["assigned_ip"] != "10.100.0.2" {
		t.Fatalf("legacy session IP was not migrated: conn=%+v err=%v", conn, err)
	}
	if ip, ok := restarted.ipam.GetAssignedIP(peer); !ok || ip.String() != "10.100.0.2" {
		t.Fatalf("legacy lease was not reserved: ip=%v present=%t", ip, ok)
	}
	newUserID, err := db.CreateUser(ctx, &models.User{Username: "after-legacy-migration", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	newConfig, _, err := restarted.GenerateClientConfig(ctx, newUserID)
	if err != nil {
		t.Fatal(err)
	}
	if got := extractAddressFromConfig(t, newConfig); got == "10.100.0.2" {
		t.Fatalf("new client reused legacy address %s", got)
	}
}

func TestHandshakeIPAssignmentFailsIfPersistenceFails(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, peer := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Stop() }()
	if _, err := db.SQLDB().ExecContext(ctx, `CREATE TRIGGER reject_client_ip_assignment
		BEFORE UPDATE OF client_params ON user_connections
		BEGIN SELECT RAISE(ABORT, 'persistence unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if session, _, err := svc.HandleIncomingPeer(ctx, peer); err == nil || session != nil {
		t.Fatalf("handshake succeeded without a durable IP: session=%+v err=%v", session, err)
	}
	if _, ok := svc.ipam.GetAssignedIP(peer); ok {
		t.Fatal("failed handshake retained an unpersisted IP lease")
	}
	var sessions int
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM vpn_sessions").Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("failed handshake persisted a session: count=%d err=%v", sessions, err)
	}
	if _, err := db.SQLDB().ExecContext(ctx, "DROP TRIGGER reject_client_ip_assignment"); err != nil {
		t.Fatal(err)
	}
	if session, _, err := svc.HandleIncomingPeer(ctx, peer); err != nil || session == nil || session.AssignedIP == "" {
		t.Fatalf("handshake did not recover after persistence returned: session=%+v err=%v", session, err)
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
	svc, _, _, userID, _ := setupTestVPNService(t, db)
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
		UserID: userID, ServerID: 0, Protocol: "awg", ClientID: peerKey,
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
