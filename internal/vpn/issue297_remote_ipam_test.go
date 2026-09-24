package vpn

import (
	"net"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRestartReservesOnlyPortalClientAddresses(t *testing.T) {
	db := setupTestDB(t)
	original, server1, server2, userID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	for _, remote := range []struct {
		server int64
		peer   string
	}{
		{server1, "remote-one"},
		{server2, "remote-two"},
	} {
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID: userID, ServerID: remote.server, Protocol: "awg", ClientID: remote.peer,
			ClientParams: map[string]any{"assigned_ip": "10.100.0.20"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: 0, Protocol: "awg", ClientID: "portal-client",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.30"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID: userID, ServerID: server1, Protocol: "awg", ClientID: "remote-session-only",
	}); err != nil {
		t.Fatal(err)
	}
	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil || len(tunnels) == 0 {
		t.Fatalf("get backend tunnels: tunnels=%+v err=%v", tunnels, err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "stale-remote-session", UserID: userID, BackendTunnelID: tunnels[0].ID,
		PeerPublicKey: "remote-session-only", AssignedIP: "10.100.0.21", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}

	restarted, err := NewVPNService(db, original.cfg)
	if err != nil {
		t.Fatalf("remote servers reused an address and blocked portal startup: %v", err)
	}
	if restarted.ipam.IsAllocated(net.ParseIP("10.100.0.20")) || restarted.ipam.IsAllocated(net.ParseIP("10.100.0.21")) {
		t.Fatal("remote-server IP was reserved in the portal IPAM")
	}
	if ip, ok := restarted.ipam.GetAssignedIP("portal-client"); !ok || ip.String() != "10.100.0.30" {
		t.Fatalf("portal client's IP was not reserved: ip=%v present=%t", ip, ok)
	}
	if err := restarted.Start(ctx); err != nil {
		t.Fatalf("restart with remote-server address reuse failed: %v", err)
	}
	defer func() { _ = restarted.Stop() }()
	for _, peer := range []string{"remote-one", "remote-two"} {
		conn, err := db.GetConnectionByToken(ctx, peer)
		if err != nil || conn == nil || conn.ClientParams["assigned_ip"] != "10.100.0.20" {
			t.Fatalf("remote connection %s changed: conn=%+v err=%v", peer, conn, err)
		}
	}
	legacyRemote, err := db.GetConnectionByToken(ctx, "remote-session-only")
	if err != nil || legacyRemote == nil || legacyRemote.ClientParams["assigned_ip"] != nil {
		t.Fatalf("remote session IP was migrated into a remote connection: conn=%+v err=%v", legacyRemote, err)
	}
	if restarted.ipam.IsAllocated(net.ParseIP("10.100.0.20")) || restarted.ipam.IsAllocated(net.ParseIP("10.100.0.21")) {
		t.Fatal("restart reserved a remote-server IP in the portal IPAM")
	}
}
