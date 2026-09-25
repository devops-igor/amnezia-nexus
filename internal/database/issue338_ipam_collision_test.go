package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestReadVPNClientIPAssignments_LosslessReadAndFaithfulScanning(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "awg0", PublicKey: "tunnel-pub",
		Endpoint: "192.0.2.10:51820",
	})
	if err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "test-user-338"})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()

	// 1. Conn1 has client_params["assigned_ip"] = "10.100.0.3"
	conn1ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-1", UserID: userID, ServerID: 0, Protocol: "awg", ClientID: "peer-1",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.3"},
		CreatedAt:    now.Add(1 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Conn2 has identical client_params["assigned_ip"] = "10.100.0.3" for different peer
	conn2ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-2", UserID: userID, ServerID: 0, Protocol: "awg", ClientID: "peer-2",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.3"},
		CreatedAt:    now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Conn3 has no assigned_ip in client_params, but vpn_sessions has colliding "10.100.0.3"
	conn3ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-3", UserID: userID, ServerID: 0, Protocol: "awg", ClientID: "peer-3",
		ClientParams: map[string]any{},
		CreatedAt:    now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "sess-peer-3", UserID: userID, BackendTunnelID: tunnelID,
		PeerPublicKey: "peer-3", AssignedIP: "10.100.0.3", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}

	// 4. Conn4 has no client_params, but vpn_sessions has valid "10.100.0.20"
	conn4ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-4", UserID: userID, ServerID: 0, Protocol: "awg", ClientID: "peer-4",
		ClientParams: map[string]any{},
		CreatedAt:    now.Add(4 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID: "sess-peer-4", UserID: userID, BackendTunnelID: tunnelID,
		PeerPublicKey: "peer-4", AssignedIP: "10.100.0.20", Status: "connected",
	}); err != nil {
		t.Fatal(err)
	}

	// 5. Conn5 has same peer-4 with another IP
	conn5ID, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-5", UserID: userID, ServerID: 0, Protocol: "awg", ClientID: "peer-4",
		ClientParams: map[string]any{"assigned_ip": "10.100.0.30"},
		CreatedAt:    now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	assignments, err := db.GetVPNClientIPAssignments(ctx)
	if err != nil {
		t.Fatalf("GetVPNClientIPAssignments failed: %v", err)
	}

	if len(assignments) != 5 {
		t.Fatalf("expected 5 assignments in lossless read, got %d", len(assignments))
	}

	byConn := make(map[string]VPNClientIPAssignment)
	for _, a := range assignments {
		byConn[a.ConnectionID] = a
	}

	// Conn1 should retain "10.100.0.3", UserID, and NeedsMigration=false
	a1, ok := byConn[conn1ID]
	if !ok || a1.AssignedIP != "10.100.0.3" || a1.UserID != userID || a1.NeedsMigration {
		t.Fatalf("conn1 assignment invalid: %+v", a1)
	}

	// Conn2 should losslessly retain "10.100.0.3", UserID, and NeedsMigration=false
	a2, ok := byConn[conn2ID]
	if !ok || a2.AssignedIP != "10.100.0.3" || a2.UserID != userID || a2.NeedsMigration {
		t.Fatalf("conn2 assignment invalid: %+v", a2)
	}

	// Conn3 should scan session IP "10.100.0.3", UserID, and NeedsMigration=true
	a3, ok := byConn[conn3ID]
	if !ok || a3.AssignedIP != "10.100.0.3" || a3.UserID != userID || !a3.NeedsMigration {
		t.Fatalf("conn3 assignment invalid: %+v", a3)
	}

	// Conn4 should scan session IP "10.100.0.20", UserID, and NeedsMigration=true
	a4, ok := byConn[conn4ID]
	if !ok || a4.AssignedIP != "10.100.0.20" || a4.UserID != userID || !a4.NeedsMigration {
		t.Fatalf("conn4 assignment invalid: %+v", a4)
	}

	// Conn5 should retain "10.100.0.30", UserID, and NeedsMigration=false
	a5, ok := byConn[conn5ID]
	if !ok || a5.AssignedIP != "10.100.0.30" || a5.UserID != userID || a5.NeedsMigration {
		t.Fatalf("conn5 assignment invalid: %+v", a5)
	}
}
