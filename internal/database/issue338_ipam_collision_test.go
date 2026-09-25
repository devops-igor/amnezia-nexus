package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestReadVPNClientIPAssignments_DeduplicatesAndAvoidsCollisions(t *testing.T) {
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

	// 4. Conn4 has no client_params, but vpn_sessions has valid "10.100.0.20" -> should migrate
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

	// 5. Conn5 has same peer-4: peer already has an IP -> should NOT assign
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

	byConn := make(map[string]VPNClientIPAssignment)
	for _, a := range assignments {
		byConn[a.ConnectionID] = a
	}

	// Conn1 should retain "10.100.0.3"
	a1, ok := byConn[conn1ID]
	if !ok || a1.AssignedIP != "10.100.0.3" {
		t.Fatalf("conn1 assignment missing or wrong AssignedIP: %+v", a1)
	}

	// Conn2 had duplicate "10.100.0.3": AssignedIP must be empty to avoid duplicate reservation
	a2, ok := byConn[conn2ID]
	if !ok {
		t.Fatalf("conn2 should be yielded for self-healing, but missing: %+v", byConn)
	}
	if a2.AssignedIP != "" {
		t.Fatalf("conn2 should have empty AssignedIP to prevent duplicate reservation, got: %s", a2.AssignedIP)
	}

	// Conn3 had colliding session IP "10.100.0.3": must NOT migrate
	if a3, ok := byConn[conn3ID]; ok && a3.NeedsMigration {
		t.Fatalf("conn3 should not migrate colliding session IP: %+v", a3)
	}

	// Conn4 was first for "10.100.0.20": should migrate
	a4, ok := byConn[conn4ID]
	if !ok || !a4.NeedsMigration || a4.AssignedIP != "10.100.0.20" {
		t.Fatalf("conn4 should migrate first session IP: %+v", a4)
	}

	// Conn5 had same peer-4 which already has an IP from Conn4: AssignedIP must be empty
	a5, ok := byConn[conn5ID]
	if !ok {
		t.Fatalf("conn5 should be yielded for self-healing, but missing: %+v", byConn)
	}
	if a5.AssignedIP != "" {
		t.Fatalf("conn5 should have empty AssignedIP since peer-4 already has IP, got: %s", a5.AssignedIP)
	}
}
