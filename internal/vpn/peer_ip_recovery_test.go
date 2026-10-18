package vpn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
)

func createTestUser(t *testing.T, db *database.DB, username string) string {
	t.Helper()
	id, err := db.CreateUser(context.Background(), &models.User{Username: username, Enabled: true})
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return id
}

func createTestConn(t *testing.T, db *database.DB, id, userID, clientID string, params map[string]any, createdAt time.Time) string {
	t.Helper()
	connID, err := db.CreateConnection(context.Background(), &models.UserConnection{
		ID:           id,
		UserID:       userID,
		ClientID:     clientID,
		ClientParams: params,
		CreatedAt:    createdAt,
	})
	if err != nil {
		t.Fatalf("create conn %s: %v", id, err)
	}
	return connID
}

func TestSortAssignments(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	t.Run("empty and single element", func(t *testing.T) {
		var empty []database.VPNClientIPAssignment
		sortAssignments(empty)
		if len(empty) != 0 {
			t.Fatalf("expected 0 elements, got %d", len(empty))
		}

		single := []database.VPNClientIPAssignment{
			{ConnectionID: "conn-1", CreatedAt: now},
		}
		sortAssignments(single)
		if single[0].ConnectionID != "conn-1" {
			t.Fatalf("expected conn-1, got %s", single[0].ConnectionID)
		}
	})

	t.Run("durable beats migration fallback regardless of age", func(t *testing.T) {
		assignments := []database.VPNClientIPAssignment{
			{ConnectionID: "migration-older", NeedsMigration: true, CreatedAt: now.Add(-2 * time.Hour)},
			{ConnectionID: "durable-newer", NeedsMigration: false, CreatedAt: now.Add(-10 * time.Minute)},
		}
		sortAssignments(assignments)
		if assignments[0].ConnectionID != "durable-newer" || assignments[1].ConnectionID != "migration-older" {
			t.Fatalf("expected durable-newer first, got %+v", assignments)
		}
	})

	t.Run("older createdAt beats newer createdAt when migration flag matches", func(t *testing.T) {
		assignments := []database.VPNClientIPAssignment{
			{ConnectionID: "newer", NeedsMigration: false, CreatedAt: now.Add(-10 * time.Minute)},
			{ConnectionID: "older", NeedsMigration: false, CreatedAt: now.Add(-1 * time.Hour)},
		}
		sortAssignments(assignments)
		if assignments[0].ConnectionID != "older" || assignments[1].ConnectionID != "newer" {
			t.Fatalf("expected older first, got %+v", assignments)
		}
	})

	t.Run("tie breaking by connectionID when flags and timestamps match", func(t *testing.T) {
		assignments := []database.VPNClientIPAssignment{
			{ConnectionID: "conn-z", NeedsMigration: false, CreatedAt: now},
			{ConnectionID: "conn-a", NeedsMigration: false, CreatedAt: now},
			{ConnectionID: "conn-m", NeedsMigration: false, CreatedAt: now},
		}
		sortAssignments(assignments)
		expected := []string{"conn-a", "conn-m", "conn-z"}
		for i, exp := range expected {
			if assignments[i].ConnectionID != exp {
				t.Fatalf("at index %d: expected %s, got %s", i, exp, assignments[i].ConnectionID)
			}
		}
	})

	t.Run("full ranking across all dimensions", func(t *testing.T) {
		assignments := []database.VPNClientIPAssignment{
			{ConnectionID: "mig-new", NeedsMigration: true, CreatedAt: now.Add(-5 * time.Minute)},
			{ConnectionID: "dur-old-2", NeedsMigration: false, CreatedAt: now.Add(-1 * time.Hour)},
			{ConnectionID: "mig-old-b", NeedsMigration: true, CreatedAt: now.Add(-2 * time.Hour)},
			{ConnectionID: "dur-new", NeedsMigration: false, CreatedAt: now.Add(-10 * time.Minute)},
			{ConnectionID: "dur-old-1", NeedsMigration: false, CreatedAt: now.Add(-1 * time.Hour)},
			{ConnectionID: "mig-old-a", NeedsMigration: true, CreatedAt: now.Add(-2 * time.Hour)},
		}
		sortAssignments(assignments)
		expected := []string{"dur-old-1", "dur-old-2", "dur-new", "mig-old-a", "mig-old-b", "mig-new"}
		for i, exp := range expected {
			if assignments[i].ConnectionID != exp {
				t.Fatalf("at index %d: expected %s, got %s", i, exp, assignments[i].ConnectionID)
			}
		}
	})
}

func TestQuarantinePersistedAssignment(t *testing.T) {
	ctx := context.Background()

	t.Run("single claimant without retiring keypair", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "quarantine-user-1")
		connID := createTestConn(t, db, "conn-q-1", userID, "client-q-1", map[string]any{
			"assigned_ip":        "10.100.0.10",
			"client_private_key": "privkey123",
			"extra_param":        "keep-me",
		}, time.Now().UTC())

		claimant := database.VPNClientIPAssignment{
			ConnectionID: connID,
			UserID:       userID,
			PeerKey:      "peer-q-1",
			AssignedIP:   "10.100.0.10",
			ClientParams: map[string]any{
				"assigned_ip":        "10.100.0.10",
				"client_private_key": "privkey123",
				"extra_param":        "keep-me",
			},
		}

		if err := quarantinePersistedAssignment(ctx, db, claimant, "10.100.0.10", false); err != nil {
			t.Fatalf("quarantine failed: %v", err)
		}

		updatedConn, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		if updatedConn.ClientID != "client-q-1" {
			t.Fatalf("expected clientID to be preserved, got %s", updatedConn.ClientID)
		}
		if _, exists := updatedConn.ClientParams["assigned_ip"]; exists {
			t.Fatalf("assigned_ip was not removed from client_params")
		}
		if updatedConn.ClientParams["quarantined_ip_collision"] != "10.100.0.10" {
			t.Fatalf("unexpected quarantined_ip_collision: %v", updatedConn.ClientParams["quarantined_ip_collision"])
		}
		if req, ok := updatedConn.ClientParams["config_regeneration_required"].(bool); !ok || !req {
			t.Fatalf("config_regeneration_required not true: %v", updatedConn.ClientParams["config_regeneration_required"])
		}
		if updatedConn.ClientParams["client_private_key"] != "privkey123" {
			t.Fatalf("expected client_private_key preserved when retireKeypair=false")
		}
		if updatedConn.ClientParams["extra_param"] != "keep-me" {
			t.Fatalf("extra_param was lost")
		}
	})

	t.Run("retiring keypair clears client_id and private key", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "quarantine-user-2")
		connID := createTestConn(t, db, "conn-q-2", userID, "client-q-2", map[string]any{
			"assigned_ip":        "10.100.0.20",
			"client_private_key": "privkey456",
		}, time.Now().UTC())

		claimant := database.VPNClientIPAssignment{
			ConnectionID: connID,
			UserID:       userID,
			PeerKey:      "peer-q-2",
			AssignedIP:   "10.100.0.20",
			ClientParams: map[string]any{
				"assigned_ip":        "10.100.0.20",
				"client_private_key": "privkey456",
			},
		}

		if err := quarantinePersistedAssignment(ctx, db, claimant, "10.100.0.20", true); err != nil {
			t.Fatalf("quarantine failed: %v", err)
		}

		updatedConn, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		if updatedConn.ClientID != "" {
			t.Fatalf("expected clientID to be cleared, got %q", updatedConn.ClientID)
		}
		if _, exists := updatedConn.ClientParams["client_private_key"]; exists {
			t.Fatalf("client_private_key was not removed from client_params")
		}
	})

	t.Run("legacy migration claimant cleans up colliding active session", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "quarantine-user-3")
		connID := createTestConn(t, db, "conn-q-3", userID, "client-q-3", map[string]any{
			"assigned_ip": "10.100.0.30",
		}, time.Now().UTC())

		serverID, err := db.CreateServer(ctx, &models.Server{Name: "Server Q3", Host: "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      serverID,
			InterfaceName: "awg0",
			PublicKey:     "tunnel-pub-q3",
			Endpoint:      "192.0.2.1:51820",
		})
		if err != nil {
			t.Fatal(err)
		}

		peerKey := "peer-pub-key-q3"
		sess := &models.VPNSession{
			ID:              "sess-q-3",
			UserID:          userID,
			BackendTunnelID: tunnelID,
			PeerPublicKey:   peerKey,
			Status:          "connected",
			AssignedIP:      "10.100.0.30",
			ConnectedAt:     time.Now().UTC(),
		}
		if err := db.CreateVPNSession(ctx, sess); err != nil {
			t.Fatal(err)
		}

		claimant := database.VPNClientIPAssignment{
			ConnectionID:   connID,
			UserID:         userID,
			PeerKey:        peerKey,
			AssignedIP:     "10.100.0.30",
			NeedsMigration: true,
			ClientParams:   map[string]any{"assigned_ip": "10.100.0.30"},
		}

		if err := quarantinePersistedAssignment(ctx, db, claimant, "10.100.0.30", false); err != nil {
			t.Fatalf("quarantine failed: %v", err)
		}

		retrievedSess, err := db.GetVPNSessionByPeerKey(ctx, peerKey)
		if err == nil && retrievedSess != nil {
			t.Fatalf("expected session %s to be deleted, but it still exists", sess.ID)
		}
	})

	t.Run("returns error when connection is not found", func(t *testing.T) {
		db := setupTestDB(t)
		claimant := database.VPNClientIPAssignment{
			ConnectionID: "non-existent-conn",
			ClientParams: map[string]any{},
		}
		if err := quarantinePersistedAssignment(ctx, db, claimant, "10.100.0.99", false); err == nil {
			t.Fatalf("expected error for non-existent connection, got nil")
		}
	})
}

func TestResolvePeerClaims(t *testing.T) {
	ctx := context.Background()

	t.Run("empty and single claim unchanged", func(t *testing.T) {
		db := setupTestDB(t)
		res, err := resolvePeerClaims(ctx, db, nil)
		if err != nil || len(res) != 0 {
			t.Fatalf("expected empty result, got %v (err=%v)", res, err)
		}

		single := []database.VPNClientIPAssignment{
			{ConnectionID: "c1", AssignedIP: "10.100.0.1"},
		}
		res, err = resolvePeerClaims(ctx, db, single)
		if err != nil || len(res) != 1 || res[0].ConnectionID != "c1" {
			t.Fatalf("expected single result, got %v (err=%v)", res, err)
		}
	})

	t.Run("multiple claims with unanimous IP unchanged", func(t *testing.T) {
		db := setupTestDB(t)
		claims := []database.VPNClientIPAssignment{
			{ConnectionID: "c1", AssignedIP: "10.100.0.5"},
			{ConnectionID: "c2", AssignedIP: "10.100.0.5"},
		}
		res, err := resolvePeerClaims(ctx, db, claims)
		if err != nil || len(res) != 2 {
			t.Fatalf("expected 2 claims unchanged, got %v (err=%v)", res, err)
		}
	})

	t.Run("conflicting claims resolve to winner and quarantine losers", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "claims-user")
		now := time.Now().UTC()

		c1ID := createTestConn(t, db, "conn-claim-win", userID, "client-win", map[string]any{
			"assigned_ip": "10.100.0.10",
		}, now.Add(-1*time.Hour))

		c2ID := createTestConn(t, db, "conn-claim-lose", userID, "client-lose", map[string]any{
			"assigned_ip":        "10.100.0.20",
			"client_private_key": "secret",
		}, now.Add(-10*time.Minute))

		claims := []database.VPNClientIPAssignment{
			{
				ConnectionID:   c2ID,
				UserID:         userID,
				PeerKey:        "peer-claim-1",
				AssignedIP:     "10.100.0.20",
				NeedsMigration: false,
				CreatedAt:      now.Add(-10 * time.Minute),
				ClientParams:   map[string]any{"assigned_ip": "10.100.0.20", "client_private_key": "secret"},
			},
			{
				ConnectionID:   c1ID,
				UserID:         userID,
				PeerKey:        "peer-claim-1",
				AssignedIP:     "10.100.0.10",
				NeedsMigration: false,
				CreatedAt:      now.Add(-1 * time.Hour),
				ClientParams:   map[string]any{"assigned_ip": "10.100.0.10"},
			},
		}

		active, err := resolvePeerClaims(ctx, db, claims)
		if err != nil {
			t.Fatalf("resolvePeerClaims failed: %v", err)
		}
		if len(active) != 1 || active[0].ConnectionID != c1ID {
			t.Fatalf("expected winning active claim %s, got %v", c1ID, active)
		}

		loserConn, err := db.GetConnection(ctx, c2ID)
		if err != nil {
			t.Fatal(err)
		}
		if loserConn.ClientID != "" {
			t.Fatalf("expected loser clientID to be retired, got %s", loserConn.ClientID)
		}
		if loserConn.ClientParams["quarantined_ip_collision"] != "10.100.0.20" {
			t.Fatalf("unexpected quarantined IP: %v", loserConn.ClientParams["quarantined_ip_collision"])
		}
	})
}

func TestReserveSinglePeerForIP(t *testing.T) {
	ctx := context.Background()

	t.Run("successful reservation in IPAM", func(t *testing.T) {
		db := setupTestDB(t)
		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		ip := net.ParseIP("10.100.0.15")
		claims := []database.VPNClientIPAssignment{
			{ConnectionID: "conn-s-1", AssignedIP: "10.100.0.15"},
		}

		if err := reserveSinglePeerForIP(ctx, db, mgr, "peer-s-1", claims, ip, "10.100.0.15"); err != nil {
			t.Fatalf("expected success, got %v", err)
		}

		assigned, ok := mgr.GetAssignedIP("peer-s-1")
		if !ok || !assigned.Equal(ip) {
			t.Fatalf("expected assigned IP %s, got %v (ok=%v)", ip, assigned, ok)
		}
	})

	t.Run("out of subnet or gateway reserved IP handled gracefully", func(t *testing.T) {
		db := setupTestDB(t)
		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		outIP := net.ParseIP("192.168.1.1")
		if err := reserveSinglePeerForIP(ctx, db, mgr, "peer-out", nil, outIP, "192.168.1.1"); err != nil {
			t.Fatalf("expected nil on out-of-subnet IP, got %v", err)
		}

		gwIP := net.ParseIP("10.100.0.1")
		if err := reserveSinglePeerForIP(ctx, db, mgr, "peer-gw", nil, gwIP, "10.100.0.1"); err != nil {
			t.Fatalf("expected nil on gateway IP, got %v", err)
		}
	})

	t.Run("peer already assigned different IP in IPAM triggers quarantine", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "single-peer-user-1")
		connID := createTestConn(t, db, "conn-diff-ip", userID, "client-diff-ip", map[string]any{
			"assigned_ip":        "10.100.0.50",
			"client_private_key": "priv",
		}, time.Now().UTC())

		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		if err := mgr.Reserve(net.ParseIP("10.100.0.30"), "peer-diff-1"); err != nil {
			t.Fatal(err)
		}

		claims := []database.VPNClientIPAssignment{
			{
				ConnectionID: connID,
				UserID:       userID,
				PeerKey:      "peer-diff-1",
				AssignedIP:   "10.100.0.50",
				ClientParams: map[string]any{"assigned_ip": "10.100.0.50", "client_private_key": "priv"},
			},
		}

		if err := reserveSinglePeerForIP(ctx, db, mgr, "peer-diff-1", claims, net.ParseIP("10.100.0.50"), "10.100.0.50"); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}

		conn, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatal(err)
		}
		if conn.ClientID != "client-diff-ip" {
			t.Fatalf("single claim should retain clientID, got %s", conn.ClientID)
		}
		if conn.ClientParams["quarantined_ip_collision"] != "10.100.0.50" {
			t.Fatalf("quarantine IP mismatch: %v", conn.ClientParams["quarantined_ip_collision"])
		}
	})

	t.Run("IP already allocated to another peer triggers quarantine and multi-claim retires keypair", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "single-peer-user-2")
		conn1ID := createTestConn(t, db, "conn-col-1", userID, "client-col", map[string]any{
			"assigned_ip":        "10.100.0.70",
			"client_private_key": "k1",
		}, time.Now().UTC())

		conn2ID := createTestConn(t, db, "conn-col-2", userID, "client-col", map[string]any{
			"assigned_ip":        "10.100.0.70",
			"client_private_key": "k1",
		}, time.Now().UTC())

		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		if err := mgr.Reserve(net.ParseIP("10.100.0.70"), "other-peer"); err != nil {
			t.Fatal(err)
		}

		claims := []database.VPNClientIPAssignment{
			{
				ConnectionID: conn1ID,
				UserID:       userID,
				PeerKey:      "colliding-peer",
				AssignedIP:   "10.100.0.70",
				ClientParams: map[string]any{"assigned_ip": "10.100.0.70", "client_private_key": "k1"},
			},
			{
				ConnectionID: conn2ID,
				UserID:       userID,
				PeerKey:      "colliding-peer",
				AssignedIP:   "10.100.0.70",
				ClientParams: map[string]any{"assigned_ip": "10.100.0.70", "client_private_key": "k1"},
			},
		}

		if err := reserveSinglePeerForIP(ctx, db, mgr, "colliding-peer", claims, net.ParseIP("10.100.0.70"), "10.100.0.70"); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}

		for _, cid := range []string{conn1ID, conn2ID} {
			c, err := db.GetConnection(ctx, cid)
			if err != nil {
				t.Fatal(err)
			}
			if c.ClientID != "" {
				t.Fatalf("expected clientID retired for %s, got %s", cid, c.ClientID)
			}
			if _, exists := c.ClientParams["client_private_key"]; exists {
				t.Fatalf("expected client_private_key deleted for %s", cid)
			}
		}
	})
}

func TestReconcileCollidingPeersForIP(t *testing.T) {
	ctx := context.Background()

	t.Run("winner selected by rank and single-claim retains keypair while multi-row loser retires", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "reconcile-user")
		now := time.Now().UTC()
		targetIP := "10.100.0.80"

		connWinID := createTestConn(t, db, "conn-peer-a", userID, "client-a", map[string]any{
			"assigned_ip":        targetIP,
			"client_private_key": "priv-a",
		}, now.Add(-2*time.Hour))

		connLoser1ID := createTestConn(t, db, "conn-peer-b1", userID, "client-b", map[string]any{
			"assigned_ip":        targetIP,
			"client_private_key": "priv-b",
		}, now.Add(-1*time.Hour))

		connLoser2ID := createTestConn(t, db, "conn-peer-b2", userID, "client-b", map[string]any{
			"assigned_ip":        targetIP,
			"client_private_key": "priv-b",
		}, now.Add(-30*time.Minute))

		peersForIP := map[string][]database.VPNClientIPAssignment{
			"peer-a": {
				{
					ConnectionID: connWinID,
					UserID:       userID,
					PeerKey:      "peer-a",
					AssignedIP:   targetIP,
					CreatedAt:    now.Add(-2 * time.Hour),
					ClientParams: map[string]any{"assigned_ip": targetIP, "client_private_key": "priv-a"},
				},
			},
			"peer-b": {
				{
					ConnectionID: connLoser1ID,
					UserID:       userID,
					PeerKey:      "peer-b",
					AssignedIP:   targetIP,
					CreatedAt:    now.Add(-1 * time.Hour),
					ClientParams: map[string]any{"assigned_ip": targetIP, "client_private_key": "priv-b"},
				},
				{
					ConnectionID: connLoser2ID,
					UserID:       userID,
					PeerKey:      "peer-b",
					AssignedIP:   targetIP,
					CreatedAt:    now.Add(-30 * time.Minute),
					ClientParams: map[string]any{"assigned_ip": targetIP, "client_private_key": "priv-b"},
				},
			},
		}

		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		if err := reconcileCollidingPeersForIP(ctx, db, mgr, peersForIP, net.ParseIP(targetIP), targetIP); err != nil {
			t.Fatalf("reconcileCollidingPeersForIP failed: %v", err)
		}

		assigned, ok := mgr.GetAssignedIP("peer-a")
		if !ok || assigned.String() != targetIP {
			t.Fatalf("expected peer-a in IPAM with %s, got %v (ok=%v)", targetIP, assigned, ok)
		}

		winConn, err := db.GetConnection(ctx, connWinID)
		if err != nil {
			t.Fatal(err)
		}
		if winConn.ClientID != "client-a" || winConn.ClientParams["assigned_ip"] != targetIP {
			t.Fatalf("winner connection mutated unexpectedly: %+v", winConn)
		}

		for _, loserID := range []string{connLoser1ID, connLoser2ID} {
			lc, err := db.GetConnection(ctx, loserID)
			if err != nil {
				t.Fatal(err)
			}
			if lc.ClientID != "" {
				t.Fatalf("expected loser clientID retired, got %s", lc.ClientID)
			}
			if _, exists := lc.ClientParams["assigned_ip"]; exists {
				t.Fatalf("expected assigned_ip cleared on loser")
			}
			if lc.ClientParams["quarantined_ip_collision"] != targetIP {
				t.Fatalf("expected quarantined_ip_collision=%s, got %v", targetIP, lc.ClientParams["quarantined_ip_collision"])
			}
			if _, exists := lc.ClientParams["client_private_key"]; exists {
				t.Fatalf("expected client_private_key deleted on multi-row loser")
			}
		}
	})

	t.Run("single-row loser retains keypair while quarantined", func(t *testing.T) {
		db := setupTestDB(t)
		userID := createTestUser(t, db, "reconcile-user-2")
		now := time.Now().UTC()
		targetIP := "10.100.0.85"

		connWinID := createTestConn(t, db, "conn-w2", userID, "client-w2", map[string]any{
			"assigned_ip": targetIP,
		}, now.Add(-2*time.Hour))

		connLoserID := createTestConn(t, db, "conn-l2", userID, "client-l2", map[string]any{
			"assigned_ip":        targetIP,
			"client_private_key": "loser-key",
		}, now.Add(-1*time.Hour))

		peersForIP := map[string][]database.VPNClientIPAssignment{
			"peer-w2": {
				{
					ConnectionID: connWinID,
					UserID:       userID,
					PeerKey:      "peer-w2",
					AssignedIP:   targetIP,
					CreatedAt:    now.Add(-2 * time.Hour),
					ClientParams: map[string]any{"assigned_ip": targetIP},
				},
			},
			"peer-l2": {
				{
					ConnectionID: connLoserID,
					UserID:       userID,
					PeerKey:      "peer-l2",
					AssignedIP:   targetIP,
					CreatedAt:    now.Add(-1 * time.Hour),
					ClientParams: map[string]any{"assigned_ip": targetIP, "client_private_key": "loser-key"},
				},
			},
		}

		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		if err := reconcileCollidingPeersForIP(ctx, db, mgr, peersForIP, net.ParseIP(targetIP), targetIP); err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}

		lc, err := db.GetConnection(ctx, connLoserID)
		if err != nil {
			t.Fatal(err)
		}
		if lc.ClientID != "client-l2" {
			t.Fatalf("single-row loser clientID should be preserved, got %s", lc.ClientID)
		}
		if lc.ClientParams["client_private_key"] != "loser-key" {
			t.Fatalf("single-row loser private key should be preserved, got %v", lc.ClientParams["client_private_key"])
		}
		if _, exists := lc.ClientParams["assigned_ip"]; exists {
			t.Fatalf("assigned_ip should be cleared")
		}
	})
}

func TestReservePersistedClientIPs(t *testing.T) {
	ctx := context.Background()

	t.Run("nil arguments return nil", func(t *testing.T) {
		db := setupTestDB(t)
		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		if err := reservePersistedClientIPs(ctx, nil, mgr); err != nil {
			t.Fatalf("expected nil on nil db, got %v", err)
		}
		if err := reservePersistedClientIPs(ctx, db, nil); err != nil {
			t.Fatalf("expected nil on nil ipam, got %v", err)
		}
	})

	t.Run("end-to-end recovery coordination with mixed records", func(t *testing.T) {
		db := setupTestDB(t)
		mgr, err := ipam.NewIPAM("10.100.0.0/24")
		if err != nil {
			t.Fatal(err)
		}

		userID := createTestUser(t, db, "e2e-user")
		now := time.Now().UTC()

		createTestConn(t, db, "e2e-single", userID, "e2e-client-1", map[string]any{
			"assigned_ip": "10.100.0.10",
		}, now.Add(-10*time.Minute))

		c2A := createTestConn(t, db, "e2e-peer2-win", userID, "e2e-client-2", map[string]any{
			"assigned_ip": "10.100.0.20",
		}, now.Add(-10*time.Minute))

		c2B := createTestConn(t, db, "e2e-peer2-lose", userID, "e2e-client-2", map[string]any{
			"assigned_ip": "10.100.0.30",
		}, now.Add(-5*time.Minute))

		c3A := createTestConn(t, db, "e2e-peer3-win", userID, "e2e-client-3", map[string]any{
			"assigned_ip": "10.100.0.50",
		}, now.Add(-2*time.Hour))

		c3B := createTestConn(t, db, "e2e-peer4-lose", userID, "e2e-client-4", map[string]any{
			"assigned_ip": "10.100.0.50",
		}, now.Add(-1*time.Hour))

		if err := reservePersistedClientIPs(ctx, db, mgr); err != nil {
			t.Fatalf("reservePersistedClientIPs failed: %v", err)
		}

		ip1, ok1 := mgr.GetAssignedIP("e2e-client-1")
		if !ok1 || ip1.String() != "10.100.0.10" {
			t.Fatalf("expected e2e-client-1 at 10.100.0.10, got %v", ip1)
		}

		ip2, ok2 := mgr.GetAssignedIP("e2e-client-2")
		if !ok2 || ip2.String() != "10.100.0.20" {
			t.Fatalf("expected e2e-client-2 at 10.100.0.20, got %v", ip2)
		}

		ip3, ok3 := mgr.GetAssignedIP("e2e-client-3")
		if !ok3 || ip3.String() != "10.100.0.50" {
			t.Fatalf("expected e2e-client-3 at 10.100.0.50, got %v", ip3)
		}

		if ip4, ok4 := mgr.GetAssignedIP("e2e-client-4"); ok4 {
			t.Fatalf("e2e-client-4 should not be in IPAM, got %v", ip4)
		}

		loseConn2, err := db.GetConnection(ctx, c2B)
		if err != nil {
			t.Fatal(err)
		}
		if loseConn2.ClientParams["quarantined_ip_collision"] != "10.100.0.30" {
			t.Fatalf("expected c2B quarantined for 10.100.0.30, got %v", loseConn2.ClientParams["quarantined_ip_collision"])
		}

		loseConn3, err := db.GetConnection(ctx, c3B)
		if err != nil {
			t.Fatal(err)
		}
		if loseConn3.ClientParams["quarantined_ip_collision"] != "10.100.0.50" {
			t.Fatalf("expected c3B quarantined for 10.100.0.50, got %v", loseConn3.ClientParams["quarantined_ip_collision"])
		}

		_ = c2A
		_ = c3A
	})
}
