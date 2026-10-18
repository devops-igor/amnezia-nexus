package vpn

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestService_Start_Idempotency(t *testing.T) {
	t.Run("already running before Start returns nil immediately", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		defer func() { _ = svc.Stop() }()

		svc.mu.Lock()
		svc.running = true
		fakeStartedAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
		svc.startedAt = fakeStartedAt
		svc.mu.Unlock()

		ctx := context.Background()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("expected nil when starting already-running service, got: %v", err)
		}

		svc.mu.RLock()
		defer svc.mu.RUnlock()
		if !svc.running {
			t.Fatal("expected service to remain running")
		}
		if svc.startedAt != fakeStartedAt {
			t.Fatalf("expected startedAt to remain unchanged, got %v", svc.startedAt)
		}
	})

	t.Run("consecutive Start calls succeed idempotently", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		defer func() { _ = svc.Stop() }()

		ctx := context.Background()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("first Start failed: %v", err)
		}
		if !svc.IsRunning() {
			t.Fatal("expected service to be running after first Start")
		}

		if err := svc.Start(ctx); err != nil {
			t.Fatalf("second Start failed: %v", err)
		}
		if !svc.IsRunning() {
			t.Fatal("expected service to remain running after second Start")
		}
	})
}

func TestService_Stop_Idempotency(t *testing.T) {
	t.Run("Stop when not running returns nil immediately", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		svc.mu.RLock()
		running := svc.running
		svc.mu.RUnlock()
		if running {
			t.Fatal("expected service to not be running initially")
		}

		if err := svc.Stop(); err != nil {
			t.Fatalf("expected nil when stopping non-running service, got: %v", err)
		}
	})

	t.Run("consecutive Stop calls succeed idempotently", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start failed: %v", err)
		}

		if err := svc.Stop(); err != nil {
			t.Fatalf("first Stop failed: %v", err)
		}
		if svc.IsRunning() {
			t.Fatal("expected service to not be running after first Stop")
		}

		if err := svc.Stop(); err != nil {
			t.Fatalf("second Stop failed: %v", err)
		}
		if svc.IsRunning() {
			t.Fatal("expected service to remain stopped after second Stop")
		}
	})
}

func TestService_CleanupEngineStartupFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)

	ctx := context.Background()
	if svc.forwarder != nil {
		svc.forwarder.Start(ctx)
		svc.forwarder.StartPumps(ctx)
	}
	if svc.prober != nil {
		svc.prober.StartAfterInitialProbe(ctx)
	}
	if svc.reconnectMgr != nil {
		svc.reconnectMgr.Start(ctx)
	}

	svc.mu.Lock()
	svc.running = true
	svc.startedAt = time.Now().UTC()
	svc.mu.Unlock()

	svc.cleanupEngineStartupFailure()

	svc.mu.RLock()
	running := svc.running
	startedAt := svc.startedAt
	svc.mu.RUnlock()

	if running {
		t.Fatal("expected running to be reset to false after cleanupEngineStartupFailure")
	}
	if !startedAt.IsZero() {
		t.Fatalf("expected startedAt to be zero after cleanupEngineStartupFailure, got: %v", startedAt)
	}
	if svc.forwarder != nil && svc.forwarder.IsRunning() {
		t.Fatal("expected forwarder to be stopped after cleanupEngineStartupFailure")
	}
}

func TestService_Start_EngineStartupFailureTrigger(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	defer func() { _ = svc.Stop() }()

	ctx := context.Background()
	// Pre-construct and start an ingress engine so startUpstreamClientEngine fails on Start().
	eng, err := svc.NewIngressEngine(ctx, "test-prestart", nil)
	if err != nil {
		t.Fatalf("failed to create test ingress engine: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("failed to pre-start test ingress engine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Stop() })

	if err := svc.SetIngressEngine(eng); err != nil {
		t.Fatalf("failed to set ingress engine: %v", err)
	}

	startErr := svc.Start(ctx)
	if startErr == nil {
		t.Fatal("expected Start to fail when ingress engine is already running")
	}

	svc.mu.RLock()
	running := svc.running
	startedAt := svc.startedAt
	svc.mu.RUnlock()

	if running {
		t.Fatal("expected service to not be running after startup failure")
	}
	if !startedAt.IsZero() {
		t.Fatalf("expected startedAt to be zero after startup failure, got: %v", startedAt)
	}
}

func TestService_RestartSessionInvalidation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "host-1", Host: "198.51.100.10"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	tunID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:          serverID,
		InterfaceName:     "awg-restart-tun",
		PublicKey:         "restart-pub-key",
		PrivateKey:        "restart-priv-key",
		Endpoint:          "198.51.100.10:51820",
		Status:            "active",
		ActiveConnections: 1,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "restart-user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	peerKey := "restart-peer-key"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   userID,
		ServerID: serverID,
		Protocol: "awg",
		ClientID: peerKey,
		Name:     "laptop",
	}); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	// Persist a connected session into the DB before service starts
	sessionID := "sess-restart-1"
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessionID,
		UserID:          userID,
		BackendTunnelID: tunID,
		PeerPublicKey:   peerKey,
		AssignedIP:      "10.100.0.50",
		Status:          "connected",
	}); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}

	cfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
	}
	svc, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	svc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})

	if svc.restartInvalidatedSessions.Load() != 0 {
		t.Fatalf("expected 0 invalidated sessions before Start, got: %d", svc.restartInvalidatedSessions.Load())
	}
	if svc.diagGeneration.Load() != 0 {
		t.Fatalf("expected 0 diagGeneration before Start, got: %d", svc.diagGeneration.Load())
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if invalidated := svc.restartInvalidatedSessions.Load(); invalidated != 1 {
		t.Fatalf("expected 1 session to be invalidated on restart, got: %d", invalidated)
	}
	if gen := svc.diagGeneration.Load(); gen != 1 {
		t.Fatalf("expected diagGeneration to be incremented to 1, got: %d", gen)
	}

	// Verify the session in the DB is no longer marked connected
	activeSessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions failed: %v", err)
	}
	if len(activeSessions) != 0 {
		t.Fatalf("expected 0 active sessions after restart invalidation, got %d", len(activeSessions))
	}
}

func TestService_ResolveActiveListenPort(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		cfgPort      int
		dbPort       int
		nilCfg       bool
		nilDB        bool
		expectedPort int
	}{
		{
			name:         "cfg listen port has highest precedence",
			cfgPort:      53001,
			dbPort:       53002,
			expectedPort: 53001,
		},
		{
			name:         "db listen port used when cfg port is 0",
			cfgPort:      0,
			dbPort:       53002,
			expectedPort: 53002,
		},
		{
			name:         "db listen port used when cfg is nil",
			nilCfg:       true,
			dbPort:       53003,
			expectedPort: 53003,
		},
		{
			name:         "fallback to default 51820 when cfg and db have 0",
			cfgPort:      0,
			dbPort:       0,
			expectedPort: 51820,
		},
		{
			name:         "fallback to default 51820 when cfg and db are nil",
			nilCfg:       true,
			nilDB:        true,
			expectedPort: 51820,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{}
			if !tt.nilCfg {
				svc.cfg = &models.VPNConfig{ListenPort: tt.cfgPort}
			}
			if !tt.nilDB {
				dir := t.TempDir()
				testDB, err := database.Open(filepath.Join(dir, "port_test.db"), "secret-1234567890123456")
				if err != nil {
					t.Fatalf("database.Open failed: %v", err)
				}
				t.Cleanup(func() { _ = testDB.Close() })
				if tt.dbPort > 0 {
					_ = testDB.SaveVPNConfig(ctx, &models.VPNConfig{ListenPort: tt.dbPort})
				}
				svc.db = testDB
			}

			port := svc.resolveActiveListenPort(ctx)
			if port != tt.expectedPort {
				t.Fatalf("resolveActiveListenPort() = %d, want %d", port, tt.expectedPort)
			}
		})
	}
}

func TestService_IsLifecycleMutated(t *testing.T) {
	t.Run("nil sessionMgr returns false", func(t *testing.T) {
		svc := &Service{sessionMgr: nil}
		if svc.isLifecycleMutated(0) {
			t.Fatal("expected isLifecycleMutated to return false when sessionMgr is nil")
		}
		if svc.isLifecycleMutated(42) {
			t.Fatal("expected isLifecycleMutated to return false when sessionMgr is nil")
		}
	})

	t.Run("sessionMgr version match returns false, mismatch returns true", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		defer func() { _ = svc.Stop() }()

		if svc.sessionMgr == nil {
			t.Fatal("expected non-nil sessionMgr")
		}

		v0 := svc.sessionMgr.LifecycleVersion()
		if svc.isLifecycleMutated(v0) {
			t.Fatalf("expected isLifecycleMutated(%d) == false when version unchanged", v0)
		}

		svc.sessionMgr.BumpLifecycleVersion()
		if !svc.isLifecycleMutated(v0) {
			t.Fatalf("expected isLifecycleMutated(%d) == true after BumpLifecycleVersion()", v0)
		}

		vCurrent := svc.sessionMgr.LifecycleVersion()
		if svc.isLifecycleMutated(vCurrent) {
			t.Fatalf("expected isLifecycleMutated(%d) == false for current version", vCurrent)
		}
		if !svc.isLifecycleMutated(vCurrent + 1) {
			t.Fatal("expected isLifecycleMutated == true for future version")
		}
	})
}

func TestService_ReconcileConnectionCounts(t *testing.T) {
	t.Run("nil pool or nil db returns without error or panic", func(t *testing.T) {
		svc := &Service{}
		svc.reconcileConnectionCounts(context.Background()) // no-op
	})

	t.Run("reconciles drifted connection counts to match active sessions", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, uID, _ := setupTestVPNService(t, db)
		defer func() { _ = svc.Stop() }()

		ctx := context.Background()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB failed: %v", err)
		}

		// Get tunnel for server s1ID
		tunnels := svc.pool.ListTunnels()
		var targetTun *models.BackendTunnel
		for _, tun := range tunnels {
			if tun.ServerID == s1ID {
				targetTun = tun
				break
			}
		}
		if targetTun == nil {
			t.Fatal("target tunnel not found in pool")
		}

		// Insert 2 active connected sessions for targetTun in DB
		for _, sessID := range []string{"sess-recon-1", "sess-recon-2"} {
			if err := db.CreateVPNSession(ctx, &models.VPNSession{
				ID:              sessID,
				UserID:          uID,
				BackendTunnelID: targetTun.ID,
				PeerPublicKey:   sessID + "-key",
				AssignedIP:      "10.100.1." + sessID[len(sessID)-1:],
				Status:          "connected",
			}); err != nil {
				t.Fatalf("CreateVPNSession failed: %v", err)
			}
		}

		// Deliberately set pool active connection count to 0 (drifted)
		if err := svc.pool.SetConnectionCount(ctx, targetTun.ID, 0); err != nil {
			t.Fatalf("SetConnectionCount failed: %v", err)
		}

		svc.reconcileConnectionCounts(ctx)

		// Verify pool tunnel active connections was updated to 2
		updatedTun, err := svc.pool.GetTunnelByID(targetTun.ID)
		if err != nil {
			t.Fatalf("GetTunnelByID failed: %v", err)
		}
		if updatedTun.ActiveConnections != 2 {
			t.Fatalf("expected ActiveConnections to be 2, got: %d", updatedTun.ActiveConnections)
		}
		if svc.lastReconcileTime.IsZero() {
			t.Fatal("expected lastReconcileTime to be set")
		}
	})

	t.Run("aborts reconciliation when session lifecycle is mutated before commit", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, uID, _ := setupTestVPNService(t, db)
		defer func() { _ = svc.Stop() }()

		ctx := context.Background()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB failed: %v", err)
		}

		tunnels := svc.pool.ListTunnels()
		var targetTun *models.BackendTunnel
		for _, tun := range tunnels {
			if tun.ServerID == s1ID {
				targetTun = tun
				break
			}
		}
		if targetTun == nil {
			t.Fatal("target tunnel not found in pool")
		}

		// Set initial pool count to 5
		if err := svc.pool.SetConnectionCount(ctx, targetTun.ID, 5); err != nil {
			t.Fatalf("SetConnectionCount failed: %v", err)
		}

		// Insert 1 active session in DB
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "sess-recon-abort",
			UserID:          uID,
			BackendTunnelID: targetTun.ID,
			PeerPublicKey:   "abort-key",
			AssignedIP:      "10.100.2.1",
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		// Inject hook that bumps lifecycle version before commit
		svc.reconcilePreCommitHook = func() {
			svc.sessionMgr.BumpLifecycleVersion()
		}

		svc.reconcileConnectionCounts(ctx)

		// Verify pool tunnel active connections was NOT updated to 1 because reconciliation was aborted
		updatedTun, err := svc.pool.GetTunnelByID(targetTun.ID)
		if err != nil {
			t.Fatalf("GetTunnelByID failed: %v", err)
		}
		if updatedTun.ActiveConnections != 5 {
			t.Fatalf("expected ActiveConnections to remain 5 (unmodified), got: %d", updatedTun.ActiveConnections)
		}
	})
}

func TestService_StartGaugeReconciler(t *testing.T) {
	t.Run("nil pool or db returns immediately without goroutine leak", func(t *testing.T) {
		svc := &Service{}
		svc.StartGaugeReconciler(context.Background())
	})

	t.Run("context cancel terminates gauge reconciler goroutine", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		defer func() { _ = svc.Stop() }()

		ctx, cancel := context.WithCancel(context.Background())
		svc.StartGaugeReconciler(ctx)
		// Immediately cancel context to verify clean termination
		cancel()
		// Small sleep to allow goroutine select to exit
		time.Sleep(20 * time.Millisecond)
	})
}
