package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

type testPeerAdderMock struct {
	calls []map[string]any
	err   error
}

func (m *testPeerAdderMock) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{"container_running": true}, nil
}

func (m *testPeerAdderMock) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	m.calls = append(m.calls, clientParams)
	if m.err != nil {
		return nil, m.err
	}
	return map[string]any{"status": "ok"}, nil
}

type testStatusOnlyProvider struct{}

func (p *testStatusOnlyProvider) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{"container_running": true}, nil
}

func TestEnableBackend_PreflightValidation(t *testing.T) {
	t.Run("deleted server rejected initially", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)

		svc.mu.Lock()
		if svc.deletedServers == nil {
			svc.deletedServers = make(map[int64]struct{})
		}
		svc.deletedServers[s1ID] = struct{}{}
		svc.mu.Unlock()

		ctx := context.Background()
		err := svc.EnableBackend(ctx, s1ID)
		if err == nil {
			t.Fatal("expected error on deleted server, got nil")
		}
		if !errors.Is(err, ErrServerNotFound) {
			t.Fatalf("expected ErrServerNotFound, got: %v", err)
		}
		if !strings.Contains(err.Error(), "is deleted") {
			t.Fatalf("expected 'is deleted' in error message, got: %v", err)
		}
	})

	t.Run("deleted server rejected under lock before AddTunnel", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)

		svc.mu.Lock()
		svc.enableBackendPreAddTunnelHook = func() {
			svc.mu.Lock()
			if svc.deletedServers == nil {
				svc.deletedServers = make(map[int64]struct{})
			}
			svc.deletedServers[s1ID] = struct{}{}
			svc.mu.Unlock()
		}
		svc.mu.Unlock()

		ctx := context.Background()
		err := svc.EnableBackend(ctx, s1ID)
		if err == nil {
			t.Fatal("expected error on server deleted under lock, got nil")
		}
		if !errors.Is(err, ErrServerNotFound) {
			t.Fatalf("expected ErrServerNotFound, got: %v", err)
		}
	})

	t.Run("missing pool returns uninitialized error", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)

		svc.mu.Lock()
		svc.pool = nil
		svc.mu.Unlock()

		ctx := context.Background()
		err := svc.EnableBackend(ctx, s1ID)
		if err == nil || !strings.Contains(err.Error(), "tunnel pool not initialized") {
			t.Fatalf("expected 'tunnel pool not initialized', got: %v", err)
		}
	})

	t.Run("missing database returns database not available", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)

		svc.mu.Lock()
		svc.db = nil
		svc.mu.Unlock()

		ctx := context.Background()
		err := svc.EnableBackend(ctx, s1ID)
		if err == nil || !strings.Contains(err.Error(), "database not available") {
			t.Fatalf("expected 'database not available', got: %v", err)
		}
	})

	t.Run("server not found in database", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		nonExistentID := int64(999999)
		err := svc.EnableBackend(ctx, nonExistentID)
		if err == nil {
			t.Fatal("expected error for non-existent server, got nil")
		}
		if !errors.Is(err, ErrServerNotFound) {
			t.Fatalf("expected ErrServerNotFound, got: %v", err)
		}
	})

	t.Run("server generation changed during enable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)

		svc.mu.Lock()
		svc.enableBackendPreAddTunnelHook = func() {
			_ = db.UpdateServer(context.Background(), s1ID, map[string]any{"host": "198.51.100.99"})
		}
		svc.mu.Unlock()

		ctx := context.Background()
		err := svc.EnableBackend(ctx, s1ID)
		if err == nil {
			t.Fatal("expected error when server generation changed, got nil")
		}
		if !errors.Is(err, ErrServerNotFound) || !strings.Contains(err.Error(), "generation changed") {
			t.Fatalf("expected generation changed error, got: %v", err)
		}
	})

	t.Run("credential resolution failure when AWG protocol missing", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		srvID, err := db.CreateServer(ctx, &models.Server{
			Name:      "no-awg-server",
			Host:      "198.51.100.25",
			Protocols: map[string]any{},
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		err = svc.EnableBackend(ctx, srvID)
		if err == nil {
			t.Fatal("expected error when AWG not installed, got nil")
		}
		if !errors.Is(err, ErrAWGNotInstalled) {
			t.Fatalf("expected ErrAWGNotInstalled, got: %v", err)
		}
	})

	t.Run("credential resolution failure when status provider discovery fails", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "failing-awg-server",
			Host: "198.51.100.26",
			Protocols: map[string]any{
				"awg": map[string]any{"port": 0},
			},
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		mockProv := &mockAWGStatusProvider{
			status: map[string]any{"container_running": false},
		}
		svc.SetAWGStatusProvider(mockProv)

		err = svc.EnableBackend(ctx, srvID)
		if err == nil {
			t.Fatal("expected error when AWG container not running, got nil")
		}
		if !errors.Is(err, ErrAWGNotInstalled) {
			t.Fatalf("expected ErrAWGNotInstalled, got: %v", err)
		}
	})
}

func TestFinishEnableBackend_Guards(t *testing.T) {
	identityTests := []struct {
		name   string
		mutate func(t *models.BackendTunnel)
	}{
		{"ID mismatch aborts enable", func(t *models.BackendTunnel) { t.ID += 100 }},
		{"PublicKey mismatch aborts enable", func(t *models.BackendTunnel) { t.PublicKey = "rotated-" + t.PublicKey }},
		{"PrivateKey mismatch aborts enable", func(t *models.BackendTunnel) { t.PrivateKey = "rotated-" + t.PrivateKey }},
		{"ProbePrivateKey mismatch aborts enable", func(t *models.BackendTunnel) { t.ProbePrivateKey = "rotated-" + t.ProbePrivateKey }},
		{"Endpoint mismatch aborts enable", func(t *models.BackendTunnel) { t.Endpoint = "203.0.113.99:51820" }},
	}
	for _, tc := range identityTests {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			svc, s1ID, _, _, _ := setupTestVPNService(t, db)
			if err := svc.pool.SyncFromDB(context.Background()); err != nil {
				t.Fatalf("failed to sync pool from DB: %v", err)
			}

			tun, err := svc.pool.GetTunnel(s1ID)
			if err != nil {
				t.Fatalf("failed to get tunnel: %v", err)
			}

			ctx := context.Background()
			stale := *tun
			tc.mutate(&stale)
			startEpoch := svc.adminDisableEpoch[s1ID]
			err = svc.finishEnableBackend(ctx, svc.pool, &stale, nil, s1ID, startEpoch)
			if err == nil || !strings.Contains(err.Error(), "backend identity modified concurrently; aborting enable") {
				t.Fatalf("expected concurrent modification error, got: %v", err)
			}
		})
	}

	t.Run("runtime status bump does not abort enable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("failed to sync pool from DB: %v", err)
		}

		tun, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("failed to get tunnel: %v", err)
		}

		ctx := context.Background()
		if err := svc.pool.SetTunnelStatus(ctx, s1ID, models.TunnelStatusActive, 12); err != nil {
			t.Fatalf("SetTunnelStatus failed: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })
		if err := svc.finishEnableBackend(ctx, svc.pool, tun, nil, s1ID, svc.adminDisableEpoch[s1ID]); err != nil {
			t.Fatalf("expected enable to tolerate a prober status write, got: %v", err)
		}
	})

	t.Run("self-healing context aborts if backend administratively disabled", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("failed to sync pool from DB: %v", err)
		}

		if err := svc.pool.SetTunnelEnabled(context.Background(), s1ID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("failed to disable tunnel: %v", err)
		}
		tun, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("failed to get tunnel: %v", err)
		}

		ctx := tunnel.ContextWithSelfHealing(context.Background())
		err = svc.finishEnableBackend(ctx, svc.pool, tun, nil, s1ID, svc.adminDisableEpoch[s1ID])
		if err == nil || !strings.Contains(err.Error(), "backend was administratively disabled; aborting enable") {
			t.Fatalf("expected administratively disabled abort, got: %v", err)
		}
	})

	t.Run("self-healing context succeeds without persisting enable if already enabled", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		t.Cleanup(func() { closeBackendDevices(svc) })
		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("failed to sync pool from DB: %v", err)
		}

		tun, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("failed to get tunnel: %v", err)
		}

		ctx := tunnel.ContextWithSelfHealing(context.Background())
		err = svc.finishEnableBackend(ctx, svc.pool, tun, nil, s1ID, svc.adminDisableEpoch[s1ID])
		if err != nil {
			t.Fatalf("expected nil from self-healing finish on enabled tunnel, got: %v", err)
		}
	})

	t.Run("administrative disable mid-enable aborts enable", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("failed to sync pool from DB: %v", err)
		}

		tun, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("failed to get tunnel: %v", err)
		}

		ctx := context.Background()
		startEpoch := svc.adminDisableEpoch[s1ID]
		if err := svc.DisableBackend(ctx, s1ID); err != nil {
			t.Fatalf("failed to disable tunnel: %v", err)
		}

		err = svc.finishEnableBackend(ctx, svc.pool, tun, nil, s1ID, startEpoch)
		if err == nil || !strings.Contains(err.Error(), "backend was administratively disabled; aborting enable") {
			t.Fatalf("expected administratively disabled error, got: %v", err)
		}
	})

	t.Run("manual enable succeeds when starting from disabled state", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, _, _ := setupTestVPNService(t, db)
		t.Cleanup(func() { closeBackendDevices(svc) })
		if err := svc.pool.SyncFromDB(context.Background()); err != nil {
			t.Fatalf("failed to sync pool from DB: %v", err)
		}

		if err := svc.DisableBackend(context.Background(), s1ID); err != nil {
			t.Fatalf("failed to disable tunnel: %v", err)
		}
		tun, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("failed to get tunnel: %v", err)
		}

		ctx := context.Background()
		startEpoch := svc.adminDisableEpoch[s1ID]
		err = svc.finishEnableBackend(ctx, svc.pool, tun, nil, s1ID, startEpoch)
		if err != nil {
			t.Fatalf("expected success on manual enable from disabled state, got: %v", err)
		}

		updated, err := svc.pool.GetTunnel(s1ID)
		if err != nil || !updated.Enabled {
			t.Fatalf("expected tunnel to be enabled, err=%v, enabled=%v", err, updated.Enabled)
		}
	})
}

func TestEnableBackend_ConcurrentDisable_HealthProvenance(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "test-health-prov", Host: "198.51.100.91",
		Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": 51820, "public_key": "health-prov-pub"}},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend: %v", err)
	}

	// Prober health-disables it (runtime: status=disabled, reason=health)
	if err := svc.pool.SetTunnelStatus(ctx, srvID, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatalf("SetTunnelStatus: %v", err)
	}
	// Admin then disables it; SetTunnelEnabled preserves health provenance
	if err := svc.DisableBackend(ctx, srvID); err != nil {
		t.Fatalf("DisableBackend: %v", err)
	}

	tunBefore, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if tunBefore.Enabled || tunBefore.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected Enabled=false with health provenance, got Enabled=%v Reason=%s", tunBefore.Enabled, tunBefore.DisableReason)
	}

	var disableErr error
	svc.SetEnableBackendPostAddTunnelHookForTest(func() {
		disableErr = svc.DisableBackend(ctx, srvID)
	})
	defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

	err = svc.EnableBackend(ctx, srvID)
	if disableErr != nil {
		t.Fatalf("concurrent DisableBackend failed: %v", disableErr)
	}
	if err == nil || !strings.Contains(err.Error(), "backend was administratively disabled; aborting enable") {
		t.Fatalf("expected administratively disabled error, got: %v", err)
	}

	finalTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if finalTun.Enabled {
		t.Errorf("expected Enabled=false in pool, got true")
	}

	svc.mu.RLock()
	_, devBySrvID := svc.backendDevices[srvID]
	_, devByTunID := svc.backendDevices[finalTun.ID]
	svc.mu.RUnlock()
	if devBySrvID || devByTunID {
		t.Errorf("expected svc.backendDevices to not exist, got devBySrvID=%v devByTunID=%v", devBySrvID, devByTunID)
	}
}

func TestEnableBackend_ConcurrentDisable_AdminProvenance(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "test-admin-prov", Host: "198.51.100.92",
		Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": 51820, "public_key": "admin-prov-pub"}},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend: %v", err)
	}
	if err := svc.DisableBackend(ctx, srvID); err != nil {
		t.Fatalf("DisableBackend: %v", err)
	}

	tunBefore, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if tunBefore.Enabled || tunBefore.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected Enabled=false with admin provenance, got Enabled=%v Reason=%s", tunBefore.Enabled, tunBefore.DisableReason)
	}

	var disableErr error
	svc.SetEnableBackendPostAddTunnelHookForTest(func() {
		disableErr = svc.DisableBackend(ctx, srvID)
	})
	defer svc.SetEnableBackendPostAddTunnelHookForTest(nil)

	err = svc.EnableBackend(ctx, srvID)
	if disableErr != nil {
		t.Fatalf("concurrent DisableBackend failed: %v", disableErr)
	}
	if err == nil || !strings.Contains(err.Error(), "backend was administratively disabled; aborting enable") {
		t.Fatalf("expected administratively disabled error, got: %v", err)
	}

	finalTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if finalTun.Enabled {
		t.Errorf("expected Enabled=false in pool, got true")
	}

	svc.mu.RLock()
	_, devBySrvID := svc.backendDevices[srvID]
	_, devByTunID := svc.backendDevices[finalTun.ID]
	svc.mu.RUnlock()
	if devBySrvID || devByTunID {
		t.Errorf("expected svc.backendDevices to not exist, got devBySrvID=%v devByTunID=%v", devBySrvID, devByTunID)
	}
}

func setupPreAddSvc(t *testing.T, db *database.DB, name, host, pub string) (*Service, int64) {
	t.Helper()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	srvID, err := db.CreateServer(context.Background(), &models.Server{
		Name: name, Host: host,
		Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": 51820, "public_key": pub}},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
	return svc, srvID
}

func TestEnableBackend_PreAddConcurrentDisable_InitiallyEnabled(t *testing.T) {
	ctx := context.Background()
	svc, srvID := setupPreAddSvc(t, setupTestDB(t), "test-preadd-enabled", "198.51.100.93", "preadd-enabled-pub")
	t.Cleanup(func() { closeBackendDevices(svc) })

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("initial EnableBackend: %v", err)
	}

	var disableErr error
	svc.SetEnableBackendPreAddTunnelHookForTest(func() {
		disableErr = svc.DisableBackend(ctx, srvID)
	})
	defer svc.SetEnableBackendPreAddTunnelHookForTest(nil)

	err := svc.EnableBackend(ctx, srvID)
	if disableErr != nil {
		t.Fatalf("concurrent DisableBackend failed: %v", disableErr)
	}
	if err == nil || !strings.Contains(err.Error(), "backend was administratively disabled; aborting enable") {
		t.Fatalf("expected administratively disabled error, got: %v", err)
	}

	finalTun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if finalTun.Enabled {
		t.Errorf("expected Enabled=false in pool, got true")
	}

	svc.mu.RLock()
	_, devBySrvID := svc.backendDevices[srvID]
	_, devByTunID := svc.backendDevices[finalTun.ID]
	svc.mu.RUnlock()
	if devBySrvID || devByTunID {
		t.Errorf("expected svc.backendDevices to not exist, got devBySrvID=%v devByTunID=%v", devBySrvID, devByTunID)
	}
}

func TestEnableBackend_PreAddConcurrentDisable_DisabledProvenance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		host       string
		healthDrop bool
		wantReason string
	}{
		{"health provenance", "198.51.100.94", true, models.DisableReasonHealth},
		{"admin provenance", "198.51.100.95", false, models.DisableReasonAdmin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, srvID := setupPreAddSvc(t, setupTestDB(t), "test-preadd-"+tc.name, tc.host, "pub-"+tc.name)
			t.Cleanup(func() { closeBackendDevices(svc) })

			if err := svc.EnableBackend(ctx, srvID); err != nil {
				t.Fatalf("initial EnableBackend: %v", err)
			}
			if tc.healthDrop {
				if err := svc.pool.SetTunnelStatus(ctx, srvID, models.TunnelStatusDisabled, 0); err != nil {
					t.Fatalf("SetTunnelStatus: %v", err)
				}
			}
			if err := svc.DisableBackend(ctx, srvID); err != nil {
				t.Fatalf("DisableBackend: %v", err)
			}

			tunBefore, err := svc.pool.GetTunnel(srvID)
			if err != nil {
				t.Fatalf("GetTunnel: %v", err)
			}
			if tunBefore.Enabled || tunBefore.DisableReason != tc.wantReason {
				t.Fatalf("expected Enabled=false with %s provenance, got Enabled=%v Reason=%s", tc.wantReason, tunBefore.Enabled, tc.wantReason)
			}

			var disableErr error
			svc.SetEnableBackendPreAddTunnelHookForTest(func() {
				disableErr = svc.DisableBackend(ctx, srvID)
			})
			defer svc.SetEnableBackendPreAddTunnelHookForTest(nil)

			err = svc.EnableBackend(ctx, srvID)
			if disableErr != nil {
				t.Fatalf("concurrent DisableBackend failed: %v", disableErr)
			}
			if err == nil || !strings.Contains(err.Error(), "backend was administratively disabled; aborting enable") {
				t.Fatalf("expected administratively disabled error, got: %v", err)
			}

			finalTun, err := svc.pool.GetTunnel(srvID)
			if err != nil {
				t.Fatalf("GetTunnel: %v", err)
			}
			if finalTun.Enabled {
				t.Errorf("expected Enabled=false in pool, got true")
			}
		})
	}
}

func TestRegisterBackendPortalPeers_KeysAndCollisions(t *testing.T) {
	_, priv1, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	_, priv2, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Run("derives distinct data and probe keys and scopes allowed_ips", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		mockAdder := &testPeerAdderMock{}
		svc.SetAWGStatusProvider(mockAdder)

		server := &models.Server{ID: 10, Host: "10.0.0.10"}
		tun := &models.BackendTunnel{
			ID:              1,
			ServerID:        10,
			PrivateKey:      priv1,
			ProbePrivateKey: priv2,
		}

		ctx := context.Background()
		if err := svc.registerBackendPortalPeers(ctx, server, tun); err != nil {
			t.Fatalf("unexpected error registering portal peers: %v", err)
		}

		if len(mockAdder.calls) != 2 {
			t.Fatalf("expected 2 AddClient calls, got %d", len(mockAdder.calls))
		}

		dataPeer := mockAdder.calls[0]
		if dataPeer["name"] != "Portal Data Plane" {
			t.Errorf("expected Portal Data Plane, got %v", dataPeer["name"])
		}
		if dataPeer["allowed_ips"] != svc.getPortalSubnet() {
			t.Errorf("expected allowed_ips %s, got %v", svc.getPortalSubnet(), dataPeer["allowed_ips"])
		}

		probePeer := mockAdder.calls[1]
		if probePeer["name"] != "Portal Health Probe" {
			t.Errorf("expected Portal Health Probe, got %v", probePeer["name"])
		}
		if _, ok := probePeer["allowed_ips"]; ok {
			t.Errorf("probe peer must not have allowed_ips set, got %v", probePeer["allowed_ips"])
		}

		if dataPeer["public_key"] == probePeer["public_key"] {
			t.Error("data peer and probe peer public keys must be distinct")
		}
	})

	t.Run("detects missing probe private key", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		svc.SetAWGStatusProvider(&testPeerAdderMock{})

		server := &models.Server{ID: 10, Host: "10.0.0.10"}
		tun := &models.BackendTunnel{
			ID:              1,
			ServerID:        10,
			PrivateKey:      priv1,
			ProbePrivateKey: "",
		}

		ctx := context.Background()
		err := svc.registerBackendPortalPeers(ctx, server, tun)
		if err == nil || !strings.Contains(err.Error(), "is missing or collides with the data key") {
			t.Fatalf("expected missing/collides error, got: %v", err)
		}
	})

	t.Run("detects colliding probe private key", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		svc.SetAWGStatusProvider(&testPeerAdderMock{})

		server := &models.Server{ID: 10, Host: "10.0.0.10"}
		tun := &models.BackendTunnel{
			ID:              1,
			ServerID:        10,
			PrivateKey:      priv1,
			ProbePrivateKey: priv1, // identical to data key
		}

		ctx := context.Background()
		err := svc.registerBackendPortalPeers(ctx, server, tun)
		if err == nil || !strings.Contains(err.Error(), "is missing or collides with the data key") {
			t.Fatalf("expected collision error, got: %v", err)
		}
	})

	t.Run("detects corrupted private keys", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		svc.SetAWGStatusProvider(&testPeerAdderMock{})

		server := &models.Server{ID: 10, Host: "10.0.0.10"}
		tunBadData := &models.BackendTunnel{
			ID:              1,
			ServerID:        10,
			PrivateKey:      "not-valid-base64-key!",
			ProbePrivateKey: priv2,
		}

		ctx := context.Background()
		err := svc.registerBackendPortalPeers(ctx, server, tunBadData)
		if err == nil || !strings.Contains(err.Error(), "failed to derive data device public key") {
			t.Fatalf("expected data key derivation error, got: %v", err)
		}

		tunBadProbe := &models.BackendTunnel{
			ID:              1,
			ServerID:        10,
			PrivateKey:      priv1,
			ProbePrivateKey: "not-valid-base64-key!",
		}
		err = svc.registerBackendPortalPeers(ctx, server, tunBadProbe)
		if err == nil || !strings.Contains(err.Error(), "failed to derive probe public key") {
			t.Fatalf("expected probe key derivation error, got: %v", err)
		}
	})

	t.Run("provider without AddClient capability is silent no-op", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)
		svc.SetAWGStatusProvider(&testStatusOnlyProvider{})

		server := &models.Server{ID: 10, Host: "10.0.0.10"}
		tun := &models.BackendTunnel{
			ID:              1,
			ServerID:        10,
			PrivateKey:      priv1,
			ProbePrivateKey: priv2,
		}

		ctx := context.Background()
		if err := svc.registerBackendPortalPeers(ctx, server, tun); err != nil {
			t.Fatalf("expected nil when provider lacks AddClient, got: %v", err)
		}
	})
}

func TestEnsureBackendProbeKeys_MigrationAndIdempotency(t *testing.T) {
	t.Run("generates curve25519 keypair for missing keys and registers peers", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "probe-test-server-1",
			Host: "198.51.100.51",
			Protocols: map[string]any{
				"awg": map[string]any{"port": 51820, "public_key": "pub"},
			},
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		mockAdder := &testPeerAdderMock{}
		svc.SetAWGStatusProvider(mockAdder)

		_, validDataPrivKey, err := tunnel.GenerateCurve25519KeyPair()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		keyGenCount := 0
		svc.pool.SetGenerateKeyPairForTest(func() (string, string, error) {
			keyGenCount++
			if keyGenCount == 1 {
				return "dataPub", validDataPrivKey, nil
			}
			return "probePub", "", nil
		})

		tun, err := svc.pool.AddTunnel(ctx, srvID, "198.51.100.51:51820", "us-east-pubkey")
		svc.pool.SetGenerateKeyPairForTest(nil)
		if err != nil {
			t.Fatalf("AddTunnel failed: %v", err)
		}
		if tun.ProbePrivateKey != "" {
			t.Fatalf("expected initial ProbePrivateKey to be empty, got: %s", tun.ProbePrivateKey)
		}

		svc.EnsureBackendProbeKeys(ctx)

		// Verify persisted to DB
		dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("failed to load tunnel from DB: %v", err)
		}
		if dbTun.ProbePrivateKey == "" {
			t.Fatal("expected EnsureBackendProbeKeys to generate and persist probe private key")
		}

		// Verify peer registration occurred
		if len(mockAdder.calls) < 2 {
			t.Fatalf("expected at least 2 AddClient calls, got %d", len(mockAdder.calls))
		}
		if mockAdder.calls[0]["name"] != "Portal Data Plane" {
			t.Errorf("expected Portal Data Plane, got: %v", mockAdder.calls[0]["name"])
		}
		if mockAdder.calls[1]["name"] != "Portal Health Probe" {
			t.Errorf("expected Portal Health Probe, got: %v", mockAdder.calls[1]["name"])
		}
	})

	t.Run("is idempotent across consecutive calls", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "probe-test-server-2",
			Host: "198.51.100.52",
			Protocols: map[string]any{
				"awg": map[string]any{"port": 51820, "public_key": "pub"},
			},
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		mockAdder := &testPeerAdderMock{}
		svc.SetAWGStatusProvider(mockAdder)

		_, validDataPrivKey, err := tunnel.GenerateCurve25519KeyPair()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		keyGenCount := 0
		svc.pool.SetGenerateKeyPairForTest(func() (string, string, error) {
			keyGenCount++
			if keyGenCount == 1 {
				return "dataPub", validDataPrivKey, nil
			}
			return "probePub", "", nil
		})

		tun, err := svc.pool.AddTunnel(ctx, srvID, "198.51.100.52:51820", "us-east-pubkey")
		svc.pool.SetGenerateKeyPairForTest(nil)
		if err != nil {
			t.Fatalf("AddTunnel failed: %v", err)
		}

		svc.EnsureBackendProbeKeys(ctx)

		dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil || dbTun.ProbePrivateKey == "" {
			t.Fatalf("expected key in DB, got: %v, err=%v", dbTun, err)
		}
		firstKey := dbTun.ProbePrivateKey

		// Sync pool so memory pool has the generated key
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB failed: %v", err)
		}

		callsAfterFirst := len(mockAdder.calls)

		// Second run must preserve the existing key
		svc.EnsureBackendProbeKeys(ctx)
		dbTunSecond, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("GetBackendTunnel failed: %v", err)
		}
		if dbTunSecond.ProbePrivateKey != firstKey {
			t.Fatalf("key changed on second run: got %s, want %s", dbTunSecond.ProbePrivateKey, firstKey)
		}

		// AddClient was called again for refresh (idempotent upsert)
		if len(mockAdder.calls) <= callsAfterFirst {
			t.Fatal("expected second run to refresh registration via AddClient")
		}
	})

	t.Run("skips disabled tunnels", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		ctx := context.Background()
		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "probe-test-server-3",
			Host: "198.51.100.53",
			Protocols: map[string]any{
				"awg": map[string]any{"port": 51820, "public_key": "pub"},
			},
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		mockAdder := &testPeerAdderMock{}
		svc.SetAWGStatusProvider(mockAdder)

		_, validDataPrivKey, err := tunnel.GenerateCurve25519KeyPair()
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		keyGenCount := 0
		svc.pool.SetGenerateKeyPairForTest(func() (string, string, error) {
			keyGenCount++
			if keyGenCount == 1 {
				return "dataPub", validDataPrivKey, nil
			}
			return "probePub", "", nil
		})

		tun, err := svc.pool.AddTunnel(ctx, srvID, "198.51.100.53:51820", "us-east-pubkey")
		svc.pool.SetGenerateKeyPairForTest(nil)
		if err != nil {
			t.Fatalf("AddTunnel failed: %v", err)
		}

		if err := svc.pool.SetTunnelEnabled(ctx, srvID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("failed to disable tunnel: %v", err)
		}

		svc.EnsureBackendProbeKeys(ctx)

		dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("GetBackendTunnel failed: %v", err)
		}
		if dbTun.ProbePrivateKey != "" {
			t.Fatalf("expected disabled tunnel to be skipped, got key: %s", dbTun.ProbePrivateKey)
		}
		if len(mockAdder.calls) != 0 {
			t.Fatalf("expected no AddClient calls for disabled tunnel, got %d", len(mockAdder.calls))
		}
	})

	t.Run("handles nil pool without panic", func(t *testing.T) {
		svc := &Service{}
		ctx := context.Background()
		// Should return immediately without panicking
		svc.EnsureBackendProbeKeys(ctx)
	})
}

func TestGetPortalSubnet_Fallback(t *testing.T) {
	t.Run("returns configured SubnetCIDR when present", func(t *testing.T) {
		svc := &Service{
			cfg: &models.VPNConfig{
				SubnetCIDR: "172.16.0.0/12",
			},
		}
		if got := svc.getPortalSubnet(); got != "172.16.0.0/12" {
			t.Fatalf("expected 172.16.0.0/12, got: %s", got)
		}
	})

	t.Run("returns default 10.100.0.0/16 when cfg is nil", func(t *testing.T) {
		svc := &Service{}
		if got := svc.getPortalSubnet(); got != "10.100.0.0/16" {
			t.Fatalf("expected default 10.100.0.0/16, got: %s", got)
		}
	})

	t.Run("returns default 10.100.0.0/16 when SubnetCIDR is empty string", func(t *testing.T) {
		svc := &Service{
			cfg: &models.VPNConfig{
				SubnetCIDR: "",
			},
		}
		if got := svc.getPortalSubnet(); got != "10.100.0.0/16" {
			t.Fatalf("expected default 10.100.0.0/16, got: %s", got)
		}
	})
}

func TestEnableBackend_DataPlaneI1_DeviceInitialization(t *testing.T) {
	ctx := context.Background()

	t.Run("injects SIP I1 into backend device by default", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "test-sip-i1", Host: "198.51.100.95",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "sip-backend-pubkey",
					"awg_params": map[string]any{"s1": 15, "s2": 40},
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer: %v", err)
		}
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel: %v", err)
		}

		svc.mu.RLock()
		dev, ok := svc.backendDevices[tun.ID].(*tunnel.AWGClientDevice)
		svc.mu.RUnlock()
		if !ok || dev == nil {
			t.Fatalf("expected attached *tunnel.AWGClientDevice for tunnel %d", tun.ID)
		}

		i1 := dev.I1()
		if !strings.HasPrefix(i1, "<b 0x") {
			t.Fatalf("expected device I1 to be hex CPS blob (<b 0x...>), got %q", i1)
		}

		// Verify stored database parameters were NOT mutated
		loadedSrv, err := db.GetServerByID(ctx, srvID)
		if err != nil {
			t.Fatalf("GetServerByID: %v", err)
		}
		awgInfo := loadedSrv.Protocols["awg"].(map[string]any)
		storedParams := awgInfo["awg_params"].(map[string]any)
		if _, exists := storedParams["i1"]; exists {
			t.Errorf("stored awg_params in DB must not be mutated with i1, found: %v", storedParams["i1"])
		}
	})

	t.Run("injects DNS I1 into backend device when configured", func(t *testing.T) {
		db := setupTestDB(t)
		cfg := &models.VPNConfig{
			VPNDataPlaneI1Protocol: "dns",
		}
		svc, err := NewVPNService(db, cfg)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "test-dns-i1", Host: "198.51.100.96",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "dns-backend-pubkey",
					"awg_params": map[string]any{"s1": 15, "s2": 40},
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer: %v", err)
		}
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel: %v", err)
		}

		svc.mu.RLock()
		dev, ok := svc.backendDevices[tun.ID].(*tunnel.AWGClientDevice)
		svc.mu.RUnlock()
		if !ok || dev == nil {
			t.Fatalf("expected attached *tunnel.AWGClientDevice for tunnel %d", tun.ID)
		}

		i1 := dev.I1()
		if !strings.HasPrefix(i1, "<r 2><b 0x") {
			t.Fatalf("expected device I1 to be DNS format (<r 2><b 0x...>), got %q", i1)
		}
	})

	t.Run("propagates mimicry packet generator error", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID, err := db.CreateServer(ctx, &models.Server{
			Name: "test-err-i1", Host: "198.51.100.97",
			Protocols: map[string]any{
				"awg": map[string]any{
					"installed":  true,
					"port":       51820,
					"public_key": "err-backend-pubkey",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer: %v", err)
		}
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		restoreGen := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry string, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
			return nil, errors.New("simulated mimicry generator failure")
		})
		defer restoreGen()

		err = svc.EnableBackend(ctx, srvID)
		if err == nil || !strings.Contains(err.Error(), "simulated mimicry generator failure") {
			t.Fatalf("expected simulated mimicry generator failure, got: %v", err)
		}
	})
}
