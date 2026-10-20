package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func testNewServerWithAWGParams(t *testing.T, svc *Service, host string, awgParams map[string]any) int64 {
	t.Helper()
	ctx := context.Background()
	awg := map[string]any{
		"installed":  true,
		"port":       51820,
		"public_key": "backend-pubkey-" + host,
	}
	if awgParams != nil {
		awg["awg_params"] = awgParams
	}
	id, err := svc.db.CreateServer(ctx, &models.Server{
		Name:      "server-" + host,
		Host:      host,
		Protocols: map[string]any{"awg": awg},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	return id
}

func testDeviceIPC(t *testing.T, svc *Service, tunID int64) (string, string) {
	t.Helper()
	svc.mu.RLock()
	dev, ok := svc.backendDevices[tunID].(*tunnel.AWGClientDevice)
	svc.mu.RUnlock()
	if !ok || dev == nil {
		t.Fatalf("no AWGClientDevice attached for tunnel %d", tunID)
	}
	ipc, err := dev.DeviceIPC()
	if err != nil {
		t.Fatalf("DeviceIPC failed: %v", err)
	}
	return dev.I1(), ipc
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

		srvID := testNewServerWithAWGParams(t, svc, "198.51.100.95", map[string]any{"s1": 15, "s2": 40})
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel: %v", err)
		}

		i1, ipc := testDeviceIPC(t, svc, tun.ID)
		if !strings.HasPrefix(i1, "<b 0x") {
			t.Fatalf("expected device I1 to be hex CPS blob (<b 0x...>), got %q", i1)
		}
		if !strings.Contains(ipc, "\ni1=<b 0x") {
			t.Fatalf("expected live device IPC to contain rendered i1, got:\n%s", ipc)
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

		srvID := testNewServerWithAWGParams(t, svc, "198.51.100.96", map[string]any{"s1": 15, "s2": 40})
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		if err := svc.EnableBackend(ctx, srvID); err != nil {
			t.Fatalf("EnableBackend: %v", err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			t.Fatalf("GetTunnel: %v", err)
		}

		i1, ipc := testDeviceIPC(t, svc, tun.ID)
		if !strings.HasPrefix(i1, "<r 2><b 0x") {
			t.Fatalf("expected device I1 to be DNS format (<r 2><b 0x...>), got %q", i1)
		}
		if !strings.Contains(ipc, "\ni1=<r 2><b 0x") {
			t.Fatalf("expected live device IPC to contain DNS i1, got:\n%s", ipc)
		}
	})

	t.Run("propagates mimicry packet generator error", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}
		t.Cleanup(func() { closeBackendDevices(svc) })

		srvID := testNewServerWithAWGParams(t, svc, "198.51.100.97", nil)
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

func TestEnsureBackendDeviceAttached_DataPlaneI1(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID := testNewServerWithAWGParams(t, svc, "198.51.100.11", map[string]any{"s1": 15, "s2": 40})
	tun, err := svc.pool.AddTunnel(ctx, srvID, "198.51.100.11:51820", "")
	if err != nil {
		t.Fatalf("AddTunnel: %v", err)
	}

	if err := svc.ensureBackendDeviceAttached(ctx, tun); err != nil {
		t.Fatalf("ensureBackendDeviceAttached: %v", err)
	}

	i1, ipc := testDeviceIPC(t, svc, tun.ID)
	if !strings.HasPrefix(i1, "<b 0x") {
		t.Errorf("device attached via prober onActive hook must have SIP I1, got %q", i1)
	}
	if !strings.Contains(ipc, "\ni1=<b 0x") {
		t.Errorf("device IPC must contain SIP i1 line, got:\n%s", ipc)
	}
}

func TestSyncBackendForwarderOnHostUpdate_DataPlaneI1(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID := testNewServerWithAWGParams(t, svc, "198.51.100.12", map[string]any{"s1": 15, "s2": 40})
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend: %v", err)
	}

	if err := svc.UpdateBackendServerHost(ctx, srvID, "198.51.100.13"); err != nil {
		t.Fatalf("UpdateBackendServerHost: %v", err)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}

	i1, ipc := testDeviceIPC(t, svc, tun.ID)
	if !strings.HasPrefix(i1, "<b 0x") {
		t.Errorf("device re-attached via host update must preserve SIP I1, got %q", i1)
	}
	if !strings.Contains(ipc, "\ni1=<b 0x") {
		t.Errorf("device IPC must contain SIP i1 line after host update, got:\n%s", ipc)
	}
}

func TestCodeRabbit1_GeneratorFailureDoesNotOrphanTunnel(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID := testNewServerWithAWGParams(t, svc, "198.51.100.14", nil)
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
		return nil, errors.New("simulated generator failure for orphan check")
	})
	defer restore()

	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when generator fails")
	}

	tun, gerr := svc.pool.GetTunnel(srvID)
	svc.mu.RLock()
	var hasDev bool
	if tun != nil {
		_, hasDev = svc.backendDevices[tun.ID]
	}
	svc.mu.RUnlock()

	if gerr == nil && tun != nil {
		t.Errorf("expected no tunnel in pool after generator failure, but found tunnel id=%d enabled=%v status=%q device_attached=%v",
			tun.ID, tun.Enabled, tun.Status, hasDev)
	}
}

func TestEnableBackend_StoredUppercaseI1_OverriddenDeterministically(t *testing.T) {
	ctx := context.Background()
	const stored = "<b 0xdeadbeef>"

	for i := 0; i < 10; i++ {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService: %v", err)
		}

		srvID := testNewServerWithAWGParams(t, svc, "198.51.100.20", map[string]any{
			"I1": stored,
			"s1": 15,
		})
		svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

		if err := svc.EnableBackend(ctx, srvID); err != nil {
			closeBackendDevices(svc)
			t.Fatalf("run %d: EnableBackend failed: %v", i, err)
		}

		tun, err := svc.pool.GetTunnel(srvID)
		if err != nil {
			closeBackendDevices(svc)
			t.Fatalf("run %d: GetTunnel failed: %v", i, err)
		}

		i1, ipc := testDeviceIPC(t, svc, tun.ID)
		closeBackendDevices(svc)

		if i1 == stored {
			t.Fatalf("run %d: stored I1 was not overridden by data plane I1", i)
		}
		if !strings.HasPrefix(i1, "<b 0x") {
			t.Fatalf("run %d: expected generated SIP I1 (<b 0x...), got %q", i, i1)
		}
		if strings.Contains(ipc, stored) {
			t.Fatalf("run %d: device IPC contains stored I1 value %s instead of generated I1:\n%s", i, stored, ipc)
		}
	}
}
