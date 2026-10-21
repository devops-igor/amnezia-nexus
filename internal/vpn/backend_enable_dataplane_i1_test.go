package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/cps"
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

func assertDeviceIPCI1Payload(t *testing.T, ipc string, proto string) {
	t.Helper()
	var foundI1 string
	for _, line := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(line, "i1=") {
			foundI1 = strings.TrimPrefix(line, "i1=")
			break
		}
	}
	if foundI1 == "" {
		t.Fatalf("no i1= entry found in device IPC:\n%s", ipc)
	}

	raw, err := cps.ParseCPSBlob(foundI1)
	if err != nil {
		t.Fatalf("failed to parse CPS blob from i1=%q: %v", foundI1, err)
	}

	switch proto {
	case "dns":
		if !strings.HasPrefix(foundI1, "<r 2><b 0x") {
			t.Fatalf("expected DNS I1 format (<r 2><b 0x...>), got %q", foundI1)
		}
		if len(raw) < 12 || raw[2] != 1 || raw[3] != 0 || raw[4] != 0 || raw[5] != 1 {
			t.Fatalf("live I1 payload is not a valid framed DNS query (len=%d)", len(raw))
		}
	default: // "sip"
		if !strings.HasPrefix(foundI1, "<b 0x") {
			t.Fatalf("expected SIP I1 format (<b 0x...>), got %q", foundI1)
		}
		rawStr := string(raw)
		if !strings.Contains(rawStr, "REGISTER sip:") || !strings.Contains(rawStr, "SIP/2.0") {
			t.Fatalf("live I1 payload does not contain ASCII 'REGISTER sip:' and 'SIP/2.0', got %q", rawStr)
		}
	}
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
		assertDeviceIPCI1Payload(t, ipc, "sip")

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
		assertDeviceIPCI1Payload(t, ipc, "dns")
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
	assertDeviceIPCI1Payload(t, ipc, "sip")
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
	assertDeviceIPCI1Payload(t, ipc, "sip")
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
	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)

	sentinelErr := errors.New("simulated generator failure for orphan check")
	restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
		return nil, sentinelErr
	})
	defer restore()

	preAddHookCalled := false
	svc.enableBackendPreAddTunnelHook = func() {
		preAddHookCalled = true
	}

	err = svc.EnableBackend(ctx, srvID)
	if err == nil {
		t.Fatal("expected EnableBackend to fail when generator fails")
	}
	if !errors.Is(err, sentinelErr) {
		t.Fatalf("expected error to wrap sentinel %v, got %v", sentinelErr, err)
	}
	if preAddHookCalled {
		t.Fatal("pre-add hook was called: generator error did not abort before pool.AddTunnel")
	}
	if adder.addClientCalls > 0 {
		t.Fatalf("peer registration occurred (%d calls) despite preflight generator failure", adder.addClientCalls)
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
		assertDeviceIPCI1Payload(t, ipc, "sip")
	}
}

func TestEnableBackend_GeneratesMimicryOnce(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID := testNewServerWithAWGParams(t, svc, "198.51.100.15", nil)
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	genCalls := 0
	restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
		genCalls++
		return cps.GenerateMimicryPackets(ctx, mimicry, domain, sshClient)
	})
	defer restore()

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	if genCalls != 1 {
		t.Fatalf("expected exactly 1 generator call (preflight reused on attach), got %d", genCalls)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	_, ipc := testDeviceIPC(t, svc, tun.ID)
	assertDeviceIPCI1Payload(t, ipc, "sip")
}

func TestRestoreBackendDevices_EnabledTunnel_DataPlaneI1(t *testing.T) {
	for _, proto := range []string{"sip", "dns"} {
		t.Run(proto, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)
			var cfg *models.VPNConfig
			if proto != "sip" {
				cfg = &models.VPNConfig{VPNDataPlaneI1Protocol: proto}
			}
			svc, err := NewVPNService(db, cfg)
			if err != nil {
				t.Fatalf("NewVPNService: %v", err)
			}
			t.Cleanup(func() { closeBackendDevices(svc) })
			svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

			const storedDummy = "<b 0xdeadbeef>"
			srvID := testNewServerWithAWGParams(t, svc, "198.51.100.30", map[string]any{
				"I1": storedDummy,
				"s1": 15,
				"s2": 40,
			})

			tun, err := svc.pool.AddTunnel(ctx, srvID, "198.51.100.30:51820", "")
			if err != nil {
				t.Fatalf("AddTunnel: %v", err)
			}

			svc.restoreBackendDevices(ctx)

			i1, ipc := testDeviceIPC(t, svc, tun.ID)
			if strings.Contains(ipc, storedDummy) || i1 == storedDummy {
				t.Fatalf("restored live device retained stored dummy I1 instead of generating configured %s I1", proto)
			}

			assertDeviceIPCI1Payload(t, ipc, proto)
		})
	}
}

func TestAuditSecondGenerationMustNotOrphan(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })
	id := testNewServerWithAWGParams(t, svc, "198.51.100.88", nil)
	adder := &mockAWGManagerWithClientAdder{}
	svc.SetAWGStatusProvider(adder)
	sentinel := errors.New("audit second generation failure")
	calls := 0
	restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, profile, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
		calls++
		if calls == 2 {
			return nil, sentinel
		}
		return cps.GenerateMimicryPackets(ctx, profile, domain, sshClient)
	})
	defer restore()
	err = svc.EnableBackend(ctx, id)
	tun, getErr := svc.pool.GetTunnel(id)
	hasDevice := false
	if tun != nil {
		svc.mu.RLock()
		hasDevice = svc.backendDevices[tun.ID] != nil
		svc.mu.RUnlock()
	}
	t.Logf("generation_calls=%d peer_registration_calls=%d error_matches=%v pool_found=%v device_attached=%v selectable_active=%d",
		calls, adder.addClientCalls, errors.Is(err, sentinel), getErr == nil, hasDevice, len(svc.pool.GetActiveTunnels()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 generation call, got %d", calls)
	}
	if tun == nil || !tun.Enabled || !hasDevice {
		t.Fatalf("expected enabled tunnel with attached device, tun=%v hasDevice=%v", tun, hasDevice)
	}
}

func TestBuildBackendDeviceParams_RejectMissingOrEmptyI1(t *testing.T) {
	ctx := context.Background()
	svc := &Service{}

	tests := []struct {
		name        string
		generatorFn func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error)
		wantErrSub  string
	}{
		{
			name: "nil map returned by generator",
			generatorFn: func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
				return nil, nil
			},
			wantErrSub: "generator returned empty data plane I1 packet for protocol \"sip\"",
		},
		{
			name: "empty map returned by generator",
			generatorFn: func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
				return map[string]string{}, nil
			},
			wantErrSub: "generator returned empty data plane I1 packet for protocol \"sip\"",
		},
		{
			name: "empty string i1 returned by generator",
			generatorFn: func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
				return map[string]string{"i1": ""}, nil
			},
			wantErrSub: "generator returned empty data plane I1 packet for protocol \"sip\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := setGenerateMimicryPacketsForTest(tt.generatorFn)
			defer restore()

			params, err := svc.buildBackendDeviceParams(ctx, "sip", map[string]any{"h1": "123"})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (params: %v)", tt.wantErrSub, params)
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErrSub, err)
			}
		})
	}
}
