package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

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
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	testCases := []struct {
		name    string
		packets map[string]string
	}{
		{
			name:    "nil map",
			packets: nil,
		},
		{
			name:    "empty map",
			packets: map[string]string{},
		},
		{
			name:    "empty string i1",
			packets: map[string]string{"i1": ""},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
				return tc.packets, nil
			})
			defer restore()

			awgParams := map[string]any{"s1": 15, "s2": 40}
			params, err := svc.buildBackendDeviceParams(ctx, "sip", awgParams)
			if err == nil {
				t.Fatalf("expected error on %s, got nil and params: %v", tc.name, params)
			}
			if params != nil {
				t.Fatalf("expected nil params on error, got: %v", params)
			}
			if !strings.Contains(err.Error(), "generator returned empty data plane I1 packet for protocol \"sip\"") {
				t.Fatalf("expected specific fail-closed error message, got: %v", err)
			}

			// Also verify via prepareBackendDeviceParams
			prepParams, prepErr := svc.prepareBackendDeviceParams(ctx, awgParams)
			if prepErr == nil || prepParams != nil {
				t.Fatalf("prepareBackendDeviceParams expected error and nil, got params=%v err=%v", prepParams, prepErr)
			}
		})
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_UpdatesRunningBackendDevices(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID := testNewServerWithAWGParams(t, svc, "198.51.100.99", map[string]any{"s1": 15, "s2": 40})
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend: %v", err)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}

	// 1. Initially attached device has default SIP I1
	svc.mu.RLock()
	devInitial := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()

	i1Initial, ipcInitial := testDeviceIPC(t, svc, tun.ID)
	assertDeviceIPCI1Payload(t, ipcInitial, "sip")
	if !strings.HasPrefix(i1Initial, "<b 0x") {
		t.Fatalf("expected initial SIP prefix, got %q", i1Initial)
	}

	// 2. Switch protocol to DNS via UpdateConfig
	cfgWithDNS := &models.VPNConfig{
		VPNDataPlaneI1Protocol: "dns",
	}
	if err := svc.UpdateConfig(ctx, cfgWithDNS); err != nil {
		t.Fatalf("UpdateConfig(dns) failed: %v", err)
	}

	// Verify device instance was re-attached with new instance
	svc.mu.RLock()
	devDNS := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if devInitial == devDNS {
		t.Fatalf("expected backend device to be re-attached with new instance, got same pointer")
	}

	// Read dev.DeviceIPC() and assert that live device IPC now contains the DNS I1 packet!
	i1DNS, ipcDNS := testDeviceIPC(t, svc, tun.ID)
	assertDeviceIPCI1Payload(t, ipcDNS, "dns")
	if !strings.HasPrefix(i1DNS, "<r 2><b 0x") {
		t.Fatalf("expected updated DNS I1 on device, got %q", i1DNS)
	}
	if !strings.Contains(ipcDNS, "i1="+i1DNS+"\n") {
		t.Fatalf("expected live device IPC to contain updated DNS i1 line, got:\n%s", ipcDNS)
	}

	// 3. Switch back to SIP
	cfgWithSIP := &models.VPNConfig{
		VPNDataPlaneI1Protocol: "sip",
	}
	if err := svc.UpdateConfig(ctx, cfgWithSIP); err != nil {
		t.Fatalf("UpdateConfig(sip) failed: %v", err)
	}

	svc.mu.RLock()
	devSIP := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if devDNS == devSIP {
		t.Fatalf("expected backend device to be re-attached with new instance, got same pointer")
	}

	i1SIP, ipcSIP := testDeviceIPC(t, svc, tun.ID)
	assertDeviceIPCI1Payload(t, ipcSIP, "sip")
	if !strings.HasPrefix(i1SIP, "<b 0x") {
		t.Fatalf("expected switched back SIP I1 on device, got %q", i1SIP)
	}
	if !strings.Contains(ipcSIP, "i1="+i1SIP+"\n") {
		t.Fatalf("expected live device IPC to contain switched back SIP i1 line, got:\n%s", ipcSIP)
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_GeneratorFailureMarksTunnelDegraded(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srvID := testNewServerWithAWGParams(t, svc, "198.51.100.100", map[string]any{"s1": 15, "s2": 40})
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend: %v", err)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}
	if tun.Status != models.TunnelStatusActive && tun.Status != TunnelStatusActive {
		t.Fatalf("expected active tunnel before switch, got %q", tun.Status)
	}

	restoreGen := setGenerateMimicryPacketsForTest(func(ctx context.Context, mimicry, domain string, sshClient ssh.SSHClient) (map[string]string, error) {
		return nil, errors.New("simulated generator failure")
	})
	defer restoreGen()

	cfgWithDNS := &models.VPNConfig{
		VPNDataPlaneI1Protocol: "dns",
	}
	if err := svc.UpdateConfig(ctx, cfgWithDNS); err != nil {
		t.Fatalf("UpdateConfig unexpected error: %v", err)
	}

	tunAfter, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel after switch: %v", err)
	}
	if tunAfter.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected tunnel status to become %q on generator failure, got %q", models.TunnelStatusDegraded, tunAfter.Status)
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_MultipleRunningBackendDevices(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })

	srv1 := testNewServerWithAWGParams(t, svc, "198.51.100.101", map[string]any{"s1": 15, "s2": 40})
	srv2 := testNewServerWithAWGParams(t, svc, "198.51.100.102", map[string]any{"s1": 15, "s2": 40})
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	if err := svc.EnableBackend(ctx, srv1); err != nil {
		t.Fatalf("EnableBackend(1): %v", err)
	}
	if err := svc.EnableBackend(ctx, srv2); err != nil {
		t.Fatalf("EnableBackend(2): %v", err)
	}

	tun1, _ := svc.pool.GetTunnel(srv1)
	tun2, _ := svc.pool.GetTunnel(srv2)

	cfgWithDNS := &models.VPNConfig{
		VPNDataPlaneI1Protocol: "dns",
	}
	if err := svc.UpdateConfig(ctx, cfgWithDNS); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	i1DNS1, ipc1 := testDeviceIPC(t, svc, tun1.ID)
	i1DNS2, ipc2 := testDeviceIPC(t, svc, tun2.ID)
	assertDeviceIPCI1Payload(t, ipc1, "dns")
	assertDeviceIPCI1Payload(t, ipc2, "dns")
	if !strings.HasPrefix(i1DNS1, "<r 2><b 0x") || !strings.HasPrefix(i1DNS2, "<r 2><b 0x") {
		t.Fatalf("expected DNS I1 prefix on both devices, got dev1=%q dev2=%q", i1DNS1, i1DNS2)
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_NoDataRaceWithLiveTimers(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	defer pc.Close()

	pub, _, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateCurve25519KeyPair failed: %v", err)
	}

	awg := map[string]any{
		"installed":  true,
		"port":       pc.LocalAddr().(*net.UDPAddr).Port,
		"public_key": pub,
		"awg_params": map[string]any{
			"rekey_timeout": "1",
		},
	}
	srvID, err := svc.db.CreateServer(ctx, &models.Server{
		Name:      "server-live-wire",
		Host:      "127.0.0.1",
		Protocols: map[string]any{"awg": awg},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	if err := svc.EnableBackend(ctx, srvID); err != nil {
		t.Fatalf("EnableBackend: %v", err)
	}

	tun, err := svc.pool.GetTunnel(srvID)
	if err != nil {
		t.Fatalf("GetTunnel: %v", err)
	}

	readPreambles := func(proto string) {
		t.Helper()
		_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		seen := 0
		buf := make([]byte, 4096)
		for seen < 2 {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatalf("%s received %d preambles: %v", proto, seen, err)
			}
			sip := strings.HasPrefix(string(buf[:n]), "REGISTER ") && strings.Contains(string(buf[:n]), "SIP/2.0")
			dns := n >= 12 && buf[2] == 1 && buf[3] == 0 && buf[4] == 0 && buf[5] == 1
			if (proto == "sip" && sip) || (proto == "dns" && dns) {
				seen++
			}
		}
		// Allow in-flight timer callback from the observed retransmission to complete.
		time.Sleep(50 * time.Millisecond)
	}

	// Verify initial SIP preambles on wire (handshake + timer retransmission)
	readPreambles("sip")

	// Switch protocol repeatedly between DNS and SIP while timers are active
	for _, proto := range []string{"dns", "sip", "dns"} {
		svc.mu.RLock()
		oldDev := svc.backendDevices[tun.ID]
		svc.mu.RUnlock()

		if err := svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: proto}); err != nil {
			t.Fatalf("UpdateConfig(%s) failed: %v", proto, err)
		}

		svc.mu.RLock()
		newDev := svc.backendDevices[tun.ID]
		svc.mu.RUnlock()

		if oldDev == newDev {
			t.Fatal("device not replaced after protocol switch")
		}
		if _, err := oldDev.Write(make([]byte, 20)); err == nil {
			t.Fatal("old device not closed after protocol switch")
		}

		_, ipc := testDeviceIPC(t, svc, tun.ID)
		assertDeviceIPCI1Payload(t, ipc, proto)
		readPreambles(proto)
	}

	// Allow in-flight timer callbacks to complete before closing devices.
	time.Sleep(100 * time.Millisecond)
	closeBackendDevices(svc)
}

func TestEnableBackend_InterleavedProtocolSwitch(t *testing.T) {
	for _, stage := range []string{"before-add", "after-add"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)
			svc, err := NewVPNService(db, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeBackendDevices(svc) })
			id := testNewServerWithAWGParams(t, svc, "198.51.100.80", nil)
			svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
			hook := func() {
				if err := svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: "dns"}); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "before-add" {
				svc.enableBackendPreAddTunnelHook = hook
			} else {
				svc.enableBackendPostAddTunnelHook = hook
			}
			if err := svc.EnableBackend(ctx, id); err != nil {
				t.Fatal(err)
			}
			tun, err := svc.pool.GetTunnel(id)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := db.GetVPNConfig(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, ipc := testDeviceIPC(t, svc, tun.ID)
			t.Logf("saved=%s runtime=%s status=%s enable_error=nil", stored.DataPlaneI1Protocol(), svc.cfg.DataPlaneI1Protocol(), tun.Status)
			assertDeviceIPCI1Payload(t, ipc, "dns")
		})
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_GeneratorFailureDetachesObsoleteDevice(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })
	id := testNewServerWithAWGParams(t, svc, "198.51.100.81", nil)
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	svc.mu.RLock()
	oldDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()

	restore := setGenerateMimicryPacketsForTest(func(context.Context, string, string, ssh.SSHClient) (map[string]string, error) {
		return nil, errors.New("transient generator failure")
	})
	err = svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: "dns"})
	restore()
	if err != nil {
		t.Fatal(err)
	}

	degraded, err := svc.pool.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if degraded.Status != models.TunnelStatusDegraded {
		t.Fatalf("status=%s, want degraded", degraded.Status)
	}

	// Verify old device is detached and closed
	svc.mu.RLock()
	retainedDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if retainedDev != nil {
		t.Fatalf("expected obsolete device to be removed from backendDevices, got %v", retainedDev)
	}
	if _, err := oldDev.Write(make([]byte, 20)); err == nil {
		t.Fatal("expected old device to be closed after detach")
	}

	// Same configured protocol retry and the real health activation hook must not silently retain stale I1.
	if err := svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: "dns"}); err != nil {
		t.Fatal(err)
	}
	svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return time.Millisecond, nil
	})
	if _, err := svc.prober.ProbeTunnel(ctx, degraded); err != nil {
		t.Fatal(err)
	}
	after, err := svc.pool.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != models.TunnelStatusActive {
		t.Fatalf("status=%s, want active", after.Status)
	}
	_, ipc := testDeviceIPC(t, svc, tun.ID)
	t.Logf("retained_old_device=%v config=%s after_health_activation=%s", oldDev == svc.backendDevices[tun.ID], svc.cfg.DataPlaneI1Protocol(), after.Status)
	assertDeviceIPCI1Payload(t, ipc, "dns")
}

func TestUpdateConfig_DataPlaneI1ProtocolSameProtocol_NoReattach(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })
	id := testNewServerWithAWGParams(t, svc, "198.51.100.82", nil)
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	svc.mu.RLock()
	old := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	calls := 0
	restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, p, d string, c ssh.SSHClient) (map[string]string, error) {
		calls++
		return cps.GenerateMimicryPackets(ctx, p, d, c)
	})
	defer restore()
	if err := svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: "sip"}); err != nil {
		t.Fatal(err)
	}
	svc.mu.RLock()
	currentDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if calls != 0 || old != currentDev {
		t.Fatalf("same effective protocol unexpectedly regenerated %d times (device replaced: %v)", calls, old != currentDev)
	}
}

func TestEnableBackend_InterleavedProtocolSwitch_GeneratorFailureMarksTunnelDegraded(t *testing.T) {
	for _, stage := range []string{"before-add", "after-add"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)
			svc, err := NewVPNService(db, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeBackendDevices(svc) })
			id := testNewServerWithAWGParams(t, svc, "198.51.100.83", nil)
			svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
			sentinel := errors.New("audit DNS regeneration failure")
			restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, p, d string, c ssh.SSHClient) (map[string]string, error) {
				if p == "dns" {
					return nil, sentinel
				}
				return cps.GenerateMimicryPackets(ctx, p, d, c)
			})
			defer restore()
			hook := func() {
				if err := svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: "dns"}); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "before-add" {
				svc.enableBackendPreAddTunnelHook = hook
			} else {
				svc.enableBackendPostAddTunnelHook = hook
			}
			err = svc.EnableBackend(ctx, id)
			if !errors.Is(err, sentinel) {
				t.Fatalf("expected injected error, got %v", err)
			}
			tun, err := svc.pool.GetTunnel(id)
			if err != nil {
				t.Fatal(err)
			}
			svc.mu.RLock()
			hasDev := svc.backendDevices[tun.ID] != nil
			svc.mu.RUnlock()
			if tun.Enabled && tun.Status == models.TunnelStatusActive && !hasDev {
				t.Fatal("failed enable left an active selectable tunnel without a device")
			}
			if tun.Status != models.TunnelStatusDegraded {
				t.Fatalf("tunnel status = %s, want %s", tun.Status, models.TunnelStatusDegraded)
			}
		})
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_PreservesLegacyParams(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
	id, err := db.CreateServer(ctx, &models.Server{Name: "legacy-params", Host: "198.51.100.84", Protocols: map[string]any{"awg": map[string]any{
		"installed": true, "port": 51820, "public_key": "legacy-backend-public-fixture",
		"params": map[string]any{"s1": 15, "s2": 40, "h1": "101", "h2": "102", "h3": "103", "h4": "104"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	_, before := testDeviceIPC(t, svc, tun.ID)
	for _, line := range []string{"s1=15\n", "s2=40\n", "h1=101\n", "h2=102\n"} {
		if !strings.Contains(before, line) {
			t.Fatalf("fixture missing %q before switch", line)
		}
	}
	if err := svc.UpdateConfig(ctx, &models.VPNConfig{VPNDataPlaneI1Protocol: "dns"}); err != nil {
		t.Fatal(err)
	}
	_, after := testDeviceIPC(t, svc, tun.ID)
	assertDeviceIPCI1Payload(t, after, "dns")
	for _, line := range []string{"s1=15\n", "s2=40\n", "h1=101\n", "h2=102\n"} {
		if !strings.Contains(after, line) {
			t.Errorf("after protocol switch missing parameter %q", line)
		}
	}
}

func TestUpdateConfig_DataPlaneI1ProtocolSwitch_CancellationMidReattach(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeBackendDevices(svc) })
	svc.SetAWGStatusProvider(&mockAWGManagerWithClientAdder{})
	ids := []int64{testNewServerWithAWGParams(t, svc, "198.51.100.85", nil), testNewServerWithAWGParams(t, svc, "198.51.100.86", nil)}
	for _, id := range ids {
		if err := svc.EnableBackend(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	updateCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	restore := setGenerateMimicryPacketsForTest(func(ctx context.Context, p, d string, c ssh.SSHClient) (map[string]string, error) {
		packets, err := cps.GenerateMimicryPackets(ctx, p, d, c)
		cancel()
		return packets, err
	})
	defer restore()
	if err := svc.UpdateConfig(updateCtx, &models.VPNConfig{VPNDataPlaneI1Protocol: "dns"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		tun, err := svc.pool.GetTunnel(id)
		if err != nil {
			t.Fatal(err)
		}
		svc.mu.RLock()
		hasDev := svc.backendDevices[tun.ID] != nil
		svc.mu.RUnlock()
		if tun.Enabled && tun.Status == models.TunnelStatusActive && !hasDev {
			t.Errorf("server %d: request cancellation left detached tunnel selectable as active", id)
		}
	}
}
