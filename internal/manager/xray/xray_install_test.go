package xray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/google/uuid"
)

func TestXrayManagerReinstallPreservesEmptyFirstShortIDs(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 42, Host: "192.0.2.42"}
	ctx := context.Background()

	privateKey, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	want := []string{"", "aabb"}
	config, err := RenderXrayConfig(443, 54321, "www.microsoft.com", "", privateKey, want, []XrayClient{})
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = config

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("repair: %v", err)
	}
	repaired, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("parse repaired config: %v", err)
	}
	for i, inbound := range repaired.Inbounds {
		got := inbound.StreamSettings.RealitySettings.ShortIDs
		if !reflect.DeepEqual(got, want) {
			t.Errorf("inbound %d short IDs = %v, want %v", i, got, want)
		}
	}
}

func TestXrayManagerProfileSwitchPreservesCustomPort(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:   101,
		Host: "192.0.2.101",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}
	ctx := context.Background()

	privateKey, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	config, err := RenderXrayConfig(8443, 54321, "www.microsoft.com", "", privateKey, []string{"0123456789abcdef"}, []XrayClient{})
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = config

	// 1. Switch profile to modern_pq without specifying port in params.
	if err := mgr.Install(ctx, server, map[string]any{"engine_profile": "modern_pq"}); err != nil {
		t.Fatalf("Install profile switch: %v", err)
	}

	protoMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected VLESS protocol metadata")
	}
	if port, _ := protoMeta["port"].(int); port != 8443 {
		t.Errorf("server.Protocols[vless] port = %v, want 8443", port)
	}

	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || parsed.Inbounds[0].Port != 8443 {
		t.Errorf("config inbound port = %v, want 8443", parsed.Inbounds[0].Port)
	}

	// 2. Switch profile with an explicitly requested port (e.g. 9443).
	if err := mgr.Install(ctx, server, map[string]any{"engine_profile": "legacy", "port": 9443}); err != nil {
		t.Fatalf("Install with explicit port: %v", err)
	}
	protoMeta2 := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if port, _ := protoMeta2["port"].(int); port != 9443 {
		t.Errorf("server.Protocols[vless] port = %v, want 9443", port)
	}
	parsed2, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed2.Inbounds) == 0 || parsed2.Inbounds[0].Port != 9443 {
		t.Errorf("config inbound port = %v, want 9443", parsed2.Inbounds[0].Port)
	}
}

type unprofiledVersionMockSSHClient struct {
	*mockXraySSHClient
	xrayVersionOutput string
}

func (m *unprofiledVersionMockSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "xray version") {
		return m.xrayVersionOutput, "", 0, nil
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManagerUnprofiledExistingInstallation_ResolvesModernPQ(t *testing.T) {
	mockSSH := &unprofiledVersionMockSSHClient{
		mockXraySSHClient: newMockXraySSHClient(),
		xrayVersionOutput: "Xray 26.10.21 (Xray, Penetrates Everything.) 26.10.21 (go1.23.2 linux/amd64)\n",
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:        202,
		Host:      "192.0.2.202",
		Protocols: map[string]any{}, // unprofiled: no engine_profile metadata
	}
	ctx := context.Background()

	privateKey, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	config, err := RenderXrayConfig(443, 54321, "www.microsoft.com", "", privateKey, []string{"0123456789abcdef"}, []XrayClient{})
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = config

	// Install with no engine_profile provided in params.
	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install unprofiled server: %v", err)
	}

	protoMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected VLESS protocol metadata")
	}
	if prof, _ := protoMeta["engine_profile"].(string); prof != "modern_pq" {
		t.Errorf("engine_profile = %q, want modern_pq (should not downgrade 26.10.x to legacy)", prof)
	}
	if img, _ := protoMeta["engine_image"].(string); img != XrayModernPQImage {
		t.Errorf("engine_image = %q, want %q", img, XrayModernPQImage)
	}

	// Verify docker run command used the modern PQ image
	foundModernRun := false
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker run") && strings.Contains(cmd, XrayModernPQImage) {
			foundModernRun = true
			break
		}
	}
	if !foundModernRun {
		t.Errorf("expected docker run with XrayModernPQImage, commands: %v", mockSSH.commands)
	}
}

type rollbackFaultMockSSHClient struct {
	*mockXraySSHClient
	failDockerRun bool
}

func (m *rollbackFaultMockSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker run") && m.failDockerRun {
		return "", "docker: Error response from daemon: failed to create shim task", 125, fmt.Errorf("exit status 125")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManagerLaunchContainer_RollbackOnFailure(t *testing.T) {
	mockSSH := &rollbackFaultMockSSHClient{
		mockXraySSHClient: newMockXraySSHClient(),
		failDockerRun:     true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:        303,
		Host:      "192.0.2.203",
		Protocols: map[string]any{models.ProtocolVLESS: map[string]any{"installed": true}},
	}
	ctx := context.Background()

	privateKey, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	config, err := RenderXrayConfig(443, 54321, "www.microsoft.com", "", privateKey, []string{"0123456789abcdef"}, []XrayClient{})
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = config

	err = mgr.Install(ctx, server, map[string]any{"port": 443, "engine_profile": "modern_pq"})
	if err == nil {
		t.Fatalf("expected Install to fail due to injected docker run fault")
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Errorf("error = %q, want mention of 'rolled back to previous container'", err.Error())
	}

	// Verify rollback commands were executed:
	// 1. docker rename amnezia-xray-backup amnezia-xray
	// 2. docker start amnezia-xray
	foundRestoreRename := false
	foundRestoreStart := false
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker rename") && strings.Contains(cmd, "amnezia-xray-backup") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreRename = true
		}
		if strings.Contains(cmd, "docker start") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreStart = true
		}
	}
	if !foundRestoreRename {
		t.Errorf("expected docker rename amnezia-xray-backup amnezia-xray in commands, got: %v", mockSSH.commands)
	}
	if !foundRestoreStart {
		t.Errorf("expected docker start amnezia-xray in commands, got: %v", mockSSH.commands)
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], config) {
		t.Errorf("rollback failed to restore previous config bytes")
	}
}

func TestXrayManagerLaunchContainer_RollbackRestoresPreviousConfig(t *testing.T) {
	mockSSH := &rollbackFaultMockSSHClient{
		mockXraySSHClient: newMockXraySSHClient(),
		failDockerRun:     true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:   4401,
		Host: "192.0.2.41",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}
	ctx := context.Background()

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	initialConfig, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{
		{ID: "e8512bce-e575-4805-a678-1d64c033e83e", Flow: "xtls-rprx-vision", Email: "retained"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), initialConfig...)

	err = mgr.Install(ctx, server, map[string]any{
		"engine_profile": "modern_pq",
		"port":           9443,
	})
	if err == nil {
		t.Fatalf("expected Install to fail due to injected docker run fault")
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected rollback error, got: %v", err)
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], initialConfig) {
		t.Errorf("rollback left replacement configuration in place; want restored initial config")
	}
	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || parsed.Inbounds[0].Port != 8443 {
		t.Errorf("expected restored config to listen on port 8443, got %+v", parsed.Inbounds)
	}
}

type pullFaultMockSSHClient struct {
	*mockXraySSHClient
	failDockerPull bool
}

func (m *pullFaultMockSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker pull") && m.failDockerPull {
		return "", "Error response from daemon: repository ghcr.io/xtls/xray-core not found", 1, fmt.Errorf("exit status 1")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManagerInstall_ImagePullFailurePreservesConfig(t *testing.T) {
	mockSSH := &pullFaultMockSSHClient{
		mockXraySSHClient: newMockXraySSHClient(),
		failDockerPull:    true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:   501,
		Host: "192.0.2.51",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}
	ctx := context.Background()

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	initialConfig, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{
		{ID: "e8512bce-e575-4805-a678-1d64c033e83e", Flow: "xtls-rprx-vision", Email: "retained"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), initialConfig...)

	err = mgr.Install(ctx, server, map[string]any{
		"engine_profile": "modern_pq",
		"port":           9443,
	})
	if err == nil {
		t.Fatalf("expected Install to fail due to injected docker pull fault")
	}
	if !strings.Contains(err.Error(), "failed to pull xray image") {
		t.Errorf("error = %q, want mention of 'failed to pull xray image'", err.Error())
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], initialConfig) {
		t.Fatalf("live config.json was mutated despite pull failure; initial config must be preserved")
	}
	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || parsed.Inbounds[0].Port != 8443 {
		t.Errorf("expected preserved config port 8443, got %+v", parsed.Inbounds)
	}
	// Verify no container rename command was executed
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker rename") {
			t.Errorf("docker rename ran despite pull failure: %v", cmd)
		}
	}
}

type delayedCrashMockSSHClient struct {
	*mockXraySSHClient
	inspectCount int
}

func (m *delayedCrashMockSSHClient) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, XrayContainerName) && !strings.Contains(cmd, "amnezia-xray-backup") {
		m.inspectCount++
		// Initial check before launch: existing container was running (inspectCount 1)
		// Check 1 during readiness: new container is running (inspectCount 2)
		// Check 2 during readiness: new container crashes (inspectCount 3)
		if m.inspectCount >= 3 {
			return "false false\n", "", 0, nil
		}
		return "true false\n", "", 0, nil
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManagerLaunchContainer_DelayedStartupFailureRollback(t *testing.T) {
	mockSSH := &delayedCrashMockSSHClient{
		mockXraySSHClient: newMockXraySSHClient(),
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{
		ID:   601,
		Host: "192.0.2.61",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}
	ctx := context.Background()

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	initialConfig, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{
		{ID: "e8512bce-e575-4805-a678-1d64c033e83e", Flow: "xtls-rprx-vision", Email: "retained"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), initialConfig...)

	err = mgr.Install(ctx, server, map[string]any{
		"engine_profile": "modern_pq",
		"port":           9443,
	})
	if err == nil {
		t.Fatalf("expected Install to fail due to delayed container crash")
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected error mentioning 'rolled back to previous container', got: %v", err)
	}
	if !strings.Contains(err.Error(), "readiness check failed") {
		t.Errorf("expected error mentioning readiness check failure, got: %v", err)
	}

	// Verify rollback restored previous container and config
	foundRestoreRename := false
	foundRestoreStart := false
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker rename") && strings.Contains(cmd, "amnezia-xray-backup") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreRename = true
		}
		if strings.Contains(cmd, "docker start") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreStart = true
		}
	}
	if !foundRestoreRename {
		t.Errorf("expected docker rename amnezia-xray-backup amnezia-xray in rollback, commands: %v", mockSSH.commands)
	}
	if !foundRestoreStart {
		t.Errorf("expected docker start amnezia-xray in rollback, commands: %v", mockSSH.commands)
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], initialConfig) {
		t.Errorf("rollback failed to restore initial configuration bytes on delayed crash")
	}
	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || parsed.Inbounds[0].Port != 8443 {
		t.Errorf("expected restored port 8443, got %+v", parsed.Inbounds)
	}
}

func TestXrayManagerLaunchContainer_FailedHandshakeRollback(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	// Configure failing handshake probe
	handshakeAttempted := false
	mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		handshakeAttempted = true
		if params.ServerName != "example.com" {
			t.Errorf("probe params ServerName = %q, want example.com", params.ServerName)
		}
		return 0, fmt.Errorf("connection refused: REALITY handshake failed")
	})

	server := &models.Server{
		ID:   701,
		Host: "192.0.2.71",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}
	ctx := context.Background()

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	initialConfig, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{
		{ID: "e8512bce-e575-4805-a678-1d64c033e83e", Flow: "xtls-rprx-vision", Email: "retained"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), initialConfig...)

	err = mgr.Install(ctx, server, map[string]any{
		"engine_profile": "modern_pq",
		"port":           9443,
	})
	if err == nil {
		t.Fatalf("expected Install to fail due to failed handshake probe")
	}
	if !handshakeAttempted {
		t.Errorf("handshake probe was not called during readiness verification")
	}
	if !strings.Contains(err.Error(), "failed REALITY handshake readiness probe") {
		t.Errorf("expected error mentioning failed REALITY handshake readiness probe, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Errorf("expected error mentioning rolled back to previous container, got: %v", err)
	}

	// Verify rollback restored previous container and config
	foundRestoreRename := false
	foundRestoreStart := false
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker rename") && strings.Contains(cmd, "amnezia-xray-backup") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreRename = true
		}
		if strings.Contains(cmd, "docker start") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreStart = true
		}
	}
	if !foundRestoreRename {
		t.Errorf("expected docker rename amnezia-xray-backup amnezia-xray in rollback, commands: %v", mockSSH.commands)
	}
	if !foundRestoreStart {
		t.Errorf("expected docker start amnezia-xray in rollback, commands: %v", mockSSH.commands)
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], initialConfig) {
		t.Errorf("rollback failed to restore initial configuration bytes on failed handshake")
	}
	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || parsed.Inbounds[0].Port != 8443 {
		t.Errorf("expected restored port 8443, got %+v", parsed.Inbounds)
	}
}

func TestXrayManager_DefaultConstructor_AuthenticatesReadinessAndRollsBackOnFailure(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	// Default construction without test-only setters wires production REALITY probe (vless.ProbeVLESSReality).
	mgr := NewXrayManager(&mockXrayPool{client: mockSSH})

	// Allocate a local port and immediately close the listener to ensure a closed TCP port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	server := &models.Server{
		ID:   801,
		Host: "127.0.0.1",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           closedPort,
				"engine_profile": "legacy",
			},
		},
	}
	ctx := context.Background()

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	initialConfig, err := RenderXrayConfig(closedPort, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{
		{ID: "e8512bce-e575-4805-a678-1d64c033e83e", Flow: "xtls-rprx-vision", Email: "retained"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), initialConfig...)

	err = mgr.Install(ctx, server, map[string]any{
		"engine_profile": "modern_pq",
		"port":           closedPort,
	})
	if err == nil {
		t.Fatalf("expected Install with default constructor to fail due to failed handshake probe on closed port")
	}
	if !strings.Contains(err.Error(), "failed VLESS traffic readiness probe") {
		t.Errorf("expected error mentioning failed VLESS traffic readiness probe, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Errorf("expected error mentioning rolled back to previous container, got: %v", err)
	}

	// Verify rollback restored previous container and initial config
	foundRestoreRename := false
	foundRestoreStart := false
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker rename") && strings.Contains(cmd, "amnezia-xray-backup") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreRename = true
		}
		if strings.Contains(cmd, "docker start") && strings.Contains(cmd, "amnezia-xray") {
			foundRestoreStart = true
		}
	}
	if !foundRestoreRename {
		t.Errorf("expected docker rename amnezia-xray-backup amnezia-xray in rollback, commands: %v", mockSSH.commands)
	}
	if !foundRestoreStart {
		t.Errorf("expected docker start amnezia-xray in rollback, commands: %v", mockSSH.commands)
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], initialConfig) {
		t.Errorf("rollback failed to restore initial configuration bytes on failed handshake")
	}
}

func TestXrayManager_ProbeParams_ForwardsEngineProfile(t *testing.T) {
	tests := []struct {
		name          string
		installParams map[string]any
		wantProfile   string
	}{
		{
			name:          "modern_pq explicitly requested",
			installParams: map[string]any{"engine_profile": "modern_pq", "port": 8443},
			wantProfile:   "modern_pq",
		},
		{
			name:          "legacy explicitly requested",
			installParams: map[string]any{"engine_profile": "legacy", "port": 8443},
			wantProfile:   "legacy",
		},
		{
			name:          "unprofiled defaults to legacy baseline",
			installParams: map[string]any{"port": 8443},
			wantProfile:   "legacy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSSH := newMockXraySSHClient()
			mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

			var captured models.VLESSRealityParams
			probeCalled := false
			mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
				probeCalled = true
				captured = params
				return 10, nil
			})

			server := &models.Server{ID: 901, Host: "192.0.2.91"}
			ctx := context.Background()

			key, _, err := GenerateRealityKeypair()
			if err != nil {
				t.Fatal(err)
			}
			initialConfig, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{
				{ID: "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d", Flow: "xtls-rprx-vision", Email: "user1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			mockSSH.files[XrayConfigPath] = append([]byte(nil), initialConfig...)

			if err := mgr.Install(ctx, server, tt.installParams); err != nil {
				t.Fatalf("Install: %v", err)
			}

			if !probeCalled {
				t.Fatal("expected readiness probe to be called")
			}
			if captured.EngineProfile != tt.wantProfile {
				t.Errorf("probeParams.EngineProfile = %q, want %q", captured.EngineProfile, tt.wantProfile)
			}
			if captured.UUID != "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d" {
				t.Errorf("probeParams.UUID = %q, want user1 UUID", captured.UUID)
			}
			if captured.ServerName != "example.com" {
				t.Errorf("probeParams.ServerName = %q, want example.com", captured.ServerName)
			}
		})
	}
}

func TestXrayManager_FreshInstallWithoutClients_Succeeds(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	var captured models.VLESSRealityParams
	probeCalled := false
	mgr.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		probeCalled = true
		captured = params
		return 15, nil
	})

	server := &models.Server{ID: 902, Host: "192.0.2.92"}
	ctx := context.Background()

	// Fresh install: no pre-existing config file, no clients
	if err := mgr.Install(ctx, server, map[string]any{
		"engine_profile": "modern_pq",
		"port":           443,
	}); err != nil {
		t.Fatalf("fresh install without existing clients failed: %v", err)
	}

	if !probeCalled {
		t.Fatal("expected readiness probe to be called during fresh install")
	}
	if captured.UUID == "" {
		t.Fatal("expected valid probe UUID for fresh install without clients, got empty string")
	}
	if _, err := uuid.Parse(captured.UUID); err != nil {
		t.Errorf("expected valid RFC 4122 UUID in probeParams, got %q: %v", captured.UUID, err)
	}
	if captured.EngineProfile != "modern_pq" {
		t.Errorf("expected EngineProfile modern_pq, got %q", captured.EngineProfile)
	}
	if captured.ServerName == "" {
		t.Error("expected non-empty ServerName in probeParams")
	}
	if captured.PublicKey == "" {
		t.Error("expected non-empty PublicKey in probeParams")
	}

	// Verify generated config has valid structure and 0 clients
	cfgBytes, exists := mockSSH.files[XrayConfigPath]
	if !exists {
		t.Fatalf("expected config file %s to be written", XrayConfigPath)
	}
	parsed, err := ParseXrayConfig(cfgBytes)
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 {
		t.Fatal("expected at least one inbound")
	}
	if len(parsed.Inbounds[0].Settings.Clients) != 0 {
		t.Errorf("expected 0 clients in fresh install, got %d", len(parsed.Inbounds[0].Settings.Clients))
	}

	// Verify server.Protocols metadata updated
	protoMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatal("expected VLESS protocol metadata")
	}
	if installed, _ := protoMeta["installed"].(bool); !installed {
		t.Error("expected installed == true")
	}
	if ep, _ := protoMeta["engine_profile"].(string); ep != "modern_pq" {
		t.Errorf("server metadata engine_profile = %q, want modern_pq", ep)
	}
}

func setupInitialXrayConfig(t *testing.T, clientID string) []byte {
	t.Helper()
	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cls := []XrayClient{}
	if clientID != "" {
		cls = []XrayClient{{ID: clientID, Flow: "xtls-rprx-vision", Email: "retained"}}
	}
	cfg, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, cls)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func hasCmd(cmds []string, s1, s2 string) bool {
	for _, c := range cmds {
		if strings.Contains(c, s1) && strings.Contains(c, s2) {
			return true
		}
	}
	return false
}

type renameFailMockSSH struct {
	*mockXraySSHClient
}

func (m *renameFailMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker rename") && strings.Contains(cmd, "amnezia-xray-backup") {
		return "", "docker daemon: rename failed", 1, errors.New("command exited 1")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_StageExistingContainer_RenameFailureRestartsContainer(t *testing.T) {
	mockSSH := &renameFailMockSSH{mockXraySSHClient: newMockXraySSHClient()}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "c1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 910, Host: "192.0.2.110"}, map[string]any{"port": 8443})
	if err == nil || !strings.Contains(err.Error(), "failed to stage existing xray container for replacement") {
		t.Fatalf("expected staging failure error, got: %v", err)
	}
	if !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
		t.Error("expected docker start amnezia-xray after rename failure")
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
		t.Error("expected previous config restored after rename failure")
	}
}

type cancelAwareMockSSH struct {
	*mockXraySSHClient
	onCommand func(cmd string)
}

func (m *cancelAwareMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if m.onCommand != nil {
		m.onCommand(cmd)
	}
	if err := ctx.Err(); err != nil {
		return "", "context canceled", 1, err
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func (m *cancelAwareMockSSH) UploadSudoFile(ctx context.Context, path string, content []byte, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.mockXraySSHClient.UploadSudoFile(ctx, path, content, mode)
}

func TestXrayManager_LaunchContainer_ContextCanceledAfterStaging_RollsBackSuccessfully(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockSSH := &cancelAwareMockSSH{
		mockXraySSHClient: newMockXraySSHClient(),
		onCommand: func(cmd string) {
			if strings.Contains(cmd, "docker run") {
				cancel()
			}
		},
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "d1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(ctx, &models.Server{ID: 911, Host: "192.0.2.111"}, map[string]any{"port": 8443})
	if err == nil || !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected rollback error, got: %v", err)
	}
	if !hasCmd(mockSSH.commands, "docker rename", "amnezia-xray") || !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
		t.Error("expected backup restored and restarted after context cancellation")
	}
}

func TestXrayManager_LaunchContainer_ContextCanceledDuringReadiness_RollsBackSuccessfully(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockSSH := &cancelAwareMockSSH{mockXraySSHClient: newMockXraySSHClient()}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	mgr.SetVLESSProbeFunc(func(probeCtx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		cancel()
		return 0, context.Canceled
	})
	cfg := setupInitialXrayConfig(t, "e1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(ctx, &models.Server{ID: 912, Host: "192.0.2.112"}, map[string]any{"port": 8443})
	if err == nil || !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected rollback error, got: %v", err)
	}
	if !hasCmd(mockSSH.commands, "docker rename", "amnezia-xray") || !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
		t.Error("expected container restored and restarted after readiness cancellation")
	}
}

func TestXrayManager_UpgradeWithClients_VerifiesVLESSTrafficProbe(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	var capturedTrafficParams models.VLESSRealityParams
	called := false
	mgr.SetVLESSTrafficProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		called = true
		capturedTrafficParams = params
		return 25, nil
	})

	const clientUUID = "f1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"
	cfg := setupInitialXrayConfig(t, clientUUID)
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	if err := mgr.Install(context.Background(), &models.Server{ID: 913, Host: "192.0.2.113"}, map[string]any{"port": 8443}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !called || capturedTrafficParams.UUID != clientUUID || capturedTrafficParams.Flow != "xtls-rprx-vision" {
		t.Fatalf("traffic probe verification failed: called=%v, params=%+v", called, capturedTrafficParams)
	}
}

func TestXrayManager_UpgradeWithClients_TrafficProbeFailureRollsBack(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	mgr.SetVLESSTrafficProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		return 0, errors.New("vless: client unauthorized")
	})
	cfg := setupInitialXrayConfig(t, "a9b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 914, Host: "192.0.2.114"}, map[string]any{"port": 8443})
	if err == nil || !strings.Contains(err.Error(), "failed VLESS traffic readiness probe") || !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected traffic probe rollback error, got: %v", err)
	}
	if !hasCmd(mockSSH.commands, "docker rename", "amnezia-xray") || !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
		t.Error("expected container restored and restarted on traffic probe failure")
	}
}
