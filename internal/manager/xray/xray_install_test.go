package xray

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
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
	config, err := RenderXrayConfig(443, 54321, "gateway.icloud.com", "", privateKey, want, []XrayClient{})
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
	config, err := RenderXrayConfig(8443, 54321, "gateway.icloud.com", "", privateKey, []string{"0123456789abcdef"}, []XrayClient{})
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
	config, err := RenderXrayConfig(443, 54321, "gateway.icloud.com", "", privateKey, []string{"0123456789abcdef"}, []XrayClient{})
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
	config, err := RenderXrayConfig(443, 54321, "gateway.icloud.com", "", privateKey, []string{"0123456789abcdef"}, []XrayClient{})
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
}
