//go:build with_utls

package xray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type stopFailMockSSH struct {
	*mockXraySSHClient
	canceledAfterEffect bool
}

func (m *stopFailMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker stop") && !strings.Contains(cmd, "docker rm") {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.dockerAlive = false
		m.mu.Unlock()
		if m.canceledAfterEffect {
			return "", "", -1, context.Canceled
		}
		return "", "docker daemon: stop failed", 1, errors.New("command exited 1")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_StageExistingContainer_StopFailureRestartsContainer(t *testing.T) {
	mockSSH := &stopFailMockSSH{mockXraySSHClient: newMockXraySSHClient()}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "c1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 920, Host: "192.0.2.120"}, map[string]any{"port": 8443})
	if err == nil || !strings.Contains(err.Error(), "failed to stop existing xray container for staging") {
		t.Fatalf("expected stop failure staging error, got: %v", err)
	}
	if !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
		t.Error("expected docker start amnezia-xray after stop failure")
	}
	if !mockSSH.dockerAlive {
		t.Error("expected container restarted and alive after stop failure")
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
		t.Error("expected previous config restored after stop failure")
	}
}

func TestXrayManager_StageExistingContainer_StopCancellationAfterEffectRestoresService(t *testing.T) {
	mockSSH := &stopFailMockSSH{
		mockXraySSHClient:   newMockXraySSHClient(),
		canceledAfterEffect: true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "d1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 921, Host: "192.0.2.121"}, map[string]any{"port": 8443})
	if err == nil || !strings.Contains(err.Error(), "failed to stop existing xray container for staging") || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled stop staging error, got: %v", err)
	}
	if !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
		t.Error("expected docker start amnezia-xray after stop cancellation")
	}
	if !mockSSH.dockerAlive {
		t.Error("expected container restarted and alive after stop cancellation")
	}
	if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
		t.Error("expected previous config restored after stop cancellation")
	}
}

func TestXrayManager_StageExistingContainer_FailsClosedWhenConfigMissing(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	yes := true
	mockSSH.existingContainer = &yes
	mockSSH.dockerAlive = true
	// mockSSH.files[XrayConfigPath] is deliberately not set: existing container running without config

	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 930, Host: "192.0.2.130"}

	err := mgr.Install(context.Background(), server, map[string]any{"port": 8443})
	if err == nil {
		t.Fatal("expected Install to fail closed when existing container config is missing, got nil error")
	}
	expectedMsg := "existing xray container detected but original configuration could not be recovered; aborting to preserve container state"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error containing %q, got: %v", expectedMsg, err)
	}

	// Verify existing container was neither stopped nor removed
	if hasCmd(mockSSH.commands, "docker stop", "amnezia-xray") {
		t.Error("expected amnezia-xray to NOT be stopped when failing closed")
	}
	if hasCmd(mockSSH.commands, "docker rm", "amnezia-xray") {
		t.Error("expected amnezia-xray to NOT be removed when failing closed")
	}
	if !mockSSH.dockerAlive {
		t.Error("expected existing container to remain alive when failing closed")
	}

	// Finding 1 assertion: config file on disk must NOT be written before existing container safety check
	if _, ok := mockSSH.files[XrayConfigPath]; ok {
		t.Error("expected config file on disk to remain absent when failing closed")
	}
}

func TestXrayManager_StageExistingContainer_FailsClosedWhenStoppedContainerConfigMissing(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	yes := true
	no := false
	mockSSH.existingContainer = &yes
	mockSSH.existingRunning = &no
	mockSSH.dockerAlive = false

	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 934, Host: "192.0.2.134"}

	err := mgr.Install(context.Background(), server, map[string]any{"port": 8443})
	if err == nil {
		t.Fatal("expected Install to fail closed when stopped container config is missing, got nil error")
	}
	expectedMsg := "existing xray container detected but original configuration could not be recovered; aborting to preserve container state"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("expected error containing %q, got: %v", expectedMsg, err)
	}

	if hasCmd(mockSSH.commands, "docker stop", "amnezia-xray") {
		t.Error("expected amnezia-xray to NOT be stopped when failing closed")
	}
	if hasCmd(mockSSH.commands, "docker rm", "amnezia-xray") {
		t.Error("expected amnezia-xray to NOT be removed when failing closed")
	}
	if _, ok := mockSSH.files[XrayConfigPath]; ok {
		t.Error("expected config file on disk to remain absent when failing closed")
	}
}

type renameRecoveryFaultMockSSH struct {
	*mockXraySSHClient
	failConfigRestore  bool
	failContainerStart bool
	renameAttempted    bool
}

func (m *renameRecoveryFaultMockSSH) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	renamed := m.renameAttempted
	m.mu.Unlock()
	if m.failConfigRestore && renamed && remotePath == XrayConfigPath {
		return errors.New("simulated upload failure during config restore")
	}
	return m.mockXraySSHClient.UploadSudoFile(ctx, remotePath, content, mode)
}

func (m *renameRecoveryFaultMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker rename") {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.renameAttempted = true
		m.mu.Unlock()
		return "", "docker rename error: name conflict", 1, errors.New("command exited 1")
	}
	if strings.Contains(cmd, "docker start") && m.failContainerStart {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.mu.Unlock()
		return "", "docker daemon: start failed", 1, errors.New("command exited 1")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_StageExistingContainer_RenameFailureSurfacesConfigUploadError(t *testing.T) {
	mockSSH := &renameRecoveryFaultMockSSH{
		mockXraySSHClient: newMockXraySSHClient(),
		failConfigRestore: true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "e1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 931, Host: "192.0.2.131"}, map[string]any{"port": 8443})
	if err == nil {
		t.Fatal("expected staging failure error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to stage existing xray container for replacement") {
		t.Errorf("expected error mentioning staging failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "recovery failures: failed to restore config") {
		t.Errorf("expected error mentioning recovery config restore failure, got: %v", err)
	}
}

func TestXrayManager_StageExistingContainer_RenameFailureSurfacesContainerStartError(t *testing.T) {
	mockSSH := &renameRecoveryFaultMockSSH{
		mockXraySSHClient:  newMockXraySSHClient(),
		failContainerStart: true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "f1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 932, Host: "192.0.2.132"}, map[string]any{"port": 8443})
	if err == nil {
		t.Fatal("expected staging failure error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to stage existing xray container for replacement") {
		t.Errorf("expected error mentioning staging failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "recovery failures: failed to restart container") {
		t.Errorf("expected error mentioning recovery restart failure, got: %v", err)
	}
}

type stopRecoveryFaultMockSSH struct {
	*mockXraySSHClient
	failContainerStart bool
}

func (m *stopRecoveryFaultMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker stop") && !strings.Contains(cmd, "docker rm") {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.dockerAlive = false
		m.mu.Unlock()
		return "", "docker daemon: stop failed", 1, errors.New("command exited 1")
	}
	if strings.Contains(cmd, "docker start") && m.failContainerStart {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.mu.Unlock()
		return "", "docker daemon: restart failed", 1, errors.New("command exited 1")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_StageExistingContainer_StopFailureSurfacesContainerStartError(t *testing.T) {
	mockSSH := &stopRecoveryFaultMockSSH{
		mockXraySSHClient:  newMockXraySSHClient(),
		failContainerStart: true,
	}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	cfg := setupInitialXrayConfig(t, "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8e")
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	err := mgr.Install(context.Background(), &models.Server{ID: 933, Host: "192.0.2.133"}, map[string]any{"port": 8443})
	if err == nil {
		t.Fatal("expected stop failure error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to stop existing xray container for staging") {
		t.Errorf("expected error mentioning stop failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "recovery failures: failed to restart container") {
		t.Errorf("expected error mentioning recovery restart failure, got: %v", err)
	}
}

type inspectFaultMockSSH struct {
	*mockXraySSHClient
	transportErr      error
	daemonErr         string
	daemonCode        int
	inspectAttempted  bool
	failConfigRestore bool
}

func (m *inspectFaultMockSSH) UploadSudoFile(ctx context.Context, remotePath string, content []byte, mode os.FileMode) error {
	m.mu.Lock()
	inspected := m.inspectAttempted
	m.mu.Unlock()
	if m.failConfigRestore && inspected && remotePath == XrayConfigPath {
		return errors.New("simulated upload failure during config restore")
	}
	return m.mockXraySSHClient.UploadSudoFile(ctx, remotePath, content, mode)
}

func (m *inspectFaultMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker inspect") && strings.Contains(cmd, "{{.State.Running}}") {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.inspectAttempted = true
		m.mu.Unlock()
		if m.transportErr != nil {
			return "", "", -1, m.transportErr
		}
		if m.daemonErr != "" {
			return "", m.daemonErr, m.daemonCode, nil
		}
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_StageExistingContainer_InspectFailureFailsClosedWithoutRemoval(t *testing.T) {
	t.Run("transport error on inspect", func(t *testing.T) {
		mockSSH := &inspectFaultMockSSH{
			mockXraySSHClient: newMockXraySSHClient(),
			transportErr:      errors.New("ssh connection reset by peer"),
		}
		cfg := setupInitialXrayConfig(t, "b1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
		mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		err := mgr.Install(context.Background(), &models.Server{ID: 935, Host: "192.0.2.135"}, map[string]any{"port": 8443})
		if err == nil {
			t.Fatal("expected Install to fail closed when inspect fails, got nil error")
		}
		if !strings.Contains(err.Error(), "failed to inspect container amnezia-xray") {
			t.Fatalf("expected error mentioning inspect container failure, got: %v", err)
		}
		// Finding 2 critical assertion: NEVER fall through to docker rm -fv amnezia-xray
		if hasCmd(mockSSH.commands, "docker rm", "amnezia-xray") {
			t.Error("expected amnezia-xray to NOT be removed when inspect fails")
		}
		if hasCmd(mockSSH.commands, "docker stop", "amnezia-xray") {
			t.Error("expected amnezia-xray to NOT be stopped when inspect fails")
		}
		if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
			t.Error("expected original config restored on disk after inspect transport failure")
		}
	})

	t.Run("daemon error on inspect", func(t *testing.T) {
		mockSSH := &inspectFaultMockSSH{
			mockXraySSHClient: newMockXraySSHClient(),
			daemonErr:         "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
			daemonCode:        125,
		}
		cfg := setupInitialXrayConfig(t, "b2b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
		mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		err := mgr.Install(context.Background(), &models.Server{ID: 936, Host: "192.0.2.136"}, map[string]any{"port": 8443})
		if err == nil {
			t.Fatal("expected Install to fail closed on daemon inspect error, got nil error")
		}
		if !strings.Contains(err.Error(), "failed to inspect container amnezia-xray") {
			t.Fatalf("expected error mentioning inspect container failure, got: %v", err)
		}
		// Finding 2 critical assertion: NEVER fall through to docker rm -fv amnezia-xray
		if hasCmd(mockSSH.commands, "docker rm", "amnezia-xray") {
			t.Error("expected amnezia-xray to NOT be removed when inspect fails")
		}
		if hasCmd(mockSSH.commands, "docker stop", "amnezia-xray") {
			t.Error("expected amnezia-xray to NOT be stopped when inspect fails")
		}
		if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
			t.Error("expected original config restored on disk after inspect daemon failure")
		}
	})

	t.Run("inspect failure surfaces config restore error", func(t *testing.T) {
		mockSSH := &inspectFaultMockSSH{
			mockXraySSHClient: newMockXraySSHClient(),
			transportErr:      errors.New("ssh connection reset by peer"),
			failConfigRestore: true,
		}
		cfg := setupInitialXrayConfig(t, "b3b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
		mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		err := mgr.Install(context.Background(), &models.Server{ID: 939, Host: "192.0.2.139"}, map[string]any{"port": 8443})
		if err == nil {
			t.Fatal("expected Install to fail closed when inspect fails, got nil error")
		}
		if !strings.Contains(err.Error(), "failed to inspect container amnezia-xray") {
			t.Fatalf("expected error mentioning inspect container failure, got: %v", err)
		}
		if !strings.Contains(err.Error(), "recovery failures: failed to restore config") {
			t.Fatalf("expected error mentioning recovery config restore failure, got: %v", err)
		}
	})
}

type ambiguousRenameMockSSH struct {
	*mockXraySSHClient
	renameAttempted bool
}

func (m *ambiguousRenameMockSSH) RunSudoCommand(ctx context.Context, cmd string) (string, string, int, error) {
	if strings.Contains(cmd, "docker rename") && !m.renameAttempted {
		m.mu.Lock()
		m.commands = append(m.commands, "sudo: "+cmd)
		m.renameAttempted = true
		// Remotely the rename succeeded: backup container now exists, original does not
		m.backupContainerAlive = true
		m.dockerAlive = false
		m.mu.Unlock()
		// But an SSH transport interruption occurs during/after command completion
		return "", "ssh: broken pipe", 1, errors.New("ssh connection lost")
	}
	return m.mockXraySSHClient.RunSudoCommand(ctx, cmd)
}

func TestXrayManager_StageExistingContainer_AmbiguousRenameFailureRecovery(t *testing.T) {
	t.Run("running container reverts rename and restarts", func(t *testing.T) {
		mockSSH := &ambiguousRenameMockSSH{
			mockXraySSHClient: newMockXraySSHClient(),
		}
		mockSSH.dockerAlive = true
		cfg := setupInitialXrayConfig(t, "c2b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
		mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		err := mgr.Install(context.Background(), &models.Server{ID: 937, Host: "192.0.2.137"}, map[string]any{"port": 8443})
		if err == nil {
			t.Fatal("expected staging error from rename failure, got nil")
		}
		if !strings.Contains(err.Error(), "failed to stage existing xray container for replacement") {
			t.Fatalf("expected staging error, got: %v", err)
		}

		// Finding 3 assertion: backup container was renamed back to amnezia-xray
		if !hasCmd(mockSSH.commands, "docker rename", "'amnezia-xray-backup' 'amnezia-xray'") {
			t.Errorf("expected docker rename amnezia-xray-backup amnezia-xray during recovery, got commands: %v", mockSSH.commands)
		}
		// Finding 3 assertion: original container was restarted
		if !hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
			t.Errorf("expected docker start amnezia-xray during recovery, got commands: %v", mockSSH.commands)
		}
		// Config restored
		if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
			t.Error("expected original config restored after ambiguous rename recovery")
		}
		// Original service back alive
		if !mockSSH.dockerAlive {
			t.Error("expected original container to be alive after ambiguous rename recovery")
		}
		if mockSSH.backupContainerAlive {
			t.Error("expected backup container to no longer exist after revert")
		}
	})

	t.Run("stopped container reverts rename without restart", func(t *testing.T) {
		mockSSH := &ambiguousRenameMockSSH{
			mockXraySSHClient: newMockXraySSHClient(),
		}
		yes := true
		no := false
		mockSSH.existingContainer = &yes
		mockSSH.existingRunning = &no
		mockSSH.dockerAlive = false

		cfg := setupInitialXrayConfig(t, "c3b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d")
		mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

		mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
		err := mgr.Install(context.Background(), &models.Server{ID: 938, Host: "192.0.2.138"}, map[string]any{"port": 8443})
		if err == nil {
			t.Fatal("expected staging error from rename failure, got nil")
		}
		if !strings.Contains(err.Error(), "failed to stage existing xray container for replacement") {
			t.Fatalf("expected staging error, got: %v", err)
		}

		// Finding 3 assertion: backup container was renamed back to amnezia-xray
		if !hasCmd(mockSSH.commands, "docker rename", "'amnezia-xray-backup' 'amnezia-xray'") {
			t.Errorf("expected docker rename amnezia-xray-backup amnezia-xray during recovery, got commands: %v", mockSSH.commands)
		}
		// Finding 3 assertion: container was NOT started (since it was stopped originally)
		if hasCmd(mockSSH.commands, "docker start", "amnezia-xray") {
			t.Error("expected docker start amnezia-xray to NOT be called for originally stopped container")
		}
		// Config restored
		if !bytes.Equal(mockSSH.files[XrayConfigPath], cfg) {
			t.Error("expected original config restored after ambiguous rename recovery")
		}
	})
}

func TestXrayManager_UpgradeWithExistingClient_EmptyFlowProbedWithEmptyFlow(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	clientUUID := "f1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"
	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	// Existing client configured with empty Flow ("")
	cls := []XrayClient{{ID: clientUUID, Flow: "", Email: "plain-vless-client"}}
	cfg, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, cls)
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	var capturedTrafficParams models.VLESSRealityParams
	trafficProbeCalled := false
	mgr.SetVLESSTrafficProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		trafficProbeCalled = true
		capturedTrafficParams = params
		return 15, nil
	})

	server := &models.Server{
		ID:   941,
		Host: "192.0.2.141",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}

	// Install with fallback flow configured (no explicit flow override; manager defaults to "xtls-rprx-vision")
	err = mgr.Install(context.Background(), server, map[string]any{
		"port": 8443,
	})
	if err != nil {
		t.Fatalf("mgr.Install failed: %v", err)
	}

	if !trafficProbeCalled {
		t.Fatal("expected traffic probe to be invoked during readiness check")
	}
	if capturedTrafficParams.UUID != clientUUID {
		t.Errorf("probeParams.UUID = %q, want %q", capturedTrafficParams.UUID, clientUUID)
	}
	// Finding F1 assertion: client with empty flow must be probed with empty flow (""),
	// not falling back to opts.flow ("xtls-rprx-vision").
	if capturedTrafficParams.Flow != "" {
		t.Errorf("probeParams.Flow = %q, want empty string for client with empty flow", capturedTrafficParams.Flow)
	}
	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || len(parsed.Inbounds[0].Settings.Clients) == 0 {
		t.Fatal("expected clients in config")
	}
	if got := parsed.Inbounds[0].Settings.Clients[0].Flow; got != "" {
		t.Errorf("expected empty flow preserved in config, got %q", got)
	}
}

func TestXrayManager_FlowConversion_PlainToVision(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	clientUUID := "f1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"
	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	// 1. Existing client configured with empty Flow ("")
	cls := []XrayClient{{ID: clientUUID, Flow: "", Email: "plain-vless-client"}}
	cfg, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, cls)
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	var capturedTrafficParams models.VLESSRealityParams
	trafficProbeCalled := false
	mgr.SetVLESSTrafficProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		trafficProbeCalled = true
		capturedTrafficParams = params
		uploaded, parseErr := ParseXrayConfig(mockSSH.files[XrayConfigPath])
		if parseErr != nil {
			return 0, parseErr
		}
		if len(uploaded.Inbounds) == 0 || len(uploaded.Inbounds[0].Settings.Clients) == 0 {
			return 0, errors.New("uploaded config has no clients")
		}
		uploadedFlow := uploaded.Inbounds[0].Settings.Clients[0].Flow
		if params.Flow != uploadedFlow {
			return 0, fmt.Errorf("probe flow %q differs from uploaded client flow %q", params.Flow, uploadedFlow)
		}
		return 15, nil
	})

	server := &models.Server{
		ID:   943,
		Host: "192.0.2.143",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
			},
		},
	}

	// Plain-to-Vision conversion: explicit flow "xtls-rprx-vision"
	err = mgr.Install(context.Background(), server, map[string]any{
		"port": 8443,
		"flow": "xtls-rprx-vision",
	})
	if err != nil {
		t.Fatalf("mgr.Install failed: %v", err)
	}

	if !trafficProbeCalled {
		t.Fatal("expected traffic probe to be invoked during readiness check")
	}
	if capturedTrafficParams.UUID != clientUUID {
		t.Errorf("probeParams.UUID = %q, want %q", capturedTrafficParams.UUID, clientUUID)
	}
	if capturedTrafficParams.Flow != "xtls-rprx-vision" {
		t.Errorf("probeParams.Flow = %q, want xtls-rprx-vision", capturedTrafficParams.Flow)
	}

	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if got := parsed.Inbounds[0].Settings.Clients[0].Flow; got != "xtls-rprx-vision" {
		t.Errorf("uploaded client flow = %q, want xtls-rprx-vision", got)
	}
}

func TestXrayManager_FlowConversion_VisionToPlain(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	clientUUID := "f1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"
	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	// 1. Existing client configured with Vision Flow ("xtls-rprx-vision")
	cls := []XrayClient{{ID: clientUUID, Flow: "xtls-rprx-vision", Email: "vision-vless-client"}}
	cfg, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, cls)
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	var capturedTrafficParams models.VLESSRealityParams
	trafficProbeCalled := false
	mgr.SetVLESSTrafficProbeFunc(func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		trafficProbeCalled = true
		capturedTrafficParams = params
		uploaded, parseErr := ParseXrayConfig(mockSSH.files[XrayConfigPath])
		if parseErr != nil {
			return 0, parseErr
		}
		if len(uploaded.Inbounds) == 0 || len(uploaded.Inbounds[0].Settings.Clients) == 0 {
			return 0, errors.New("uploaded config has no clients")
		}
		uploadedFlow := uploaded.Inbounds[0].Settings.Clients[0].Flow
		if params.Flow != uploadedFlow {
			return 0, fmt.Errorf("probe flow %q differs from uploaded client flow %q", params.Flow, uploadedFlow)
		}
		return 15, nil
	})

	server := &models.Server{
		ID:   944,
		Host: "192.0.2.144",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           8443,
				"engine_profile": "legacy",
				"flow":           "xtls-rprx-vision",
			},
		},
	}

	// Vision-to-plain conversion: explicit flow "" via vless_options
	err = mgr.Install(context.Background(), server, map[string]any{
		"port": 8443,
		"vless_options": &models.VLESSInstallOptions{
			Flow:    "",
			FlowSet: true,
		},
	})
	if err != nil {
		t.Fatalf("mgr.Install failed: %v", err)
	}

	if !trafficProbeCalled {
		t.Fatal("expected traffic probe to be invoked during readiness check")
	}
	if capturedTrafficParams.UUID != clientUUID {
		t.Errorf("probeParams.UUID = %q, want %q", capturedTrafficParams.UUID, clientUUID)
	}
	if capturedTrafficParams.Flow != "" {
		t.Errorf("probeParams.Flow = %q, want empty string", capturedTrafficParams.Flow)
	}

	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if got := parsed.Inbounds[0].Settings.Clients[0].Flow; got != "" {
		t.Errorf("uploaded client flow = %q, want empty string", got)
	}
}

func TestXrayManager_ProfileSwitch_OmittedPortPreservesExistingInboundPort(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatalf("GenerateRealityKeypair: %v", err)
	}
	// Remote Xray inbound configuration is on port 8443
	cfg, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, []XrayClient{})
	if err != nil {
		t.Fatalf("RenderXrayConfig: %v", err)
	}
	mockSSH.files[XrayConfigPath] = append([]byte(nil), cfg...)

	// Server metadata is STALE with port 443
	server := &models.Server{
		ID:   942,
		Host: "192.0.2.142",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"port":           443, // STALE! Mismatched with remote 8443!
				"engine_profile": "legacy",
			},
		},
	}

	// Routine profile switch where port was omitted (port_explicit: false)
	err = mgr.Install(context.Background(), server, map[string]any{
		"engine_profile": "modern_pq",
		"port_explicit":  false,
	})
	if err != nil {
		t.Fatalf("mgr.Install failed: %v", err)
	}

	// 1. Verify remote Xray inbound config was NOT overwritten with stale port 443
	parsed, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("ParseXrayConfig: %v", err)
	}
	if len(parsed.Inbounds) == 0 || parsed.Inbounds[0].Port != 8443 {
		t.Fatalf("remote config inbound port = %v, want 8443 (stale metadata 443 must not overwrite)", parsed.Inbounds[0].Port)
	}

	// 2. Verify server metadata was repaired to 8443
	vMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("expected VLESS metadata on server")
	}
	if port, _ := vMeta["port"].(int); port != 8443 {
		t.Errorf("server.Protocols[vless] port = %v, want 8443", port)
	}
}
