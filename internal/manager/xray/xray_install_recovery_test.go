//go:build with_utls

package xray

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

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
