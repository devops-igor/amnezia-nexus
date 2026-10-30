//go:build with_utls

package xray

import (
	"bytes"
	"context"
	"errors"
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
