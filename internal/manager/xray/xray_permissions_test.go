package xray

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type modeRecordingXraySSHClient struct {
	*mockXraySSHClient
	modeMu sync.Mutex
	modes  []os.FileMode
}

func (m *modeRecordingXraySSHClient) UploadSudoFile(
	ctx context.Context,
	remotePath string,
	content []byte,
	mode os.FileMode,
) error {
	if remotePath == XrayConfigPath {
		m.modeMu.Lock()
		m.modes = append(m.modes, mode)
		m.modeMu.Unlock()
	}
	return m.mockXraySSHClient.UploadSudoFile(ctx, remotePath, content, mode)
}

func TestXraySecretConfigPermissions(t *testing.T) {
	base := newMockXraySSHClient()
	client := &modeRecordingXraySSHClient{mockXraySSHClient: base}
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: client}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 42, Host: "192.0.2.42", SSHPort: 22}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	added, err := mgr.AddClient(ctx, server, map[string]any{"name": "permissions"})
	if err != nil {
		t.Fatalf("AddClient with sudo download: %v", err)
	}
	clientID, _ := added["client_id"].(string)
	if err := mgr.RemoveClient(ctx, server, clientID); err != nil {
		t.Fatalf("RemoveClient with sudo download: %v", err)
	}

	client.modeMu.Lock()
	modes := append([]os.FileMode(nil), client.modes...)
	client.modeMu.Unlock()
	if len(modes) != 3 {
		t.Fatalf("config writes = %d, want 3", len(modes))
	}
	for _, mode := range modes {
		if mode != 0600 {
			t.Errorf("config mode = %04o, want 0600", mode)
		}
	}

	base.mu.Lock()
	commands := append([]string(nil), base.commands...)
	base.mu.Unlock()
	foundRestrictiveDirectory := false
	for _, command := range commands {
		if strings.Contains(command, "chmod 0700") && strings.Contains(command, XrayConfigDir) {
			foundRestrictiveDirectory = true
			break
		}
	}
	if !foundRestrictiveDirectory {
		t.Fatalf("missing chmod 0700 for %s in commands: %v", XrayConfigDir, commands)
	}
}
