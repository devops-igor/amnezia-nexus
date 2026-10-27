package naive

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type modeRecordingNaiveSSHClient struct {
	*mockNaiveSSHClient
	modeMu sync.Mutex
	modes  []os.FileMode
}

func (m *modeRecordingNaiveSSHClient) UploadSudoFile(
	ctx context.Context,
	remotePath string,
	content []byte,
	mode os.FileMode,
) error {
	if remotePath == NaiveCaddyfilePath {
		m.modeMu.Lock()
		m.modes = append(m.modes, mode)
		m.modeMu.Unlock()
	}
	return m.mockNaiveSSHClient.UploadSudoFile(ctx, remotePath, content, mode)
}

func TestNaiveSecretConfigPermissions(t *testing.T) {
	base := newMockNaiveSSHClient()
	client := &modeRecordingNaiveSSHClient{mockNaiveSSHClient: base}
	mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: client}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 43, Host: "192.0.2.43", SSHPort: 22}
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
		t.Fatalf("Caddyfile writes = %d, want 3", len(modes))
	}
	for _, mode := range modes {
		if mode != 0600 {
			t.Errorf("Caddyfile mode = %04o, want 0600", mode)
		}
	}

	base.mu.Lock()
	commands := append([]string(nil), base.commands...)
	base.mu.Unlock()
	foundRestrictiveDirectory := false
	for _, command := range commands {
		if strings.Contains(command, "chmod 0700") && strings.Contains(command, NaiveConfigDir) {
			foundRestrictiveDirectory = true
			break
		}
	}
	if !foundRestrictiveDirectory {
		t.Fatalf("missing chmod 0700 for %s in commands: %v", NaiveConfigDir, commands)
	}
}
