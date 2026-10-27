package xray

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestXrayManagerInstallWithHardenedConfigDirectory(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mockSSH.sshUser = "ubuntu"
	mockSSH.denyConfigStat = true
	mockSSH.denyConfigDownload = true
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 42, Host: "192.0.2.42", SSHUser: "ubuntu"}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("fresh install with unprivileged stat denied: %v", err)
	}
	if _, err := mgr.AddClient(ctx, server, map[string]any{"name": "preserved-client"}); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	before, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("parse config before repair: %v", err)
	}

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("repair with unprivileged stat denied: %v", err)
	}
	after, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("parse config after repair: %v", err)
	}
	beforeReality := before.Inbounds[0].StreamSettings.RealitySettings
	afterReality := after.Inbounds[0].StreamSettings.RealitySettings
	if afterReality.PrivateKey != beforeReality.PrivateKey {
		t.Error("repair replaced the REALITY private key")
	}
	if !reflect.DeepEqual(afterReality.ShortIDs, beforeReality.ShortIDs) {
		t.Errorf("repair replaced short IDs: got %v, want %v", afterReality.ShortIDs, beforeReality.ShortIDs)
	}
	if !reflect.DeepEqual(after.Inbounds[0].Settings.Clients, before.Inbounds[0].Settings.Clients) {
		t.Errorf("repair replaced clients: got %+v, want %+v", after.Inbounds[0].Settings.Clients, before.Inbounds[0].Settings.Clients)
	}

	checkCommand := "sudo: test -f '" + XrayConfigPath + "'"
	checks := 0
	for _, command := range mockSSH.commands {
		if strings.TrimSpace(command) == checkCommand {
			checks++
		}
	}
	if checks != 2 {
		t.Errorf("privileged existence checks = %d, want 2; commands: %v", checks, mockSSH.commands)
	}
}
