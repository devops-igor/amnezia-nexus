package naive

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestNaiveManagerInstallWithHardenedConfigDirectory(t *testing.T) {
	mockSSH := newMockNaiveSSHClient()
	mockSSH.sshUser = "ubuntu"
	mockSSH.denyConfigStat = true
	mockSSH.denyConfigDownload = true
	mgr := NewNaiveManagerWithServerLocks(&mockNaivePool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 88, Host: "198.51.100.88", SSHUser: "ubuntu"}
	ctx := context.Background()

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("fresh install with unprivileged stat denied: %v", err)
	}
	if _, err := mgr.AddClient(ctx, server, map[string]any{"name": "preserved-client"}); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	_, _, beforeClients, err := ParseCaddyfile(string(mockSSH.files[NaiveCaddyfilePath]))
	if err != nil {
		t.Fatalf("parse Caddyfile before repair: %v", err)
	}

	if err := mgr.Install(ctx, server, map[string]any{"port": 443}); err != nil {
		t.Fatalf("repair with unprivileged stat denied: %v", err)
	}
	_, _, afterClients, err := ParseCaddyfile(string(mockSSH.files[NaiveCaddyfilePath]))
	if err != nil {
		t.Fatalf("parse Caddyfile after repair: %v", err)
	}
	if !reflect.DeepEqual(afterClients, beforeClients) {
		t.Errorf("repair replaced clients: got %+v, want %+v", afterClients, beforeClients)
	}

	checkCommand := "sudo: test -f '" + NaiveCaddyfilePath + "'"
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
