package xray

import (
	"context"
	"reflect"
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
