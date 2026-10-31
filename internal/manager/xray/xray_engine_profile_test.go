package xray

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestResolveEngineProfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantProfile EngineProfile
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "empty defaults to legacy baseline",
			input:       "",
			wantProfile: EngineProfileLegacy,
			wantVersion: XrayLegacyVersion,
			wantErr:     false,
		},
		{
			name:        "legacy name",
			input:       "legacy",
			wantProfile: EngineProfileLegacy,
			wantVersion: XrayLegacyVersion,
			wantErr:     false,
		},
		{
			name:        "legacy version tag",
			input:       "1.8.24",
			wantProfile: EngineProfileLegacy,
			wantVersion: XrayLegacyVersion,
			wantErr:     false,
		},
		{
			name:        "modern_pq name",
			input:       "modern_pq",
			wantProfile: EngineProfileModernPQ,
			wantVersion: XrayModernPQVersion,
			wantErr:     false,
		},
		{
			name:        "modern_pq version tag",
			input:       "26.10.29",
			wantProfile: EngineProfileModernPQ,
			wantVersion: XrayModernPQVersion,
			wantErr:     false,
		},
		{
			name:        "modern_pq case insensitive with spaces",
			input:       "Modern PQ",
			wantProfile: EngineProfileModernPQ,
			wantVersion: XrayModernPQVersion,
			wantErr:     false,
		},
		{
			name:    "unknown profile returns error",
			input:   "unsupported-version-999",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ResolveEngineProfile(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if info.Name != tt.wantProfile {
				t.Errorf("info.Name = %q, want %q", info.Name, tt.wantProfile)
			}
			if info.Version != tt.wantVersion {
				t.Errorf("info.Version = %q, want %q", info.Version, tt.wantVersion)
			}
			if !strings.Contains(info.Image, info.ImageDigest) {
				t.Errorf("info.Image %q does not contain digest %q", info.Image, info.ImageDigest)
			}
		})
	}
}

func TestXrayManager_ProfileSwitchingPreservesConfigAndCredentials(t *testing.T) {
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())
	server := &models.Server{ID: 101, Host: "192.0.2.101"}
	ctx := context.Background()

	// 1. Initial install with default profile (Legacy Baseline 1.8.24)
	err := mgr.Install(ctx, server, map[string]any{"port": 443})
	if err != nil {
		t.Fatalf("initial install failed: %v", err)
	}

	meta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("missing vless metadata")
	}
	if meta["engine_profile"] != string(EngineProfileLegacy) {
		t.Errorf("initial engine_profile = %v, want %s", meta["engine_profile"], EngineProfileLegacy)
	}
	if meta["engine_version"] != XrayLegacyVersion {
		t.Errorf("initial engine_version = %v, want %s", meta["engine_version"], XrayLegacyVersion)
	}
	if meta["engine_image"] != XrayLegacyImage {
		t.Errorf("initial engine_image = %v, want %s", meta["engine_image"], XrayLegacyImage)
	}

	initialPubKey := meta["public_key"]
	initialShortID := meta["short_id"]

	// Parse initial config to read clients and private key
	initialCfg, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("parse initial config: %v", err)
	}
	initialPrivKey := initialCfg.Inbounds[0].StreamSettings.RealitySettings.PrivateKey

	// Add a client to the initial installation
	clientParams := map[string]any{
		"name":  "alice",
		"email": "alice@example.com",
	}
	addedClient, err := mgr.AddClient(ctx, server, clientParams)
	if err != nil {
		t.Fatalf("AddClient failed: %v", err)
	}
	addedUUID, _ := addedClient["client_id"].(string)
	if addedClient["engine_profile"] != string(EngineProfileLegacy) {
		t.Errorf("initial client engine_profile = %v, want %s", addedClient["engine_profile"], EngineProfileLegacy)
	}

	// 2. Switch engine profile to Modern PQ (26.10.29)
	switchParams := map[string]any{
		"engine_profile": string(EngineProfileModernPQ),
	}
	if err := mgr.Install(ctx, server, switchParams); err != nil {
		t.Fatalf("profile switch to modern_pq failed: %v", err)
	}

	updatedMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if !ok {
		t.Fatalf("missing updated vless metadata")
	}
	if updatedMeta["engine_profile"] != string(EngineProfileModernPQ) {
		t.Errorf("updated engine_profile = %v, want %s", updatedMeta["engine_profile"], EngineProfileModernPQ)
	}
	if updatedMeta["engine_version"] != XrayModernPQVersion {
		t.Errorf("updated engine_version = %v, want %s", updatedMeta["engine_version"], XrayModernPQVersion)
	}
	if updatedMeta["engine_image"] != XrayModernPQImage {
		t.Errorf("updated engine_image = %v, want %s", updatedMeta["engine_image"], XrayModernPQImage)
	}

	// Verify cryptographic credentials preserved without regression
	if updatedMeta["public_key"] != initialPubKey {
		t.Errorf("public_key changed after profile switch: got %v, want %v", updatedMeta["public_key"], initialPubKey)
	}
	if updatedMeta["short_id"] != initialShortID {
		t.Errorf("short_id changed after profile switch: got %v, want %v", updatedMeta["short_id"], initialShortID)
	}

	// Verify clients preserved in XrayConfigPath
	switchedCfg, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("parse switched config: %v", err)
	}
	switchedPrivKey := switchedCfg.Inbounds[0].StreamSettings.RealitySettings.PrivateKey
	if switchedPrivKey != initialPrivKey {
		t.Errorf("private key changed after profile switch: got %q, want %q", switchedPrivKey, initialPrivKey)
	}

	clients := switchedCfg.Inbounds[0].Settings.Clients
	if len(clients) != 1 {
		t.Fatalf("expected 1 client preserved, got %d", len(clients))
	}
	if clients[0].ID != addedUUID || clients[0].Email != addedUUID {
		t.Errorf("client not preserved properly: %+v", clients[0])
	}

	// Verify GetServerStatus reflects container running and configuration
	status, err := mgr.GetServerStatus(ctx, server)
	if err != nil {
		t.Fatalf("GetServerStatus: %v", err)
	}
	if !status["container_running"].(bool) {
		t.Errorf("expected container_running = true")
	}
	if status["public_key"] != initialPubKey {
		t.Errorf("status public_key = %v, want %v", status["public_key"], initialPubKey)
	}

	// Verify docker run command pulled and ran the Modern PQ image
	var dockerRunFound bool
	for _, cmd := range mockSSH.commands {
		if strings.Contains(cmd, "docker run") && strings.Contains(cmd, XrayModernPQImage) {
			dockerRunFound = true
			break
		}
	}
	if !dockerRunFound {
		t.Errorf("expected docker run command with image %s", XrayModernPQImage)
	}

	// 3. Switch back to Legacy Baseline (1.8.24) and verify clients/keys still intact
	if err := mgr.Install(ctx, server, map[string]any{"engine_profile": "legacy"}); err != nil {
		t.Fatalf("profile switch back to legacy failed: %v", err)
	}
	revertedMeta := server.Protocols[models.ProtocolVLESS].(map[string]any)
	if revertedMeta["engine_profile"] != string(EngineProfileLegacy) {
		t.Errorf("reverted engine_profile = %v, want %s", revertedMeta["engine_profile"], EngineProfileLegacy)
	}
	if revertedMeta["engine_version"] != XrayLegacyVersion {
		t.Errorf("reverted engine_version = %v, want %s", revertedMeta["engine_version"], XrayLegacyVersion)
	}

	revertedCfg, err := ParseXrayConfig(mockSSH.files[XrayConfigPath])
	if err != nil {
		t.Fatalf("parse reverted config: %v", err)
	}
	if len(revertedCfg.Inbounds[0].Settings.Clients) != 1 {
		t.Fatalf("expected 1 client preserved after second switch, got %d", len(revertedCfg.Inbounds[0].Settings.Clients))
	}
	if !reflect.DeepEqual(revertedCfg.Inbounds[0].StreamSettings.RealitySettings.ShortIDs, switchedCfg.Inbounds[0].StreamSettings.RealitySettings.ShortIDs) {
		t.Errorf("shortIDs mismatch after revert")
	}
}

func TestXrayManager_AddClientPropagatesEngineProfile(t *testing.T) {
	ctx := context.Background()
	mockSSH := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: mockSSH}, awg.NewServerLockRegistry())

	server := &models.Server{
		ID:      2,
		Host:    "192.0.2.10",
		SSHPort: 22,
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"engine_profile": string(EngineProfileModernPQ),
			},
		},
	}

	// 1. Initial install with modern profile
	if err := mgr.Install(ctx, server, map[string]any{"engine_profile": "modern_pq"}); err != nil {
		t.Fatalf("Install modern: %v", err)
	}

	// 2. Add client inherits modern profile
	client1, err := mgr.AddClient(ctx, server, map[string]any{"name": "modern-user"})
	if err != nil {
		t.Fatalf("AddClient modern: %v", err)
	}
	if client1["engine_profile"] != string(EngineProfileModernPQ) {
		t.Fatalf("got engine_profile = %v, want %s", client1["engine_profile"], EngineProfileModernPQ)
	}

	// 3. Explicit override in clientParams
	client2, err := mgr.AddClient(ctx, server, map[string]any{"name": "legacy-override", "engine_profile": "legacy"})
	if err != nil {
		t.Fatalf("AddClient override: %v", err)
	}
	if client2["engine_profile"] != string(EngineProfileLegacy) {
		t.Fatalf("got engine_profile = %v, want %s", client2["engine_profile"], EngineProfileLegacy)
	}
}
