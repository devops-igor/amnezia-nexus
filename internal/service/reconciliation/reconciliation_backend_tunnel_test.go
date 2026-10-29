package reconciliation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestReconciler_PreservesBackendTunnelClients_Naive(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:      "Naive-Node",
		Host:      "10.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{"naive": map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	// Mark legacy peers adopted so ongoing reconciliation will delete unmanaged zombies
	if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, "naive"), true); err != nil {
		t.Fatalf("set legacy adopted: %v", err)
	}

	// Create an active backend tunnel for server sID
	naiveUsername := "user_f116e91ee501"
	naiveParams, err := json.Marshal(models.NaiveProxyParams{
		Username: naiveUsername,
		Password: "secret-password",
		Domain:   "hehe.drochi.games",
		EnableH3: false,
	})
	if err != nil {
		t.Fatalf("marshal naive params: %v", err)
	}

	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:       sID,
		InterfaceName:  "naive-be-26",
		Endpoint:       "10.0.0.1:443",
		Protocol:       models.ProtocolNaive,
		ProtocolParams: naiveParams,
		Enabled:        true,
		Status:         models.TunnelStatusActive,
		StateVersion:   1,
	})
	if err != nil {
		t.Fatalf("create backend tunnel: %v", err)
	}

	old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
	realZombie := "user_real_zombie_9999"

	mgr := &mockZombiePeerProtocolManager{
		proto: "naive",
		clients: []map[string]any{
			{"clientId": naiveUsername, "username": naiveUsername, "creationDate": old},
			{"clientId": realZombie, "username": realZombie, "creationDate": old},
		},
	}
	reg := newMockRegistry()
	reg.Register(mgr)

	r := New(db, reg)
	if err := r.CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers failed: %v", err)
	}

	mgr.mu.Lock()
	deleted := append([]string(nil), mgr.deleted...)
	mgr.mu.Unlock()

	// Assert: realZombie was deleted, but active backend client was preserved
	if len(deleted) != 1 || deleted[0] != realZombie {
		t.Fatalf("expected only realZombie %s to be deleted, got %v", realZombie, deleted)
	}

	// Assert: naiveUsername was preserved and recorded in peer_lifecycle with backend_active
	lifecycles, err := db.GetPeerLifecycles(ctx, sID, "naive")
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	rec, ok := lifecycles[naiveUsername]
	if !ok {
		t.Fatalf("expected naive backend client %s to be tracked in peer_lifecycle", naiveUsername)
	}
	if rec.Status != "backend_active" {
		t.Fatalf("expected status 'backend_active', got %q", rec.Status)
	}
}

func TestReconciler_PreservesBackendTunnelClients_VLESS(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:      "VLESS-Node",
		Host:      "10.0.0.2",
		SSHPort:   22,
		Protocols: map[string]any{"vless": map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, "vless"), true); err != nil {
		t.Fatalf("set legacy adopted: %v", err)
	}

	vlessUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	vlessParams, err := json.Marshal(models.VLESSRealityParams{
		UUID:        vlessUUID,
		PublicKey:   "test-pub-key",
		ServerName:  "gateway.icloud.com",
		Fingerprint: "chrome",
	})
	if err != nil {
		t.Fatalf("marshal vless params: %v", err)
	}

	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:       sID,
		InterfaceName:  "vless-be-1",
		Endpoint:       "10.0.0.2:443",
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessParams,
		Enabled:        true,
		Status:         models.TunnelStatusActive,
		StateVersion:   1,
	})
	if err != nil {
		t.Fatalf("create backend tunnel: %v", err)
	}

	old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
	realZombie := "zombie-uuid-9999"

	mgr := &mockZombiePeerProtocolManager{
		proto: "vless",
		clients: []map[string]any{
			{"clientId": vlessUUID, "uuid": vlessUUID, "creationDate": old},
			{"clientId": realZombie, "uuid": realZombie, "creationDate": old},
		},
	}
	reg := newMockRegistry()
	reg.Register(mgr)

	r := New(db, reg)
	if err := r.CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers failed: %v", err)
	}

	mgr.mu.Lock()
	deleted := append([]string(nil), mgr.deleted...)
	mgr.mu.Unlock()

	if len(deleted) != 1 || deleted[0] != realZombie {
		t.Fatalf("expected only realZombie %s to be deleted, got %v", realZombie, deleted)
	}

	lifecycles, err := db.GetPeerLifecycles(ctx, sID, "vless")
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	rec, ok := lifecycles[vlessUUID]
	if !ok {
		t.Fatalf("expected vless backend client %s to be tracked in peer_lifecycle", vlessUUID)
	}
	if rec.Status != "backend_active" {
		t.Fatalf("expected status 'backend_active', got %q", rec.Status)
	}
}
