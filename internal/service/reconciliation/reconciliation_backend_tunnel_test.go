package reconciliation

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	sqlite "modernc.org/sqlite"
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

func TestReconciler_PreservesBackendTunnelClients_Disabled(t *testing.T) {
	for _, proto := range []string{models.ProtocolNaive, models.ProtocolVLESS} {
		t.Run(proto, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:      "Disabled-Node-" + proto,
				Host:      "10.0.0.10",
				SSHPort:   22,
				Protocols: map[string]any{proto: map[string]any{"installed": true}},
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, proto), true); err != nil {
				t.Fatalf("set legacy adopted: %v", err)
			}

			cid := "user_disabled_naive"
			params := []byte(`{"username":"user_disabled_naive","password":"secret-password","domain":"proxy.example.com"}`)
			if proto == models.ProtocolVLESS {
				cid = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
				params = []byte(fmt.Sprintf(`{"uuid":%q,"public_key":"test-pub","server_name":"example.com"}`, cid))
			}

			tid, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID:       sID,
				InterfaceName:  "be-disabled-1",
				Endpoint:       "10.0.0.10:443",
				Protocol:       proto,
				ProtocolParams: params,
				Enabled:        true,
				Status:         models.TunnelStatusActive,
				StateVersion:   1,
			})
			if err != nil {
				t.Fatalf("create backend tunnel: %v", err)
			}

			// Admin temporarily disables backend tunnel for maintenance
			if err := db.UpdateBackendTunnelEnabled(ctx, tid, false, models.DisableReasonAdmin); err != nil {
				t.Fatalf("disable backend tunnel: %v", err)
			}

			old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
			realZombie := "real_zombie_peer_555"

			mgr := &mockZombiePeerProtocolManager{
				proto: proto,
				clients: []map[string]any{
					{"clientId": cid, "username": cid, "uuid": cid, "creationDate": old},
					{"clientId": realZombie, "username": realZombie, "uuid": realZombie, "creationDate": old},
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

			// Assert: disabled backend client must NOT be deleted; real zombie IS deleted
			if len(deleted) != 1 || deleted[0] != realZombie {
				t.Fatalf("expected only realZombie %s to be deleted, got %v", realZombie, deleted)
			}

			// Assert: disabled backend client adopted into peer_lifecycle
			lifecycles, err := db.GetPeerLifecycles(ctx, sID, proto)
			if err != nil {
				t.Fatalf("GetPeerLifecycles failed: %v", err)
			}
			rec, ok := lifecycles[cid]
			if !ok {
				t.Fatalf("expected disabled backend client %s to be tracked in peer_lifecycle", cid)
			}
			if rec.Status != "backend_active" {
				t.Fatalf("expected status 'backend_active', got %q", rec.Status)
			}
		})
	}
}

func TestReconciler_PreservesBackendTunnelClients_QueryError(t *testing.T) {
	for _, proto := range []string{models.ProtocolNaive, models.ProtocolVLESS} {
		t.Run(proto, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:      "QueryErr-Node-" + proto,
				Host:      "10.0.0.20",
				SSHPort:   22,
				Protocols: map[string]any{proto: map[string]any{"installed": true}},
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, proto), true); err != nil {
				t.Fatalf("set legacy adopted: %v", err)
			}

			cid := "user_query_err_client"
			params := []byte(`{"username":"user_query_err_client","password":"secret-password","domain":"proxy.example.com"}`)
			if proto == models.ProtocolVLESS {
				cid = "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa"
				params = []byte(fmt.Sprintf(`{"uuid":%q,"public_key":"test-pub","server_name":"example.com"}`, cid))
			}

			_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID:       sID,
				InterfaceName:  "be-queryerr-1",
				Endpoint:       "10.0.0.20:443",
				Protocol:       proto,
				ProtocolParams: params,
				Enabled:        true,
				Status:         models.TunnelStatusActive,
				StateVersion:   1,
			})
			if err != nil {
				t.Fatalf("create backend tunnel: %v", err)
			}

			// Inject SQLite Authorizer fault that denies reading backend_tunnels table
			var denied bool
			conn, err := db.SQLDB().Conn(ctx)
			if err != nil {
				t.Fatalf("db.SQLDB().Conn: %v", err)
			}
			err = conn.Raw(func(raw any) error {
				auth, ok := raw.(sqlite.AuthorizerRegisterer)
				if !ok {
					return fmt.Errorf("missing SQLite authorizer")
				}
				return auth.RegisterAuthorizer(func(action sqlite.AuthorizerActionCode, table, column, schema, trigger string) sqlite.AuthorizerReturnCode {
					if action == sqlite.AuthRead && table == "backend_tunnels" && !denied {
						denied = true
						return sqlite.AuthorizerDeny
					}
					return sqlite.AuthorizerOK
				})
			})
			if err != nil {
				t.Fatalf("register authorizer: %v", err)
			}
			if err := conn.Close(); err != nil {
				t.Fatalf("conn.Close: %v", err)
			}

			old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
			mgr := &mockZombiePeerProtocolManager{
				proto: proto,
				clients: []map[string]any{
					{"clientId": cid, "username": cid, "uuid": cid, "creationDate": old},
				},
			}
			reg := newMockRegistry()
			reg.Register(mgr)

			r := New(db, reg)
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers failed: %v", err)
			}

			if !denied {
				t.Fatal("expected SQLite authorizer fault injection to be triggered")
			}

			mgr.mu.Lock()
			deleted := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			// Assert: fail-closed invariant: zero deletions when backend inventory read fails
			if len(deleted) != 0 {
				t.Fatalf("expected 0 deletions on backend inventory query error, got %v", deleted)
			}
		})
	}
}

func TestReconciler_RemovesOrphanBackendActiveWithoutBackendTunnel(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:      "Naive-Orphan-Node",
		Host:      "10.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{"naive": map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, "naive"), true); err != nil {
		t.Fatalf("set legacy adopted: %v", err)
	}

	orphanClient := "orphan_backend_user_123"
	// Record lifecycle as backend_active with auto_provisioned ownership, but DO NOT create a backend_tunnels row
	past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	if err := db.RecordPeerLifecycle(ctx, sID, "naive", orphanClient, "orphan_backend", peerOwnershipAutoProvisioned, "backend_active"); err != nil {
		t.Fatalf("record lifecycle: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE peer_lifecycle SET created_at = ? WHERE server_id = ? AND client_id = ?", past, sID, orphanClient); err != nil {
		t.Fatalf("update created_at: %v", err)
	}

	old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
	mgr := &mockZombiePeerProtocolManager{
		proto: "naive",
		clients: []map[string]any{
			{"clientId": orphanClient, "username": orphanClient, "creationDate": old},
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

	// Assert: orphan backend_active client without backend_tunnels row was deleted
	if len(deleted) != 1 || deleted[0] != orphanClient {
		t.Fatalf("expected orphan client %q deleted, got %v", orphanClient, deleted)
	}

	// Verify lifecycle record was also deleted
	lifecycles, err := db.GetPeerLifecycles(ctx, sID, "naive")
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	if rec, exists := lifecycles[orphanClient]; exists {
		t.Fatalf("expected orphan lifecycle record deleted, got %+v", rec)
	}
}

// TestReconciler_PreservesOperatorSuppliedBackendCredentialsAfterBackendDeletion verifies
// that when a backend using operator-supplied credentials is deleted (backend_tunnels row removed),
// background reconciliation past the stale threshold NEVER revokes the remote credential.
func TestReconciler_PreservesOperatorSuppliedBackendCredentialsAfterBackendDeletion(t *testing.T) {
	for _, proto := range []string{models.ProtocolNaive, models.ProtocolVLESS} {
		t.Run(proto, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:      "Operator-Node-" + proto,
				Host:      "10.0.0.50",
				SSHPort:   22,
				Protocols: map[string]any{proto: map[string]any{"installed": true}},
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			// Mark legacy peers adopted so that unmanaged zombie peers would normally be deleted
			if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, proto), true); err != nil {
				t.Fatalf("set legacy adopted: %v", err)
			}

			operatorClientID := "operator_shared_user_99"
			if proto == models.ProtocolVLESS {
				operatorClientID = "e4f5a6b7-c8d9-4012-a345-6789abcdef01"
			}

			// Record lifecycle as backend_active with operator_supplied ownership
			// (simulating backend enable with operator-supplied credentials).
			past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
			if err := db.RecordPeerLifecycle(ctx, sID, proto, operatorClientID, "vpn-backend-1", peerOwnershipOperatorSupplied, "backend_active"); err != nil {
				t.Fatalf("record lifecycle: %v", err)
			}
			if _, err := db.ExecContext(ctx, "UPDATE peer_lifecycle SET created_at = ? WHERE server_id = ? AND client_id = ?", past, sID, operatorClientID); err != nil {
				t.Fatalf("update created_at: %v", err)
			}

			// Backend tunnel is permanently deleted: NO row exists in backend_tunnels table.
			old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
			mgr := &mockZombiePeerProtocolManager{
				proto: proto,
				clients: []map[string]any{
					{"clientId": operatorClientID, "username": operatorClientID, "creationDate": old},
				},
			}
			reg := newMockRegistry()
			reg.Register(mgr)

			r := New(db, reg)

			// First reconciliation cycle past stale threshold
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers (cycle 1) failed: %v", err)
			}

			mgr.mu.Lock()
			deleted := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			// Invariant: operator-supplied credential must NEVER be deleted from remote node
			if len(deleted) != 0 {
				t.Fatalf("expected 0 remote deletions for operator-supplied credential, got %v", deleted)
			}

			// Verify lifecycle record was preserved and reclassified to active
			lifecycles, err := db.GetPeerLifecycles(ctx, sID, proto)
			if err != nil {
				t.Fatalf("GetPeerLifecycles failed: %v", err)
			}
			rec, exists := lifecycles[operatorClientID]
			if !exists {
				t.Fatalf("expected lifecycle record preserved for operator client %s", operatorClientID)
			}
			if rec.Status != "active" {
				t.Fatalf("expected lifecycle status reclassified to 'active', got %q", rec.Status)
			}
			if rec.UserID != peerOwnershipOperatorSupplied {
				t.Fatalf("expected ownership preserved as %q, got %q", peerOwnershipOperatorSupplied, rec.UserID)
			}

			// Second reconciliation cycle: verify ongoing reconciliation with legacyAdopted=true
			// still does NOT delete the preserved operator-supplied credential
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers (cycle 2) failed: %v", err)
			}

			mgr.mu.Lock()
			deletedCycle2 := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			if len(deletedCycle2) != 0 {
				t.Fatalf("expected 0 remote deletions on subsequent cycle, got %v", deletedCycle2)
			}
		})
	}
}

func TestReconciler_PreservesUserAssociatedBackendCredentialsAfterBackendDeletion(t *testing.T) {
	for _, proto := range []string{models.ProtocolNaive, models.ProtocolVLESS} {
		t.Run(proto, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:      "User-Backend-Node-" + proto,
				Host:      "10.0.0.51",
				SSHPort:   22,
				Protocols: map[string]any{proto: map[string]any{"installed": true}},
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, proto), true); err != nil {
				t.Fatalf("set legacy adopted: %v", err)
			}

			sharedClientID := "user_shared_client_99"
			if proto == models.ProtocolVLESS {
				sharedClientID = "a1b2c3d4-e5f6-4789-abcd-0123456789ab"
			}
			userID := "user-uuid-persistent-777"

			// 1. Initial user lifecycle entry
			if err := db.RecordPeerLifecycle(ctx, sID, proto, sharedClientID, "User Device", userID, "active"); err != nil {
				t.Fatalf("record initial user peer lifecycle: %v", err)
			}

			// 2. Backend enrollment uses the same credential
			if err := db.RecordPeerLifecycle(ctx, sID, proto, sharedClientID, "vpn-backend-1", peerOwnershipOperatorSupplied, "backend_active"); err != nil {
				t.Fatalf("record backend proxy lifecycle: %v", err)
			}

			// Assert user_id was preserved and not overwritten by operator_supplied
			lifecycles, err := db.GetPeerLifecycles(ctx, sID, proto)
			if err != nil {
				t.Fatalf("get peer lifecycles: %v", err)
			}
			rec, exists := lifecycles[sharedClientID]
			if !exists {
				t.Fatalf("expected lifecycle record for %s", sharedClientID)
			}
			if rec.UserID != userID {
				t.Fatalf("expected user_id to be preserved as %q, got %q", userID, rec.UserID)
			}
			if rec.Status != "backend_active" {
				t.Fatalf("expected status 'backend_active', got %q", rec.Status)
			}

			// 3. Backend tunnel is deleted (no row in backend_tunnels) and record ages
			past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
			if _, err := db.ExecContext(ctx, "UPDATE peer_lifecycle SET created_at = ? WHERE server_id = ? AND client_id = ?", past, sID, sharedClientID); err != nil {
				t.Fatalf("update created_at: %v", err)
			}

			mgr := &mockZombiePeerProtocolManager{
				proto: proto,
				clients: []map[string]any{
					{"clientId": sharedClientID, "username": sharedClientID, "creationDate": past},
				},
			}
			reg := newMockRegistry()
			reg.Register(mgr)

			r := New(db, reg)

			// First reconciliation cycle
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers (cycle 1) failed: %v", err)
			}

			mgr.mu.Lock()
			deleted := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			if len(deleted) != 0 {
				t.Fatalf("expected 0 remote deletions for user-associated credential, got %v", deleted)
			}

			// Verify lifecycle record was preserved with original user_id
			lifecycles, err = db.GetPeerLifecycles(ctx, sID, proto)
			if err != nil {
				t.Fatalf("GetPeerLifecycles failed: %v", err)
			}
			rec, exists = lifecycles[sharedClientID]
			if !exists {
				t.Fatalf("expected lifecycle record preserved for %s", sharedClientID)
			}
			if rec.Status != "active" {
				t.Fatalf("expected status reclassified to 'active', got %q", rec.Status)
			}
			if rec.UserID != userID {
				t.Fatalf("expected user_id preserved as %q, got %q", userID, rec.UserID)
			}

			// Second reconciliation cycle
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers (cycle 2) failed: %v", err)
			}

			mgr.mu.Lock()
			deletedCycle2 := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			if len(deletedCycle2) != 0 {
				t.Fatalf("expected 0 remote deletions on subsequent cycle, got %v", deletedCycle2)
			}
		})
	}
}

func TestReconciler_OwnershipPersistenceFailure_PreservesExternallyManagedCredentials(t *testing.T) {
	for _, proto := range []string{models.ProtocolNaive, models.ProtocolVLESS} {
		t.Run(proto, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:      "Failed-Persistence-Node-" + proto,
				Host:      "10.0.0.52",
				SSHPort:   22,
				Protocols: map[string]any{proto: map[string]any{"installed": true}},
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, proto), true); err != nil {
				t.Fatalf("set legacy adopted: %v", err)
			}

			operatorClientID := "operator_persisted_fail_client"
			var paramsRaw []byte
			if proto == models.ProtocolVLESS {
				operatorClientID = "b2c3d4e5-f6a7-4890-bcde-123456789abc"
				paramsRaw, _ = json.Marshal(models.VLESSRealityParams{UUID: operatorClientID})
			} else {
				paramsRaw, _ = json.Marshal(models.NaiveProxyParams{Username: operatorClientID})
			}

			// Simulate failed ownership persistence:
			// The backend tunnel was created and disabled (fail-closed in handler),
			// but NO peer_lifecycle record exists.
			if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID:       sID,
				Protocol:       proto,
				ProtocolParams: paramsRaw,
				Enabled:        false,
				CreatedAt:      time.Now().Add(-10 * time.Minute),
			}); err != nil {
				t.Fatalf("create backend tunnel: %v", err)
			}

			past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
			mgr := &mockZombiePeerProtocolManager{
				proto: proto,
				clients: []map[string]any{
					{"clientId": operatorClientID, "username": operatorClientID, "creationDate": past},
				},
			}
			reg := newMockRegistry()
			reg.Register(mgr)

			r := New(db, reg)

			// First cycle: reconciler must preserve the externally managed client and adopt it
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers (cycle 1) failed: %v", err)
			}

			mgr.mu.Lock()
			deleted := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			if len(deleted) != 0 {
				t.Fatalf("expected 0 remote deletions when ownership persistence failed, got %v", deleted)
			}

			// Verify adopted into peer_lifecycle with operator ownership
			lifecycles, err := db.GetPeerLifecycles(ctx, sID, proto)
			if err != nil {
				t.Fatalf("GetPeerLifecycles failed: %v", err)
			}
			rec, exists := lifecycles[operatorClientID]
			if !exists {
				t.Fatalf("expected client %s to be adopted into peer_lifecycle", operatorClientID)
			}
			if rec.UserID != peerOwnershipOperatorSupplied {
				t.Fatalf("expected adopted ownership %q, got %q", peerOwnershipOperatorSupplied, rec.UserID)
			}

			// Second cycle: still preserved
			if err := r.CleanupZombiePeers(ctx); err != nil {
				t.Fatalf("CleanupZombiePeers (cycle 2) failed: %v", err)
			}

			mgr.mu.Lock()
			deletedCycle2 := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			if len(deletedCycle2) != 0 {
				t.Fatalf("expected 0 remote deletions on subsequent cycle, got %v", deletedCycle2)
			}
		})
	}
}

type mockInterleavedZombieManager struct {
	proto      string
	clients    []map[string]any
	removeHook func(clientID string)
	deleted    []string
	mu         sync.Mutex
}

func (m *mockInterleavedZombieManager) Protocol() string { return m.proto }
func (m *mockInterleavedZombieManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	return nil
}
func (m *mockInterleavedZombieManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}
func (m *mockInterleavedZombieManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clients, nil
}
func (m *mockInterleavedZombieManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return nil, nil
}
func (m *mockInterleavedZombieManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	if m.removeHook != nil {
		m.removeHook(clientID)
	}
	m.mu.Lock()
	m.deleted = append(m.deleted, clientID)
	m.mu.Unlock()
	return nil
}
func (m *mockInterleavedZombieManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "", nil
}
func (m *mockInterleavedZombieManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{"container_exists": true}, nil
}

func TestReconciler_InterleavedDeletionPreservation_RefreshesLifecycle(t *testing.T) {
	for _, proto := range []string{models.ProtocolNaive, models.ProtocolVLESS} {
		t.Run(proto, func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:      "Interleaved-Node-" + proto,
				Host:      "10.0.0.53",
				SSHPort:   22,
				Protocols: map[string]any{proto: map[string]any{"installed": true}},
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			if err := db.SetSetting(ctx, legacyPeersAdoptedSettingKey(sID, proto), true); err != nil {
				t.Fatalf("set legacy adopted: %v", err)
			}

			operatorClientID := "operator_interleaved_client"
			var paramsRaw []byte
			if proto == models.ProtocolVLESS {
				operatorClientID = "c3d4e5f6-a7b8-4901-cdef-23456789abcd"
				paramsRaw, _ = json.Marshal(models.VLESSRealityParams{UUID: operatorClientID})
			} else {
				paramsRaw, _ = json.Marshal(models.NaiveProxyParams{Username: operatorClientID})
			}

			// Create a disabled backend tunnel (simulating failed/disabled backend without lifecycle record)
			tunID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID:       sID,
				Protocol:       proto,
				ProtocolParams: paramsRaw,
				Enabled:        false,
				CreatedAt:      time.Now().Add(-10 * time.Minute),
			})
			if err != nil {
				t.Fatalf("create backend tunnel: %v", err)
			}

			past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
			unrelatedZombie := "unrelated_zombie_" + proto

			started := make(chan struct{})
			resume := make(chan struct{})
			var once sync.Once

			mgr := &mockInterleavedZombieManager{
				proto: proto,
				clients: []map[string]any{
					{"clientId": unrelatedZombie, "username": unrelatedZombie, "creationDate": past},
					{"clientId": operatorClientID, "username": operatorClientID, "creationDate": past},
				},
				removeHook: func(clientID string) {
					if clientID == unrelatedZombie {
						once.Do(func() { close(started) })
						select {
						case <-resume:
						case <-time.After(5 * time.Second):
						}
					}
				},
			}
			reg := newMockRegistry()
			reg.Register(mgr)

			r := New(db, reg)

			cleanupErrCh := make(chan error, 1)
			go func() {
				cleanupErrCh <- r.CleanupZombiePeers(ctx)
			}()

			// Wait until reconciler has taken the lifecycle snapshot and is removing the unrelated zombie
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for reconciler to start removing unrelated zombie")
			}

			// Interleaved deletion: commit preservation record and delete backend tunnel
			if err := db.RecordPeerLifecycle(ctx, sID, proto, operatorClientID, "vpn-backend-1", peerOwnershipOperatorSupplied, "active"); err != nil {
				t.Fatalf("failed to record peer lifecycle: %v", err)
			}
			if err := db.DeleteBackendTunnel(ctx, tunID); err != nil {
				t.Fatalf("failed to delete backend tunnel: %v", err)
			}

			// Resume reconciler so it reaches the operator client
			close(resume)

			select {
			case err := <-cleanupErrCh:
				if err != nil {
					t.Fatalf("CleanupZombiePeers failed: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for CleanupZombiePeers to finish")
			}

			mgr.mu.Lock()
			deleted := append([]string(nil), mgr.deleted...)
			mgr.mu.Unlock()

			// Verify: unrelated zombie was removed, but operator client was NOT removed
			for _, id := range deleted {
				if id == operatorClientID {
					t.Fatalf("operator credential %s was revoked despite interleaved active/operator preservation commit", operatorClientID)
				}
			}
			if len(deleted) != 1 || deleted[0] != unrelatedZombie {
				t.Fatalf("expected exactly [unrelatedZombie] deleted, got %v", deleted)
			}

			// Verify lifecycle record remains intact in SQLite
			lifecycles, err := db.GetPeerLifecycles(ctx, sID, proto)
			if err != nil {
				t.Fatalf("GetPeerLifecycles failed: %v", err)
			}
			rec, exists := lifecycles[operatorClientID]
			if !exists {
				t.Fatalf("expected lifecycle record for %s to exist", operatorClientID)
			}
			if rec.Status != "active" || rec.UserID != peerOwnershipOperatorSupplied {
				t.Fatalf("expected active/operator_supplied, got status=%q user_id=%q", rec.Status, rec.UserID)
			}
		})
	}
}

func TestReconciler_WithdrawDisabledOwnerConns_PreservesSharedBackendCredential(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Naive-Shared", Host: "10.0.0.1", Protocols: map[string]any{"naive": map[string]any{"installed": true}}})
	sharedUser := "shared_naive_client"
	naiveParams, _ := json.Marshal(models.NaiveProxyParams{Username: sharedUser, Password: "p", Domain: "d.example"})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{ServerID: sID, Protocol: models.ProtocolNaive, ProtocolParams: naiveParams, Enabled: true, Status: models.TunnelStatusActive})
	_, _ = db.CreateUser(ctx, &models.User{ID: "u-dis", Username: "dis", Enabled: false})
	_, _ = db.CreateConnection(ctx, &models.UserConnection{ID: "c-dis", UserID: "u-dis", ServerID: sID, Protocol: models.ProtocolNaive, ClientID: sharedUser})
	_ = db.RecordPeerLifecycle(ctx, sID, models.ProtocolNaive, sharedUser, "Shared", "u-dis", "active")

	mgr := &mockZombiePeerProtocolManager{proto: "naive", clients: []map[string]any{{"clientId": sharedUser}}}
	reg := newMockRegistry()
	reg.Register(mgr)

	if err := New(db, reg).CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers: %v", err)
	}

	mgr.mu.Lock()
	del := len(mgr.deleted)
	mgr.mu.Unlock()
	if del > 0 {
		t.Fatalf("expected 0 remote removals, got %d", del)
	}
	if conn, _ := db.GetConnection(ctx, "c-dis"); conn == nil {
		t.Fatal("shared connection must remain for credential rotation")
	}
	lifecycles, _ := db.GetPeerLifecycles(ctx, sID, models.ProtocolNaive)
	if rec := lifecycles[sharedUser]; rec.UserID != "u-dis" {
		t.Fatalf("shared credential must retain ownership, got %+v", rec)
	}
}
