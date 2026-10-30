package reconciliation

import (
	"context"
	"encoding/json"
	"fmt"
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
