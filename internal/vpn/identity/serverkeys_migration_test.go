package identity

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func setupTestDB(tb testing.TB) *database.DB {
	tb.Helper()
	dir := tb.TempDir()
	dbPath := filepath.Join(dir, "test_vpn_identity.db")
	db, err := database.Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		tb.Fatalf("failed to open test db: %v", err)
	}
	tb.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func TestServerKeysRecoverLegacyPlaintextAndRejectCorruptIdentity(t *testing.T) {
	for _, scenario := range []string{"plaintext", "encrypted", "mismatch", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			db := setupTestDB(t)
			ctx := t.Context()
			priv, pub, err := generateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			privB64 := base64.StdEncoding.EncodeToString(priv[:])
			pubB64 := base64.StdEncoding.EncodeToString(pub[:])
			stored := privB64
			if scenario == "encrypted" {
				stored, err = security.EncryptCredential(privB64, db.SecretKey())
				if err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "mismatch" {
				pubB64 = base64.StdEncoding.EncodeToString(make([]byte, 32))
			}
			if scenario == "corrupt" {
				stored = "invalid-key"
			}
			// Simulate rows written by older versions; bypass the new save boundary.
			encoded, err := json.Marshal(&models.VPNConfig{
				ServerPrivateKey: stored, ServerPublicKey: pubB64,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx,
				"INSERT INTO settings (key, value) VALUES ('vpn_config', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(encoded)); err != nil {
				t.Fatal(err)
			}
			gotPriv, gotPub, err := NewServerKeysManager(db).EnsureKeypair(ctx)
			if scenario == "mismatch" || scenario == "corrupt" {
				if err == nil {
					t.Fatal("startup silently rotated a broken portal identity")
				}
				cfg, readErr := db.GetVPNConfig(ctx)
				if readErr != nil || cfg.ServerPrivateKey != stored {
					t.Fatalf("broken key was overwritten: %v", readErr)
				}
				return
			}
			if err != nil || gotPriv != priv || gotPub != pub {
				t.Fatalf("stored identity not recovered: %v", err)
			}
			cfg, err := db.GetVPNConfig(ctx)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := security.DecryptCredential(cfg.ServerPrivateKey, db.SecretKey())
			if err != nil || plain != privB64 || cfg.ServerPublicKey != pubB64 {
				t.Fatalf("identity not encrypted and preserved: %v", err)
			}
		})
	}
}
