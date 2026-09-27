package vpn

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func TestPortalKeySurvivesConfigUpdateAndDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.db")
	const secret = "test-secret-key-1234567890123456"
	db, err := database.Open(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "portal-restart", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(issued, "PublicKey = "+before.ServerPublicKey) {
		t.Fatal("issued config does not pin the portal public key")
	}
	crafted := *before
	crafted.ServerPrivateKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := svc.UpdateConfig(ctx, &crafted); err == nil {
		t.Fatal("service accepted a replacement portal private key")
	}
	updated := *before
	updated.PublicEndpoint = "vpn.example.test"
	if err := svc.UpdateConfig(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := security.DecryptCredential(stored.ServerPrivateKey, secret)
	if err != nil {
		t.Fatalf("portal key stored unencrypted: %v", err)
	}
	if raw, err := base64.StdEncoding.DecodeString(decoded); err != nil || len(raw) != 32 {
		t.Fatal("stored portal key is not a valid private key")
	}
	if err := svc.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = database.Open(path, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	restarted, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Stop()
	got, err := restarted.GetConfig(ctx)
	if err != nil || got.ServerPublicKey != before.ServerPublicKey {
		t.Fatalf("portal identity changed after restart: %v", err)
	}
	reissued, _, err := restarted.GenerateClientConfig(ctx, userID)
	if err != nil || !strings.Contains(reissued, "PublicKey = "+before.ServerPublicKey) {
		t.Fatalf("previously issued client's pinned portal key changed: %v", err)
	}
}
