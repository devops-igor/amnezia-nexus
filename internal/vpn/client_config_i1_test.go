package vpn

import (
	"context"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestPortalI1ProtocolSwitchAndGenerationFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.VPNDataPlaneI1Protocol = "dns"
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetVPNConfig(ctx)
	if err != nil || loaded.VPNDataPlaneI1Protocol != "dns" {
		t.Fatalf("DNS setting not persisted: %+v, %v", loaded, err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "dns-i1-user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	config, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if i1 := parseDirectiveString(t, config, "I1"); !strings.HasPrefix(i1, "<r 2><b 0x") {
		t.Fatalf("expected DNS I1, got %q", i1)
	}
	config2, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil || config2 != config {
		t.Fatalf("DNS refetch not stable: %v", err)
	}
	cfg.VPNDataPlaneI1Protocol = "sip"
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	config3, _, err := svc.GenerateClientConfig(ctx, userID)
	if err != nil || config3 != config {
		t.Fatalf("existing connection changed after protocol switch: %v", err)
	}
	cfg.VPNDataPlaneI1Protocol = "quic"
	if err := svc.UpdateConfig(ctx, cfg); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
	if err := db.SaveVPNConfig(ctx, cfg); err == nil {
		t.Fatal("unsupported protocol persisted")
	}
	otherID, err := db.CreateUser(ctx, &models.User{Username: "cancelled-i1-user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := svc.GenerateClientConfig(cancelled, otherID); err == nil {
		t.Fatal("cancelled generation succeeded")
	}
	if _, err := resolvePortalI1(cancelled, cfg, map[string]any{}); err == nil {
		t.Fatal("cancelled I1 generation succeeded")
	}
	cfg.VPNDataPlaneI1Protocol = "sip"
	if _, err := resolvePortalI1(ctx, cfg, map[string]any{"portal_i1": 42}); err == nil {
		t.Fatal("invalid persisted I1 accepted")
	}
}
