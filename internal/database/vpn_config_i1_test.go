package database

import (
	"context"
	"strings"
	"testing"
)

func TestVPNConfigI1ProtocolValidationOnLoad(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	cfg, err := db.GetVPNConfig(ctx)
	if err != nil || cfg.DataPlaneI1Protocol() != "sip" {
		t.Fatalf("default protocol: %+v, %v", cfg, err)
	}
	if _, err := db.sqlDB.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES ('vpn_config', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		`{"vpn_data_plane_i1_protocol":"quic"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetVPNConfig(ctx); err == nil || !strings.Contains(err.Error(), "invalid vpn_data_plane_i1_protocol") {
		t.Fatalf("expected invalid stored protocol error, got %v", err)
	}
}
