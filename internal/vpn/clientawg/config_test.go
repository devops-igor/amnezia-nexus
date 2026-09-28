package clientawg

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// seedVPNConfigRaw writes a vpn_config row exactly as given, bypassing the
// settings API guard: SetSetting routes the vpn_config key through
// SaveVPNConfig, which validates the portal identity and round-trips
// models.VPNConfig, dropping the clientawg-only random_trailers and
// disable_cookies fields. Legacy pre-guard databases and backup restores
// hand the loader rows in exactly this raw shape, so the loader tests must
// be able to persist one. Corrupt fixtures are expected to fail LOADER
// validation; any error here is a test setup failure.
func seedVPNConfigRaw(t *testing.T, db *database.DB, value map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal vpn_config fixture: %v", err)
	}
	if _, err := db.SQLDB().Exec(
		"INSERT INTO settings (key, value) VALUES ('vpn_config', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		string(encoded),
	); err != nil {
		t.Fatalf("seed raw vpn_config row: %v", err)
	}
}

func TestLoadConfigPreservesSnapshotAndDecryptsIdentity(t *testing.T) {
	const secret = "loader-test-secret"
	db, err := database.Open(filepath.Join(t.TempDir(), "panel.db"), secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := testConfig()
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy plaintext", true: "encrypted"}[encrypted], func(t *testing.T) {
			private := cfg.PrivateKey
			if encrypted {
				private, err = security.EncryptCredential(private, secret)
				if err != nil {
					t.Fatal(err)
				}
			}
			stored := map[string]any{"server_private_key": private, "server_public_key": cfg.PublicKey, "listen_port": 12345, "h1": "100-110", "h2": "200-210", "h3": "300-310", "h4": "400-410", "s1": 12, "s2": 13, "s3": 14, "s4": 15, "header_protection_key": cfg.PrivateKey, "content_padding_addition": "true", "random_trailers": true, "disable_cookies": true}
			seedVPNConfigRaw(t, db, stored)
			before, _, err := db.GetSettingRaw(t.Context(), "vpn_config")
			if err != nil {
				t.Fatal(err)
			}
			got, err := LoadConfig(t.Context(), db, cfg.TUN, cfg.Peers)
			if err != nil {
				t.Fatal(err)
			}
			after, _, err := db.GetSettingRaw(t.Context(), "vpn_config")
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("loader modified persisted snapshot")
			}
			if got.PrivateKey != cfg.PrivateKey || got.PublicKey != cfg.PublicKey || got.ListenPort != 12345 || got.Parameters.H1 != "100-110" || got.Parameters.S4 != 15 || got.Parameters.HeaderProtectionKey != cfg.PrivateKey || got.Parameters.ContentPaddingAddition != "16-64" || !got.Parameters.RandomTrailers || !got.Parameters.DisableCookies {
				t.Fatal("loader changed effective identity/parameters")
			}
			got.Peers[0].PublicKey = "changed"
			if cfg.Peers[0].PublicKey == "changed" {
				t.Fatal("loader did not isolate caller slice")
			}
		})
	}
}

func TestLoadConfigDefaultsAbsentFlagsToFalse(t *testing.T) {
	cfg := testConfig()
	db, err := database.Open(filepath.Join(t.TempDir(), "panel.db"), "secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stored := map[string]any{"server_private_key": cfg.PrivateKey, "server_public_key": cfg.PublicKey, "listen_port": 1234, "h1": 1, "h2": 2, "h3": 3, "h4": 4}
	seedVPNConfigRaw(t, db, stored)
	got, err := LoadConfig(t.Context(), db, cfg.TUN, cfg.Peers)
	if err != nil {
		t.Fatal(err)
	}
	if got.Parameters.RandomTrailers || got.Parameters.DisableCookies {
		t.Fatal("absent or null flags must load as false")
	}
}

func TestLoadConfigRejectsIncompleteSnapshotWithoutWrites(t *testing.T) {
	cfg := testConfig()
	tests := map[string]func(map[string]any){
		"missing identity":           func(m map[string]any) { delete(m, "server_private_key") },
		"corrupt encrypted identity": func(m map[string]any) { m["server_private_key"] = "secret-invalid-token" },
		"mismatched identity":        func(m map[string]any) { _, m["server_public_key"] = testKeys(57) },
		"missing port":               func(m map[string]any) { delete(m, "listen_port") },
		"missing headers":            func(m map[string]any) { delete(m, "h1"); delete(m, "h2"); delete(m, "h3"); delete(m, "h4") },
		"malformed cookie flag":      func(m map[string]any) { m["disable_cookies"] = "secret-invalid-boolean" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			db, err := database.Open(filepath.Join(t.TempDir(), "panel.db"), "secret")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			stored := map[string]any{"server_private_key": cfg.PrivateKey, "server_public_key": cfg.PublicKey, "listen_port": 1234, "h1": 1, "h2": 2, "h3": 3, "h4": 4}
			change(stored)
			seedVPNConfigRaw(t, db, stored)
			before, _, err := db.GetSettingRaw(t.Context(), "vpn_config")
			if err != nil {
				t.Fatal(err)
			}
			_, err = LoadConfig(t.Context(), db, cfg.TUN, cfg.Peers)
			if err == nil {
				t.Fatal("incomplete snapshot accepted")
			}
			if strings.Contains(err.Error(), "secret-") || strings.Contains(err.Error(), cfg.PrivateKey) {
				t.Fatal("loader error exposed secret")
			}
			after, _, err := db.GetSettingRaw(t.Context(), "vpn_config")
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("failed loader modified database")
			}
		})
	}
}

func TestDatagramCapacityValidation(t *testing.T) {
	cfg := testConfig()
	cfg.TUN.MTU = 65507 - device.MinMessageSize - (device.PaddingMultiple - 1)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.TUN.MTU++
	if err := cfg.validate(); err == nil {
		t.Fatal("MTU overflowing datagram accepted")
	}
	cfg = testConfig()
	cfg.Parameters.S4 = 65507 - cfg.TUN.MTU - device.MinMessageSize - (device.PaddingMultiple - 1)
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Parameters.S4++
	if err := cfg.validate(); err == nil {
		t.Fatal("S4 overflowing datagram accepted")
	}
	for _, set := range []func(*Config){func(c *Config) { c.Parameters.S1 = 65507 - device.MessageInitiationSize + 1 }, func(c *Config) { c.Parameters.S2 = 65507 - device.MessageResponseSize + 1 }, func(c *Config) { c.Parameters.S3 = 65507 - device.MessageCookieReplySize + 1 }, func(c *Config) { c.Parameters.ContentPaddingAddition = "65000-65535" }} {
		cfg = testConfig()
		set(&cfg)
		if err := cfg.validate(); err == nil {
			t.Fatal("datagram overflow accepted")
		}
	}
}

func TestConfigSerializationOmitsSecrets(t *testing.T) {
	cfg := testConfig()
	cfg.Parameters.HeaderProtectionKey = "secret-hp"
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), cfg.PrivateKey) || strings.Contains(string(encoded), "secret-hp") {
		t.Fatal("config JSON exposes secret")
	}
}
