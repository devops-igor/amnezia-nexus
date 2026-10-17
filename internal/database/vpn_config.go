package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	"golang.org/x/crypto/curve25519"
)

// GetVPNConfig retrieves the load balancing and VPN configuration from settings.
func (d *DB) GetVPNConfig(ctx context.Context) (*models.VPNConfig, error) {
	val, found, err := d.GetSettingRaw(ctx, "vpn_config")
	if err != nil {
		return nil, err
	}

	var cfg models.VPNConfig
	if !found {
		fillVPNConfigDefaults(&cfg)
		return &cfg, nil
	}

	if !val.Valid {
		return nil, fmt.Errorf("persisted vpn_config setting is SQL NULL")
	}
	trimmed := strings.TrimSpace(val.String)
	if trimmed == "" {
		return nil, fmt.Errorf("persisted vpn_config setting is empty")
	}
	if trimmed == "null" {
		return nil, fmt.Errorf("persisted vpn_config setting is JSON null")
	}

	if err := json.Unmarshal([]byte(val.String), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse vpn_config JSON: %w", err)
	}

	fillVPNConfigDefaults(&cfg)
	// Obfuscation-parameter migration (generating H/S when unset and
	// persisting them) intentionally does NOT happen here: the database
	// package must not own obfuscation-parameter derivation. NewVPNService
	// in internal/vpn owns the migration so a single component derives,
	// persists, and distributes the parameters to listener and clients.
	return &cfg, nil
}

func fillVPNConfigDefaults(cfg *models.VPNConfig) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = models.LBLeastConnections
	}
	if cfg.MinRebalanceSessions <= 0 {
		cfg.MinRebalanceSessions = 8
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = "10.100.0.0/16"
	}
	if cfg.HealthThresholdMS == 0 {
		cfg.HealthThresholdMS = 500
	}
	if cfg.MaxTotalPeers == 0 {
		cfg.MaxTotalPeers = 1000
	}
	if cfg.MaxPeersPerBackend == 0 {
		cfg.MaxPeersPerBackend = 250
	}
	if cfg.AffinityTTLMinutes <= 0 {
		cfg.AffinityTTLMinutes = 30
	}
	if cfg.Weights == nil {
		cfg.Weights = make(map[int64]int)
	}
}

// SaveVPNConfig persists the VPN configuration to the settings table.
func (d *DB) saveVPNConfig(ctx context.Context, cfg *models.VPNConfig) error {
	if cfg == nil {
		return errors.New("vpn config is nil")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	// The settings serializer does not encrypt vpn_config. Normalize a copy
	// here so no caller can accidentally persist the live endpoint secret.
	stored, err := d.GetVPNConfig(ctx)
	if err != nil {
		return err
	}
	if stored.ServerPrivateKey == "" && stored.ServerPublicKey != "" {
		return errors.New("stored portal public key has no private key")
	}
	copy := *cfg
	if copy.ServerPrivateKey == "" && stored.ServerPrivateKey != "" {
		copy.ServerPrivateKey = stored.ServerPrivateKey
		copy.ServerPublicKey = stored.ServerPublicKey
	}
	if copy.ServerPrivateKey != "" {
		plain, err := security.DecryptCredential(copy.ServerPrivateKey, d.secretKey)
		if err != nil {
			// Older config updates wrote the raw base64 private key to the
			// setting. Only recover a valid key matching its recorded public key.
			plain = copy.ServerPrivateKey
		}
		raw, err := base64.StdEncoding.DecodeString(plain)
		if err != nil || len(raw) != 32 {
			return errors.New("invalid portal private key in vpn config")
		}
		public, err := curve25519.X25519(raw, curve25519.Basepoint)
		if err != nil {
			return fmt.Errorf("invalid portal private key in vpn config: %w", err)
		}
		derived := base64.StdEncoding.EncodeToString(public)
		if copy.ServerPublicKey != "" && copy.ServerPublicKey != derived {
			return errors.New("portal private key does not match stored public key")
		}
		if stored.ServerPrivateKey != "" && stored.ServerPublicKey != "" && stored.ServerPublicKey != derived {
			return errors.New("portal identity cannot be changed by vpn config save")
		}
		copy.ServerPublicKey = derived
		if plain == copy.ServerPrivateKey {
			// A plaintext legacy row must have a matching stored public key.
			if stored.ServerPrivateKey == copy.ServerPrivateKey && stored.ServerPublicKey != derived {
				return errors.New("plaintext portal key does not match stored public key")
			}
			copy.ServerPrivateKey, err = security.EncryptCredential(plain, d.secretKey)
			if err != nil {
				return fmt.Errorf("encrypt portal private key: %w", err)
			}
		}
	} else if copy.ServerPublicKey != "" {
		return errors.New("portal public key has no private key")
	}
	encoded, err := json.Marshal(&copy)
	if err != nil {
		return fmt.Errorf("marshal vpn config: %w", err)
	}
	_, err = d.sqlDB.ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES ('vpn_config', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		string(encoded),
	)
	if err != nil {
		return fmt.Errorf("persist vpn config: %w", err)
	}
	return nil
}
