package vpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// obfuscationMigrationMu serializes first-read obfuscation migration
// across concurrent NewVPNService calls so racing first starts converge
// on one persisted parameter set instead of divergent ephemeral values
// that would desync the listener from rendered client configs.
var obfuscationMigrationMu sync.Mutex

// generatePortalHeaderProtectionKey generates a cryptographically random
// 32-byte header protection key encoded in base64.
func generatePortalHeaderProtectionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random header protection key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// enforceMinSValues ensures all AWG junk packet sizes meet the minimum of 12.
func enforceMinSValues(cfg *models.VPNConfig) bool {
	var changed bool
	if cfg.S1 < 12 {
		cfg.S1 = 12
		changed = true
	}
	if cfg.S2 < 12 {
		cfg.S2 = 12
		changed = true
	}
	if cfg.S3 < 12 {
		cfg.S3 = 12
		changed = true
	}
	if cfg.S4 < 12 {
		cfg.S4 = 12
		changed = true
	}
	return changed
}

func isObfuscationConfigComplete(cfg *models.VPNConfig) bool {
	if cfg == nil {
		return true
	}
	if cfg.HeaderProtectionKey == "" {
		return false
	}
	if cfg.S1 < 12 || cfg.S2 < 12 || cfg.S3 < 12 || cfg.S4 < 12 {
		return false
	}
	if awg.NeedsHeaderUpgrade(cfg.H1) || awg.NeedsHeaderUpgrade(cfg.H2) ||
		awg.NeedsHeaderUpgrade(cfg.H3) || awg.NeedsHeaderUpgrade(cfg.H4) {
		return false
	}
	if err := awg.ValidateQuadrantDisjointness(cfg.H1, cfg.H2, cfg.H3, cfg.H4); err != nil {
		return false
	}
	return true
}

func generateMissingObfuscation(cfg *models.VPNConfig) (bool, error) {
	var generated bool
	if cfg.H1.IsZero() && cfg.H2.IsZero() && cfg.H3.IsZero() && cfg.H4.IsZero() {
		h1, h2, h3, h4, s1, s2, s3, s4, err := awg.GenerateStandardObfuscationValues()
		if err != nil {
			return false, fmt.Errorf("failed to generate obfuscation params: %w", err)
		}
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = h1, h2, h3, h4
		cfg.S1, cfg.S2, cfg.S3, cfg.S4 = s1, s2, s3, s4
		generated = true
	} else if awg.NeedsHeaderUpgrade(cfg.H1) || awg.NeedsHeaderUpgrade(cfg.H2) ||
		awg.NeedsHeaderUpgrade(cfg.H3) || awg.NeedsHeaderUpgrade(cfg.H4) ||
		awg.ValidateQuadrantDisjointness(cfg.H1, cfg.H2, cfg.H3, cfg.H4) != nil {
		h1, h2, h3, h4, upgraded, err := awg.UpgradeDegenerateHeaders(cfg.H1, cfg.H2, cfg.H3, cfg.H4)
		if err != nil {
			return false, fmt.Errorf("failed to upgrade obfuscation headers: %w", err)
		}
		if upgraded {
			cfg.H1, cfg.H2, cfg.H3, cfg.H4 = h1, h2, h3, h4
			generated = true
		}
		if cfg.S1 == 0 && cfg.S2 == 0 && cfg.S3 == 0 && cfg.S4 == 0 {
			cfg.S1, cfg.S2, cfg.S3, cfg.S4 = 50, 70, 20, 15
			generated = true
		}
	}
	if cfg.HeaderProtectionKey == "" {
		hpk, err := generatePortalHeaderProtectionKey()
		if err != nil {
			return false, err
		}
		cfg.HeaderProtectionKey = hpk
		generated = true
	}
	return generated, nil
}

// ensureObfuscationParams migrates a VPNConfig that lacks AWG obfuscation
// values, contains legacy degenerate headers (lo == hi), or lacks HeaderProtectionKey.
// Checks the DB first under a mutex — a concurrent first start may have already
// persisted parameters, and the persisted values win over any in-memory guess — generates
// standard-profile parameters and portal HeaderProtectionKey when still unset,
// upgrades degenerate headers to ranges with span >= 1000, and persists them synchronously.
// Persistence failures are returned so startup fails loudly instead of running with
// divergent ephemeral values. The ListenPort is propagated through every save branch (R3):
// the migration must never persist a zeroed listen_port, which GetVPNConfig's
// fill-down would re-default to the default port and desync the running listener
// from rendered client configs. Ports <= 0 fall back to 51820.
func ensureObfuscationParams(ctx context.Context, db *database.DB, cfg *models.VPNConfig) error {
	if cfg == nil {
		return nil
	}
	// If all obfuscation parameters (header ranges, min S values, and HeaderProtectionKey)
	// are already valid and complete, nothing to migrate.
	if isObfuscationConfigComplete(cfg) {
		return nil
	}

	if db == nil {
		if _, err := generateMissingObfuscation(cfg); err != nil {
			return err
		}
		enforceMinSValues(cfg)
		return nil
	}

	obfuscationMigrationMu.Lock()
	defer obfuscationMigrationMu.Unlock()

	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to read persisted VPN config for obfuscation migration: %w", err)
	}
	if persisted != nil {
		if isObfuscationConfigComplete(persisted) {
			cfg.H1, cfg.H2, cfg.H3, cfg.H4 = persisted.H1, persisted.H2, persisted.H3, persisted.H4
			cfg.S1, cfg.S2, cfg.S3, cfg.S4 = persisted.S1, persisted.S2, persisted.S3, persisted.S4
			cfg.HeaderProtectionKey = persisted.HeaderProtectionKey
			return nil
		}
		if !persisted.H1.IsZero() && cfg.H1.IsZero() {
			cfg.H1, cfg.H2, cfg.H3, cfg.H4 = persisted.H1, persisted.H2, persisted.H3, persisted.H4
			cfg.S1, cfg.S2, cfg.S3, cfg.S4 = persisted.S1, persisted.S2, persisted.S3, persisted.S4
		}
		if persisted.HeaderProtectionKey != "" && cfg.HeaderProtectionKey == "" {
			cfg.HeaderProtectionKey = persisted.HeaderProtectionKey
		}
	}

	if isObfuscationConfigComplete(cfg) {
		return nil
	}

	needsSave, err := generateMissingObfuscation(cfg)
	if err != nil {
		return err
	}
	if enforceMinSValues(cfg) {
		needsSave = true
	}

	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}

	if needsSave {
		target := persisted
		if target == nil {
			target = cfg
		} else {
			target.H1, target.H2, target.H3, target.H4 = cfg.H1, cfg.H2, cfg.H3, cfg.H4
			target.S1, target.S2, target.S3, target.S4 = cfg.S1, cfg.S2, cfg.S3, cfg.S4
			target.HeaderProtectionKey = cfg.HeaderProtectionKey
			// R3: propagate the caller's (already validated) listen port so the
			// migration save cannot zero out a previously wired port.
			target.ListenPort = cfg.ListenPort
		}
		if err := db.SaveVPNConfig(ctx, target); err != nil {
			return fmt.Errorf("failed to persist obfuscation params: %w", err)
		}
	}
	return nil
}

// preserveObfuscationParams copies unset (zero) AWG obfuscation fields
// from the current config into an incoming config so partial updates
// cannot clobber the parameters already distributed to peers.
func preserveObfuscationParams(from, to *models.VPNConfig) {
	if to.H1.IsZero() {
		to.H1 = from.H1
	}
	if to.H2.IsZero() {
		to.H2 = from.H2
	}
	if to.H3.IsZero() {
		to.H3 = from.H3
	}
	if to.H4.IsZero() {
		to.H4 = from.H4
	}
	if to.S1 == 0 {
		to.S1 = from.S1
	}
	if to.S2 == 0 {
		to.S2 = from.S2
	}
	if to.S3 == 0 {
		to.S3 = from.S3
	}
	if to.S4 == 0 {
		to.S4 = from.S4
	}
	if to.HeaderProtectionKey == "" {
		to.HeaderProtectionKey = from.HeaderProtectionKey
	}
	if to.ContentPaddingAddition == "" {
		to.ContentPaddingAddition = from.ContentPaddingAddition
	}
}

// obfuscationDiffers reports whether two configs disagree on any AWG
// obfuscation parameter.
func obfuscationDiffers(a, b *models.VPNConfig) bool {
	return a.H1 != b.H1 || a.H2 != b.H2 || a.H3 != b.H3 || a.H4 != b.H4 ||
		a.S1 != b.S1 || a.S2 != b.S2 || a.S3 != b.S3 || a.S4 != b.S4 ||
		a.HeaderProtectionKey != b.HeaderProtectionKey || a.ContentPaddingAddition != b.ContentPaddingAddition
}

func defaultVPNConfig() *models.VPNConfig {
	return &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            make(map[int64]int),
	}
}

func applyVPNConfigDefaults(cfg *models.VPNConfig) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = models.LBLeastConnections
	}
	if cfg.ListenPort <= 0 {
		cfg.ListenPort = 51820
	}
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = "10.100.0.0/16"
	}
	if cfg.HealthThresholdMS <= 0 {
		cfg.HealthThresholdMS = 500
	}
	if cfg.MaxTotalPeers <= 0 {
		cfg.MaxTotalPeers = 1000
	}
	if cfg.MaxPeersPerBackend <= 0 {
		cfg.MaxPeersPerBackend = 250
	}
	if cfg.ClientQueueSize > 0 {
		maxQueue := forwarder.MaxClientQueuePacketsForRoutes(cfg.MaxTotalPeers)
		if cfg.ClientQueueSize > maxQueue {
			cfg.ClientQueueSize = maxQueue
		}
	}
	if cfg.Weights == nil {
		cfg.Weights = make(map[int64]int)
	}
}
