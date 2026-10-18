package vpn

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestEnforceMinSValues(t *testing.T) {
	tests := []struct {
		name        string
		input       *models.VPNConfig
		wantChanged bool
		wantS1      int
		wantS2      int
		wantS3      int
		wantS4      int
	}{
		{
			name: "all zero values bumped to 12",
			input: &models.VPNConfig{
				S1: 0, S2: 0, S3: 0, S4: 0,
			},
			wantChanged: true,
			wantS1:      12,
			wantS2:      12,
			wantS3:      12,
			wantS4:      12,
		},
		{
			name: "negative and below 12 values bumped to 12",
			input: &models.VPNConfig{
				S1: -5, S2: 1, S3: 11, S4: 0,
			},
			wantChanged: true,
			wantS1:      12,
			wantS2:      12,
			wantS3:      12,
			wantS4:      12,
		},
		{
			name: "all >= 12 unchanged",
			input: &models.VPNConfig{
				S1: 12, S2: 50, S3: 20, S4: 15,
			},
			wantChanged: false,
			wantS1:      12,
			wantS2:      50,
			wantS3:      20,
			wantS4:      15,
		},
		{
			name: "only S1 below 12",
			input: &models.VPNConfig{
				S1: 10, S2: 15, S3: 20, S4: 25,
			},
			wantChanged: true,
			wantS1:      12,
			wantS2:      15,
			wantS3:      20,
			wantS4:      25,
		},
		{
			name: "only S2 below 12",
			input: &models.VPNConfig{
				S1: 15, S2: 8, S3: 20, S4: 25,
			},
			wantChanged: true,
			wantS1:      15,
			wantS2:      12,
			wantS3:      20,
			wantS4:      25,
		},
		{
			name: "only S3 below 12",
			input: &models.VPNConfig{
				S1: 15, S2: 20, S3: 5, S4: 25,
			},
			wantChanged: true,
			wantS1:      15,
			wantS2:      20,
			wantS3:      12,
			wantS4:      25,
		},
		{
			name: "only S4 below 12",
			input: &models.VPNConfig{
				S1: 15, S2: 20, S3: 25, S4: 11,
			},
			wantChanged: true,
			wantS1:      15,
			wantS2:      20,
			wantS3:      25,
			wantS4:      12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := enforceMinSValues(tt.input)
			if changed != tt.wantChanged {
				t.Errorf("enforceMinSValues() changed = %v, wantChanged %v", changed, tt.wantChanged)
			}
			if tt.input.S1 != tt.wantS1 || tt.input.S2 != tt.wantS2 || tt.input.S3 != tt.wantS3 || tt.input.S4 != tt.wantS4 {
				t.Errorf("got S values (%d, %d, %d, %d), want (%d, %d, %d, %d)",
					tt.input.S1, tt.input.S2, tt.input.S3, tt.input.S4,
					tt.wantS1, tt.wantS2, tt.wantS3, tt.wantS4)
			}
		})
	}
}

func makeCompleteTestConfig() *models.VPNConfig {
	return &models.VPNConfig{
		H1:                  models.NewHeaderRange(1000000, 1005000),
		H2:                  models.NewHeaderRange(600000000, 600005000),
		H3:                  models.NewHeaderRange(1200000000, 1200005000),
		H4:                  models.NewHeaderRange(1800000000, 1800005000),
		S1:                  50,
		S2:                  70,
		S3:                  20,
		S4:                  15,
		HeaderProtectionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
}

func TestIsObfuscationConfigComplete(t *testing.T) {
	t.Run("nil config returns true", func(t *testing.T) {
		if !isObfuscationConfigComplete(nil) {
			t.Error("expected nil config to return true")
		}
	})

	t.Run("valid complete config returns true", func(t *testing.T) {
		cfg := makeCompleteTestConfig()
		if !isObfuscationConfigComplete(cfg) {
			t.Error("expected valid complete config to return true")
		}
	})

	t.Run("missing HeaderProtectionKey returns false", func(t *testing.T) {
		cfg := makeCompleteTestConfig()
		cfg.HeaderProtectionKey = ""
		if isObfuscationConfigComplete(cfg) {
			t.Error("expected empty HeaderProtectionKey to return false")
		}
	})

	sTests := []struct {
		name string
		mod  func(*models.VPNConfig)
	}{
		{"S1 < 12", func(c *models.VPNConfig) { c.S1 = 11 }},
		{"S2 < 12", func(c *models.VPNConfig) { c.S2 = 0 }},
		{"S3 < 12", func(c *models.VPNConfig) { c.S3 = -1 }},
		{"S4 < 12", func(c *models.VPNConfig) { c.S4 = 5 }},
	}
	for _, st := range sTests {
		t.Run(st.name, func(t *testing.T) {
			cfg := makeCompleteTestConfig()
			st.mod(cfg)
			if isObfuscationConfigComplete(cfg) {
				t.Errorf("expected %s to return false", st.name)
			}
		})
	}

	hTests := []struct {
		name string
		mod  func(*models.VPNConfig)
	}{
		{"H1 degenerate", func(c *models.VPNConfig) { c.H1 = models.NewHeaderRange(1000, 1000) }},
		{"H2 span < 1000", func(c *models.VPNConfig) { c.H2 = models.NewHeaderRange(600000000, 600000500) }},
		{"H3 zero", func(c *models.VPNConfig) { c.H3 = models.HeaderRange{} }},
		{"H4 overlaps with H2", func(c *models.VPNConfig) {
			// Overlap with H2 [600000000, 600005000]
			c.H4 = models.NewHeaderRange(600002000, 600007000)
		}},
	}
	for _, ht := range hTests {
		t.Run(ht.name, func(t *testing.T) {
			cfg := makeCompleteTestConfig()
			ht.mod(cfg)
			if isObfuscationConfigComplete(cfg) {
				t.Errorf("expected %s to return false", ht.name)
			}
		})
	}
}

func TestGenerateMissingObfuscation(t *testing.T) {
	t.Run("upgrades degenerate headers to span >= 1000 and sets default S values", func(t *testing.T) {
		cfg := &models.VPNConfig{
			H1: models.NewHeaderRange(1000000, 1000000),
			H2: models.NewHeaderRange(600000000, 600000000),
			H3: models.NewHeaderRange(1200000000, 1200000000),
			H4: models.NewHeaderRange(1800000000, 1800000000),
		}

		generated, err := generateMissingObfuscation(cfg)
		if err != nil {
			t.Fatalf("generateMissingObfuscation failed: %v", err)
		}
		if !generated {
			t.Fatal("expected generated to be true")
		}

		headers := []models.HeaderRange{cfg.H1, cfg.H2, cfg.H3, cfg.H4}
		for i, h := range headers {
			if awg.NeedsHeaderUpgrade(h) {
				t.Errorf("H%d = %v still needs upgrade", i+1, h)
			}
			span := h.Hi - h.Lo
			if span < 1000 {
				t.Errorf("H%d span %d < 1000", i+1, span)
			}
		}

		if err := awg.ValidateQuadrantDisjointness(cfg.H1, cfg.H2, cfg.H3, cfg.H4); err != nil {
			t.Errorf("ValidateQuadrantDisjointness failed after upgrade: %v", err)
		}

		if cfg.S1 != 50 || cfg.S2 != 70 || cfg.S3 != 20 || cfg.S4 != 15 {
			t.Errorf("expected S values (50, 70, 20, 15), got (%d, %d, %d, %d)",
				cfg.S1, cfg.S2, cfg.S3, cfg.S4)
		}

		if cfg.HeaderProtectionKey == "" {
			t.Error("expected HeaderProtectionKey to be generated")
		}
		decoded, err := base64.StdEncoding.DecodeString(cfg.HeaderProtectionKey)
		if err != nil || len(decoded) != 32 {
			t.Errorf("expected 32-byte base64 HeaderProtectionKey, got %q (err: %v)", cfg.HeaderProtectionKey, err)
		}
	})

	t.Run("all zero fields generate standard obfuscation", func(t *testing.T) {
		cfg := &models.VPNConfig{}
		generated, err := generateMissingObfuscation(cfg)
		if err != nil {
			t.Fatalf("generateMissingObfuscation failed: %v", err)
		}
		if !generated {
			t.Fatal("expected generated to be true")
		}

		headers := []models.HeaderRange{cfg.H1, cfg.H2, cfg.H3, cfg.H4}
		for i, h := range headers {
			if h.IsZero() || awg.NeedsHeaderUpgrade(h) {
				t.Errorf("H%d = %v invalid or needs upgrade", i+1, h)
			}
			if h.Hi-h.Lo < 1000 {
				t.Errorf("H%d span %d < 1000", i+1, h.Hi-h.Lo)
			}
		}

		if cfg.S1 < 12 || cfg.S2 < 12 || cfg.S3 < 12 || cfg.S4 < 12 {
			t.Errorf("expected S values >= 12, got (%d, %d, %d, %d)", cfg.S1, cfg.S2, cfg.S3, cfg.S4)
		}
		if cfg.HeaderProtectionKey == "" {
			t.Error("expected HeaderProtectionKey to be generated")
		}
	})

	t.Run("complete config produces no changes", func(t *testing.T) {
		cfg := makeCompleteTestConfig()
		orig := *cfg
		generated, err := generateMissingObfuscation(cfg)
		if err != nil {
			t.Fatalf("generateMissingObfuscation failed: %v", err)
		}
		if generated {
			t.Error("expected generated to be false for complete config")
		}
		if !reflect.DeepEqual(cfg, &orig) {
			t.Errorf("config changed unexpectedly: got %+v, want %+v", cfg, orig)
		}
	})
}

func TestPreserveObfuscationParams(t *testing.T) {
	t.Run("copies all unset fields from source to destination", func(t *testing.T) {
		from := makeCompleteTestConfig()
		from.ContentPaddingAddition = "5-10"

		to := &models.VPNConfig{}
		preserveObfuscationParams(from, to)

		if to.H1 != from.H1 || to.H2 != from.H2 || to.H3 != from.H3 || to.H4 != from.H4 {
			t.Errorf("H values not preserved: got %+v, want %+v", to, from)
		}
		if to.S1 != from.S1 || to.S2 != from.S2 || to.S3 != from.S3 || to.S4 != from.S4 {
			t.Errorf("S values not preserved: got %+v, want %+v", to, from)
		}
		if to.HeaderProtectionKey != from.HeaderProtectionKey {
			t.Errorf("HeaderProtectionKey not preserved: got %q, want %q", to.HeaderProtectionKey, from.HeaderProtectionKey)
		}
		if to.ContentPaddingAddition != from.ContentPaddingAddition {
			t.Errorf("ContentPaddingAddition not preserved: got %q, want %q", to.ContentPaddingAddition, from.ContentPaddingAddition)
		}
	})

	t.Run("does not overwrite already existing fields in destination", func(t *testing.T) {
		from := makeCompleteTestConfig()
		from.ContentPaddingAddition = "5-10"

		to := &models.VPNConfig{
			H1:                     models.NewHeaderRange(2000000, 2005000),
			H2:                     models.NewHeaderRange(700000000, 700005000),
			H3:                     models.NewHeaderRange(1300000000, 1300005000),
			H4:                     models.NewHeaderRange(1900000000, 1900005000),
			S1:                     99,
			S2:                     88,
			S3:                     77,
			S4:                     66,
			HeaderProtectionKey:    "ZXhpc3RpbmdrZXlleGlzdGluZ2tleWV4aXN0aW5na2V5MSE=",
			ContentPaddingAddition: "20-30",
		}
		origTo := *to

		preserveObfuscationParams(from, to)

		if !reflect.DeepEqual(to, &origTo) {
			t.Errorf("existing destination fields were overwritten: got %+v, want %+v", to, origTo)
		}
	})

	t.Run("partial preservation only fills unset fields", func(t *testing.T) {
		from := makeCompleteTestConfig()
		from.ContentPaddingAddition = "5-10"

		to := &models.VPNConfig{
			H1: models.NewHeaderRange(2000000, 2005000),
			S1: 99,
		}

		preserveObfuscationParams(from, to)

		// H1 and S1 should be kept from 'to'
		if to.H1 != models.NewHeaderRange(2000000, 2005000) || to.S1 != 99 {
			t.Errorf("existing H1/S1 in to were modified: H1=%v, S1=%d", to.H1, to.S1)
		}
		// H2..H4, S2..S4, HPK, CPA should be filled from 'from'
		if to.H2 != from.H2 || to.H3 != from.H3 || to.H4 != from.H4 {
			t.Errorf("H2..H4 were not copied from source: got %+v", to)
		}
		if to.S2 != from.S2 || to.S3 != from.S3 || to.S4 != from.S4 {
			t.Errorf("S2..S4 were not copied from source: got %+v", to)
		}
		if to.HeaderProtectionKey != from.HeaderProtectionKey {
			t.Errorf("HeaderProtectionKey not copied: got %q, want %q", to.HeaderProtectionKey, from.HeaderProtectionKey)
		}
		if to.ContentPaddingAddition != from.ContentPaddingAddition {
			t.Errorf("ContentPaddingAddition not copied: got %q, want %q", to.ContentPaddingAddition, from.ContentPaddingAddition)
		}
	})
}

func TestObfuscationDiffers(t *testing.T) {
	base := makeCompleteTestConfig()
	base.ContentPaddingAddition = "10-20"

	tests := []struct {
		name        string
		modify      func(c *models.VPNConfig)
		wantDiffers bool
	}{
		{
			name:        "identical configs do not differ",
			modify:      func(c *models.VPNConfig) {},
			wantDiffers: false,
		},
		{
			name: "non-obfuscation fields differ does not trigger obfuscation diff",
			modify: func(c *models.VPNConfig) {
				c.ListenPort = 55555
				c.SubnetCIDR = "192.168.0.0/24"
				c.Algorithm = models.LBWeighted
				c.HealthThresholdMS = 999
				c.MaxTotalPeers = 2000
				c.MaxPeersPerBackend = 500
				c.ClientQueueSize = 100
				c.ServerPrivateKey = "priv"
				c.ServerPublicKey = "pub"
			},
			wantDiffers: false,
		},
		{
			name: "H1 differs",
			modify: func(c *models.VPNConfig) {
				c.H1 = models.NewHeaderRange(2000000, 2005000)
			},
			wantDiffers: true,
		},
		{
			name: "H2 differs",
			modify: func(c *models.VPNConfig) {
				c.H2 = models.NewHeaderRange(700000000, 700005000)
			},
			wantDiffers: true,
		},
		{
			name: "H3 differs",
			modify: func(c *models.VPNConfig) {
				c.H3 = models.NewHeaderRange(1300000000, 1300005000)
			},
			wantDiffers: true,
		},
		{
			name: "H4 differs",
			modify: func(c *models.VPNConfig) {
				c.H4 = models.NewHeaderRange(1900000000, 1900005000)
			},
			wantDiffers: true,
		},
		{
			name: "S1 differs",
			modify: func(c *models.VPNConfig) {
				c.S1 = 99
			},
			wantDiffers: true,
		},
		{
			name: "S2 differs",
			modify: func(c *models.VPNConfig) {
				c.S2 = 99
			},
			wantDiffers: true,
		},
		{
			name: "S3 differs",
			modify: func(c *models.VPNConfig) {
				c.S3 = 99
			},
			wantDiffers: true,
		},
		{
			name: "S4 differs",
			modify: func(c *models.VPNConfig) {
				c.S4 = 99
			},
			wantDiffers: true,
		},
		{
			name: "HeaderProtectionKey differs",
			modify: func(c *models.VPNConfig) {
				c.HeaderProtectionKey = "YW5vdGhlcmtleWFub3RoZXJrZXlhbm90aGVya2V5ISE="
			},
			wantDiffers: true,
		},
		{
			name: "ContentPaddingAddition differs",
			modify: func(c *models.VPNConfig) {
				c.ContentPaddingAddition = "30-40"
			},
			wantDiffers: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := *base
			tt.modify(&other)
			differs := obfuscationDiffers(base, &other)
			if differs != tt.wantDiffers {
				t.Errorf("obfuscationDiffers() = %v, want %v", differs, tt.wantDiffers)
			}
		})
	}
}

func TestDefaultVPNConfig_And_ApplyVPNConfigDefaults(t *testing.T) {
	t.Run("defaultVPNConfig returns expected defaults", func(t *testing.T) {
		cfg := defaultVPNConfig()
		if cfg.Algorithm != models.LBLeastConnections {
			t.Errorf("Algorithm = %q, want %q", cfg.Algorithm, models.LBLeastConnections)
		}
		if cfg.ListenPort != 51820 {
			t.Errorf("ListenPort = %d, want 51820", cfg.ListenPort)
		}
		if cfg.SubnetCIDR != "10.100.0.0/16" {
			t.Errorf("SubnetCIDR = %q, want 10.100.0.0/16", cfg.SubnetCIDR)
		}
		if cfg.HealthThresholdMS != 500 {
			t.Errorf("HealthThresholdMS = %d, want 500", cfg.HealthThresholdMS)
		}
		if cfg.MaxTotalPeers != 1000 {
			t.Errorf("MaxTotalPeers = %d, want 1000", cfg.MaxTotalPeers)
		}
		if cfg.MaxPeersPerBackend != 250 {
			t.Errorf("MaxPeersPerBackend = %d, want 250", cfg.MaxPeersPerBackend)
		}
		if cfg.Weights == nil {
			t.Error("expected non-nil Weights map")
		}
	})

	t.Run("applyVPNConfigDefaults fills zero/empty fields", func(t *testing.T) {
		cfg := &models.VPNConfig{}
		applyVPNConfigDefaults(cfg)

		if cfg.Algorithm != models.LBLeastConnections {
			t.Errorf("Algorithm = %q, want %q", cfg.Algorithm, models.LBLeastConnections)
		}
		if cfg.ListenPort != 51820 {
			t.Errorf("ListenPort = %d, want 51820", cfg.ListenPort)
		}
		if cfg.SubnetCIDR != "10.100.0.0/16" {
			t.Errorf("SubnetCIDR = %q, want 10.100.0.0/16", cfg.SubnetCIDR)
		}
		if cfg.HealthThresholdMS != 500 {
			t.Errorf("HealthThresholdMS = %d, want 500", cfg.HealthThresholdMS)
		}
		if cfg.MaxTotalPeers != 1000 {
			t.Errorf("MaxTotalPeers = %d, want 1000", cfg.MaxTotalPeers)
		}
		if cfg.MaxPeersPerBackend != 250 {
			t.Errorf("MaxPeersPerBackend = %d, want 250", cfg.MaxPeersPerBackend)
		}
		if cfg.Weights == nil {
			t.Error("expected non-nil Weights map")
		}
	})

	t.Run("applyVPNConfigDefaults clamps ClientQueueSize if exceeds max", func(t *testing.T) {
		cfg := &models.VPNConfig{
			MaxTotalPeers:   100,
			ClientQueueSize: 999999,
		}
		applyVPNConfigDefaults(cfg)
		maxQueue := forwarder.MaxClientQueuePacketsForRoutes(100)
		if cfg.ClientQueueSize != maxQueue {
			t.Errorf("ClientQueueSize = %d, want clamped %d", cfg.ClientQueueSize, maxQueue)
		}
	})

	t.Run("applyVPNConfigDefaults preserves valid non-zero values", func(t *testing.T) {
		cfg := &models.VPNConfig{
			Algorithm:          models.LBWeighted,
			ListenPort:         55555,
			SubnetCIDR:         "192.168.1.0/24",
			HealthThresholdMS:  1000,
			MaxTotalPeers:      500,
			MaxPeersPerBackend: 100,
			Weights:            map[int64]int{1: 10},
		}
		applyVPNConfigDefaults(cfg)

		if cfg.Algorithm != models.LBWeighted || cfg.ListenPort != 55555 ||
			cfg.SubnetCIDR != "192.168.1.0/24" || cfg.HealthThresholdMS != 1000 ||
			cfg.MaxTotalPeers != 500 || cfg.MaxPeersPerBackend != 100 ||
			cfg.Weights[1] != 10 {
			t.Errorf("valid values were overwritten: %+v", cfg)
		}
	})
}

func TestGeneratePortalHeaderProtectionKey(t *testing.T) {
	key1, err := generatePortalHeaderProtectionKey()
	if err != nil {
		t.Fatalf("generatePortalHeaderProtectionKey failed: %v", err)
	}
	raw1, err := base64.StdEncoding.DecodeString(key1)
	if err != nil {
		t.Fatalf("key1 is not valid base64: %v", err)
	}
	if len(raw1) != 32 {
		t.Fatalf("key1 decoded length = %d, want 32", len(raw1))
	}

	key2, err := generatePortalHeaderProtectionKey()
	if err != nil {
		t.Fatalf("generatePortalHeaderProtectionKey failed: %v", err)
	}
	if key1 == key2 {
		t.Fatalf("expected distinct random keys, got identical: %q", key1)
	}
}
