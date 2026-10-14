package vpn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestUpdateConfig_PreservesObfuscationParams(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	baseCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		HealthThresholdMS:   500,
		ListenPort:          51820,
		SubnetCIDR:          "10.100.0.0/16",
		MaxTotalPeers:       500,
		MaxPeersPerBackend:  100,
		Weights:             map[int64]int{},
		H1:                  models.NewHeaderRange(111111, 115000),
		H2:                  models.NewHeaderRange(600000000, 600005000),
		H3:                  models.NewHeaderRange(1200000000, 1200005000),
		H4:                  models.NewHeaderRange(1800000000, 1800005000),
		S1:                  40,
		S2:                  50,
		S3:                  30,
		S4:                  20,
		HeaderProtectionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Startup generates a real identity; a partial update must preserve it.
	seedCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if seedCfg.ServerPrivateKey == "" || seedCfg.ServerPublicKey == "" {
		t.Fatalf("expected NewVPNService to establish portal identity, got: %+v", seedCfg)
	}

	// Partial update: payload omits H/S (all zero) and identity fields.
	partial := &models.VPNConfig{
		Algorithm:          models.LBWeighted,
		HealthThresholdMS:  600,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		MaxTotalPeers:      800,
		MaxPeersPerBackend: 200,
		Weights:            map[int64]int{},
	}
	if err := svc.UpdateConfig(ctx, partial); err != nil {
		t.Fatalf("UpdateConfig with partial cfg failed: %v", err)
	}

	// s.cfg must retain the stored H/S and identity.
	svcCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if svcCfg.H1 != models.NewHeaderRange(111111, 115000) || svcCfg.H2 != models.NewHeaderRange(600000000, 600005000) || svcCfg.H3 != models.NewHeaderRange(1200000000, 1200005000) || svcCfg.H4 != models.NewHeaderRange(1800000000, 1800005000) {
		t.Errorf("service cfg H values clobbered by partial update: %+v", svcCfg)
	}
	if svcCfg.S1 != 40 || svcCfg.S2 != 50 || svcCfg.S3 != 30 || svcCfg.S4 != 20 {
		t.Errorf("service cfg S values clobbered by partial update: %+v", svcCfg)
	}
	if svcCfg.ServerPrivateKey != seedCfg.ServerPrivateKey || svcCfg.ServerPublicKey != seedCfg.ServerPublicKey {
		t.Errorf("service cfg identity clobbered by partial update: %+v", svcCfg)
	}

	// Stored config must retain them too.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.H1 != models.NewHeaderRange(111111, 115000) || stored.H2 != models.NewHeaderRange(600000000, 600005000) || stored.H3 != models.NewHeaderRange(1200000000, 1200005000) || stored.H4 != models.NewHeaderRange(1800000000, 1800005000) {
		t.Errorf("stored H values clobbered by partial update: %+v", stored)
	}
	if stored.S1 != 40 || stored.S2 != 50 || stored.S3 != 30 || stored.S4 != 20 {
		t.Errorf("stored S values clobbered by partial update: %+v", stored)
	}
	if stored.ServerPrivateKey != seedCfg.ServerPrivateKey || stored.ServerPublicKey != seedCfg.ServerPublicKey {
		t.Errorf("stored portal identity clobbered by partial update: priv=%q pub=%q", stored.ServerPrivateKey, stored.ServerPublicKey)
	}

}

func TestUpdateConfig_RejectsObfuscationChangeWhileRunning(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	before, _ := svc.GetConfig(ctx)

	changed := *before
	changed.H1 = models.DegenerateHeaderRange(987654321)
	changed.S1 = 77
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("expected error when changing obfuscation params while listener runs")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected immutability error, got: %v", err)
	}

	after, _ := svc.GetConfig(ctx)
	if after.H1 != before.H1 {
		t.Errorf("running config was mutated by rejected update: H1 %s -> %s", before.H1, after.H1)
	}
}

func TestUpdateConfig_PropagatesObfuscationChangeWhenIdle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	before, _ := svc.GetConfig(ctx)

	changed := *before
	changed.H1 = models.DegenerateHeaderRange(123456789)
	changed.H2 = models.DegenerateHeaderRange(234567891)
	changed.H3 = models.DegenerateHeaderRange(345678912)
	changed.H4 = models.DegenerateHeaderRange(456789123)
	changed.S1 = 33
	changed.S2 = 44
	changed.S3 = 55
	changed.S4 = 66
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig with changed H/S on idle service failed: %v", err)
	}

	after, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if after.H1 != models.DegenerateHeaderRange(123456789) || after.H2 != models.DegenerateHeaderRange(234567891) || after.H3 != models.DegenerateHeaderRange(345678912) || after.H4 != models.DegenerateHeaderRange(456789123) {
		t.Errorf("service config not updated on idle service: %+v", after)
	}
	if after.S1 != 33 || after.S2 != 44 || after.S3 != 55 || after.S4 != 66 {
		t.Errorf("service S params not updated on idle service: %+v", after)
	}
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.H1 != after.H1 || stored.S1 != after.S1 {
		t.Errorf("persisted config not updated: %+v", stored)
	}
}

// --- Issue #18 R3: obfuscation migration must preserve listen_port ---

// TestEnsureObfuscationParams_PreservesLegacyListenPort verifies directly that
// the legacy-row migration (zero H1..H4/S1..S4) keeps an already-wired
// listen_port instead of zeroing it (which GetVPNConfig's fill-down would
// re-default, desyncing the running listener from rendered client configs).
func TestEnsureObfuscationParams_PreservesLegacyListenPort(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Legacy row: obfuscation params zero, listen port already wired.
	legacy := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         31458,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            map[int64]int{},
		// H1..H4 / S1..S4 deliberately zero -> triggers the migration.
	}
	if err := db.SaveVPNConfig(ctx, legacy); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	if err := ensureObfuscationParams(ctx, db, legacy); err != nil {
		t.Fatalf("ensureObfuscationParams failed: %v", err)
	}

	if legacy.ListenPort != 31458 {
		t.Errorf("migration must preserve in-memory listen_port, got %d", legacy.ListenPort)
	}
	if legacy.H1.IsZero() || legacy.H2.IsZero() || legacy.H3.IsZero() || legacy.H4.IsZero() {
		t.Errorf("migration did not fill H params: %+v", legacy)
	}
	if legacy.S1 < 0 || legacy.S2 < 0 || legacy.S3 < 0 || legacy.S4 < 0 {
		t.Errorf("migration produced invalid S params: %+v", legacy)
	}

	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != 31458 {
		t.Errorf("persisted listen_port: want 31458, got %d", stored.ListenPort)
	}
	if stored.H1.IsZero() {
		t.Errorf("persisted config missing migrated obfuscation params: %+v", stored)
	}
}

func TestEnsureObfuscationParams_HeaderProtectionKeyMigration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Legacy config with H1..H4 already populated with degenerate headers (DEV environment scenario),
	// but HeaderProtectionKey is empty and S values are < 12.
	legacy := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          31458,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       1000,
		MaxPeersPerBackend:  250,
		Weights:             map[int64]int{},
		H1:                  models.DegenerateHeaderRange(359398951),
		H2:                  models.DegenerateHeaderRange(944086617),
		H3:                  models.DegenerateHeaderRange(1418011628),
		H4:                  models.DegenerateHeaderRange(1749149601),
		S1:                  5,
		S2:                  7,
		S3:                  9,
		S4:                  11,
		HeaderProtectionKey: "",
	}
	if err := db.SaveVPNConfig(ctx, legacy); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	if err := ensureObfuscationParams(ctx, db, legacy); err != nil {
		t.Fatalf("ensureObfuscationParams failed: %v", err)
	}

	if legacy.HeaderProtectionKey == "" {
		t.Fatalf("expected HeaderProtectionKey to be generated, got empty string")
	}
	rawKey, err := health.DecodeKey(legacy.HeaderProtectionKey)
	if err != nil || len(rawKey) != 32 {
		t.Fatalf("generated HeaderProtectionKey is not valid 32-byte key: %v", err)
	}

	// Floor constraint S1..S4 >= 12 must be enforced
	if legacy.S1 < 12 || legacy.S2 < 12 || legacy.S3 < 12 || legacy.S4 < 12 {
		t.Errorf("expected S1..S4 >= 12, got S1=%d S2=%d S3=%d S4=%d", legacy.S1, legacy.S2, legacy.S3, legacy.S4)
	}
	// Degenerate headers must be upgraded to ranges (span >= 1000) containing the legacy values
	if legacy.H1.IsDegenerate() || legacy.H1.Hi-legacy.H1.Lo < 1000 || !legacy.H1.Contains(359398951) {
		t.Errorf("H1 not cleanly upgraded to range containing 359398951: %s", legacy.H1.String())
	}
	if legacy.H2.IsDegenerate() || legacy.H2.Hi-legacy.H2.Lo < 1000 || !legacy.H2.Contains(944086617) {
		t.Errorf("H2 not cleanly upgraded to range containing 944086617: %s", legacy.H2.String())
	}
	if legacy.H3.IsDegenerate() || legacy.H3.Hi-legacy.H3.Lo < 1000 || !legacy.H3.Contains(1418011628) {
		t.Errorf("H3 not cleanly upgraded to range containing 1418011628: %s", legacy.H3.String())
	}
	if legacy.H4.IsDegenerate() || legacy.H4.Hi-legacy.H4.Lo < 1000 || !legacy.H4.Contains(1749149601) {
		t.Errorf("H4 not cleanly upgraded to range containing 1749149601: %s", legacy.H4.String())
	}
	if err := awg.ValidateQuadrantDisjointness(legacy.H1, legacy.H2, legacy.H3, legacy.H4); err != nil {
		t.Errorf("upgraded header ranges are not disjoint: %v", err)
	}

	// Verify persistence in DB
	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.HeaderProtectionKey != legacy.HeaderProtectionKey {
		t.Errorf("persisted HeaderProtectionKey mismatch: got %q, want %q", persisted.HeaderProtectionKey, legacy.HeaderProtectionKey)
	}
	if persisted.S1 < 12 || persisted.S2 < 12 || persisted.S3 < 12 || persisted.S4 < 12 {
		t.Errorf("persisted S1..S4 < 12: %+v", persisted)
	}
	if persisted.H1 != legacy.H1 || persisted.H2 != legacy.H2 || persisted.H3 != legacy.H3 || persisted.H4 != legacy.H4 {
		t.Errorf("persisted H values do not match upgraded ranges: %+v", persisted)
	}
}

func TestUpdateConfig_EnforcesMinSValues(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	baseCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		HealthThresholdMS:   500,
		ListenPort:          51820,
		SubnetCIDR:          "10.100.0.0/16",
		MaxTotalPeers:       500,
		MaxPeersPerBackend:  100,
		Weights:             map[int64]int{},
		H1:                  models.NewHeaderRange(111111, 115000),
		H2:                  models.NewHeaderRange(600000000, 600005000),
		H3:                  models.NewHeaderRange(1200000000, 1200005000),
		H4:                  models.NewHeaderRange(1800000000, 1800005000),
		S1:                  40,
		S2:                  50,
		S3:                  30,
		S4:                  20,
		HeaderProtectionKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Partial update with a small NON-ZERO S3: preserveObfuscationParams
	// only fills zero fields, so without enforceMinSValues this would reach
	// the listener with HP key set and S3 < 12 (impossible-state bug).
	update := &models.VPNConfig{
		Algorithm:          models.LBRoundRobin,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
		S3:                 4,
	}
	if err := svc.UpdateConfig(ctx, update); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if update.S3 < 12 {
		t.Errorf("expected S3 clamped to >= 12, got %d", update.S3)
	}
	// Preserved fields must remain.
	if update.H1 != models.NewHeaderRange(111111, 115000) || update.S1 != 40 {
		t.Errorf("expected preserved H1/S1, got H1=%s S1=%d", update.H1, update.S1)
	}
	if update.HeaderProtectionKey == "" {
		t.Error("expected HeaderProtectionKey preserved on partial update")
	}
}

func TestEnsureObfuscationParams_DegenerateToRangeUpgrade(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Seed legacy database with DEV environment single values and pre-existing HeaderProtectionKey
	legacyH1 := uint32(359398951)
	legacyH2 := uint32(944086617)
	legacyH3 := uint32(1418011628)
	legacyH4 := uint32(1749149601)
	existingHPKey := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()

	legacyCfg := &models.VPNConfig{
		Algorithm:           models.LBLeastConnections,
		ListenPort:          port,
		SubnetCIDR:          "10.100.0.0/16",
		HealthThresholdMS:   500,
		MaxTotalPeers:       1000,
		MaxPeersPerBackend:  250,
		Weights:             map[int64]int{},
		H1:                  models.DegenerateHeaderRange(legacyH1),
		H2:                  models.DegenerateHeaderRange(legacyH2),
		H3:                  models.DegenerateHeaderRange(legacyH3),
		H4:                  models.DegenerateHeaderRange(legacyH4),
		S1:                  45,
		S2:                  60,
		S3:                  25,
		S4:                  15,
		HeaderProtectionKey: existingHPKey,
	}
	if err := db.SaveVPNConfig(ctx, legacyCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Test Backend",
		Host: "127.0.0.1",
		Protocols: map[string]any{
			"awg": map[string]any{
				"public_key": "backend-pubkey-123456789012345678",
				"port":       51821,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "backend-pubkey-123456789012345678",
		PrivateKey:    "backend-privkey-12345678901234567",
		Endpoint:      "127.0.0.1:51821",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	// Starting NewVPNService runs ensureObfuscationParams
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	upgradedCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	// 1. Assert headers are upgraded to ranges with span >= 1000
	for idx, tc := range []struct {
		rng models.HeaderRange
		val uint32
		q   int
	}{
		{upgradedCfg.H1, legacyH1, 0},
		{upgradedCfg.H2, legacyH2, 1},
		{upgradedCfg.H3, legacyH3, 2},
		{upgradedCfg.H4, legacyH4, 3},
	} {
		if tc.rng.IsDegenerate() {
			t.Errorf("H%d remained degenerate: %s", idx+1, tc.rng)
		}
		if tc.rng.Hi-tc.rng.Lo < 1000 {
			t.Errorf("H%d span < 1000: %s (span=%d)", idx+1, tc.rng, tc.rng.Hi-tc.rng.Lo)
		}
		// Invariant: original legacy single value MUST be contained within the upgraded range
		if !tc.rng.Contains(tc.val) {
			t.Errorf("H%d range %s does not contain legacy value %d", idx+1, tc.rng, tc.val)
		}
		qLo, qHi := awg.QuadrantBounds(tc.q)
		if tc.rng.Lo < qLo || tc.rng.Hi > qHi {
			t.Errorf("H%d range %s outside quadrant %d [%d, %d]", idx+1, tc.rng, tc.q, qLo, qHi)
		}
	}

	// 2. Assert pairwise disjointness
	if err := awg.ValidateQuadrantDisjointness(upgradedCfg.H1, upgradedCfg.H2, upgradedCfg.H3, upgradedCfg.H4); err != nil {
		t.Fatalf("upgraded ranges are not pairwise disjoint: %v", err)
	}

	// 3. Assert upgraded config is persisted to SQLite DB
	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.H1 != upgradedCfg.H1 || persisted.H2 != upgradedCfg.H2 ||
		persisted.H3 != upgradedCfg.H3 || persisted.H4 != upgradedCfg.H4 {
		t.Errorf("persisted config differs from in-memory upgraded config: %+v vs %+v", persisted, upgradedCfg)
	}
	if persisted.H1.IsDegenerate() || persisted.H1.Hi-persisted.H1.Lo < 1000 {
		t.Errorf("persisted H1 is not upgraded range: %s", persisted.H1)
	}

	// 4. Assert GenerateClientConfig emits range strings "lo-hi" for H1-H4
	uID, err := db.CreateUser(ctx, &models.User{Username: "legacy_user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	expectedH1 := fmt.Sprintf("H1 = %d-%d", upgradedCfg.H1.Lo, upgradedCfg.H1.Hi)
	expectedH2 := fmt.Sprintf("H2 = %d-%d", upgradedCfg.H2.Lo, upgradedCfg.H2.Hi)
	expectedH3 := fmt.Sprintf("H3 = %d-%d", upgradedCfg.H3.Lo, upgradedCfg.H3.Hi)
	expectedH4 := fmt.Sprintf("H4 = %d-%d", upgradedCfg.H4.Lo, upgradedCfg.H4.Hi)

	if !strings.Contains(cfgStr, expectedH1) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH1, cfgStr)
	}
	if !strings.Contains(cfgStr, expectedH2) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH2, cfgStr)
	}
	if !strings.Contains(cfgStr, expectedH3) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH3, cfgStr)
	}
	if !strings.Contains(cfgStr, expectedH4) {
		t.Errorf("client config missing range %q, got config:\n%s", expectedH4, cfgStr)
	}

	// Must NOT contain single values
	singleH1 := fmt.Sprintf("H1 = %d\n", legacyH1)
	if strings.Contains(cfgStr, singleH1) {
		t.Errorf("client config emitted single value %q instead of range", singleH1)
	}
}

func TestEnsureObfuscationParams_ReadFailureAbortsWithoutWrite(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	const malformedJSON = "{invalid-json"
	if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', ?)", malformedJSON); err != nil {
		t.Fatalf("failed to insert malformed vpn_config: %v", err)
	}

	cfg := defaultVPNConfig()
	err := ensureObfuscationParams(ctx, db, cfg)
	if err == nil {
		t.Fatal("expected ensureObfuscationParams to fail on unreadable setting")
	}
	if !strings.Contains(err.Error(), "failed to read persisted VPN config for obfuscation migration") {
		t.Fatalf("expected obfuscation migration read error, got: %v", err)
	}

	// Invariant: Missing obfuscation parameters must NOT be generated on read failure
	if !cfg.H1.IsZero() {
		t.Fatalf("expected cfg.H1 to remain zero, got: %v", cfg.H1)
	}
	if cfg.HeaderProtectionKey != "" {
		t.Fatalf("expected cfg.HeaderProtectionKey to remain empty, got: %q", cfg.HeaderProtectionKey)
	}

	// Invariant: Raw corrupted setting must NOT be overwritten
	var rawValue string
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
		t.Fatalf("failed to read raw vpn_config: %v", err)
	}
	if rawValue != malformedJSON {
		t.Fatalf("malformed setting was overwritten: got %q, want %q", rawValue, malformedJSON)
	}
}
