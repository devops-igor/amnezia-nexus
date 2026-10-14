package vpn

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestUpdateConfig_RollbackPersistenceFailureIsReported(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	baseCfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		ClientQueueSize:    2,
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	// Force runtime application to fail after persistence succeeds: active
	// routes make client queue resizing unsafe. The trigger permits that first
	// save, then rejects the rollback save while the new value is stored.
	svc.forwarder.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	if _, err := db.SQLDB().ExecContext(ctx, `CREATE TRIGGER fail_vpn_rollback BEFORE UPDATE OF value ON settings
		WHEN OLD.key = 'vpn_config' AND OLD.value LIKE '%"client_queue_size":4%'
		BEGIN SELECT RAISE(ABORT, 'rollback persistence unavailable'); END;`); err != nil {
		t.Fatalf("create rollback trigger: %v", err)
	}

	changed := *baseCfg
	changed.ClientQueueSize = 4
	err = svc.UpdateConfig(ctx, &changed)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure in returned error, got: %v", err)
	}

	runtimeCfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if runtimeCfg.ClientQueueSize != 2 {
		t.Fatalf("runtime config changed despite failed application: %d", runtimeCfg.ClientQueueSize)
	}
	storedCfg, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if storedCfg.ClientQueueSize != 4 {
		t.Fatalf("expected explicit partial state with new persisted config, got %d", storedCfg.ClientQueueSize)
	}
}

func TestUpdateConfig_SaveFailureDoesNotMutateQueueRuntime(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	baseCfg := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		HealthThresholdMS:  500,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		ClientQueueSize:    2,
		MaxTotalPeers:      500,
		MaxPeersPerBackend: 100,
		Weights:            map[int64]int{},
	}
	if err := db.SaveVPNConfig(ctx, baseCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test DB: %v", err)
	}

	changed := *baseCfg
	changed.ClientQueueSize = 4
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("UpdateConfig unexpectedly succeeded after DB close")
	}
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfg.ClientQueueSize != 2 {
		t.Fatalf("service queue size changed after failed save: %d", cfg.ClientQueueSize)
	}
	svc.forwarder.RegisterSession("session-1", "connection-1", "peer-1", "10.100.0.10", 1)
	queue, ok := svc.forwarder.GetClientPacketChannel("peer-1")
	if !ok {
		t.Fatal("GetClientPacketChannel did not find registered peer")
	}
	if cap(queue) != 2 {
		t.Fatalf("runtime queue size changed after failed save: %d", cap(queue))
	}
}

func TestVPNConfigMigration_FailsLoudly(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Seed a legacy config row without obfuscation parameters so the
	// migration path in NewVPNService is forced to generate and persist.
	legacyJSON := `{"algorithm":"least_connections","listen_port":51820,"subnet_cidr":"10.100.0.0/16","health_threshold_ms":500,"max_total_peers":1000,"max_peers_per_backend":250}`
	if _, err := db.SQLDB().ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", "vpn_config", legacyJSON); err != nil {
		t.Fatalf("failed to seed legacy vpn_config: %v", err)
	}

	// Break persistence for vpn_config saves while keeping the legacy row readable.
	for _, q := range []string{
		`CREATE TRIGGER fail_vpn_config_update BEFORE UPDATE ON settings WHEN NEW.key = 'vpn_config' BEGIN SELECT RAISE(FAIL, 'simulated save failure'); END;`,
		`CREATE TRIGGER fail_vpn_config_insert BEFORE INSERT ON settings WHEN NEW.key = 'vpn_config' BEGIN SELECT RAISE(FAIL, 'simulated save failure'); END;`,
	} {
		if _, err := db.SQLDB().ExecContext(ctx, q); err != nil {
			t.Fatalf("failed to create failure trigger: %v", err)
		}
	}

	// NewVPNService must fail explicitly with the obfuscation-persistence
	// error, not start silently with divergent ephemeral values.
	svc, err := NewVPNService(db, nil)
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected NewVPNService to fail loudly when obfuscation persistence fails")
	}
	if !strings.Contains(err.Error(), "failed to persist obfuscation params") {
		t.Fatalf("expected obfuscation persistence error, got: %v", err)
	}
}

func TestConcurrentFirstRead_ConsistentParams(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Fresh DB: no vpn_config row yet, so both goroutines run the
	// migration path concurrently.

	const goroutines = 2
	results := make(chan models.HeaderRange, goroutines)
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			svc, err := NewVPNService(db, nil)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = svc.Stop() }()
			cfg, err := svc.GetConfig(ctx)
			if err != nil {
				errs <- err
				return
			}
			results <- cfg.H1
		}()
	}

	var h1s []models.HeaderRange
	for i := 0; i < goroutines; i++ {
		select {
		case err := <-errs:
			t.Fatalf("concurrent NewVPNService failed: %v", err)
		case h1 := <-results:
			h1s = append(h1s, h1)
		}
	}

	if h1s[0] != h1s[1] {
		t.Errorf("concurrent first reads diverged: H1 values %v", h1s)
	}

	// Persisted value must match what both services saw.
	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.H1 != h1s[0] {
		t.Errorf("persisted H1 %s does not match service H1 %s", persisted.H1, h1s[0])
	}
	if persisted.H1.IsZero() {
		t.Error("expected persisted H1 to be generated (non-zero)")
	}
}

// --- Issue #16: listen-port change safety (C2) ---

func TestUpdateConfig_RejectsListenPortChangeWhileRunning(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	changed := *before
	changed.ListenPort = before.ListenPort + 7
	err = svc.UpdateConfig(ctx, &changed)
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected error when changing listen_port while listener runs")
	}
	if !strings.Contains(err.Error(), "listen_port cannot be changed while the VPN listener is running") {
		t.Fatalf("expected running-listener rejection error, got: %v", err)
	}

	// The running config must be untouched.
	after, _ := svc.GetConfig(ctx)
	if after.ListenPort != before.ListenPort {
		t.Errorf("running config was mutated by rejected update: listen_port %d -> %d", before.ListenPort, after.ListenPort)
	}
	_ = svc.Stop()

	// Once the listener is idle the same change is accepted...
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig after Stop failed: %v", err)
	}
	cfgAfter, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgAfter.ListenPort != changed.ListenPort {
		t.Errorf("idle config port not updated: want %d, got %d", changed.ListenPort, cfgAfter.ListenPort)
	}
	// ...and persisted, so the next boot binds the new port.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != changed.ListenPort {
		t.Errorf("persisted listen_port not updated: want %d, got %d", changed.ListenPort, stored.ListenPort)
	}
}

func TestUpdateConfig_AllowsListenPortChangeWhenIdle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	changed := *before
	changed.ListenPort = 31458
	if err := svc.UpdateConfig(ctx, &changed); err != nil {
		t.Fatalf("UpdateConfig with changed listen_port on idle service failed: %v", err)
	}

	cfgAfter, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgAfter.ListenPort != 31458 {
		t.Errorf("service config listen_port: want 31458, got %d", cfgAfter.ListenPort)
	}

	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != 31458 {
		t.Errorf("persisted listen_port: want 31458, got %d", stored.ListenPort)
	}
}

// --- Issue #16: VPN_LISTEN_PORT env wiring (C1/C4) ---

// TestVPNPortWiring_EnvPortWinsOnFirstBootThenPersists constructs the C1
// wiring sequence that cmd/panel/main.go and cmd/server/main.go run before
// vpnSvc.Start: GetConfig -> set port from env -> UpdateConfig. It asserts
// the port is persisted to the DB config,
// rendered into the client config endpoint, and read back
// unchanged by a fresh service (the "subsequent boots read the persisted
// value" leg of the precedence contract).
func TestVPNPortWiring_EnvPortWinsOnFirstBootThenPersists(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// C1 wiring sequence (env VPN_LISTEN_PORT=31458 differs from DB config).
	const envPort = 31458
	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	wasPort := cfgVPN.ListenPort
	if wasPort == envPort {
		t.Fatalf("test premise: DB config already at env port %d", envPort)
	}
	cfgVPN.ListenPort = envPort
	if err := svc.UpdateConfig(ctx, cfgVPN); err != nil {
		t.Fatalf("UpdateConfig (env wiring) failed: %v", err)
	}
	t.Logf("wired VPN_LISTEN_PORT=%d (was %d)", envPort, wasPort)

	// Persisted for subsequent boots.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != envPort {
		t.Errorf("persisted listen_port: want %d, got %d", envPort, stored.ListenPort)
	}

	// GenerateClientConfig renders the matching endpoint port.
	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")
	uID, err := db.CreateUser(ctx, &models.User{Username: "portwire", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	cfgStr, _, err := svc.GenerateClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}
	if !strings.Contains(cfgStr, "Endpoint = ") {
		t.Fatalf("expected Endpoint directive in client config: %s", cfgStr)
	}
	if !strings.Contains(cfgStr, ":31458") {
		t.Errorf("client config endpoint must carry the wired listen port :%d, got:\n%s", envPort, cfgStr)
	}

	// A fresh service over the same DB (next boot, env wiring already
	// applied) reads the persisted port without any further update.
	svc2, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService (second boot) failed: %v", err)
	}
	cfg2, err := svc2.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig (second boot) failed: %v", err)
	}
	if cfg2.ListenPort != envPort {
		t.Errorf("second boot must read persisted port %d, got %d", envPort, cfg2.ListenPort)
	}
}

// TestVPNPortWiring_SamePortIsNoop pins the main.go guard: when the env port
// equals the DB config port, the wiring must not call UpdateConfig (no
// rewrite, no spurious audit/persist churn).
func TestVPNPortWiring_SamePortIsNoop(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgVPN.ListenPort == 0 {
		t.Fatalf("expected non-zero ListenPort, got %d", cfgVPN.ListenPort)
	}
}

// TestBootWiring_ListenPortPersistsThroughMigration runs the full boot-wiring
// sequence against a legacy DB row (zero obfuscation params): NewVPNService
// triggers ensureObfuscationParams during boot, then the env-wiring sequence
// (GetConfig -> set 31458 -> UpdateConfig) persists the port, and a FRESH
// db.GetVPNConfig must return 31458 with the migrated params intact.
func TestBootWiring_ListenPortPersistsThroughMigration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	legacy := &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51820,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      1000,
		MaxPeersPerBackend: 250,
		Weights:            map[int64]int{},
		// H1..H4 / S1..S4 zero -> boot-time migration fills and persists them.
	}
	if err := db.SaveVPNConfig(ctx, legacy); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	// Env wiring sequence from cmd/*/main.go (runs before service Start).
	cfgVPN, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfgVPN.H1.IsZero() {
		t.Fatalf("boot did not migrate legacy obfuscation params: %+v", cfgVPN)
	}
	cfgVPN.ListenPort = 31458
	if err := svc.UpdateConfig(ctx, cfgVPN); err != nil {
		t.Fatalf("UpdateConfig (env wiring) failed: %v", err)
	}

	// FRESH read from the DB (what the next boot consumes).
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.ListenPort != 31458 {
		t.Errorf("fresh persisted listen_port: want 31458, got %d", stored.ListenPort)
	}
	if stored.H1.IsZero() {
		t.Errorf("fresh persisted config lost migrated obfuscation params: %+v", stored)
	}
}

// TestRejectedUpdateConfigLeavesPersistedRowUntouched extends the
// TestUpdateConfig_RejectsObfuscationChangeWhileRunning pattern to the
// PERSISTED row: a rejected (immutable-while-running) UpdateConfig must leave
// the stored config — including the wired listen_port — completely untouched.
func TestRejectedUpdateConfigLeavesPersistedRowUntouched(t *testing.T) {
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

	before, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	changed := *before
	changed.H1 = models.DegenerateHeaderRange(987654321)
	changed.S1 = 77
	if err := svc.UpdateConfig(ctx, &changed); err == nil {
		t.Fatal("expected error when changing obfuscation params while listener runs")
	} else if !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("expected immutability error, got: %v", err)
	}

	after, _ := svc.GetConfig(ctx)
	if after.H1 != before.H1 || after.S1 != before.S1 || after.ListenPort != before.ListenPort {
		t.Errorf("running config mutated by rejected update: before(H1=%s S1=%d port=%d) after(H1=%s S1=%d port=%d)",
			before.H1, before.S1, before.ListenPort, after.H1, after.S1, after.ListenPort)
	}

	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted.H1 != before.H1 || persisted.S1 != before.S1 || persisted.ListenPort != before.ListenPort {
		t.Errorf("persisted row mutated by rejected update: want(H1=%s S1=%d port=%d) got(H1=%s S1=%d port=%d)",
			before.H1, before.S1, before.ListenPort, persisted.H1, persisted.S1, persisted.ListenPort)
	}
}

func TestConfigImmutabilityContract(t *testing.T) {
	ctx := context.Background()

	t.Run("StoredSingleInts_ByteIdentical_NoReRandomization", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_single_ints", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection with single ints (float64 as unmarshaled from JSON)
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-single",
			Name:     "user_single_ints-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-single",
				"rekey_after_time":       float64(125),
				"rekey_timeout":          float64(5),
				"reject_after_time":      float64(180),
				"keepalive_timeout":      float64(10),
				"max_handshake_attempts": float64(6),
				"persistent_keepalive":   float64(26),
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		// First render
		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}

		// Second render
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		// Byte-identical regression check
		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders for same UserConnection!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		// Stored single ints must be rendered unchanged as degenerate "N" (not re-randomized!)
		if !strings.Contains(cfg1, "RekeyAfterTime = 125\n") {
			t.Errorf("expected RekeyAfterTime = 125 preserved unchanged, got:\n%s", cfg1)
		}
		if !strings.Contains(cfg1, "RekeyTimeout = 5\n") {
			t.Errorf("expected RekeyTimeout = 5 preserved unchanged, got:\n%s", cfg1)
		}
		if !strings.Contains(cfg1, "PersistentKeepalive = 26\n") {
			t.Errorf("expected PersistentKeepalive = 26 preserved unchanged, got:\n%s", cfg1)
		}
	})

	t.Run("StoredRanges_ByteIdentical", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_stored_ranges", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection with ranges
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-range",
			Name:     "user_stored_ranges-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-range",
				"rekey_after_time":       "105-135",
				"rekey_timeout":          "4-6",
				"reject_after_time":      "165-195",
				"keepalive_timeout":      "9-11",
				"max_handshake_attempts": "5-7",
				"persistent_keepalive":   "23-28",
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders for stored ranges!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		if !strings.Contains(cfg1, "RekeyAfterTime = 105-135\n") {
			t.Errorf("expected RekeyAfterTime = 105-135, got:\n%s", cfg1)
		}
		if !strings.Contains(cfg1, "PersistentKeepalive = 23-28\n") {
			t.Errorf("expected PersistentKeepalive = 23-28, got:\n%s", cfg1)
		}
	})

	t.Run("PartiallyMissingParam_IndividualFallback_ByteIdentical", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_partial", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection missing rekey_after_time, but having rekey_timeout=5
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-partial",
			Name:     "user_partial-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-partial",
				"rekey_timeout":          float64(5),
				"reject_after_time":      float64(180),
				"keepalive_timeout":      float64(10),
				"max_handshake_attempts": float64(6),
				"persistent_keepalive":   float64(26),
				// rekey_after_time is intentionally missing!
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders for partially missing params!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		// Partner rekey_timeout MUST NOT have been re-rolled
		if !strings.Contains(cfg1, "RekeyTimeout = 5\n") {
			t.Errorf("stored partner RekeyTimeout = 5 was re-rolled wholesale! Cfg:\n%s", cfg1)
		}

		// Missing rekey_after_time was individually backfilled as a range
		rat := parseDirectiveRange(t, cfg1, "RekeyAfterTime")
		if rat == nil || rat.Lo < 100 || rat.Hi > 140 {
			t.Errorf("expected individually backfilled RekeyAfterTime in [100, 140], got %v", rat)
		}
	})

	t.Run("OrderingInvariantClamping_BackfilledParam", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_clamp", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		// Seed pre-existing connection with an unusually low stored rekey_after_time = 5,
		// and missing rekey_timeout. Backfilled rekey_timeout must be clamped strictly < 5.
		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: "pubkey-user-clamp",
			Name:     "user_clamp-awg",
			ClientParams: map[string]any{
				"client_private_key":     "privkey-user-clamp",
				"rekey_after_time":       float64(5),
				"reject_after_time":      float64(180),
				"keepalive_timeout":      float64(10),
				"max_handshake_attempts": float64(6),
				"persistent_keepalive":   float64(26),
				// rekey_timeout is missing
			},
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: config not byte-identical across renders with clamped partner!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		rt := parseDirectiveRange(t, cfg1, "RekeyTimeout")
		rat := parseDirectiveRange(t, cfg1, "RekeyAfterTime")

		if rt.Hi >= rat.Lo {
			t.Errorf("ordering invariant failed: backfilled rt.Hi (%d) must be < stored rat.Lo (%d)", rt.Hi, rat.Lo)
		}
		if rat.Lo != 5 || rat.Hi != 5 {
			t.Errorf("stored partner rat changed: %+v", rat)
		}
	})

	t.Run("BrandNewUser_ByteIdenticalAcrossRenders", func(t *testing.T) {
		db := setupTestDB(t)
		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		uID, err := db.CreateUser(ctx, &models.User{Username: "user_brand_new", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		cfg1, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 1 failed: %v", err)
		}
		cfg2, _, err := svc.GenerateClientConfig(ctx, uID)
		if err != nil {
			t.Fatalf("GenerateClientConfig 2 failed: %v", err)
		}

		if cfg1 != cfg2 {
			t.Fatalf("REGRESSION: brand new user config not byte-identical across renders!\nCfg1:\n%s\nCfg2:\n%s", cfg1, cfg2)
		}

		// Verify all 6 are emitted as ranges "lo-hi"
		for _, directive := range []string{
			"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
			"KeepaliveTimeout", "MaxHandshakeAttempts", "PersistentKeepalive",
		} {
			val := parseDirectiveString(t, cfg1, directive)
			if !strings.Contains(val, "-") {
				t.Errorf("new user %s should be range 'lo-hi', got %q", directive, val)
			}
		}
	})
}

// Issue #344 Regression Tests: Fail startup on unreadable persisted VPN configuration

func TestNewVPNService_MalformedVPNConfigFailsAndPreservesRow(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	const malformedJSON = "{invalid-json"
	if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', ?)", malformedJSON); err != nil {
		t.Fatalf("failed to insert malformed vpn_config: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected NewVPNService to fail on malformed vpn_config")
	}
	if !strings.Contains(err.Error(), "failed to load VPN config") {
		t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
	}

	var rawValue string
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
		t.Fatalf("failed to read raw vpn_config: %v", err)
	}
	if rawValue != malformedJSON {
		t.Fatalf("malformed setting was overwritten: got %q, want %q", rawValue, malformedJSON)
	}
}

func TestNewVPNService_DatabaseReadErrorFailsWithoutPersistence(t *testing.T) {
	ctx := context.Background()

	t.Run("closed_database", func(t *testing.T) {
		db := setupTestDB(t)
		if err := db.Close(); err != nil {
			t.Fatalf("failed to close test db: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail when database is closed")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}
	})

	t.Run("dropped_settings_table", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "DROP TABLE settings"); err != nil {
			t.Fatalf("failed to drop settings table: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail when settings table is unreadable")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}
	})
}

func TestNewVPNService_TrulyAbsentConfigInitializesFirstBoot(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Ensure vpn_config row is completely absent (first boot without pre-seeded row)
	if _, err := db.SQLDB().ExecContext(ctx, "DELETE FROM settings WHERE key = 'vpn_config'"); err != nil {
		t.Fatalf("failed to delete vpn_config setting: %v", err)
	}

	var count int
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM settings WHERE key = 'vpn_config'").Scan(&count); err != nil {
		t.Fatalf("failed to count vpn_config rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 vpn_config rows before init, got %d", count)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed on absent config: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	persisted, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if persisted == nil {
		t.Fatal("expected persisted VPN config to exist")
	}
	if persisted.ListenPort != 51820 {
		t.Errorf("expected ListenPort 51820, got %d", persisted.ListenPort)
	}
	if persisted.H1.IsZero() || persisted.H2.IsZero() || persisted.H3.IsZero() || persisted.H4.IsZero() {
		t.Errorf("expected valid non-zero H values, got H1=%s H2=%s H3=%s H4=%s", persisted.H1, persisted.H2, persisted.H3, persisted.H4)
	}
	if persisted.HeaderProtectionKey == "" {
		t.Errorf("expected non-empty HeaderProtectionKey")
	}

	// Verify the row actually exists in the database settings table
	if err := db.SQLDB().QueryRowContext(ctx, "SELECT COUNT(*) FROM settings WHERE key = 'vpn_config'").Scan(&count); err != nil {
		t.Fatalf("failed to count vpn_config rows after init: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 vpn_config row after init, got %d", count)
	}
}

func TestNewVPNService_ExistingEmptySQLNullOrJSONNullConfigFailsAndPreservesRow(t *testing.T) {
	ctx := context.Background()

	t.Run("empty_string", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', '')"); err != nil {
			t.Fatalf("failed to insert empty vpn_config: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail on empty vpn_config")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}

		var rawValue sql.NullString
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
			t.Fatalf("failed to read raw vpn_config: %v", err)
		}
		if !rawValue.Valid || rawValue.String != "" {
			t.Fatalf("expected empty string row preserved, got: %+v", rawValue)
		}
	})

	t.Run("sql_null", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', NULL)"); err != nil {
			t.Fatalf("failed to insert SQL NULL vpn_config: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail on SQL NULL vpn_config")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}

		var rawValue sql.NullString
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
			t.Fatalf("failed to read raw vpn_config: %v", err)
		}
		if rawValue.Valid {
			t.Fatalf("expected SQL NULL preserved, got valid string: %q", rawValue.String)
		}
	})

	t.Run("json_null", func(t *testing.T) {
		db := setupTestDB(t)
		if _, err := db.SQLDB().ExecContext(ctx, "INSERT OR REPLACE INTO settings (key, value) VALUES ('vpn_config', 'null')"); err != nil {
			t.Fatalf("failed to insert json null vpn_config: %v", err)
		}

		svc, err := NewVPNService(db, nil)
		if err == nil {
			_ = svc.Stop()
			t.Fatal("expected NewVPNService to fail on json null vpn_config")
		}
		if !strings.Contains(err.Error(), "failed to load VPN config") {
			t.Fatalf("expected 'failed to load VPN config' in error, got: %v", err)
		}

		var rawValue sql.NullString
		if err := db.SQLDB().QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'vpn_config'").Scan(&rawValue); err != nil {
			t.Fatalf("failed to read raw vpn_config: %v", err)
		}
		if !rawValue.Valid || rawValue.String != "null" {
			t.Fatalf("expected json null string preserved, got: %+v", rawValue)
		}
	})
}
