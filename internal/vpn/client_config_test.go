package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ipam"
)

func TestGenerateUserClientConfig_Success(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, _, _, uID, _ := setupTestVPNService(t, db)
	cfgStr, filename, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig returned unexpected error: %v", err)
	}
	if filename != "amnezia-portal-alice.conf" {
		t.Fatalf("expected filename amnezia-portal-alice.conf, got: %s", filename)
	}
	if !strings.Contains(cfgStr, "[Interface]") {
		t.Fatalf("expected [Interface] section in config, got:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "PrivateKey =") {
		t.Fatalf("expected PrivateKey in config, got:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "Address =") {
		t.Fatalf("expected Address in config, got:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "[Peer]") {
		t.Fatalf("expected [Peer] section in config, got:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "PublicKey =") {
		t.Fatalf("expected PublicKey in config, got:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "Endpoint =") {
		t.Fatalf("expected Endpoint in config, got:\n%s", cfgStr)
	}
}

func TestGenerateClientConfigForConnection_SuccessAndErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("valid connection renders config and updates db", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)

		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			Name:     "alice-phone",
		}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		cfgStr, filename, err := svc.GenerateClientConfigForConnection(ctx, uID, connID)
		if err != nil {
			t.Fatalf("GenerateClientConfigForConnection failed: %v", err)
		}
		if filename != "alice-phone.conf" {
			t.Fatalf("expected filename alice-phone.conf, got: %s", filename)
		}
		if !strings.Contains(cfgStr, "[Interface]") {
			t.Fatalf("expected [Interface] in config, got:\n%s", cfgStr)
		}

		updatedConn, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatalf("GetConnection failed: %v", err)
		}
		if updatedConn == nil {
			t.Fatalf("expected updated connection to be non-nil")
		}
		if updatedConn.ClientID == "" {
			t.Fatalf("expected non-empty ClientID on connection")
		}
		if updatedConn.ClientParams == nil {
			t.Fatalf("expected non-nil ClientParams on connection")
		}
	})

	t.Run("nil database returns error", func(t *testing.T) {
		svc := &Service{}
		_, _, err := svc.GenerateClientConfigForConnection(ctx, "any-user", "any-conn")
		if err == nil {
			t.Fatalf("expected error for nil database, got nil")
		}
		if !strings.Contains(err.Error(), "database not available") {
			t.Fatalf("expected 'database not available' error, got: %v", err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, _, _ := setupTestVPNService(t, db)

		_, _, err := svc.GenerateClientConfigForConnection(ctx, "non-existent-user", "any-conn")
		if err == nil {
			t.Fatalf("expected error for nonexistent user, got nil")
		}
		if !strings.Contains(err.Error(), "user not found") {
			t.Fatalf("expected 'user not found' error, got: %v", err)
		}
	})

	t.Run("connection not found", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)

		_, _, err := svc.GenerateClientConfigForConnection(ctx, uID, "non-existent-conn")
		if err == nil {
			t.Fatalf("expected error for nonexistent connection, got nil")
		}
		if !strings.Contains(err.Error(), "connection not found") {
			t.Fatalf("expected 'connection not found' error, got: %v", err)
		}
	})

	t.Run("unauthorized wrong user", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)

		bobID, err := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}

		conn := &models.UserConnection{
			UserID:   bobID,
			ServerID: 0,
			Protocol: "awg",
			Name:     "bob-device",
		}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		_, _, err = svc.GenerateClientConfigForConnection(ctx, uID, connID)
		if err == nil {
			t.Fatalf("expected unauthorized error, got nil")
		}
		if !strings.Contains(err.Error(), "unauthorized") {
			t.Fatalf("expected 'unauthorized' error, got: %v", err)
		}
	})

	t.Run("non-load balancer connection rejected", func(t *testing.T) {
		db := setupTestDB(t)
		svc, s1ID, _, uID, _ := setupTestVPNService(t, db)

		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: s1ID,
			Protocol: "awg",
			Name:     "alice-server1",
		}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		_, _, err = svc.GenerateClientConfigForConnection(ctx, uID, connID)
		if err == nil {
			t.Fatalf("expected non-lb connection error, got nil")
		}
		if !strings.Contains(err.Error(), "not a load balancer connection") {
			t.Fatalf("expected 'not a load balancer connection' error, got: %v", err)
		}
	})

	t.Run("unsupported protocol rejected", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, uID, _ := setupTestVPNService(t, db)

		conn := &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "vless",
			Name:     "alice-vless",
		}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		_, _, err = svc.GenerateClientConfigForConnection(ctx, uID, connID)
		if err == nil {
			t.Fatalf("expected unsupported protocol error, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported protocol") {
			t.Fatalf("expected 'unsupported protocol' error, got: %v", err)
		}
	})
}

func TestResolveHeaderProtectionKey(t *testing.T) {
	ctx := context.Background()

	t.Run("uses cfg header protection key and clamps junk to min 12", func(t *testing.T) {
		cfg := &models.VPNConfig{HeaderProtectionKey: "test-hp-key"}
		awgParams := &awg.AWGParams{
			InitPacketJunkSize:        "4",
			ResponsePacketJunkSize:    "8",
			CookieReplyPacketJunkSize: "12",
			TransportPacketJunkSize:   "20",
		}
		resolveHeaderProtectionKey(ctx, nil, cfg, awgParams)
		if awgParams.HeaderProtectionKey != "test-hp-key" {
			t.Fatalf("expected HeaderProtectionKey %q, got %q", "test-hp-key", awgParams.HeaderProtectionKey)
		}
		if awgParams.InitPacketJunkSize != "12" {
			t.Fatalf("expected InitPacketJunkSize 12, got %s", awgParams.InitPacketJunkSize)
		}
		if awgParams.ResponsePacketJunkSize != "12" {
			t.Fatalf("expected ResponsePacketJunkSize 12, got %s", awgParams.ResponsePacketJunkSize)
		}
		if awgParams.CookieReplyPacketJunkSize != "12" {
			t.Fatalf("expected CookieReplyPacketJunkSize 12, got %s", awgParams.CookieReplyPacketJunkSize)
		}
		if awgParams.TransportPacketJunkSize != "20" {
			t.Fatalf("expected TransportPacketJunkSize 20, got %s", awgParams.TransportPacketJunkSize)
		}
	})

	t.Run("falls back to db when cfg key is empty", func(t *testing.T) {
		db := setupTestDB(t)
		err := db.SaveVPNConfig(ctx, &models.VPNConfig{HeaderProtectionKey: "db-hp-key"})
		if err != nil {
			t.Fatalf("SaveVPNConfig failed: %v", err)
		}
		awgParams := &awg.AWGParams{
			InitPacketJunkSize: "0",
		}
		resolveHeaderProtectionKey(ctx, db, nil, awgParams)
		if awgParams.HeaderProtectionKey != "db-hp-key" {
			t.Fatalf("expected HeaderProtectionKey %q, got %q", "db-hp-key", awgParams.HeaderProtectionKey)
		}
		if awgParams.InitPacketJunkSize != "12" {
			t.Fatalf("expected InitPacketJunkSize 12, got %s", awgParams.InitPacketJunkSize)
		}
	})

	t.Run("preserves existing awgParams key without overriding", func(t *testing.T) {
		cfg := &models.VPNConfig{HeaderProtectionKey: "cfg-key"}
		awgParams := &awg.AWGParams{
			HeaderProtectionKey: "already-set-key",
			InitPacketJunkSize:  "15",
		}
		resolveHeaderProtectionKey(ctx, nil, cfg, awgParams)
		if awgParams.HeaderProtectionKey != "already-set-key" {
			t.Fatalf("expected existing key to be preserved, got %q", awgParams.HeaderProtectionKey)
		}
		if awgParams.InitPacketJunkSize != "15" {
			t.Fatalf("expected InitPacketJunkSize 15, got %s", awgParams.InitPacketJunkSize)
		}
	})
}

func TestResolveContentPadding(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		cfgCP       string
		seedServers bool
		serverCP    any
		serverCPAdd string
		wantEnabled bool
		wantVal     string
	}{
		{
			name:        "cfg boolean true",
			cfgCP:       "true",
			wantEnabled: true,
			wantVal:     "16-64",
		},
		{
			name:        "cfg boolean 1",
			cfgCP:       "1",
			wantEnabled: true,
			wantVal:     "16-64",
		},
		{
			name:        "cfg boolean yes",
			cfgCP:       "yes",
			wantEnabled: true,
			wantVal:     "16-64",
		},
		{
			name:        "cfg custom range",
			cfgCP:       "20-80",
			wantEnabled: true,
			wantVal:     "20-80",
		},
		{
			name:        "cfg disabled falls back to server awg_content_padding",
			cfgCP:       "false",
			seedServers: true,
			serverCP:    true,
			wantEnabled: true,
			wantVal:     "16-64",
		},
		{
			name:        "cfg disabled falls back to server content_padding_addition string",
			cfgCP:       "",
			seedServers: true,
			serverCPAdd: "32-64",
			wantEnabled: true,
			wantVal:     "32-64",
		},
		{
			name:        "both empty returns false",
			cfgCP:       "",
			seedServers: false,
			wantEnabled: false,
			wantVal:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupTestDB(t)
			if tt.seedServers {
				params := map[string]any{}
				if tt.serverCP != nil {
					params["awg_content_padding"] = tt.serverCP
				}
				if tt.serverCPAdd != "" {
					params["content_padding_addition"] = tt.serverCPAdd
				}
				_, err := db.CreateServer(ctx, &models.Server{
					Name: "awg-srv",
					Protocols: map[string]any{
						"awg": map[string]any{
							"awg_params": params,
						},
					},
				})
				if err != nil {
					t.Fatalf("CreateServer failed: %v", err)
				}
			}

			cfg := &models.VPNConfig{ContentPaddingAddition: tt.cfgCP}
			enabled, val := resolveContentPadding(ctx, db, cfg)
			if enabled != tt.wantEnabled {
				t.Fatalf("expected enabled %v, got %v", tt.wantEnabled, enabled)
			}
			if val != tt.wantVal {
				t.Fatalf("expected val %q, got %q", tt.wantVal, val)
			}
		})
	}

	t.Run("nil db returns false", func(t *testing.T) {
		enabled, val := resolveContentPadding(ctx, nil, nil)
		if enabled {
			t.Fatalf("expected false for nil db, got true")
		}
		if val != "" {
			t.Fatalf("expected empty val for nil db, got %q", val)
		}
	})
}

func TestClientConfig_ObfuscationParametersRendering(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, _, _, uID, _ := setupTestVPNService(t, db, func(cfg *models.VPNConfig) {
		cfg.HeaderProtectionKey = "hp-test-secret-12345"
		cfg.ContentPaddingAddition = "16-64"
		cfg.S1 = 15
		cfg.S2 = 20
		cfg.H1 = models.DegenerateHeaderRange(100)
		cfg.H2 = models.DegenerateHeaderRange(200)
		cfg.H3 = models.DegenerateHeaderRange(300)
		cfg.H4 = models.DegenerateHeaderRange(400)
	})

	cfgStr, _, err := svc.GenerateUserClientConfig(ctx, uID)
	if err != nil {
		t.Fatalf("GenerateUserClientConfig failed: %v", err)
	}

	expectedSubstrings := []string{
		"H1 = ",
		"H2 = ",
		"H3 = ",
		"H4 = ",
		"S1 = 15",
		"S2 = 20",
		"HeaderProtectionKey = hp-test-secret-12345",
		"ContentPaddingAddition = 16-64",
		"Jmin = 10",
		"Jmax = 30",
	}
	for _, substr := range expectedSubstrings {
		if !strings.Contains(cfgStr, substr) {
			t.Fatalf("expected client config to contain %q, config:\n%s", substr, cfgStr)
		}
	}
}

func TestResolveAssignedIP_BehaviorAndPersistence(t *testing.T) {
	ipamMgr, err := ipam.NewIPAM("10.100.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAM failed: %v", err)
	}
	svc := &Service{
		ipam: ipamMgr,
	}
	cfg := &models.VPNConfig{SubnetCIDR: "10.100.0.0/24"}

	t.Run("reserves valid existing assigned_ip inside CIDR", func(t *testing.T) {
		params := map[string]any{
			"assigned_ip": "10.100.0.42",
		}
		ip, err := svc.resolveAssignedIP(params, cfg, "client-pub-1")
		if err != nil {
			t.Fatalf("resolveAssignedIP failed: %v", err)
		}
		if ip != "10.100.0.42" {
			t.Fatalf("expected 10.100.0.42, got %s", ip)
		}

		assigned, exists := ipamMgr.GetAssignedIP("client-pub-1")
		if !exists {
			t.Fatalf("expected lease in IPAM for client-pub-1")
		}
		if assigned.String() != "10.100.0.42" {
			t.Fatalf("expected IPAM assigned IP 10.100.0.42, got %s", assigned.String())
		}
	})

	t.Run("conflicting existing assigned_ip returns ErrIPAlreadyAllocated", func(t *testing.T) {
		params := map[string]any{
			"assigned_ip": "10.100.0.42", // Already leased to client-pub-1
		}
		_, err := svc.resolveAssignedIP(params, cfg, "client-pub-2")
		if err == nil {
			t.Fatalf("expected conflict error, got nil")
		}
		if !errors.Is(err, ipam.ErrIPAlreadyAllocated) {
			t.Fatalf("expected ErrIPAlreadyAllocated, got: %v", err)
		}
	})

	t.Run("config_regeneration_required releases old and allocates new", func(t *testing.T) {
		params := map[string]any{
			"assigned_ip":                  "10.100.0.42",
			"config_regeneration_required": true,
		}
		ip, err := svc.resolveAssignedIP(params, cfg, "client-pub-1")
		if err != nil {
			t.Fatalf("resolveAssignedIP failed: %v", err)
		}
		if ip == "" {
			t.Fatalf("expected non-empty IP allocated")
		}
		if _, exists := params["config_regeneration_required"]; exists {
			t.Fatalf("expected config_regeneration_required to be deleted from clientParams")
		}
	})

	t.Run("quarantined_ip_collision allocates fresh IP", func(t *testing.T) {
		params := map[string]any{
			"assigned_ip":              "10.100.0.99",
			"quarantined_ip_collision": "10.100.0.99",
		}
		ip, err := svc.resolveAssignedIP(params, cfg, "client-pub-quarantine")
		if err != nil {
			t.Fatalf("resolveAssignedIP failed: %v", err)
		}
		if ip == "" {
			t.Fatalf("expected non-empty IP allocated")
		}
		if _, exists := params["quarantined_ip_collision"]; exists {
			t.Fatalf("expected quarantined_ip_collision to be deleted from clientParams")
		}
	})

	t.Run("out-of-subnet IP triggers new allocation inside subnet", func(t *testing.T) {
		params := map[string]any{
			"assigned_ip": "198.51.100.50",
		}
		ip, err := svc.resolveAssignedIP(params, cfg, "client-pub-out-of-subnet")
		if err != nil {
			t.Fatalf("resolveAssignedIP failed: %v", err)
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("failed to parse returned IP: %s", ip)
		}
		_, cidr, _ := net.ParseCIDR("10.100.0.0/24")
		if !cidr.Contains(parsed) {
			t.Fatalf("expected IP %s to be within 10.100.0.0/24", ip)
		}
	})

	t.Run("nil ipam returns unavailable error when allocation needed", func(t *testing.T) {
		nilSvc := &Service{ipam: nil}
		params := map[string]any{}
		_, err := nilSvc.resolveAssignedIP(params, cfg, "client-no-ipam")
		if err == nil {
			t.Fatalf("expected error for nil ipam, got nil")
		}
		if !strings.Contains(err.Error(), "IP address manager is unavailable") {
			t.Fatalf("expected 'IP address manager is unavailable', got: %v", err)
		}
	})
}

func TestFindAWGConnection_Priority(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	user := &models.User{Username: "charlie", Enabled: true}
	userID, err := db.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	user.ID = userID

	t.Run("returns nil when user has no connections", func(t *testing.T) {
		conn := findAWGConnection(ctx, db, user)
		if conn != nil {
			t.Fatalf("expected nil connection, got %+v", conn)
		}
	})

	t.Run("priority 1: matches pending connection with empty ClientID", func(t *testing.T) {
		_, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:    userID,
			ServerID:  0,
			Protocol:  "awg",
			ClientID:  "existing-client-id",
			Name:      "charlie-existing",
			CreatedAt: time.Now().Add(-10 * time.Minute),
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		pendingID, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:    userID,
			ServerID:  0,
			Protocol:  "awg",
			ClientID:  "",
			Name:      "charlie-pending",
			CreatedAt: time.Now().Add(-5 * time.Minute),
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		conn := findAWGConnection(ctx, db, user)
		if conn == nil {
			t.Fatalf("expected found connection, got nil")
		}
		if conn.ID != pendingID {
			t.Fatalf("expected connection ID %s, got %s", pendingID, conn.ID)
		}
	})

	t.Run("priority 2: matches default portal connection name", func(t *testing.T) {
		user2 := &models.User{Username: "dave", Enabled: true}
		user2ID, err := db.CreateUser(ctx, user2)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		user2.ID = user2ID

		_, err = db.CreateConnection(ctx, &models.UserConnection{
			UserID:    user2ID,
			ServerID:  0,
			Protocol:  "awg",
			ClientID:  "dave-other-pub",
			Name:      "dave-other",
			CreatedAt: time.Now().Add(-5 * time.Minute),
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		defaultConnID, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID:    user2ID,
			ServerID:  0,
			Protocol:  "awg",
			ClientID:  "dave-default-pub",
			Name:      "dave-awg",
			CreatedAt: time.Now().Add(-10 * time.Minute),
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		conn := findAWGConnection(ctx, db, user2)
		if conn == nil {
			t.Fatalf("expected found connection, got nil")
		}
		if conn.ID != defaultConnID {
			t.Fatalf("expected default conn %s, got %s", defaultConnID, conn.ID)
		}
	})
}

func TestSaveOrUpdateAWGConnection(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	t.Run("updates existing connection", func(t *testing.T) {
		user := &models.User{Username: "eve", Enabled: true}
		userID, err := db.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		user.ID = userID

		conn := &models.UserConnection{
			UserID:   userID,
			ServerID: 0,
			Protocol: "awg",
			Name:     "eve-awg",
		}
		connID, err := db.CreateConnection(ctx, conn)
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}
		conn.ID = connID

		params := map[string]any{"test_param": "hello"}
		err = saveOrUpdateAWGConnection(ctx, db, user, conn, "eve-client-pubkey", params)
		if err != nil {
			t.Fatalf("saveOrUpdateAWGConnection failed: %v", err)
		}

		updated, err := db.GetConnection(ctx, connID)
		if err != nil {
			t.Fatalf("GetConnection failed: %v", err)
		}
		if updated == nil {
			t.Fatalf("expected non-nil updated connection")
		}
		if updated.ClientID != "eve-client-pubkey" {
			t.Fatalf("expected ClientID eve-client-pubkey, got %s", updated.ClientID)
		}
	})

	t.Run("creates new connection for user without connections", func(t *testing.T) {
		user := &models.User{Username: "frank", Enabled: true}
		userID, err := db.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		user.ID = userID

		params := map[string]any{"assigned_ip": "10.100.0.70"}
		err = saveOrUpdateAWGConnection(ctx, db, user, nil, "frank-pubkey", params)
		if err != nil {
			t.Fatalf("saveOrUpdateAWGConnection failed: %v", err)
		}

		conns, err := db.GetConnectionsByUserID(ctx, userID)
		if err != nil {
			t.Fatalf("GetConnectionsByUserID failed: %v", err)
		}
		if len(conns) != 1 {
			t.Fatalf("expected 1 connection created, got %d", len(conns))
		}
		if conns[0].Name != "frank-awg" {
			t.Fatalf("expected name frank-awg, got %s", conns[0].Name)
		}
		if conns[0].ClientID != "frank-pubkey" {
			t.Fatalf("expected ClientID frank-pubkey, got %s", conns[0].ClientID)
		}
	})

	t.Run("rejects auto-creation for user with existing connections", func(t *testing.T) {
		user := &models.User{Username: "grace", Enabled: true}
		userID, err := db.CreateUser(ctx, user)
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		user.ID = userID

		_, err = db.CreateConnection(ctx, &models.UserConnection{
			UserID:   userID,
			ServerID: 1, // remote server connection
			Protocol: "awg",
			Name:     "grace-remote",
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		err = saveOrUpdateAWGConnection(ctx, db, user, nil, "grace-pubkey", nil)
		if err == nil {
			t.Fatalf("expected rejection error, got nil")
		}
		if !strings.Contains(err.Error(), "no load balancer connection exists for user with existing connections") {
			t.Fatalf("expected specific rejection error, got: %v", err)
		}
	})
}

func TestParamHelpers(t *testing.T) {
	t.Run("getTimingParam", func(t *testing.T) {
		if tr := getTimingParam(nil, "key"); tr != nil {
			t.Fatalf("expected nil for nil map, got %+v", tr)
		}
		m := map[string]any{
			"valid_range": "10-20",
			"single_val":  "15",
			"invalid":     "not-a-number",
			"zero":        "0",
			"negative":    "-5",
		}
		if tr := getTimingParam(m, "absent"); tr != nil {
			t.Fatalf("expected nil for absent key, got %+v", tr)
		}
		if tr := getTimingParam(m, "invalid"); tr != nil {
			t.Fatalf("expected nil for invalid value, got %+v", tr)
		}
		if tr := getTimingParam(m, "zero"); tr != nil {
			t.Fatalf("expected nil for zero value, got %+v", tr)
		}
		if tr := getTimingParam(m, "negative"); tr != nil {
			t.Fatalf("expected nil for negative value, got %+v", tr)
		}

		trRange := getTimingParam(m, "valid_range")
		if trRange == nil {
			t.Fatalf("expected non-nil for valid_range")
		}
		if trRange.Lo != 10 || trRange.Hi != 20 {
			t.Fatalf("expected 10-20, got %d-%d", trRange.Lo, trRange.Hi)
		}

		trSingle := getTimingParam(m, "single_val")
		if trSingle == nil {
			t.Fatalf("expected non-nil for single_val")
		}
		if trSingle.Lo != 15 || trSingle.Hi != 15 {
			t.Fatalf("expected 15-15, got %d-%d", trSingle.Lo, trSingle.Hi)
		}
	})

	t.Run("getStringParam", func(t *testing.T) {
		if s := getStringParam(nil, "key"); s != "" {
			t.Fatalf("expected empty for nil map, got %q", s)
		}
		m := map[string]any{
			"str": "hello",
			"num": 42,
		}
		if s := getStringParam(m, "absent"); s != "" {
			t.Fatalf("expected empty for absent key, got %q", s)
		}
		if s := getStringParam(m, "str"); s != "hello" {
			t.Fatalf("expected 'hello', got %q", s)
		}
		if s := getStringParam(m, "num"); s != "42" {
			t.Fatalf("expected '42', got %q", s)
		}
	})
}

func TestResolveClientConfigParameters(t *testing.T) {
	t.Run("generates keys and timing ranges when conn is nil", func(t *testing.T) {
		p, err := resolveClientConfigParameters(nil, true, "16-64")
		if err != nil {
			t.Fatalf("resolveClientConfigParameters failed: %v", err)
		}
		if p.clientPub == "" {
			t.Fatalf("expected generated clientPub")
		}
		if p.clientPriv == "" {
			t.Fatalf("expected generated clientPriv")
		}
		if p.rat == nil || p.rt == nil || p.rej == nil || p.kt == nil || p.mha == nil || p.pk == nil {
			t.Fatalf("expected non-nil timing ranges")
		}
		if p.cpAdd == nil || *p.cpAdd != "16-64" {
			t.Fatalf("expected ContentPaddingAddition 16-64")
		}
	})

	t.Run("preserves existing client params", func(t *testing.T) {
		conn := &models.UserConnection{
			ClientID: "existing-client-pubkey",
			ClientParams: map[string]any{
				"client_private_key":       "existing-client-privkey",
				"rekey_after_time":         "10-25",
				"rekey_timeout":            "1-5",
				"reject_after_time":        "30-60",
				"keepalive_timeout":        "2-10",
				"max_handshake_attempts":   "3-7",
				"persistent_keepalive":     "20-30",
				"content_padding_addition": "32-64",
			},
		}

		p, err := resolveClientConfigParameters(conn, false, "")
		if err != nil {
			t.Fatalf("resolveClientConfigParameters failed: %v", err)
		}
		if p.clientPub != "existing-client-pubkey" {
			t.Fatalf("expected existing pubkey, got %s", p.clientPub)
		}
		if p.clientPriv != "existing-client-privkey" {
			t.Fatalf("expected existing privkey, got %s", p.clientPriv)
		}
		if p.rat == nil || p.rat.Lo != 10 || p.rat.Hi != 25 {
			t.Fatalf("unexpected rat: %+v", p.rat)
		}
		if p.cpAdd == nil || *p.cpAdd != "32-64" {
			t.Fatalf("unexpected cpAdd: %+v", p.cpAdd)
		}
	})
}
