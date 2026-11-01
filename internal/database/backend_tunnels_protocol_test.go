package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func TestBackendTunnels_ProtocolMigrationFromLegacyDB(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy-protocol.db")
	secretKey := "test-secret-key-1234567890123456"

	// 1. Create a legacy backend_tunnels table without protocol & protocol_params
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open raw sqlite: %v", err)
	}

	createLegacyDDL := `
		CREATE TABLE backend_tunnels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			interface_name TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			probe_private_key TEXT NOT NULL DEFAULT '',
			endpoint TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'connecting',
			disable_reason TEXT NOT NULL DEFAULT '',
			state_version INTEGER NOT NULL DEFAULT 1,
			last_health_check TEXT,
			latency_ms INTEGER DEFAULT 0,
			active_connections INTEGER DEFAULT 0,
			created_at TEXT NOT NULL
		);
	`
	if _, err := raw.ExecContext(ctx, createLegacyDDL); err != nil {
		_ = raw.Close()
		t.Fatalf("failed to create legacy backend_tunnels: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	insertLegacy := `
		INSERT INTO backend_tunnels (server_id, interface_name, public_key, private_key, endpoint, created_at)
		VALUES (1, 'awg-legacy-0', 'pubkey-leg-0', 'privkey-leg-0', '198.51.100.1:51820', ?)
	`
	if _, err := raw.ExecContext(ctx, insertLegacy, now); err != nil {
		_ = raw.Close()
		t.Fatalf("failed to insert legacy backend_tunnels row: %v", err)
	}
	_ = raw.Close()

	// 2. Open via nexus Open() which runs migrations
	db, err := Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("failed to open migrated DB: %v", err)
	}
	defer db.Close()

	// 3. Verify columns exist via dbHasColumn helper
	hasProto, err := dbHasColumn(t, db, "backend_tunnels", "protocol")
	if err != nil || !hasProto {
		t.Fatalf("expected protocol column to exist after migration, got %v (err: %v)", hasProto, err)
	}
	hasProtoParams, err := dbHasColumn(t, db, "backend_tunnels", "protocol_params")
	if err != nil || !hasProtoParams {
		t.Fatalf("expected protocol_params column to exist after migration, got %v (err: %v)", hasProtoParams, err)
	}

	// 4. Verify existing row defaulted to awg and empty protocol_params
	legacyTunnel, err := db.GetBackendTunnel(ctx, 1)
	if err != nil {
		t.Fatalf("failed to get migrated tunnel: %v", err)
	}
	if legacyTunnel.Protocol != models.ProtocolAWG {
		t.Errorf("expected legacy tunnel protocol %q, got %q", models.ProtocolAWG, legacyTunnel.Protocol)
	}
	if len(legacyTunnel.ProtocolParams) != 0 {
		t.Errorf("expected empty protocol_params for legacy tunnel, got %s", string(legacyTunnel.ProtocolParams))
	}
}

func TestBackendTunnels_MultiProtocolCRUDAndEncryption(t *testing.T) {
	ctx := context.Background()
	secretKey := "test-secret-key-1234567890123456"
	dbPath := filepath.Join(t.TempDir(), "multiprotocol-crud.db")

	db, err := Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	srvID, err := db.CreateServer(ctx, &models.Server{Name: "Test Node 1", Host: "192.0.2.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// 1. Create an AWG tunnel with empty protocol (must default to awg)
	awgTunnel := &models.BackendTunnel{
		ServerID:        srvID,
		InterfaceName:   "awg-be-10",
		PublicKey:       "awg-pub-10",
		PrivateKey:      "awg-priv-10",
		ProbePrivateKey: "awg-probe-10",
		Endpoint:        "192.0.2.10:51820",
		Status:          "active",
	}
	awgID, err := db.CreateBackendTunnel(ctx, awgTunnel)
	if err != nil {
		t.Fatalf("CreateBackendTunnel (AWG) failed: %v", err)
	}

	gotAWG, err := db.GetBackendTunnel(ctx, awgID)
	if err != nil || gotAWG == nil {
		t.Fatalf("GetBackendTunnel (AWG) failed: %v", err)
	}
	if gotAWG.Protocol != models.ProtocolAWG {
		t.Errorf("expected AWG tunnel to default to protocol %q, got %q", models.ProtocolAWG, gotAWG.Protocol)
	}
	if len(gotAWG.ProtocolParams) != 0 {
		t.Errorf("expected AWG tunnel to have empty protocol_params, got %s", string(gotAWG.ProtocolParams))
	}

	// 2. Create a VLESS tunnel with encrypted VLESSRealityParams
	vlessParams := models.VLESSRealityParams{
		UUID:        "e99fa99b-4497-40da-b9c1-5dfa14bc1234",
		Flow:        "xtls-rprx-vision",
		PublicKey:   "kS3W90hA4z9R-vless-pub",
		ShortID:     "16a8",
		ServerName:  "camouflage.microsoft.com",
		Fingerprint: "chrome",
		Transport:   "tcp",
	}
	vlessBytes, err := json.Marshal(vlessParams)
	if err != nil {
		t.Fatalf("failed to marshal vless params: %v", err)
	}

	vlessTunnel := &models.BackendTunnel{
		ServerID:       srvID,
		InterfaceName:  "vless-be-20",
		Endpoint:       "198.51.100.20:443",
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: json.RawMessage(vlessBytes),
		Status:         "active",
	}
	vlessID, err := db.CreateBackendTunnel(ctx, vlessTunnel)
	if err != nil {
		t.Fatalf("CreateBackendTunnel (VLESS) failed: %v", err)
	}

	// 2a. Inspect raw database to ensure encryption at rest
	var rawCiphertext string
	err = db.sqlDB.QueryRowContext(ctx, "SELECT protocol_params FROM backend_tunnels WHERE id = ?", vlessID).Scan(&rawCiphertext)
	if err != nil {
		t.Fatalf("failed to query raw protocol_params: %v", err)
	}
	if !security.LooksLikeFernetToken(rawCiphertext) {
		t.Errorf("expected protocol_params to be stored as Fernet ciphertext, got %q", rawCiphertext)
	}
	if strings.Contains(rawCiphertext, "camouflage.microsoft.com") || strings.Contains(rawCiphertext, "e99fa99b") {
		t.Errorf("sensitive plaintext leaked into raw protocol_params column!")
	}

	// 2b. Read through GetBackendTunnel and verify decryption
	gotVLESS, err := db.GetBackendTunnel(ctx, vlessID)
	if err != nil || gotVLESS == nil {
		t.Fatalf("GetBackendTunnel (VLESS) failed: %v", err)
	}
	if gotVLESS.Protocol != models.ProtocolVLESS {
		t.Errorf("expected Protocol %q, got %q", models.ProtocolVLESS, gotVLESS.Protocol)
	}
	var decodedVLESS models.VLESSRealityParams
	if err := json.Unmarshal(gotVLESS.ProtocolParams, &decodedVLESS); err != nil {
		t.Fatalf("failed to unmarshal decrypted VLESS params: %v", err)
	}
	if decodedVLESS != vlessParams {
		t.Errorf("decrypted VLESS params mismatch: got %+v, want %+v", decodedVLESS, vlessParams)
	}

	// 2c. Verify GetBackendTunnelByServerID
	bySrv, err := db.GetBackendTunnelByServerID(ctx, srvID)
	if err != nil || bySrv == nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if bySrv.Protocol != models.ProtocolAWG && bySrv.Protocol != models.ProtocolVLESS {
		t.Errorf("expected Protocol awg or vless, got %q", bySrv.Protocol)
	}

	// 3. Create a NaiveProxy tunnel with encrypted NaiveProxyParams
	naiveParams := models.NaiveProxyParams{
		Username: "admin_user",
		Password: "SuperSecretPassword99!",
		Domain:   "proxy.domain.org",
		EnableH3: true,
	}
	naiveBytes, err := json.Marshal(naiveParams)
	if err != nil {
		t.Fatalf("failed to marshal naive params: %v", err)
	}

	naiveTunnel := &models.BackendTunnel{
		ServerID:       srvID,
		InterfaceName:  "naive-be-30",
		Endpoint:       "203.0.113.30:443",
		Protocol:       models.ProtocolNaive,
		ProtocolParams: json.RawMessage(naiveBytes),
		Status:         "active",
	}
	naiveID, err := db.CreateBackendTunnel(ctx, naiveTunnel)
	if err != nil {
		t.Fatalf("CreateBackendTunnel (Naive) failed: %v", err)
	}

	// 3a. Inspect raw database for password leak
	var rawNaiveCiphertext string
	err = db.sqlDB.QueryRowContext(ctx, "SELECT protocol_params FROM backend_tunnels WHERE id = ?", naiveID).Scan(&rawNaiveCiphertext)
	if err != nil {
		t.Fatalf("failed to query raw naive protocol_params: %v", err)
	}
	if strings.Contains(rawNaiveCiphertext, "SuperSecretPassword99!") {
		t.Errorf("naive password leaked into raw SQLite database!")
	}

	// 3b. Read through GetBackendTunnels (list all)
	allTunnels, err := db.GetBackendTunnels(ctx)
	if err != nil {
		t.Fatalf("GetBackendTunnels failed: %v", err)
	}
	if len(allTunnels) != 3 {
		t.Fatalf("expected 3 tunnels, got %d", len(allTunnels))
	}

	// 4. Test UpdateBackendTunnel with protocol_params
	newVLESSParams := models.VLESSRealityParams{
		UUID:        "ffffffff-4497-40da-b9c1-5dfa14bc1234",
		Flow:        "xtls-rprx-vision",
		PublicKey:   "updated-pubkey",
		ShortID:     "9999",
		ServerName:  "updated.camouflage.com",
		Fingerprint: "chrome",
		Transport:   "tcp",
	}
	newVLESSBytes, _ := json.Marshal(newVLESSParams)

	err = db.UpdateBackendTunnel(ctx, vlessID, map[string]any{
		"protocol_params": string(newVLESSBytes),
	})
	if err != nil {
		t.Fatalf("UpdateBackendTunnel protocol_params failed: %v", err)
	}

	updatedVLESS, err := db.GetBackendTunnel(ctx, vlessID)
	if err != nil || updatedVLESS == nil {
		t.Fatalf("GetBackendTunnel after update failed: %v", err)
	}
	var updatedDecoded models.VLESSRealityParams
	if err := json.Unmarshal(updatedVLESS.ProtocolParams, &updatedDecoded); err != nil {
		t.Fatalf("failed to decode updated protocol_params: %v", err)
	}
	if updatedDecoded.ServerName != "updated.camouflage.com" || updatedDecoded.UUID != "ffffffff-4497-40da-b9c1-5dfa14bc1234" {
		t.Errorf("updated protocol_params mismatch: %+v", updatedDecoded)
	}

	// 5. Test SameTunnelIdentity with retrieved tunnels
	if !models.SameTunnelIdentity(updatedVLESS, updatedVLESS) {
		t.Errorf("expected SameTunnelIdentity to return true for identical retrieved tunnel")
	}
	if models.SameTunnelIdentity(gotAWG, updatedVLESS) {
		t.Errorf("expected SameTunnelIdentity to return false between AWG and VLESS tunnels")
	}
}

func TestBackendTunnels_ProtocolMigrationIdempotent(t *testing.T) {
	ctx := context.Background()
	secretKey := "test-secret-key-1234567890123456"
	dbPath := filepath.Join(t.TempDir(), "idempotent-protocol.db")

	db, err := Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	// Calling migrateBackendTunnelsProtocol again must succeed without error
	for i := 0; i < 3; i++ {
		if err := db.migrateBackendTunnelsProtocol(ctx); err != nil {
			t.Fatalf("run %d: migrateBackendTunnelsProtocol failed: %v", i+1, err)
		}
	}
}

func TestBackendTunnel_IPv6_Persistence(t *testing.T) {
	ctx := context.Background()
	secretKey := "test-secret-key-1234567890123456"
	dbPath := filepath.Join(t.TempDir(), "ipv6-backend.db")

	db, err := Open(dbPath, secretKey)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	srvID, err := db.CreateServer(ctx, &models.Server{
		Name:      "ipv6-test-server",
		Host:      "[2001:db8::10]",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	naiveParams := models.NaiveProxyParams{
		Username: "ipv6_user",
		Password: "ipv6_password",
		Domain:   "ipv6.camouflage.org",
		EnableH3: true,
	}
	rawParams, _ := json.Marshal(naiveParams)

	const originalEndpoint = "[2001:db8::10]:443"
	tun := &models.BackendTunnel{
		ServerID:       srvID,
		InterfaceName:  "naive-be-ipv6",
		Endpoint:       originalEndpoint,
		Protocol:       models.ProtocolNaive,
		ProtocolParams: rawParams,
		Status:         "active",
		Enabled:        true,
	}

	id, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel with bracketed IPv6 failed: %v", err)
	}

	// 1. Retrieve by ID
	retrieved, err := db.GetBackendTunnel(ctx, id)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if retrieved.Endpoint != originalEndpoint {
		t.Errorf("GetBackendTunnel endpoint = %q, want %q", retrieved.Endpoint, originalEndpoint)
	}

	// 2. Parse endpoint cleanly
	host, port, err := retrieved.EndpointHostPort()
	if err != nil {
		t.Fatalf("EndpointHostPort failed: %v", err)
	}
	if host != "2001:db8::10" || port != "443" {
		t.Errorf("EndpointHostPort = (%q, %q), want (%q, %q)", host, port, "2001:db8::10", "443")
	}

	// 3. Update endpoint to another bracketed IPv6
	const updatedEndpoint = "[2001:db8::20]:8443"
	if err := db.UpdateBackendTunnelEndpoint(ctx, id, updatedEndpoint); err != nil {
		t.Fatalf("UpdateBackendTunnelEndpoint failed: %v", err)
	}

	// 4. Retrieve by ServerID
	byServer, err := db.GetBackendTunnelByServerID(ctx, srvID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if byServer.Endpoint != updatedEndpoint {
		t.Errorf("updated endpoint = %q, want %q", byServer.Endpoint, updatedEndpoint)
	}
	uHost, uPort, err := byServer.EndpointHostPort()
	if err != nil {
		t.Fatalf("EndpointHostPort after update failed: %v", err)
	}
	if uHost != "2001:db8::20" || uPort != "8443" {
		t.Errorf("EndpointHostPort after update = (%q, %q), want (%q, %q)", uHost, uPort, "2001:db8::20", "8443")
	}
}
